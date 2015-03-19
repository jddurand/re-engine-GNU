#define PERL_GET_NO_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "config_REGEXP.h"

/* Things that MUST be supported */

#if ! REGEXP_PPRIVATE_CAN
#  error "pprivate not found in structure regexp"
#endif

#ifndef RX_WRAPPED
#  if ! REGEXP_WRAPPED_CAN
#    error "RX_WRAPPED macro not found"
#  else
#    define RX_WRAPPED(rx) (rx)->wrapped
#  endif
#endif

#ifndef RX_WRAPLEN
#  if ! REGEXP_WRAPLEN_CAN
#    error "RX_WRAPLEN macro not found"
#  else
#    define RX_WRAPLEN(rx) (rx)->wraplen
#  endif
#endif

#include "config.h"
#include "regex.h"

static regexp_engine engine_GNU;

typedef struct GNU_private {
#ifdef HAVE_REGEXP_ENGINE_DUPE
  char   *native_utf8;
  STRLEN  len_native_utf8;
#endif
  regex_t regex;
} GNU_private_t;

/******************************************************************/
/* Copy of DROLSKY/Params-Validate-1.18/lib/Params/Validate/XS.xs */
/******************************************************************/
/* type constants */
#define SCALAR    1
#define ARRAYREF  2
#define HASHREF   4
#define CODEREF   8
#define GLOB      16
#define GLOBREF   32
#define SCALARREF 64
#define UNKNOWN   128
#define UNDEF     256
#define OBJECT    512
#define HANDLE    (GLOB | GLOBREF)
#define BOOLEAN   (SCALAR | UNDEF)

#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
IV
get_type(SV* sv) {
  IV type = 0;

  if (SvTYPE(sv) == SVt_PVGV) {
    return GLOB;
  }
  if (!SvOK(sv)) {
    return UNDEF;
  }
  if (!SvROK(sv)) {
    return SCALAR;
  }

  switch (SvTYPE(SvRV(sv))) {
  case SVt_NULL:
  case SVt_IV:
  case SVt_NV:
  case SVt_PV:
#if PERL_VERSION <= 10
  case SVt_RV:
#endif
  case SVt_PVMG:
  case SVt_PVIV:
  case SVt_PVNV:
#if PERL_VERSION <= 8
  case SVt_PVBM:
#elif PERL_VERSION >= 11
  case SVt_REGEXP:
#endif
    type = SCALARREF;
    break;
  case SVt_PVAV:
    type = ARRAYREF;
    break;
  case SVt_PVHV:
    type = HASHREF;
    break;
  case SVt_PVCV:
    type = CODEREF;
    break;
  case SVt_PVGV:
    type = GLOBREF;
    break;
    /* Perl 5.10 has a bunch of new types that I don't think will ever
       actually show up here (I hope), but not handling them makes the
       C compiler cranky. */
  default:
    type = UNKNOWN;
    break;
  }

  if (type) {
    if (sv_isobject(sv)) return type | OBJECT;
    return type;
  }

  /* Getting here should not be possible */
  return UNKNOWN;
}

/* Call to malloc free() */
#ifdef free
#define _SAVE_FREE_DEFINITION free
#undef free
#else
#undef _SAVE_FREE_DEFINITION
#endif
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
void _libc_free(void *ptr) {
  free(ptr);
}
#ifdef _SAVE_FREE_DEFINITION
#define free _SAVE_FREE_DEFINITION
#endif

#define GNU_key2int(key, value) do {                             \
  SV* val = cophh_fetch_pvs(CopHINTHASH_get(PL_curcop), key, 0); \
  if (val != &PL_sv_placeholder) {                               \
    value = SvIV(val);                                           \
  } else {                                                       \
    value = 0;                                                   \
  }                                                              \
} while (0)

GNU_STATIC
char *sv2nativeutf8(pTHX_ SV *sv, short isDebug, STRLEN *len_native_utf8) {
    char                     *perl_utf8;
    STRLEN                    len_perl_utf8;
    char                     *native_utf8;
    bool                      is_utf8;
    SV                        *sv_tmp;

    /* Because we do not want to affect original sv */
    sv_tmp = sv_mortalcopy(sv);

    /* Upgrade sv_tmp to UTF-8 and get pointer to Perl's string */
    /* Perl's internal utf8 representation is not utf8 */
    perl_utf8 = SvPVutf8(sv_tmp, len_perl_utf8);

    *len_native_utf8 = len_perl_utf8;
    is_utf8 = 1;
    native_utf8 = (char*)bytes_from_utf8((U8 *)perl_utf8, len_native_utf8, &is_utf8);

    if (native_utf8 == perl_utf8) {
      /* Oups, not allocated */
      Newx(native_utf8, *len_native_utf8, char);
      Copy(perl_utf8, native_utf8, *len_native_utf8, char);
    }

    return native_utf8;
}

#ifdef HAVE_REGEXP_ENGINE_COMP
GNU_STATIC
#if PERL_VERSION <= 10
REGEXP * GNU_comp(pTHX_ const SV * const pattern, const U32 flags)
#else
REGEXP * GNU_comp(pTHX_ SV * const pattern, const U32 flags)
#endif
{
    REGEXP                   *rx;
    GNU_private_t            *ri;
    int                       isDebug;
    int                       defaultSyntax;
    char                     *logHeader = "[re::engine::GNU] GNU_comp";
    char                     *native_utf8;
    STRLEN                    len_native_utf8;

    /* Input as char * */
    STRLEN plen;
    char  *exp;

    /* Copy of flags in input */
    U32 extflags = flags;

    /* SVs that are in input */
    IV pattern_type = get_type((SV *)pattern);
    SV *sv_pattern;
    SV *sv_syntax = NULL;

    reg_errcode_t ret;
    SV * wrapped; /* For stringification */

    GNU_key2int("re::engine::GNU/debug", isDebug);
    GNU_key2int("re::engine::GNU/syntax", defaultSyntax);

    if (isDebug) {
      fprintf(stderr, "%s: pattern=%p flags=0x%lx\n", logHeader, pattern, (unsigned long) flags);
      fprintf(stderr, "%s: ... default syntax: %d\n", logHeader, defaultSyntax);
    }

    /********************/
    /* GNU engine setup */
    /********************/
    if (isDebug) {
      fprintf(stderr, "%s: ... allocating GNU_private_t\n", logHeader);
    }
    Newxz(ri, 1, GNU_private_t);

    /* We accept in input:                                                  */
    /* - a scalar                                                           */
    /* - an arrayref with at least 2 members: the syntax and the pattern    */
    /* - a hash with with at least the key 'pattern', eventually 'syntax'   */

    if (pattern_type == SCALAR) {

      if (isDebug) {
        fprintf(stderr, "%s: ... input is a scalar\n", logHeader);
      }

      sv_pattern = sv_2mortal(newSVsv((SV *)pattern));

    } else if (pattern_type == ARRAYREF) {
      AV *av = (AV *)SvRV(pattern);
      SV **a_pattern;
      SV **a_syntax;

      if (isDebug) {
        fprintf(stderr, "%s: ... input is an array ref\n", logHeader);
      }

      if (av_len(av) < 1) {
        croak("%s: array ref must have at least two elements, i.e. [syntax => pattern]", logHeader);
      }
      a_pattern = av_fetch(av, 1, 1);
      a_syntax = av_fetch(av, 0, 1);

      if (a_pattern == NULL || get_type((SV *)*a_pattern) != SCALAR) {
        croak("%s: array ref must have a scalar as second element, got %d", logHeader, get_type((SV *)a_pattern));
      }
      if (a_syntax == NULL || get_type((SV *)*a_syntax) != SCALAR) {
        croak("%s: array ref must have a scalar as first element, got %d", logHeader, get_type((SV *)a_syntax));
      }

      sv_pattern = sv_2mortal(newSVsv(*a_pattern));
      sv_syntax  = sv_2mortal(newSVsv(*a_syntax));

    } else if (pattern_type == HASHREF) {
      HV  *hv        = (HV *)SvRV(pattern);
      SV **h_pattern = hv_fetch(hv, "pattern", 7, 0);
      SV **h_syntax  = hv_fetch(hv, "syntax", 6, 0);

      if (isDebug) {
        fprintf(stderr, "%s: ... input is a hash ref\n", logHeader);
      }

      if (h_pattern == NULL || get_type((SV *)*h_pattern) != SCALAR) {
        croak("%s: hash ref key must have a key 'pattern' refering to a scalar", logHeader);
      }
      if (h_syntax == NULL || get_type((SV *)*h_syntax) != SCALAR) {
        croak("%s: hash ref key must have a key 'syntax' refering to a scalar", logHeader);
      }

      sv_pattern = sv_2mortal(newSVsv(*h_pattern));
      sv_syntax  = sv_2mortal(newSVsv(*h_syntax));

    } else {
      croak("%s: pattern must be a scalar, an array ref [syntax => pattern], or a hash ref {'syntax' => syntax, 'pattern' => pattern} where syntax and flavour are exclusive", logHeader);
    }

    exp = SvPV(sv_pattern, plen);

    {
      /************************************************************/
      /* split optimizations - copied from re-engine-xxx by avar  */
      /************************************************************/
#if (defined(RXf_SPLIT) && defined(RXf_SKIPWHITE) && defined(RXf_WHITE))
      /* C<split " ">, bypass the PCRE engine alltogether and act as perl does */
      if (flags & RXf_SPLIT && plen == 1 && exp[0] == ' ') {
        if (isDebug) {
          fprintf(stderr, "%s: ... split ' ' optimization\n", logHeader);
        }
        extflags |= (RXf_SKIPWHITE|RXf_WHITE);
      }
#endif

#ifdef RXf_NULL
      /* RXf_NULL - Have C<split //> split by characters */
      if (plen == 0) {
        if (isDebug) {
          fprintf(stderr, "%s: ... split // optimization\n", logHeader);
        }
        extflags |= RXf_NULL;
      }
#endif

#ifdef RXf_START_ONLY
      /* RXf_START_ONLY - Have C<split /^/> split on newlines */
      if (plen == 1 && exp[0] == '^') {
        if (isDebug) {
          fprintf(stderr, "%s: ... split /^/ optimization", logHeader);
        }
        extflags |= RXf_START_ONLY;
      }
#endif

#ifdef RXf_WHITE
      /* RXf_WHITE - Have C<split /\s+/> split on whitespace */
      if (plen == 3 && strnEQ("\\s+", exp, 3)) {
        if (isDebug) {
          fprintf(stderr, "%s: ... split /\\s+/ optimization\n", logHeader);
        }
        extflags |= RXf_WHITE;
      }
#endif
    }

    ri->regex.buffer           = NULL;
    ri->regex.allocated        = 0;
    ri->regex.used             = 0;
    ri->regex.syntax           = (sv_syntax != NULL) ? SvUV(sv_syntax) : defaultSyntax;
    ri->regex.fastmap          = NULL;
    ri->regex.translate        = NULL;
    ri->regex.re_nsub          = 0;
    ri->regex.can_be_null      = 0;
    ri->regex.regs_allocated   = 0;
    ri->regex.fastmap_accurate = 0;
    ri->regex.no_sub           = 0;
    ri->regex.not_bol          = 0;
    ri->regex.not_eol          = 0;
    ri->regex.newline_anchor   = 0;

    /* /msixp flags */
#ifdef RXf_PMf_MULTILINE
    /* /m */
    if ((flags & RXf_PMf_MULTILINE) == RXf_PMf_MULTILINE) {
      if (isDebug) {
        fprintf(stderr, "%s: ... /m flag\n", logHeader);
      }
      ri->regex.newline_anchor = 1;
    } else {
      if (isDebug) {
        fprintf(stderr, "%s: ... no /m flag\n", logHeader);
      }
    }
#endif
#ifdef RXf_PMf_SINGLELINE
    /* /s */
    if ((flags & RXf_PMf_SINGLELINE) == RXf_PMf_SINGLELINE) {
      if (isDebug) {
        fprintf(stderr, "%s: ... /s flag\n", logHeader);
      }
      ri->regex.syntax |= RE_DOT_NEWLINE;
    } else {
      if (isDebug) {
        fprintf(stderr, "%s: ... no /s flag\n", logHeader);
      }
    }
#endif
#ifdef RXf_PMf_FOLD
    /* /i */
    if ((flags & RXf_PMf_FOLD) == RXf_PMf_FOLD) {
      if (isDebug) {
        fprintf(stderr, "%s: ... /i flag\n", logHeader);
      }
      ri->regex.syntax |= RE_ICASE;
    } else {
      if (isDebug) {
        fprintf(stderr, "%s: ... no /i flag\n", logHeader);
      }
    }
#endif
#ifdef RXf_PMf_EXTENDED
    /* /x */
    if ((flags & RXf_PMf_EXTENDED) == RXf_PMf_EXTENDED) {
      /* Not supported: explicitely removed */
      if (isDebug) {
        fprintf(stderr, "%s: ... /x flag removed\n", logHeader);
      }
      extflags &= ~RXf_PMf_EXTENDED;
    }
#endif
#ifdef RXf_PMf_KEEPCOPY
    /* /p */
    if ((flags & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY) {
      if (isDebug) {
        fprintf(stderr, "%s: ... /p flag\n", logHeader);
      }
    } else {
      if (isDebug) {
        fprintf(stderr, "%s: ... no /p flag\n", logHeader);
      }
    }
#endif

    /* REGEX structure for perl */
#if PERL_VERSION > 10
    rx = (REGEXP*) newSV_type(SVt_REGEXP);
#else
    Newxz(rx, 1, REGEXP);
#endif

    REGEXP_REFCNT_SET(rx, 1);
    REGEXP_EXTFLAGS_SET(rx, extflags);
    REGEXP_ENGINE_SET(rx, &engine_GNU);

    /* AFAIK prelen and precomp macros do not always provide an lvalue */
    /*
    REGEXP_PRELEN_SET(rx, (I32)plen);
    REGEXP_PRECOMP_SET(rx, (exp != NULL) ? savepvn(exp, plen) : NULL);
    */

    native_utf8 = sv2nativeutf8(aTHX_ sv_pattern, isDebug, &len_native_utf8);
    if (isDebug) {
      fprintf(stderr, "%s: ... re_compile_internal(preg=%p, pattern=%p, length=%d, syntax=0x%lx)\n", logHeader, &(ri->regex), native_utf8, (int) len_native_utf8, (unsigned long) ri->regex.syntax);
    }
    ret = re_compile_internal (&(ri->regex), native_utf8, len_native_utf8, ri->regex.syntax);
#ifdef HAVE_REGEXP_ENGINE_DUPE
    /*
      Always do a copy of the pattern for the dupe method
    */
    ri->len_native_utf8 = len_native_utf8;
    ri->native_utf8 = native_utf8;
#else
    Safefree(native_utf8);
#endif
    if (ret != _REG_NOERROR) {
      extern const char __re_error_msgid[];
      extern const size_t __re_error_msgid_idx[];
      croak("%s: %s", logHeader, __re_error_msgid + __re_error_msgid_idx[(int) ret]);
    }

    REGEXP_PPRIVATE_SET(rx, ri);
    REGEXP_LASTPAREN_SET(rx, 0);
    REGEXP_LASTCLOSEPAREN_SET(rx, 0);
    REGEXP_NPARENS_SET(rx, (U32)ri->regex.re_nsub); /* cast from size_t */
    if (isDebug) {
      fprintf(stderr, "%s: ... %d () detected\n", logHeader, (int) ri->regex.re_nsub);
    }

    /* qr// stringification */
    if (isDebug) {
      fprintf(stderr, "%s: ... allocating wrapped\n", logHeader);
    }
    wrapped = newSVpvn("(?", 2);
    sv_2mortal(wrapped);

    if (ri->regex.newline_anchor == 1) {
        sv_catpvn(wrapped, "m", 1);
    }
    if ((ri->regex.syntax & RE_DOT_NEWLINE) == RE_DOT_NEWLINE) {
        sv_catpvn(wrapped, "s", 1);
    }
    if ((ri->regex.syntax & RE_ICASE) == RE_ICASE) {
        sv_catpvn(wrapped, "i", 1);
    }
    sv_catpvn(wrapped, ":", 1);
    sv_catpvn(wrapped, "(?#re::engine::GNU", 18);
    {
      char tmp[50];

      sprintf(tmp, "%d", defaultSyntax);
      sv_catpvn(wrapped, "/syntax=", 8);
      sv_catpvn(wrapped, tmp, strlen(tmp));
    }
    sv_catpvn(wrapped, ")", 1);

    sv_catpvn(wrapped, exp, plen);
    sv_catpvn(wrapped, ")", 1);
    RX_WRAPPED(rx) = savepvn(SvPVX(wrapped), SvCUR(wrapped));
    RX_WRAPLEN(rx) = SvCUR(wrapped);
    if (isDebug) {
      fprintf(stderr, "%s: ... stringification to %s\n", logHeader, RX_WRAPPED(rx));
    }

    /*
      Tell perl how many match vars we have and allocate space for
      them, at least one is always allocated for $&
     */
    /* Note: we made sure that offs is always supported whatever the perl version */
    Newxz(REGEXP_OFFS_GET(rx), REGEXP_NPARENS_GET(rx) + 1, regexp_paren_pair);

    if (isDebug) {
      fprintf(stderr, "%s: return %p\n", logHeader, rx);
    }

    /* return the regexp structure to perl */
    return rx;
}
#endif /* HAVE_REGEXP_ENGINE_COMP */

#ifdef HAVE_REGEXP_ENGINE_EXEC

/* Copy of http://perl5.git.perl.org/perl.git/blob_plain/HEAD:/regexec.c */
/* and little adaptation -; 2015.03.15 */

GNU_STATIC
void
GNU_exec_set_capture_string(pTHX_ REGEXP * const rx,
                            char *strbeg,
                            char *strend,
                            SV *sv,
                            U32 flags,
                            short utf8_target)
{
  int   isDebug;
  char *logHeader = "[re::engine::GNU] GNU_exec_set_capture_string";

  GNU_key2int("re::engine::GNU/debug", isDebug);

  if (isDebug) {
    fprintf(stderr, "%s: rx=%p, strbeg=%p, strend=%p, sv=%p, flags=0x%lx, utf8_target=%d\n", logHeader, rx, strbeg, strend, sv, (unsigned long) flags, (int) utf8_target);
  }

  if ((flags & REXEC_COPY_STR) == REXEC_COPY_STR) {
#if REGEXP_SAVED_COPY_CAN
    short canCow = 1;
#else
    short canCow = 0;
#endif
    /* It is perl that decides if this version is COW enabled or not */
    /* From our point of view, it is equivalent to test is saved_copy */
    /* is available */
    if (canCow != 0) {
#if REGEXP_SAVED_COPY_CAN
      if ((REGEXP_SAVED_COPY_GET(rx) != NULL
           && SvIsCOW(REGEXP_SAVED_COPY_GET(rx))
           && SvPOKp(REGEXP_SAVED_COPY_GET(rx))
           && SvIsCOW(sv)
           && SvPOKp(sv)
           && SvPVX(sv) == SvPVX(REGEXP_SAVED_COPY_GET(rx)))) {
        /* just reuse saved_copy SV */
        if (isDebug) {
          fprintf(stderr, "%s: ... reusing save_copy SV\n", logHeader);
        }
        if (RX_MATCH_COPIED(rx)) {
#if REGEXP_SUBBEG_CAN
          Safefree(REGEXP_SUBBEG_GET(rx));
#endif /* REGEXP_SUBBEG_CAN */
          RX_MATCH_COPIED_off(rx);
        }
      } else {
        if (isDebug) {
          fprintf(stderr, "%s: ... creating new COW sv\n", logHeader);
        }
        RX_MATCH_COPY_FREE(rx);
        REGEXP_SAVED_COPY_SET(rx, sv_setsv_cow(REGEXP_SAVED_COPY_GET(rx), sv));
      }
      REGEXP_SUBBEG_SET(rx, (char *)SvPVX_const(REGEXP_SAVED_COPY_GET(rx)));
      REGEXP_SUBLEN_SET(rx, strend - strbeg);
      REGEXP_SUBOFFSET_SET(rx, 0);
      REGEXP_SUBCOFFSET_SET(rx, 0);
      if (isDebug) {
        fprintf(stderr, "%s: ... "
#if REGEXP_SUBBEG_CAN
                "subbeg=%p, "
#endif
#if REGEXP_SUBLEN_CAN
                "sublen=%d, "
#endif
#if REGEXP_SUBOFFSET_CAN
                "suboffset=%d, "
#endif
#if REGEXP_SUBCOFFSET_CAN
                "subcoffset=%d"
#endif
                "\n", logHeader
#if REGEXP_SUBBEG_CAN
                , REGEXP_SUBBEG_GET(rx)
#endif
#if REGEXP_SUBLEN_CAN
                , REGEXP_SUBLEN_GET(rx)
#endif
#if REGEXP_SUBOFFSET_CAN
                , REGEXP_SUBOFFSET_GET(rx)
#endif
#if REGEXP_SUBCOFFSET_CAN
                , REGEXP_SUBCOFFSET_GET(rx)
#endif
                );
      }
#endif /* REGEXP_SAVED_COPY_CAN */
    } else {
      /* The following are optimizations that appeared in 5.20. This is almost */
      /* copied verbatim from it */
#if REGEXP_EXTFLAGS_CAN && REGEXP_LASTPAREN_CAN && REGEXP_OFFS_CAN && REGEXP_SUBLEN_CAN && REGEXP_SUBBEG_CAN
      {
        SSize_t min = 0;
        SSize_t max = strend - strbeg;
        SSize_t sublen;
#if defined(RXf_PMf_KEEPCOPY) && defined(PL_sawampersand) && defined(REXEC_COPY_SKIP_POST) && defined(SAWAMPERSAND_RIGHT) && defined(REXEC_COPY_SKIP_PRE) && defined(SAWAMPERSAND_LEFT)
        /* $' and $` optimizations */

        if (((flags & REXEC_COPY_SKIP_POST) == REXEC_COPY_SKIP_POST)
            && !((REGEXP_EXTFLAGS_GET(rx) & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY) /* //p */
            && !((PL_sawampersand & SAWAMPERSAND_RIGHT) == SAWAMPERSAND_RIGHT)
            ) {
          /* don't copy $' part of string */
          U32 n = 0;
          max = -1;
          /* calculate the right-most part of the string covered
           * by a capture. Due to look-ahead, this may be to
           * the right of $&, so we have to scan all captures */
          if (isDebug) {
            fprintf(stderr, "%s: ... calculate right-most part of the string coverred by a capture\n", logHeader);
          }
          while (n <= REGEXP_LASTPAREN_GET(rx)) {
            if (REGEXP_OFFS_GET(rx)[n].end > max) {
              max = REGEXP_OFFS_GET(rx)[n].end;
            }
            n++;
          }
          if (max == -1)
            max = ((PL_sawampersand & SAWAMPERSAND_LEFT) == SAWAMPERSAND_LEFT)
              ? REGEXP_OFFS_GET(rx)[0].start
              : 0;
        }
        if (((flags & REXEC_COPY_SKIP_PRE) == REXEC_COPY_SKIP_PRE)
            && !((REGEXP_EXTFLAGS_GET(rx) & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY) /* //p */
            && !((PL_sawampersand & SAWAMPERSAND_LEFT) == SAWAMPERSAND_LEFT)
            ) {
          /* don't copy $` part of string */
          U32 n = 0;
          min = max;
          /* calculate the left-most part of the string covered
           * by a capture. Due to look-behind, this may be to
           * the left of $&, so we have to scan all captures */
          if (isDebug) {
            fprintf(stderr, "%s: ... calculate left-most part of the string coverred by a capture\n", logHeader);
          }
          while (min && n <= REGEXP_LASTPAREN_GET(rx)) {
            if (   REGEXP_OFFS_GET(rx)[n].start != -1
                   && REGEXP_OFFS_GET(rx)[n].start < min)
              {
                min = REGEXP_OFFS_GET(rx)[n].start;
              }
            n++;
          }
          if (((PL_sawampersand & SAWAMPERSAND_RIGHT) == SAWAMPERSAND_RIGHT)
              && min > REGEXP_OFFS_GET(rx)[0].end
              )
            min = REGEXP_OFFS_GET(rx)[0].end;
        }
#endif /* RXf_PMf_KEEPCOPY && PL_sawampersand && REXEC_COPY_SKIP_POST && SAWAMPERSAND_RIGHT && REXEC_COPY_SKIP_PRE && SAWAMPERSAND_LEFT */

        sublen = max - min;

        if (RX_MATCH_COPIED(rx)) {
          if (sublen > REGEXP_SUBLEN_GET(rx))
            REGEXP_SUBBEG_SET(rx, (char*)saferealloc(REGEXP_SUBBEG_GET(rx), sublen+1));
        }
        else {
          REGEXP_SUBBEG_SET(rx, (char*)safemalloc(sublen+1));
        }
        Copy(strbeg + min, REGEXP_SUBBEG_GET(rx), sublen, char);
        REGEXP_SUBBEG_GET(rx)[sublen] = '\0';
        REGEXP_SUBOFFSET_SET(rx, min);
        REGEXP_SUBLEN_SET(rx, sublen);
        RX_MATCH_COPIED_on(rx);
        if (isDebug) {
          fprintf(stderr, "%s: ... "
#if REGEXP_SUBBEG_CAN
                  "subbeg=%p, "
#endif
#if REGEXP_SUBLEN_CAN
                  "sublen=%d, "
#endif
#if REGEXP_SUBOFFSET_CAN
                  "suboffset=%d, "
#endif
#if REGEXP_SUBCOFFSET_CAN
                  "subcoffset=%d"
#endif
                  "\n", logHeader
#if REGEXP_SUBBEG_CAN
                  , REGEXP_SUBBEG_GET(rx)
#endif
#if REGEXP_SUBLEN_CAN
                  , REGEXP_SUBLEN_GET(rx)
#endif
#if REGEXP_SUBOFFSET_CAN
                  , REGEXP_SUBOFFSET_GET(rx)
#endif
#if REGEXP_SUBCOFFSET_CAN
                  , REGEXP_SUBCOFFSET_GET(rx)
#endif
                  );
        }
      }
#endif /* REGEXP_EXTFLAGS_CAN && REGEXP_LASTPAREN_CAN && REGEXP_OFFS_CAN && REGEXP_SUBLEN_CAN && REGEXP_SUBBEG_CAN */

#if REGEXP_SUBCOFFSET_CAN && REGEXP_SUBOFFSET_CAN
      REGEXP_SUBCOFFSET_SET(rx, REGEXP_SUBOFFSET_GET(rx));
      if (REGEXP_SUBOFFSET_GET(rx) != 0 && utf8_target != 0) {
        /* Convert byte offset to chars.
         * XXX ideally should only compute this if @-/@+
         * has been seen, a la PL_sawampersand ??? */

        /* If there's a direct correspondence between the
         * string which we're matching and the original SV,
         * then we can use the utf8 len cache associated with
         * the SV. In particular, it means that under //g,
         * sv_pos_b2u() will use the previously cached
         * position to speed up working out the new length of
         * subcoffset, rather than counting from the start of
         * the string each time. This stops
         *   $x = "\x{100}" x 1E6; 1 while $x =~ /(.)/g;
         * from going quadratic */
#ifdef HAVE_SV_POS_B2U_FLAGS
        if (SvPOKp(sv) && SvPVX(sv) == strbeg)
          REGEXP_SUBCOFFSET_SET(rx, sv_pos_b2u_flags(sv, REGEXP_SUBCOFFSET_GET(rx),
                                                     SV_GMAGIC|SV_CONST_RETURN));
        else
#endif
          REGEXP_SUBCOFFSET_SET(rx, utf8_length((U8*)strbeg,
                                                (U8*)(strbeg + REGEXP_SUBOFFSET_GET(rx))));
      }
      if (isDebug) {
        fprintf(stderr, "%s: ... suboffset=%d and utf8target=%d => subcoffset=%d\n", logHeader, REGEXP_SUBOFFSET_GET(rx), (int) utf8_target, REGEXP_SUBCOFFSET_GET(rx));
      }
#endif /* REGEXP_SUBCOFFSET_CAN && REGEXP_SUBOFFSET_CAN */
    }
  } else {
    RX_MATCH_COPY_FREE(rx);
    REGEXP_SUBBEG_SET(rx, strbeg);
    REGEXP_SUBOFFSET_SET(rx, 0);
    REGEXP_SUBCOFFSET_SET(rx, 0);
    REGEXP_SUBLEN_SET(rx, strend - strbeg);
  }

  if (isDebug) {
    fprintf(stderr, "%s: return void\n", logHeader);
  }

}

GNU_STATIC
I32
#if PERL_VERSION >= 19
GNU_exec(pTHX_ REGEXP * const rx, char *stringarg, char *strend, char *strbeg, SSize_t minend, SV * sv, void *data, U32 flags)
#else
GNU_exec(pTHX_ REGEXP * const rx, char *stringarg, char *strend, char *strbeg, I32 minend, SV * sv, void *data, U32 flags)
#endif
{
    GNU_private_t      *ri = REGEXP_PPRIVATE_GET(rx);
    regoff_t            rc;
    U32                 i;
    struct re_registers regs;     /* for subexpression matches */
    int                 isDebug;
    char               *logHeader = "[re::engine::GNU] GNU_exec";
    short               utf8_target = DO_UTF8(sv) ? 1 : 0;

    char               *native_utf8;
    STRLEN              len_native_utf8;

    SV                 *sv_stringarg;
    char               *nativestringarg_utf8;
    STRLEN              len_nativestringarg_utf8;
    bool                nativestringarg_utf8_tofree;

    STRLEN              len_nativerange_utf8;

    regs.num_regs = 0;
    regs.start = NULL;
    regs.end = NULL;

    GNU_key2int("re::engine::GNU/debug", isDebug);

    if (isDebug) {
      fprintf(stderr, "%s: rx=%p, stringarg=%p, strend=%p, strbeg=%p, minend=%d, sv=%p, data=%p, flags=0x%lx\n", logHeader, rx, stringarg, strend, strbeg, (int) minend, sv, data, (unsigned long) flags);
      fprintf(stderr, "%s: ... pattern=%s\n", logHeader, RX_WRAPPED(rx));
    }

    if (isDebug) {
      fprintf(stderr, "%s: ... re_search(bufp=%p, string=%p, length=%d, start=%d, range=%d, regs=%p)\n", logHeader, &(ri->regex), strbeg, (int) (strend - strbeg), (int) (stringarg - strbeg), (int) (strend - stringarg), &regs);
    }
    native_utf8 = sv2nativeutf8(aTHX_ sv, isDebug, &len_native_utf8);
    if (stringarg != strbeg) {
      sv_stringarg = sv_2mortal(newSVpvn_utf8(stringarg, strend - stringarg, utf8_target));
      nativestringarg_utf8 = sv2nativeutf8(sv_stringarg, isDebug, &len_nativestringarg_utf8);
      nativestringarg_utf8_tofree = 1;
    } else {
      len_nativestringarg_utf8 = len_native_utf8;
      nativestringarg_utf8 = native_utf8;
      nativestringarg_utf8_tofree = 0;
    }
    /* rc = re_search(&(ri->regex), strbeg, strend - strbeg, stringarg - strbeg, strend - stringarg, &regs); */
    len_nativerange_utf8 = len_native_utf8 - len_nativestringarg_utf8;
    rc = re_search(&(ri->regex), native_utf8, len_native_utf8, len_native_utf8 - len_nativerange_utf8, len_nativerange_utf8, &regs);
    Safefree(native_utf8);
    if (nativestringarg_utf8_tofree) {
      Safefree(nativestringarg_utf8);
    }

    if (rc <= -2) {
      croak("%s: Internal error in re_search()", logHeader);
    } else if (rc == -1) {
      if (isDebug) {
        fprintf(stderr, "%s: return 0 (no match)\n", logHeader);
      }
      return 0;
    }

    /* Why isn't it done by the higher level ? */
    RX_MATCH_UTF8_set(rx, utf8_target);
    RX_MATCH_TAINTED_off(rx);

    REGEXP_LASTPAREN_SET(rx, REGEXP_NPARENS_GET(rx));
    REGEXP_LASTCLOSEPAREN_SET(rx, REGEXP_NPARENS_GET(rx));

    /* There is always at least the index 0 for $& */
    for (i = 0; i < REGEXP_NPARENS_GET(rx) + 1; i++) {
        if (isDebug) {
          I32 start = (I32) utf8_distance(strbeg + regs.start[i], strbeg);
          I32 end   = (I32) utf8_distance(strbeg + regs.end[i],   strbeg);
          fprintf(stderr, "%s: ... Match No %d positions: bytes=[%d,%d], characters=[%d,%d]\n", logHeader, i, (int) regs.start[i], (int) regs.end[i], (int) utf8_distance(strbeg + regs.start[i], strbeg), (int) utf8_distance(strbeg + regs.end[i], strbeg));
        }
#if REGEXP_OFFS_CAN
        REGEXP_OFFS_GET(rx)[i].start = regs.start[i];
        REGEXP_OFFS_GET(rx)[i].end = regs.end[i];
#endif
    }

    if ((flags & REXEC_NOT_FIRST) != REXEC_NOT_FIRST) {
      // GNU_exec_set_capture_string(aTHX_ rx, strbeg, strend, sv, flags, utf8_target);
      // goto SKIP;
    }

    if ((flags & REXEC_NOT_FIRST) != REXEC_NOT_FIRST) {
      const I32 length = strend - strbeg;
#if REGEXP_SAVED_COPY_CAN
      short canCow = 1;
      short doCow = canCow ? (REGEXP_SAVED_COPY_GET(rx) != NULL
                              && SvIsCOW(REGEXP_SAVED_COPY_GET(rx))
                              && SvPOKp(REGEXP_SAVED_COPY_GET(rx))
                              && SvIsCOW(sv)
                              && SvPOKp(sv)
                              && SvPVX(sv) == SvPVX(REGEXP_SAVED_COPY_GET(rx))) : 0;
#else
      short canCow = 0;
      short doCow = 0;
#endif
      RX_MATCH_COPY_FREE(rx);
      if ((flags & REXEC_COPY_STR) == REXEC_COPY_STR) {
        /* Adapted from perl-5.10. Not performant, I know */
        if (canCow != 0 && doCow != 0) {
#if REGEXP_SAVED_COPY_CAN
          if (isDebug) {
            fprintf(stderr, "%s: ... reusing save_copy SV\n", logHeader);
          }
          REGEXP_SAVED_COPY_SET(rx, sv_setsv_cow(REGEXP_SAVED_COPY_GET(rx), sv));
#if REGEXP_SUBBEG_CAN
          {
             SV *csv = REGEXP_SAVED_COPY_GET(rx);
             char *s = (char *) SvPVX_const(csv);
             REGEXP_SUBBEG_SET(rx, s);
          }
#endif
#endif
        } else {
          RX_MATCH_COPIED_on(rx);
#if REGEXP_SUBBEG_CAN
          REGEXP_SUBBEG_SET(rx, savepvn(strbeg, length));
#endif
        }
      } else {
          REGEXP_SUBBEG_SET(rx, strbeg);
      }
      REGEXP_SUBLEN_SET(rx, length);
      REGEXP_SUBOFFSET_SET(rx, 0);
      REGEXP_SUBCOFFSET_SET(rx, 0);
    }

SKIP:

    if (regs.start != NULL) {
      _libc_free(regs.start);
    }

    if (regs.end != NULL) {
      _libc_free(regs.end);
    }

    if (isDebug) {
      fprintf(stderr, "%s: return 1 (match)\n", logHeader);
    }

    return 1;
}
#endif /* HAVE_REGEXP_ENGINE_EXEC */

#ifdef HAVE_REGEXP_ENGINE_INTUIT
GNU_STATIC
char *
#if PERL_VERSION >= 19
GNU_intuit(pTHX_ REGEXP * const rx, SV * sv, const char *strbeg, char *strpos, char *strend, U32 flags, re_scream_pos_data *data)
#else
GNU_intuit(pTHX_ REGEXP * const rx, SV * sv, char *strpos, char *strend, U32 flags, re_scream_pos_data *data)
#endif
{
  int                       isDebug;
  char                     *logHeader = "[re::engine::GNU] GNU_intuit";

  PERL_UNUSED_ARG(rx);
  PERL_UNUSED_ARG(sv);
#if PERL_VERSION >= 19
  PERL_UNUSED_ARG(strbeg);
#endif
  PERL_UNUSED_ARG(strpos);
  PERL_UNUSED_ARG(strend);
  PERL_UNUSED_ARG(flags);
  PERL_UNUSED_ARG(data);

  GNU_key2int("re::engine::GNU/debug", isDebug);

  if (isDebug) {
    fprintf(stderr, "%s: rx=%p, sv=%p, strpos=%p, strend=%p, flags=0x%lx, data=%p\n", logHeader, rx, sv, strpos, strend, (unsigned long) flags, data);
    fprintf(stderr, "%s: return NULL\n", logHeader);
  }

  return NULL;
}
#endif

#ifdef HAVE_REGEXP_ENGINE_CHECKSTR
GNU_STATIC
SV *
GNU_checkstr(pTHX_ REGEXP * const rx)
{
  int                       isDebug;
  char                     *logHeader = "[re::engine::GNU] GNU_checkstr";

  PERL_UNUSED_ARG(rx);

  GNU_key2int("re::engine::GNU/debug", isDebug);

  if (isDebug) {
    fprintf(stderr, "%s: rx=%p\n", logHeader, rx);
    fprintf(stderr, "%s: return NULL\n", logHeader);
  }

  return NULL;
}
#endif

#ifdef HAVE_REGEXP_ENGINE_FREE
GNU_STATIC
void
GNU_free(pTHX_ REGEXP * const rx)
{
  regexp             *re = _RegSV(rx);
  GNU_private_t      *ri = REGEXP_PPRIVATE_GET(rx);
  int                isDebug;
  char              *logHeader = "[re::engine::GNU] GNU_free";

  GNU_key2int("re::engine::GNU/debug", isDebug);

  if (isDebug) {
    fprintf(stderr, "%s: rx=%p\n", logHeader, rx);
  }

#ifdef HAVE_REGEXP_ENGINE_DUPE
  Safefree(ri->native_utf8);
#endif
  if (isDebug) {
    fprintf(stderr, "%s: ... regfree(preg=%p)\n", logHeader, &(ri->regex));
  }
  regfree(&(ri->regex));

  if (isDebug) {
    fprintf(stderr, "%s: return void\n", logHeader);
  }

}
#endif

#ifdef HAVE_REGEXP_ENGINE_QR_PACKAGE
GNU_STATIC
SV *
GNU_qr_package(pTHX_ REGEXP * const rx)
{
  int                isDebug;
  char              *logHeader = "[re::engine::GNU] GNU_qr_package";
  SV                *rc;

  PERL_UNUSED_ARG(rx);

  GNU_key2int("re::engine::GNU/debug", isDebug);

  if (isDebug) {
    fprintf(stderr, "%s: rx=%p\n", logHeader, rx);
  }

  rc = newSVpvs("re::engine::GNU");

  if (isDebug) {
    fprintf(stderr, "%s: return %p\n", logHeader, rc);
  }

  return rc;

}
#endif

#ifdef HAVE_REGEXP_ENGINE_DUPE
GNU_STATIC
void *
GNU_dupe(pTHX_ REGEXP * const rx, CLONE_PARAMS *param)
{
  GNU_private_t *oldri = REGEXP_PPRIVATE_GET(rx);
  GNU_private_t *ri;
  reg_errcode_t  ret;
  int                       isDebug;
  char                     *logHeader = "[re::engine::GNU] GNU_dupe";

  PERL_UNUSED_ARG(param);

  if (isDebug) {
    fprintf(stderr, "%s: rx=%p, param=%p\n", logHeader, rx, param);
  }

  if (isDebug) {
    fprintf(stderr, "%s: ... allocating GNU_private_t\n", logHeader);
  }
  Newxz(ri, 1, GNU_private_t);
  Newx(ri->native_utf8, oldri->len_native_utf8, char);
  ri->len_native_utf8 = oldri->len_native_utf8;
  Copy(oldri->native_utf8, ri->native_utf8, ri->len_native_utf8, char);

  ri->regex.buffer           = NULL;
  ri->regex.allocated        = 0;
  ri->regex.used             = 0;
  ri->regex.syntax           = oldri->regex.syntax;
  ri->regex.fastmap          = NULL;
  ri->regex.translate        = NULL;
  ri->regex.re_nsub          = 0;
  ri->regex.can_be_null      = 0;
  ri->regex.regs_allocated   = 0;
  ri->regex.fastmap_accurate = 0;
  ri->regex.no_sub           = 0;
  ri->regex.not_bol          = 0;
  ri->regex.not_eol          = 0;
  ri->regex.newline_anchor   = 0;

  if (isDebug) {
    fprintf(stderr, "%s: ... re_compile_internal(preg=%p, pattern=%p, length=%d, syntax=0x%lx)\n", logHeader, &(ri->regex), ri->pattern_utf8, (int) ri->len_pattern_utf8, (unsigned long) ri->regex.syntax);
  }
  ret = re_compile_internal (&(ri->regex), ri->pattern_utf8, ri->len_pattern_utf8, ri->regex.syntax);
  if (ret != _REG_NOERROR) {
    extern const char __re_error_msgid[];
    extern const size_t __re_error_msgid_idx[];
    croak("%s: %s", logHeader, __re_error_msgid + __re_error_msgid_idx[(int) ret]);
  }

  if (isDebug) {
    fprintf(stderr, "%s: return %p\n", logHeader, ri);
  }

  return ri;
}
#endif

MODULE = re::engine::GNU		PACKAGE = re::engine::GNU		
PROTOTYPES: ENABLE

BOOT:
#ifdef HAVE_REGEXP_ENGINE_COMP
  engine_GNU.comp = GNU_comp;
#endif
#ifdef HAVE_REGEXP_ENGINE_EXEC
  engine_GNU.exec = GNU_exec;
#endif
#ifdef HAVE_REGEXP_ENGINE_INTUIT
  engine_GNU.intuit = GNU_intuit;
#endif
#ifdef HAVE_REGEXP_ENGINE_CHECKSTR
  engine_GNU.checkstr = GNU_checkstr;
#endif
#ifdef HAVE_REGEXP_ENGINE_FREE
  engine_GNU.free = GNU_free;
#endif
#ifdef HAVE_REGEXP_ENGINE_NUMBERED_BUFF_FETCH
#ifdef HAVE_PERL_REG_NUMBERED_BUFF_FETCH
  engine_GNU.numbered_buff_FETCH = Perl_reg_numbered_buff_fetch;
#else
  engine_GNU.numbered_buff_FETCH = NULL;
#endif
#endif
#ifdef HAVE_REGEXP_ENGINE_NUMBERED_BUFF_STORE
#ifdef HAVE_PERL_REG_NUMBERED_BUFF_STORE
  engine_GNU.numbered_buff_STORE = Perl_reg_numbered_buff_store;
#else
  engine_GNU.numbered_buff_STORE = NULL;
#endif
#endif
#ifdef HAVE_REGEXP_ENGINE_NUMBERED_BUFF_LENGTH
#ifdef HAVE_PERL_REG_NUMBERED_BUFF_LENGTH
  engine_GNU.numbered_buff_LENGTH = Perl_reg_numbered_buff_length;
#else
  engine_GNU.numbered_buff_LENGTH = NULL;
#endif
#endif
#ifdef HAVE_REGEXP_ENGINE_NAMED_BUFF
#ifdef HAVE_PERL_REG_NAMED_BUFF
  engine_GNU.named_buff = Perl_reg_named_buff;
#else
  engine_GNU.named_buff = NULL;
#endif
#endif
#ifdef HAVE_REGEXP_ENGINE_NAMED_BUFF_ITER
#ifdef HAVE_PERL_REG_NAMED_BUFF_ITER
  engine_GNU.named_buff_iter = Perl_reg_named_buff_iter;
#else
  engine_GNU.named_buff_iter = NULL;
#endif
#endif
#ifdef HAVE_REGEXP_ENGINE_QR_PACKAGE
  engine_GNU.qr_package = GNU_qr_package;
#endif
#ifdef HAVE_REGEXP_ENGINE_DUPE
  engine_GNU.dupe = GNU_dupe;
#endif

void
ENGINE(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(PTR2IV(&engine_GNU))));

void
RE_SYNTAX_AWK(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_AWK)));

void
RE_SYNTAX_ED(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_ED)));

void
RE_SYNTAX_EGREP(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_EGREP)));

void
RE_SYNTAX_EMACS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_EMACS)));

void
RE_SYNTAX_GNU_AWK(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_GNU_AWK)));

void
RE_SYNTAX_GREP(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_GREP)));

void
RE_SYNTAX_POSIX_AWK(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_POSIX_AWK)));

void
RE_SYNTAX_POSIX_BASIC(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_POSIX_BASIC)));

void
RE_SYNTAX_POSIX_EGREP(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_POSIX_EGREP)));

void
RE_SYNTAX_POSIX_EXTENDED(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_POSIX_EXTENDED)));

void
RE_SYNTAX_POSIX_MINIMAL_BASIC(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_POSIX_MINIMAL_BASIC)));

void
RE_SYNTAX_POSIX_MINIMAL_EXTENDED(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_POSIX_MINIMAL_EXTENDED)));

void
RE_SYNTAX_SED(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_SYNTAX_SED)));

void
RE_BACKSLASH_ESCAPE_IN_LISTS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_BACKSLASH_ESCAPE_IN_LISTS)));

void
RE_BK_PLUS_QM(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_BK_PLUS_QM)));

void
RE_CHAR_CLASSES(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_CHAR_CLASSES)));

void
RE_CONTEXT_INDEP_ANCHORS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_CONTEXT_INDEP_ANCHORS)));

void
RE_CONTEXT_INDEP_OPS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_CONTEXT_INDEP_OPS)));

void
RE_CONTEXT_INVALID_OPS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_CONTEXT_INVALID_OPS)));

void
RE_DOT_NEWLINE(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_DOT_NEWLINE)));

void
RE_DOT_NOT_NULL(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_DOT_NOT_NULL)));

void
RE_HAT_LISTS_NOT_NEWLINE(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_HAT_LISTS_NOT_NEWLINE)));

void
RE_INTERVALS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_INTERVALS)));

void
RE_LIMITED_OPS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_LIMITED_OPS)));

void
RE_NEWLINE_ALT(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NEWLINE_ALT)));

void
RE_NO_BK_BRACES(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_BK_BRACES)));

void
RE_NO_BK_PARENS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_BK_PARENS)));

void
RE_NO_BK_REFS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_BK_REFS)));

void
RE_NO_BK_VBAR(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_BK_VBAR)));

void
RE_NO_EMPTY_RANGES(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_EMPTY_RANGES)));

void
RE_UNMATCHED_RIGHT_PAREN_ORD(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_UNMATCHED_RIGHT_PAREN_ORD)));

void
RE_NO_POSIX_BACKTRACKING(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_POSIX_BACKTRACKING)));

void
RE_NO_GNU_OPS(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_GNU_OPS)));

void
RE_DEBUG(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_DEBUG)));

void
RE_INVALID_INTERVAL_ORD(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_INVALID_INTERVAL_ORD)));

void
RE_ICASE(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_ICASE)));

void
RE_CARET_ANCHORS_HERE(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_CARET_ANCHORS_HERE)));

void
RE_CONTEXT_INVALID_DUP(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_CONTEXT_INVALID_DUP)));

void
RE_NO_SUB(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(RE_NO_SUB)));
