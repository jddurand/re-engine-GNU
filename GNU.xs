#define PERL_GET_NO_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "GNU.h"
#include "config_REGEXP.h"

#include "config.h"
#include "regex.h"

#if PERL_VERSION > 10
#define RegSV(p) SvANY(p)
#else
#define RegSV(p) (p)
#endif

typedef struct GNU_private {
  SV *sv_pattern_copy;
  SV *sv_victim_copy;

  char *pattern_utf8;
  char *victim_utf8;

  STRLEN len_pattern_utf8;
  STRLEN len__victim_utf8;

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

static IV
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

#if PERL_VERSION <= 10
REGEXP * GNU_comp(pTHX_ const SV * const pattern, const U32 flags)
#else
REGEXP * GNU_comp(pTHX_ SV * const pattern, const U32 flags)
#endif
{
    REGEXP                   *rx;
    regexp                   *re;
    GNU_private_t            *ri;

    /* Input as char * */
    STRLEN plen;
    char  *exp = SvPV((SV*)pattern, plen);

    /* Copy of flags in input */
    U32 extflags = flags;

    /* SVs that are in input */
    IV pattern_type = get_type(pattern);
    SV *sv_pattern;
    SV *sv_syntax = NULL;

    reg_errcode_t ret;

    {
      /************************************************************/
      /* split optimizations - copied from re-engine-xxx by avar  */
      /************************************************************/
#if (defined(RXf_SPLIT) && defined(RXf_SKIPWHITE) && defined(RXf_WHITE))
      /* C<split " ">, bypass the PCRE engine alltogether and act as perl does */
      if (flags & RXf_SPLIT && plen == 1 && exp[0] == ' ')
        extflags |= (RXf_SKIPWHITE|RXf_WHITE);
#endif

#ifdef RXf_NULL
      /* RXf_NULL - Have C<split //> split by characters */
      if (plen == 0) {
        extflags |= RXf_NULL;
      }
#endif

#ifdef RXf_START_ONLY
      /* RXf_START_ONLY - Have C<split /^/> split on newlines */
      if (plen == 1 && exp[0] == '^') {
        extflags |= RXf_START_ONLY;
      }
#endif

#ifdef RXf_WHITE
      /* RXf_WHITE - Have C<split /\s+/> split on whitespace */
      if (plen == 3 && strnEQ("\\s+", exp, 3)) {
        extflags |= RXf_WHITE;
      }
#endif
    }

    /********************/
    /* GNU engine setup */
    /********************/
    Newxz(ri, 1, GNU_private_t);

    /* We accept in input:                                                  */
    /* - a scalar                                                           */
    /* - an arrayref with at least 2 members: the syntax and the pattern    */
    /* - a hash with with at least the key 'pattern', eventually 'syntax'   */

    if (pattern_type == SCALAR) {

      sv_pattern = pattern;

    } else if (pattern_type == ARRAYREF) {
      AV *av = (AV *)pattern;
      SV **a_pattern;
      SV **a_syntax;

      if (av_top_index(av) < 1) {
        croak("re::engine::GNU: array ref must have at least two elements, i.e. [syntax => pattern]");
      }
      a_pattern = av_fetch(av, 1, 0);
      a_syntax = av_fetch(av, 0, 0);

      if (a_pattern == NULL || get_type(*a_pattern) != SCALAR) {
        croak("re::engine::GNU: array ref must have a scalar as second element");
      }
      if (a_syntax == NULL || get_type(*a_syntax) != SCALAR) {
        croak("re::engine::GNU: array ref must have a scalar as first element");
      }

      sv_pattern = *a_pattern;
      sv_syntax  = *a_syntax;

    } else if (pattern_type == HASHREF) {
      HV  *hv        = (HV *)pattern;
      SV **h_pattern = hv_fetch(hv, "pattern", 7, 0);
      SV **h_syntax  = hv_fetch(hv, "syntax", 6, 0);

      if (h_pattern == NULL || get_type(*h_pattern) != SCALAR) {
        croak("re::engine::GNU: hash ref key must have a key 'pattern' refering to a scalar");
      }
      if (h_syntax == NULL || get_type(*h_syntax) != SCALAR) {
        croak("re::engine::GNU: hash ref key must have a key 'syntax' refering to a scalar");
      }

      sv_pattern = *h_pattern;
      sv_syntax  = *h_syntax;

    } else {
      croak("re::engine::GNU: pattern must be a scalar, an array ref [syntax => pattern], or a hash ref {'syntax' => syntax, 'pattern' => pattern} where syntax and flavour are exclusive");
    }

    ri->sv_pattern_copy        = newSVsv(sv_pattern);
    ri->pattern_utf8           = SvPVutf8(ri->sv_pattern_copy, ri->len_pattern_utf8);
    ri->sv_victim_copy         = NULL;
    ri->victim_utf8            = NULL;

    ri->regex.buffer           = NULL;
    ri->regex.allocated        = 0;
    ri->regex.used             = 0;
    ri->regex.syntax           = (sv_syntax != NULL) ? SvUV(sv_syntax) : 0; /* == RE_SYNTAX_EMACS */
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
      ri->regex.newline_anchor = 1;
    }
#endif
#ifdef RXf_PMf_SINGLELINE
    /* /s */
    if ((flags & RXf_PMf_SINGLELINE) == RXf_PMf_SINGLELINE) {
      ri->regex.syntax |= RE_DOT_NEWLINE;
    } else {
      ri->regex.syntax &= ~RE_DOT_NEWLINE;
    }
#endif
#ifdef RXf_PMf_FOLD
    /* /i */
    if ((flags & RXf_PMf_FOLD) == RXf_PMf_FOLD) {
      ri->regex.syntax |= RE_ICASE;
    } else {
      ri->regex.syntax &= ~RE_ICASE;
    }
#endif
#ifdef RXf_PMf_EXTENDED
    /* /x */
    if ((flags & RXf_PMf_EXTENDED) == RXf_PMf_EXTENDED) {
      /* Not supported: explicitely removed */
      extflags &= ~RXf_PMf_EXTENDED;
    }
#endif
#ifdef RXf_PMf_KEEPCOPY
    /* /p */
    if ((flags & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY) {
      /* Not supported: explicitely removed */
      extflags &= ~RXf_PMf_KEEPCOPY;
    }
#endif

    /* REGEX structure for perl */
    Newxz(rx, 1, REGEXP);
#ifdef HAVE_REGEXP_REFCNT
    rx->refcnt = 1;
#endif

    re = RegSV(rx);
#ifdef HAVE_REGEXP_EXTFLAGS
    re->extflags = extflags;
#endif
#ifdef HAVE_REGEXP_ENGINE
    re->engine = &engine_GNU;
#endif
    /* Precompiled regexp for pp_regcomp to use */
#ifdef HAVE_REGEXP_PRELEN
    re->prelen = (I32)plen;
#endif
#ifdef HAVE_REGEXP_PRECOMP
    re->precomp = SAVEPVN(exp, re->prelen);
#endif
    /* qr// stringification, reuse the space */
#ifdef HAVE_REGEXP_WRAPLEN
#ifdef HAVE_REGEXP_PRELEN
    re->wraplen = re->prelen;
#endif
#endif
#ifdef HAVE_REGEXP_WRAPPED
#ifdef HAVE_REGEXP_PRECOMP
    re->wrapped = (char *)re->precomp; /* from const char* */
#endif
#endif

    ret = re_compile_internal (&(ri->regex), ri->pattern_utf8, ri->len_pattern_utf8, ri->regex.syntax);
    if (ret != _REG_NOERROR) {
      extern const char __re_error_msgid[];
      extern const size_t __re_error_msgid_idx[];
      croak("error compiling `%s': %s (error message truncated)", exp, __re_error_msgid + __re_error_msgid_idx[(int) ret]);
    }

/* #ifdef HAVE_REGEXP_PPRIVATE* / /* pprivate must always exist */
    re->pprivate = ri;
/* #endif */

#ifdef HAVE_REGEXP_NPARENS
    re->nparens = (U32)ri->regex.re_nsub; /* cast from size_t */
#endif

    /*
      Tell perl how many match vars we have and allocate space for
      them, at least one is always allocated for $&
     */
    Newxz(re->offs, re->nparens + 1, regexp_paren_pair);

    /* return the regexp structure to perl */
    return rx;
}

I32
GNU_exec(pTHX_ REGEXP * const rx, char *stringarg, char *strend, char *strbeg, I32 minend, SV * sv, void *data, U32 flags)
{
    regexp             *re = RegSV(rx);
    GNU_private_t      *ri = re->pprivate;
    regoff_t            offs;
    int                 i;
    struct re_registers regs;     /* for subexpression matches */

    regs.start = NULL;
    regs.end = NULL;

    offs = re_search(&(ri->regex), stringarg, strend - stringarg, strbeg - stringarg, strend - strbeg, &regs);

    if (offs <= -2) {
      croak("Internal error matching regular expression");
    } else if (offs == -1) {
      return 0;
    }

#ifdef HAVE_REGEXP_SUBBEG
    re->subbeg = strbeg;
#endif
#ifdef HAVE_REGEXP_SUBLEN
    re->sublen = strend - strbeg;
#endif
    /*
      re_search returns offsets from the start of `stringarg' but perl expects
      them to count from `strbeg'.
    */
    offs = stringarg - strbeg;

#ifdef HAVE_REGEXP_OFFS
    for (i = 0; i < regs.num_regs; i++) {
      re->offs[i].start = regs.start[i];
      re->offs[i].end = regs.end[i];
    }
    if (regs.num_regs < ri->regex.re_nsub) {
      for (i = regs.num_regs; i < ri->regex.re_nsub + 1; i++) {
        re->offs[i].start = -1;
        re->offs[i].end = -1;
      }
    }
#endif
#ifdef HAVE_REGEXP_LASTPAREN
    re->lastparen = i;
#endif

    if (regs.start != NULL) {
      free(regs.start);
    }
    if (regs.end != NULL) {
      free(regs.end);
    }

    return 1;
}

char *
GNU_intuit(pTHX_ REGEXP * const rx, SV * sv, char *strpos, char *strend, U32 flags, re_scream_pos_data *data)
{
  PERL_UNUSED_ARG(rx);
  PERL_UNUSED_ARG(sv);
  PERL_UNUSED_ARG(strpos);
  PERL_UNUSED_ARG(strend);
  PERL_UNUSED_ARG(flags);
  PERL_UNUSED_ARG(data);
  return NULL;
}

SV *
GNU_checkstr(pTHX_ REGEXP * const rx)
{
  PERL_UNUSED_ARG(rx);
  return NULL;
}

void
GNU_free(pTHX_ REGEXP * const rx)
{
  regexp             *re = RegSV(rx);
  GNU_private_t      *ri = re->pprivate;

  regfree(&(ri->regex));
}

#ifdef USE_ITHREADS
void *
GNU_dupe(pTHX_ REGEXP * const rx, CLONE_PARAMS *param)
{
  PERL_UNUSED_ARG(param);
  regexp             *re = RegSV(rx);

  return re->pprivate;
}
#endif

SV *
GNU_package(pTHX_ REGEXP * const rx)
{
  PERL_UNUSED_ARG(rx);
  return newSVpvs("re::engine::GNU");
}

MODULE = re::engine::GNU		PACKAGE = re::engine::GNU		
PROTOTYPES: ENABLE

void
ENGINE(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(PTR2IV(&engine_GNU))));
