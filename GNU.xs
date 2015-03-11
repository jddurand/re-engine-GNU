#define PERL_GET_NO_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "config_REGEXP.h"
#ifndef HAVE_REGEXP_PPRIVATE
#error "pprivate not found in structure regexp"
#endif

#include "config.h"
#include "regex.h"

#if PERL_VERSION > 10
#define _RegSV(p) SvANY(p)
#else
#define _RegSV(p) (p)
#endif

static regexp_engine engine_GNU;

typedef struct GNU_private {
  SV *sv_pattern_copy;

  char *pattern_utf8;
  STRLEN len_pattern_utf8;

  regex_t regex;
} GNU_private_t;

/*****************************************************************/
/* Just in case it does not exist - Copy of autodie/variables.xs */
/*****************************************************************/
#ifndef CopHINTHASH_get
#define CopHINTHASH_get(c) ((c)->cop_hints_hash)
#endif
#ifndef cophh_fetch_pvs
#ifdef STR_WITH_LEN
#define cophh_fetch_pvs(cophh, key, flags) Perl_refcounted_he_fetch(aTHX_ cophh, NULL, key, sizeof(key) - 1, 0, flags)
#else
#define cophh_fetch_pvs(cophh, key, flags) Perl_refcounted_he_fetch(aTHX_ cophh, NULL, STR_WITH_LEN(key), 0, flags)
#endif
#endif

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

/***************/
/* Util macros */
/***************/
#undef RX_EXTFLAGS_SET
#undef RX_EXTFLAGS_GET
#undef RX_EXTFLAGS_CAN
#ifndef RX_EXTFLAGS
  #ifdef HAVE_REGEXP_EXTFLAGS
    #define RX_EXTFLAGS(rx) (((struct regexp *) (rx))->extflags)
    #define RX_EXTFLAGS_SET(rx,x) RX_EXTFLAGS(rx) = (x)
    #define RX_EXTFLAGS_GET(rx) RX_EXTFLAGS(rx)
    #define RX_EXTFLAGS_CAN 1
  #else
    #define RX_EXTFLAGS(rx)
    #define RX_EXTFLAGS_SET(rx,x)
    #define RX_EXTFLAGS_GET(rx)
    #define RX_EXTFLAGS_CAN 0
  #endif
#else
  #define RX_EXTFLAGS_SET(rx,x) RX_EXTFLAGS(rx) = (x)
  #define RX_EXTFLAGS_GET(rx) RX_EXTFLAGS(rx)
  #define RX_EXTFLAGS_CAN 1
#endif

#undef RX_ENGINE_SET
#undef RX_ENGINE_GET
#undef RX_ENGINE_CAN
#ifndef RX_ENGINE
  #ifdef HAVE_REGEXP_ENGINE
    #define RX_ENGINE(rx) (((struct regexp *) (rx))->engine)
    #define RX_ENGINE_SET(rx,x) RX_ENGINE(rx) = (x)
    #define RX_ENGINE_GET(rx) RX_ENGINE(rx)
    #define RX_ENGINE_CAN 1
  #else
    #define RX_ENGINE(rx)
    #define RX_ENGINE_SET(rx,x)
    #define RX_ENGINE_GET(rx)
    #define RX_ENGINE_CAN 0
  #endif
#else
  #define RX_ENGINE_SET(rx,x) RX_ENGINE(rx) = (x)
  #define RX_ENGINE_GET(rx) RX_ENGINE(rx)
  #define RX_ENGINE_CAN 1
#endif

#undef RX_WRAPPED_SET
#undef RX_WRAPPED_GET
#undef RX_WRAPPED_CAN
#ifndef RX_WRAPPED
  #ifdef HAVE_REGEXP_WRAPPED
    #define RX_WRAPPED(rx) (((struct regexp *) (rx))->wrapped)
    #define RX_WRAPPED_SET(rx,x) RX_WRAPPED(rx) = (x)
    #define RX_WRAPPED_GET(rx) RX_WRAPPED(rx)
    #define RX_WRAPPED_CAN 1
  #else
    #define RX_WRAPPED(rx)
    #define RX_WRAPPED_SET(rx,x)
    #define RX_WRAPPED_GET(rx)
    #define RX_WRAPPED_CAN 0
  #endif
#else
  #define RX_WRAPPED_SET(rx,x) RX_WRAPPED(rx) = (x)
  #define RX_WRAPPED_GET(rx) RX_WRAPPED(rx)
  #define RX_WRAPPED_CAN 1
#endif

#undef RX_WRAPLEN_SET
#undef RX_WRAPLEN_GET
#undef RX_WRAPLEN_CAN
#ifndef RX_WRAPLEN
  #ifdef HAVE_REGEXP_WRAPLEN
    #define RX_WRAPLEN(rx) (((struct regexp *) (rx))->wraplen)
    #define RX_WRAPLEN_SET(rx,x) RX_WRAPLEN(rx) = (x)
    #define RX_WRAPLEN_GET(rx) RX_WRAPLEN(rx)
    #define RX_WRAPLEN_CAN 1
  #else
    #define RX_WRAPLEN(rx)
    #define RX_WRAPLEN_SET(rx,x)
    #define RX_WRAPLEN_GET(rx)
    #define RX_WRAPLEN_CAN 0
  #endif
#else
  #define RX_WRAPLEN_SET(rx,x) RX_WRAPLEN(rx) = (x)
  #define RX_WRAPLEN_GET(rx) RX_WRAPLEN(rx)
  #define RX_WRAPLEN_CAN 1
#endif

#undef RX_NPARENS_SET
#undef RX_NPARENS_GET
#undef RX_NPARENS_CAN
#ifndef RX_NPARENS
  #ifdef HAVE_REGEXP_NPARENS
    #define RX_NPARENS(rx) (((struct regexp *) (rx))->nparens)
    #define RX_NPARENS_SET(rx,x) RX_NPARENS(rx) = (x)
    #define RX_NPARENS_GET(rx) RX_NPARENS(rx)
    #define RX_NPARENS_CAN 1
  #else
    #define RX_NPARENS(rx)
    #define RX_NPARENS_SET(rx,x)
    #define RX_NPARENS_GET(rx)
    #define RX_NPARENS_CAN 0
  #endif
#else
  #define RX_NPARENS_SET(rx,x) RX_NPARENS(rx) = (x)
  #define RX_NPARENS_GET(rx) RX_NPARENS(rx)
  #define RX_NPARENS_CAN 1
#endif

#undef RX_LASTCLOSEPAREN_SET
#undef RX_LASTCLOSEPAREN_GET
#undef RX_LASTCLOSEPAREN_CAN
#ifndef RX_LASTCLOSEPAREN
  #ifdef HAVE_REGEXP_LASTCLOSEPAREN
    #define RX_LASTCLOSEPAREN(rx) (((struct regexp *) (rx))->lastcloseparen)
    #define RX_LASTCLOSEPAREN_SET(rx,x) RX_LASTCLOSEPAREN(rx) = (x)
    #define RX_LASTCLOSEPAREN_GET(rx) RX_LASTCLOSEPAREN(rx)
    #define RX_LASTCLOSEPAREN_CAN 1
  #else
    #define RX_LASTCLOSEPAREN(rx)
    #define RX_LASTCLOSEPAREN_SET(rx,x)
    #define RX_LASTCLOSEPAREN_GET(rx)
    #define RX_LASTCLOSEPAREN_CAN 0
  #endif
#else
  #define RX_LASTCLOSEPAREN_SET(rx,x) RX_LASTCLOSEPAREN(rx) = (x)
  #define RX_LASTCLOSEPAREN_GET(rx) RX_LASTCLOSEPAREN(rx)
  #define RX_LASTCLOSEPAREN_CAN 1
#endif

#undef RX_LASTPAREN_SET
#undef RX_LASTPAREN_GET
#undef RX_LASTPAREN_CAN
#ifndef RX_LASTPAREN
  #ifdef HAVE_REGEXP_LASTPAREN
    #define RX_LASTPAREN(rx) (((struct regexp *) (rx))->lastparen)
    #define RX_LASTPAREN_SET(rx,x) RX_LASTPAREN(rx) = (x)
    #define RX_LASTPAREN_GET(rx) RX_LASTPAREN(rx)
    #define RX_LASTPAREN_CAN 1
  #else
    #define RX_LASTPAREN(rx)
    #define RX_LASTPAREN_SET(rx,x)
    #define RX_LASTPAREN_GET(rx)
    #define RX_LASTPAREN_CAN 0
  #endif
#else
  #define RX_LASTPAREN_SET(rx,x) RX_LASTPAREN(rx) = (x)
  #define RX_LASTPAREN_GET(rx) RX_LASTPAREN(rx)
  #define RX_LASTPAREN_CAN 1
#endif

#undef RX_SUBBEG_SET
#undef RX_SUBBEG_GET
#undef RX_SUBBEG_CAN
#ifndef RX_SUBBEG
  #ifdef HAVE_REGEXP_SUBBEG
    #define RX_SUBBEG(rx) (((struct regexp *) (rx))->subbeg)
    #define RX_SUBBEG_SET(rx,x) RX_SUBBEG(rx) = (x)
    #define RX_SUBBEG_GET(rx) RX_SUBBEG(rx)
    #define RX_SUBBEG_CAN 1
  #else
    #define RX_SUBBEG(rx)
    #define RX_SUBBEG_SET(rx,x)
    #define RX_SUBBEG_GET(rx)
    #define RX_SUBBEG_CAN 0
  #endif
#else
  #define RX_SUBBEG_SET(rx,x) RX_SUBBEG(rx) = (x)
  #define RX_SUBBEG_GET(rx) RX_SUBBEG(rx)
  #define RX_SUBBEG_CAN 1
#endif

#undef RX_SUBLEN_SET
#undef RX_SUBLEN_GET
#undef RX_SUBLEN_CAN
#ifndef RX_SUBLEN
  #ifdef HAVE_REGEXP_SUBLEN
    #define RX_SUBLEN(rx) (((struct regexp *) (rx))->sublen)
    #define RX_SUBLEN_SET(rx,x) RX_SUBLEN(rx) = (x)
    #define RX_SUBLEN_GET(rx) RX_SUBLEN(rx)
    #define RX_SUBLEN_CAN 1
  #else
    #define RX_SUBLEN(rx)
    #define RX_SUBLEN_SET(rx,x)
    #define RX_SUBLEN_GET(rx)
    #define RX_SUBLEN_CAN 0
  #endif
#else
  #define RX_SUBLEN_SET(rx,x) RX_SUBLEN(rx) = (x)
  #define RX_SUBLEN_GET(rx) RX_SUBLEN(rx)
  #define RX_SUBLEN_CAN 1
#endif

#undef RX_OFFS_SET
#undef RX_OFFS_GET
#undef RX_OFFS_CAN
#ifndef RX_OFFS
  #ifdef HAVE_REGEXP_OFFS
    #define RX_OFFS(rx) (((struct regexp *) (rx))->offs)
    #define RX_OFFS_SET(rx,x) RX_OFFS(rx) = (x)
    #define RX_OFFS_GET(rx) RX_OFFS(rx)
    #define RX_OFFS_I_SET(rx,i,startValue,endValue) do { (RX_OFFS_GET(rx))[i].start = (startValue); (RX_OFFS_GET(rx))[i].end = (endValue); } while (0)
    #define RX_OFFS_CAN 1
  #else
    #define RX_OFFS(rx)
    #define RX_OFFS_SET(rx,x)
    #define RX_OFFS_GET(rx)
    #define RX_OFFS_I_SET(rx,i,start,end)
    #define RX_OFFS_CAN 0
  #endif
#else
  #define RX_OFFS_SET(rx,x) RX_OFFS(rx) = (x)
  #define RX_OFFS_GET(rx) RX_OFFS(rx)
  #define RX_OFFS_I_SET(rx,i,startValue,endValue) do { (RX_OFFS_GET(rx))[i].start = (startValue); (RX_OFFS_GET(rx))[i].end = (endValue); } while (0)
  #define RX_OFFS_CAN 1
#endif

#undef RX_PRELEN_SET
#undef RX_PRELEN_GET
#undef RX_PRELEN_CAN
#ifndef RX_PRELEN
  #ifdef HAVE_REGEXP_PRELEN
    #define RX_PRELEN(rx) (((struct regexp *) (rx))->prelen)
    #define RX_PRELEN_SET(rx,x) RX_PRELEN(rx) = (x)
    #define RX_PRELEN_GET(rx) RX_PRELEN(rx)
    #define RX_PRELEN_CAN 1
  #else
    #define RX_PRELEN(rx)
    #define RX_PRELEN_SET(rx,x)
    #define RX_PRELEN_GET(rx)
    #define RX_PRELEN_CAN 0
  #endif
#else
  #define RX_PRELEN_SET(rx,x) RX_PRELEN(rx) = (x)
  #define RX_PRELEN_GET(rx) RX_PRELEN(rx)
  #define RX_PRELEN_CAN 1
#endif

#undef RX_PRECOMP_SET
#undef RX_PRECOMP_GET
#undef RX_PRECOMP_CAN
#ifndef RX_PRECOMP
  #ifdef HAVE_REGEXP_PRECOMP
    #define RX_PRECOMP(rx) (((struct regexp *) (rx))->precomp)
    #define RX_PRECOMP_SET(rx,x) RX_PRECOMP(rx) = (x)
    #define RX_PRECOMP_GET(rx) RX_PRECOMP(rx)
    #define RX_PRECOMP_CAN 1
  #else
    #define RX_PRECOMP(rx)
    #define RX_PRECOMP_SET(rx,x)
    #define RX_PRECOMP_GET(rx)
    #define RX_PRECOMP_CAN 0
  #endif
#else
  #define RX_PRECOMP_SET(rx,x) RX_PRECOMP(rx) = (x)
  #define RX_PRECOMP_GET(rx) RX_PRECOMP(rx)
  #define RX_PRECOMP_CAN 1
#endif

#undef RXp_PAREN_NAMES_SET
#undef RXp_PAREN_NAMES_GET
#undef RXp_PAREN_NAMES_CAN
#ifndef RXp_PAREN_NAMES
  #ifdef HAVE_REGEXP_PAREN_NAMES
    #define RXp_PAREN_NAMES(rx) (((struct regexp *) (rx))->paren_names)
    #define RXp_PAREN_NAMES_SET(rx,x) RXp_PAREN_NAMES(rx) = (x)
    #define RXp_PAREN_NAMES_GET(rx) RXp_PAREN_NAMES(rx)
    #define RXp_PAREN_NAMES_CAN 1
  #else
    #define RXp_PAREN_NAMES(rx)
    #define RXp_PAREN_NAMES_SET(rx,x)
    #define RXp_PAREN_NAMES_GET(rx)
    #define RXp_PAREN_NAMES_CAN 0
  #endif
#else
  #define RXp_PAREN_NAMES_SET(rx,x) RXp_PAREN_NAMES(rx) = (x)
  #define RXp_PAREN_NAMES_GET(rx) RXp_PAREN_NAMES(rx)
  #define RXp_PAREN_NAMES_CAN 1
#endif

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
  }                                                              \
  value = 0;                                                     \
} while (0)

#ifdef HAVE_REGEXP_ENGINE_COMP
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
#if PERL_VERSION <= 10
REGEXP * GNU_comp(pTHX_ const SV * const pattern, const U32 flags)
#else
REGEXP * GNU_comp(pTHX_ SV * const pattern, const U32 flags)
#endif
{
    REGEXP                   *rx;
    regexp                   *re;
    GNU_private_t            *ri;
    int                       isDebug;
    char                     *logHeader = "[re::engine::GNU] GNU_comp";

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

#if RX_WRAPPED_CAN
    SV * wrapped; /* For stringification */
#endif

    GNU_key2int("re::engine::GNU::debug", isDebug);

    if (isDebug) {
      fprintf(stderr, "%s: %s", logHeader, "start\n");
    }

#if RX_WRAPPED_CAN
    if (isDebug) {
      fprintf(stderr, "%s: %s", logHeader, "allocating wrapped\n");
    }
    wrapped = newSVpvn("(?", 2);
    sv_2mortal(wrapped);
#endif

    /********************/
    /* GNU engine setup */
    /********************/
    if (isDebug) {
      fprintf(stderr, "%s: %s", logHeader, "allocating GNU_private_t\n");
    }
    Newxz(ri, 1, GNU_private_t);

    /* We accept in input:                                                  */
    /* - a scalar                                                           */
    /* - an arrayref with at least 2 members: the syntax and the pattern    */
    /* - a hash with with at least the key 'pattern', eventually 'syntax'   */

    if (pattern_type == SCALAR) {

      sv_pattern = newSVsv((SV *)pattern);

    } else if (pattern_type == ARRAYREF) {
      AV *av = (AV *)SvRV(pattern);
      SV **a_pattern;
      SV **a_syntax;

      if (av_len(av) < 1) {
        croak("re::engine::GNU: array ref must have at least two elements, i.e. [syntax => pattern]");
      }
      a_pattern = av_fetch(av, 1, 1);
      a_syntax = av_fetch(av, 0, 1);

      if (a_pattern == NULL || get_type((SV *)*a_pattern) != SCALAR) {
        croak("re::engine::GNU: array ref must have a scalar as second element, got %d", get_type((SV *)a_pattern));
      }
      if (a_syntax == NULL || get_type((SV *)*a_syntax) != SCALAR) {
        croak("re::engine::GNU: array ref must have a scalar as first element, got %d", get_type((SV *)a_syntax));
      }

      sv_pattern = newSVsv(*a_pattern);
      sv_syntax  = newSVsv(*a_syntax);

    } else if (pattern_type == HASHREF) {
      HV  *hv        = (HV *)SvRV(pattern);
      SV **h_pattern = hv_fetch(hv, "pattern", 7, 0);
      SV **h_syntax  = hv_fetch(hv, "syntax", 6, 0);

      if (h_pattern == NULL || get_type((SV *)*h_pattern) != SCALAR) {
        croak("re::engine::GNU: hash ref key must have a key 'pattern' refering to a scalar");
      }
      if (h_syntax == NULL || get_type((SV *)*h_syntax) != SCALAR) {
        croak("re::engine::GNU: hash ref key must have a key 'syntax' refering to a scalar");
      }

      sv_pattern = newSVsv(*h_pattern);
      sv_syntax  = newSVsv(*h_syntax);

    } else {
      croak("re::engine::GNU: pattern must be a scalar, an array ref [syntax => pattern], or a hash ref {'syntax' => syntax, 'pattern' => pattern} where syntax and flavour are exclusive");
    }

    exp = SvPV(sv_pattern, plen);

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

    ri->sv_pattern_copy        = sv_pattern;
    ri->pattern_utf8           = SvPVutf8(ri->sv_pattern_copy, ri->len_pattern_utf8);

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

    if (sv_syntax != NULL) {
      SvREFCNT_dec(sv_syntax);
      sv_syntax = NULL;
    }
   

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
#if PERL_VERSION > 10
    rx = (REGEXP*) newSV_type(SVt_REGEXP);
#else
    Newxz(rx, 1, REGEXP);
#endif

    /* struct regexp (same adress as rx, different cast) */
    re = _RegSV(rx);

#if PERL_VERSION <= 10
#ifdef HAVE_REGEXP_REFCNT
    re->refcnt = 1;
#endif
#endif

    RX_EXTFLAGS_SET(rx, extflags);
    RX_ENGINE_SET(rx, &engine_GNU);

    /* AFAIK prelen and precomp macros do not always provide an lvalue */
    /*
    RX_PRELEN_SET(rx, (I32)plen);
    RX_PRECOMP_SET(rx, (exp != NULL) ? savepvn(exp, plen) : NULL);
    */

    ret = re_compile_internal (&(ri->regex), ri->pattern_utf8, ri->len_pattern_utf8, ri->regex.syntax);
    if (ret != _REG_NOERROR) {
      extern const char __re_error_msgid[];
      extern const size_t __re_error_msgid_idx[];
      croak("%s", __re_error_msgid + __re_error_msgid_idx[(int) ret]);
    }

    re->pprivate = ri;
#if RXp_PAREN_NAMES_CAN
    /* Not supported */
    /* RXp_PAREN_NAMES_SET(re, newHV()); */
#endif
    RX_LASTPAREN_SET(rx, 0);
    RX_LASTCLOSEPAREN_SET(rx, 0);
    RX_NPARENS_SET(rx, (U32)ri->regex.re_nsub); /* cast from size_t */

    /* qr// stringification */
#if RX_WRAPPED_CAN
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
    sv_catpvn(wrapped, "(?#re::engine::GNU)", 19);
    sv_catpvn(wrapped, exp, plen);
    sv_catpvn(wrapped, ")", 1);
    RX_WRAPPED_SET(rx, savepvn(SvPVX(wrapped), SvCUR(wrapped)));
    RX_WRAPLEN_SET(rx, SvCUR(wrapped));
#endif

    /*
      Tell perl how many match vars we have and allocate space for
      them, at least one is always allocated for $&
     */
    Newxz(re->offs, RX_NPARENS_GET(rx) + 1, regexp_paren_pair);

    /* return the regexp structure to perl */
    return rx;
}
#endif /* HAVE_REGEXP_ENGINE_COMP */

#ifdef HAVE_REGEXP_ENGINE_EXEC
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
I32
#if PERL_VERSION >= 19
GNU_exec(pTHX_ REGEXP * const rx, char *stringarg, char *strend, char *strbeg, SSize_t minend, SV * sv, void *data, U32 flags)
#else
GNU_exec(pTHX_ REGEXP * const rx, char *stringarg, char *strend, char *strbeg, I32 minend, SV * sv, void *data, U32 flags)
#endif
{
    regexp             *re = _RegSV(rx);
    GNU_private_t      *ri = re->pprivate;
    regoff_t            rc;
    U32                 i;
    struct re_registers regs;     /* for subexpression matches */

    regs.num_regs = 0;
    regs.start = NULL;
    regs.end = NULL;

    rc = re_search(&(ri->regex), stringarg, strend - stringarg, strbeg - stringarg, strend - strbeg, &regs);

    if (rc <= -2) {
      croak("Internal error matching regular expression");
    } else if (rc == -1) {
      return 0;
    }

    RX_SUBBEG_SET(rx, strbeg);
    RX_SUBLEN_SET(rx, strend - strbeg);
    RX_LASTPAREN_SET(rx, RX_NPARENS_GET(rx));
    RX_LASTCLOSEPAREN_SET(rx, RX_NPARENS_GET(rx));

    /* There is always at least the index 0 for $& */
    for (i = 0; i < RX_NPARENS_GET(rx) + 1; i++) {
      RX_OFFS_I_SET(rx, i, regs.start[i], regs.end[i]);
    }

    if (regs.start != NULL) {
      _libc_free(regs.start);
    }

    if (regs.end != NULL) {
      _libc_free(regs.end);
    }

    return 1;
}
#endif /* HAVE_REGEXP_ENGINE_EXEC */

#ifdef HAVE_REGEXP_ENGINE_INTUIT
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
char *
#if PERL_VERSION >= 19
GNU_intuit(pTHX_ REGEXP * const rx, SV * sv, const char *strbeg, char *strpos, char *strend, U32 flags, re_scream_pos_data *data)
#else
GNU_intuit(pTHX_ REGEXP * const rx, SV * sv, char *strpos, char *strend, U32 flags, re_scream_pos_data *data)
#endif
{
  PERL_UNUSED_ARG(rx);
  PERL_UNUSED_ARG(sv);
#if PERL_VERSION >= 19
  PERL_UNUSED_ARG(strbeg);
#endif
  PERL_UNUSED_ARG(strpos);
  PERL_UNUSED_ARG(strend);
  PERL_UNUSED_ARG(flags);
  PERL_UNUSED_ARG(data);

  return NULL;
}
#endif

#ifdef HAVE_REGEXP_ENGINE_CHECKSTR
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
SV *
GNU_checkstr(pTHX_ REGEXP * const rx)
{
  PERL_UNUSED_ARG(rx);
  return NULL;
}
#endif

#ifdef HAVE_REGEXP_ENGINE_FREE
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
void
GNU_free(pTHX_ REGEXP * const rx)
{
  regexp             *re = _RegSV(rx);
  GNU_private_t      *ri = re->pprivate;

  SvREFCNT_dec(ri->sv_pattern_copy);
  regfree(&(ri->regex));
}
#endif

#ifdef HAVE_REGEXP_ENGINE_QR_PACKAGE
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
SV *
GNU_qr_package(pTHX_ REGEXP * const rx)
{
  PERL_UNUSED_ARG(rx);

  return newSVpvs("re::engine::GNU");
}
#endif

#ifdef HAVE_REGEXP_ENGINE_DUPE
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
void *
GNU_dupe(pTHX_ REGEXP * const rx, CLONE_PARAMS *param)
{
  regexp        *re = _RegSV(rx);
  GNU_private_t *oldri = (GNU_private_t *) re->pprivate;
  GNU_private_t *ri;
  reg_errcode_t  ret;

  PERL_UNUSED_ARG(param);

  Newxz(ri, 1, GNU_private_t);

  ri->sv_pattern_copy = newSVsv(oldri->sv_pattern_copy);
  ri->pattern_utf8    = SvPVutf8(ri->sv_pattern_copy, ri->len_pattern_utf8);

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

  ret = re_compile_internal (&(ri->regex), ri->pattern_utf8, ri->len_pattern_utf8, ri->regex.syntax);
  if (ret != _REG_NOERROR) {
    extern const char __re_error_msgid[];
    extern const size_t __re_error_msgid_idx[];
    croak("%s", __re_error_msgid + __re_error_msgid_idx[(int) ret]);
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
