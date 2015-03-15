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

/* Few compatibility issues */
#if PERL_VERSION > 10
#  define _RegSV(p) SvANY(p)
#else
#  define _RegSV(p) (p)
#endif

#ifndef PM_GETRE
#  define PM_GETRE(o) ((o)->op_pmregexp)
#endif

#ifndef PERL_UNUSED_VAR
#  define PERL_UNUSED_VAR(x) ((void)x)
#endif

#ifndef PERL_UNUSED_ARG
#  define PERL_UNUSED_ARG(x) PERL_UNUSED_VAR(x)
#endif

#ifndef sv_setsv_cow
#  define sv_setsv_cow(a,b) Perl_sv_setsv_cow(aTHX_ a,b)
#endif

#ifndef RX_MATCH_TAINTED_off
#  ifdef RXf_TAINTED_SEEN
#    ifdef NO_TAINT_SUPPORT
#      define RX_MATCH_TAINTED_off(x)
#    else
#      define RX_MATCH_TAINTED_off(x) (RX_EXTFLAGS_SET(x, RX_EXTFLAGS_GET(x) & ~RXf_TAINTED_SEEN))
#    endif
#  else
#    define RX_MATCH_TAINTED_off(x)
#  endif
#endif

#ifndef RX_MATCH_UTF8_set
#  ifdef RXf_MATCH_UTF8
#    define RX_MATCH_UTF8_set(x, t) ((t) ? (RX_EXTFLAGS_SET(x, RX_EXTFLAGS_GET(x) |= RXf_MATCH_UTF8)) :(RX_EXTFLAGS_SET(x, RX_EXTFLAGS_GET(x) &= ~RXf_MATCH_UTF8)))
#  else
#    define RX_MATCH_UTF8_set(x, t)
#  endif
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

#undef RX_SAVED_COPY_SET
#undef RX_SAVED_COPY_GET
#undef RX_SAVED_COPY_CAN
#ifndef RX_SAVED_COPY
  #ifdef HAVE_REGEXP_SAVED_COPY
    #define RX_SAVED_COPY(rx) (((struct regexp *) (rx))->saved_copy)
    #define RX_SAVED_COPY_SET(rx,x) RX_SAVED_COPY(rx) = (x)
    #define RX_SAVED_COPY_GET(rx) RX_SAVED_COPY(rx)
    #define RX_SAVED_COPY_CAN 1
  #else
    #define RX_SAVED_COPY(rx)
    #define RX_SAVED_COPY_SET(rx,x)
    #define RX_SAVED_COPY_GET(rx)
    #define RX_SAVED_COPY_CAN 0
  #endif
#else
  #define RX_SAVED_COPY_SET(rx,x) RX_SAVED_COPY(rx) = (x)
  #define RX_SAVED_COPY_GET(rx) RX_SAVED_COPY(rx)
  #define RX_SAVED_COPY_CAN 1
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

#undef RX_SUBOFFSET_SET
#undef RX_SUBOFFSET_GET
#undef RX_SUBOFFSET_CAN
#ifndef RX_SUBOFFSET
  #ifdef HAVE_REGEXP_SUBOFFSET
    #define RX_SUBOFFSET(rx) (((struct regexp *) (rx))->suboffset)
    #define RX_SUBOFFSET_SET(rx,x) RX_SUBOFFSET(rx) = (x)
    #define RX_SUBOFFSET_GET(rx) RX_SUBOFFSET(rx)
    #define RX_SUBOFFSET_CAN 1
  #else
    #define RX_SUBOFFSET(rx)
    #define RX_SUBOFFSET_SET(rx,x)
    #define RX_SUBOFFSET_GET(rx)
    #define RX_SUBOFFSET_CAN 0
  #endif
#else
  #define RX_SUBOFFSET_SET(rx,x) RX_SUBOFFSET(rx) = (x)
  #define RX_SUBOFFSET_GET(rx) RX_SUBOFFSET(rx)
  #define RX_SUBOFFSET_CAN 1
#endif

#undef RX_SUBCOFFSET_SET
#undef RX_SUBCOFFSET_GET
#undef RX_SUBCOFFSET_CAN
#ifndef RX_SUBCOFFSET
  #ifdef HAVE_REGEXP_SUBCOFFSET
    #define RX_SUBCOFFSET(rx) (((struct regexp *) (rx))->subcoffset)
    #define RX_SUBCOFFSET_SET(rx,x) RX_SUBCOFFSET(rx) = (x)
    #define RX_SUBCOFFSET_GET(rx) RX_SUBCOFFSET(rx)
    #define RX_SUBCOFFSET_CAN 1
  #else
    #define RX_SUBCOFFSET(rx)
    #define RX_SUBCOFFSET_SET(rx,x)
    #define RX_SUBCOFFSET_GET(rx)
    #define RX_SUBCOFFSET_CAN 0
  #endif
#else
  #define RX_SUBCOFFSET_SET(rx,x) RX_SUBCOFFSET(rx) = (x)
  #define RX_SUBCOFFSET_GET(rx) RX_SUBCOFFSET(rx)
  #define RX_SUBCOFFSET_CAN 1
#endif

#undef RX_OFFS_SET
#undef RX_OFFS_GET
#undef RX_OFFS_CAN
#ifndef RX_OFFS
  #ifdef HAVE_REGEXP_OFFS
    #define RX_OFFS(rx) (((struct regexp *) (rx))->offs)
    #define RX_OFFS_SET(rx,x) RX_OFFS(rx) = (x)
    #define RX_OFFS_GET(rx) RX_OFFS(rx)
    #define RX_OFFS_I_GET(rx,i) (RX_OFFS_GET(rx))[i]
    #define RX_OFFS_I_SET(rx,i,startValue,endValue) do { (RX_OFFS_GET(rx))[i].start = (startValue); (RX_OFFS_GET(rx))[i].end = (endValue); } while (0)
    #define RX_OFFS_CAN 1
  #else
    #define RX_OFFS(rx)
    #define RX_OFFS_SET(rx,x)
    #define RX_OFFS_GET(rx)
    #define RX_OFFS_I_GET(rx,i)
    #define RX_OFFS_I_SET(rx,i,start,end)
    #define RX_OFFS_CAN 0
  #endif
#else
  #define RX_OFFS_SET(rx,x) RX_OFFS(rx) = (x)
  #define RX_OFFS_GET(rx) RX_OFFS(rx)
  #define RX_OFFS_I_GET(rx,i) (RX_OFFS_GET(rx))[i]
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
  } else {                                                       \
    value = 0;                                                   \
  }                                                              \
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
    int                       defaultSyntax;
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

    GNU_key2int("re::engine::GNU/debug", isDebug);
    GNU_key2int("re::engine::GNU/syntax", defaultSyntax);

    if (isDebug) {
      fprintf(stderr, "%s: pattern=%p flags=0x%lx\n", logHeader, pattern, (unsigned long) flags);
      fprintf(stderr, "%s: ... default syntax: %d\n", logHeader, defaultSyntax);
    }

#if RX_WRAPPED_CAN
    if (isDebug) {
      fprintf(stderr, "%s: ... allocating wrapped\n", logHeader);
    }
    wrapped = newSVpvn("(?", 2);
    sv_2mortal(wrapped);
#endif

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

      sv_pattern = newSVsv((SV *)pattern);

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

      sv_pattern = newSVsv(*a_pattern);
      sv_syntax  = newSVsv(*a_syntax);

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

      sv_pattern = newSVsv(*h_pattern);
      sv_syntax  = newSVsv(*h_syntax);

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

    ri->sv_pattern_copy        = sv_pattern;
    ri->pattern_utf8           = SvPVutf8(ri->sv_pattern_copy, ri->len_pattern_utf8);

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

    if (sv_syntax != NULL) {
      SvREFCNT_dec(sv_syntax);
      sv_syntax = NULL;
    }
   

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

    if (isDebug) {
      fprintf(stderr, "%s: ... re_compile_internal(preg=%p, pattern=%p, length=%d, syntax=0x%lx)\n", logHeader, &(ri->regex), ri->pattern_utf8, (int) ri->len_pattern_utf8, (unsigned long) ri->regex.syntax);
    }
    ret = re_compile_internal (&(ri->regex), ri->pattern_utf8, ri->len_pattern_utf8, ri->regex.syntax);
    if (ret != _REG_NOERROR) {
      extern const char __re_error_msgid[];
      extern const size_t __re_error_msgid_idx[];
      croak("%s: %s", logHeader, __re_error_msgid + __re_error_msgid_idx[(int) ret]);
    }

    re->pprivate = ri;
#if RXp_PAREN_NAMES_CAN
    /* Not supported */
    /* RXp_PAREN_NAMES_SET(re, newHV()); */
#endif
    RX_LASTPAREN_SET(rx, 0);
    RX_LASTCLOSEPAREN_SET(rx, 0);
    RX_NPARENS_SET(rx, (U32)ri->regex.re_nsub); /* cast from size_t */
    if (isDebug) {
      fprintf(stderr, "%s: ... %d () detected\n", logHeader, (int) ri->regex.re_nsub);
    }

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
    RX_WRAPPED_SET(rx, savepvn(SvPVX(wrapped), SvCUR(wrapped)));
    RX_WRAPLEN_SET(rx, SvCUR(wrapped));
    if (isDebug) {
      fprintf(stderr, "%s: ... stringification to %s\n", logHeader, RX_WRAPPED_GET(rx));
    }
#endif

    /*
      Tell perl how many match vars we have and allocate space for
      them, at least one is always allocated for $&
     */
    Newxz(RX_OFFS_GET(rx), RX_NPARENS_GET(rx) + 1, regexp_paren_pair);

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

static void
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

#ifdef REXEC_COPY_STR
    if ((flags & REXEC_COPY_STR) == REXEC_COPY_STR) {
#if (defined(PERL_ANY_COW) && defined(SvCANCOW) && defined(SvIsCOW) && defined(RXf_COPY_DONE) && defined(RX_MATCH_COPY_FREE))
#if RX_SAVED_COPY_CAN && RX_EXTFLAGS_CAN && RX_SUBBEG_CAN && RX_SUBLEN_CAN && RX_SUBOFFSET_CAN && RX_SUBCOFFSET_CAN
        if (SvCANCOW(sv)) {
            /* Create a new COW SV to share the match string and store
             * in saved_copy, unless the current COW SV in saved_copy
             * is valid and suitable for our purpose */
          if ((   RX_SAVED_COPY_GET(rx) != NULL
                 && SvIsCOW(RX_SAVED_COPY_GET(rx))
                 && SvPOKp(RX_SAVED_COPY_GET(rx))
                 && SvIsCOW(sv)
                 && SvPOKp(sv)
                 && SvPVX(sv) == SvPVX(RX_SAVED_COPY_GET(rx))))
            {
                /* just reuse saved_copy SV */
              if (isDebug) {
                fprintf(stderr, "%s: ... reusing save_copy SV\n", logHeader);
              }
              if ((RX_EXTFLAGS_GET(rx) & RXf_COPY_DONE) == RXf_COPY_DONE) {
                Safefree(RX_SUBBEG_GET(rx));
                RX_EXTFLAGS_SET(rx, RX_EXTFLAGS_GET(rx) & ~RXf_COPY_DONE);
              }
            }
          else {
            /* create new COW SV to share string */
            if (isDebug) {
              fprintf(stderr, "%s: ... creating new COW sv\n", logHeader);
            }
            RX_MATCH_COPY_FREE(rx);
            RX_SAVED_COPY_SET(rx, sv_setsv_cow(RX_SAVED_COPY_GET(rx), sv));
          }
          RX_SUBBEG_SET(rx, (char *)SvPVX_const(RX_SAVED_COPY_GET(rx)));
          RX_SUBLEN_SET(rx, strend - strbeg);
          RX_SUBOFFSET_SET(rx, 0);
          RX_SUBCOFFSET_SET(rx, 0);
          if (isDebug) {
            fprintf(stderr, "%s: ... subbeg=%p, sublen=%d, suboffset=%d, subcoffset=%d\n", logHeader, RX_SUBBEG_GET(rx), RX_SUBLEN_GET(rx), RX_SUBOFFSET_GET(rx), RX_SUBCOFFSET_GET(rx));
          }
        } else
#endif /* RX_SAVED_COPY_CAN && RX_EXTFLAGS_CAN && RX_SUBBEG_CAN && RX_SUBLEN_CAN && RX_SUBOFFSET_CAN && RX_SUBCOFFSET_CAN*/
#endif /* PERL_ANY_COW && SvCANCOW && SvIsCOW && RXf_COPY_DONE && RX_MATCH_COPY_FREE */
        {
#if (defined(REXEC_COPY_SKIP_POST) && defined(RXf_PMf_KEEPCOPY) && defined(PL_sawampersand) && defined(SAWAMPERSAND_RIGHT) && defined(SAWAMPERSAND_LEFT) && defined(REXEC_COPY_SKIP_PRE) && defined(RX_MATCH_COPIED) && defined(RX_MATCH_COPIED_on))
#if RX_EXTFLAGS_CAN && RX_LASTPAREN_CAN && RX_OFFS_CAN && RX_SUBLEN_CAN && RX_SUBBEG_CAN && RX_SUBOFFSET_CAN
            SSize_t min = 0;
            SSize_t max = strend - strbeg;
            SSize_t sublen;

            if (    ((flags & REXEC_COPY_SKIP_POST) == REXEC_COPY_SKIP_POST)
                    && !((RX_EXTFLAGS_GET(rx) & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY) /* //p */
                    && !((PL_sawampersand & SAWAMPERSAND_RIGHT) == SAWAMPERSAND_RIGHT)
                    ) { /* don't copy $' part of string */
              U32 n = 0;
              max = -1;
              /* calculate the right-most part of the string covered
               * by a capture. Due to look-ahead, this may be to
               * the right of $&, so we have to scan all captures */
              if (isDebug) {
                fprintf(stderr, "%s: ... calculate right-most part of the string coverred by a capture\n", logHeader);
              }
              while (n <= RX_LASTPAREN_GET(rx)) {
                if (RX_OFFS_I_GET(rx, n).end > max) {
                  max = RX_OFFS_I_GET(rx, n).end;
                }
                n++;
              }
              if (max == -1)
                max = ((PL_sawampersand & SAWAMPERSAND_LEFT) == SAWAMPERSAND_LEFT)
                  ? RX_OFFS_I_GET(rx, 0).start
                  : 0;
            }

            if (    ((flags & REXEC_COPY_SKIP_PRE) == REXEC_COPY_SKIP_PRE)
                    && !((RX_EXTFLAGS_GET(rx) & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY) /* //p */
                    && !((PL_sawampersand & SAWAMPERSAND_LEFT) == SAWAMPERSAND_LEFT)
                    ) { /* don't copy $` part of string */
              U32 n = 0;
              min = max;
              /* calculate the left-most part of the string covered
               * by a capture. Due to look-behind, this may be to
               * the left of $&, so we have to scan all captures */
              if (isDebug) {
                fprintf(stderr, "%s: ... calculate left-most part of the string coverred by a capture\n", logHeader);
              }
              while (min && n <= RX_LASTPAREN_GET(rx)) {
                if (   RX_OFFS_I_GET(rx, n).start != -1
                       && RX_OFFS_I_GET(rx, n).start < min)
                  {
                    min = RX_OFFS_I_GET(rx, n).start;
                  }
                n++;
              }
              if (((PL_sawampersand & SAWAMPERSAND_RIGHT) == SAWAMPERSAND_RIGHT)
                  && min > RX_OFFS_I_GET(rx, 0).end
                  )
                min = RX_OFFS_I_GET(rx, 0).end;
            }

            sublen = max - min;

            if (RX_MATCH_COPIED(rx)) {
              if (sublen > RX_SUBLEN_GET(rx))
                RX_SUBBEG_SET(rx, (char*)saferealloc(RX_SUBBEG_GET(rx), sublen+1));
            }
            else {
              RX_SUBBEG_SET(rx, (char*)safemalloc(sublen+1));
            }
            Copy(strbeg + min, RX_SUBBEG_GET(rx), sublen, char);
            RX_SUBBEG_GET(rx)[sublen] = '\0';
            RX_SUBOFFSET_SET(rx, min);
            RX_SUBLEN_SET(rx, sublen);
            RX_MATCH_COPIED_on(rx);
            if (isDebug) {
              fprintf(stderr, "%s: ... subbeg=%p, suboffset=%d, sublen=%d\n", logHeader, RX_SUBBEG_GET(rx), RX_SUBCOFFSET_GET(rx), RX_SUBLEN_GET(rx));
            }
#endif /* RX_EXTFLAGS_CAN && RX_LASTPAREN_CAN && RX_OFFS_CAN */
#endif /* REXEC_COPY_SKIP_POST && RXf_PMf_KEEPCOPY && PL_sawampersand && SAWAMPERSAND_RIGHT && SAWAMPERSAND_LEFT && REXEC_COPY_SKIP_PRE */
        }
#if RX_SUBCOFFSET_CAN && RX_SUBOFFSET_CAN
        RX_SUBCOFFSET_SET(rx, RX_SUBOFFSET_GET(rx));
        if (RX_SUBOFFSET_GET(rx) != 0 && utf8_target != 0) {
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
            RX_SUBCOFFSET_SET(rx, sv_pos_b2u_flags(sv, RX_SUBCOFFSET_GET(rx),
                                                   SV_GMAGIC|SV_CONST_RETURN));
          else
#endif
            RX_SUBCOFFSET_SET(rx, utf8_length((U8*)strbeg,
                                              (U8*)(strbeg + RX_SUBOFFSET_GET(rx))));
        }
        if (isDebug) {
          fprintf(stderr, "%s: ... suboffset=%d and utf8target=%d => subcoffset=%d\n", logHeader, RX_SUBOFFSET_GET(rx), (int) utf8_target, RX_SUBCOFFSET_GET(rx));
        }
#endif /* RX_SUBCOFFSET_CAN && RX_SUBOFFSET_CAN */
    }
    else {
#endif /* REXEC_COPY_STR */
#ifdef RX_MATCH_COPY_FREE
        RX_MATCH_COPY_FREE(rx);
#if RX_SUBBEG_CAN && RX_SUBOFFSET_CAN && RX_SUBCOFFSET_CAN && RX_SUBLEN_CAN
        RX_SUBBEG_SET(rx, strbeg);
        RX_SUBOFFSET_SET(rx, 0);
        RX_SUBCOFFSET_SET(rx, 0);
        RX_SUBLEN_SET(rx, strend - strbeg);
#endif /* RX_SUBBEG_CAN && RX_SUBOFFSET_CAN && RX_SUBCOFFSET_CAN && RX_SUBLEN_CAN */
#endif /* RX_MATCH_COPY_FREE */
#ifdef REXEC_COPY_STR
    }
#endif

  if (isDebug) {
    fprintf(stderr, "%s: return void\n", logHeader);
  }

}

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
    int                 isDebug;
    char               *logHeader = "[re::engine::GNU] GNU_exec";
    short               utf8_target = DO_UTF8(sv) ? 1 : 0;

    regs.num_regs = 0;
    regs.start = NULL;
    regs.end = NULL;

    GNU_key2int("re::engine::GNU/debug", isDebug);

    if (isDebug) {
      fprintf(stderr, "%s: rx=%p, stringarg=%p, strend=%p, strbeg=%p, minend=%d, sv=%p, data=%p, flags=0x%lx\n", logHeader, rx, stringarg, strend, strbeg, (int) minend, sv, data, (unsigned long) flags);
    }

    if (isDebug) {
      fprintf(stderr, "%s: ... re_search(bufp=%p, string=%p, length=%d, start=%d, range=%d, regs=%p)\n", logHeader, &(ri->regex), strbeg, (int) (strend - strbeg), (int) (stringarg - strbeg), (int) (strend - stringarg), &regs);
    }
    rc = re_search(&(ri->regex), strbeg, strend - strbeg, stringarg - strbeg, strend - stringarg, &regs);

    if (rc <= -2) {
      croak("%s: Internal error in re_search()", logHeader);
    } else if (rc == -1) {
      if (isDebug) {
        fprintf(stderr, "%s: return 0 (no match)\n", logHeader);
      }
      return 0;
    }

    /* Why isn't it done by the higher level ? */
    RX_MATCH_TAINTED_off(rx);
    RX_MATCH_UTF8_set(rx, utf8_target);

    RX_LASTPAREN_SET(rx, RX_NPARENS_GET(rx));
    RX_LASTCLOSEPAREN_SET(rx, RX_NPARENS_GET(rx));

    /* There is always at least the index 0 for $& */
    for (i = 0; i < RX_NPARENS_GET(rx) + 1; i++) {
        if (isDebug) {
          I32 start = (I32) utf8_distance(strbeg + regs.start[i], strbeg);
          I32 end   = (I32) utf8_distance(strbeg + regs.end[i],   strbeg);
          fprintf(stderr, "%s: ... Match No %d positions: bytes=[%d,%d], characters=[%d,%d]\n", logHeader, i, (int) regs.start[i], (int) regs.end[i], (int) utf8_distance(strbeg + regs.start[i], strbeg), (int) utf8_distance(strbeg + regs.end[i], strbeg));
        }
        /* It ASSUMED that RX_OFFS_CAN is 1 */
        RX_OFFS_I_SET(rx, i, regs.start[i], regs.end[i]);
    }

#ifdef REXEC_NOT_FIRST
    if ( !(flags & REXEC_NOT_FIRST) ) {
      GNU_exec_set_capture_string(aTHX_ rx, strbeg, strend, sv, flags, utf8_target);
    }
#endif

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
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
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
  int                isDebug;
  char              *logHeader = "[re::engine::GNU] GNU_free";

  GNU_key2int("re::engine::GNU/debug", isDebug);

  if (isDebug) {
    fprintf(stderr, "%s: rx=%p\n", logHeader, rx);
  }

  SvREFCNT_dec(ri->sv_pattern_copy);
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
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
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
