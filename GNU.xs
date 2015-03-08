#define PERL_GET_NO_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "config_REGEXP.h"

#include "config.h"
#include "regex.h"

#if PERL_VERSION > 10
#define _RegSV(p) SvANY(p)
#else
#define _RegSV(p) (p)
#endif

#define _SAVEPVN(p,n) ((p) ? savepvn(p,n) : NULL)

static regexp_engine engine_GNU;

typedef struct GNU_private {
  SV *sv_pattern_copy;

  char *pattern_utf8;
  STRLEN len_pattern_utf8;

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

/* Call to malloc free() */
#ifdef free
#define _SAVE_FREE_DEFINITION free
#undef free
#else
#undef _SAVE_FREE_DEFINITION
#endif
static void _libc_free(void *ptr) {
  free(ptr);
}
#ifdef _SAVE_FREE_DEFINITION
#define free _SAVE_FREE_DEFINITION
#endif

#ifdef HAVE_REGEXP_ENGINE_COMP
static
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
    IV pattern_type = get_type((SV *)pattern);
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

      if (h_pattern == NULL || get_type((SV *)*h_pattern) != SCALARREF) {
        croak("re::engine::GNU: hash ref key must have a key 'pattern' refering to a scalar");
      }
      if (h_syntax == NULL || get_type((SV *)*h_syntax) != SCALARREF) {
        croak("re::engine::GNU: hash ref key must have a key 'syntax' refering to a scalar");
      }

      sv_pattern = newSVsv(*h_pattern);
      sv_syntax  = newSVsv(*h_syntax);

    } else {
      croak("re::engine::GNU: pattern must be a scalar, an array ref [syntax => pattern], or a hash ref {'syntax' => syntax, 'pattern' => pattern} where syntax and flavour are exclusive");
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
#ifdef HAVE_REGEXP_REFCNT
    rx->refcnt = 1;
#endif
#endif

    re = _RegSV(rx);
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
    re->precomp = _SAVEPVN(exp, re->prelen);
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
      croak("%s", __re_error_msgid + __re_error_msgid_idx[(int) ret]);
    }

/* #ifdef HAVE_REGEXP_PPRIVATE */ /* pprivate must always exist */
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
#endif /* HAVE_REGEXP_ENGINE_COMP */

#ifdef HAVE_REGEXP_ENGINE_EXEC
static
I32
#if PERL_VERSION >= 19
GNU_exec(pTHX_ REGEXP * const rx, char *stringarg, char *strend, char *strbeg, SSize_t minend, SV * sv, void *data, U32 flags)
#else
GNU_exec(pTHX_ REGEXP * const rx, char *stringarg, char *strend, char *strbeg, I32 minend, SV * sv, void *data, U32 flags)
#endif
{
    regexp             *re = _RegSV(rx);
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
    /* There is always at least the index 0 for $& */
    for (i = 0; i < re->nparens + 1; i++) {
      re->offs[i].start = regs.start[i];
      re->offs[i].end = regs.end[i];
    }
#endif
#ifdef HAVE_REGEXP_LASTPAREN
    re->lastparen = i;
#endif

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
static
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
static
SV *
GNU_checkstr(pTHX_ REGEXP * const rx)
{
  PERL_UNUSED_ARG(rx);
  return NULL;
}
#endif

#ifdef HAVE_REGEXP_ENGINE_FREE
static
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
static
SV *
GNU_qr_package(pTHX_ REGEXP * const rx)
{
  PERL_UNUSED_ARG(rx);

  return newSVpvs("re::engine::GNU");
}
#endif

#ifdef HAVE_REGEXP_ENGINE_DUPE
static
void *
GNU_dupe(pTHX_ REGEXP * const rx, CLONE_PARAMS *param)
{
  PERL_UNUSED_ARG(param);
  regexp        *re = _RegSV(rx);
  GNU_private_t *oldri = (GNU_private_t *) re->pprivate;
  GNU_private_t *ri;
  reg_errcode_t  ret;

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
