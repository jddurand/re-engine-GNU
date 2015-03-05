#define PERL_GET_NO_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "GNU.h"
#include "config_REGEXP.h"

#include "gnu-regex/config.h"
#include "gnu-regex/regex.h"

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
    regexp                   *rx;
    struct re_pattern_buffer *re;
    GNU_private_t            *GNU_private;

    /* Copy of flags in input */
    U32 extflags = flags;

    /* SVs that are in input */
    IV pattern_type = get_type(pattern);
    SV *sv_pattern;
    SV *sv_syntax = NULL;
    SV *sv_flavour = NULL;

    {
      /************************************************************/
      /* split optimizations - copied from re-engine-xxx by avar  */
      /************************************************************/
      STRLEN plen;
      char  *exp = SvPV((SV*)pattern, plen);

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
    Newxz(GNU_private, 1, GNU_private_t);

    /* We accept in input:                                                  */
    /* - a scalar                                                           */
    /* - an arrayref with at least 2 members: the syntax and the pattern    */
    /* - a hash with with at least the keys 'syntax', flavour' and 'pattern'*/

    if (pattern_type == SCALAR) {

      sv_pattern = pattern;

    } else if (pattern_type == ARRAYREF) {
      AV *av = (AV *)pattern;
      SV **a_pattern;
      SV **a_flavour;

      if (av_top_index(av) < 1) {
        croak("re::engine::GNU: array ref must have at least two elements, i.e. [flavour => pattern]");
      }
      a_pattern = av_fetch(av, 1, 0);
      a_flavour = av_fetch(av, 0, 0);

      if (a_pattern == NULL || get_type(*a_pattern) != SCALAR) {
        croak("re::engine::GNU: array ref must have a scalar as second element");
      }
      if (a_flavour == NULL || get_type(*a_flavour) != SCALAR) {
        croak("re::engine::GNU: array ref must have a scalar as first element");
      }

      sv_pattern = *a_pattern;
      sv_flavour  = *a_flavour;

    } else if (pattern_type == HASHREF) {
      HV  *hv        = (HV *)pattern;
      SV **h_pattern = hv_fetch(hv, "pattern", 7, 0);
      SV **h_flavour = hv_fetch(hv, "flavour", 7, 0);
      SV **h_syntax  = hv_fetch(hv, "syntax", 6, 0);

      if (h_pattern == NULL || get_type(*h_pattern) != SCALAR) {
        croak("re::engine::GNU: hash ref key must have a key 'pattern' refering to a scalar");
      }

      if (h_flavour != NULL && h_syntax != NULL) {
        croak("re::engine::GNU: hash ref keys 'flavour' and 'syntax' are exclusive");
      }
      if (h_flavour != NULL && get_type(*h_flavour) != SCALAR) {
        croak("re::engine::GNU: hash ref key 'flavour' must point to a scalar");
      }
      if (h_syntax != NULL && get_type(*h_syntax) != SCALAR) {
        croak("re::engine::GNU: hash ref key 'syntax' must point to a scalar");
      }

      if (h_flavour != NULL) {
        STRLEN flavour_len;
        char *flavour = SvPV((SV*)*h_flavour, flavour_len);

        if (flavour_len == 5 && strncmp(flavour, "emacs", 5) == 0) {
          GNU_private->regex.syntax = RE_SYNTAX_EMACS;
        }
        else if (flavour_len == 3 && strncmp(flavour, "awk", 3) == 0) {
          GNU_private->regex.syntax = RE_SYNTAX_AWK;
        }
        else if (flavour_len == 7 && strncmp(flavour, "GNU awk", 7) == 0) {
          GNU_private->regex.syntax = RE_SYNTAX_GNU_AWK;
        }
        else if (flavour_len == 9 && strncmp(flavour, "POSIX awk", 9) == 0) {
          GNU_private->regex.syntax = RE_SYNTAX_POSIX_AWK;
        }
        else if (flavour_len == 4 && strncmp(flavour, "egrep", 4) == 0) {
          GNU_private->regex.syntax = RE_SYNTAX_EGREP;
        }

      }

      sv_pattern = *h_pattern;
      sv_flavour = *h_flavour;
      sv_syntax  = *h_syntax;

    } else {
      croak("re::engine::GNU: pattern must be a scalar, an array ref [flavour => pattern], or a hash ref {'syntax' => syntax, 'flavour' => flavour, 'pattern' => pattern} where syntax and flavour are exclusive");
    }

    GNU_private->sv_pattern_copy = newSVsv(sv_pattern);
    GNU_private->pattern_utf8    = SvPVutf8(GNU_private->sv_pattern_copy, GNU_private->len_pattern_utf8);

    GNU_private->regex.buffer           = NULL;
    GNU_private->regex.allocated        = 0;
    GNU_private->regex.used             = 0;
    GNU_private->regex.syntax           = (sv_syntax != NULL) ? SvUV(sv_syntax) : 0;
    GNU_private->regex.fastmap          = NULL;
    GNU_private->regex.translate        = NULL;
    GNU_private->regex.re_nsub          = 0;
    GNU_private->regex.can_be_null      = 1;
    GNU_private->regex.regs_allocated   = 2;
    GNU_private->regex.fastmap_accurate = 2;
    GNU_private->regex.no_sub           = 1;
    GNU_private->regex.not_bol          = 1;
    GNU_private->regex.not_eol          = 1;
    GNU_private->regex.newline_anchor   = 1;

    if (char  *exp = SvPV((SV*)pattern, plen);

    /* /msixp flags */
#ifdef RXf_PMf_MULTILINE
    /* /m */
    if ((flags & RXf_PMf_MULTILINE) == RXf_PMf_MULTILINE) {
      GNU_private->regex.newline_anchor = 1;
    } else {
      GNU_private->regex.newline_anchor = 0;
    }
#endif
#ifdef RXf_PMf_SINGLELINE
    /* /s */
    if ((flags & RXf_PMf_SINGLELINE) == RXf_PMf_SINGLELINE) {
      GNU_private->regex.syntax |= RE_DOT_NEWLINE;
    } else {
      GNU_private->regex.syntax &= ~RE_DOT_NEWLINE;
    }
#endif
#ifdef RXf_PMf_FOLD
    /* /i */
    if ((flags & RXf_PMf_FOLD) == RXf_PMf_FOLD) {
      uv_syntax |= REG_ICASE;
    }
#endif
#ifdef RXf_PMf_EXTENDED
    /* /x */
    if ((flags & RXf_PMf_EXTENDED) == RXf_PMf_EXTENDED) {
      croak("re::engine::GNU: /x modifier is not supported");
    }
#endif
#ifdef RXf_PMf_KEEPCOPY
    /* /p */
    if ((flags & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY) {
      croak("re::engine::GNU: /p modifier is not supported");
    }
#endif

    /* REGEX structure for perl */
    Newxz(rx, 1, regexp);

#ifdef HAVE_REGEXP_REFCNT
    rx->refcnt = 1;
#endif
#ifdef HAVE_REGEXP_EXTFLAGS
    rx->extflags = extflags;
#endif
#ifdef HAVE_REGEXP_ENGINE
    rx->engine = &engine_GNU;
#endif
    /* Precompiled regexp for pp_regcomp to use */
#ifdef HAVE_REGEXP_PRELEN
    rx->prelen = (I32)plen;
#endif
#ifdef HAVE_REGEXP_PRECOMP
    rx->precomp = SAVEPVN(exp, rx->prelen);
#endif
    /* qr// stringification, reuse the space */
#ifdef HAVE_REGEXP_WRAPLEN
#ifdef HAVE_REGEXP_PRELEN
    rx->wraplen = rx->prelen;
#endif
#endif
#ifdef HAVE_REGEXP_WRAPPED
#ifdef HAVE_REGEXP_PRECOMP
    rx->wrapped = (char *)rx->precomp; /* from const char* */
#endif
#endif

    Newxz(re, 1, regex_t);

    err = regncomp(re, exp, plen, cflags);

    if (err != 0) {
        /* note: we do not call regfree() when regncomp returns an error */
        err_str_length = regerror(err, re, err_str, ERR_STR_LENGTH);
        if (err_str_length > ERR_STR_LENGTH) {
            croak("error compiling `%s': %s (error message truncated)", exp, err_str);
        } else {
            croak("error compiling `%s': %s", exp, err_str);
        }
    }

    /* Save for later */
    rx->pprivate = GNU_private;

    /*
      Tell perl how many match vars we have and allocate space for
      them, at least one is always allocated for $&
     */
    rx->nparens = (U32)re->re_nsub; /* cast from size_t */
    Newxz(rx->offs, rx->nparens + 1, regexp_paren_pair);

    /* return the regexp structure to perl */
    return rx;
}

MODULE = re::engine::GNU		PACKAGE = re::engine::GNU		
PROTOTYPES: ENABLE

void
ENGINE(...)
PROTOTYPE:
PPCODE:
    XPUSHs(sv_2mortal(newSViv(PTR2IV(&engine_GNU))));
