#define SAVEPVN(p,n) ((p) ? savepvn(p,n) : NULL)

START_EXTERN_C

EXTERN_C const regexp_engine engine_gnu;

#if PERL_VERSION <= 10
EXTERN_C REGEXP * GNU_comp10(pTHX_ const SV * const, const U32);
#define GNU_COMP GNU_comp10
#else
EXTERN_C REGEXP * GNU_comp(pTHX_ SV * const, U32);
#define GNU_COMP GNU_comp
#endif
#if PERL_VERSION >= 19
EXTERN_C char *   GNU_intuit(pTHX_ REGEXP * const, SV *, const char *, char *, char *, U32, re_scream_pos_data *);
EXTERN_C I32      GNU_exec(pTHX_ REGEXP * const, char *, char *, char *, SSize_t, SV *, void *, U32);
#else 
EXTERN_C char *   GNU_intuit(pTHX_ REGEXP * const, SV *, char *, char *, U32, re_scream_pos_data *);
EXTERN_C I32      GNU_exec(pTHX_ REGEXP * const, char *, char *, char *, I32, SV *, void *, U32);
#endif
EXTERN_C SV *     GNU_checkstr(pTHX_ REGEXP * const);
EXTERN_C void     GNU_free(pTHX_ REGEXP * const);
EXTERN_C void     GNU_numbered_buff_FETCH (pTHX_ REGEXP * const rx, const I32 paren, SV * const sv);
EXTERN_C void     GNU_numbered_buff_STORE (pTHX_ REGEXP * const rx, const I32 paren, SV const * const value);
EXTERN_C I32      GNU_numbered_buff_LENGTH (pTHX_ REGEXP * const rx, const SV * const sv, const I32 paren);
EXTERN_C SV*      GNU_named_buff (pTHX_ REGEXP * const rx, SV * const key, SV * const value, U32 flags);
EXTERN_C SV*      GNU_named_buff_iter (pTHX_ REGEXP * const rx, const SV * const lastkey, const U32 flags);
EXTERN_C SV *     GNU_package(pTHX_ REGEXP * const);
#ifdef USE_ITHREADS
EXTERN_C void *   GNU_dupe(pTHX_ REGEXP * const, CLONE_PARAMS *);
#endif
END_EXTERN_C
char *get_regerror(int, regex_t *);

const regexp_engine engine_GNU = {
  GNU_COMP,
  GNU_exec,
  GNU_intuit,
  GNU_checkstr,
  GNU_free,
  Perl_reg_numbered_buff_fetch,
  Perl_reg_numbered_buff_store,
  Perl_reg_numbered_buff_length,
  Perl_reg_named_buff,
  Perl_reg_named_buff_iter,
  GNU_package,
#if defined(USE_ITHREADS)
  GNU_dupe,
#endif
};
