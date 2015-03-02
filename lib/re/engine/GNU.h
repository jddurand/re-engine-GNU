#define SAVEPVN(p,n) ((p) ? savepvn(p,n) : NULL)

START_EXTERN_C
EXTERN_C const regexp_engine engine_gnu;
EXTERN_C REGEXP * GNU_comp(pTHX_ const SV const *, const U32);
#if PERL_VERSION >= 19
EXTERN_C char *   GNU_intuit(pTHX_ REGEXP * const, SV *, const char *, char *, char *, U32, re_scream_pos_data *);
EXTERN_C I32      GNU_exec(pTHX_ REGEXP * const, char *, char *, char *, SSize_t, SV *, void *, U32);
#else 
EXTERN_C char *   GNU_intuit(pTHX_ REGEXP * const, SV *, char *, char *, U32, re_scream_pos_data *);
EXTERN_C I32      GNU_exec(pTHX_ REGEXP * const, char *, char *, char *, I32, SV *, void *, U32);
#endif
EXTERN_C SV *     GNU_checkstr(pTHX_ REGEXP * const);
EXTERN_C void     GNU_free(pTHX_ REGEXP * const);
/* No numbered/named buff callbacks */
EXTERN_C SV *     GNU_package(pTHX_ REGEXP * const);
#ifdef USE_ITHREADS
EXTERN_C void *   GNU_dupe(pTHX_ REGEXP * const, CLONE_PARAMS *);
#endif
END_EXTERN_C
char *get_regerror(int, regex_t *);

const regexp_engine engine_gnu = {
  GNU_comp,
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
