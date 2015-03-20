/* Call to libc free() in XS or not */
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

/* Call to libc malloc() in XS or not */
#ifdef malloc
#define _SAVE_MALLOC_DEFINITION malloc
#undef malloc
#else
#undef _SAVE_MALLOC_DEFINITION
#endif
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
void *_libc_malloc(size_t size) {
  return malloc(size);
}
#ifdef _SAVE_MALLOC_DEFINITION
#define malloc _SAVE_MALLOC_DEFINITION
#endif

/* Call to libc realloc() in XS or not */
#ifdef realloc
#define _SAVE_REALLOC_DEFINITION realloc
#undef realloc
#else
#undef _SAVE_REALLOC_DEFINITION
#endif
#ifdef PERL_STATIC_INLINE
PERL_STATIC_INLINE
#else
static
#endif
void *_libc_realloc(void *ptr, size_t size) {
  return realloc(ptr, size);
}
#ifdef _SAVE_REALLOC_DEFINITION
#define realloc _SAVE_REALLOC_DEFINITION
#endif
