#ifndef __UNCONFIG_H__

#ifdef _GNU_SOURCE_WAS_UNDEF
#undef _GNU_SOURCE
#endif
#undef regerror
#undef re_set_syntax
#undef re_search_2
#undef re_exec
#undef re_compile_pattern
#undef regfree
#undef re_compile_fastmap
#undef re_set_registers
#undef re_comp
#undef re_syntax_options
#undef re_match_2
#undef re_match
#undef re_search
#undef regexec
#undef regcomp

#endif /* ?__UNCONFIG_H__ */
