#ifndef NOTGENERATEDCONFIG_H
#define NOTGENERATEDCONFIG_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* For SWIG, we prefer (char *) instead of (unsigned char *) */
#undef RE_TRANSLATE_TYPE
#define RE_TRANSLATE_TYPE char *
#undef __RE_TRANSLATE_TYPE
#define __RE_TRANSLATE_TYPE char *

#include "config_autoconf.h"

#endif /* NOTGENERATEDCONFIG_H */
