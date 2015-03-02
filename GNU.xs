#define PERL_GET_NO_CONTEXT 1
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "regex.h"
#include "GNU.h"

MODULE = re::engine::GNU		PACKAGE = re::engine::GNU		

