#ifndef AURA_BUG_STUFF /* @todo: get a better name, perhaps one without _stuff */
#define AURA_BUG_STUFF

#include "compiler_lib.h"
#include <assert.h>
#include <stdlib.h>
#include <syslog.h>

#define A_BUG_ON_2(cond, is_daemon)                                                           \
    do {                                                                                      \
        if (likely(cond)) {                                                                   \
            if ((is_daemon))                                                                  \
                syslog(LOG_ALERT, "Assertion '%s' failed: %s:%d", #cond, __FILE__, __LINE__); \
            else                                                                              \
                fprintf(stderr, "Asserton '%s' failed: %s:%d\n", #cond, __FILE__, __LINE__);  \
            abort();                                                                          \
        }                                                                                     \
    } while (0)

#endif