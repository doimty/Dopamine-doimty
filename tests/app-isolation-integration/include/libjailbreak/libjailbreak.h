#ifndef DOIMTY_APP_ISOLATION_HOST_LIBJAILBREAK_H
#define DOIMTY_APP_ISOLATION_HOST_LIBJAILBREAK_H

// Only the root provider/log sink is substituted; compile real jbroot conversion,
// Foundation/path/config factory, readiness adapter and lifecycle driver.
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <bsm/audit.h>
#include <xpc/xpc.h>
#include "jbroot.h"

#define JBLogDebug(...) ((void)0)
#define JBLogError(...) ((void)0)
#endif
