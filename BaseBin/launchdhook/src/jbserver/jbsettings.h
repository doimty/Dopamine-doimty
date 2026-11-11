#ifndef JBSETTINGS_H
#define JBSETTINGS_H

#include <stdbool.h>
#include <xpc/xpc.h>

int jbsettings_get(const char *key, xpc_object_t *valueOut);
int jbsettings_set(const char *key, xpc_object_t value);

bool doimty_blacklist_isolation_enabled(void);
bool doimty_blacklist_isolation_supported(void);

#endif
