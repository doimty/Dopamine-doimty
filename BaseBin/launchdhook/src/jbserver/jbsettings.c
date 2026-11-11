#include "jbsettings.h"
#include <libjailbreak/info.h>
#include <libjailbreak/doimty_isolation.h>
#include <errno.h>
#include <string.h>

bool doimty_blacklist_isolation_enabled(void)
{
	return __atomic_load_n(&gSystemInfo.jailbreakSettings.doimtyBlacklistIsolationEnabled,
		__ATOMIC_ACQUIRE);
}

bool doimty_blacklist_isolation_supported(void)
{
#ifdef __arm64e__
	if (__builtin_available(iOS 15.0, *)) {
		if (!__builtin_available(iOS 16.0, *)) return true;
	}
#endif
	return false;
}

int jbsettings_get(const char *key, xpc_object_t *valueOut)
{
	if (!key || !valueOut) return -1;

	if (!strcmp(key, "markAppsAsDebugged")) {
		*valueOut = xpc_bool_create(jbsetting(markAppsAsDebugged));
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier")) {
		*valueOut = xpc_double_create(jbsetting(jetsamMultiplier));
		return 0;
	}
	else if (!strcmp(key, DOIMTY_ISOLATION_SETTING_KEY)) {
		*valueOut = xpc_bool_create(doimty_blacklist_isolation_enabled());
		return 0;
	}
	else if (!strcmp(key, DOIMTY_ISOLATION_SUPPORTED_KEY)) {
		*valueOut = xpc_bool_create(doimty_blacklist_isolation_supported());
		return 0;
	}
	return -1;
}

int jbsettings_set(const char *key, xpc_object_t value)
{
	if (!key || !value) return -1;
	if (!strcmp(key, "markAppsAsDebugged") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = xpc_bool_get_value(value);
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier") && xpc_get_type(value) == XPC_TYPE_DOUBLE) {
		gSystemInfo.jailbreakSettings.jetsamMultiplier = xpc_double_get_value(value);
		return 0;
	}
	else if (!strcmp(key, DOIMTY_ISOLATION_SETTING_KEY) && xpc_get_type(value) == XPC_TYPE_BOOL) {
		if (!doimty_blacklist_isolation_supported()) return ENOTSUP;
		__atomic_store_n(&gSystemInfo.jailbreakSettings.doimtyBlacklistIsolationEnabled,
			xpc_bool_get_value(value), __ATOMIC_RELEASE);
		return 0;
	}
	// The support capability is read-only, even for a Boolean value.
	return -1;
}
