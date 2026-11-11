#include "../BaseBin/launchdhook/src/jbserver/jbsettings.h"
#include "../BaseBin/libjailbreak/src/info.h"
#include "../BaseBin/libjailbreak/src/doimty_isolation.h"
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct system_info gSystemInfo = {0};
struct official_settings_layout { bool markAppsAsDebugged; double jetsamMultiplier; };
_Static_assert(sizeof(((struct system_info *)0)->jailbreakSettings) == sizeof(struct official_settings_layout), "settings ABI size unchanged");
_Static_assert(offsetof(struct system_info, jailbreakSettings.jetsamMultiplier) - offsetof(struct system_info, jailbreakSettings) == offsetof(struct official_settings_layout, jetsamMultiplier), "jetsam offset unchanged");
_Static_assert(offsetof(struct system_info, jailbreakSettings.doimtyBlacklistIsolationEnabled) == offsetof(struct system_info, jailbreakSettings.markAppsAsDebugged) + sizeof(bool), "isolation occupies bool padding");

static void get_bool(const char *key, bool expected)
{
    xpc_object_t out = NULL;
    assert(jbsettings_get(key, &out) == 0);
    assert(xpc_get_type(out) == XPC_TYPE_BOOL && xpc_bool_get_value(out) == expected);
    xpc_release(out);
}
static int set_bool(const char *key, bool value)
{
    xpc_object_t object = xpc_bool_create(value);
    int result = jbsettings_set(key, object);
    xpc_release(object);
    return result;
}
static int set_double(const char *key, double value)
{
    xpc_object_t object = xpc_double_create(value);
    int result = jbsettings_set(key, object);
    xpc_release(object);
    return result;
}
static void test_full_serializer(void)
{
    // Compile and execute every official generic type, not just bool/double settings.
    gSystemInfo.kernelConstant.slide = 0x1234000;
    gSystemInfo.jailbreakInfo.rootPath = strdup("/tmp/fixture-only");
    gSystemInfo.jailbreakInfo.appIdentifier = strdup("com.example.fixture");
    assert(gSystemInfo.jailbreakInfo.rootPath && gSystemInfo.jailbreakInfo.appIdentifier);
    gSystemInfo.jailbreakSettings.markAppsAsDebugged = true;
    gSystemInfo.jailbreakSettings.jetsamMultiplier = 2.5;
    __atomic_store_n(&gSystemInfo.jailbreakSettings.doimtyBlacklistIsolationEnabled, true, __ATOMIC_RELEASE);
    xpc_object_t snapshot = xpc_dictionary_create_empty();
    SYSTEM_INFO_SERIALIZE(snapshot);
    free(gSystemInfo.jailbreakInfo.rootPath);
    free(gSystemInfo.jailbreakInfo.appIdentifier);
    memset(&gSystemInfo, 0, sizeof(gSystemInfo));
    SYSTEM_INFO_DESERIALIZE(snapshot);
    assert(gSystemInfo.kernelConstant.slide == 0x1234000);
    assert(!strcmp(gSystemInfo.jailbreakInfo.rootPath, "/tmp/fixture-only"));
    assert(!strcmp(gSystemInfo.jailbreakInfo.appIdentifier, "com.example.fixture"));
    assert(gSystemInfo.jailbreakSettings.markAppsAsDebugged && gSystemInfo.jailbreakSettings.jetsamMultiplier == 2.5);
    assert(doimty_blacklist_isolation_enabled());
    free(gSystemInfo.jailbreakInfo.rootPath);
    free(gSystemInfo.jailbreakInfo.appIdentifier);
    memset(&gSystemInfo, 0, sizeof(gSystemInfo));
    xpc_release(snapshot);
}

int main(void)
{
    assert(!doimty_blacklist_isolation_enabled());
    // macOS intentionally covers the unsupported backend, without iOS processes.
    assert(!doimty_blacklist_isolation_supported());
    get_bool(DOIMTY_ISOLATION_SUPPORTED_KEY, false);
    assert(set_bool(DOIMTY_ISOLATION_SUPPORTED_KEY, true) != 0);
    assert(set_bool(DOIMTY_ISOLATION_SETTING_KEY, true) == ENOTSUP);
    assert(set_bool(DOIMTY_ISOLATION_SETTING_KEY, false) == ENOTSUP);
    assert(set_double(DOIMTY_ISOLATION_SETTING_KEY, 1.0) != 0);
    xpc_object_t null = xpc_null_create();
    assert(jbsettings_set(NULL, null) != 0);
    assert(jbsettings_set(DOIMTY_ISOLATION_SETTING_KEY, NULL) != 0);
    assert(jbsettings_set(DOIMTY_ISOLATION_SETTING_KEY, null) != 0);
    assert(jbsettings_get(DOIMTY_ISOLATION_SETTING_KEY, NULL) != 0);
    xpc_object_t out = NULL;
    assert(jbsettings_get(NULL, &out) != 0);
    xpc_release(null);
    assert(!doimty_blacklist_isolation_enabled());
    assert(set_bool("markAppsAsDebugged", true) == 0);
    assert(set_double("jetsamMultiplier", 2.5) == 0);
    get_bool("markAppsAsDebugged", true);
    assert(jbsettings_get("jetsamMultiplier", &out) == 0 && xpc_double_get_value(out) == 2.5);
    xpc_release(out);
    test_full_serializer();
    xpc_object_t legacy = xpc_dictionary_create_empty();
    xpc_dictionary_set_bool(legacy, "jailbreakSettings.markAppsAsDebugged", true);
    xpc_dictionary_set_double(legacy, "jailbreakSettings.jetsamMultiplier", 3.0);
    __atomic_store_n(&gSystemInfo.jailbreakSettings.doimtyBlacklistIsolationEnabled, true, __ATOMIC_RELEASE);
    SYSTEM_INFO_DESERIALIZE(legacy);
    assert(!doimty_blacklist_isolation_enabled());
    assert(gSystemInfo.jailbreakSettings.markAppsAsDebugged && gSystemInfo.jailbreakSettings.jetsamMultiplier == 3.0);
    xpc_release(legacy);
    puts("app-isolation-settings: ABI offsets, full serializer types, missing-key default, null/readonly/unsupported and original settings passed");
    return 0;
}
