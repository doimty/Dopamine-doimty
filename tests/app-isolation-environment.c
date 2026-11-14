#include "../BaseBin/launchdhook/src/app_isolation_policy.h"
#include "../BaseBin/libroothider/src/app_isolation_ranges.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *root = "/private/var/containers/Bundle/Application/.jbroot-1122334455667788";
    const char *env[] = {
        "PATH=/usr/bin:/bin",
        "_SafeMode=1", "_MSSafeMode=0", "_SafeMode=another",
        "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook-1122334455667788.dylib:/opt/foreign/keep.dylib",
        "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib",
        "OTHER_DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib",
        "_SafeModeExtra=keep", "SENTINEL=unicode-utf8", NULL
    };
    char **copy = RHIsolationCopyEnvironment(env, root, "/usr/lib/systemhook-1122334455667788.dylib");
    assert(copy);
    const char *expected[] = {
        "PATH=/usr/bin:/bin", "DYLD_INSERT_LIBRARIES=/opt/foreign/keep.dylib",
        "OTHER_DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib",
        "_SafeModeExtra=keep", "SENTINEL=unicode-utf8", NULL
    };
    unsigned i;
    for (i = 0; expected[i]; i++) {
        assert(copy[i] && !strcmp(copy[i], expected[i]));
        assert(copy[i] != env[i]);
    }
    assert(!copy[i]);
    assert(!strcmp(env[1], "_SafeMode=1"));
    copy[0][0] = 'X';
    assert(env[0][0] == 'P');
    RHIsolationFreeEnvironment(copy);
    copy = RHIsolationCopyEnvironment(NULL, root, NULL);
    assert(copy && !copy[0]);
    RHIsolationFreeEnvironment(copy);
    RHIsolationFreeEnvironment(NULL);
    const char *empty[] = {"DYLD_INSERT_LIBRARIES=", "A=", NULL};
    copy = RHIsolationCopyEnvironment(empty, root, NULL);
    assert(copy && copy[0] && !strcmp(copy[0], "A=") && !copy[1]);
    RHIsolationFreeEnvironment(copy);

    /* First-load launchd has an empty (not NULL) active hook path. It must not
     * be treated as matching empty colon components or arbitrary entries. */
    char *filtered = RHIsolationCopyLibraryInserts("a::b:/usr/lib/systemhook.dylib::",
        NULL, "");
    assert(filtered && !strcmp(filtered, "a::b::"));
    free(filtered);
    filtered = RHIsolationCopyLibraryInserts("::", root, "");
    assert(filtered && !strcmp(filtered, "::"));
    free(filtered);

    struct rh_app_isolation_layout valid = {
        .stock_size = 0x50000, .patched_size = 0x70000,
        .stock_cache_function = 0x18000, .patched_cache_function = 0x20000,
        .patched_trampoline = 0x30000,
    };
    assert(rh_app_isolation_layout_valid(valid, 0x4000));
    struct rh_app_isolation_layout bad = valid;
    bad.patched_trampoline = 0;
    assert(!rh_app_isolation_layout_valid(bad, 0x4000));
    bad.patched_trampoline = 0x3fff;
    assert(!rh_app_isolation_layout_valid(bad, 0x4000));
    bad.patched_trampoline = 0x4000;
    assert(rh_app_isolation_layout_valid(bad, 0x4000));
    bad.patched_trampoline = valid.patched_size - 39;
    assert(!rh_app_isolation_layout_valid(bad, 0x4000));
    bad.patched_trampoline = valid.patched_size - 40;
    assert(rh_app_isolation_layout_valid(bad, 0x4000));
    bad = valid; bad.stock_cache_function = valid.stock_size - 19;
    assert(!rh_app_isolation_layout_valid(bad, 0x4000));
    bad = valid; bad.patched_cache_function = valid.patched_size - 19;
    assert(!rh_app_isolation_layout_valid(bad, 0x4000));
    bad = valid; bad.stock_size = 0;
    assert(!rh_app_isolation_layout_valid(bad, 0x4000));
    assert(!rh_app_isolation_layout_valid(valid, 0));
    assert(rh_app_isolation_address_span(0x100000000, 0x20000, 40));
    assert(!rh_app_isolation_address_span(UINT64_MAX - 10, 12, 1));
    assert(!rh_app_isolation_address_span(UINT64_MAX - 10, 9, 3));
    assert(rh_app_isolation_address_span(UINT64_MAX - 10, 9, 2));
    assert(!rh_app_isolation_address_span(0, 0, 0));
    puts("app-isolation-environment: original inputs preserved; own inserts removed; patch span checks passed");
    return 0;
}
