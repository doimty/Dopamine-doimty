#include "../BaseBin/launchdhook/src/app_isolation_policy.h"
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

    puts("app-isolation-environment: original inputs preserved; own inserts removed");
    return 0;
}
