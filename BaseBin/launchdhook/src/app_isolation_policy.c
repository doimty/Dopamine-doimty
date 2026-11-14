#include "app_isolation_policy.h"

#include <stdlib.h>
#include <string.h>

bool app_isolation_path_is_extension(const char *path)
{
    return path && (strstr(path, "/PlugIns/") ||
                    strstr(path, "/Extensions/") ||
                    strstr(path, ".appex/"));
}

enum app_isolation_route app_isolation_policy_decide(
    const struct app_isolation_context *context)
{
    if (!context) {
        return APP_ISOLATION_ROUTE_ORIGINAL;
    }

    const bool spinlock_supported =
        context->ios15_arm64e && context->global_dyld_fix;

    if (context->effective_blacklisted) {
        if (spinlock_supported &&
            (context->is_extension || context->active_prewarm ||
             context->dyld_use_closures)) {
            return APP_ISOLATION_ROUTE_REJECT;
        }

        if (spinlock_supported && context->spinlock_safe_opt_in &&
            context->ordinary_removable_app && context->not_trollstore) {
            return APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK;
        }

        return APP_ISOLATION_ROUTE_BLACKLIST_NATIVE;
    }

    if (context->choicy_blocked) {
        return spinlock_supported ? APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK
                                  : APP_ISOLATION_ROUTE_BLACKLIST_NATIVE;
    }

    return context->launchd_first_load ? APP_ISOLATION_ROUTE_ORIGINAL
                                      : APP_ISOLATION_ROUTE_NORMAL;
}

static bool path_is_canonical(const char *path, size_t length)
{
    if (!path || length < 2 || path[0] != '/') {
        return false;
    }

    size_t start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i == length || path[i] == '/') {
            const size_t component_length = i - start;
            if (component_length == 0 ||
                (component_length == 1 && path[start] == '.') ||
                (component_length == 2 && path[start] == '.' &&
                 path[start + 1] == '.')) {
                return false;
            }
            start = i + 1;
        }
    }
    return true;
}

static bool span_equals(const char *value, size_t length, const char *expected)
{
    return length == strlen(expected) && memcmp(value, expected, length) == 0;
}

static bool is_systemhook_name(const char *name, size_t length)
{
    static const char prefix[] = "systemhook-";
    static const char suffix[] = ".dylib";
    const size_t prefix_length = sizeof(prefix) - 1;
    const size_t suffix_length = sizeof(suffix) - 1;

    if (span_equals(name, length, "systemhook.dylib")) {
        return true;
    }
    if (length != prefix_length + 16 + suffix_length ||
        memcmp(name, prefix, prefix_length) != 0 ||
        memcmp(name + prefix_length + 16, suffix, suffix_length) != 0) {
        return false;
    }
    for (size_t i = prefix_length; i < prefix_length + 16; ++i) {
        const char digit = name[i];
        if (!((digit >= '0' && digit <= '9') ||
              (digit >= 'a' && digit <= 'f') ||
              (digit >= 'A' && digit <= 'F'))) {
            return false;
        }
    }
    return true;
}

/* Check exact relative locations only after the canonical root boundary. */
static bool is_root_library(const char *relative, size_t length)
{
    static const char basebin[] = "/basebin/";
    static const char *const engines[] = {
        "/basebin/launchdhook.dylib",
        "/basebin/forkfix.dylib",
        "/usr/lib/roothideinit.dylib",
        "/usr/lib/roothidepatch.dylib",
        "/usr/lib/libroothide.dylib",
        "/usr/lib/libjoker.dylib",
        "/usr/lib/libellekit.dylib",
        "/usr/lib/TweakLoader.dylib",
        "/usr/lib/TweakInject.dylib",
        "/usr/lib/libhooker/libinjector.dylib",
        "/usr/lib/libhooker/MobileSafety.dylib"
    };
    const size_t basebin_length = sizeof(basebin) - 1;

    if (length > basebin_length &&
        memcmp(relative, basebin, basebin_length) == 0 &&
        is_systemhook_name(relative + basebin_length,
                           length - basebin_length)) {
        return true;
    }
    for (size_t i = 0; i < sizeof(engines) / sizeof(engines[0]); ++i) {
        if (span_equals(relative, length, engines[i])) {
            return true;
        }
    }
    return false;
}

static bool is_owned_library(const char *entry, size_t length,
                             const char *root, size_t root_length,
                             const char *active_hook, size_t active_hook_length)
{
    static const char public_library_path[] = "/usr/lib/";
    const size_t public_prefix_length = sizeof(public_library_path) - 1;

    if (!path_is_canonical(entry, length)) {
        return false;
    }
    // An empty active-hook path is a real first-load state; it must not match
    // empty components or any other entry.
    if (active_hook_length > 0 && active_hook && length == active_hook_length &&
        memcmp(entry, active_hook, length) == 0) {
        return true;
    }
    if (length > public_prefix_length &&
        memcmp(entry, public_library_path, public_prefix_length) == 0 &&
        is_systemhook_name(entry + public_prefix_length,
                           length - public_prefix_length)) {
        return true;
    }
    if (!root) {
        return false;
    }

    /* Canonicalize only the proven /private/var alias for both operands. */
    if (root_length >= 13 && memcmp(root, "/private/var/", 13) == 0) {
        root += 8;
        root_length -= 8;
    } else if (root_length == 12 && memcmp(root, "/private/var", 12) == 0) {
        root += 8;
        root_length -= 8;
    }
    if (length >= 13 && memcmp(entry, "/private/var/", 13) == 0) {
        entry += 8;
        length -= 8;
    }
    return length > root_length && entry[root_length] == '/' &&
           memcmp(entry, root, root_length) == 0 &&
           is_root_library(entry + root_length, length - root_length);
}

char *RHIsolationCopyLibraryInserts(const char *value,
                                  const char *jailbreak_root,
                                  const char *active_hook_path)
{
    if (!value) {
        return NULL;
    }

    const size_t value_length = strlen(value);
    char *result = malloc(value_length + 1);
    if (!result) {
        return NULL;
    }

    size_t root_length = jailbreak_root ? strlen(jailbreak_root) : 0;
    if (root_length > 1 && jailbreak_root[root_length - 1] == '/') {
        --root_length;
    }
    if (!path_is_canonical(jailbreak_root, root_length)) {
        jailbreak_root = NULL;
        root_length = 0;
    }
    const size_t active_hook_length =
        active_hook_path ? strlen(active_hook_path) : 0;

    size_t copied = 0;
    bool have_component = false;
    const char *entry = value;
    for (;;) {
        const char *separator = strchr(entry, ':');
        const size_t length = separator ? (size_t)(separator - entry)
                                        : strlen(entry);
        if (!is_owned_library(entry, length, jailbreak_root, root_length,
                              active_hook_path, active_hook_length)) {
            if (have_component) {
                result[copied++] = ':';
            }
            memcpy(result + copied, entry, length);
            copied += length;
            have_component = true;
        }
        if (!separator) {
            break;
        }
        entry = separator + 1;
    }
    result[copied] = '\0';
    return result;
}

void RHIsolationFreeEnvironment(char **envp)
{
    if (!envp) return;
    for (size_t index = 0; envp[index]; index++) free(envp[index]);
    free(envp);
}

char **RHIsolationCopyEnvironment(const char *const *envp,
                                const char *jailbreak_root,
                                const char *active_hook_path)
{
    size_t count = 0;
    if (envp) while (envp[count]) count++;
    if (count > ((size_t)-1) / sizeof(char *) - 1) return NULL;
    char **copy = calloc(count + 1, sizeof(char *));
    if (!copy) return NULL;
    size_t copied = 0;
    for (size_t index = 0; index < count; index++) {
        const char *entry = envp[index];
        if (!strncmp(entry, "_SafeMode=", 10) || !strncmp(entry, "_MSSafeMode=", 12)) continue;
        static const char prefix[] = "DYLD_INSERT_LIBRARIES=";
        if (!strncmp(entry, prefix, sizeof(prefix) - 1)) {
            char *filtered = RHIsolationCopyLibraryInserts(entry + sizeof(prefix) - 1,
                jailbreak_root, active_hook_path);
            if (!filtered) { RHIsolationFreeEnvironment(copy); return NULL; }
            size_t length = strlen(filtered);
            if (!length) { free(filtered); continue; }
            if (length > ((size_t)-1) - sizeof(prefix)) {
                free(filtered); RHIsolationFreeEnvironment(copy); return NULL;
            }
            copy[copied] = malloc(sizeof(prefix) + length);
            if (copy[copied]) {
                memcpy(copy[copied], prefix, sizeof(prefix) - 1);
                memcpy(copy[copied] + sizeof(prefix) - 1, filtered, length + 1);
            }
            free(filtered);
        } else {
            size_t length = strlen(entry);
            copy[copied] = malloc(length + 1);
            if (copy[copied]) memcpy(copy[copied], entry, length + 1);
        }
        if (!copy[copied]) { RHIsolationFreeEnvironment(copy); return NULL; }
        copied++;
    }
    return copy;
}
