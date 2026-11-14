#ifndef APP_ISOLATION_POLICY_H
#define APP_ISOLATION_POLICY_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* These routes describe the existing spawn branches; this module never spawns. */
enum app_isolation_route {
    APP_ISOLATION_ROUTE_ORIGINAL,
    APP_ISOLATION_ROUTE_NORMAL,
    APP_ISOLATION_ROUTE_BLACKLIST_NATIVE,
    APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK,
    APP_ISOLATION_ROUTE_REJECT
};

/*
 * The caller supplies already-resolved facts, including effective whitelist /
 * blacklist membership. An opt-in never creates blacklist membership.
 *
 * ios15_arm64e: the existing iOS 15 arm64e platform check, not iOS >= 15.
 * global_dyld_fix: the existing global dyld/spinlock fix is enabled.
 * effective_blacklisted: the existing full RootHide blacklist decision.
 * choicy_blocked: the caller's existing Choicy decision, with its own gates.
 * ordinary_removable_app: a verified ordinary removable app main executable;
 *     false for system/critical processes, helpers and non-app paths. The caller
 *     must validate the actual executable path, not just a bundle identifier.
 * not_trollstore: false for both TrollStore and TrollStore Lite apps. Production
 *     wiring currently passes true so every app kind can opt in; the gate stays
 *     available and covered by tests.
 * spinlock_safe_opt_in: the appconfigSpinlockSafe[bundleID] value is bool true.
 * is_extension: classification of the actual spawn path using the helper below.
 * active_prewarm / dyld_use_closures: environment variable presence, even if the
 *     value is empty or "0", matching the existing envbuf_getenv checks.
 * launchd_first_load: the existing pre-finalization original-spawn fallback.
 *
 * The ordinary-app, TrollStore and opt-in facts only gate the new full-blacklist
 * route. They must not change the caller's existing Choicy-only eligibility.
 */
struct app_isolation_context {
    bool ios15_arm64e;
    bool global_dyld_fix;
    bool effective_blacklisted;
    bool choicy_blocked;
    bool ordinary_removable_app;
    bool not_trollstore;
    bool spinlock_safe_opt_in;
    bool is_extension;
    bool active_prewarm;
    bool dyld_use_closures;
    bool launchd_first_load;
};

/*
 * Precedence:
 * 1. Full blacklist + iOS 15 arm64e + dyld fix rejects extensions, prewarm and
 *    closures launches, including opted-in apps and simultaneous Choicy blocks.
 * 2. A full blacklist otherwise uses the native blacklist route, except that a
 *    supported, opted-in ordinary non-TrollStore app uses spinlock-only.
 * 3. Choicy without a full blacklist uses legacy spinlock-only on iOS 15 arm64e
 *    with the dyld fix, and the native blacklist route on other configurations.
 * 4. Without either blacklist, first load uses ORIGINAL; otherwise NORMAL.
 *
 * NULL selects ORIGINAL. Early special cases (launchd, jailbreakd, activation
 * guards, missing spawn attributes/path) remain the caller's responsibility.
 */
enum app_isolation_route app_isolation_policy_decide(
    const struct app_isolation_context *context);

/*
 * Match the legacy case-sensitive substrings "/PlugIns/", "/Extensions/" and
 * ".appex/" in the actual executable path. NULL and empty paths are false.
 * This is deliberately neither filesystem resolution nor app eligibility.
 */
bool app_isolation_path_is_extension(const char *path);

/*
 * Return a malloc-owned filtered DYLD_INSERT_LIBRARIES list; the caller frees it.
 * NULL input returns NULL; non-NULL input returns NULL only on allocation failure.
 * An empty result is allocated as ""; the caller may unset the variable then.
 *
 * Remove only canonical absolute entries identifying the exact active_hook_path,
 * /usr/lib/systemhook.dylib or systemhook-<16 hex digits>.dylib, or the following
 * libraries below the supplied jailbreak_root:
 *   /basebin/{systemhook.dylib,systemhook-<16hex>.dylib,launchdhook.dylib,
 *             forkfix.dylib}
 *   /usr/lib/{roothideinit,roothidepatch,libroothide,libjoker,libellekit,
 *             TweakLoader,TweakInject}.dylib
 *   /usr/lib/libhooker/{libinjector,MobileSafety}.dylib
 *
 * The configured root must be absolute, canonical and non-root (one optional
 * trailing slash is accepted). /private/var and /var are equivalent only for this
 * root; the active hook itself is an exact byte match. Relative names, unrelated
 * libraries, lookalike roots, repeated slashes and dot/traversal paths survive.
 * Preserve the order, spelling and multiplicity of retained entries, including
 * empty colon-separated components. Filtering never proves zero injection.
 */
char *RHIsolationCopyLibraryInserts(const char *value,
                                  const char *jailbreak_root,
                                  const char *active_hook_path);

/* Checked deep copy: remove every _SafeMode/_MSSafeMode key and filter each
 * DYLD_INSERT_LIBRARIES value as above. Unrelated entries/input stay intact.
 * NULL input yields an allocated empty array; NULL output means allocation failure.
 */
char **RHIsolationCopyEnvironment(const char *const *envp,
                                const char *jailbreak_root,
                                const char *active_hook_path);
void RHIsolationFreeEnvironment(char **envp);

#ifdef __cplusplus
}
#endif

#endif
