#ifndef DOIMTY_APP_ISOLATION_POLICY_H
#define DOIMTY_APP_ISOLATION_POLICY_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Own policy. The first five routes model unchanged official behavior.
enum app_isolation_route {
    APP_ISOLATION_ROUTE_ORIGINAL,
    APP_ISOLATION_ROUTE_NORMAL,
    APP_ISOLATION_ROUTE_BLACKLIST_NATIVE,
    APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK,
    APP_ISOLATION_ROUTE_REJECT,
    APP_ISOLATION_ROUTE_BLACKLIST_STRICT
};

struct app_isolation_context {
    bool ios15_arm64e;
    bool global_dyld_fix;
    bool global_isolation_enabled;
    bool effective_blacklisted;
    bool choicy_blocked;
    bool verified_main_executable;
    bool isolation_opted_out;
    bool is_extension;
    bool active_prewarm;
    bool dyld_use_closures;
    bool launchd_first_load;
};

// Caller facts must come from roothide_get_app_spawn_policy, not path guesses.
// Extension/prewarm/closure restrictions precede the new strict route. Choicy
// without full blacklist retains the official spinlock-only/native decision.
enum app_isolation_route app_isolation_policy_decide(
    const struct app_isolation_context *context);

// Production readiness adapter: call ready exactly once, and only after all
// cheap strict gates succeed. A pre-spawn readiness failure uses official native
// blacklist behavior. No callback here spawns or repairs a process.
enum app_isolation_route app_isolation_policy_resolve(
    const struct app_isolation_context *context,
    bool (*ready)(void *), void *opaque);

// Shared production adapter: populate membership from the official lookup when
// off, and from one qualified config snapshot when the own gates are active.
// This is compiled by both launchdhook and the real Foundation integration test.
enum app_isolation_route app_isolation_classify_path(
    const char *path, struct app_isolation_context *context,
    bool (*ready)(void *), void *opaque);

bool app_isolation_path_is_extension(const char *path);

// Reused own environment filter from ac8b411. Deep-copy inputs, remove all
// _SafeMode/_MSSafeMode keys, and only exact canonical jailbreak-owned inserts.
// Retain unrelated inserts, their order, multiplicity and empty components.
// NULL env input returns an allocated empty vector; allocation failure => NULL.
char *RHIsolationCopyLibraryInserts(const char *value,
                                  const char *jailbreak_root,
                                  const char *active_hook_path);
char **RHIsolationCopyEnvironment(const char *const *envp,
                                 const char *jailbreak_root,
                                 const char *active_hook_path);
void RHIsolationFreeEnvironment(char **envp);

#ifdef __cplusplus
}
#endif
#endif
