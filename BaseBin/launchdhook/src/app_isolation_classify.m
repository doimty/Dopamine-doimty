#import <Foundation/Foundation.h>
#include "app_isolation_policy.h"
#include <libroothider/common.h>

enum app_isolation_route app_isolation_classify_path(
    const char *path, struct app_isolation_context *context,
    bool (*ready)(void *), void *opaque)
{
    if (!context) return APP_ISOLATION_ROUTE_ORIGINAL;
    context->effective_blacklisted = false;
    context->verified_main_executable = false;
    context->isolation_opted_out = false;
    bool ownGate = context->ios15_arm64e && context->global_dyld_fix &&
        context->global_isolation_enabled && !context->launchd_first_load;
    if (ownGate) {
        struct roothide_app_spawn_policy facts = roothide_get_app_spawn_policy(path);
        context->effective_blacklisted = facts.blacklisted;
        context->verified_main_executable = facts.verified_main_executable;
        context->isolation_opted_out = facts.isolation_opted_out;
    } else {
        // Match the official non-app/builtin early exits. No new main-file
        // validation, retained configuration or readiness RPC when disabled.
        context->effective_blacklisted = isBlacklistedPath(path);
    }
    return app_isolation_policy_resolve(context, ready, opaque);
}
