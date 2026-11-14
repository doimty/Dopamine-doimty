#include "../BaseBin/launchdhook/src/app_isolation_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int checks;
static unsigned int failures;

static const char *route_name(enum app_isolation_route route)
{
    switch (route) {
    case APP_ISOLATION_ROUTE_ORIGINAL: return "ORIGINAL";
    case APP_ISOLATION_ROUTE_NORMAL: return "NORMAL";
    case APP_ISOLATION_ROUTE_BLACKLIST_NATIVE: return "BLACKLIST_NATIVE";
    case APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK: return "BLACKLIST_SPINLOCK";
    case APP_ISOLATION_ROUTE_REJECT: return "REJECT";
    }
    return "INVALID";
}

static void expect_route(const char *name,
                         const struct app_isolation_context *context,
                         enum app_isolation_route expected)
{
    const enum app_isolation_route actual = app_isolation_policy_decide(context);
    ++checks;
    if (actual != expected) {
        ++failures;
        fprintf(stderr, "%s: expected %s, got %s\n", name,
                route_name(expected), route_name(actual));
    }
}

static struct app_isolation_context eligible_app(void)
{
    const struct app_isolation_context context = {
        .ios15_arm64e = true,
        .global_dyld_fix = true,
        .effective_blacklisted = true,
        .ordinary_removable_app = true,
        .not_trollstore = true,
        .spinlock_safe_opt_in = true
    };
    return context;
}

static void test_named_routes(void)
{
    struct app_isolation_context context = {0};
    expect_route("null context", NULL, APP_ISOLATION_ROUTE_ORIGINAL);
    expect_route("ordinary unblocked launch", &context,
                 APP_ISOLATION_ROUTE_NORMAL);
    context.launchd_first_load = true;
    expect_route("first load unblocked", &context,
                 APP_ISOLATION_ROUTE_ORIGINAL);

    context = eligible_app();
    expect_route("eligible full blacklist opt-in", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK);
    context.spinlock_safe_opt_in = false;
    expect_route("full blacklist default remains native", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
    context.choicy_blocked = true;
    expect_route("full blacklist outranks Choicy without opt-in", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
    context.spinlock_safe_opt_in = true;
    expect_route("full blacklist and Choicy with eligible opt-in", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK);
    context.is_extension = true;
    expect_route("extension denial outranks opt-in and Choicy", &context,
                 APP_ISOLATION_ROUTE_REJECT);
    context.is_extension = false;
    context.active_prewarm = true;
    expect_route("prewarm denial outranks opt-in and Choicy", &context,
                 APP_ISOLATION_ROUTE_REJECT);
    context.active_prewarm = false;
    context.dyld_use_closures = true;
    expect_route("closure denial outranks opt-in and Choicy", &context,
                 APP_ISOLATION_ROUTE_REJECT);
    context.global_dyld_fix = false;
    expect_route("closures restrictions require dyld fix", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
    context.global_dyld_fix = true;
    context.ios15_arm64e = false;
    expect_route("closures restrictions require supported platform", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);

    context = eligible_app();
    context.effective_blacklisted = false;
    expect_route("opt-in never overrides effective whitelist", &context,
                 APP_ISOLATION_ROUTE_NORMAL);
    context.launchd_first_load = true;
    expect_route("whitelisted opt-in preserves first load", &context,
                 APP_ISOLATION_ROUTE_ORIGINAL);

    context = eligible_app();
    context.effective_blacklisted = false;
    context.choicy_blocked = true;
    context.ordinary_removable_app = false;
    context.not_trollstore = false;
    context.spinlock_safe_opt_in = false;
    context.is_extension = true;
    context.active_prewarm = true;
    context.dyld_use_closures = true;
    expect_route("Choicy trusts the parent's legacy eligibility", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK);
    context.launchd_first_load = true;
    expect_route("Choicy precedes first load", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK);
    context.global_dyld_fix = false;
    expect_route("Choicy without dyld fix is native", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);

    context = eligible_app();
    context.launchd_first_load = true;
    expect_route("full blacklist opt-in precedes first load", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK);
    context.spinlock_safe_opt_in = false;
    expect_route("full blacklist native precedes first load", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
    context.is_extension = true;
    expect_route("full blacklist denial precedes first load", &context,
                 APP_ISOLATION_ROUTE_REJECT);

    static const struct {
        const char *name;
        bool ios15_arm64e;
    } platforms[] = {
        {"iOS 15 arm64e", true},
        {"iOS 15 arm64", false},
        {"iOS 14 arm64e", false},
        {"iOS 16 arm64e", false},
        {"iOS 17 arm64e", false},
        {"iOS 19 arm64e", false},
        {"host or unknown platform", false}
    };
    for (size_t i = 0; i < sizeof(platforms) / sizeof(platforms[0]); ++i) {
        context = eligible_app();
        context.ios15_arm64e = platforms[i].ios15_arm64e;
        expect_route(platforms[i].name, &context,
                     platforms[i].ios15_arm64e
                         ? APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK
                         : APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
    }

    static const char *const non_apps[] = {
        "/sbin/launchd",
        "/usr/libexec/xpcproxy",
        "/usr/libexec/runningboardd",
        "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        "/Applications/Preferences.app/Preferences",
        "/var/jb/basebin/jailbreakd",
        "/var/containers/Bundle/Application/UUID/App.app/Helpers/helper"
    };
    for (size_t i = 0; i < sizeof(non_apps) / sizeof(non_apps[0]); ++i) {
        context = eligible_app();
        /* The parent validates these paths; the policy consumes that fact. */
        context.ordinary_removable_app = false;
        expect_route(non_apps[i], &context,
                     APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
        context.effective_blacklisted = false;
        expect_route(non_apps[i], &context, APP_ISOLATION_ROUTE_NORMAL);
    }

    context = eligible_app();
    context.not_trollstore = false;
    expect_route("TrollStore app stays native", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
    expect_route("TrollStore Lite app stays native", &context,
                 APP_ISOLATION_ROUTE_BLACKLIST_NATIVE);
}

/*
 * Independent legacy outcome table: rows are unsupported/supported spinlock,
 * columns are neither/Choicy/full blacklist/both. Restrictions and first load
 * are then applied in the legacy prehook order. No production helper is used.
 */
static enum app_isolation_route legacy_route(
    const struct app_isolation_context *context)
{
    static const enum app_isolation_route table[2][4] = {
        {APP_ISOLATION_ROUTE_NORMAL, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE,
         APP_ISOLATION_ROUTE_BLACKLIST_NATIVE,
         APP_ISOLATION_ROUTE_BLACKLIST_NATIVE},
        {APP_ISOLATION_ROUTE_NORMAL, APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK,
         APP_ISOLATION_ROUTE_BLACKLIST_NATIVE,
         APP_ISOLATION_ROUTE_BLACKLIST_NATIVE}
    };
    const unsigned int supported =
        context->ios15_arm64e && context->global_dyld_fix;
    const unsigned int blocked = (context->choicy_blocked ? 1u : 0u) |
                                (context->effective_blacklisted ? 2u : 0u);
    enum app_isolation_route route = table[supported][blocked];
    if (blocked >= 2 && supported &&
        (context->is_extension || context->active_prewarm ||
         context->dyld_use_closures)) {
        route = APP_ISOLATION_ROUTE_REJECT;
    } else if (blocked == 0 && context->launchd_first_load) {
        route = APP_ISOLATION_ROUTE_ORIGINAL;
    }
    return route;
}

static void test_full_flag_matrix(void)
{
    for (unsigned int mask = 0; mask < (1u << 11); ++mask) {
        const struct app_isolation_context context = {
            .ios15_arm64e = (mask & (1u << 0)) != 0,
            .global_dyld_fix = (mask & (1u << 1)) != 0,
            .effective_blacklisted = (mask & (1u << 2)) != 0,
            .choicy_blocked = (mask & (1u << 3)) != 0,
            .ordinary_removable_app = (mask & (1u << 4)) != 0,
            .not_trollstore = (mask & (1u << 5)) != 0,
            .spinlock_safe_opt_in = (mask & (1u << 6)) != 0,
            .is_extension = (mask & (1u << 7)) != 0,
            .active_prewarm = (mask & (1u << 8)) != 0,
            .dyld_use_closures = (mask & (1u << 9)) != 0,
            .launchd_first_load = (mask & (1u << 10)) != 0
        };
        enum app_isolation_route expected = legacy_route(&context);
        /* Exactly one new eligible legacy-native case is allowed to change. */
        if (expected == APP_ISOLATION_ROUTE_BLACKLIST_NATIVE &&
            context.effective_blacklisted && context.ios15_arm64e &&
            context.global_dyld_fix && context.ordinary_removable_app &&
            context.not_trollstore && context.spinlock_safe_opt_in) {
            expected = APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK;
        }
        char name[64];
        (void)snprintf(name, sizeof(name), "flag matrix 0x%03x", mask);
        expect_route(name, &context, expected);

        if (!context.spinlock_safe_opt_in) {
            (void)snprintf(name, sizeof(name),
                           "legacy opt-in off 0x%03x", mask);
            expect_route(name, &context, legacy_route(&context));
        }
    }
}

static void test_extension_paths(void)
{
    static const struct {
        const char *path;
        bool expected;
    } cases[] = {
        {NULL, false},
        {"", false},
        {"/", false},
        {"/var/containers/Bundle/Application/UUID/App.app/App", false},
        {"/private/var/containers/Bundle/Application/UUID/App.app/App", false},
        {"/App.app/PlugIns/Widget.appex/Widget", true},
        {"/App.app/PlugIns/Widget", true},
        {"/App.app/Extensions/Widget", true},
        {"/App.app/Other/Widget.appex/Widget", true},
        {"Widget.appex/Widget", true},
        {"/PlugIns/", true},
        {"/Extensions/", true},
        {".appex/", true},
        {"/App.app/PlugIns", false},
        {"/App.app/Extensions", false},
        {"/App.app/Widget.appex", false},
        {"/App.app/PlugInsExtra/Widget", false},
        {"/App.app/ExtensionsExtra/Widget", false},
        {"/App.app/Widget.appexExtra/Widget", false},
        {"/App.app/plugins/Widget", false},
        {"/App.app/extensions/Widget", false},
        {"/App.app/Widget.APPEX/Widget", false},
        {"PlugIns/Widget", false},
        {"Extensions/Widget", false},
        {"/App.app/OtherPlugIns/Widget", false},
        {"/App.app/PlugIns/../App", true}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const bool actual = app_isolation_path_is_extension(cases[i].path);
        ++checks;
        if (actual != cases[i].expected) {
            ++failures;
            fprintf(stderr, "extension path %zu (%s): expected %d, got %d\n",
                    i, cases[i].path ? cases[i].path : "NULL",
                    cases[i].expected, actual);
        }
    }
}

static void expect_inserts(const char *name, const char *input,
                           const char *root, const char *active_hook,
                           const char *expected)
{
    char *actual = RHIsolationCopyLibraryInserts(input, root, active_hook);
    ++checks;
    if ((!expected && actual) ||
        (expected && (!actual || strcmp(actual, expected) != 0))) {
        ++failures;
        fprintf(stderr, "%s: expected [%s], got [%s]\n", name,
                expected ? expected : "NULL", actual ? actual : "NULL");
    }
    free(actual);
}

static void test_library_filter(void)
{
    static const struct {
        const char *name;
        const char *input;
        const char *root;
        const char *active_hook;
        const char *expected;
    } cases[] = {
        {"null input", NULL, "/var/jb", NULL, NULL},
        {"empty input", "", "/var/jb", NULL, ""},
        {"empty components", ":a::b:", "/var/jb", NULL, ":a::b:"},
        {"only empty components", "::", "/var/jb", NULL, "::"},
        {"public systemhook", "/usr/lib/systemhook.dylib", NULL, NULL, ""},
        {"public branded hook", "/usr/lib/systemhook-0123456789aBcDeF.dylib",
         NULL, NULL, ""},
        {"exact active hook", "/custom/current-hook.dylib:/other/current-hook.dylib",
         NULL, "/custom/current-hook.dylib", "/other/current-hook.dylib"},
        {"active hook relative name preserved", "current-hook.dylib",
         NULL, "current-hook.dylib", "current-hook.dylib"},
        {"active hook traversal preserved", "/custom/../current-hook.dylib",
         NULL, "/custom/../current-hook.dylib", "/custom/../current-hook.dylib"},
        {"active hook match is exact", "/private/var/jb/custom-hook.dylib",
         NULL, "/var/jb/custom-hook.dylib", "/private/var/jb/custom-hook.dylib"},
        {"foreign basename preserved", "/thirdparty/systemhook.dylib:/libellekit.dylib",
         "/var/jb", NULL, "/thirdparty/systemhook.dylib:/libellekit.dylib"},
        {"relative known basenames preserved",
         "systemhook.dylib:libellekit.dylib:TweakLoader.dylib:roothideinit.dylib",
         "/var/jb", NULL,
         "systemhook.dylib:libellekit.dylib:TweakLoader.dylib:roothideinit.dylib"},
        {"foreign root engine preserved", "/foreign/jb/usr/lib/libellekit.dylib",
         "/var/jb", NULL, "/foreign/jb/usr/lib/libellekit.dylib"},
        {"root prefix lookalike preserved", "/var/jb-other/usr/lib/libellekit.dylib",
         "/var/jb", NULL, "/var/jb-other/usr/lib/libellekit.dylib"},
        {"root private alias removed", "/private/var/jb/usr/lib/libellekit.dylib",
         "/var/jb", NULL, ""},
        {"root public alias removed", "/var/jb/usr/lib/libellekit.dylib",
         "/private/var/jb", NULL, ""},
        {"root with trailing slash", "/var/jb/usr/lib/libellekit.dylib",
         "/var/jb/", NULL, ""},
        {"root with private alias and slash", "/var/jb/usr/lib/libellekit.dylib",
         "/private/var/jb/", NULL, ""},
        {"random jbroot", "/var/containers/Bundle/Application/.jbroot-0123/basebin/systemhook.dylib",
         "/var/containers/Bundle/Application/.jbroot-0123", NULL, ""},
        {"random jbroot alias", "/private/var/containers/Bundle/Application/.jbroot-0123/usr/lib/roothidepatch.dylib",
         "/var/containers/Bundle/Application/.jbroot-0123", NULL, ""},
        {"traversal preserved", "/var/jb/usr/lib/../lib/libellekit.dylib",
         "/var/jb", NULL, "/var/jb/usr/lib/../lib/libellekit.dylib"},
        {"dot component preserved", "/var/jb/./usr/lib/libellekit.dylib",
         "/var/jb", NULL, "/var/jb/./usr/lib/libellekit.dylib"},
        {"duplicate slash preserved", "/var/jb//usr/lib/libellekit.dylib",
         "/var/jb", NULL, "/var/jb//usr/lib/libellekit.dylib"},
        {"trailing slash preserved", "/var/jb/usr/lib/libellekit.dylib/",
         "/var/jb", NULL, "/var/jb/usr/lib/libellekit.dylib/"},
        {"public traversal preserved", "/usr/lib/../lib/systemhook.dylib",
         "/var/jb", NULL, "/usr/lib/../lib/systemhook.dylib"},
        {"null root preserves engines", "/var/jb/usr/lib/libellekit.dylib",
         NULL, NULL, "/var/jb/usr/lib/libellekit.dylib"},
        {"empty root preserves engines", "/var/jb/usr/lib/libellekit.dylib",
         "", NULL, "/var/jb/usr/lib/libellekit.dylib"},
        {"root slash cannot claim engines", "/usr/lib/libellekit.dylib",
         "/", NULL, "/usr/lib/libellekit.dylib"},
        {"relative root cannot claim engines", "var/jb/usr/lib/libellekit.dylib",
         "var/jb", NULL, "var/jb/usr/lib/libellekit.dylib"},
        {"noncanonical root cannot claim engines", "/var/jb/usr/lib/libellekit.dylib",
         "/var/./jb", NULL, "/var/jb/usr/lib/libellekit.dylib"},
        {"double root trailing slash preserves engines", "/var/jb/usr/lib/libellekit.dylib",
         "/var/jb//", NULL, "/var/jb/usr/lib/libellekit.dylib"},
        {"nearby hex names survive",
         "/usr/lib/systemhook-0123456789abcde.dylib:/usr/lib/systemhook-0123456789abcdef0.dylib:/usr/lib/systemhook-0123456789abcdeg.dylib",
         "/var/jb", NULL,
         "/usr/lib/systemhook-0123456789abcde.dylib:/usr/lib/systemhook-0123456789abcdef0.dylib:/usr/lib/systemhook-0123456789abcdeg.dylib"},
        {"filename suffix survives", "/usr/lib/systemhook.dylib.backup",
         "/var/jb", NULL, "/usr/lib/systemhook.dylib.backup"},
        {"filename case survives", "/usr/lib/Systemhook.dylib",
         "/var/jb", NULL, "/usr/lib/Systemhook.dylib"},
        {"unknown root library survives", "/var/jb/usr/lib/ThirdParty.dylib",
         "/var/jb", NULL, "/var/jb/usr/lib/ThirdParty.dylib"},
        {"engine wrong directory survives", "/var/jb/basebin/libellekit.dylib",
         "/var/jb", NULL, "/var/jb/basebin/libellekit.dylib"},
        {"engine suffix survives", "/var/jb/usr/lib/libellekit.dylib.old",
         "/var/jb", NULL, "/var/jb/usr/lib/libellekit.dylib.old"},
        {"foreign libhooker survives", "/foreign/usr/lib/libhooker/libinjector.dylib",
         "/var/jb", NULL, "/foreign/usr/lib/libhooker/libinjector.dylib"},
        {"keep empty separators and order",
         ":/usr/lib/systemhook.dylib:a::/var/jb/usr/lib/libellekit.dylib:b:",
         "/var/jb", NULL, ":a::b:"},
        {"all owned entries removed",
         "/usr/lib/systemhook.dylib:/var/jb/basebin/systemhook-0123456789ABCDEF.dylib:/var/jb/usr/lib/roothideinit.dylib",
         "/var/jb", NULL, ""},
        {"adjacent kept libraries",
         "a:/usr/lib/systemhook.dylib:b:/var/jb/basebin/forkfix.dylib:c",
         "/var/jb", NULL, "a:b:c"},
        {"retained duplicates", "a:a:/usr/lib/systemhook.dylib:a",
         "/var/jb", NULL, "a:a:a"},
        {"empty surrounding removed hook", ":/usr/lib/systemhook.dylib:",
         "/var/jb", NULL, ":"},
        {"empty preceding removed hook", ":/usr/lib/systemhook.dylib",
         "/var/jb", NULL, ""},
        {"hook entry argument aliases input", "/custom/hook.dylib",
         "/var/jb", "/custom/hook.dylib", ""}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        expect_inserts(cases[i].name, cases[i].input, cases[i].root,
                       cases[i].active_hook, cases[i].expected);
    }

    static const char *const owned[] = {
        "/basebin/systemhook.dylib",
        "/basebin/systemhook-0000000000000000.dylib",
        "/basebin/systemhook-FFFFFFFFFFFFFFFF.dylib",
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
    for (size_t i = 0; i < sizeof(owned) / sizeof(owned[0]); ++i) {
        char input[256];
        (void)snprintf(input, sizeof(input), "/var/jb%s", owned[i]);
        expect_inserts(owned[i], input, "/var/jb", NULL, "");
        (void)snprintf(input, sizeof(input), "/private/var/jb%s", owned[i]);
        expect_inserts(owned[i], input, "/var/jb", NULL, "");
        (void)snprintf(input, sizeof(input), "/thirdparty%s", owned[i]);
        expect_inserts(owned[i], input, "/var/jb", NULL, input);
    }

    /* Exercise every separator placement without a production-code oracle. */
    static const char *const pieces[] = {
        "", "thirdparty.dylib", "/usr/lib/systemhook.dylib",
        "/private/var/jb/usr/lib/libellekit.dylib"
    };
    for (size_t a = 0; a < 4; ++a) {
        for (size_t b = 0; b < 4; ++b) {
            for (size_t c = 0; c < 4; ++c) {
                const size_t indexes[] = {a, b, c};
                char input[256];
                char expected[256] = {0};
                size_t used = 0;
                bool have_entry = false;
                (void)snprintf(input, sizeof(input), "%s:%s:%s",
                               pieces[a], pieces[b], pieces[c]);
                for (size_t i = 0; i < 3; ++i) {
                    if (indexes[i] > 1) continue;
                    if (have_entry) expected[used++] = ':';
                    const size_t length = strlen(pieces[indexes[i]]);
                    memcpy(expected + used, pieces[indexes[i]], length);
                    used += length;
                    have_entry = true;
                }
                expected[used] = '\0';
                expect_inserts("separator matrix", input, "/var/jb", NULL,
                               expected);
            }
        }
    }

    /* The function returns independent owned storage and never edits its input. */
    char mutable_input[] = "/usr/lib/systemhook.dylib:thirdparty.dylib";
    char *result = RHIsolationCopyLibraryInserts(mutable_input, "/var/jb", NULL);
    ++checks;
    if (!result || result == mutable_input ||
        strcmp(mutable_input,
               "/usr/lib/systemhook.dylib:thirdparty.dylib") != 0) {
        ++failures;
        fprintf(stderr, "filter must allocate and preserve input\n");
    }
    free(result);
}

int main(void)
{
    test_named_routes();
    test_full_flag_matrix();
    test_extension_paths();
    test_library_filter();
    if (failures) {
        fprintf(stderr, "app isolation policy: %u/%u checks failed\n",
                failures, checks);
        return EXIT_FAILURE;
    }
    printf("app isolation policy: %u checks passed (2048 flag combinations)\n",
           checks);
    return EXIT_SUCCESS;
}
