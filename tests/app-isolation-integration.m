#import <Foundation/Foundation.h>
#include <libjailbreak/libjailbreak.h>
#include "common.h"
#include "app_isolation_policy.h"
#include "app_isolation_spawn.h"
#include <objc/runtime.h>
#include <sys/stat.h>
#include <errno.h>

#ifndef APP_PATH_PREFIX
#error Test runner must supply its private canonical system-temporary container root.
#endif

// Declared here because the launchdhook include path also ships a common.h.
NSString *getAppIdentifierFromPath(const char *path);
NSSet *builtinApps(void);

static char rootPath[PATH_MAX];
static unsigned checks, configReads, infoReads;
static NSData *replaceAfterRead;
static NSString *const bundleID = @"com.example.isolation";
char *get_jbroot(void) { return rootPath; }

static void require(BOOL value, NSString *message)
{
    checks++;
    if (!value) { fprintf(stderr, "FAIL: %s\n", message.UTF8String); exit(1); }
}
static void makeDirectory(NSString *path)
{
    require([NSFileManager.defaultManager createDirectoryAtPath:path
        withIntermediateDirectories:YES attributes:nil error:NULL], @"mkdir fixture");
}
static void writeBytes(NSString *path, NSString *text)
{
    require([[text dataUsingEncoding:NSUTF8StringEncoding] writeToFile:path atomically:NO], @"write fixture bytes");
}
static NSData *plistData(id value)
{
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:value
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    require(data != nil, @"serialize fixture plist");
    return data;
}
static void writePlist(NSString *path, id value)
{
    require([plistData(value) writeToFile:path options:NSDataWritingAtomic error:NULL], @"replace fixture plist");
}
static void removePath(NSString *path)
{
    require([NSFileManager.defaultManager removeItemAtPath:path error:NULL], @"remove fixture");
}
static void makeExecutable(NSString *path)
{
    makeDirectory(path.stringByDeletingLastPathComponent);
    writeBytes(path, @"fixture only; never executed\n");
    require(chmod(path.fileSystemRepresentation, 0755) == 0, @"chmod fixture");
}
static void makeSymlink(NSString *target, NSString *link)
{
    require(symlink(target.fileSystemRepresentation, link.fileSystemRepresentation) == 0, @"symlink fixture");
}
static NSDictionary *info(NSString *identifier, id executable)
{
    return @{ @"CFBundleIdentifier": identifier, @"CFBundleExecutable": executable };
}
static NSDictionary *config(id blacklisted, id override)
{
    NSMutableDictionary *value = [@{ @"appconfig": @{ bundleID: blacklisted } } mutableCopy];
    if (override) value[@"appconfigSpinlockSafe"] = @{ bundleID: override };
    return value;
}

// Instrument only Foundation's file read to prove one production config snapshot.
// Mutation after that read simulates a real atomic replacement, not hand-filled
// membership/eligibility. It does not replace any production policy logic.
@interface NSDictionary (DoimtyIsolationReadProbe)
+ (instancetype)doimty_readProbe:(NSString *)path;
@end
@implementation NSDictionary (DoimtyIsolationReadProbe)
+ (instancetype)doimty_readProbe:(NSString *)path
{
    id snapshot = [self doimty_readProbe:path];
    if ([path.lastPathComponent isEqualToString:@"Info.plist"]) infoReads++;
    if ([path.lastPathComponent isEqualToString:@"RootHideConfig.plist"]) {
        configReads++;
        if (replaceAfterRead) {
            NSData *replacement = replaceAfterRead;
            replaceAfterRead = nil;
            require([replacement writeToFile:path options:NSDataWritingAtomic error:NULL], @"atomic concurrent replacement");
        }
    }
    return snapshot;
}
@end

static struct roothide_app_spawn_policy expectPolicy(NSString *name, NSString *path,
    bool blacklisted, bool eligible, bool optedOut)
{
    NSString *legacyID = getAppIdentifierFromPath(path.fileSystemRepresentation);
    unsigned expectedReads = legacyID && ![builtinApps() containsObject:legacyID] ? 1 : 0;
    configReads = infoReads = 0;
    struct roothide_app_spawn_policy p = roothide_get_app_spawn_policy(path.fileSystemRepresentation);
    require(configReads == expectedReads, [name stringByAppendingString:@" preserves config read budget"]);
    require(p.blacklisted == blacklisted && p.verified_main_executable == eligible &&
        p.isolation_opted_out == optedOut, [NSString stringWithFormat:@"%@ got %d/%d/%d", name,
        p.blacklisted, p.verified_main_executable, p.isolation_opted_out]);
    require(isBlacklistedPath(path.fileSystemRepresentation) == blacklisted,
        [name stringByAppendingString:@" retains official boolValue blacklist"]);
    return p;
}

struct readiness { unsigned calls; bool available; };
static bool ready(void *opaque)
{
    struct readiness *r = opaque;
    r->calls++;
    return r->available;
}
static enum app_isolation_route routeFor(NSString *path, bool global, bool supported,
    bool dyld, bool firstLoad, bool choicy, bool prewarm, bool closures,
    struct readiness *readiness)
{
    struct app_isolation_context c = {
        .ios15_arm64e = supported, .global_dyld_fix = dyld,
        .global_isolation_enabled = global,
        .choicy_blocked = choicy,
        .is_extension = app_isolation_path_is_extension(path.fileSystemRepresentation),
        .active_prewarm = prewarm, .dyld_use_closures = closures,
        .launchd_first_load = firstLoad,
    };
    return app_isolation_classify_path(path.fileSystemRepresentation, &c, ready, readiness);
}
static void expectRoute(NSString *name, NSString *path, bool global, bool supported,
    bool dyld, bool firstLoad, bool choicy, bool prewarm, bool closures,
    bool available, enum app_isolation_route expected, unsigned pings)
{
    configReads = infoReads = 0;
    (void)isBlacklistedPath(path.fileSystemRepresentation);
    unsigned legacyConfigReads = configReads, legacyInfoReads = infoReads;
    configReads = infoReads = 0;
    struct readiness r = {0, available};
    require(routeFor(path, global, supported, dyld, firstLoad, choicy, prewarm,
        closures, &r) == expected, name);
    require(r.calls == pings, [name stringByAppendingString:@" readiness gate order"]);
    if (!(global && supported && dyld && !firstLoad)) {
        require(configReads == legacyConfigReads && infoReads == legacyInfoReads,
            [name stringByAppendingString:@" disabled classifier does only official I/O"]);
    }
}

static void testLegacyMatrix(NSString *path)
{
    // Every membership/qualification input still comes from the real factory.
    // The reference below is the official five-route behavior, exhaustive across
    // dyld/firstload/Choicy/prewarm/closures with globaloff or unsupported.
    struct roothide_app_spawn_policy p = roothide_get_app_spawn_policy(path.fileSystemRepresentation);
    for (unsigned mode = 0; mode < 2; mode++)
    for (unsigned bits = 0; bits < 32; bits++) {
        bool global = mode != 0, supported = mode == 0;
        bool dyld = bits & 1, first = bits & 2, choicy = bits & 4;
        bool prewarm = bits & 8, closures = bits & 16;
        bool spinlock = supported && dyld;
        enum app_isolation_route expected;
        if (p.blacklisted) {
            expected = spinlock && (app_isolation_path_is_extension(path.fileSystemRepresentation) || prewarm || closures)
                ? APP_ISOLATION_ROUTE_REJECT : APP_ISOLATION_ROUTE_BLACKLIST_NATIVE;
        } else if (choicy) {
            expected = spinlock ? APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK : APP_ISOLATION_ROUTE_BLACKLIST_NATIVE;
        } else {
            expected = first ? APP_ISOLATION_ROUTE_ORIGINAL : APP_ISOLATION_ROUTE_NORMAL;
        }
        expectRoute(@"official globaloff/unsupported route matrix", path, global, supported,
            dyld, first, choicy, prewarm, closures, true, expected, 0);
    }
}

// Integration through the same readiness adapter, owned environment factory and
// production lifecycle driver. These callbacks never create or signal processes.
struct adapter {
    short flags;
    pid_t publication;
    pid_t *registered;
    char **environment;
    int repairError;
    unsigned spawns, repairs, resumes, kills;
};
static int adapterGet(void *opaque, short *flags)
{
    *flags = ((struct adapter *)opaque)->flags;
    return 0;
}
static int adapterSet(void *opaque, short flags)
{
    ((struct adapter *)opaque)->flags = flags;
    return 0;
}
static int adapterSpawn(void *opaque, pid_t *published)
{
    struct adapter *a = opaque;
    require(published == a->registered && (a->flags & 0x80), @"registered exact PID and suspended spawn");
    require(a->environment && !strcmp(a->environment[0], "KEEP=yes") &&
        !strcmp(a->environment[1], "DYLD_INSERT_LIBRARIES=/opt/foreign/keep.dylib") &&
        !a->environment[2], @"production environment filter reaches adapter");
    a->spawns++;
    *published = 4242;
    return 0;
}
static int adapterRepair(void *opaque, pid_t child)
{
    struct adapter *a = opaque;
    require(child == a->publication && a->flags == 0, @"repair sees restored attrs and exact child");
    a->repairs++;
    return a->repairError;
}
static int adapterResume(void *opaque, pid_t child)
{
    struct adapter *a = opaque;
    require(child == a->publication && !a->repairError && a->repairs == 1, @"resume only after acknowledgment");
    a->resumes++;
    return 0;
}
static int adapterKill(void *opaque, pid_t child)
{
    struct adapter *a = opaque;
    require(child == a->publication && !a->resumes, @"failed repair child terminated before resume");
    a->kills++;
    return 0;
}
static void testAdapter(NSString *main, int repairError)
{
    struct readiness r = {0, true};
    require(routeFor(main, true, true, true, false, false, false, false, &r) ==
        APP_ISOLATION_ROUTE_BLACKLIST_STRICT && r.calls == 1, @"real production factory chooses strict adapter");
    const char *env[] = {"KEEP=yes", "_SafeMode=1", "_MSSafeMode=1",
        "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib:/opt/foreign/keep.dylib", NULL};
    struct adapter a = { .repairError = repairError };
    a.registered = &a.publication;
    a.environment = RHIsolationCopyEnvironment(env, rootPath, "/usr/lib/systemhook.dylib");
    const struct app_isolation_spawn_ops ops = {adapterGet, adapterSet, adapterSpawn,
        adapterRepair, adapterResume, adapterKill};
    struct app_isolation_spawn_report report = app_isolation_spawn(&ops, &a,
        a.registered, 0x80);
    require(report.result == 0 && report.created && a.spawns == 1 && a.repairs == 1,
        @"single created child, no repeated spawn");
    require(report.error == repairError && a.resumes == !repairError && a.kills == !!repairError,
        @"repair failure has kill and zero resume, success has one resume");
    require(a.publication == 4242 && a.flags == 0, @"publication and caller attrs preserved");
    RHIsolationFreeEnvironment(a.environment);
}

int main(int argc, char **argv)
{
    @autoreleasepool {
        require(argc == 2, @"supply system-temporary fixture root");
        require(strlcpy(rootPath, argv[1], sizeof(rootPath)) < sizeof(rootPath), @"root length");
        Method original = class_getClassMethod(NSDictionary.class, @selector(dictionaryWithContentsOfFile:));
        Method probe = class_getClassMethod(NSDictionary.class, @selector(doimty_readProbe:));
        require(original && probe, @"Foundation read instrumentation exists");
        method_exchangeImplementations(original, probe);
        NSString *root = @(rootPath);
        NSString *container = [@APP_PATH_PREFIX stringByAppendingPathComponent:@"12345678-1234-1234-1234-123456789012"];
        NSString *bundle = [container stringByAppendingPathComponent:@"App.app"];
        NSString *main = [bundle stringByAppendingPathComponent:@"Main"];
        NSString *helper = [bundle stringByAppendingPathComponent:@"Helpers/helper"];
        NSString *xpc = [bundle stringByAppendingPathComponent:@"XPCServices/Helper.xpc/Helper"];
        NSString *extension = [bundle stringByAppendingPathComponent:@"PlugIns/Widget.appex/Widget"];
        NSString *infoPath = [bundle stringByAppendingPathComponent:@"Info.plist"];
        NSString *configDir = [root stringByAppendingPathComponent:@"var/mobile/Library/RootHide"];
        NSString *configuration = [configDir stringByAppendingPathComponent:@"RootHideConfig.plist"];
        makeDirectory(configDir);
        for (NSString *path in @[main, helper, xpc, extension]) makeExecutable(path);
        writePlist(infoPath, info(bundleID, @"Main"));
        expectPolicy(@"missing config", main, false, true, false);
        writePlist(configuration, config(@YES, @NO));
        expectPolicy(@"strict Boolean false", main, true, true, true);
        expectRoute(@"explicit optout native", main, true, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 0);
        replaceAfterRead = plistData(config(@NO, @YES));
        configReads = 0;
        struct roothide_app_spawn_policy raced = roothide_get_app_spawn_policy(main.fileSystemRepresentation);
        require(configReads == 1 && raced.blacklisted && raced.isolation_opted_out, @"atomic replacement cannot split a production snapshot");
        expectPolicy(@"next call reads new config", main, false, true, false);
        writeBytes(configuration, @"bad plist");
        for (unsigned n = 0; n < 10; n++) expectPolicy(@"bad config never cached", main, false, true, false);
        writeBytes(configuration, @"");
        expectPolicy(@"empty config", main, false, true, false);
        writePlist(configuration, @[@"wrong root"]);
        expectPolicy(@"wrong config root", main, false, true, false);
        for (id section in @[@"wrong", @[], @1]) {
            writePlist(configuration, @{ @"appconfig": section });
            expectPolicy(@"wrong blacklist section", main, false, true, false);
        }
        for (id value in @[@0, @"false", @[], @{}]) {
            writePlist(configuration, config(@YES, value));
            expectPolicy(@"nonBoolean optout retains default", main, true, true, false);
        }
        writePlist(configuration, @{ @"appconfig": @{bundleID: @YES}, @"appconfigSpinlockSafe": @"wrong" });
        expectPolicy(@"wrong optout section default", main, true, true, false);
        writePlist(configuration, config(@"YES", @NO));
        expectPolicy(@"official string boolValue", main, true, true, true);
        writePlist(configuration, config(@1, nil));
        testLegacyMatrix(main);
        testLegacyMatrix(helper);
        testLegacyMatrix(extension);
        expectPolicy(@"official numeric boolValue", main, true, true, false);
        for (NSString *path in @[helper, xpc]) {
            expectPolicy(@"helper XPC membership independent", path, true, false, false);
            expectRoute(@"helper XPC native", path, true, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 0);
        }
        expectRoute(@"globaloff preserves blacklist native", main, false, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 0);
        expectRoute(@"unsupported no ping", main, true, false, true, false, false, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 0);
        expectRoute(@"dyldoff no ping", main, true, true, false, false, false, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 0);
        expectRoute(@"firstload no ping", main, true, true, true, true, false, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 0);
        expectRoute(@"extension official restriction wins", extension, true, true, true, false, true, false, false, true, APP_ISOLATION_ROUTE_REJECT, 0);
        expectRoute(@"prewarm official restriction wins", main, true, true, true, false, false, true, false, true, APP_ISOLATION_ROUTE_REJECT, 0);
        expectRoute(@"closures official restriction wins", main, true, true, true, false, false, false, true, true, APP_ISOLATION_ROUTE_REJECT, 0);
        expectRoute(@"helper readiness failed pre-spawn", main, true, true, true, false, false, false, false, false, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 1);
        expectRoute(@"strict ready", main, true, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_STRICT, 1);
        testAdapter(main, 0);
        testAdapter(main, ENOTSUP);
        writePlist(configuration, config(@NO, @NO));
        testLegacyMatrix(main);
        testLegacyMatrix(helper);
        expectRoute(@"Choicy-only spinlock unchanged", helper, true, true, true, false, true, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK, 0);
        expectRoute(@"Choicy-only globaloff unchanged", main, false, true, true, false, true, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_SPINLOCK, 0);
        expectRoute(@"Choicy unsupported native", main, true, false, true, false, true, false, false, true, APP_ISOLATION_ROUTE_BLACKLIST_NATIVE, 0);
        expectRoute(@"no blacklist normal", main, true, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_NORMAL, 0);
        expectRoute(@"no blacklist firstload original", main, true, true, true, true, false, false, false, true, APP_ISOLATION_ROUTE_ORIGINAL, 0);
        writePlist(configuration, config(@YES, @NO));
        NSString *alias = [root stringByAppendingPathComponent:@"main-alias"];
        makeSymlink(main, alias);
        expectPolicy(@"caller alias resolves regular actual main", alias, true, true, true);
        removePath(alias);
        removePath(main);
        makeSymlink(helper, main);
        expectPolicy(@"declared main symlink to helper", main, true, false, false);
        removePath(main);
        makeSymlink([bundle stringByAppendingPathComponent:@"Missing"], main);
        expectPolicy(@"broken main symlink", main, false, false, false);
        removePath(main);
        makeExecutable(main);
        require(chmod(main.fileSystemRepresentation, 0644) == 0, @"remove execute bits");
        expectPolicy(@"regular but not executable", main, true, false, false);
        require(chmod(main.fileSystemRepresentation, 0755) == 0, @"restore execute bits");
        removePath(main);
        makeDirectory(main);
        expectPolicy(@"main directory is not a regular file", main, true, false, false);
        removePath(main);
        makeExecutable(main);
        removePath(infoPath);
        expectPolicy(@"missing Info", main, false, false, false);
        writeBytes(infoPath, @"broken plist");
        expectPolicy(@"bad Info", main, false, false, false);
        writePlist(infoPath, @{ @"CFBundleIdentifier": bundleID });
        expectPolicy(@"missing executable only loses qualification", main, true, false, false);
        for (id value in @[@3, @"", @"Helpers/helper", @"Missing", @"..", @"Ma\nin"]) {
            writePlist(infoPath, info(bundleID, value));
            expectPolicy(@"wrong actual CFBundleExecutable", main, true, false, false);
        }
        writePlist(infoPath, @{ @"CFBundleIdentifier": @3, @"CFBundleExecutable": @"Main" });
        expectPolicy(@"wrong identifier type", main, false, false, false);
        writePlist(infoPath, info(bundleID, @"Main"));
        NSString *invalid = [@APP_PATH_PREFIX stringByAppendingPathComponent:@"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz/App.app"];
        NSString *invalidMain = [invalid stringByAppendingPathComponent:@"Main"];
        makeExecutable(invalidMain);
        writePlist([invalid stringByAppendingPathComponent:@"Info.plist"], info(bundleID, @"Main"));
        expectPolicy(@"legacy nonUUID blacklist not qualification", invalidMain, true, false, false);
        NSString *nested = [container stringByAppendingPathComponent:@"Nested/App.app"];
        NSString *nestedMain = [nested stringByAppendingPathComponent:@"Main"];
        makeExecutable(nestedMain);
        writePlist([nested stringByAppendingPathComponent:@"Info.plist"], info(bundleID, @"Main"));
        expectPolicy(@"legacy nested app blacklist not qualification", nestedMain, true, false, false);
        NSString *outside = [root stringByAppendingPathComponent:@"outside"];
        makeExecutable(outside);
        expectRoute(@"nonapp globaloff zero new reads", outside, false, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_NORMAL, 0);
        expectRoute(@"nonapp enabled zero config reads", outside, true, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_NORMAL, 0);
        expectPolicy(@"outside app", outside, false, false, false);
        removePath(main);
        makeSymlink(outside, main);
        expectPolicy(@"escaping main symlink", main, false, false, false);
        removePath(main);
        makeExecutable(main);
        for (NSString *marker in @[@"_TrollStore", @"_TrollStoreLite"]) {
            NSString *markerPath = [container stringByAppendingPathComponent:marker];
            writeBytes(markerPath, @"");
            expectPolicy(@"TS/TSLite retain main qualification", main, true, true, true);
            removePath(markerPath);
        }
        writePlist(infoPath, info(@"com.opa334.Dopamine-roothide", @"Main"));
        writePlist(configuration, @{ @"appconfig": @{ @"com.opa334.Dopamine-roothide": @YES } });
        expectPolicy(@"official builtin exemption", main, false, true, false);
        expectRoute(@"builtin globaloff skips configuration", main, false, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_NORMAL, 0);
        expectRoute(@"builtin enabled skips configuration", main, true, true, true, false, false, false, false, true, APP_ISOLATION_ROUTE_NORMAL, 0);
        method_exchangeImplementations(original, probe);
        printf("app-isolation-integration: %u checks passed; real Foundation/path/config factory and readiness/spawn adapter; no process execution\n", checks);
    }
    return 0;
}
