#import <Foundation/Foundation.h>

#include <libjailbreak/libjailbreak.h>
#include "common.h"
#include <sys/stat.h>

// Host tests substitute only a private system-temporary container root.
#ifndef APP_PATH_PREFIX
#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
#endif
#define NULL_UUID "00000000-0000-0000-0000-000000000000"

NSString *getAppBundlePathFromSpawnPath(const char *path)
{
    if (!path) return nil;

    char abspath[PATH_MAX];
    if (!realpath(path, abspath)) return nil;

    if (strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX) - 1) != 0)
        return nil;

    char *p1 = abspath + sizeof(APP_PATH_PREFIX) - 1;
    char *p2 = strchr(p1, '/');
    if (!p2) return nil;

    //is normal app or jailbroken app/daemon?
    if ((p2 - p1) != (sizeof(NULL_UUID) - 1))
        return nil;

    char *p = strstr(p2, ".app/");
    if (!p) return nil;

    p[sizeof(".app/") - 1] = '\0';

    return [NSString stringWithUTF8String:abspath];
}

// get main bundle identifier of app for (PlugIns's) executable path
NSString *getAppIdentifierFromPath(const char *path)
{
    if (!path) return nil;

    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath) return nil;

    NSDictionary *appInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath]];
    if (![appInfo isKindOfClass:NSDictionary.class]) return nil;

    NSString *identifier = appInfo[@"CFBundleIdentifier"];
    if (![identifier isKindOfClass:NSString.class] || !identifier.length) return nil;

    return identifier;
}

NSSet* builtinApps()
{
    static NSSet* apps = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        JBLogDebug("Initializing builtin apps set");
        apps = [NSSet setWithObjects:@"com.opa334.Dopamine-roothide", nil];
        NSString* customBundleId = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.AppIdentifier") encoding:NSUTF8StringEncoding error:nil];
        if(customBundleId && customBundleId.length > 0) {
            JBLogDebug("Added custom bundle identifier to builtin apps: %s", customBundleId.UTF8String);
            apps = [apps setByAddingObject:customBundleId];
        }
    });
    return apps;
}

static NSDictionary *doimtyCopyRootHideConfig(void)
{
    NSString *path = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    if (!path) return nil;
    NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:path];
    return [config isKindOfClass:NSDictionary.class] ? config : nil;
}

static bool doimtyBlacklistedInConfig(const char *identifier, NSDictionary *config)
{
    if (!identifier || [builtinApps() containsObject:@(identifier)]) return false;
    NSDictionary *appconfig = config[@"appconfig"];
    if (![appconfig isKindOfClass:NSDictionary.class]) return false;
    NSNumber *blacklisted = appconfig[@(identifier)];
    if (![blacklisted respondsToSelector:@selector(boolValue)]) return false;
    // Preserve official NSNumber / NSString boolValue conversion, not strict bool.
    return blacklisted.boolValue;
}

bool isBlacklistedApp(const char* identifier)
{
    // Preserve the official early exemption: builtins do not read RootHideConfig.
    if (!identifier || [builtinApps() containsObject:@(identifier)]) return false;
    return doimtyBlacklistedInConfig(identifier, doimtyCopyRootHideConfig());
}

bool isBlacklistedPath(const char* path)
{
    if(!path) return false;
    NSString* identifier = getAppIdentifierFromPath(path);
    if(!identifier) return false;
    return isBlacklistedApp(identifier.UTF8String);
}

// Eligibility is independent of blacklist membership and per-app opt-out.
// Resolve the actual canonical top-level .app main, never promote a helper/XPC.
static NSString *doimtyIsolationAppIdentifier(const char *path)
{
    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath) return nil;
    char bundleReal[PATH_MAX];
    if (!realpath(bundlePath.fileSystemRepresentation, bundleReal) ||
        strncmp(bundleReal, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX) - 1)) return nil;
    const char *container = bundleReal + sizeof(APP_PATH_PREFIX) - 1;
    const char *bundleName = strchr(container, '/');
    if (!bundleName || bundleName - container != sizeof(NULL_UUID) - 1 ||
        strchr(bundleName + 1, '/')) return nil;
    NSString *uuid = [[NSString alloc] initWithBytes:container
        length:bundleName - container encoding:NSUTF8StringEncoding];
    NSUUID *parsedUUID = uuid ? [[NSUUID alloc] initWithUUIDString:uuid] : nil;
    if (!parsedUUID || [parsedUUID.UUIDString caseInsensitiveCompare:uuid] != NSOrderedSame) return nil;
    bundlePath = [NSString stringWithUTF8String:bundleReal];
    if (![bundlePath.lastPathComponent hasSuffix:@".app"]) return nil;

    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
        [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
    if (![info isKindOfClass:NSDictionary.class]) return nil;
    NSString *identifier = info[@"CFBundleIdentifier"];
    NSString *executable = info[@"CFBundleExecutable"];
    if (![identifier isKindOfClass:NSString.class] || !identifier.length ||
        ![executable isKindOfClass:NSString.class] || !executable.length ||
        [executable isEqualToString:@"."] || [executable isEqualToString:@".."] ||
        [executable containsString:@"/"] ||
        [executable rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound) return nil;
    NSString *expected = [bundlePath stringByAppendingPathComponent:executable];
    struct stat st;
    // lstat must observe a regular main file, not a symlink. Require an execute
    // bit even when launchd/root's access(X_OK) would otherwise succeed.
    if (lstat(expected.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode) ||
        !(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) ||
        access(expected.fileSystemRepresentation, X_OK) != 0) return nil;
    char expectedReal[PATH_MAX], actualReal[PATH_MAX];
    if (!realpath(expected.fileSystemRepresentation, expectedReal) ||
        strcmp(expectedReal, expected.fileSystemRepresentation) != 0 ||
        !realpath(path, actualReal) || strcmp(actualReal, expectedReal) != 0) return nil;
    return identifier;
}

struct roothide_app_spawn_policy roothide_get_app_spawn_policy(const char *path)
{
    struct roothide_app_spawn_policy result = {0};
    if (!path) return result;
    // Non-app spawns retain the official early return, without config I/O.
    NSString *legacyIdentifier = getAppIdentifierFromPath(path);
    if (!legacyIdentifier) return result;
    // A failed or malformed read is an empty official blacklist, not last-good.
    // Keep this one NSDictionary alive through both membership and opt-out.
    NSDictionary *config = [builtinApps() containsObject:legacyIdentifier] ? nil : doimtyCopyRootHideConfig();
    result.blacklisted = doimtyBlacklistedInConfig(legacyIdentifier.UTF8String, config);
    NSString *identifier = doimtyIsolationAppIdentifier(path);
    // If bundle metadata changed between reads, do not promote a different ID
    // using membership from the earlier read.
    if (![identifier isEqualToString:legacyIdentifier]) identifier = nil;
    result.verified_main_executable = identifier != nil;
    NSDictionary *overrides = config[@"appconfigSpinlockSafe"];
    if (identifier && [overrides isKindOfClass:NSDictionary.class]) {
        id value = overrides[identifier];
        // Only an actual plist CFBoolean false opts out. 0 / "false" / bad
        // sections are not an opt-out and retain the automatic default.
        result.isolation_opted_out = value &&
            CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID() &&
            !CFBooleanGetValue((__bridge CFBooleanRef)value);
    }
    return result;
}
