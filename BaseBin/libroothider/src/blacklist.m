#import <Foundation/Foundation.h>

#include <libjailbreak/libjailbreak.h>
#include "common.h"


#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
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
    if (!appInfo) return nil;

    NSString *identifier = appInfo[@"CFBundleIdentifier"];
    if (!identifier) return nil;

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

bool isBlacklistedApp(const char* identifier)
{
    if(!identifier) return false;

    if([builtinApps() containsObject:@(identifier)]) return false;

    NSString* configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    NSDictionary* roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!roothideConfig) return false;

    NSDictionary* appconfig = roothideConfig[@"appconfig"];
    if(!appconfig) return false;

    NSNumber* blacklisted = appconfig[@(identifier)];
    if(!blacklisted) return false;

    return blacklisted.boolValue;
}

bool isBlacklistedPath(const char* path)
{
    if(!path) return false;
    NSString* identifier = getAppIdentifierFromPath(path);
    if(!identifier) return false;
    return isBlacklistedApp(identifier.UTF8String);
}

// Resolve a verified main executable in a user app bundle to its identifier.
static NSString *isolationAppIdentifier(const char *path)
{
    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath) return nil;
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[bundlePath stringByAppendingPathComponent:@"Info.plist"]];
    if (![info isKindOfClass:NSDictionary.class]) return nil;
    NSString *identifier = info[@"CFBundleIdentifier"];
    NSString *executable = info[@"CFBundleExecutable"];
    if (![identifier isKindOfClass:NSString.class] || !identifier.length ||
        ![executable isKindOfClass:NSString.class] || !executable.length ||
        [executable containsString:@"/"]) return nil;
    NSString *expected = [[bundlePath stringByAppendingPathComponent:executable] stringByResolvingSymlinksInPath];
    NSString *actual = [[NSString stringWithUTF8String:path] stringByResolvingSymlinksInPath];
    if (![actual isEqualToString:expected]) return nil;
    return identifier;
}

static id isolationOverrideValue(const char *path)
{
    NSString *identifier = isolationAppIdentifier(path);
    if (!identifier) return nil;
    NSDictionary *preferences = [NSDictionary dictionaryWithContentsOfFile:
        JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist")];
    if (![preferences isKindOfClass:NSDictionary.class]) return nil;
    NSDictionary *apps = preferences[@"appconfigSpinlockSafe"];
    if (![apps isKindOfClass:NSDictionary.class]) return nil;
    id value = apps[identifier];
    if (!value || CFGetTypeID((__bridge CFTypeRef)value) != CFBooleanGetTypeID()) return nil;
    return value;
}

// Only an explicit Boolean false disables the automatic route for one app.
bool appSpinlockIsolationOptedOut(const char *path)
{
    id value = isolationOverrideValue(path);
    return value && !CFBooleanGetValue((__bridge CFBooleanRef)value);
}
