// Stub implementations for the TIPA update path (see the Makefile note).
// update_target.m is excluded from the jbctl build because its
// JBCTLUpdatePackage ObjC class is the only class defined in jbctl, and its
// class metadata crashes the ObjC runtime at launch on arm64e (readClass PAC
// failure, before main() runs), so jbctl never runs launchd_stash_port and
// the injected hook panics with "Failed to recover primitives (error -2)".
// Official roothide's jbctl defines no ObjC classes. This stub keeps the
// symbols main.m references so it still links unchanged; the preflight
// always returns nil, so the TIPA path fails gracefully through main.m's
// existing error branch ("TIPA preflight failed..."). Use tarball/basebin
// updates until the class issue is resolved. The production preflight in
// update_target.m is still exercised by the update-contracts native test.
#import <Foundation/Foundation.h>
#import "update_target.h"

NSString * const JBCTLDopamineBundleIdentifier = @"com.doimty.dopamine";

JBCTLUpdatePackage * _Nullable jbctl_update_preflight_tipa(NSString *path) {
    (void)path;
    return nil;
}

NSString * _Nullable jbctl_update_bound_basebin_path(NSString * _Nullable bundlePath, JBCTLUpdatePackage * _Nullable package) {
    (void)bundlePath;
    (void)package;
    return nil;
}
