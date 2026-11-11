#import <Foundation/Foundation.h>

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <unistd.h>
#include <libgen.h>
#include <substrate.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <libroothider/libroothider.h>
#include <libroothider/jailbreakd.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/trustcache_fs.h>
#include <libjailbreak/jbserver.h>

#include "../systemhook/src/common/common.h"
#include "../systemhook/src/common/envbuf.h"
#include "jbserver/jbsettings.h"
#include "app_isolation_policy.h"
#include "app_isolation_spawn.h"

int roothider_inline_version = 0;
bool launchdhookFirstLoad = false;
const char* HOOK_DYLIB_PATH = NULL;
mach_port_t gJBServerAlternativePort = MACH_PORT_NULL;

extern void roothider_launchd_postinit(bool);
extern mach_port_t startAlternativeJBServer(void(^message_handler)(xpc_object_t));

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
extern int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *__restrict, int *__restrict) __API_AVAILABLE(macos(10.8), ios(6.0));
extern int posix_spawnattr_setexceptionports_np(posix_spawnattr_t *__restrict, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

//from launchdhook/spawn_hook.c
extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);
extern int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict]);

extern int systemwide_process_checkin(audit_token_t *processToken, char **rootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut, bool *forceCSAdhocOut);
extern int roothide_trust_executable_recurse(const char *executablePath, const char *processWorkingDir, xpc_object_t preferredArchsArray);

//from systemhook/roothide_common.c
int __sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
int __sysctlbyname(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int __sysctlbyname_hook(const char *name, size_t namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

/*
int (*sysctlbyname_orig)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
int sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)
{
	if (strcmp(name, "vm.shared_region_pivot") == 0) {
		return 0;
	}
	return sysctlbyname_orig(name, oldp, oldlenp, newp, newlen);
}
*/

void roothide_launchd_preinit()
{
#ifdef ENABLE_LOGS
	redirectLogDir();
	enableJBDLog(JBLogDebugFunction, JBLogErrorFunction);
#endif

	if (__builtin_available(iOS 19.0, *)) {
		// Boomerang uses task_resume because other processes cannot signal PID 1.
		// That releases the Mach suspension but leaves p_stat as SSTOP. A signal
		// from launchd to itself is allowed and completes the BSD SIGCONT handling.
		if (kill(getpid(), SIGCONT) != 0) {
			launchd_panic("Failed to clear launchd stopped state (errno %d).", errno);
			return;
		}
	}

	JBLogDebug("roothide_launchd_preinit");

	roothider_inline_version = [[NSProcessInfo processInfo] operatingSystemVersion].majorVersion;

	exec_set_patch(false);
}

void roothide_launchd_postinit(bool firstLoad)
{
	JBLogDebug("roothide_launchd_postinit: firstLoad=%d", firstLoad);

	launchdhookFirstLoad = firstLoad;

	exec_set_patch(true);

	if(firstLoad)
	{
		HOOK_DYLIB_PATH = "";
		
#ifdef __arm64e__
		if (!__builtin_available(iOS 16.0, *))
		{
			if(roothide_config_set_spinlock_fix(dyld_patch_enabled()) != 0) {
				launchd_panic("roothide_config_set_spinlock_fix failed");
				return;
			}
		}
#endif
	}
	else
	{		
		NSString* systemhookFilePath = [NSString stringWithFormat:@"%@/systemhook-%016llX.dylib", JBROOT_PATH(@"/basebin"), jbinfo(jbrand)];

		if([NSFileManager.defaultManager fileExistsAtPath:JBROOT_PATH(@"/basebin/systemhook.dylib")])
		{
			[NSFileManager.defaultManager removeItemAtPath:systemhookFilePath error:nil];
			assert([NSFileManager.defaultManager moveItemAtPath:JBROOT_PATH(@"/basebin/systemhook.dylib") toPath:systemhookFilePath error:nil]);
		}
		
		assert(unsandbox("/usr/lib", systemhookFilePath.fileSystemRepresentation) == 0);

		//new "real path"
		asprintf(&HOOK_DYLIB_PATH, "/usr/lib/systemhook-%016llX.dylib", jbinfo(jbrand));
	}

	if (__builtin_available(iOS 16.0, *))
	{
		void* __sysctl_orig = NULL;
		void* __sysctlbyname_orig = NULL;
		MSHookFunction(&__sysctl, (void *) __sysctl_hook, &__sysctl_orig);
		MSHookFunction(&__sysctlbyname, (void *) __sysctlbyname_hook, &__sysctlbyname_orig);
	}
#ifdef __arm64e__
	else 
	{
		// iOS15 arm64e only
		// MSHookFunction(sysctlbyname, (void *)sysctlbyname_hook, (void **)&sysctlbyname_orig);
	}
#endif

	if(!firstLoad)
	{
		int ret = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));
		if (ret != 0) {
			launchd_panic("ensure dyld trustcache failed: %d", ret);
			return;
		}
	}
	
	roothider_launchd_postinit(firstLoad);

	id jbserver_msg_handler = ^(xpc_object_t xmsg) {
		jbserver_received_xpc_message(&gGlobalServer, xmsg);
		// xpc_release(xdict);
	};
	
	// load jailbreakd after applying hooks
	assert(initJailbreakd(firstLoad, jbserver_msg_handler) == 0);
	
	gJBServerAlternativePort = startAlternativeJBServer(jbserver_msg_handler);
}

int roothide_launchd_trust_executable(const char* path)
{
	return dyld_patch_enabled() ? systemwide_trust_file_by_path(path) : roothide_trust_executable_recurse(path, "/", NULL);
}

int roothide_launchd___posix_spawn_posthook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	//spawn_prehook ensure this is always available
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	if (should_suspend) {
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	}

	// on some devices dyldhook may fail due to vm_protect(VM_PROT_READ|VM_PROT_WRITE), 2, (os/kern) protection failure in dsc::__DATA_CONST:__const, 
	// so we need to disable dyld-in-cache here. (or we can use VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY)
	char **envc = envbuf_mutcopy((const char **)envp);
	if(envbuf_getenv(envc, "DYLD_INSERT_LIBRARIES")) {
		envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
		envbuf_setenv(&envc, "DYLD_SHARED_REGION", "use");
	}

#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		if(!dyld_patch_enabled() && process_force_dyld_patch(path, argv)) {
			envbuf_setenv(&envc, "SPINLOCK_FIX_DISABLED", "1");
		}
	}
#endif

	pid_t pidval = 0;
	if (!pidp) pidp = &pidval;
	int ret = __posix_spawn_orig_wrapper(pidp, path, desc, argv, envc);
	pid_t pid = *pidp;

	envbuf_free(envc);
	
	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

	if (ret == 0 && pid > 0) {
		if(should_suspend) {
			if(jbdSpawnPatchChild(pid, should_resume) != 0) {
				JBLogError("Failed to patch spawned process (%d) %s", pid, path);
				//just kill it instead of letting it hang forever so that launchd can respawn it later
				kill(pid, SIGQUIT); //core dump
				kill(pid, SIGKILL);
				ret = 202;
			}
		}
	} else {
		JBLogError("spawn failed: %d %s, pid=%d", ret, strerror(ret), pid);
	}

	return ret;
}

void trust_tslite_app_bundle(const char* executable)
{
	//this comes from spawn_prehook so the main executable has not been trusted when spawn a ts app first time

	int fd = open(executable, O_RDONLY);
	if(fd < 0) {
		JBLogError("Failed to open tslite app bundle: err=%d,path=%s", errno, executable);
		return;
	}

	struct fgetsigsinfo siginfo = {0, GETSIGSINFO_PLATFORM_BINARY, 0};
	int sigret = fcntl(fd, F_GETSIGSINFO, &siginfo);
	int sigerr = errno;
	close(fd);

	if(sigret != 0 && sigerr != ENOENT) {
		JBLogError("Failed to get signature for tslite app: err=%d,path=%s", sigerr, executable);
		return;
	}

	if (siginfo.fg_sig_is_platform != 0) {
		JBLogDebug("tslite app has already been trusted: %s", executable);
		return;
	}

	NSString* bundlePath = getAppBundlePathFromSpawnPath(executable);
	if (!bundlePath) {
		JBLogError("Failed to find tslite app bundle for %s", executable ? executable : "(null)");
		return;
	}

	if(jb_trustcache_add_directory(bundlePath.fileSystemRepresentation, true) != 0) {
		JBLogError("Failed to add tslite app bundle to trust cache: %s", bundlePath.fileSystemRepresentation);
	}
}

int __blacklisted_posix_spawn_orig_wrapper(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	if(!path || !hasTrollstoreLiteMarker(path))
	{
		return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	}

	trust_tslite_app_bundle(path);

	//spawn_prehook ensure this is always available
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool should_suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = should_suspend && (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	if (should_suspend) {
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
	}

	pid_t pidval = 0;
	if (!pidp) pidp = &pidval;
	int ret = __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	pid_t pid = *pidp;

	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

	if (ret == 0 && pid > 0)
	{
		audit_token_t token = {0};
		mach_port_t task = MACH_PORT_NULL;
		kern_return_t kr = task_name_for_pid(mach_task_self(), pid, &task);
		if (kr == KERN_SUCCESS)
		{
			mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
			kr = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
			mach_port_deallocate(mach_task_self(), task);

			if (kr == KERN_SUCCESS)
			{
				char *rootPathOut = NULL;
				char *bootUUIDOut = NULL;
				bool forceCSAdhocOut = false;
				bool fullyDebuggedOut = false;
				systemwide_process_checkin(&token, &rootPathOut, &bootUUIDOut, NULL, &fullyDebuggedOut, &forceCSAdhocOut);
				free(rootPathOut);
				free(bootUUIDOut);
			}
		}
		if (kr != KERN_SUCCESS) {
			JBLogError("Failed to get audit token for pid %d: %d", pid, kr);
		}
	}

	if (ret == 0 && pid > 0) {
		if(should_resume)
			kill(pid, SIGCONT);
	}

	return ret;
}

// Own strict lifecycle adapter, separate from the unchanged official wrappers.
struct app_isolation_native_context {
    const char *path;
    struct _posix_spawn_args_desc *desc;
    char *const *argv;
    char *const *envp;
};

static bool isolation_helper_ready(void *opaque)
{
    (void)opaque;
    return jbdIsolationHelperReady();
}
static int isolation_get_flags(void *opaque, short *flags)
{
    struct app_isolation_native_context *context = opaque;
    return posix_spawnattr_getflags(&context->desc->attrp, flags);
}
static int isolation_set_flags(void *opaque, short flags)
{
    struct app_isolation_native_context *context = opaque;
    return posix_spawnattr_setflags(&context->desc->attrp, flags);
}
static int isolation_spawn_original(void *opaque, pid_t *published)
{
    struct app_isolation_native_context *context = opaque;
    return __posix_spawn_orig_wrapper(published, context->path, context->desc,
        context->argv, context->envp);
}
// Preserve the official Lite trust/check-in grant before strict repair. This
// does not add a new trust/signing mode, and failure is nonfatal as officially.
static void isolation_grant_lite_trust(const char *path, pid_t child)
{
    if (!path || !hasTrollstoreLiteMarker(path)) return;
    mach_port_t task = MACH_PORT_NULL;
    if (task_name_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS) {
        JBLogError("isolation: no audit token for %d", child);
        return;
    }
    audit_token_t token = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    mach_port_deallocate(mach_task_self(), task);
    if (kr != KERN_SUCCESS) {
        JBLogError("isolation: task_info failed for %d: %d", child, kr);
        return;
    }
    char *rootPath = NULL, *bootUUID = NULL;
    bool fullyDebugged = false, forceCSAdhoc = false;
    systemwide_process_checkin(&token, &rootPath, &bootUUID, NULL,
        &fullyDebugged, &forceCSAdhoc);
    free(rootPath);
    free(bootUUID);
}
static int isolation_install_repair(void *opaque, pid_t child)
{
    struct app_isolation_native_context *context = opaque;
    isolation_grant_lite_trust(context->path, child);
    return jbdAppIsolationRepair(child);
}
static int isolation_resume(void *opaque, pid_t child)
{
    (void)opaque;
    return kill(child, SIGCONT) == 0 ? 0 : errno;
}
static int isolation_terminate(void *opaque, pid_t child)
{
    (void)opaque;
    if (child <= 1) return EINVAL;
    kill(child, SIGQUIT);
    if (kill(child, SIGKILL) == 0 || errno == ESRCH) return 0;
    return errno;
}
static int isolation_spawn_strict(pid_t *published, const char *path,
    struct _posix_spawn_args_desc *desc, char *const argv[], char *const envp[])
{
    if (hasTrollstoreLiteMarker(path)) trust_tslite_app_bundle(path);
    struct app_isolation_native_context context = {path, desc, argv, envp};
    const struct app_isolation_spawn_ops operations = {
        isolation_get_flags, isolation_set_flags, isolation_spawn_original,
        isolation_install_repair, isolation_resume, isolation_terminate
    };
    struct app_isolation_spawn_report report = app_isolation_spawn(&operations,
        &context, published, POSIX_SPAWN_START_SUSPENDED);
    int savedError = errno;
    if (report.error) {
        JBLogError("isolation phase=%d error=%d created=%d repair=%d kill-request=%d kill-error=%d path=%s",
            report.phase, report.error, report.created, report.repair_applied,
            report.child_killed, report.kill_error, path);
    }
    errno = savedError;
    return report.result;
}

int roothide_launchd___posix_spawn__spinlock_fix_only(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	//spawn_prehook ensure this is always available
	posix_spawnattr_t attrp = &desc->attrp;

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	bool should_resume = (flags & POSIX_SPAWN_START_SUSPENDED)==0;

	posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);

	pid_t pidval = 0;
	if (!pidp) pidp = &pidval;
	int ret = __blacklisted_posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	pid_t pid = *pidp;
	
	posix_spawnattr_setflags(attrp, flags); // maybe caller will use it again?

	if (ret == 0 && pid > 0) {
		if(jbdSpinlockFixOnly(pid, should_resume)  != 0) {
			JBLogError("Failed to patch(spinlock fix) spawned process (%d) %s", pid, path);
			//just kill it instead of letting it hang forever so that launchd can respawn it later
			kill(pid, SIGQUIT); //core dump
			kill(pid, SIGKILL);
			ret = 202;
		}
	} else {
		JBLogError("spawn failed: %d %s, pid=%d", ret, strerror(ret), pid);
	}

	return ret;
}

int roothide_launchd___posix_spawn_prehook(pid_t *restrict pidp, const char *restrict path, struct _posix_spawn_args_desc *desc, char *const argv[restrict], char *const envp[restrict])
{
	if(!desc || !desc->attrp) {
		posix_spawnattr_t attr=NULL;
		posix_spawnattr_init(&attr);
		int ret = posix_spawn(pidp, path, (desc && desc->file_actions) ? &desc->file_actions : NULL, &attr, argv, envp);
		posix_spawnattr_destroy(&attr);
		return ret;
	}
	posix_spawnattr_t attrp = &desc->attrp;

	if(!path) {
		return __posix_spawn_hook(pidp, path, desc, argv, envp);
	}

	if(isRemovableBundlePath(path)) {
		static dispatch_once_t onceToken = {0};
		dispatch_once(&onceToken, ^{
			extern void fix__iosConnect();
			fix__iosConnect();
		});
	}

	if(strcmp(path, "/sbin/launchd") == 0) {
		short flags = 0;
		posix_spawnattr_getflags(attrp, &flags);
		posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);
		return __posix_spawn_hook(pidp, path, desc, argv, envp);
	}

	if(path && isRemovableBundlePath(path) && string_has_suffix(path, "/Dopamine"))
	{
		/* if the jailbreak activation is interrupted for some reason, 
			we prevent the app from relaunching to prevent the system from being in an unknown state */
		if(launchdhookFirstLoad) {
#ifdef ENABLE_LOGS
			launchd_panic("reboot device due to jailbreak failure!");
#endif
			return EPERM;
		}

		char roothidefile[PATH_MAX];
		snprintf(roothidefile, sizeof(roothidefile), "%s.roothide", path);
		if(access(roothidefile, F_OK) != 0) {
			return EPERM;
		}
	}
	
	if(string_has_suffix(path, "/basebin/jailbreakd")) {
		return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	}


	// mitigate spinlock panic for ios15(A12+) devices

	bool iOS15Arm64e = false;
	bool choicyBlocked = false;
#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		iOS15Arm64e = true;
		if(envbuf_getenv(envp, "_SafeMode") || envbuf_getenv(envp, "_MSSafeMode")) {
			if(path && isRemovableBundlePath(path) && !hasTrollstoreMarker(path)) {
				choicyBlocked = true;
			}
		}
	}
#endif

    struct app_isolation_context isolationContext = {
        .ios15_arm64e = iOS15Arm64e,
        .global_dyld_fix = dyld_patch_enabled(),
        .global_isolation_enabled = !launchdhookFirstLoad && iOS15Arm64e &&
            doimty_blacklist_isolation_enabled() && doimty_blacklist_isolation_supported(),
        .effective_blacklisted = false,
        .choicy_blocked = choicyBlocked,
        .verified_main_executable = false,
        .isolation_opted_out = false,
        .is_extension = app_isolation_path_is_extension(path),
        .active_prewarm = envbuf_getenv(envp, "ActivePrewarm") != NULL,
        .dyld_use_closures = envbuf_getenv(envp, "DYLD_USE_CLOSURES") != NULL,
        .launchd_first_load = launchdhookFirstLoad,
    };
    // Use the same production classifier exercised by the Foundation tests.
    // Its off/unsupported/first-load path is the official blacklist lookup.
    enum app_isolation_route isolationRoute = app_isolation_classify_path(path,
        &isolationContext, isolation_helper_ready, NULL);
    bool roothideBlacklisted = isolationContext.effective_blacklisted;
    bool strictIsolation = isolationRoute == APP_ISOLATION_ROUTE_BLACKLIST_STRICT;
    jbdIsolationNoteDecision(strictIsolation ? 1 : 0, roothideBlacklisted ? 1 : 0,
        isolationContext.ios15_arm64e ? 1 : 0, isolationContext.global_isolation_enabled ? 0 : 1);
	if (choicyBlocked || roothideBlacklisted)
	{
		int ret;

		JBLogDebug("blacklisted app %s", path);

		if(dyld_patch_enabled() && iOS15Arm64e && roothideBlacklisted && (strstr(path, "/PlugIns/") || strstr(path, "/Extensions/") || strstr(path, ".appex/"))) {
			JBLogDebug("prevent blacklisted app's extension from running: ", path);
			ret = EPERM;
		}
		else if(dyld_patch_enabled() && iOS15Arm64e && roothideBlacklisted && (envbuf_getenv(envp, "ActivePrewarm") || envbuf_getenv(envp, "DYLD_USE_CLOSURES"))) {
			JBLogDebug("prevent blacklisted app from prewarming: ", path);
			ret = EPERM;
		}
		else
		{
			char **envc = strictIsolation ? RHIsolationCopyEnvironment((const char *const *)envp,
                JBROOT_PATH("/"), HOOK_DYLIB_PATH) : envbuf_mutcopy((const char **)envp);
            if (strictIsolation && !envc) { errno = ENOMEM; return -1; }

            if (!strictIsolation) {
			    //choicy may set these
			    envbuf_unsetenv(&envc, "_SafeMode");
			    envbuf_unsetenv(&envc, "_MSSafeMode");
            }
	
			/* According to xnu, the new thread in new process will not run in userland until after copyout pid
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4321
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4882
			https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_exec.c#L4933
			*/
	
			/* and posix_spawn->kernel->amfid->launchd may cause xpc dead loop so we can't use lock-spawn-unlock here */
	
			volatile pid_t* blacklistedPidp = allocBlacklistProcessId();
            if (strictIsolation && !blacklistedPidp) {
                RHIsolationFreeEnvironment(envc);
                errno = ENOMEM;
                return -1;
            }
	
            if (strictIsolation) {
                ret = isolation_spawn_strict((pid_t *)blacklistedPidp, path, desc, argv, envc);
            } else if(roothideBlacklisted || !dyld_patch_enabled() || !iOS15Arm64e) {
				ret = __blacklisted_posix_spawn_orig_wrapper(blacklistedPidp, path, desc, argv, envc);
			} else {
				ret = roothide_launchd___posix_spawn__spinlock_fix_only(blacklistedPidp, path, desc, argv, envc);
			}
            int spawnError = errno;
	
			pid_t pid = *blacklistedPidp;
			if(pidp) *pidp = *blacklistedPidp;

			commitBlacklistProcessId(blacklistedPidp); // will release blacklistedPidp
			blacklistedPidp = NULL;

            if (strictIsolation) RHIsolationFreeEnvironment(envc); else envbuf_free(envc);
				
			if(!strictIsolation && ret==0 && pid>0) {
				short flags = 0;
				posix_spawnattr_getflags(attrp, &flags);
				if((flags & POSIX_SPAWN_START_SUSPENDED) != 0) {
					platform_set_process_debugged(pid, false);
				}
			}
            if (strictIsolation) errno = spawnError;
		}
	
		return ret;
	}

	if(launchdhookFirstLoad) 
	{
		//we should not enable system-wide injection until the jailbreak is finalized (userspace reboot).
		return __posix_spawn_orig_wrapper(pidp, path, desc, argv, envp);
	}
	
	return __posix_spawn_hook(pidp, path, desc, argv, envp);
}
