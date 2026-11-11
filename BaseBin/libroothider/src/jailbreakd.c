#include <spawn.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <xpc/xpc.h>
#include <mach/mach.h>
/* audit.h must precede the repository libbsm shim's shared include guard. */
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <sys/param.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbserver_domains.h>
#include "jailbreakd.h"
#include "app_isolation_mach.h"
#include "common.h"
#include "log.h"

#ifdef ENABLE_LOGS
static void (*JBDLogDebugFunction)(const char *format, ...);
static void (*JBDLogErrorFunction)(const char *format, ...);

#define JBLogDebug(...) do { if(JBDLogDebugFunction)JBDLogDebugFunction(__VA_ARGS__); } while(0)
#define JBLogError(...) do { if(JBDLogErrorFunction)JBDLogErrorFunction(__VA_ARGS__); } while(0)

void enableJBDLog(void* debugLog, void* errorLog)
{
	JBDLogDebugFunction = debugLog;
	JBDLogErrorFunction = errorLog;
}
#endif

#define JAILBREAKD_CLIENT_PORT_FAST_GET

mach_port_t gJailbreakdPort = MACH_PORT_NULL;

static bool __firstLoad = false;
static bool __jailbreakd_initialized = false;
static void (^__bootstrap_msg_handler)(xpc_object_t);

/* Local publication bookkeeping only; no RPC or kernel primitive while locked. */
static pthread_mutex_t isolationStateLock = PTHREAD_MUTEX_INITIALIZER;
static mach_port_t isolationService = MACH_PORT_NULL;
static pid_t isolationExpectedPid;
static int isolationHelperPidversion;
static uint64_t isolationGeneration;
static bool isolationVerified;

/* Last spawn decision, recorded for the read-only diagnostics string. */
/* Plain ints mutated only through __atomic builtins, which clang accepts. */
static int diagStrict, diagBlacklisted, diagSupported, diagReadySkip, diagDecisions;
static int diagRegistrations, diagRegisterFailures;

void jbdIsolationNoteDecision(int strict, int blacklisted, int supported, int readySkip)
{
    __atomic_store_n(&diagStrict, strict, __ATOMIC_RELAXED);
    __atomic_store_n(&diagBlacklisted, blacklisted, __ATOMIC_RELAXED);
    __atomic_store_n(&diagSupported, supported, __ATOMIC_RELAXED);
    __atomic_store_n(&diagReadySkip, readySkip, __ATOMIC_RELAXED);
    __atomic_fetch_add(&diagDecisions, 1, __ATOMIC_RELAXED);
}

/* Stable snapshot for jbsettings; values only, never behavior. */
const char *jbdIsolationDiagnostics(void)
{
    static char buffer[192];
    pthread_mutex_lock(&isolationStateLock);
    bool verified = isolationVerified;
    bool portValid = MACH_PORT_VALID(isolationService);
    int helperPid = isolationExpectedPid;
    pthread_mutex_unlock(&isolationStateLock);
    snprintf(buffer, sizeof(buffer),
        "reg=%d/%d ver=%d port=%d pid=%d dec=%d strict=%d bl=%d sup=%d skip=%d",
        __atomic_load_n(&diagRegistrations, __ATOMIC_RELAXED),
        __atomic_load_n(&diagRegisterFailures, __ATOMIC_RELAXED),
        verified ? 1 : 0, portValid ? 1 : 0, helperPid,
        __atomic_load_n(&diagDecisions, __ATOMIC_RELAXED),
        __atomic_load_n(&diagStrict, __ATOMIC_RELAXED),
        __atomic_load_n(&diagBlacklisted, __ATOMIC_RELAXED),
        __atomic_load_n(&diagSupported, __ATOMIC_RELAXED),
        __atomic_load_n(&diagReadySkip, __ATOMIC_RELAXED));
    return buffer;
}

static void isolation_clear_locked(void)
{
    if (MACH_PORT_VALID(isolationService)) mach_port_deallocate(mach_task_self(), isolationService);
    isolationService = MACH_PORT_NULL;
    isolationHelperPidversion = 0;
    isolationVerified = false;
    isolationGeneration++;
}

static void isolation_invalidate_generation(uint64_t generation, bool retire)
{
    pthread_mutex_lock(&isolationStateLock);
    if (isolationGeneration == generation) {
        isolationVerified = false;
        if (retire) isolation_clear_locked();
    }
    pthread_mutex_unlock(&isolationStateLock);
}

/* Only an optional capability on the original RootHide CHECKIN is accepted.
 * The actual helper incarnation comes from XPC's kernel audit token, not payload. */
int jbdRegisterIsolationHelper(audit_token_t *token, xpc_object_t capability)
{
    __atomic_fetch_add(&diagRegistrations, 1, __ATOMIC_RELAXED);
    if (!token || !capability || xpc_get_type(capability) != XPC_TYPE_DICTIONARY) {
        __atomic_fetch_add(&diagRegisterFailures, 1, __ATOMIC_RELAXED);
        return EINVAL;
    }
    extern int audit_token_to_pidversion(audit_token_t);
    pid_t pid = audit_token_to_pid(*token);
    int pidversion = audit_token_to_pidversion(*token);
    int result = EPERM;
    if (audit_token_to_euid(*token) == 0 && pid > 1 && pidversion > 0 &&
        rh_isolation_pidversion(pid) == pidversion &&
        xpc_dictionary_get_uint64(capability, "isolation-protocol") == RH_ISOLATION_MACH_VERSION) {
        mach_port_t port = xpc_dictionary_copy_mach_send(capability, "isolation-port");
        mach_port_type_t type = 0;
        if (MACH_PORT_VALID(port) && mach_port_type(mach_task_self(), port, &type) == KERN_SUCCESS &&
            (type & MACH_PORT_TYPE_SEND)) {
            pthread_mutex_lock(&isolationStateLock);
            if (pid == isolationExpectedPid) {
                isolation_clear_locked();
                isolationService = port;
                isolationHelperPidversion = pidversion;
                port = MACH_PORT_NULL;
                result = 0;
            }
            pthread_mutex_unlock(&isolationStateLock);
        }
        if (MACH_PORT_VALID(port)) mach_port_deallocate(mach_task_self(), port);
    }
    if (result != 0) __atomic_fetch_add(&diagRegisterFailures, 1, __ATOMIC_RELAXED);
    return result;
}

mach_port_t jbdCheckinWithIsolation(mach_port_t isolation_port)
{
    /* With no own receiver, use the official old-client function unchanged. */
    if (!MACH_PORT_VALID(isolation_port)) return jbclient_jailbreakd_checkin();
    xpc_object_t args = xpc_dictionary_create_empty();
    xpc_object_t capability = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(capability, "isolation-protocol", RH_ISOLATION_MACH_VERSION);
    xpc_dictionary_set_mach_send(capability, "isolation-port", isolation_port);
    xpc_dictionary_set_value(args, "isolation-capability", capability);
    xpc_release(capability);
    /* One original check-in, not a new repair/readiness XPC RPC. Old servers
     * ignore the optional field and return their original receive right. */
    xpc_object_t reply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_JAILBREAKD_CHECKIN, args);
    xpc_release(args);
    mach_port_t port = MACH_PORT_NULL;
    if (reply) {
        if (xpc_dictionary_get_int64(reply, "result") == 0) {
            xpc_object_t object = xpc_dictionary_get_value(reply, "port");
            if (object) port = xpc_mach_recv_extract_right(object);
        }
        xpc_release(reply);
    }
    return port;
}

static mach_port_t isolation_copy_service(bool require_verified, pid_t *helper,
                                          int *pidversion, uint64_t *generation)
{
    /* firstLoad and global-off policy belong to the spawn owner, not transport. */
    if (getpid() != 1 || !__jailbreakd_initialized) return MACH_PORT_NULL;
    if (pthread_mutex_trylock(&isolationStateLock) != 0) return MACH_PORT_NULL;
    mach_port_t port = MACH_PORT_NULL;
    if ((!require_verified || isolationVerified) && MACH_PORT_VALID(isolationService) &&
        isolationExpectedPid > 1 && isolationHelperPidversion > 0 &&
        mach_port_mod_refs(mach_task_self(), isolationService, MACH_PORT_RIGHT_SEND, 1) == KERN_SUCCESS) {
        port = isolationService;
        *helper = isolationExpectedPid;
        *pidversion = isolationHelperPidversion;
        *generation = isolationGeneration;
    }
    pthread_mutex_unlock(&isolationStateLock);
    return port;
}

int posix_spawnattr_setspecialport_np(posix_spawnattr_t *attr, mach_port_t new_port, int which);
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

int registerServerPort()
{
	assert(getpid() == 1);
    pthread_mutex_lock(&isolationStateLock);
    isolation_clear_locked();
    isolationExpectedPid = 0;
    pthread_mutex_unlock(&isolationStateLock);

	// deallocate the previous port if it exists
	if(MACH_PORT_VALID(gJailbreakdPort)) {
		mach_port_deallocate(mach_task_self(), gJailbreakdPort);
		gJailbreakdPort = MACH_PORT_NULL;
	}

	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gJailbreakdPort);
	mach_port_insert_right(mach_task_self(), gJailbreakdPort, gJailbreakdPort, MACH_MSG_TYPE_MAKE_SEND);

	JBLogDebug("jailbreakd server port: %x", gJailbreakdPort);

#ifdef JAILBREAKD_CLIENT_PORT_FAST_GET
	mach_port_t self_host = mach_host_self();
	kern_return_t kr = host_set_special_port(self_host, HOST_LAUNCHCTL_PORT, gJailbreakdPort);
	mach_port_deallocate(mach_task_self(), self_host);
#endif

	return kr==KERN_SUCCESS ? 0 : -1;
}

#ifdef JAILBREAKD_CLIENT_PORT_FAST_GET
mach_port_t jailbreakdClientPortFastGet()
{
	mach_port_t port = MACH_PORT_NULL;
	mach_port_t self_host = mach_host_self();
	kern_return_t kr = host_get_special_port(self_host, HOST_LOCAL_NODE, HOST_LAUNCHCTL_PORT, &port);
	mach_port_deallocate(mach_task_self(), self_host);
	if(kr != KERN_SUCCESS) {
		JBLogError("jailbreakdClientPortFastGet failed: %x,%s", kr, mach_error_string(kr));
		return MACH_PORT_NULL;
	}
	return port;
}
#endif

void setJailbreakdProcess(pid_t pid)
{
    pthread_mutex_lock(&isolationStateLock);
    if (isolationExpectedPid != pid) isolation_clear_locked();
    isolationExpectedPid = pid;
    pthread_mutex_unlock(&isolationStateLock);
	//Reclaim the previous jailbreakd zombie process
	const char *pidenv = getenv("JAILBREAKD_PID");
	if (pidenv) 
	{
		pid_t oldpid = atoi(pidenv);
		if(oldpid != pid)
		{
			waitpid(oldpid, NULL, 0);
			unsetenv("JAILBREAKD_PID");
		}
	}

	char buf[32];
	snprintf(buf, sizeof(buf), "%d", pid);
	setenv("JAILBREAKD_PID", buf, 1);
}

int spawnJailbreakd()
{
	assert(getpid() == 1);

	static mach_port_t bootstraport = MACH_PORT_NULL;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &bootstraport);
		mach_port_insert_right(mach_task_self(), bootstraport, bootstraport, MACH_MSG_TYPE_MAKE_SEND);
		JBLogDebug("jailbreakd bootstrap port: %x", bootstraport);

		static dispatch_source_t source; //retain the dispatch source
		source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)bootstraport, 0, dispatch_get_global_queue(0,0));
		dispatch_source_set_event_handler(source, ^{
			JBLogDebug("received message from jailbreakd");
			xpc_object_t xdict = NULL;
			int err = xpc_pipe_receive(bootstraport, &xdict);
			if(err == 0) {
				__bootstrap_msg_handler(xdict);
				xpc_release(xdict);
			}
		});
		dispatch_resume(source);
	});


	char* log_dir_env = NULL;
    if(getenv("JB_LOG_DIR")) {
		asprintf(&log_dir_env, "JB_LOG_DIR=%s", getenv("JB_LOG_DIR"));
    }

	pid_t pid;
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	// posix_spawnattr_setspecialport_np(&attr, bootstraport, TASK_BOOTSTRAP_PORT);
	// posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ bootstraport, MACH_PORT_NULL }, 3);
	posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, bootstraport }, 3);
	int ret = posix_spawn(&pid, JBROOT_PATH("/basebin/jailbreakd"), NULL, &attr, (char*[]){"jailbreakd",NULL}, __firstLoad ? NULL :  ((char*[]){"RESPAWN_REQUIRED=1", log_dir_env, NULL}));
	posix_spawnattr_destroy(&attr);

	if(log_dir_env) {
		free(log_dir_env);
		log_dir_env=NULL;
	}

	if (ret != 0) {
		JBLogError("posix_spawn jailbreakd failed: %d\n", ret);
		return ret;
	}

	JBLogDebug("jailbreakd spawned, pid=%d\n", pid);

	/* here we can't wait for jailbreakd to initialize since opainject will suspend all other threads */
	
	setJailbreakdProcess(pid);

	return 0;
}

int initJailbreakd(bool firstLoad, void(^msghandler)(xpc_object_t))
{
	assert(getpid() == 1);

	assert(__jailbreakd_initialized == false);

	__firstLoad = firstLoad;

	if(registerServerPort() != 0) {
		JBLogError("registerServerPort failed");
		return -1;
	}

	__jailbreakd_initialized = true;

	__bootstrap_msg_handler = msghandler;

	return spawnJailbreakd();
}

mach_port_t reactiveJailbreakdPort()
{
/* restarting jailbreakd may cause it to lose its previous internal state, 
	so we only use it during development. */
#ifndef ENABLE_LOGS
	//launchd_panic("jailbreakd crashed");
	abort();
#endif

	assert(getpid() == 1);

	//prevent jailbreakdClientPort from calling before initJailbreakd
	assert(__jailbreakd_initialized);

	mach_port_t port = MACH_PORT_NULL;

	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&mutex);

	// lock and check if another thread has reactivated the port

	kern_return_t kr = mach_port_mod_refs(mach_task_self(), gJailbreakdPort, MACH_PORT_RIGHT_SEND, 1);
	if(kr == KERN_SUCCESS) {
		port = gJailbreakdPort;
	}
	else
	{
		//make jailbreakd crashes perceptible
		sleep(5);

		//register server port before spawn jailbreakd
		if(registerServerPort() == 0)
		{
			//acquire the send right first
			kr = mach_port_mod_refs(mach_task_self(), gJailbreakdPort, MACH_PORT_RIGHT_SEND, 1);
			if(kr == KERN_SUCCESS)
			{
				port = gJailbreakdPort;

				// Try to restart jailbreakd
				if(spawnJailbreakd() != 0) {
					JBLogError("loadJailbreakd failed");
				}
			}
			else
			{
				JBLogError("jailbreakdClientPort failed");
			}
		}
		else
		{
			JBLogError("registerServerPort failed");
		}
	}

	pthread_mutex_unlock(&mutex);

	return port;
}

mach_port_t jailbreakdServerPort()
{
	assert(getpid() == 1);

	return gJailbreakdPort;
}

mach_port_t jailbreakdClientPort()
{
	mach_port_t port = MACH_PORT_NULL;

	if(getpid() == 1)
	{
		kern_return_t kr = mach_port_mod_refs(mach_task_self(), gJailbreakdPort, MACH_PORT_RIGHT_SEND, 1);
		if(kr == KERN_SUCCESS) {
			port = gJailbreakdPort;
		} else {
			JBLogError("jailbreakd port dead: %x,%s port=%x", kr, mach_error_string(kr), gJailbreakdPort);		
			port = reactiveJailbreakdPort();
		}
	}
	else
	{

#ifdef JAILBREAKD_CLIENT_PORT_FAST_GET
		port = jailbreakdClientPortFastGet();
		if(!MACH_PORT_VALID(port))
		{
#endif

			port = jbclient_jailbreakd_lookup();

#ifdef JAILBREAKD_CLIENT_PORT_FAST_GET
		}
#endif

	}

	return port;
}

// xpc_object_t jailbreakdRequestViaLaunchd(xpc_object_t xdict)
// {
// 	// to do
// }

xpc_object_t jailbreakdXpcRequest(xpc_object_t xdict)
{
	mach_port_t port = jailbreakdClientPort();
	if (!MACH_PORT_VALID(port)) {
		JBLogError("invalid jailbreakdClientPort: %x", port);
		return NULL;
	}
	
	xpc_object_t xreply = NULL;
	xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
	if (pipe) {
		int err = xpc_pipe_routine(pipe, xdict, &xreply);
		if (err != 0) {
			char *desc = NULL;
			JBLogError("xpc_pipe_routine error on sending message to jailbreakd: %d / %s\n%s", err, xpc_strerror(err), (desc=xpc_copy_description(xdict)));
			if(desc) free(desc);
			if(xreply) xpc_release(xreply);
			xreply = NULL;
		};
	} else {
		JBLogError("xpc_pipe_create_from_port failed");
	}

	mach_port_deallocate(mach_task_self(), port);

	xpc_release(pipe);
	return xreply;
}

int jbdTestCall(int value)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_TEST_CALL);
	xpc_dictionary_set_int64(message, "value", value);

	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}

#ifdef ENABLE_LOGS
int jbdSystemwideLog(const char* fmt, ...)
{
	char* log = NULL;

	va_list args;
	va_start(args, fmt);
	vasprintf(&log, fmt, args);
	va_end(args);

	__uint64_t tid = 0;
	pthread_threadid_np(pthread_self(), &tid);

	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SYSTEMWIDE_LOG);
	xpc_dictionary_set_uint64(message, "tid", tid);
	xpc_dictionary_set_string(message, "log", log);

	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	free(log);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}
#endif

int jbdSpawnPatchChild(int pid, bool resume)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPAWN_PATCH_CHILD);
	xpc_dictionary_set_int64(message, "pid", pid);
	xpc_dictionary_set_bool(message, "resume", resume);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

int jbdSpinlockFixOnly(int pid, bool resume)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPINLOCK_FIX_ONLY);
	xpc_dictionary_set_int64(message, "pid", pid);
	xpc_dictionary_set_bool(message, "resume", resume);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

/* The capability is only a candidate until the running helper answers PING. */
bool jbdIsolationHelperReady(void)
{
    pid_t helper = 0;
    int version = 0;
    uint64_t generation = 0;
    mach_port_t port = isolation_copy_service(false, &helper, &version, &generation);
    if (!MACH_PORT_VALID(port)) return false;
    int result = rh_isolation_mach_call(port, helper, version, RH_ISOLATION_PING, 0, 0,
                                        RH_ISOLATION_PING_MS);
    mach_port_deallocate(mach_task_self(), port);
    if (result) {
        isolation_invalidate_generation(generation, result != ETIMEDOUT && result != EINTR);
        return false;
    }
    /* Avoid waiting for publication on the launchd spawn path. */
    if (pthread_mutex_trylock(&isolationStateLock) != 0) return false;
    bool current = isolationGeneration == generation;
    if (current) isolationVerified = true;
    pthread_mutex_unlock(&isolationStateLock);
    return current;
}

int jbdAppIsolationRepair(pid_t pid)
{
    if (getpid() != 1 || pid <= 1) return EPERM;
    int targetVersion = rh_isolation_pidversion(pid);
    if (targetVersion <= 0) return ESRCH;
    pid_t helper = 0;
    int helperVersion = 0;
    uint64_t generation = 0;
    mach_port_t port = isolation_copy_service(true, &helper, &helperVersion, &generation);
    if (!MACH_PORT_VALID(port)) return ENOTCONN;
    int result = rh_isolation_mach_call(port, helper, helperVersion, RH_ISOLATION_REPAIR,
                                        pid, targetVersion, RH_ISOLATION_REPAIR_MS);
    mach_port_deallocate(mach_task_self(), port);
    if (result == ETIMEDOUT || result == ENOTCONN || result == EPROTO || result == EIO)
        isolation_invalidate_generation(generation, result != ETIMEDOUT);
    /* Never resume on timeout/mismatch/partial repair; caller spawn ops kill it. */
    return result;
}

int jbdSpawnExecStart(const char* execfile, bool resume)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPAWN_EXEC_START);
	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_dictionary_set_bool(message, "resume", resume);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

int jbdSpawnExecCancel(const char* execfile)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPAWN_EXEC_CANCEL);
	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

int jbdExecTraceStart(const char* execfile, bool* traced)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_EXEC_TRACE_START);

	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_dictionary_set_uint64(message, "traced", (uint64_t)(void*)traced);

	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}

int jbdExecTraceCancel(const char* execfile, bool* detached)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_EXEC_TRACE_CANCEL);

	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_dictionary_set_uint64(message, "detached", (uint64_t)(void*)detached);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}
