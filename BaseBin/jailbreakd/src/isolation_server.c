/* Declare audit accessors before the repository's same-guard libbsm shim. */
#include <bsm/audit.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <libjailbreak/libjailbreak.h>
#include <libroothider/libroothider.h>
#include <libroothider/app_isolation_mach.h>
#include <libroothider/app_isolation_repair.h>

struct isolation_cancellation {
    uint64_t deadline_ns;
    mach_port_t reply_right;
};

static bool repair_cancelled(void *opaque)
{
    struct isolation_cancellation *context = opaque;
    return rh_isolation_request_cancelled(context->deadline_ns, context->reply_right);
}

static bool isolation_supported(void)
{
#ifdef __arm64e__
    if (!__builtin_available(iOS 16.0, *)) return dyld_patch_enabled();
#endif
    return false;
}

static int repair_child(const struct rh_isolation_mach_request *request,
                        mach_port_t reply_right, void *unused)
{
    (void)unused;
    struct isolation_cancellation context = {request->deadline_ns, reply_right};
    if (repair_cancelled(&context)) return ETIMEDOUT;
    if (rh_isolation_pidversion(request->pid) != request->pidversion) return ESRCH;
    bool paused = false;
    if (proc_get_ppid(request->pid) != 1 || proc_paused(request->pid, &paused) != 0 || !paused)
        return EBUSY;
    if (repair_cancelled(&context)) return ETIMEDOUT;
    int result = proc_fix_spinlock_strict_checked(request->pid, request->pidversion,
                                                 repair_cancelled, &context);
    if (repair_cancelled(&context)) return ETIMEDOUT;
    return result >= 0 ? result : EIO;
}

static void isolation_receive(void *context)
{
    mach_port_t port = (mach_port_t)(uintptr_t)context;
    rh_isolation_mach_serve_once(port, 1, isolation_supported(), repair_child, NULL);
}

static void isolation_cancel(void *context)
{
    mach_port_t port = (mach_port_t)(uintptr_t)context;
    /* Exact receive removal, then our send/dead-name uref; no deprecated destroy. */
    mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
    mach_port_deallocate(mach_task_self(), port);
}

/* Called after primitive initialization and respawn, before the legacy check-in.
 * The receiver is armed here, but actual readiness requires a PING after dispatch_main. */
mach_port_t jailbreakd_start_isolation_server(void)
{
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
        return MACH_PORT_NULL;
    }
    static dispatch_source_t source;
    source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, port, 0, dispatch_get_main_queue());
    if (!source) {
        mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
        mach_port_deallocate(mach_task_self(), port);
        return MACH_PORT_NULL;
    }
    /* C callbacks avoid imposing a new -fblocks requirement on the official Makefile. */
    dispatch_set_context(source, (void *)(uintptr_t)port);
    dispatch_source_set_event_handler_f(source, isolation_receive);
    dispatch_source_set_cancel_handler_f(source, isolation_cancel);
    dispatch_resume(source);
    return port;
}
