/* Real macOS Mach transport tests; no jailbreak primitives or device access. */
#include "app_isolation_mach.h"
#include <assert.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern int audit_token_to_pidversion(audit_token_t);
static volatile sig_atomic_t owned_child;
static void cleanup_child(void)
{
    if (owned_child > 1) {
        kill((pid_t)owned_child, SIGKILL);
        waitpid((pid_t)owned_child, NULL, 0);
        owned_child = 0;
    }
}
static void abort_cleanup(int signo)
{
    cleanup_child();
    signal(signo, SIG_DFL);
    raise(signo);
}
struct fixture {
    mach_port_t port;
    dispatch_queue_t queue;
    dispatch_source_t source;
    atomic_int supported;
    atomic_int delay_ms;
    atomic_int mutation;
    atomic_int callback_count;
    atomic_int reply_mode;
    atomic_int expected_client;
    atomic_int late_ack_count;
};

static int checked_fixture(const struct rh_isolation_mach_request *request,
                           mach_port_t right, void *opaque)
{
    struct fixture *fixture = opaque;
    atomic_fetch_add(&fixture->callback_count, 1);
    if (rh_isolation_pidversion(request->pid) != request->pidversion) return ESRCH;
    int delay = atomic_load(&fixture->delay_ms);
    if (delay) usleep((useconds_t)delay * 1000);
    if (rh_isolation_request_cancelled(request->deadline_ns, right)) return ETIMEDOUT;
    if (rh_isolation_pidversion(request->pid) != request->pidversion) return ESRCH;
    /* A guarded remote-write stand-in: count only, never alter the child. */
    atomic_fetch_add(&fixture->mutation, 1);
    return 0;
}

static void malformed_ack(struct fixture *fixture, int mode)
{
    union {
        struct rh_isolation_mach_request request;
        unsigned char bytes[sizeof(struct rh_isolation_mach_request) + MAX_TRAILER_SIZE];
    } buffer = {0};
    kern_return_t kr = mach_msg(&buffer.request.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                               0, sizeof(buffer), fixture->port, 0, MACH_PORT_NULL);
    assert(kr == KERN_SUCCESS);
    struct rh_isolation_mach_request *request = &buffer.request;
    struct rh_isolation_mach_reply reply = {0};
    reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.header.msgh_remote_port = request->header.msgh_remote_port;
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_id = RH_ISOLATION_MACH_REPLY_ID;
    reply.magic = RH_ISOLATION_MACH_MAGIC;
    reply.version = RH_ISOLATION_MACH_VERSION + (mode == 1);
    reply.operation = request->operation;
    reply.nonce = request->nonce + (mode == 2);
    reply.pid = request->pid;
    reply.pidversion = request->pidversion;
    reply.helper_pid = request->helper_pid;
    reply.helper_pidversion = request->helper_pidversion + (mode == 5);
    reply.pidversion += mode == 4;
    reply.applied = mode == 3 ? 0 : 1;
    if (mode == 6) {
        /* A genuinely late ACK, rather than a callback which cancels itself. */
        usleep(150000);
        atomic_fetch_add(&fixture->late_ack_count, 1);
    }
    kr = mach_msg(&reply.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof(reply),
                  0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) mach_msg_destroy(&reply.header);
}

static void start_fixture(struct fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    atomic_init(&fixture->supported, 1);
    atomic_init(&fixture->delay_ms, 0);
    atomic_init(&fixture->mutation, 0);
    atomic_init(&fixture->callback_count, 0);
    atomic_init(&fixture->reply_mode, 0);
    atomic_init(&fixture->expected_client, getpid());
    atomic_init(&fixture->late_ack_count, 0);
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &fixture->port) == KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(), fixture->port, fixture->port, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    fixture->queue = dispatch_queue_create("rh.isolation.test", DISPATCH_QUEUE_SERIAL);
    fixture->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, fixture->port, 0, fixture->queue);
    assert(fixture->source);
    dispatch_source_set_event_handler(fixture->source, ^{
        int mode = atomic_load(&fixture->reply_mode);
        if (mode) malformed_ack(fixture, mode);
        else rh_isolation_mach_serve_once(fixture->port, atomic_load(&fixture->expected_client),
                                         atomic_load(&fixture->supported), checked_fixture, fixture);
    });
    dispatch_resume(fixture->source);
}

static void drain_fixture(struct fixture *fixture)
{
    dispatch_sync(fixture->queue, ^{});
}

static void stop_fixture(struct fixture *fixture)
{
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_source_set_cancel_handler(fixture->source, ^{ dispatch_semaphore_signal(done); });
    dispatch_source_cancel(fixture->source);
    assert(dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
    // The fixture owns one receive right and one send uref under this name.
    assert(mach_port_mod_refs(mach_task_self(), fixture->port, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    assert(mach_port_deallocate(mach_task_self(), fixture->port) == KERN_SUCCESS);
    dispatch_release(done);
    dispatch_release(fixture->source);
    dispatch_release(fixture->queue);
}

static mach_msg_type_number_t name_count(void)
{
    mach_port_name_array_t names;
    mach_port_type_array_t types;
    mach_msg_type_number_t names_count = 0, types_count = 0;
    assert(mach_port_names(mach_task_self(), &names, &names_count, &types, &types_count) == KERN_SUCCESS);
    vm_deallocate(mach_task_self(), (vm_address_t)names, names_count * sizeof(*names));
    vm_deallocate(mach_task_self(), (vm_address_t)types, types_count * sizeof(*types));
    return names_count;
}

int main(void)
{
    /* Create a stopped child before dispatch starts any worker threads. */
    int marker[2]; assert(pipe(marker) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(marker[0]);
        raise(SIGSTOP);
        (void)write(marker[1], "resumed", 7);
        _exit(0);
    }
    owned_child = child;
    atexit(cleanup_child);
    signal(SIGABRT, abort_cleanup);
    close(marker[1]);
    int status;
    assert(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    assert(fcntl(marker[0], F_SETFL, O_NONBLOCK) == 0);
    errno = EDOM;
    assert(rh_isolation_pidversion(0) == 0);
    assert(rh_isolation_pidversion(-1) == 0);
    assert(rh_isolation_pidversion(INT_MAX) == 0);
    int helper_version = rh_isolation_pidversion(getpid()), child_version = rh_isolation_pidversion(child);
    assert(helper_version > 0 && child_version > 0 && errno == EDOM);
    assert(rh_isolation_mach_call(MACH_PORT_NULL, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 20) == ENOTCONN);

    /* A port with an owner but no serving loop must never count as ready. */
    mach_port_t unready;
    assert(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &unready) == KERN_SUCCESS);
    assert(mach_port_insert_right(mach_task_self(), unready, unready, MACH_MSG_TYPE_MAKE_SEND) == KERN_SUCCESS);
    mach_port_limits_t limits = { .mpl_qlimit = 1 };
    assert(mach_port_set_attributes(mach_task_self(), unready, MACH_PORT_LIMITS_INFO,
                                   (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT) == KERN_SUCCESS);
    uint64_t before = rh_isolation_now_ns();
    assert(rh_isolation_mach_call(unready, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 25) == ETIMEDOUT);
    assert(rh_isolation_now_ns() - before < 1000000000ull);
    /* The first request filled qlimit=1. Later calls fail during SEND, not RECEIVE:
     * pseudo-copyout must release the extra destination uref and local send-once. */
    mach_port_urefs_t start_refs = 0, current_refs = 0;
    assert(mach_port_get_refs(mach_task_self(), unready, MACH_PORT_RIGHT_SEND, &start_refs) == KERN_SUCCESS);
    mach_msg_type_number_t full_queue_names = name_count();
    for (int i = 0; i < 64; i++) {
        assert(rh_isolation_mach_call(unready, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 2) == ETIMEDOUT);
        assert(mach_port_get_refs(mach_task_self(), unready, MACH_PORT_RIGHT_SEND, &current_refs) == KERN_SUCCESS);
        assert(current_refs == start_refs);
        assert(name_count() == full_queue_names);
    }
    assert(mach_port_mod_refs(mach_task_self(), unready, MACH_PORT_RIGHT_RECEIVE, -1) == KERN_SUCCESS);
    assert(rh_isolation_mach_call(unready, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 25) == ENOTCONN);
    mach_port_deallocate(mach_task_self(), unready);

    struct fixture fixture;
    start_fixture(&fixture);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, RH_ISOLATION_PING_MS) == 0);
    drain_fixture(&fixture);
    mach_msg_type_number_t start_names = name_count();
    atomic_store(&fixture.supported, 0);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 500) == ENOTSUP);
    atomic_store(&fixture.supported, 1);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version + 1, RH_ISOLATION_PING, 0, 0, 500) == EPROTO);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version + 1, RH_ISOLATION_REPAIR, child, child_version, 500) == EPROTO);
    assert(atomic_load(&fixture.callback_count) == 0 && atomic_load(&fixture.mutation) == 0);
    atomic_store(&fixture.expected_client, getpid() + 1);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version, 500) == EPERM);
    assert(atomic_load(&fixture.callback_count) == 0 && atomic_load(&fixture.mutation) == 0);
    atomic_store(&fixture.expected_client, getpid());
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version + 1, 500) == ESRCH);
    assert(atomic_load(&fixture.mutation) == 0);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version, 500) == 0);
    assert(atomic_load(&fixture.mutation) == 1);
    for (int mode = 1; mode <= 5; mode++) {
        atomic_store(&fixture.reply_mode, mode);
        assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version, 500) == EPROTO);
    }
    atomic_store(&fixture.reply_mode, 0);

    /* Active repair exceeds the deadline: caller returns, callback observes cancellation before a write. */
    atomic_store(&fixture.delay_ms, 150);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version, 30) == ETIMEDOUT);
    drain_fixture(&fixture);
    assert(atomic_load(&fixture.mutation) == 1);
    atomic_store(&fixture.delay_ms, 0);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version, 500) == 0);
    assert(atomic_load(&fixture.mutation) == 2);

    /* A late ACK targets the retired receive right and never a later mailbox. */
    atomic_store(&fixture.reply_mode, 6);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version, 30) == ETIMEDOUT);
    drain_fixture(&fixture);
    assert(atomic_load(&fixture.late_ack_count) == 1);
    atomic_store(&fixture.reply_mode, 0);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 500) == 0);
    assert(atomic_load(&fixture.mutation) == 2);

    /* An expired queued repair is discarded before the callback is entered. */
    drain_fixture(&fixture);
    int callbacks = atomic_load(&fixture.callback_count);
    dispatch_suspend(fixture.source);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_REPAIR, child, child_version, 25) == ETIMEDOUT);
    dispatch_resume(fixture.source);
    assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 500) == 0);
    assert(atomic_load(&fixture.callback_count) == callbacks);
    assert(atomic_load(&fixture.mutation) == 2);

    /* Count from the initial warm PING, so errors, timeouts and malformed ACKs
     * are covered too, not just this successful repetition loop. */
    for (int i = 0; i < 100; i++)
        assert(rh_isolation_mach_call(fixture.port, getpid(), helper_version, RH_ISOLATION_PING, 0, 0, 500) == 0);
    drain_fixture(&fixture);
    assert(name_count() <= start_names + 2);
    char value;
    assert(read(marker[0], &value, 1) == -1 && errno == EAGAIN); /* child never resumed */
    stop_fixture(&fixture);
    kill(child, SIGKILL);
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    owned_child = 0;
    close(marker[0]);
    puts("PASS: real Mach readiness, dead/unsupported helper, protocol/nonce/identity, cancellation, late request, rights and paused-child tests");
    return 0;
}
