#include "app_isolation_mach.h"
// The checked-in iOS libbsm shim shares _BSM_AUDIT_H with audit.h. Include
// audit.h first so its accessor declarations are not hidden by that shim.
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libproc.h>

extern int audit_token_to_pidversion(audit_token_t token);

struct rh_proc_unique_info {
    uint8_t uuid[16];
    uint64_t uniqueid, parent_uniqueid;
    int32_t pidversion;
    uint32_t reserved2;
    uint64_t reserved3, reserved4;
};
_Static_assert(sizeof(struct rh_proc_unique_info) == 56, "Unexpected PROC_PIDUNIQIDENTIFIERINFO layout");

int rh_isolation_pidversion(pid_t pid)
{
    if (pid <= 0) return 0;
    int saved_errno = errno;
    struct rh_proc_unique_info info = {0};
    int size = proc_pidinfo(pid, 17, 0, &info, sizeof(info));
    int version = size == (int)sizeof(info) && info.pidversion > 0 ? info.pidversion : 0;
    errno = saved_errno;
    return version;
}

uint64_t rh_isolation_now_ns(void)
{
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
}

bool rh_isolation_request_cancelled(uint64_t deadline_ns, mach_port_t reply_right)
{
    if (!deadline_ns || rh_isolation_now_ns() >= deadline_ns) return true;
    mach_port_type_t type = 0;
    return !MACH_PORT_VALID(reply_right) ||
        mach_port_type(mach_task_self(), reply_right, &type) != KERN_SUCCESS ||
        !(type & MACH_PORT_TYPE_SEND_ONCE);
}

static mach_msg_timeout_t remaining_ms(uint64_t deadline)
{
    uint64_t now = rh_isolation_now_ns();
    if (now >= deadline) return 0;
    return (mach_msg_timeout_t)((deadline - now + 999999ull) / 1000000ull);
}

static int transport_error(mach_msg_return_t result)
{
    if (result == MACH_SEND_TIMED_OUT || result == MACH_RCV_TIMED_OUT) return ETIMEDOUT;
    if (result == MACH_SEND_INVALID_DEST || result == MACH_RCV_PORT_DIED ||
        result == MACH_RCV_INVALID_NAME) return ENOTCONN;
    if (result == MACH_SEND_INTERRUPTED || result == MACH_RCV_INTERRUPTED) return EINTR;
    if (result == MACH_RCV_TOO_LARGE) return EPROTO;
    return EIO;
}

/* A timed-out/interrupted send can pseudo-copyout both header rights. COPY_SEND
 * becomes an additional destination SEND uref; MAKE_SEND_ONCE becomes a distinct
 * local send-once name. Pre-copyin failures leave the original dispositions, so
 * only release actual returned rights, never the caller's receive/service rights.
 * XNU xnu-8019.80.24 ipc_kmsg_copyout_pseudo (iOS 15), lines 5264-5269. */
static void discard_pseudo_send_rights(mach_msg_header_t *header, mach_msg_return_t result)
{
    mach_msg_return_t base = result & ~MACH_MSG_MASK;
    if (base != MACH_SEND_TIMED_OUT && base != MACH_SEND_INTERRUPTED) return;
    if (MACH_MSGH_BITS_REMOTE(header->msgh_bits) == MACH_MSG_TYPE_PORT_SEND &&
        MACH_PORT_VALID(header->msgh_remote_port)) {
        mach_port_deallocate(mach_task_self(), header->msgh_remote_port);
        header->msgh_remote_port = MACH_PORT_NULL;
    }
    if (MACH_MSGH_BITS_LOCAL(header->msgh_bits) == MACH_MSG_TYPE_PORT_SEND_ONCE &&
        MACH_PORT_VALID(header->msgh_local_port)) {
        /* mach_port_deallocate also removes a returned name which has since died. */
        mach_port_deallocate(mach_task_self(), header->msgh_local_port);
        header->msgh_local_port = MACH_PORT_NULL;
    }
}

int rh_isolation_mach_call(mach_port_t service, pid_t helper_pid, int helper_pidversion,
                          uint32_t operation, pid_t target, int target_pidversion,
                          unsigned timeout_ms)
{
    if (!MACH_PORT_VALID(service) || helper_pid <= 0 || helper_pidversion <= 0) return ENOTCONN;
    if ((operation != RH_ISOLATION_PING && operation != RH_ISOLATION_REPAIR) ||
        !timeout_ms || timeout_ms > RH_ISOLATION_REPAIR_MS) return EINVAL;
    if (operation == RH_ISOLATION_REPAIR && (target <= 1 || target_pidversion <= 0)) return EINVAL;

    mach_port_t reply_port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port) != KERN_SUCCESS)
        return ENOMEM;
    struct rh_isolation_mach_request request = {0};
    request.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    request.header.msgh_size = sizeof(request);
    request.header.msgh_remote_port = service;
    request.header.msgh_local_port = reply_port;
    request.header.msgh_id = RH_ISOLATION_MACH_REQUEST_ID;
    request.magic = RH_ISOLATION_MACH_MAGIC;
    request.version = RH_ISOLATION_MACH_VERSION;
    request.operation = operation;
    arc4random_buf(&request.nonce, sizeof(request.nonce));
    request.deadline_ns = rh_isolation_now_ns() + (uint64_t)timeout_ms * 1000000ull;
    request.pid = target;
    request.pidversion = target_pidversion;
    request.helper_pid = helper_pid;
    request.helper_pidversion = helper_pidversion;

    mach_msg_return_t transport = mach_msg(&request.header,
        MACH_SEND_MSG | MACH_SEND_TIMEOUT | MACH_SEND_INTERRUPT, sizeof(request), 0,
        MACH_PORT_NULL, remaining_ms(request.deadline_ns), MACH_PORT_NULL);
    int result;
    if (transport != MACH_MSG_SUCCESS) {
        discard_pseudo_send_rights(&request.header, transport);
        result = transport_error(transport & ~MACH_MSG_MASK);
        goto done;
    }
    union {
        struct rh_isolation_mach_reply reply;
        unsigned char bytes[sizeof(struct rh_isolation_mach_reply) + MAX_TRAILER_SIZE];
    } buffer = {0};
    mach_msg_timeout_t remaining = remaining_ms(request.deadline_ns);
    if (!remaining) { result = ETIMEDOUT; goto done; }
    transport = mach_msg(&buffer.reply.header,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        0, sizeof(buffer), reply_port, remaining, MACH_PORT_NULL);
    if (transport != MACH_MSG_SUCCESS) {
        result = transport_error(transport);
        goto done;
    }
    struct rh_isolation_mach_reply *reply = &buffer.reply;
    if ((reply->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) ||
        reply->header.msgh_size != sizeof(*reply) ||
        reply->header.msgh_remote_port != MACH_PORT_NULL ||
        reply->header.msgh_id != RH_ISOLATION_MACH_REPLY_ID) {
        mach_msg_destroy(&reply->header);
        result = EPROTO;
        goto done;
    }
    mach_msg_audit_trailer_t *trailer = (void *)(buffer.bytes + sizeof(*reply));
    if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
        trailer->msgh_trailer_size < sizeof(*trailer) ||
        audit_token_to_pid(trailer->msgh_audit) != helper_pid ||
        audit_token_to_pidversion(trailer->msgh_audit) != helper_pidversion ||
        reply->magic != RH_ISOLATION_MACH_MAGIC || reply->version != RH_ISOLATION_MACH_VERSION ||
        reply->operation != operation || reply->nonce != request.nonce ||
        reply->pid != target || reply->pidversion != target_pidversion ||
        reply->helper_pid != helper_pid || reply->helper_pidversion != helper_pidversion ||
        reply->reserved || reply->applied > 1 || reply->status < 0 ||
        (operation == RH_ISOLATION_PING && reply->applied) ||
        (reply->status != 0 && reply->applied) ||
        (operation == RH_ISOLATION_REPAIR && reply->status == 0 && !reply->applied)) {
        result = EPROTO;
    } else if (rh_isolation_now_ns() >= request.deadline_ns) {
        result = ETIMEDOUT;
    } else {
        result = reply->status;
    }
    /* A valid simple response carries no rights, but destroy rejects unexpected reply rights too. */
    mach_msg_destroy(&reply->header);
done:
    /* Discard queued/late replies, revoke the service's send-once right, never reuse this mailbox. */
    mach_port_mod_refs(mach_task_self(), reply_port, MACH_PORT_RIGHT_RECEIVE, -1);
    return result;
}

int rh_isolation_mach_serve_once(mach_port_t service, pid_t expected_client,
                                 bool supported, rh_isolation_mach_repair_fn repair,
                                 void *context)
{
    union {
        struct rh_isolation_mach_request request;
        unsigned char bytes[sizeof(struct rh_isolation_mach_request) + MAX_TRAILER_SIZE];
    } buffer = {0};
    struct rh_isolation_mach_request *request = &buffer.request;
    mach_msg_return_t transport = mach_msg(&request->header,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT |
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        0, sizeof(buffer), service, 0, MACH_PORT_NULL);
    if (transport != MACH_MSG_SUCCESS) return transport_error(transport);
    if ((request->header.msgh_bits & MACH_MSGH_BITS_COMPLEX) ||
        request->header.msgh_size != sizeof(*request) ||
        request->header.msgh_id != RH_ISOLATION_MACH_REQUEST_ID ||
        MACH_MSGH_BITS_REMOTE(request->header.msgh_bits) != MACH_MSG_TYPE_PORT_SEND_ONCE) {
        mach_msg_destroy(&request->header);
        return EPROTO;
    }
    mach_msg_audit_trailer_t *trailer = (void *)(buffer.bytes + sizeof(*request));
    int result = EPROTO;
    uint64_t now = rh_isolation_now_ns();
    if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
        trailer->msgh_trailer_size < sizeof(*trailer) ||
        audit_token_to_pid(trailer->msgh_audit) != expected_client ||
        audit_token_to_pidversion(trailer->msgh_audit) != rh_isolation_pidversion(expected_client)) {
        result = EPERM;
    } else if (request->magic == RH_ISOLATION_MACH_MAGIC &&
               request->version == RH_ISOLATION_MACH_VERSION && !request->reserved &&
               request->helper_pid == getpid() && request->helper_pidversion > 0 &&
               request->helper_pidversion == rh_isolation_pidversion(getpid()) &&
               request->deadline_ns <= now + (uint64_t)RH_ISOLATION_REPAIR_MS * 1000000ull) {
        if (rh_isolation_request_cancelled(request->deadline_ns, request->header.msgh_remote_port)) {
            result = ETIMEDOUT;
        } else if (!supported) {
            result = ENOTSUP;
        } else if (request->operation == RH_ISOLATION_PING && !request->pid && !request->pidversion) {
            result = 0;
        } else if (request->operation == RH_ISOLATION_REPAIR && request->pid > 1 &&
                   request->pidversion > 0 && repair) {
            if (rh_isolation_pidversion(request->pid) != request->pidversion) {
                result = ESRCH;
            } else {
                result = repair(request, request->header.msgh_remote_port, context);
                if (result < 0) result = EIO;
                if (rh_isolation_pidversion(request->pid) != request->pidversion) result = ESRCH;
                if (rh_isolation_request_cancelled(request->deadline_ns, request->header.msgh_remote_port))
                    result = ETIMEDOUT;
            }
        }
    }
    struct rh_isolation_mach_reply reply = {0};
    reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.header.msgh_size = sizeof(reply);
    reply.header.msgh_remote_port = request->header.msgh_remote_port;
    reply.header.msgh_id = RH_ISOLATION_MACH_REPLY_ID;
    reply.magic = RH_ISOLATION_MACH_MAGIC;
    reply.version = RH_ISOLATION_MACH_VERSION;
    reply.operation = request->operation;
    reply.nonce = request->nonce;
    reply.pid = request->pid;
    reply.pidversion = request->pidversion;
    reply.helper_pid = request->helper_pid;
    reply.helper_pidversion = request->helper_pidversion;
    reply.status = result;
    reply.applied = result == 0 && request->operation == RH_ISOLATION_REPAIR;
    request->header.msgh_remote_port = MACH_PORT_NULL;
    /* Send-once right consumption is local and has a zero send timeout. */
    transport = mach_msg(&reply.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT | MACH_SEND_INTERRUPT,
                         sizeof(reply), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
    if (transport != MACH_MSG_SUCCESS) mach_msg_destroy(&reply.header);
    return transport == MACH_MSG_SUCCESS ? 0 : transport_error(transport);
}
