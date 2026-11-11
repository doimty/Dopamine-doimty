#ifndef RH_APP_ISOLATION_MACH_H
#define RH_APP_ISOLATION_MACH_H

#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Separate from the legacy XPC protocol. Every call owns its reply receive right. */
#define RH_ISOLATION_MACH_MAGIC 0x52484953u
#define RH_ISOLATION_MACH_VERSION 2u
#define RH_ISOLATION_MACH_REQUEST_ID 0x52484901
#define RH_ISOLATION_MACH_REPLY_ID 0x52484902
#define RH_ISOLATION_PING 1u
#define RH_ISOLATION_REPAIR 2u
#define RH_ISOLATION_PING_MS 100u
#define RH_ISOLATION_REPAIR_MS 1500u

struct rh_isolation_mach_request {
    mach_msg_header_t header;
    uint32_t magic;
    uint32_t version;
    uint32_t operation;
    uint32_t reserved;
    uint64_t nonce;
    uint64_t deadline_ns;
    int32_t pid;
    int32_t pidversion;
    int32_t helper_pid;
    int32_t helper_pidversion;
};

struct rh_isolation_mach_reply {
    mach_msg_header_t header;
    uint32_t magic;
    uint32_t version;
    uint32_t operation;
    int32_t status;
    uint64_t nonce;
    int32_t pid;
    int32_t pidversion;
    int32_t helper_pid;
    int32_t helper_pidversion;
    uint32_t applied;
    uint32_t reserved;
};

/* Caller and service share the machine's monotonic uptime clock, not wall time. */
uint64_t rh_isolation_now_ns(void);
// Userspace-only identity query; also linked into systemhook without kernel helpers.
int rh_isolation_pidversion(pid_t pid);
bool rh_isolation_request_cancelled(uint64_t deadline_ns, mach_port_t reply_right);
int rh_isolation_mach_call(mach_port_t service, pid_t helper_pid, int helper_pidversion,
                          uint32_t operation, pid_t target, int target_pidversion,
                          unsigned timeout_ms);

/* One nonblocking receive on a serial service queue. Callback runs synchronously. */
typedef int (*rh_isolation_mach_repair_fn)(const struct rh_isolation_mach_request *,
                                           mach_port_t reply_right, void *context);
int rh_isolation_mach_serve_once(mach_port_t service, pid_t expected_client,
                                 bool supported, rh_isolation_mach_repair_fn repair,
                                 void *context);

#endif
