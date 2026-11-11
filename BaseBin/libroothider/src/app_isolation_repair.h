#ifndef RH_APP_ISOLATION_REPAIR_H
#define RH_APP_ISOLATION_REPAIR_H

#include <stdbool.h>
#include <sys/types.h>

typedef bool (*rh_isolation_cancel_fn)(void *context);
/* Cooperative cancellation: no new write begins after cancellation is observed.
 * Already executing kernel operations are not preempted by a user-space deadline.
 * A held Mach task right plus audit binds userspace operations; proc_find is only
 * a lookup. Proc/task revalidation is not a retained kernel reference: the narrow
 * check/write race and in-flight kernel primitive remain explicit.
 * The caller retains ownership of the stopped child and must kill it on failure. */
int proc_fix_spinlock_strict_checked(pid_t pid, int expected_pidversion,
                                    rh_isolation_cancel_fn cancelled, void *context);

#endif
