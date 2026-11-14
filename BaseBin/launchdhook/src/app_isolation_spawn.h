#ifndef APP_ISOLATION_SPAWN_H
#define APP_ISOLATION_SPAWN_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The phase whose operation determined the result, or COMPLETE on success. */
enum app_isolation_spawn_phase {
    APP_ISOLATION_SPAWN_VALIDATE = 0,
    APP_ISOLATION_SPAWN_GET_FLAGS,
    APP_ISOLATION_SPAWN_SET_SUSPENDED,
    APP_ISOLATION_SPAWN_SPAWN,
    APP_ISOLATION_SPAWN_RESTORE_FLAGS,
    APP_ISOLATION_SPAWN_REPAIR,
    APP_ISOLATION_SPAWN_RESUME,
    APP_ISOLATION_SPAWN_COMPLETE
};

struct app_isolation_spawn_report {
    /* Raw spawn convention: 0 if a valid child was created, otherwise -1.
     * Failures after creation still return 0 so launchd observes the child's
     * exit. A spawn reporting success with PID <= 1 is a contract error (-1).
     */
    int result;
    enum app_isolation_spawn_phase phase;
    int created;
    /* The strict callback acknowledged repair-hook installation. This does
     * not certify later hook execution or runtime cache-map correctness.
     */
    int repair_applied;
    /* The kill callback accepted the termination request, not confirmed exit. */
    int child_killed;
    /* Primary POSIX error code; 0 on a fully successful lifecycle. */
    int error;
    int flags_restored;
    /* A failed cleanup must not hide the primary error. */
    int kill_error;
};

struct app_isolation_spawn_ops {
    /* All callbacks except spawn return 0 on success, or a positive POSIX
     * error code on failure. Their errno values are ignored. A negative
     * return violates that contract and is reported as EIO.
     */
    int (*get_flags)(void *context, short *flags);
    int (*set_flags)(void *context, short flags);
    /* Must call raw original spawn with published_pid itself: never use a
     * private PID and copy it out later. Returns 0 on success, or -1 with
     * errno set on failure. Other return values are contract errors (EIO).
     * context carries the parent's attrp/descriptor/environment and arguments.
     */
    int (*spawn)(void *context, pid_t *published_pid);
    /* Success means strict, acknowledged spinlock repair-hook installation
     * completed, not that the hook ran or runtime cache mappings were checked.
     * This callback and the repair server must leave the child suspended.
     */
    int (*repair)(void *context, pid_t child);
    int (*resume)(void *context, pid_t child);
    /* Terminates only child; the parent may send SIGQUIT then SIGKILL here. */
    int (*kill)(void *context, pid_t child);
};

/* Drives one isolated spawn without allocation, global state, or retries.
 *
 * The parent must register published_pid with its blacklist BEFORE calling.
 * Every callback and published_pid must be non-NULL; context may be NULL.
 * suspended_flag is the parent's POSIX_SPAWN_START_SUSPENDED value and must
 * identify one nonzero flag bit. This C module needs no platform spawn API.
 *
 * The original flags are read and START_SUSPENDED is set before spawn. The
 * caller's flags are restored immediately after every spawn attempt. Repair
 * must succeed before resume, and resume runs only if the caller originally
 * requested a running child. Any restore/repair/resume failure after a valid
 * child was created invokes kill once, preserves the published PID, and
 * returns result 0. The parent must not retry the original/native spawn.
 *
 * On result -1, errno is report.error (in particular raw spawn errno survives
 * attribute restoration). On result 0, entry errno is preserved, including
 * cleanup failures; inspect report.error/phase for the lifecycle outcome.
 * flags_restored means the original flags were confirmed unchanged or a
 * restore call succeeded. No userspace flag operation resumes a child.
 */
struct app_isolation_spawn_report app_isolation_spawn(
    const struct app_isolation_spawn_ops *ops,
    void *context,
    pid_t *published_pid,
    short suspended_flag);

#ifdef __cplusplus
}
#endif

#endif
