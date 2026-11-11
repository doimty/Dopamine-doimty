#include "app_isolation_spawn.h"

#include <errno.h>
#include <stddef.h>

static int callback_error(int status)
{
    return status >= 0 ? status : EIO;
}

static struct app_isolation_spawn_report finish(
    struct app_isolation_spawn_report report, int entry_errno)
{
    errno = report.result == -1 ? report.error : entry_errno;
    return report;
}

static void terminate_child(const struct app_isolation_spawn_ops *ops,
                            void *context, pid_t child,
                            struct app_isolation_spawn_report *report)
{
    /* The published PID stays intact, including when termination fails. */
    if (!report->created || child <= 1) return;
    report->kill_error = callback_error(ops->kill(context, child));
    report->child_killed = report->kill_error == 0;
}

struct app_isolation_spawn_report app_isolation_spawn(
    const struct app_isolation_spawn_ops *ops,
    void *context,
    pid_t *published_pid,
    short suspended_flag)
{
    const int entry_errno = errno;
    struct app_isolation_spawn_report report = {0};
    unsigned int suspended_bits = (unsigned short)suspended_flag;
    short original_flags = 0;
    int status;
    int spawn_errno;
    int restore_error;
    pid_t child = 0;

    report.result = -1;
    report.phase = APP_ISOLATION_SPAWN_VALIDATE;
    report.error = EINVAL;
    if (!ops || !published_pid || !ops->get_flags || !ops->set_flags ||
        !ops->spawn || !ops->repair || !ops->resume || !ops->kill ||
        !suspended_bits || (suspended_bits & (suspended_bits - 1))) {
        return finish(report, entry_errno);
    }

    report.phase = APP_ISOLATION_SPAWN_GET_FLAGS;
    report.error = callback_error(ops->get_flags(context, &original_flags));
    if (report.error) return finish(report, entry_errno);

    report.phase = APP_ISOLATION_SPAWN_SET_SUSPENDED;
    status = ops->set_flags(context,
                           (short)((unsigned short)original_flags |
                                   suspended_bits));
    report.error = callback_error(status);
    if (report.error) {
        /* A failed injected setter is not trusted to leave attributes intact.
         * This best-effort restore never permits a spawn after that failure.
         */
        status = ops->set_flags(context, original_flags);
        report.flags_restored = callback_error(status) == 0;
        return finish(report, entry_errno);
    }

    report.phase = APP_ISOLATION_SPAWN_SPAWN;
    status = ops->spawn(context, published_pid);
    spawn_errno = errno;
    if (status == 0) {
        child = *published_pid;
        if (child > 1) {
            report.created = 1;
            report.result = 0;
            report.error = 0;
        } else {
            /* Neither PID 0 (a process group) nor PID 1 is a valid child. */
            report.error = EPROTO;
        }
    } else {
        report.error = status == -1 && spawn_errno > 0 ? spawn_errno : EIO;
    }

    /* Attribute restoration is required even when raw spawn fails. It only
     * edits the user's attribute object; it never resumes a suspended child.
     */
    restore_error = callback_error(ops->set_flags(context, original_flags));
    report.flags_restored = restore_error == 0;
    if (!report.created) return finish(report, entry_errno);

    if (restore_error) {
        report.phase = APP_ISOLATION_SPAWN_RESTORE_FLAGS;
        report.error = restore_error;
        terminate_child(ops, context, child, &report);
        return finish(report, entry_errno);
    }

    report.phase = APP_ISOLATION_SPAWN_REPAIR;
    report.error = callback_error(ops->repair(context, child));
    if (report.error) {
        terminate_child(ops, context, child, &report);
        return finish(report, entry_errno);
    }
    report.repair_applied = 1;

    if (!((unsigned short)original_flags & suspended_bits)) {
        report.phase = APP_ISOLATION_SPAWN_RESUME;
        report.error = callback_error(ops->resume(context, child));
        if (report.error) {
            terminate_child(ops, context, child, &report);
            return finish(report, entry_errno);
        }
    }

    report.phase = APP_ISOLATION_SPAWN_COMPLETE;
    return finish(report, entry_errno);
}
