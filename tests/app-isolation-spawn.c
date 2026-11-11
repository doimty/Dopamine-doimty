/* Host-only lifecycle tests. No callback creates or signals a real process. */
#include "../BaseBin/launchdhook/src/app_isolation_spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
                #condition); \
        abort(); \
    } \
} while (0)

#define SUSPENDED_FLAG ((short)0x0080)
#define OTHER_FLAGS ((short)0x0025)
#define ENTRY_ERRNO E2BIG
#define CHILD_PID ((pid_t)2468)
#define UNWRITTEN_PID ((pid_t)-771)

struct fixture {
    struct {
        unsigned int before;
        pid_t pid;
        unsigned int after;
    } publication;
    pid_t *registered_pid;
    pid_t decoy_pid;
    short original_flags;
    short current_flags;
    short suspended_flag;
    int get_error;
    int force_error;
    int restore_error;
    int spawn_result;
    int spawn_errno;
    pid_t spawn_pid;
    int repair_error;
    int resume_error;
    int kill_error;
    unsigned int set_calls;
    int child_created;
    int child_suspended;
    int attributes_restored;
    int repair_completed;
    int executed;
    int terminated;
    char events[32];
    size_t event_count;
};

static void event(struct fixture *f, char value)
{
    CHECK(f->event_count + 1 < sizeof(f->events));
    f->events[f->event_count++] = value;
    f->events[f->event_count] = '\0';
}

static void initialize(struct fixture *f, short original_flags)
{
    memset(f, 0, sizeof(*f));
    f->publication.before = 0xa51c73e9U;
    f->publication.pid = UNWRITTEN_PID;
    f->publication.after = 0x4e9b6123U;
    f->decoy_pid = (pid_t)97531;
    f->original_flags = original_flags;
    f->current_flags = original_flags;
    f->suspended_flag = SUSPENDED_FLAG;
    f->spawn_pid = CHILD_PID;
    f->spawn_errno = ECHILD;
    /* The parent publishes this exact address before entering the driver. */
    f->registered_pid = &f->publication.pid;
    event(f, 'B');
}

static int get_flags(void *context, short *flags)
{
    struct fixture *f = context;
    CHECK(flags != NULL);
    event(f, 'G');
    errno = ERANGE; /* POSIX callback errors must not be read from errno. */
    if (!f->get_error) *flags = f->current_flags;
    return f->get_error;
}

static int set_flags(void *context, short flags)
{
    struct fixture *f = context;
    int status;
    ++f->set_calls;
    if (f->set_calls == 1) {
        event(f, 'F');
        CHECK(flags == (short)((unsigned short)f->original_flags |
                              (unsigned short)f->suspended_flag));
        status = f->force_error;
        /* Even an injected setter which changes flags then fails must not
         * permit spawn, and its original flags should be restored.
         */
        f->current_flags = flags;
    } else {
        CHECK(f->set_calls == 2);
        event(f, 'O');
        CHECK(flags == f->original_flags);
        status = f->restore_error;
        if (!status) {
            f->current_flags = flags;
            f->attributes_restored = 1;
        }
        /* Editing the attribute object must leave a created child stopped. */
        if (f->child_created) CHECK(f->child_suspended);
    }
    errno = ERANGE;
    return status;
}

static int raw_spawn(void *context, pid_t *published_pid)
{
    struct fixture *f = context;
    event(f, 'S');
    CHECK(f->registered_pid == &f->publication.pid);
    CHECK(published_pid == f->registered_pid);
    CHECK(f->set_calls == 1);
    CHECK(!f->force_error);
    CHECK((unsigned short)f->current_flags &
          (unsigned short)f->suspended_flag);
    CHECK(!f->executed);
    CHECK(!f->repair_completed);
    if (f->spawn_result == 0) {
        /* Simulate the kernel's write to the already registered address. */
        *published_pid = f->spawn_pid;
        event(f, 'P');
        f->child_created = f->spawn_pid > 1;
        f->child_suspended = f->child_created;
    }
    errno = f->spawn_errno;
    return f->spawn_result;
}

static void check_child(struct fixture *f, pid_t child)
{
    CHECK(child > 1);
    CHECK(child == f->spawn_pid);
    CHECK(child == f->publication.pid);
    CHECK(child != f->decoy_pid);
    CHECK(f->child_created);
}

static int strict_repair(void *context, pid_t child)
{
    struct fixture *f = context;
    event(f, 'R');
    check_child(f, child);
    CHECK(f->attributes_restored);
    CHECK(f->child_suspended);
    CHECK(!f->executed);
    if (!f->repair_error) f->repair_completed = 1;
    errno = ERANGE;
    return f->repair_error;
}

static int resume_child(void *context, pid_t child)
{
    struct fixture *f = context;
    event(f, 'C');
    check_child(f, child);
    CHECK(f->attributes_restored);
    CHECK(f->repair_completed);
    CHECK(f->child_suspended);
    CHECK(!((unsigned short)f->original_flags &
            (unsigned short)f->suspended_flag));
    CHECK(!f->executed);
    if (!f->resume_error) {
        f->child_suspended = 0;
        /* The execution sentinel cannot be reached until acknowledged repair. */
        f->executed = 1;
        event(f, 'E');
    }
    errno = ERANGE;
    return f->resume_error;
}

static int kill_child(void *context, pid_t child)
{
    struct fixture *f = context;
    event(f, 'K');
    check_child(f, child);
    CHECK(!f->executed);
    if (!f->kill_error) f->terminated = 1;
    errno = ERANGE;
    return f->kill_error;
}

static const struct app_isolation_spawn_ops operations = {
    .get_flags = get_flags,
    .set_flags = set_flags,
    .spawn = raw_spawn,
    .repair = strict_repair,
    .resume = resume_child,
    .kill = kill_child
};

static struct app_isolation_spawn_report run(struct fixture *f)
{
    errno = ENTRY_ERRNO;
    return app_isolation_spawn(&operations, f, &f->publication.pid,
                               f->suspended_flag);
}

static void expect_events(struct fixture *f, const char *expected)
{
    CHECK(strcmp(f->events, expected) == 0);
    CHECK(f->publication.before == 0xa51c73e9U);
    CHECK(f->publication.after == 0x4e9b6123U);
    CHECK(f->decoy_pid == (pid_t)97531);
}

static void expect_report(struct app_isolation_spawn_report report,
                          int result, enum app_isolation_spawn_phase phase,
                          int created, int repaired, int killed, int error,
                          int restored, int kill_error)
{
    CHECK(report.result == result);
    CHECK(report.phase == phase);
    CHECK(report.created == created);
    CHECK(report.repair_applied == repaired);
    CHECK(report.child_killed == killed);
    CHECK(report.error == error);
    CHECK(report.flags_restored == restored);
    CHECK(report.kill_error == kill_error);
    CHECK(errno == (result == -1 ? error : ENTRY_ERRNO));
}

static void test_success_and_caller_suspension(void)
{
    struct fixture f;
    struct app_isolation_spawn_report report;
    initialize(&f, OTHER_FLAGS);
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_COMPLETE, 1, 1, 0, 0, 1, 0);
    expect_events(&f, "BGFSPORCE");
    CHECK(f.publication.pid == CHILD_PID);
    CHECK(f.current_flags == OTHER_FLAGS);
    CHECK(f.executed && !f.child_suspended);

    initialize(&f, (short)(OTHER_FLAGS | SUSPENDED_FLAG));
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_COMPLETE, 1, 1, 0, 0, 1, 0);
    expect_events(&f, "BGFSPOR");
    CHECK(f.publication.pid == CHILD_PID);
    CHECK(f.current_flags == f.original_flags);
    CHECK(f.repair_completed && f.child_suspended && !f.executed);

    /* The injected native flag may occupy the sign bit of short. */
    initialize(&f, OTHER_FLAGS);
    f.suspended_flag = (short)0x8000;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_COMPLETE, 1, 1, 0, 0, 1, 0);
    expect_events(&f, "BGFSPORCE");
}

static void test_get_and_force_fail_without_spawn(void)
{
    struct fixture f;
    struct app_isolation_spawn_report report;
    initialize(&f, OTHER_FLAGS);
    f.get_error = EPERM;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_GET_FLAGS, 0, 0, 0,
                  EPERM, 0, 0);
    expect_events(&f, "BG");
    CHECK(f.publication.pid == UNWRITTEN_PID);
    CHECK(f.current_flags == OTHER_FLAGS);

    initialize(&f, OTHER_FLAGS);
    f.force_error = EACCES;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SET_SUSPENDED, 0, 0, 0,
                  EACCES, 1, 0);
    expect_events(&f, "BGFO");
    CHECK(f.publication.pid == UNWRITTEN_PID);
    CHECK(f.current_flags == OTHER_FLAGS);

    initialize(&f, OTHER_FLAGS);
    f.force_error = EACCES;
    f.restore_error = EBUSY;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SET_SUSPENDED, 0, 0, 0,
                  EACCES, 0, 0);
    expect_events(&f, "BGFO");
    CHECK(f.publication.pid == UNWRITTEN_PID);
}

static void test_spawn_failure_restores_and_preserves_errno(void)
{
    struct fixture f;
    struct app_isolation_spawn_report report;
    initialize(&f, OTHER_FLAGS);
    f.spawn_result = -1;
    f.spawn_errno = ENOENT;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SPAWN, 0, 0, 0,
                  ENOENT, 1, 0);
    expect_events(&f, "BGFSO");
    CHECK(f.publication.pid == UNWRITTEN_PID);
    CHECK(f.current_flags == OTHER_FLAGS);

    initialize(&f, OTHER_FLAGS);
    f.spawn_result = -1;
    f.spawn_errno = ENOEXEC;
    f.restore_error = EBUSY;
    /* A stale nonchild value in the published slot must never be signalled. */
    f.publication.pid = (pid_t)9001;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SPAWN, 0, 0, 0,
                  ENOEXEC, 0, 0);
    expect_events(&f, "BGFSO");
    CHECK(f.publication.pid == (pid_t)9001);
}

static void test_restore_failure_terminates_created_child(void)
{
    struct fixture f;
    struct app_isolation_spawn_report report;
    unsigned int original_suspension;
    for (original_suspension = 0; original_suspension < 2;
         ++original_suspension) {
        initialize(&f, (short)(OTHER_FLAGS |
                   (original_suspension ? SUSPENDED_FLAG : 0)));
        f.restore_error = EBUSY;
        report = run(&f);
        expect_report(report, 0, APP_ISOLATION_SPAWN_RESTORE_FLAGS,
                      1, 0, 1, EBUSY, 0, 0);
        expect_events(&f, "BGFSPOK");
        CHECK(f.publication.pid == CHILD_PID);
        CHECK(!f.repair_completed && !f.executed && f.terminated);
    }
}

static void test_repair_and_resume_failures_terminate_without_retry(void)
{
    struct fixture f;
    struct app_isolation_spawn_report report;
    initialize(&f, OTHER_FLAGS);
    f.repair_error = ENOTSUP;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_REPAIR, 1, 0, 1,
                  ENOTSUP, 1, 0);
    expect_events(&f, "BGFSPORK");
    CHECK(f.publication.pid == CHILD_PID);
    CHECK(!f.repair_completed && !f.executed && f.terminated);

    initialize(&f, (short)(OTHER_FLAGS | SUSPENDED_FLAG));
    f.repair_error = EPERM;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_REPAIR, 1, 0, 1,
                  EPERM, 1, 0);
    expect_events(&f, "BGFSPORK");
    CHECK(f.child_suspended && !f.executed);

    initialize(&f, OTHER_FLAGS);
    f.resume_error = ESRCH;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_RESUME, 1, 1, 1,
                  ESRCH, 1, 0);
    expect_events(&f, "BGFSPORCK");
    CHECK(f.publication.pid == CHILD_PID);
    CHECK(f.repair_completed && !f.executed && f.terminated);

    initialize(&f, OTHER_FLAGS);
    f.repair_error = ENOTSUP;
    f.kill_error = EPERM;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_REPAIR, 1, 0, 0,
                  ENOTSUP, 1, EPERM);
    expect_events(&f, "BGFSPORK");
    CHECK(f.publication.pid == CHILD_PID);
    CHECK(!f.executed && !f.terminated);
}

static void test_invalid_pid_never_signals_another_process(void)
{
    const pid_t invalid_pids[] = { (pid_t)0, (pid_t)1, (pid_t)-1 };
    struct fixture f;
    struct app_isolation_spawn_report report;
    size_t i;
    for (i = 0; i < sizeof(invalid_pids) / sizeof(invalid_pids[0]); ++i) {
        initialize(&f, OTHER_FLAGS);
        f.spawn_pid = invalid_pids[i];
        report = run(&f);
        expect_report(report, -1, APP_ISOLATION_SPAWN_SPAWN, 0, 0, 0,
                      EPROTO, 1, 0);
        expect_events(&f, "BGFSPO");
        CHECK(f.publication.pid == invalid_pids[i]);
        CHECK(!f.executed && !f.terminated);
    }

    initialize(&f, OTHER_FLAGS);
    f.spawn_pid = 0;
    f.restore_error = EBUSY;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SPAWN, 0, 0, 0,
                  EPROTO, 0, 0);
    expect_events(&f, "BGFSPO");
}

static void test_callback_contract_errors(void)
{
    struct fixture f;
    struct app_isolation_spawn_report report;
    initialize(&f, OTHER_FLAGS);
    f.get_error = -1;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_GET_FLAGS, 0, 0, 0,
                  EIO, 0, 0);
    expect_events(&f, "BG");

    initialize(&f, OTHER_FLAGS);
    f.force_error = -1;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SET_SUSPENDED, 0, 0, 0,
                  EIO, 1, 0);
    expect_events(&f, "BGFO");

    initialize(&f, OTHER_FLAGS);
    f.spawn_result = EACCES; /* POSIX spawn convention is forbidden here. */
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SPAWN, 0, 0, 0,
                  EIO, 1, 0);
    expect_events(&f, "BGFSO");

    initialize(&f, OTHER_FLAGS);
    f.spawn_result = -1;
    f.spawn_errno = 0;
    report = run(&f);
    expect_report(report, -1, APP_ISOLATION_SPAWN_SPAWN, 0, 0, 0,
                  EIO, 1, 0);
    expect_events(&f, "BGFSO");

    initialize(&f, OTHER_FLAGS);
    f.restore_error = -1;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_RESTORE_FLAGS, 1, 0, 1,
                  EIO, 0, 0);
    expect_events(&f, "BGFSPOK");

    initialize(&f, OTHER_FLAGS);
    f.repair_error = -1;
    f.kill_error = -1;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_REPAIR, 1, 0, 0,
                  EIO, 1, EIO);
    expect_events(&f, "BGFSPORK");

    initialize(&f, OTHER_FLAGS);
    f.resume_error = -1;
    report = run(&f);
    expect_report(report, 0, APP_ISOLATION_SPAWN_RESUME, 1, 1, 1,
                  EIO, 1, 0);
    expect_events(&f, "BGFSPORCK");
}

static int get_flags_with_null_context(void *context, short *flags)
{
    CHECK(context == NULL);
    CHECK(flags != NULL);
    errno = ERANGE;
    return ENOTSUP;
}

static void test_argument_validation(void)
{
    struct fixture f;
    struct app_isolation_spawn_report report;
    struct app_isolation_spawn_ops ops;
    unsigned int missing;
    initialize(&f, OTHER_FLAGS);
    errno = ENTRY_ERRNO;
    report = app_isolation_spawn(NULL, &f, &f.publication.pid, SUSPENDED_FLAG);
    expect_report(report, -1, APP_ISOLATION_SPAWN_VALIDATE, 0, 0, 0,
                  EINVAL, 0, 0);
    expect_events(&f, "B");

    errno = ENTRY_ERRNO;
    report = app_isolation_spawn(&operations, &f, NULL, SUSPENDED_FLAG);
    expect_report(report, -1, APP_ISOLATION_SPAWN_VALIDATE, 0, 0, 0,
                  EINVAL, 0, 0);
    expect_events(&f, "B");

    for (missing = 0; missing < 6; ++missing) {
        ops = operations;
        switch (missing) {
        case 0: ops.get_flags = NULL; break;
        case 1: ops.set_flags = NULL; break;
        case 2: ops.spawn = NULL; break;
        case 3: ops.repair = NULL; break;
        case 4: ops.resume = NULL; break;
        case 5: ops.kill = NULL; break;
        }
        errno = ENTRY_ERRNO;
        report = app_isolation_spawn(&ops, &f, &f.publication.pid,
                                     SUSPENDED_FLAG);
        expect_report(report, -1, APP_ISOLATION_SPAWN_VALIDATE, 0, 0, 0,
                      EINVAL, 0, 0);
        expect_events(&f, "B");
    }

    errno = ENTRY_ERRNO;
    report = app_isolation_spawn(&operations, &f, &f.publication.pid, 0);
    expect_report(report, -1, APP_ISOLATION_SPAWN_VALIDATE, 0, 0, 0,
                  EINVAL, 0, 0);
    errno = ENTRY_ERRNO;
    report = app_isolation_spawn(&operations, &f, &f.publication.pid, 3);
    expect_report(report, -1, APP_ISOLATION_SPAWN_VALIDATE, 0, 0, 0,
                  EINVAL, 0, 0);
    expect_events(&f, "B");
    CHECK(f.publication.pid == UNWRITTEN_PID);

    ops = operations;
    ops.get_flags = get_flags_with_null_context;
    errno = ENTRY_ERRNO;
    report = app_isolation_spawn(&ops, NULL, &f.publication.pid, SUSPENDED_FLAG);
    expect_report(report, -1, APP_ISOLATION_SPAWN_GET_FLAGS, 0, 0, 0,
                  ENOTSUP, 0, 0);
}

int main(void)
{
    test_success_and_caller_suspension();
    test_get_and_force_fail_without_spawn();
    test_spawn_failure_restores_and_preserves_errno();
    test_restore_failure_terminates_created_child();
    test_repair_and_resume_failures_terminate_without_retry();
    test_invalid_pid_never_signals_another_process();
    test_callback_contract_errors();
    test_argument_validation();
    puts("app-isolation-spawn: all tests passed");
    return 0;
}
