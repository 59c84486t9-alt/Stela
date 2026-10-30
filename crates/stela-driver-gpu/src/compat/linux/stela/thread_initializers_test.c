// SPDX-License-Identifier: MIT
/* Native architecture metadata initializers, without current/task admission. */
#include <linux/preempt.h>
#include <linux/sched.h>
#include <stela/test.h>

/* Initializer-only object. All unowned resource fields stay absent; this is
 * neither an initialized full task-resource graph nor an executable task. The
 * unchanged upstream init_task.c is separately compiled with its real graph. */
static struct task_struct initial = {
    .thread_info = INIT_THREAD_INFO(initial),
    .thread = INIT_THREAD,
};

int main(void)
{
    assert(initial.thread_info.task == &initial);
    assert(!initial.thread_info.flags);
    assert(initial.thread_info.preempt_count == INIT_PREEMPT_COUNT);
    assert(INIT_PREEMPT_COUNT == PREEMPT_OFFSET);
    assert(!initial.stack && !initial.worker_private);
    assert(!initial.mm && !initial.signal && !initial.sighand);
    assert(!initial.files && !initial.fs && !initial.nsproxy);
    return 0;
}
