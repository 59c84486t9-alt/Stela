// SPDX-License-Identifier: GPL-2.0-only
/* Native kernel-thread frame construction; original copy_process resources
 * remain authoritative. The machine's x86 ret_from_fork/context scheduler is
 * not a second active owner of the actual native Runtime stack. */
#include <linux/build_bug.h>
#include <linux/errno.h>
#include <linux/sched/task.h>
#include <stela/task.h>
#include <linux/mm.h>
#include <stela/task_bootstrap.h>

static_assert(CONFIG_THREAD_INFO_IN_TASK == 1);
static_assert(!IS_ENABLED(CONFIG_VMAP_STACK));
static_assert(THREAD_SIZE >= PAGE_SIZE);

/* Source weak arch_dup_task_struct's actual copy, plus this native arch's
 * genuine embedded thread_info backpointer. CONFIG_THREAD_INFO_IN_TASK makes
 * generic setup_thread_stack a no-op, so the copied parent pointer must not
 * survive. This is born original allocation metadata, NOT current/task grant. */
int arch_dup_task_struct(struct task_struct *task, struct task_struct *parent)
{
    *task = *parent;
    task->thread_info.task = task;
    return 0;
}

int copy_thread(struct task_struct *task, const struct kernel_clone_args *args)
{
    /* Validation here remains prepublication. The actual typed producer must
     * retain the exact source fn/argument/module/code/stack graph and prepare
     * its one native bootstrap frame; no callback executes on this path. */
    if (!args || !args->kthread || !args->fn || args->io_thread || args->user_worker)
        return -EOPNOTSUPP;
    return stela_linux_task_thread_prepare(task, args);
}

void wake_up_new_task(struct task_struct *task)
{
    stela_linux_task_wake_new(task);
}

void __noreturn do_task_dead(void)
{
    /* Original source closure (sched/core.c do_task_dead), with the one native
     * architectural switch instead of a second Linux __schedule runqueue. */
    set_special_state(TASK_DEAD);
    current->flags |= PF_NOFREEZE;
    stela_linux_task_terminal_current();
}
