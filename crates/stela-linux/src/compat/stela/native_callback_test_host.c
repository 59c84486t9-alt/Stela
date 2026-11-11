// SPDX-License-Identifier: GPL-2.0-or-later
/* The standalone C suites use the sanitized common archive with a bare owner.
 * They have no Rust task broker or timer delivery owner. Trap if a suite
 * reaches either boundary so it cannot pass on fabricated native state.
 * The Rust-hosted task suites link the real providers instead. */
#include <stela/managed.h>
#include <stela/task_bootstrap.h>
#include <stela/test.h>
#include <stela/timer.h>

#define UNUSED __attribute__((unused))
#define REFUSE() stela_test_fail(__FILE__, __LINE__, __func__)

int stela_linux_task_stack_allocate(struct stela_linux_task_birth *birth UNUSED,
    int node UNUSED, bool *unexposed UNUSED)
{
    REFUSE();
}

void stela_linux_task_native_source_freed(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED, u64 generation UNUSED)
{
    REFUSE();
}

void stela_linux_task_native_source_tail(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED, u64 generation UNUSED)
{
    REFUSE();
}

void stela_linux_task_native_abort(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED, u64 generation UNUSED)
{
    REFUSE();
}

int stela_linux_task_native_thread_prepare(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED, int (*entry)(void *) UNUSED,
    void *argument UNUSED)
{
    REFUSE();
}

int stela_linux_task_native_reserve_rank(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED, const struct stela_linux_task_rank *rank UNUSED)
{
    REFUSE();
}

void stela_linux_task_native_publish(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED, const struct stela_linux_task_rank *rank UNUSED)
{
    REFUSE();
}

void stela_linux_task_native_activate(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED)
{
    REFUSE();
}

void stela_linux_task_native_terminal_returned(struct stela_linux_task *task UNUSED,
    const struct stela_linux_owner *owner UNUSED, u64 generation UNUSED)
{
    REFUSE();
}

bool stela_linux_task_native_pending(const struct stela_linux_owner *owner UNUSED)
{
    REFUSE();
}

int stela_linux_task_native_process_one(const struct stela_linux_owner *owner UNUSED)
{
    REFUSE();
}

void stela_linux_managed_source_event(void *context UNUSED,
    struct stela_linux_managed_lease *lease UNUSED, const struct stela_linux_owner *owner UNUSED,
    unsigned int event UNUSED, int result UNUSED)
{
    REFUSE();
}

int stela_linux_timer_delivery_check(const struct stela_linux_timer_delivery *delivery UNUSED,
    const struct stela_linux_owner *owner UNUSED)
{
    REFUSE();
}
