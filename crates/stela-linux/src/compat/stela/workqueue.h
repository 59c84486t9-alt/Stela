/* SPDX-License-Identifier: MIT */
#ifndef STELA_WORKQUEUE_H
#define STELA_WORKQUEUE_H
#include <linux/types.h>

/* A worker the owner started (its start_worker service): runs queued work in
 * the entered owner, on the calling Linux task, until none it may take is
 * left. */
enum stela_linux_worker_kind {
    STELA_WORKER_DEDICATED = 0, STELA_WORKER_NORMAL = 1, STELA_WORKER_HIGHPRI = 2,
};
struct stela_linux_worker_call { const struct stela_linux_owner *owner; unsigned int kind; };
_Static_assert(sizeof(struct stela_linux_worker_call) == 16, "Linux worker call ABI");
void stela_linux_workers_run(unsigned int kind);

/* Start a dedicated retained kernel continuation through the same native
 * task producer, without pretending its identity is the creator's task.
 * The callback/context must stay live until its non-yielding return tail. */
int stela_linux_start_task(void (*run)(void *), void *context);

/* The scheduler's report that the current task is about to sleep, or has
 * woken; a sleeping worker hands pending work to another. */
void stela_linux_worker_sleeping(bool sleeping);
/* Attempt pending worker startup after resource availability changed. Actual
 * entered process context is required; this acknowledges no work completion. */
void stela_linux_workqueue_retry(void);
#endif
