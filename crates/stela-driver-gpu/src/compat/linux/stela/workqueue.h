/* SPDX-License-Identifier: MIT */
#ifndef STELA_WORKQUEUE_H
#define STELA_WORKQUEUE_H
#include <linux/types.h>

/* A worker the owner started (its start_worker service): runs queued work in
 * the entered owner, on the calling Linux task, until none it may take is
 * left. */
void stela_linux_workers_run(void);

/* The scheduler's report that the current task is about to sleep, or has
 * woken; a sleeping worker hands pending work to another. */
void stela_linux_worker_sleeping(bool sleeping);
#endif
