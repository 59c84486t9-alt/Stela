/* SPDX-License-Identifier: MIT */
#ifndef STELA_COUNTS_H
#define STELA_COUNTS_H
#include <linux/types.h>

struct task_struct;

/* Slots per kind. A slot keeps the function that first claimed it; calls of
 * functions past the last slot count in `other`. Function 1 stands for none. */
#define STELA_LINUX_COUNT_SLOTS 32

struct stela_linux_count {
	unsigned long function;
	unsigned long count;
};

struct stela_linux_count_kind {
	struct stela_linux_count slots[STELA_LINUX_COUNT_SLOTS];
	unsigned long other;
};

/* What ran in the environment, for the host's heartbeat, which reads and
 * clears the counts. Updated with atomics only; nothing here reads them. */
struct stela_linux_counts {
	/* Timer-list and high-resolution timer callbacks, by function. */
	struct stela_linux_count_kind timers;
	/* Work items, by function. */
	struct stela_linux_count_kind works;
	/* Tasks a timeout woke, by the work item or thread function the task
	 * was running (zero for neither). */
	struct stela_linux_count_kind sleepers;
	/* Tasks a timeout woke. */
	unsigned long timeouts;
};

extern struct stela_linux_counts stela_linux_counts;

void stela_linux_count(struct stela_linux_count_kind *kind, unsigned long function);
/* Count a timeout's wake of `task`; `woke` is wake_up_process's result. */
void stela_linux_count_timeout(struct task_struct *task, bool woke);
/* Count the work item current's worker is running, if it is a worker. */
void stela_linux_count_work(void);

#endif
