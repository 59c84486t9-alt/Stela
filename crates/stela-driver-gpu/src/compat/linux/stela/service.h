/* SPDX-License-Identifier: MIT */
#ifndef STELA_SERVICE_H
#define STELA_SERVICE_H
#include <linux/types.h>

/* Bring jiffies up to the clock and run the expired timers, on the owner's
 * service task in an entered owner. Returns the clock reading at which to run
 * again, or S64_MAX when nothing is armed. */
s64 stela_linux_service_run(void);

struct stela_linux_owner;

struct stela_linux_service_call {
	const struct stela_linux_owner *owner;
	void *context;
	/* Begin the next due batch; false when none is due. */
	bool (*begin)(void *context);
	/* The next line raised since the batch began, or a negative value. */
	int (*next_irq)(void *context);
	/* Finish it, with the clock reading to run again at (as above). */
	void (*finish)(void *context, s64 deadline);
	bool (*done)(void *context);
};

/* The body of a service task, entered in call's owner until call is done. */
void stela_linux_service_loop(const struct stela_linux_service_call *call);

/* Sleep on the service task's timers, for an owner's delay_us service to run a
 * delay that may sleep: the delay's caller is a Linux task in an entered owner,
 * and other tasks and the service run meanwhile. */
void stela_linux_sleep_us(u64 minimum);

/* The body of a task its owner's start_worker service started. */
void stela_linux_worker_main(void *owner);
#endif
