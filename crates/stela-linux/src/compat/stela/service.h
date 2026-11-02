/* SPDX-License-Identifier: MIT */
#ifndef STELA_SERVICE_H
#define STELA_SERVICE_H
#include <linux/types.h>
#include <stela/timer.h>

/* Bring jiffies up to the clock and run the expired timers, on the owner's
 * service task in an entered owner. Returns the clock reading at which to run
 * again, or S64_MAX when nothing is armed. */
s64 stela_linux_service_run(const struct stela_linux_timer_delivery *delivery);

struct stela_linux_owner;

struct stela_linux_service_call {
	const struct stela_linux_owner *owner;
	void *context;
	/* Begin the next due batch; false when none is due. */
	bool (*begin)(void *context);
	/* The next line raised since the batch began, or a negative value. */
	int (*next_irq)(void *context);
	/* Complete the exact original primary service body after it returned. */
	void (*complete_irq)(void *context);
	/* Nonblocking process leaves, on this real service task in the owner. */
	void (*drain)(void *context);
	/* Rust takes the SAME owned Domain batch, creates its real scoped
	 * TimerDelivery, invokes service_run, then consumes Domain.finish. */
	void (*finish)(void *context);
	bool (*done)(void *context);
};

_Static_assert(sizeof(struct stela_linux_service_call) == 64, "Linux service call ABI");

/* The body of a service task, entered in call's owner until call is done. */
void stela_linux_service_loop(const struct stela_linux_service_call *call);

#endif
