/* SPDX-License-Identifier: MIT */
#ifndef STELA_TIMER_H
#define STELA_TIMER_H
#include <linux/types.h>

/* The owner's service delivers Linux's timers. Both run in an entered owner;
 * stela_linux_timers_run also needs balanced process context on the service's
 * task. */

/* The earliest pending expiry in jiffies, or false when no timer is armed:
 * the service's next timer deadline. */
bool stela_linux_timers_next(unsigned long *expires);

/* Run every timer whose expiry jiffies has reached, earliest first. */
void stela_linux_timers_run(void);

/* The same for high-resolution timers, which those two also serve. */
bool stela_linux_hrtimers_next(unsigned long *expires);
void stela_linux_hrtimers_run(void);
#endif
