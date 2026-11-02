/* SPDX-License-Identifier: MIT */
#ifndef STELA_TIMER_H
#define STELA_TIMER_H
#include <linux/types.h>
struct stela_linux_owner;
/* Borrowed ONLY from the same real owned Domain::Batch in Rust service finish.
 * No C constructor, NULL/Bare fallback, native IRQ/clock or device permission. */
struct stela_linux_timer_delivery;
int stela_linux_timer_delivery_check(const struct stela_linux_timer_delivery *delivery,
                                    const struct stela_linux_owner *owner);
void stela_linux_timer_queue_current(void);
void stela_linux_timers_changed(void);
void stela_linux_timer_delivery_require(const struct stela_linux_timer_delivery *delivery);
/* Nominal labels only: timer_list expiry is jiffies; highres expiry remains
 * exact nanoseconds. Neither query attests physical minimum readiness. */
bool stela_linux_timers_next(unsigned long *expires);
bool stela_linux_hrtimers_next_ns(s64 *expires);
/* Actual canonical service/current/owned batch, balanced process entry. The
 * qualified private hard/soft callback producer supplies original C IRQ state.
 * No borrowed delivery may survive scheduling/reentry or Domain.finish. */
void stela_linux_timers_run(const struct stela_linux_timer_delivery *delivery);
void stela_linux_hrtimers_run_hard(const struct stela_linux_timer_delivery *delivery);
void stela_linux_hrtimers_run_soft(const struct stela_linux_timer_delivery *delivery);
#endif
