/* SPDX-License-Identifier: MIT */
#ifndef STELA_RCU_H
#define STELA_RCU_H
#include <linux/types.h>

struct rcu_head;

/* Selected TinyRCU source boundaries. No callback queue, GP counter, timer,
 * task/current constructor or native IRQ authorization lives in this adapter.
 * Sleeping RCU APIs require a retained source process, entered canonical owner
 * and no read-side/atomic nesting. Callback begin/end are paired only by the
 * original reclaim loop inside the original softirq dispatch guard. */
void stela_linux_rcu_require_process(void);
void stela_linux_rcu_callback_begin(const struct rcu_head *head);
void stela_linux_rcu_callback_end(const struct rcu_head *head);
#endif
