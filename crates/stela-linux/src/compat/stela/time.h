/* SPDX-License-Identifier: MIT */
#ifndef STELA_TIME_H
#define STELA_TIME_H
#include <linux/types.h>
struct stela_linux_owner;
struct task_struct;
/* Read actual same-owner boottime. Refusal leaves the output unchanged. */
int stela_linux_boottime_ns(s64 *now);
/* Produced only by the actual minimum factory, with owned source/root/code.
 * Operations validate same original current/owner. All failures are terminal;
 * no operation returns a successful physical grant after source failure. */
struct stela_linux_minimum_deadline {
    bool (*ready)(struct stela_linux_minimum_deadline *deadline);
    s64 (*wake_ns)(struct stela_linux_minimum_deadline *deadline);
    u64 (*remaining_quanta_ceil)(struct stela_linux_minimum_deadline *deadline, u64 quantum_us);
    void (*release)(struct stela_linux_minimum_deadline *deadline);
};
_Static_assert(sizeof(struct stela_linux_minimum_deadline) == 32, "minimum deadline ABI");
/* Actual source provenance guard, not pointer identity as authority. */
struct task_struct *stela_linux_minimum_task(const struct stela_linux_owner *owner);
/* One original relative minimum; early=true preserves schedule_timeout's
 * explicit wake semantics. Return0 only after actual ready; otherwise a
 * checked positive conservative count in the original counter domain. */
enum stela_linux_minimum_wake {
    STELA_MINIMUM_STRICT,
    STELA_MINIMUM_EARLY,
    STELA_MINIMUM_SIGNAL,
};
u64 stela_linux_minimum_sleep(u64 minimum_us, unsigned int state,
                             enum stela_linux_minimum_wake wake, u64 quantum_us);
#endif
