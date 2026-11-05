/* SPDX-License-Identifier: MIT */
#ifndef STELA_MANAGED_KTHREAD_H
#define STELA_MANAGED_KTHREAD_H
#include <linux/types.h>
struct stela_linux_owner;
struct stela_linux_managed_lease;
/* Actual C-owned lease born only in PID1 managed_create, never a task pointer
 * adoption. Existing-ref get/put are bounded, allocation/wait/current-free.
 * Caller already owns a real live lease reference; root equality is only a
 * negative consistency check. Producer put cannot free Rust's initial owner. */
bool stela_linux_managed_lease_get(struct stela_linux_managed_lease *,
    const struct stela_linux_owner *);
void stela_linux_managed_lease_put(struct stela_linux_managed_lease *,
    const struct stela_linux_owner *);
void stela_linux_managed_native_retired(struct stela_linux_managed_lease *,
    const struct stela_linux_owner *);
void *stela_linux_managed_lease_context(struct stela_linux_managed_lease *,
    const struct stela_linux_owner *);
/* Source events describe actual private constructor branches. None alone
 * constructs native no-publication, callback completion or a source join. */
enum stela_linux_managed_event {
    STELA_MANAGED_WAIT_INTERRUPTED = 1,
    STELA_MANAGED_CREATE_FAILED,
    STELA_MANAGED_CHILD_ABANDONED,
    STELA_MANAGED_CALLBACK_SKIPPED,
    STELA_MANAGED_CALLER_RETURNED,
    STELA_MANAGED_NATIVE_RETIRED,
    STELA_MANAGED_PRODUCERS_JOINED,
};
void stela_linux_managed_source_event(void *context,
    struct stela_linux_managed_lease *, const struct stela_linux_owner *,
    unsigned int event, int result);
/* Actual PID1 source process ONLY. Returns a retained lease even when the
 * original creation wait reports EINTR; caller must not infer NoChild from
 * result. Context/code/job is retained BEFORE this may queue or block.
 * A negative return with *lease==NULL means constructor had no C allocation;
 * no original create_info was allocated/queued by that precise branch. */
int stela_linux_managed_create(const struct stela_linux_owner *, void *context,
    int (*threadfn)(void *), struct stela_linux_managed_lease **lease);
/* Actual C producer closure plus initial-owner uniqueness is checked here,
 * never inferred from errno/refcount alone. Called only by actual PID1 after
 * native child metadata/stack closure when any birth was associated. */
int stela_linux_managed_lease_release(struct stela_linux_managed_lease *,
    const struct stela_linux_owner *);
#endif
