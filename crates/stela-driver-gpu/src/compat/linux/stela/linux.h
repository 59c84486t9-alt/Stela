/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_H
#define STELA_LINUX_H
/* Stela's kernel-API binding. Linux code runs only between stela_linux_enter
 * and stela_linux_exit, for one owner at a time: entering waits until no other
 * owner runs Linux code, and Linux code never enters again. That is the
 * uniprocessor, non-preemptible execution generated/autoconf.h configures.
 * Both boundaries require balanced preemption/BH/read-side state and enabled
 * simulated IRQs. Callbacks and critical sections cannot escape the borrowed
 * owner; exit invokes pending RCU callbacks before returning that owner.
 *
 * The owner supplies the services that depend on its device and platform.
 * Linux names no device for most of them (msleep, ktime_get, printk), so they
 * belong to whoever runs the code; device-scoped services, such as register
 * access, are bound by the adapter that owns the device. A NULL log or warn
 * discards those reports and a NULL firmware has no images; a service reached
 * without its callback, or outside enter and exit, traps. */
#include <linux/compiler_attributes.h>
#include <linux/types.h>

struct stela_linux_services {
	/* Monotonic nanoseconds. */
	s64 (*now_ns)(void *context);
	/* Wait at least minimum and preferably at most maximum microseconds;
	 * atomic waits must not sleep. */
	void (*delay_us)(void *context, u64 minimum, u64 maximum, bool atomic);
	/* A firmware image by Linux's name, valid until the owner exits, or a
	 * negative errno. Success returns a readable stable source window; the
	 * common request adapter copies it before publishing owned firmware.
	 * Return within the same entered owner and quiescent context. No pointer
	 * to this context or source is retained in the resulting firmware. */
	int (*firmware)(void *context, const char *name, const u8 **data, size_t *size);
	/* One formatted kernel message at its printk level (LOGLEVEL_*). */
	void (*log)(void *context, int level, const char *message);
	/* A WARN that fired, with its condition text when Linux records one. */
	void (*warn)(void *context, const char *file, int line, const char *condition);
	/* An operation Stela does not provide yet; the caller then continues
	 * with that service's documented degraded result. An owner without this
	 * service traps instead. Called for every occurrence. */
	void (*unsupported)(void *context, const char *operation);
	/* Infallible bytes from an already seeded, retained CSPRNG. Kernel
	 * registration must obtain that real capability before admitting callers;
	 * a non-NULL callback alone is not seed/readiness evidence. It neither
	 * allocates, waits, switches owner/task nor changes the incoming atomic/IRQ
	 * state. The caller retains actual IRQ-safe non-migrating serialization;
	 * this table is not a native execution/interrupt grant. */
	void (*random_bytes)(void *context, void *bytes, size_t size);
	/* Start a Linux task that runs stela_linux_workers_run in this owner,
	 * or return a negative errno when none can start now. The request must
	 * not run the worker inline. */
	int (*start_worker)(void *context);
	/* Power the machine off, without waiting for clean exits if force. */
	void (*shutdown)(void *context, bool force);
	/* Map page-aligned device memory uncached, or return NULL; unmapped by
	 * the address map_device returned. */
	void *(*map_device)(void *context, u64 physical, size_t size);
	void (*unmap_device)(void *context, void *address);
	/* Map count write-back pages contiguously, or return NULL. */
	void *(*map_pages)(void *context, const u64 *physical, size_t count);
	void (*unmap_pages)(void *context, void *address, size_t count);
	/* Route a line to the owner's service, which calls stela_linux_irq_run
	 * when it fires, or return a negative errno; disabling masks it and
	 * returns only once no new firing can reach the service. */
	int (*irq_enable)(void *context, unsigned int irq);
	void (*irq_disable)(void *context, unsigned int irq);
};

struct stela_linux_owner {
	const struct stela_linux_services *services;
	void *context;
};

/* Private x86-64 C ABI. All producers and consumers rebuild from this header;
 * Rust currently passes owners opaquely rather than mirroring this table. */
_Static_assert(sizeof(struct stela_linux_services) == 120, "Linux services ABI");
_Static_assert(__builtin_offsetof(struct stela_linux_services, random_bytes) == 48,
	       "Linux random callback ABI");
_Static_assert(sizeof(struct stela_linux_owner) == 16, "Linux owner ABI");

/* An owner for Linux code that needs none of these services. */
extern const struct stela_linux_owner stela_linux_bare;

void stela_linux_enter(const struct stela_linux_owner *owner);
/* One acquisition attempt; false leaves an already-running owner untouched.
 * This is also safe when a platform callback tries to retire another owner. */
bool stela_linux_try_enter(const struct stela_linux_owner *owner);
void stela_linux_exit(void);
/* Checked quiescence in the serialized context, not a native IRQ witness. */
bool stela_linux_quiescent(void);
/* Internal RCU retirement while the execution owner is still borrowed. */
/* Entered serialized-owner observation only. Private RCU delivery remains
 * active despite balanced public preempt/IRQ counters. No task/root grant. */
bool stela_linux_rcu_callback_active(void);
void stela_linux_rcu_finish(void);
/* The owner running Linux code; traps outside enter and exit. */
const struct stela_linux_owner *stela_linux_owner(void);
/* Report an operation Stela does not provide yet to the running owner. */
void stela_linux_unsupported(const char *operation);
/* Emit an emergency report through the entered owner, then unconditionally
 * trap without returning; this does not implement Linux panic machinery. */
__noreturn void stela_linux_fatal(const char *message);

/* Platform memory behind Linux's allocators: Stela's global heap in its
 * images, libc in hosted test programs. Zeroed and aligned to align, a power
 * of two accepted by the platform layout, or NULL when exhausted; freed with the
 * same size and alignment. */
void *stela_linux_heap_alloc(size_t size, size_t align);
void stela_linux_heap_free(void *object, size_t size, size_t align);
/* Permanent access to the SAME canonical heap/free identity, without waiting,
 * reclaim, growth or fallback. Query first; absent/in-progress capability is
 * unsupported, while an installed allocator's NULL is ordinary exhaustion or
 * contention. Nonzero valid layouts require the actual retained owner/context.
 * Registration supplies no native ISR entry, page/PFN or DMA authority. */
bool stela_linux_heap_try_available(void);
void *stela_linux_heap_try_alloc(size_t size, size_t align);
/* Actual retained native image DATA only; no pointer read or heap/free grant.
 * Requires permanent Rust image registration before the dependent lifecycle is
 * admitted. Missing/in-progress registration traps instead of returning false.
 * The registration is independent of per-call Linux execution owners. The
 * admission owner must cover every complete borrowed constant name (including
 * NUL), with stable true classification through release. A negative free query
 * requires separate heap ownership (except canonical NULL/zero-size no-op
 * values); negative duplication may copy a valid
 * mutable/stack string. A negative result never proves an unknown pointer is
 * heap. */
bool stela_linux_is_rodata(const void *address);
#endif
