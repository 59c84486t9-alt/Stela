// SPDX-License-Identifier: MIT
/* Dynamic per-CPU storage for Stela's single qualified Linux CPU. Static
 * per-CPU objects already use the same identity mapping in asm/percpu.h.
 * Each allocation owns a separately aligned, zeroed canonical heap window.
 * There is no reserved first chunk: Linux's reserved request consequently
 * follows its documented fallback to ordinary dynamic storage. */
#include <linux/limits.h>
#include <linux/log2.h>
#include <linux/minmax.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <stela/linux.h>
#include <linux/sched/mm.h>
#include <linux/string.h>

static_assert(!IS_ENABLED(CONFIG_SMP));
static_assert(!IS_ENABLED(CONFIG_NUMA));
static_assert(!IS_ENABLED(CONFIG_MODULES));
static_assert(!IS_ENABLED(CONFIG_MEMCG));
static_assert(CONFIG_NR_CPUS == 1);

struct percpu_header { size_t size, align; };

void __percpu *pcpu_alloc_noprof(size_t size, size_t align, bool reserved, gfp_t gfp)
{
	gfp = current_gfp_context(gfp);
	/* No dedicated reserved chunk is installed in this !SMP profile. */
	(void)reserved;
	align = max_t(size_t, align, PCPU_MIN_ALLOC_SIZE);
	size = ALIGN(size, PCPU_MIN_ALLOC_SIZE);
	if (!size || size > PCPU_MIN_UNIT_SIZE || align > PAGE_SIZE ||
	    !is_power_of_2(align)) {
		WARN(!(gfp & __GFP_NOWARN), "illegal size (%zu) or align (%zu) for percpu allocation\n",
		     size, align);
		return NULL;
	}
	/* Direct canonical metadata allocation breaks the actual Linux bootstrap
	 * cycle: original SLUB itself needs per-CPU storage before kmalloc is up.
	 * This is the SAME global heap/free identity; no private allocator or
	 * alternate arena stands in for original Linux slabs/pages. */
	align = max_t(size_t, align, sizeof(struct percpu_header));
	gfp_t backing = gfp & (GFP_KERNEL | __GFP_NORETRY | __GFP_NOWARN);
	bool blocking = gfpflags_allow_blocking(backing);
	if (blocking && !stela_linux_quiescent()) {
		stela_linux_unsupported("percpu blocking allocation context");
		return NULL;
	}
	if (!blocking && !stela_linux_heap_try_available()) {
		stela_linux_unsupported("percpu nonblocking canonical heap unavailable");
		return NULL;
	}
	/* Bounds above make this sum small; both size and prefix are aligned.
	 * Canonical allocation returns the complete zeroed owned layout. */
	u8 *base = blocking ? stela_linux_heap_alloc(size + align, align) :
		stela_linux_heap_try_alloc(size + align, align);
	if (!base)
		return NULL;
	struct percpu_header *header = (struct percpu_header *)(base + align) - 1;
	*header = (struct percpu_header){.size = size + align, .align = align};
	return (void __percpu *)(base + align);
}

void free_percpu(void __percpu *object)
{
	if (!object)
		return;
	const struct percpu_header *header = (const struct percpu_header *)object - 1;
	stela_linux_heap_free((u8 *)object - header->align, header->size, header->align);
}

#ifdef STELA_LINUX_PERCPU_TEST
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <stela/linux.h>
#include <stela/test.h>

static unsigned int context_refusals;
static void context_unsupported(void *context, const char *operation)
{
	(void)context;
	assert(!strcmp(operation, "percpu blocking allocation context"));
	context_refusals++;
}
static const struct stela_linux_services percpu_services = {.unsupported = context_unsupported};
static const struct stela_linux_owner percpu_owner = {.services = &percpu_services};

void stela_linux_percpu_fixture(void *context);
void stela_linux_percpu_taskless_fixture(void);

void stela_linux_percpu_fixture(void *context)
{
	(void)context;
	stela_linux_enter(&percpu_owner);
	for (size_t align = 1; align <= PAGE_SIZE; align *= 2) {
		for (size_t bytes = 1; bytes <= PCPU_MIN_UNIT_SIZE; bytes = bytes * 2 + 1) {
			u8 __percpu *a = pcpu_alloc_noprof(bytes, align, false, GFP_KERNEL);
			u8 __percpu *b = pcpu_alloc_noprof(bytes, align, true, GFP_KERNEL);
			assert(a && b && a != b);
			assert(!((unsigned long)a & (align - 1U)));
			assert(!((unsigned long)b & (align - 1U)));
			assert(per_cpu_ptr(a, 0) == a && this_cpu_ptr(a) == a);
			for (size_t i = 0; i < bytes; i++)
				assert(!a[i] && !b[i]);
			memset(a, 0x5a, bytes);
			memset(b, 0xa5, bytes);
			for (size_t i = 0; i < bytes; i++)
				assert(a[i] == 0x5a && b[i] == 0xa5);
			free_percpu(a);
			free_percpu(b);
		}
	}
	assert(!pcpu_alloc_noprof(0, 1, false, GFP_KERNEL | __GFP_NOWARN));
	assert(!pcpu_alloc_noprof(SIZE_MAX, 1, false, GFP_KERNEL | __GFP_NOWARN));
	assert(!pcpu_alloc_noprof(PCPU_MIN_UNIT_SIZE + 1, 1, false, GFP_KERNEL | __GFP_NOWARN));
	assert(!pcpu_alloc_noprof(1, PAGE_SIZE * 2, false, GFP_KERNEL | __GFP_NOWARN));
	assert(!pcpu_alloc_noprof(1, 12, false, GFP_KERNEL | __GFP_NOWARN));
	free_percpu(NULL);
	/* All eight real original task memalloc contexts retain ordinary
	 * DIRECT_RECLAIM eligibility at this pin. The original context helper
	 * projects IO/FS/MOVABLE before backing allocation. No task is invented. */
	unsigned int flags = current->flags;
	for (unsigned int combination = 0; combination < 8; combination++) {
		current->flags = flags |
			((combination & 1U) ? PF_MEMALLOC_NOIO : 0U) |
			((combination & 2U) ? PF_MEMALLOC_NOFS : 0U) |
			((combination & 4U) ? PF_MEMALLOC_PIN : 0U);
		stela_test_allocations_begin(false);
		u8 *p = pcpu_alloc_noprof(47, 32, false, GFP_KERNEL | __GFP_MOVABLE);
		struct stela_test_allocations attempts = stela_test_allocations_end();
		assert(p && attempts.heap == 1 && !attempts.heap_try && !attempts.pages);
		assert(!((unsigned long)p & 31UL));
		for (size_t i = 0; i < 47; i++)
			assert(!p[i]);
		free_percpu(p);
	}
	current->flags = flags;
	/* Unsupported blocking contexts refuse before either allocator route. */
	for (unsigned int critical = 0; critical < 3; critical++) {
		unsigned long irq = 0;
		if (critical == 0)
			preempt_disable();
		else if (critical == 1)
			rcu_read_lock();
		else
			local_irq_save(irq);
		unsigned int before = context_refusals;
		stela_test_allocations_begin(false);
		assert(!pcpu_alloc_noprof(47, 32, false, GFP_KERNEL));
		struct stela_test_allocations attempts = stela_test_allocations_end();
		assert(context_refusals == before + 1);
		assert(!attempts.heap && !attempts.heap_try && !attempts.pages);
		if (critical == 0)
			preempt_enable();
		else if (critical == 1)
			rcu_read_unlock();
		else
			local_irq_restore(irq);
	}
	/* Genuine canonical allocation failure is fallible and creates no
	 * hidden pointer/public object. Neither reserved nor ordinary path leaks. */
	for (unsigned int reserved = 0; reserved < 2; reserved++) {
		stela_test_allocations_begin(true);
		assert(!pcpu_alloc_noprof(47, 32, reserved != 0, GFP_KERNEL));
		struct stela_test_allocations attempts = stela_test_allocations_end();
		assert(attempts.heap == 1 && !attempts.heap_try && !attempts.pages);
	}
	/* Real canonical nonblocking route: a one-attempt allocator refusal is
	 * ordinary exhaustion and cannot fall back to blocking/slab allocation. */
	stela_test_heap_try_enable(true);
	stela_test_allocations_begin(false);
	u8 *atomic = pcpu_alloc_noprof(47, 32, false, GFP_ATOMIC);
	struct stela_test_allocations attempts = stela_test_allocations_end();
	assert(atomic && !attempts.heap && attempts.heap_try == 1 && !attempts.pages);
	assert(stela_test_heap_try_contains(atomic));
	for (size_t i = 0; i < 47; i++)
		assert(!atomic[i]);
	free_percpu(atomic);
	stela_test_heap_try_enable(false);
	stela_test_allocations_begin(false);
	assert(!pcpu_alloc_noprof(47, 32, false, GFP_NOWAIT));
	attempts = stela_test_allocations_end();
	assert(!attempts.heap && attempts.heap_try == 1 && !attempts.pages);
	stela_linux_exit();
}

static void taskless_allocation(void)
{
	stela_linux_enter(&stela_linux_bare);
	(void)pcpu_alloc_noprof(47, 32, false, GFP_KERNEL);
	stela_linux_exit();
}

void stela_linux_percpu_taskless_fixture(void)
{
	assert(stela_test_traps(taskless_allocation));
}
#endif
