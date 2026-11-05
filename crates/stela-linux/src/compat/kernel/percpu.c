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
