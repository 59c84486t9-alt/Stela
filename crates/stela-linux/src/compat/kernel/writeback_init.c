// SPDX-License-Identifier: GPL-2.0-only
/* Global writeback startup from Linux mm/page-writeback.c.
 * Copyright (C) 2002, Linus Torvalds.
 * Copyright (C) 2007 Red Hat, Inc., Peter Zijlstra.
 */
#include <linux/build_bug.h>
#include <linux/cpuhotplug.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched/rt.h>
#include <linux/vmstat.h>
#include <linux/writeback.h>
#include <trace/events/writeback.h>
#include <stela/linux.h>
#include <stela/page.h>

static_assert(!IS_ENABLED(CONFIG_HIGHMEM));
static_assert(!IS_ENABLED(CONFIG_CGROUP_WRITEBACK));
static_assert(!IS_ENABLED(CONFIG_SYSCTL));

static long ratelimit_pages = 32;

static void dirty_limits(unsigned long available, bool boosted, unsigned long prior_limit,
			 unsigned long *background, unsigned long *dirty)
{
	/* Preserve Linux's per-PAGE_SIZE rounding of its default VM ratios. */
	unsigned long bg = ((10 * PAGE_SIZE / 100) * available) / PAGE_SIZE;
	unsigned long limit = ((20 * PAGE_SIZE / 100) * available) / PAGE_SIZE;

	if (boosted) {
		bg += bg / 4 + prior_limit / 32;
		limit += limit / 4 + prior_limit / 32;
	}
	limit = min(limit, (unsigned long)UINT_MAX);
	if (bg >= limit)
		bg = limit / 2;
	*background = bg;
	*dirty = limit;
}

void global_dirty_limits(unsigned long *background, unsigned long *dirty)
{
	unsigned long available;
	if (stela_linux_available_page_frames(&available))
		stela_linux_fatal("writeback free-frame snapshot unavailable");

	/* The native allocator reports available payload frames directly.
	 * There are no Linux buddy watermarks or highmem zones to subtract. */
	available += global_node_page_state(NR_INACTIVE_FILE);
	available += global_node_page_state(NR_ACTIVE_FILE);
	dirty_limits(available + 1, rt_or_dl_task(current), global_wb_domain.dirty_limit,
		     background, dirty);
	trace_global_dirty_state(*background, *dirty);
}

void writeback_set_ratelimit(void)
{
	unsigned long background, dirty;
	global_dirty_limits(&background, &dirty);
	global_wb_domain.dirty_limit = dirty;
	WRITE_ONCE(ratelimit_pages, max_t(long, dirty / (num_online_cpus() * 32), 16));
}

static int page_writeback_cpu_online(unsigned int cpu)
{
	(void)cpu;
	writeback_set_ratelimit();
	return 0;
}

void __init page_writeback_init(void)
{
	if (wb_domain_init(&global_wb_domain, GFP_KERNEL))
		stela_linux_fatal("writeback domain initialization failed");

	if (cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/writeback:online",
			     page_writeback_cpu_online, NULL) < 0 ||
	    cpuhp_setup_state(CPUHP_MM_WRITEBACK_DEAD, "mm/writeback:dead",
			     NULL, page_writeback_cpu_online) < 0)
		stela_linux_fatal("writeback CPU state registration failed");
}

#ifdef STELA_LINUX_WRITEBACK_INIT_TEST
#include <stela/test.h>

int main(void)
{
	unsigned long background, dirty;
	dirty_limits(4096, false, 0, &background, &dirty);
	assert(background == 409 && dirty == 819);
	dirty_limits(4096, true, 320, &background, &dirty);
	assert(background == 521 && dirty == 1033);
	dirty_limits(1, false, 0, &background, &dirty);
	assert(!background && !dirty);
	dirty_limits(1UL << 40, false, 0, &background, &dirty);
	assert(dirty == UINT_MAX && background == UINT_MAX / 2);
	return 0;
}
#endif
