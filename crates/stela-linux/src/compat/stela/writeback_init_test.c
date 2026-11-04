// SPDX-License-Identifier: MIT
#include <linux/backing-dev.h>
#include <linux/cpu.h>
#include <linux/init_task.h>
#include <linux/vmstat.h>
#include <linux/writeback.h>
#include <stela/linux.h>
#include <stela/page_test.h>
#include <stela/test.h>

static size_t free_frames;

struct task_struct *__wrap_stela_linux_current(void)
{
	return &init_task;
}

static int available_frames(void *context, size_t start, size_t pages, size_t *available)
{
	(void)context;
	assert(start == (size_t)stela_test_memory && pages == STELA_TEST_PAGES);
	assert(free_frames <= pages);
	*available = free_frames;
	return 0;
}

static void check_limits(unsigned long expected_background, unsigned long expected_dirty)
{
	unsigned long background, dirty;

	global_dirty_limits(&background, &dirty);
	assert(background == expected_background && dirty == expected_dirty);
}

int main(void)
{
	static const struct stela_linux_services services = {
		.available_page_frames = available_frames,
	};
	static const struct stela_linux_owner owner = {.services = &services};

	stela_linux_enter(&owner);
	stela_test_register_pages();
	boot_cpu_init();
	assert(!fprop_global_init(&global_wb_domain.completions, GFP_KERNEL));
	check_limits(0, 0);

	free_frames = STELA_TEST_PAGES;
	mod_node_page_state(NODE_DATA(0), NR_ACTIVE_FILE, 4095 - STELA_TEST_PAGES);
	check_limits(409, 819);
	writeback_set_ratelimit();
	assert(global_wb_domain.dirty_limit == 819);

	int priority = init_task.prio;
	init_task.prio = 0;
	global_wb_domain.dirty_limit = 320;
	check_limits(521, 1033);
	init_task.prio = priority;

	static struct backing_dev_info bdi = {.capabilities = BDI_CAP_WRITEBACK};
	bdi.wb.bdi = &bdi;
	struct super_block super = {.s_bdi = &bdi};
	struct inode inode = {.i_sb = &super};
	struct address_space mapping = {.host = &inode};
	init_task.nr_dirtied = init_task.nr_dirtied_pause = 1;
	assert(!balance_dirty_pages_ratelimited_flags(&mapping, BDP_ASYNC));
	assert(!init_task.nr_dirtied && init_task.nr_dirtied_pause > 1);

	bdi.capabilities = 0;
	init_task.nr_dirtied = 1;
	assert(!balance_dirty_pages_ratelimited_flags(&mapping, BDP_ASYNC));
	assert(init_task.nr_dirtied == 1);
	init_task.nr_dirtied = 0;

	/* Exercise the cap without allocating a correspondingly large catalog. */
	atomic_long_add((1L << 40) - 4096, &vm_node_stat[NR_ACTIVE_FILE]);
	check_limits(UINT_MAX / 2, UINT_MAX);
	atomic_long_sub((1L << 40) - 4096, &vm_node_stat[NR_ACTIVE_FILE]);
	mod_node_page_state(NODE_DATA(0), NR_ACTIVE_FILE, -(4095 - STELA_TEST_PAGES));

	stela_linux_exit();
	return 0;
}
