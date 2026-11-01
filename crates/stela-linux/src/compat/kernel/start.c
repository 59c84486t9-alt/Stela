// SPDX-License-Identifier: MIT
/* What Linux's start_kernel does that its drivers rely on: the caches behind
 * its radix and maple trees, then the initcalls, by level. Linux logs a failed
 * initcall and carries on, but a driver over a failed subsystem cannot run, so
 * Stela stops at the first failed stage and reports it. */
#include <linux/maple_tree.h>
#include <linux/radix-tree.h>
#include <stela/registry.h>

int stela_linux_start(const struct stela_linux_registry_image *image,
		      struct stela_linux_registry **result)
{
	radix_tree_init();
	maple_tree_init();
	int error = stela_linux_registry_begin(image, NULL, 0, result);

	if (!error)
		error = stela_linux_registry_early_parameters(*result, NULL);
	if (!error)
		error = stela_linux_registry_initial_parameters(*result, NULL, NULL);
	for (unsigned int stage = 0; !error && stage < STELA_LINUX_STAGE_DONE; stage++)
		error = stela_linux_registry_run_stage(*result, stage, NULL);
	return error;
}
