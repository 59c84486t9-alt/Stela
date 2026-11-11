// SPDX-License-Identifier: GPL-2.0-or-later
/* Driver initcalls run after the original Initial resource bootstrap.
 * Stop at the first failed stage and preserve its error. */
#include <stela/registry.h>

int stela_linux_start(const struct stela_linux_registry_image *image,
		      struct stela_linux_registry **result)
{
	int error = stela_linux_registry_begin(image, NULL, 0, result);

	if (!error)
		error = stela_linux_registry_early_parameters(*result, NULL);
	if (!error)
		error = stela_linux_registry_initial_parameters(*result, NULL, NULL);
	for (unsigned int stage = 0; !error && stage < STELA_LINUX_STAGE_DONE; stage++)
		error = stela_linux_registry_run_stage(*result, stage, NULL);
	return error;
}
