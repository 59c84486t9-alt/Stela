/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_MODULE_H
#define STELA_XE_MODULE_H
#include <linux/types.h>
/* Copyright © 2023 Intel Corporation; from xe_module.h. Stela has no module
 * parameters, so every one keeps its zero default. */
struct xe_modparam {
	bool force_execlist;
	bool probe_display;
	int force_vram_bar_size;
	int guc_log_level;
	char *guc_firmware_path;
	char *huc_firmware_path;
	char *gsc_firmware_path;
	char *force_probe;
	unsigned int wedged_mode;
	u32 svm_notifier_size;
};
static const struct xe_modparam xe_modparam = {0};
#endif
