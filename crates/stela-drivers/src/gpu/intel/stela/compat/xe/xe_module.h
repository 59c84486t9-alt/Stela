/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_MODULE_H
#define STELA_XE_MODULE_H
/* Stela has no module parameters: every firmware path is the default. */
struct xe_modparam {
	char *guc_firmware_path;
	char *huc_firmware_path;
	char *gsc_firmware_path;
};
static const struct xe_modparam xe_modparam = {0};
#endif
