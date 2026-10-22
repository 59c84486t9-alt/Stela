/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_PRINT_H
#define STELA_DRM_PRINT_H
#include <linux/compiler.h>
struct drm_device;
enum stela_drm_level { STELA_DRM_ERR, STELA_DRM_NOTICE, STELA_DRM_DBG };
/* Each translation unit that logs defines this report, which must return. */
static void stela_drm_printk(const struct drm_device *, enum stela_drm_level,
			     const char *format, ...) __attribute__((format(printf, 3, 4)));
#define drm_err(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_ERR, format, ##__VA_ARGS__)
#define drm_notice(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_NOTICE, format, ##__VA_ARGS__)
#define drm_dbg(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_DBG, format, ##__VA_ARGS__)
#endif
