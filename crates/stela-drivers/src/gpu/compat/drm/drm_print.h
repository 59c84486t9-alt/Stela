/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_PRINT_H
#define STELA_DRM_PRINT_H
#include <linux/bug.h>
#include <linux/compiler.h>
struct drm_device;
/* Stela formats through no printer object; the type only names one. */
struct drm_printer {
};
enum stela_drm_level {
	STELA_DRM_ERR, STELA_DRM_WARN, STELA_DRM_NOTICE, STELA_DRM_INFO, STELA_DRM_DBG
};
/* Each translation unit that logs defines this report, which must return. */
static void stela_drm_printk(const struct drm_device *, enum stela_drm_level,
			     const char *format, ...) __attribute__((format(printf, 3, 4)));
static void drm_printf(struct drm_printer *p, const char *f, ...)
	__attribute__((format(printf, 2, 3)));
#define drm_err(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_ERR, format, ##__VA_ARGS__)
#define drm_warn(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_WARN, format, ##__VA_ARGS__)
#define drm_notice(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_NOTICE, format, ##__VA_ARGS__)
#define drm_info(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_INFO, format, ##__VA_ARGS__)
#define drm_err_once(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_ERR, format, ##__VA_ARGS__)
#define drm_dbg(drm, format, ...) \
	stela_drm_printk(drm, STELA_DRM_DBG, format, ##__VA_ARGS__)
#define drm_WARN_ON(drm, condition) WARN_ON(condition)
/* Linux's legacy messages name no device. */
#define DRM_ERROR(format, ...) \
	stela_drm_printk(NULL, STELA_DRM_ERR, format, ##__VA_ARGS__)
#define DRM_DEBUG(format, ...) \
	stela_drm_printk(NULL, STELA_DRM_DBG, format, ##__VA_ARGS__)
#endif
