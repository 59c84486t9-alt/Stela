/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_PRINTK_H
#define STELA_XE_PRINTK_H
#include <drm/drm_print.h>
#include "xe_device_types.h"
/* Device reports carry the upstream message; the adapter that owns the
 * device already names it. */
#define xe_err(xe, format, ...) drm_err(&(xe)->drm, format, ##__VA_ARGS__)
#define xe_warn(xe, format, ...) drm_warn(&(xe)->drm, format, ##__VA_ARGS__)
#define xe_notice(xe, format, ...) drm_notice(&(xe)->drm, format, ##__VA_ARGS__)
#define xe_info(xe, format, ...) drm_info(&(xe)->drm, format, ##__VA_ARGS__)
#define xe_dbg(xe, format, ...) drm_dbg(&(xe)->drm, format, ##__VA_ARGS__)
#endif
