/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_FOURCC_H
#define STELA_DRM_FOURCC_H
#include <linux/types.h>
#include <uapi/drm/drm_fourcc.h>
/* A pixel format description, which a source that looks one up declares. */
struct drm_format_info;
static const struct drm_format_info *drm_format_info(u32 format);
#endif
