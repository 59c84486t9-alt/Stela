/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_CLIENT_SETUP_H
#define STELA_DRM_CLIENT_SETUP_H
struct drm_device;
struct drm_format_info;
/* Stela runs no in-kernel DRM client; a source that starts one declares it. */
static void drm_client_setup(struct drm_device *dev, const struct drm_format_info *format);
#endif
