/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMDGPU_MODE_H
#define STELA_AMDGPU_MODE_H
#include <linux/types.h>
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_fourcc.h>
/* The display state unchanged sources read; Stela drives no display. */
struct amdgpu_mode_info {
	bool mode_config_initialized;
	int num_crtc;
};
#endif
