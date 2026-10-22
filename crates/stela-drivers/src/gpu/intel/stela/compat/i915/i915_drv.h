/* SPDX-License-Identifier: MIT */
#ifndef STELA_I915_DRV_H
#define STELA_I915_DRV_H
#include <linux/math.h>
#include <linux/sizes.h>
#include <linux/types.h>
#include "intel_step.h"
/* Device identity and capability queries are services that the adapter
 * defines for its device.
 */
struct drm_i915_private {
	u32 gen2_imr_mask;
};
static unsigned int stela_i915_graphics_ver(const struct drm_i915_private *i915);
static unsigned int stela_i915_graphics_ver_full(const struct drm_i915_private *i915);
static bool stela_i915_is_dg2(const struct drm_i915_private *i915);
static bool stela_i915_is_g4x(const struct drm_i915_private *i915);
static bool stela_i915_is_kabylake(const struct drm_i915_private *i915);
static bool stela_i915_has_flat_ccs(const struct drm_i915_private *i915);
static bool stela_i915_has_3d_pipeline(const struct drm_i915_private *i915);
static bool stela_i915_is_graphics_step(const struct drm_i915_private *i915,
					int since, int until);
#define IP_VER(ver, rel) ((ver) << 8 | (rel))
#define GRAPHICS_VER(i915) stela_i915_graphics_ver(i915)
#define GRAPHICS_VER_FULL(i915) stela_i915_graphics_ver_full(i915)
#define IS_DG2(i915) stela_i915_is_dg2(i915)
#define IS_G4X(i915) stela_i915_is_g4x(i915)
#define IS_KABYLAKE(i915) stela_i915_is_kabylake(i915)
#define HAS_FLAT_CCS(i915) stela_i915_has_flat_ccs(i915)
#define HAS_3D_PIPELINE(i915) stela_i915_has_3d_pipeline(i915)
#define IS_GRAPHICS_STEP(i915, since, until) stela_i915_is_graphics_step(i915, since, until)
#endif
