/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_SAMPLER_H
#define STELA_AMD_SAMPLER_H

#include "pipe/p_defines.h"
#include <stdbool.h>
#include <stdint.h>

struct radeon_info;

#ifdef __cplusplus
extern "C" {
#endif

enum stela_amd_sampler_status {
   STELA_AMD_SAMPLER_OK,
   STELA_AMD_SAMPLER_INVALID,
   STELA_AMD_SAMPLER_UNSUPPORTED,
   STELA_AMD_SAMPLER_DEVICE_INFO_UNAVAILABLE,
};

enum stela_amd_border_color {
   STELA_AMD_BORDER_TRANSPARENT_BLACK,
   STELA_AMD_BORDER_OPAQUE_BLACK,
   STELA_AMD_BORDER_OPAQUE_WHITE,
};

/* Same-process frontend facts, not Metal enum numbers or a guest ABI. The
 * existing pipe enums name internal sampling semantics; no graphics API is
 * called or translated. Scalars stay wide until validation before bitfields.
 * The actual texture/view binding must qualify format/filter/comparison,
 * coordinate dimensionality, permissions and resource residency separately.
 */
struct stela_amd_sampler_state {
   enum pipe_tex_wrap wrap[3];
   enum pipe_tex_filter min_filter;
   enum pipe_tex_filter mag_filter;
   enum pipe_tex_mipfilter mip_filter;
   enum pipe_compare_func compare_func;
   enum pipe_tex_reduction_mode reduction_mode;
   enum stela_amd_border_color border_color;
   uint32_t max_anisotropy; /* 1..16; original policy selects a supported ratio. */
   float min_lod;
   float max_lod;
   float lod_bias;
   bool compare_enabled;
   bool unnormalized_coords;
   bool seamless_cube;
};

/* info must be the actual initialized device/query and matching compiler info.
 * Standard built-in colors require no custom border-color allocation. Every
 * error preserves all output words. LOD quantization/clamping and per-generation
 * packing use the retained original driver, never a custom fixed-point encoder.
 * Unnormalized mode currently accepts exact single-level edge/border sampling;
 * other combinations are explicit refusals pending real binding qualification.
 * Success forms CPU state only, not a Metal capability or filtering guarantee.
 */
enum stela_amd_sampler_status
stela_amd_build_sampler(const struct radeon_info *info,
                         const struct stela_amd_sampler_state *state,
                         uint32_t descriptor[4]);

#ifdef __cplusplus
}
#endif

#endif
