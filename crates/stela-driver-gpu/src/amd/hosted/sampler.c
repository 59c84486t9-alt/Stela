/* SPDX-License-Identifier: MIT */
/* Stela's sampler policy: validated pipe sampler facts mapped to the SQ
 * sampler fields, packed by Mesa's unchanged ac_build_sampler_descriptor.
 */

#include "sampler.h"
#include "amd/common/ac_descriptors.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/sid.h"
#include "util/u_math.h"
#include <math.h>
#include <string.h>

static const unsigned address_modes[] = {
   [PIPE_TEX_WRAP_REPEAT] = V_008F30_SQ_TEX_WRAP,
   [PIPE_TEX_WRAP_CLAMP] = V_008F30_SQ_TEX_CLAMP_HALF_BORDER,
   [PIPE_TEX_WRAP_CLAMP_TO_EDGE] = V_008F30_SQ_TEX_CLAMP_LAST_TEXEL,
   [PIPE_TEX_WRAP_CLAMP_TO_BORDER] = V_008F30_SQ_TEX_CLAMP_BORDER,
   [PIPE_TEX_WRAP_MIRROR_REPEAT] = V_008F30_SQ_TEX_MIRROR,
   [PIPE_TEX_WRAP_MIRROR_CLAMP] = V_008F30_SQ_TEX_MIRROR_ONCE_HALF_BORDER,
   [PIPE_TEX_WRAP_MIRROR_CLAMP_TO_EDGE] = V_008F30_SQ_TEX_MIRROR_ONCE_LAST_TEXEL,
   [PIPE_TEX_WRAP_MIRROR_CLAMP_TO_BORDER] = V_008F30_SQ_TEX_MIRROR_ONCE_BORDER,
};

static const unsigned mip_filters[] = {
   [PIPE_TEX_MIPFILTER_NEAREST] = V_008F38_SQ_TEX_Z_FILTER_POINT,
   [PIPE_TEX_MIPFILTER_LINEAR] = V_008F38_SQ_TEX_Z_FILTER_LINEAR,
   [PIPE_TEX_MIPFILTER_NONE] = V_008F38_SQ_TEX_Z_FILTER_NONE,
};

static const unsigned compare_funcs[] = {
   [PIPE_FUNC_NEVER] = V_008F30_SQ_TEX_DEPTH_COMPARE_NEVER,
   [PIPE_FUNC_LESS] = V_008F30_SQ_TEX_DEPTH_COMPARE_LESS,
   [PIPE_FUNC_EQUAL] = V_008F30_SQ_TEX_DEPTH_COMPARE_EQUAL,
   [PIPE_FUNC_LEQUAL] = V_008F30_SQ_TEX_DEPTH_COMPARE_LESSEQUAL,
   [PIPE_FUNC_GREATER] = V_008F30_SQ_TEX_DEPTH_COMPARE_GREATER,
   [PIPE_FUNC_NOTEQUAL] = V_008F30_SQ_TEX_DEPTH_COMPARE_NOTEQUAL,
   [PIPE_FUNC_GEQUAL] = V_008F30_SQ_TEX_DEPTH_COMPARE_GREATEREQUAL,
   [PIPE_FUNC_ALWAYS] = V_008F30_SQ_TEX_DEPTH_COMPARE_ALWAYS,
};

static const unsigned reduction_modes[] = {
   [PIPE_TEX_REDUCTION_WEIGHTED_AVERAGE] = V_008F30_SQ_IMG_FILTER_MODE_BLEND,
   [PIPE_TEX_REDUCTION_MIN] = V_008F30_SQ_IMG_FILTER_MODE_MIN,
   [PIPE_TEX_REDUCTION_MAX] = V_008F30_SQ_IMG_FILTER_MODE_MAX,
};

/* Clamping wraps can sample the border color, which needs the 3D/cube
 * border-color mipmap support older generations lack.
 */
static bool
samples_border(enum pipe_tex_wrap wrap)
{
   return wrap == PIPE_TEX_WRAP_CLAMP || wrap == PIPE_TEX_WRAP_CLAMP_TO_BORDER ||
          wrap == PIPE_TEX_WRAP_MIRROR_CLAMP || wrap == PIPE_TEX_WRAP_MIRROR_CLAMP_TO_BORDER;
}

/* Anisotropic filtering applies once the ratio exceeds one. */
static unsigned
xy_filter(enum pipe_tex_filter filter, unsigned max_anisotropy)
{
   const bool linear = filter == PIPE_TEX_FILTER_LINEAR;
   if (max_anisotropy > 1)
      return linear ? V_008F38_SQ_TEX_XY_FILTER_ANISO_BILINEAR :
                      V_008F38_SQ_TEX_XY_FILTER_ANISO_POINT;
   return linear ? V_008F38_SQ_TEX_XY_FILTER_BILINEAR : V_008F38_SQ_TEX_XY_FILTER_POINT;
}

static unsigned
builtin_border(enum stela_amd_border_color color)
{
   switch (color) {
   case STELA_AMD_BORDER_OPAQUE_BLACK: return V_008F3C_SQ_TEX_BORDER_COLOR_OPAQUE_BLACK;
   case STELA_AMD_BORDER_OPAQUE_WHITE: return V_008F3C_SQ_TEX_BORDER_COLOR_OPAQUE_WHITE;
   case STELA_AMD_BORDER_TRANSPARENT_BLACK: return V_008F3C_SQ_TEX_BORDER_COLOR_TRANS_BLACK;
   }
   UNREACHABLE("prevalidated built-in border color");
}

enum stela_amd_sampler_status
stela_amd_build_sampler(const struct radeon_info *info,
                         const struct stela_amd_sampler_state *state,
                         uint32_t descriptor[4])
{
   if (!info || !state || !descriptor)
      return STELA_AMD_SAMPLER_INVALID;
   if (info->gfx_level < GFX6 || info->gfx_level >= NUM_GFX_VERSIONS)
      return STELA_AMD_SAMPLER_UNSUPPORTED;
   if (info->family <= CHIP_UNKNOWN || info->family >= CHIP_LAST ||
       ac_get_gfx_level(info->family) != info->gfx_level ||
       info->compiler_info.gfx_level != info->gfx_level ||
       !info->compiler_info.max_waves_per_simd)
      return STELA_AMD_SAMPLER_DEVICE_INFO_UNAVAILABLE;
   if (!info->has_image_opcodes)
      return STELA_AMD_SAMPLER_UNSUPPORTED;
   if ((unsigned)state->min_filter > PIPE_TEX_FILTER_LINEAR ||
       (unsigned)state->mag_filter > PIPE_TEX_FILTER_LINEAR ||
       (unsigned)state->mip_filter > PIPE_TEX_MIPFILTER_NONE ||
       (unsigned)state->compare_func > PIPE_FUNC_ALWAYS ||
       (unsigned)state->reduction_mode > PIPE_TEX_REDUCTION_MAX ||
       (unsigned)state->border_color > STELA_AMD_BORDER_OPAQUE_WHITE ||
       !state->max_anisotropy || state->max_anisotropy > 16 ||
       !isfinite(state->min_lod) || !isfinite(state->max_lod) || !isfinite(state->lod_bias) ||
       state->min_lod < 0 || state->max_lod < state->min_lod)
      return STELA_AMD_SAMPLER_INVALID;
   for (unsigned axis = 0; axis < 3; axis++) {
      if ((unsigned)state->wrap[axis] > PIPE_TEX_WRAP_MIRROR_CLAMP_TO_BORDER)
         return STELA_AMD_SAMPLER_INVALID;
      if (!info->compiler_info.has_3d_cube_border_color_mipmap &&
          samples_border(state->wrap[axis]))
         return STELA_AMD_SAMPLER_UNSUPPORTED;
   }
   if (!info->compiler_info.has_3d_cube_border_color_mipmap &&
       (state->mip_filter != PIPE_TEX_MIPFILTER_NONE || state->max_anisotropy > 1))
      return STELA_AMD_SAMPLER_UNSUPPORTED;
   if (state->unnormalized_coords) {
      if (state->mip_filter != PIPE_TEX_MIPFILTER_NONE || state->max_anisotropy != 1 ||
          state->min_filter != state->mag_filter || state->min_lod != 0 || state->max_lod != 0 ||
          state->lod_bias != 0)
         return STELA_AMD_SAMPLER_UNSUPPORTED;
      for (unsigned axis = 0; axis < 3; axis++) {
         if (state->wrap[axis] != PIPE_TEX_WRAP_CLAMP_TO_EDGE &&
             state->wrap[axis] != PIPE_TEX_WRAP_CLAMP_TO_BORDER)
            return STELA_AMD_SAMPLER_UNSUPPORTED;
      }
   }
   const float min_bias = info->gfx_level >= GFX10 ? -32 : -16;
   const float max_bias = info->gfx_level >= GFX10 ? 31 : 16;
   if (state->lod_bias < min_bias || state->lod_bias > max_bias)
      return STELA_AMD_SAMPLER_UNSUPPORTED;
   const bool nearest = state->min_filter == PIPE_TEX_FILTER_NEAREST &&
                        state->mag_filter == PIPE_TEX_FILTER_NEAREST;
   const struct ac_sampler_state ac_state = {
      .address_mode_u = address_modes[state->wrap[0]],
      .address_mode_v = address_modes[state->wrap[1]],
      .address_mode_w = address_modes[state->wrap[2]],
      /* log2 of the 1..16 anisotropy ratio. */
      .max_aniso_ratio = util_logbase2(state->max_anisotropy),
      .depth_compare_func = state->compare_enabled ? compare_funcs[state->compare_func] :
                                                     V_008F30_SQ_TEX_DEPTH_COMPARE_NEVER,
      .unnormalized_coords = state->unnormalized_coords,
      .cube_wrap = state->seamless_cube,
      .trunc_coord = (nearest && !state->compare_enabled) || info->compiler_info.conformant_trunc_coord,
      .filter_mode = reduction_modes[state->reduction_mode],
      .mag_filter = xy_filter(state->mag_filter, state->max_anisotropy),
      .min_filter = xy_filter(state->min_filter, state->max_anisotropy),
      .mip_filter = mip_filters[state->mip_filter],
      .min_lod = state->min_lod, .max_lod = state->max_lod, .lod_bias = state->lod_bias,
      .border_color_type = builtin_border(state->border_color),
   };
   uint32_t result[4];
   ac_build_sampler_descriptor(info->gfx_level, &ac_state, result);
   memcpy(descriptor, result, sizeof(result));
   return STELA_AMD_SAMPLER_OK;
}
