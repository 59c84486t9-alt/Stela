/*
 * Copyright 2012 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Pure sampler policy retained from Mesa 31e9a6b2e95e30d84bf3177d1f497d063e59b6b2,
 * gallium/drivers/radeonsi/si_state.c. No frontend or allocation lifecycle is retained.
 */

#include "sampler.h"
#include "amd/common/ac_descriptors.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/sid.h"
#include <math.h>
#include <string.h>

static unsigned is_wrap_mode_legal(const struct radeon_info *info, unsigned wrap)
{
   if (!info->compiler_info.has_3d_cube_border_color_mipmap) {
      switch (wrap) {
      case PIPE_TEX_WRAP_CLAMP:
      case PIPE_TEX_WRAP_CLAMP_TO_BORDER:
      case PIPE_TEX_WRAP_MIRROR_CLAMP:
      case PIPE_TEX_WRAP_MIRROR_CLAMP_TO_BORDER:
         return false;
      }
   }
   return true;
}

static unsigned si_tex_wrap(unsigned wrap)
{
   switch (wrap) {
   default:
   case PIPE_TEX_WRAP_REPEAT:
      return V_008F30_SQ_TEX_WRAP;
   case PIPE_TEX_WRAP_CLAMP:
      return V_008F30_SQ_TEX_CLAMP_HALF_BORDER;
   case PIPE_TEX_WRAP_CLAMP_TO_EDGE:
      return V_008F30_SQ_TEX_CLAMP_LAST_TEXEL;
   case PIPE_TEX_WRAP_CLAMP_TO_BORDER:
      return V_008F30_SQ_TEX_CLAMP_BORDER;
   case PIPE_TEX_WRAP_MIRROR_REPEAT:
      return V_008F30_SQ_TEX_MIRROR;
   case PIPE_TEX_WRAP_MIRROR_CLAMP:
      return V_008F30_SQ_TEX_MIRROR_ONCE_HALF_BORDER;
   case PIPE_TEX_WRAP_MIRROR_CLAMP_TO_EDGE:
      return V_008F30_SQ_TEX_MIRROR_ONCE_LAST_TEXEL;
   case PIPE_TEX_WRAP_MIRROR_CLAMP_TO_BORDER:
      return V_008F30_SQ_TEX_MIRROR_ONCE_BORDER;
   }
}

static unsigned si_tex_mipfilter(unsigned filter)
{
   switch (filter) {
   case PIPE_TEX_MIPFILTER_NEAREST:
      return V_008F38_SQ_TEX_Z_FILTER_POINT;
   case PIPE_TEX_MIPFILTER_LINEAR:
      return V_008F38_SQ_TEX_Z_FILTER_LINEAR;
   default:
   case PIPE_TEX_MIPFILTER_NONE:
      return V_008F38_SQ_TEX_Z_FILTER_NONE;
   }
}

static unsigned si_tex_compare(unsigned mode, unsigned compare)
{
   if (mode == PIPE_TEX_COMPARE_NONE)
      return V_008F30_SQ_TEX_DEPTH_COMPARE_NEVER;

   switch (compare) {
   default:
   case PIPE_FUNC_NEVER:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_NEVER;
   case PIPE_FUNC_LESS:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_LESS;
   case PIPE_FUNC_EQUAL:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_EQUAL;
   case PIPE_FUNC_LEQUAL:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_LESSEQUAL;
   case PIPE_FUNC_GREATER:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_GREATER;
   case PIPE_FUNC_NOTEQUAL:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_NOTEQUAL;
   case PIPE_FUNC_GEQUAL:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_GREATEREQUAL;
   case PIPE_FUNC_ALWAYS:
      return V_008F30_SQ_TEX_DEPTH_COMPARE_ALWAYS;
   }
}

static inline unsigned si_tex_filter(unsigned filter, unsigned max_aniso)
{
   if (filter == PIPE_TEX_FILTER_LINEAR)
      return max_aniso > 1 ? V_008F38_SQ_TEX_XY_FILTER_ANISO_BILINEAR
                           : V_008F38_SQ_TEX_XY_FILTER_BILINEAR;
   else
      return max_aniso > 1 ? V_008F38_SQ_TEX_XY_FILTER_ANISO_POINT
                           : V_008F38_SQ_TEX_XY_FILTER_POINT;
}

static inline unsigned si_tex_aniso_filter(unsigned filter)
{
   if (filter < 2)
      return 0;
   if (filter < 4)
      return 1;
   if (filter < 8)
      return 2;
   if (filter < 16)
      return 3;
   return 4;
}

static unsigned si_tex_filter_mode(unsigned mode)
{
   switch (mode) {
   case PIPE_TEX_REDUCTION_WEIGHTED_AVERAGE:
      return V_008F30_SQ_IMG_FILTER_MODE_BLEND;
   case PIPE_TEX_REDUCTION_MIN:
      return V_008F30_SQ_IMG_FILTER_MODE_MIN;
   case PIPE_TEX_REDUCTION_MAX:
      return V_008F30_SQ_IMG_FILTER_MODE_MAX;
   default:
      break;
   }
   return 0;
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
      if (!is_wrap_mode_legal(info, state->wrap[axis]))
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
      .address_mode_u = si_tex_wrap(state->wrap[0]),
      .address_mode_v = si_tex_wrap(state->wrap[1]),
      .address_mode_w = si_tex_wrap(state->wrap[2]),
      .max_aniso_ratio = si_tex_aniso_filter(state->max_anisotropy),
      .depth_compare_func = si_tex_compare(state->compare_enabled ? PIPE_TEX_COMPARE_R_TO_TEXTURE :
                                                                 PIPE_TEX_COMPARE_NONE,
                                          state->compare_func),
      .unnormalized_coords = state->unnormalized_coords,
      .cube_wrap = state->seamless_cube,
      .trunc_coord = (nearest && !state->compare_enabled) || info->compiler_info.conformant_trunc_coord,
      .filter_mode = si_tex_filter_mode(state->reduction_mode),
      .mag_filter = si_tex_filter(state->mag_filter, state->max_anisotropy),
      .min_filter = si_tex_filter(state->min_filter, state->max_anisotropy),
      .mip_filter = si_tex_mipfilter(state->mip_filter),
      .min_lod = state->min_lod, .max_lod = state->max_lod, .lod_bias = state->lod_bias,
      .border_color_type = builtin_border(state->border_color),
   };
   uint32_t result[4];
   ac_build_sampler_descriptor(info->gfx_level, &ac_state, result);
   memcpy(descriptor, result, sizeof(result));
   return STELA_AMD_SAMPLER_OK;
}
