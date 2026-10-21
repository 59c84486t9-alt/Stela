/*
 * Copyright © 2017 Intel Corporation
 * SPDX-License-Identifier: MIT
 *
 * Allocation-free sampler policy shared with the retained Iris caller.
 * Include after original generation packers, GENX and iris_pack_state.
 * Bodies below are moved unchanged from iris_state.c; API object creation,
 * border-color ownership and state upload remain with their actual owners.
 */
#ifndef IRIS_SAMPLER_STATE_H
#define IRIS_SAMPLER_STATE_H
#include "pipe/p_state.h"
#include "util/macros.h"
#if !defined(GFX_VER) || !defined(iris_pack_state)
#error "Sampler policy needs its actual generation and generated packer context"
#endif

static unsigned
translate_shadow_func(enum pipe_compare_func pipe_func)
{
   /* Gallium specifies the result of shadow comparisons as:
    *
    *    1 if ref <op> texel,
    *    0 otherwise.
    *
    * The hardware does:
    *
    *    0 if texel <op> ref,
    *    1 otherwise.
    *
    * So we need to flip the operator and also negate.
    */
   static const unsigned map[] = {
      [PIPE_FUNC_NEVER]    = PREFILTEROP_ALWAYS,
      [PIPE_FUNC_LESS]     = PREFILTEROP_LEQUAL,
      [PIPE_FUNC_EQUAL]    = PREFILTEROP_NOTEQUAL,
      [PIPE_FUNC_LEQUAL]   = PREFILTEROP_LESS,
      [PIPE_FUNC_GREATER]  = PREFILTEROP_GEQUAL,
      [PIPE_FUNC_NOTEQUAL] = PREFILTEROP_EQUAL,
      [PIPE_FUNC_GEQUAL]   = PREFILTEROP_GREATER,
      [PIPE_FUNC_ALWAYS]   = PREFILTEROP_NEVER,
   };
   return map[pipe_func];
}

static unsigned
translate_mip_filter(enum pipe_tex_mipfilter pipe_mip)
{
   static const unsigned map[] = {
      [PIPE_TEX_MIPFILTER_NEAREST] = MIPFILTER_NEAREST,
      [PIPE_TEX_MIPFILTER_LINEAR]  = MIPFILTER_LINEAR,
      [PIPE_TEX_MIPFILTER_NONE]    = MIPFILTER_NONE,
   };
   return map[pipe_mip];
}

static uint32_t
translate_wrap(unsigned pipe_wrap)
{
   static const unsigned map[] = {
      [PIPE_TEX_WRAP_REPEAT]                 = TCM_WRAP,
      [PIPE_TEX_WRAP_CLAMP]                  = TCM_HALF_BORDER,
      [PIPE_TEX_WRAP_CLAMP_TO_EDGE]          = TCM_CLAMP,
      [PIPE_TEX_WRAP_CLAMP_TO_BORDER]        = TCM_CLAMP_BORDER,
      [PIPE_TEX_WRAP_MIRROR_REPEAT]          = TCM_MIRROR,
      [PIPE_TEX_WRAP_MIRROR_CLAMP_TO_EDGE]   = TCM_MIRROR_ONCE,

      /* These are unsupported. */
      [PIPE_TEX_WRAP_MIRROR_CLAMP]           = -1,
      [PIPE_TEX_WRAP_MIRROR_CLAMP_TO_BORDER] = -1,
   };
   return map[pipe_wrap];
}

#if GFX_VER > 8
static uint32_t
translate_tex_filter_mode(unsigned mode)
{
   static const unsigned map[] = {
      [PIPE_TEX_REDUCTION_WEIGHTED_AVERAGE] = STD_FILTER,
      [PIPE_TEX_REDUCTION_MIN]              = MINIMUM,
      [PIPE_TEX_REDUCTION_MAX]              = MAXIMUM,
   };
   return map[mode];
}
#endif

static void
fill_sampler_state(uint32_t *sampler_state,
                   const struct pipe_sampler_state *state,
                   unsigned max_anisotropy)
{
   float min_lod = state->min_lod;
   unsigned mag_img_filter = state->mag_img_filter;

   // XXX: explain this code ported from ilo...I don't get it at all...
   if (state->min_mip_filter == PIPE_TEX_MIPFILTER_NONE &&
       state->min_lod > 0.0f) {
      min_lod = 0.0f;
      mag_img_filter = state->min_img_filter;
   }

#if GFX_VER > 8
   uint32_t reduction_mode =
      translate_tex_filter_mode(state->reduction_mode);
#endif

   iris_pack_state(GENX(SAMPLER_STATE), sampler_state, samp) {
      samp.TCXAddressControlMode = translate_wrap(state->wrap_s);
      samp.TCYAddressControlMode = translate_wrap(state->wrap_t);
      samp.TCZAddressControlMode = translate_wrap(state->wrap_r);
      samp.CubeSurfaceControlMode = state->seamless_cube_map;
      samp.NonnormalizedCoordinateEnable = state->unnormalized_coords;
      samp.MinModeFilter = state->min_img_filter;
      samp.MagModeFilter = mag_img_filter;
      samp.MipModeFilter = translate_mip_filter(state->min_mip_filter);
      samp.MaximumAnisotropy = RATIO21;
#if GFX_VER > 8
      samp.ReductionType = reduction_mode;
      samp.ReductionTypeEnable =
         reduction_mode != PIPE_TEX_REDUCTION_WEIGHTED_AVERAGE;
#endif
      if (max_anisotropy >= 2) {
         if (state->min_img_filter == PIPE_TEX_FILTER_LINEAR) {
#if GFX_VER >= 30
            samp.MinModeFilter = MAPFILTER_ANISOTROPIC_FAST;
#else
            samp.MinModeFilter = MAPFILTER_ANISOTROPIC;
#endif
            samp.AnisotropicAlgorithm = EWAApproximation;
         }

         if (state->mag_img_filter == PIPE_TEX_FILTER_LINEAR) {
#if GFX_VER >= 30
            samp.MagModeFilter = MAPFILTER_ANISOTROPIC_FAST;
#else
            samp.MagModeFilter = MAPFILTER_ANISOTROPIC;
#endif
         }

         samp.MaximumAnisotropy =
            MIN2((max_anisotropy - 2) / 2, RATIO161);
      }

      /* Set address rounding bits if not using nearest filtering. */
      if (state->min_img_filter != PIPE_TEX_FILTER_NEAREST) {
         samp.UAddressMinFilterRoundingEnable = true;
         samp.VAddressMinFilterRoundingEnable = true;
         samp.RAddressMinFilterRoundingEnable = true;
      }

      if (state->mag_img_filter != PIPE_TEX_FILTER_NEAREST) {
         samp.UAddressMagFilterRoundingEnable = true;
         samp.VAddressMagFilterRoundingEnable = true;
         samp.RAddressMagFilterRoundingEnable = true;
      }

      if (state->compare_mode == PIPE_TEX_COMPARE_R_TO_TEXTURE)
         samp.ShadowFunction = translate_shadow_func(state->compare_func);

      const float hw_max_lod = GFX_VER >= 7 ? 14 : 13;

      samp.LODPreClampMode = CLAMP_MODE_OGL;
      samp.MinLOD = CLAMP(min_lod, 0, hw_max_lod);
      samp.MaxLOD = CLAMP(state->max_lod, 0, hw_max_lod);
      samp.TextureLODBias = CLAMP(state->lod_bias, -16, 15);

      /* .BorderColorPointer is filled in by iris_bind_sampler_states. */
   }
}

#endif
