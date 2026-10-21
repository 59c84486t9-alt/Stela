/* SPDX-License-Identifier: MIT */
/* Hosted descriptor CPU models. No initialized GPU or filter execution. */
#include "../stela/sampler.h"
#include "amd/common/ac_descriptors.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/sid.h"
#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

struct si_screen { struct radeon_info info; };
#include "sampler_policy_reference.h"

static struct stela_amd_sampler_state
sampler(void)
{
   return (struct stela_amd_sampler_state){
      .wrap = {PIPE_TEX_WRAP_CLAMP_TO_EDGE, PIPE_TEX_WRAP_CLAMP_TO_EDGE, PIPE_TEX_WRAP_CLAMP_TO_EDGE},
      .min_filter = PIPE_TEX_FILTER_NEAREST, .mag_filter = PIPE_TEX_FILTER_NEAREST,
      .mip_filter = PIPE_TEX_MIPFILTER_NONE, .compare_func = PIPE_FUNC_ALWAYS,
      .reduction_mode = PIPE_TEX_REDUCTION_WEIGHTED_AVERAGE,
      .border_color = STELA_AMD_BORDER_TRANSPARENT_BLACK,
      .max_anisotropy = 1, .max_lod = 15, .seamless_cube = true,
   };
}

static struct radeon_info
model(enum radeon_family family, bool graphics)
{
   struct radeon_info info = {.family = family, .gfx_level = ac_get_gfx_level(family),
      .has_graphics = graphics, .has_image_opcodes = graphics || family < CHIP_GFX940};
   ac_fill_compiler_info(&info, NULL, false);
   return info;
}

static void
donor(const struct radeon_info *info, const struct stela_amd_sampler_state *state, uint32_t words[4])
{
   const unsigned border[] = {V_008F3C_SQ_TEX_BORDER_COLOR_TRANS_BLACK,
      V_008F3C_SQ_TEX_BORDER_COLOR_OPAQUE_BLACK, V_008F3C_SQ_TEX_BORDER_COLOR_OPAQUE_WHITE};
   const struct ac_sampler_state ac = {
      .address_mode_u = si_tex_wrap(state->wrap[0]), .address_mode_v = si_tex_wrap(state->wrap[1]),
      .address_mode_w = si_tex_wrap(state->wrap[2]),
      .max_aniso_ratio = si_tex_aniso_filter(state->max_anisotropy),
      .depth_compare_func = si_tex_compare(state->compare_enabled ? PIPE_TEX_COMPARE_R_TO_TEXTURE :
                                                                 PIPE_TEX_COMPARE_NONE, state->compare_func),
      .unnormalized_coords = state->unnormalized_coords, .cube_wrap = state->seamless_cube,
      .trunc_coord = (state->min_filter == PIPE_TEX_FILTER_NEAREST &&
         state->mag_filter == PIPE_TEX_FILTER_NEAREST && !state->compare_enabled) ||
         info->compiler_info.conformant_trunc_coord,
      .filter_mode = si_tex_filter_mode(state->reduction_mode),
      .mag_filter = si_tex_filter(state->mag_filter, state->max_anisotropy),
      .min_filter = si_tex_filter(state->min_filter, state->max_anisotropy),
      .mip_filter = si_tex_mipfilter(state->mip_filter), .min_lod = state->min_lod,
      .max_lod = state->max_lod, .lod_bias = state->lod_bias,
      .border_color_type = border[state->border_color],
   };
   ac_build_sampler_descriptor(info->gfx_level, &ac, words);
}

static unsigned
check(const struct radeon_info *info, const struct stela_amd_sampler_state *state,
        enum stela_amd_sampler_status expected)
{
   const uint32_t preserved[] = {0x12345678, 0x23456789, 0x34567890, 0x45678901};
   uint32_t words[4]; memcpy(words, preserved, sizeof(words));
   enum stela_amd_sampler_status status = stela_amd_build_sampler(info, state, words);
   assert(status == expected);
   if (status != STELA_AMD_SAMPLER_OK) {
      assert(!memcmp(words, preserved, sizeof(words)));
      return 0;
   }
   uint32_t reference[4]; donor(info, state, reference);
   assert(!memcmp(words, reference, sizeof(words)));
   /* Independent field decoding from scalar semantics, not the policy helpers. */
   const unsigned wraps[] = {V_008F30_SQ_TEX_WRAP, V_008F30_SQ_TEX_CLAMP_HALF_BORDER,
      V_008F30_SQ_TEX_CLAMP_LAST_TEXEL, V_008F30_SQ_TEX_CLAMP_BORDER,
      V_008F30_SQ_TEX_MIRROR, V_008F30_SQ_TEX_MIRROR_ONCE_HALF_BORDER,
      V_008F30_SQ_TEX_MIRROR_ONCE_LAST_TEXEL, V_008F30_SQ_TEX_MIRROR_ONCE_BORDER};
   assert(G_008F30_CLAMP_X(words[0]) == wraps[state->wrap[0]]);
   assert(G_008F30_CLAMP_Y(words[0]) == wraps[state->wrap[1]]);
   assert(G_008F30_CLAMP_Z(words[0]) == wraps[state->wrap[2]]);
   unsigned aniso = 0;
   for (unsigned value = state->max_anisotropy; value > 1; value >>= 1) aniso++;
   assert(G_008F30_MAX_ANISO_RATIO(words[0]) == aniso);
   assert(G_008F30_DEPTH_COMPARE_FUNC(words[0]) == (state->compare_enabled ? state->compare_func : 0));
   assert(G_008F30_FORCE_UNNORMALIZED(words[0]) == state->unnormalized_coords);
   assert(G_008F30_DISABLE_CUBE_WRAP(words[0]) == !state->seamless_cube);
   assert(G_008F30_COMPAT_MODE(words[0]) == (info->gfx_level == GFX8 || info->gfx_level == GFX9));
   assert(G_008F30_TRUNC_COORD(words[0]) ==
          ((state->min_filter == PIPE_TEX_FILTER_NEAREST &&
            state->mag_filter == PIPE_TEX_FILTER_NEAREST && !state->compare_enabled) ||
           info->compiler_info.conformant_trunc_coord));
   const unsigned filters[] = {V_008F38_SQ_TEX_XY_FILTER_POINT, V_008F38_SQ_TEX_XY_FILTER_BILINEAR,
      V_008F38_SQ_TEX_XY_FILTER_ANISO_POINT, V_008F38_SQ_TEX_XY_FILTER_ANISO_BILINEAR};
   assert(G_008F38_XY_MIN_FILTER(words[2]) == filters[state->min_filter + (aniso ? 2 : 0)]);
   assert(G_008F38_XY_MAG_FILTER(words[2]) == filters[state->mag_filter + (aniso ? 2 : 0)]);
   const unsigned mips[] = {V_008F38_SQ_TEX_Z_FILTER_POINT, V_008F38_SQ_TEX_Z_FILTER_LINEAR,
                            V_008F38_SQ_TEX_Z_FILTER_NONE};
   assert(G_008F38_MIP_FILTER(words[2]) == mips[state->mip_filter]);
   assert(G_008F3C_BORDER_COLOR_TYPE(words[3]) == (unsigned)state->border_color);
   assert((info->gfx_level >= GFX11 ? G_008F3C_BORDER_COLOR_PTR_GFX11(words[3]) :
                                    G_008F3C_BORDER_COLOR_PTR_GFX6(words[3])) == 0);
   unsigned min_lod = info->gfx_level >= GFX12 ? G_008F34_MIN_LOD_GFX12(words[1]) :
                                                G_008F34_MIN_LOD_GFX6(words[1]);
   unsigned max_lod = info->gfx_level >= GFX12 ? G_008F34_MAX_LOD_GFX12(words[1]) :
                                                G_008F34_MAX_LOD_GFX6(words[1]);
   const float limit = info->gfx_level >= GFX12 ? 17 : 15;
   assert(min_lod == (unsigned)(fminf(state->min_lod, limit) * 256));
   assert(max_lod == (unsigned)(fminf(state->max_lod, limit) * 256));
   const unsigned bias_mask = G_008F38_LOD_BIAS(UINT32_MAX);
   unsigned raw_bias = G_008F38_LOD_BIAS(words[2]);
   int bias = raw_bias & ((bias_mask + 1) >> 1) ? (int)raw_bias - (int)bias_mask - 1 : (int)raw_bias;
   assert(bias == (int)(state->lod_bias * 256));
   return 1;
}

static unsigned
matrix(const struct radeon_info *info)
{
   if (!info->has_image_opcodes) {
      struct stela_amd_sampler_state state = sampler();
      check(info, &state, STELA_AMD_SAMPLER_UNSUPPORTED);
      return 0;
   }
   struct si_screen screen = {.info = *info};
   unsigned comparisons = 0;
   const unsigned anisotropy[] = {1, 2, 3, 4, 7, 8, 12, 16};
   for (unsigned wrap = 0; wrap < 8; wrap++) {
      for (unsigned filters = 0; filters < 4; filters++) {
         for (unsigned mip = 0; mip < 3; mip++) {
            for (unsigned a = 0; a < ARRAY_SIZE(anisotropy); a++) {
               for (unsigned compare = 0; compare < 8; compare++) {
                  struct stela_amd_sampler_state state = sampler();
                  state.wrap[0] = wrap; state.wrap[1] = (wrap + 3) % 8; state.wrap[2] = (wrap + 6) % 8;
                  state.min_filter = filters & 1; state.mag_filter = filters >> 1;
                  state.mip_filter = mip; state.max_anisotropy = anisotropy[a];
                  state.compare_enabled = a & 1; state.compare_func = compare;
                  state.reduction_mode = compare % 3; state.border_color = a % 3;
                  state.min_lod = 1.25; state.max_lod = a & 1 ? 7.5 : FLT_MAX;
                  state.lod_bias = -1.5; state.seamless_cube = a & 1;
                  bool legal = is_wrap_mode_legal(&screen, state.wrap[0]) &&
                     is_wrap_mode_legal(&screen, state.wrap[1]) && is_wrap_mode_legal(&screen, state.wrap[2]) &&
                     (info->compiler_info.has_3d_cube_border_color_mipmap ||
                      (mip == PIPE_TEX_MIPFILTER_NONE && anisotropy[a] == 1));
                  comparisons += check(info, &state, legal ? STELA_AMD_SAMPLER_OK : STELA_AMD_SAMPLER_UNSUPPORTED);
               }
            }
         }
      }
   }
   return comparisons;
}

static void
invalid_inputs(const struct radeon_info *info)
{
   const struct stela_amd_sampler_state original = sampler();
   struct stela_amd_sampler_state state;
#define INVALID(field, value, status) do { state = original; state.field = value; check(info, &state, status); } while (0)
   INVALID(wrap[1], -1, STELA_AMD_SAMPLER_INVALID);
   INVALID(min_filter, -1, STELA_AMD_SAMPLER_INVALID);
   INVALID(mag_filter, 2, STELA_AMD_SAMPLER_INVALID);
   INVALID(mip_filter, 3, STELA_AMD_SAMPLER_INVALID);
   INVALID(compare_func, 8, STELA_AMD_SAMPLER_INVALID);
   INVALID(reduction_mode, 3, STELA_AMD_SAMPLER_INVALID);
   INVALID(border_color, 3, STELA_AMD_SAMPLER_INVALID);
   INVALID(max_anisotropy, 0, STELA_AMD_SAMPLER_INVALID);
   INVALID(max_anisotropy, 17, STELA_AMD_SAMPLER_INVALID);
   INVALID(min_lod, NAN, STELA_AMD_SAMPLER_INVALID);
   INVALID(max_lod, INFINITY, STELA_AMD_SAMPLER_INVALID);
   INVALID(max_lod, NAN, STELA_AMD_SAMPLER_INVALID);
   INVALID(lod_bias, -INFINITY, STELA_AMD_SAMPLER_INVALID);
   INVALID(lod_bias, NAN, STELA_AMD_SAMPLER_INVALID);
   INVALID(min_lod, -1, STELA_AMD_SAMPLER_INVALID);
   INVALID(min_lod, 16, STELA_AMD_SAMPLER_INVALID);
   INVALID(lod_bias, -33, STELA_AMD_SAMPLER_UNSUPPORTED);
   INVALID(unnormalized_coords, true, STELA_AMD_SAMPLER_UNSUPPORTED);
#undef INVALID
   state = original; state.unnormalized_coords = true; state.max_lod = 0;
   check(info, &state, STELA_AMD_SAMPLER_OK);
   state.wrap[0] = PIPE_TEX_WRAP_REPEAT;
   check(info, &state, STELA_AMD_SAMPLER_UNSUPPORTED);
   struct radeon_info missing = *info; missing.compiler_info.gfx_level = GFX6;
   check(&missing, &original, STELA_AMD_SAMPLER_DEVICE_INFO_UNAVAILABLE);
   missing = *info; missing.family = CHIP_UNKNOWN;
   check(&missing, &original, STELA_AMD_SAMPLER_DEVICE_INFO_UNAVAILABLE);
   missing = *info; missing.has_image_opcodes = false;
   check(&missing, &original, STELA_AMD_SAMPLER_UNSUPPORTED);
   uint32_t words[4] = {0};
   assert(stela_amd_build_sampler(NULL, &original, words) == STELA_AMD_SAMPLER_INVALID);
   assert(stela_amd_build_sampler(info, NULL, words) == STELA_AMD_SAMPLER_INVALID);
   assert(stela_amd_build_sampler(info, &original, NULL) == STELA_AMD_SAMPLER_INVALID);
}

int main(void)
{
   const struct {enum radeon_family family; bool graphics;} targets[] = {
      {CHIP_TAHITI, true}, {CHIP_BONAIRE, true}, {CHIP_CARRIZO, true}, {CHIP_RAVEN, true},
      {CHIP_MI100, false}, {CHIP_MI200, false}, {CHIP_GFX940, false},
      {CHIP_NAVI10, true}, {CHIP_REMBRANDT, true}, {CHIP_NAVI31, true},
      {CHIP_STRIX1, true}, {CHIP_GFX1170, true}, {CHIP_GFX1201, true}, {CHIP_GFX1210, true},
   };
   unsigned comparisons = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(targets); i++) {
      struct radeon_info info = model(targets[i].family, targets[i].graphics);
      comparisons += matrix(&info);
      if (info.has_image_opcodes) {
         struct stela_amd_sampler_state edge = sampler();
         edge.min_lod = edge.max_lod = FLT_MAX;
         edge.lod_bias = info.gfx_level >= GFX10 ? -32 : -16;
         comparisons += check(&info, &edge, STELA_AMD_SAMPLER_OK);
         edge.lod_bias = info.gfx_level >= GFX10 ? 31 : 16;
         comparisons += check(&info, &edge, STELA_AMD_SAMPLER_OK);
      }
   }
   struct radeon_info conformant = model(CHIP_NAVI31, true);
   invalid_inputs(&conformant);
   conformant.compiler_info.conformant_trunc_coord = true;
   comparisons += matrix(&conformant);
   printf("AMD samplers: %u pinned-policy/descriptor cases across14generationmodels+queried-coordinate variant; hardwareunverified\n", comparisons);
   return 0;
}
