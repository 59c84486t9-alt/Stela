/*
 * Copyright © 2022 Collabora Ltd. and Red Hat Inc.
 * SPDX-License-Identifier: MIT
 */
/* Original pure NVK sampler packing extracted from nvk_sampler.c. Original
 * Vulkan callers bridge only the value fields below; no packing policy changes.
 * Callers validate values/device capabilities before this assert-bearing packer.
 */
#ifndef NIL_SAMPLER_H
#define NIL_SAMPLER_H
#include "nouveau/headers/nv_device_info.h"
#include "vulkan/util/vk_color_value.h"
#include "util/bitpack_helpers.h"
#include "util/format/format_utils.h"
#include "util/format_srgb.h"
#include "nouveau/headers/nvidia/classes/cla097.h"
#include "nouveau/headers/nvidia/classes/clb197.h"
#include "nouveau/headers/nvidia/classes/cl9097tex.h"
#include "nouveau/headers/nvidia/classes/cla097tex.h"
#include "nouveau/headers/nvidia/classes/clb197tex.h"
#include "nouveau/headers/drf.h"

struct nvk_sampler_header {
   uint32_t bits[8];
};

/* Values consumed by the original NVK packer. Vulkan enum/color declarations
 * specify value semantics only; no vk_sampler/object/YCbCr state is included.
 * Internal, same-process C interface, not a guest or cross-CPU ABI.
 */
struct nil_sampler_state {
   VkSamplerCreateFlags flags;
   VkFilter mag_filter;
   VkFilter min_filter;
   VkSamplerMipmapMode mipmap_mode;
   VkSamplerAddressMode address_mode_u;
   VkSamplerAddressMode address_mode_v;
   VkSamplerAddressMode address_mode_w;
   float mip_lod_bias;
   float max_anisotropy;
   VkCompareOp compare_op;
   float min_lod;
   float max_lod;
   VkBorderColor border_color;
   bool anisotropy_enable;
   bool compare_enable;
   bool unnormalized_coordinates;
   bool image_view_is_srgb;
   VkClearColorValue border_color_value;
   VkComponentMapping border_color_component_mapping;
   VkSamplerReductionMode reduction_mode;
};

ALWAYS_INLINE static void
__set_u32(uint32_t *o, uint32_t v, unsigned lo, unsigned hi)
{
   assert(lo <= hi && hi < 32);
   *o |= util_bitpack_uint(v, lo % 32, hi % 32);
}

#define FIXED_FRAC_BITS 8

ALWAYS_INLINE static void
__set_ufixed(uint32_t *o, float v, unsigned lo, unsigned hi)
{
   assert(lo <= hi && hi < 32);
   *o |= util_bitpack_ufixed_clamp(v, lo % 32, hi % 32, FIXED_FRAC_BITS);
}

ALWAYS_INLINE static void
__set_sfixed(uint32_t *o, float v, unsigned lo, unsigned hi)
{
   assert(lo <= hi && hi < 32);
   *o |= util_bitpack_sfixed_clamp(v, lo % 32, hi % 32, FIXED_FRAC_BITS);
}

ALWAYS_INLINE static void
__set_bool(uint32_t *o, bool b, unsigned lo, unsigned hi)
{
   assert(lo == hi && hi < 32);
   *o |= util_bitpack_uint(b, lo % 32, hi % 32);
}

#ifndef MW
#define MW(x) x
#define NIL_SAMPLER_DEFINED_MW
#endif

#define SAMP_SET_U(o, NV, i, FIELD, val) \
   __set_u32(&o.bits[i], (val), DRF_LO(NV##_TEXSAMP##i##_##FIELD),\
                             DRF_HI(NV##_TEXSAMP##i##_##FIELD))

#define SAMP_SET_UF(o, NV, i, FIELD, val) \
   __set_ufixed(&o.bits[i], (val), DRF_LO(NV##_TEXSAMP##i##_##FIELD),\
                                DRF_HI(NV##_TEXSAMP##i##_##FIELD))

#define SAMP_SET_SF(o, NV, i, FIELD, val) \
   __set_sfixed(&o.bits[i], (val), DRF_LO(NV##_TEXSAMP##i##_##FIELD),\
                                DRF_HI(NV##_TEXSAMP##i##_##FIELD))

#define SAMP_SET_B(o, NV, i, FIELD, b) \
   __set_bool(&o.bits[i], (b), DRF_LO(NV##_TEXSAMP##i##_##FIELD),\
                            DRF_HI(NV##_TEXSAMP##i##_##FIELD))

#define SAMP_SET_E(o, NV, i, FIELD, E) \
   SAMP_SET_U(o, NV, i, FIELD, NV##_TEXSAMP##i##_##FIELD##_##E)

static inline uint32_t
vk_to_9097_address_mode(VkSamplerAddressMode addr_mode)
{
#define MODE(VK, NV) \
   [VK_SAMPLER_ADDRESS_MODE_##VK] = NV9097_TEXSAMP0_ADDRESS_U_##NV
   static const uint8_t vk_to_9097[] = {
      MODE(REPEAT,               WRAP),
      MODE(MIRRORED_REPEAT,      MIRROR),
      MODE(CLAMP_TO_EDGE,        CLAMP_TO_EDGE),
      MODE(CLAMP_TO_BORDER,      BORDER),
      MODE(MIRROR_CLAMP_TO_EDGE, MIRROR_ONCE_CLAMP_TO_EDGE),
   };
#undef MODE

   assert(addr_mode < ARRAY_SIZE(vk_to_9097));
   return vk_to_9097[addr_mode];
}

static uint32_t
vk_to_9097_texsamp_compare_op(VkCompareOp op)
{
#define OP(VK, NV) \
   [VK_COMPARE_OP_##VK] = NV9097_TEXSAMP0_DEPTH_COMPARE_FUNC_##NV
   ASSERTED static const uint8_t vk_to_9097[] = {
      OP(NEVER,            ZC_NEVER),
      OP(LESS,             ZC_LESS),
      OP(EQUAL,            ZC_EQUAL),
      OP(LESS_OR_EQUAL,    ZC_LEQUAL),
      OP(GREATER,          ZC_GREATER),
      OP(NOT_EQUAL,        ZC_NOTEQUAL),
      OP(GREATER_OR_EQUAL, ZC_GEQUAL),
      OP(ALWAYS,           ZC_ALWAYS),
   };
#undef OP

   assert(op < ARRAY_SIZE(vk_to_9097));
   assert(op == vk_to_9097[op]);

   return op;
}

static uint32_t
vk_to_9097_max_anisotropy(float max_anisotropy)
{
   if (max_anisotropy >= 16)
      return NV9097_TEXSAMP0_MAX_ANISOTROPY_ANISO_16_TO_1;

   if (max_anisotropy >= 12)
      return NV9097_TEXSAMP0_MAX_ANISOTROPY_ANISO_12_TO_1;

   uint32_t aniso_u32 = MAX2(0.0f, max_anisotropy);
   return aniso_u32 >> 1;
}

static uint32_t
vk_to_9097_trilin_opt(float max_anisotropy)
{
   /* No idea if we want this but matching nouveau */
   if (max_anisotropy >= 12)
      return 0;

   if (max_anisotropy >= 4)
      return 6;

   if (max_anisotropy >= 2)
      return 4;

   return 0;
}


static inline struct nvk_sampler_header
nil_sampler_pack(const struct nv_device_info *info,
                 const struct nil_sampler_state *state)
{
   struct nvk_sampler_header samp = {};

   SAMP_SET_U(samp, NV9097, 0, ADDRESS_U,
              vk_to_9097_address_mode(state->address_mode_u));
   SAMP_SET_U(samp, NV9097, 0, ADDRESS_V,
              vk_to_9097_address_mode(state->address_mode_v));
   SAMP_SET_U(samp, NV9097, 0, ADDRESS_P,
              vk_to_9097_address_mode(state->address_mode_w));

   if (state->compare_enable) {
      SAMP_SET_B(samp, NV9097, 0, DEPTH_COMPARE, true);
      SAMP_SET_U(samp, NV9097, 0, DEPTH_COMPARE_FUNC,
                 vk_to_9097_texsamp_compare_op(state->compare_op));
   }

   SAMP_SET_B(samp, NV9097, 0, S_R_G_B_CONVERSION, true);
   SAMP_SET_E(samp, NV9097, 0, FONT_FILTER_WIDTH, SIZE_2);
   SAMP_SET_E(samp, NV9097, 0, FONT_FILTER_HEIGHT, SIZE_2);

   if (state->anisotropy_enable) {
      SAMP_SET_U(samp, NV9097, 0, MAX_ANISOTROPY,
                 vk_to_9097_max_anisotropy(state->max_anisotropy));
   }

   switch (state->mag_filter) {
   case VK_FILTER_NEAREST:
      SAMP_SET_E(samp, NV9097, 1, MAG_FILTER, MAG_POINT);
      break;
   case VK_FILTER_LINEAR:
      SAMP_SET_E(samp, NV9097, 1, MAG_FILTER, MAG_LINEAR);
      break;
   default:
      UNREACHABLE("Invalid filter");
   }

   switch (state->min_filter) {
   case VK_FILTER_NEAREST:
      SAMP_SET_E(samp, NV9097, 1, MIN_FILTER, MIN_POINT);
      break;
   case VK_FILTER_LINEAR:
      if (state->anisotropy_enable)
         SAMP_SET_E(samp, NV9097, 1, MIN_FILTER, MIN_ANISO);
      else
         SAMP_SET_E(samp, NV9097, 1, MIN_FILTER, MIN_LINEAR);
      break;
   default:
      UNREACHABLE("Invalid filter");
   }

   switch (state->mipmap_mode) {
   case VK_SAMPLER_MIPMAP_MODE_NEAREST:
      SAMP_SET_E(samp, NV9097, 1, MIP_FILTER, MIP_POINT);
      break;
   case VK_SAMPLER_MIPMAP_MODE_LINEAR:
      SAMP_SET_E(samp, NV9097, 1, MIP_FILTER, MIP_LINEAR);
      break;
   default:
      UNREACHABLE("Invalid mipmap mode");
   }

   assert(info->cls_eng3d >= KEPLER_A);
   if (state->flags & VK_SAMPLER_CREATE_NON_SEAMLESS_CUBE_MAP_BIT_EXT) {
      SAMP_SET_E(samp, NVA097, 1, CUBEMAP_INTERFACE_FILTERING, USE_WRAP);
   } else {
      SAMP_SET_E(samp, NVA097, 1, CUBEMAP_INTERFACE_FILTERING, AUTO_SPAN_SEAM);
   }

   if (info->cls_eng3d >= MAXWELL_B) {
      switch (state->reduction_mode) {
      case VK_SAMPLER_REDUCTION_MODE_WEIGHTED_AVERAGE:
         SAMP_SET_E(samp, NVB197, 1, REDUCTION_FILTER, RED_NONE);
         break;
      case VK_SAMPLER_REDUCTION_MODE_MIN:
         SAMP_SET_E(samp, NVB197, 1, REDUCTION_FILTER, RED_MINIMUM);
         break;
      case VK_SAMPLER_REDUCTION_MODE_MAX:
         SAMP_SET_E(samp, NVB197, 1, REDUCTION_FILTER, RED_MAXIMUM);
         break;
      default:
         UNREACHABLE("Invalid reduction mode");
      }
   }

   SAMP_SET_SF(samp, NV9097, 1, MIP_LOD_BIAS, state->mip_lod_bias);

   assert(info->cls_eng3d >= KEPLER_A);
   if (state->unnormalized_coordinates) {
      SAMP_SET_E(samp, NVA097, 1, FLOAT_COORD_NORMALIZATION,
                                  FORCE_UNNORMALIZED_COORDS);
   } else {
      SAMP_SET_E(samp, NVA097, 1, FLOAT_COORD_NORMALIZATION,
                                  USE_HEADER_SETTING);
   }
   SAMP_SET_U(samp, NV9097, 1, TRILIN_OPT,
              vk_to_9097_trilin_opt(state->max_anisotropy));

   SAMP_SET_UF(samp, NV9097, 2, MIN_LOD_CLAMP, state->min_lod);
   SAMP_SET_UF(samp, NV9097, 2, MAX_LOD_CLAMP, state->max_lod);

   VkClearColorValue bc = state->border_color_value;

   /* If the image is sRGB, we have to sRGB encode the border color value
    * BEFORE we swizzle because the swizzle might move alpha around.
    */
   if (state->image_view_is_srgb) {
      for (uint32_t i = 0; i < 3; i++)
         bc.float32[i] = util_format_linear_to_srgb_float(bc.float32[i]);
   }

   /* Swizzle the border color as needed */
   const bool bc_is_int = vk_color_value_is_int(state->border_color);
   bc = vk_color_value_swizzle(bc,
      state->border_color_component_mapping, bc_is_int);

   uint8_t bc_srgb[3];
   if (state->image_view_is_srgb) {
      for (uint32_t i = 0; i < 3; i++)
         bc_srgb[i] = _mesa_float_to_unorm(bc.float32[i], 8);
   } else {
      /* Otherwise, we can assume no swizzle or that the border color is
       * transparent black or opaque white and there's nothing to do but
       * convert the (unswizzled) border color to sRGB.
       */
      for (unsigned i = 0; i < 3; i++)
         bc_srgb[i] = util_format_linear_float_to_srgb_8unorm(bc.float32[i]);
   }

   SAMP_SET_U(samp, NV9097, 2, S_R_G_B_BORDER_COLOR_R, bc_srgb[0]);
   SAMP_SET_U(samp, NV9097, 3, S_R_G_B_BORDER_COLOR_G, bc_srgb[1]);
   SAMP_SET_U(samp, NV9097, 3, S_R_G_B_BORDER_COLOR_B, bc_srgb[2]);

   SAMP_SET_U(samp, NV9097, 4, BORDER_COLOR_R, bc.uint32[0]);
   SAMP_SET_U(samp, NV9097, 5, BORDER_COLOR_G, bc.uint32[1]);
   SAMP_SET_U(samp, NV9097, 6, BORDER_COLOR_B, bc.uint32[2]);
   SAMP_SET_U(samp, NV9097, 7, BORDER_COLOR_A, bc.uint32[3]);

   return samp;
}

#undef SAMP_SET_U
#undef SAMP_SET_UF
#undef SAMP_SET_SF
#undef SAMP_SET_B
#undef SAMP_SET_E
#undef FIXED_FRAC_BITS
#ifdef NIL_SAMPLER_DEFINED_MW
#undef MW
#undef NIL_SAMPLER_DEFINED_MW
#endif
#endif
