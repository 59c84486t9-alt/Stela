/*
 * Copyright 2012 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Pure sampler policy retained from Mesa 31e9a6b2e95e30d84bf3177d1f497d063e59b6b2,
 * gallium/drivers/radeonsi/si_state.c. No frontend or allocation lifecycle is retained.
 */

/* Exact original function bytes, compiled with test-only containers. */
/* is_wrap_mode_legal: SHA256 7746b94e7d12d71c273e53e5dca91d75ef88d1ec6d30424b2bbfcd45d48422e8 */
/* si_tex_wrap: SHA256 d721d9efb51157590ce0cd2cb4068522db9d13139f5df824a90ef657fe4b4f4c */
/* si_tex_mipfilter: SHA256 cc65ff8e84f80b434897cbff035e0480e2fa5a70e7de67f710af7d9a21cfe05e */
/* si_tex_compare: SHA256 ab07c67338f050a09fffa922e4103c120a2cac8d9666076e70428b860294794c */
/* si_tex_filter: SHA256 e78dcf6dc8068841b1a568bcde505f497245049247dc6d55d78d4daf0e8caf53 */
/* si_tex_aniso_filter: SHA256 9aaf456bd05a2dd458943b08973daca2304dea9f75df1820e3a2c303b2fd686c */
/* si_tex_filter_mode: SHA256 d52ad2bd5f57818d7010af47e139272be7157bffc03312a77eecef67814be349 */
static unsigned is_wrap_mode_legal(struct si_screen *screen, unsigned wrap)
{
   if (!screen->info.compiler_info.has_3d_cube_border_color_mipmap) {
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
