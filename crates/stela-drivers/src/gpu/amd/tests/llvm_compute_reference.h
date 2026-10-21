/*
 * Copyright 2012 Advanced Micro Devices, Inc.
 * Copyright 2013 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Exact donor from Mesa 31e9a6b2e95e30d84bf3177d1f497d063e59b6b2,
 * src/gallium/drivers/radeonsi/gfx/si_shader.c.
 * Function SHA256 ff8eb230fe15b559ad2a946ced5607e5ec3a694124a26ebf85d8e533b588cea1
 * Compiled only with minimal model containers in air_shared_test.c.
 */
unsigned si_calculate_needed_lds_size(enum amd_gfx_level gfx_level, struct si_shader *shader)
{
   mesa_shader_stage stage =
      shader->is_gs_copy_shader ? MESA_SHADER_VERTEX : shader->selector->stage;
   unsigned lds_size = 0;

   if (gfx_level >= GFX9 && stage <= MESA_SHADER_GEOMETRY &&
       (stage == MESA_SHADER_GEOMETRY || shader->key.ge.as_ngg)) {
      unsigned size_in_dw = shader->key.ge.as_ngg ? shader->ngg.info.esgs_lds_size
                                                  : shader->gs_info.esgs_lds_size;

      if (stage == MESA_SHADER_GEOMETRY && shader->key.ge.as_ngg)
         size_in_dw += shader->ngg.info.ngg_out_lds_size;

      lds_size = size_in_dw * 4;
   }

   if (stage == MESA_SHADER_COMPUTE ||
       stage == MESA_SHADER_TASK ||
       stage == MESA_SHADER_MESH) {
      lds_size = shader->info.shared_size;
   }

   /* Check that the LDS size is within hw limits. */
   assert(lds_size <= shader->selector->screen->info.compiler_info.lds_size_per_workgroup);
   return lds_size;
}
