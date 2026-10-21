/*
 * Copyright 2012 Advanced Micro Devices, Inc.
 * Copyright 2013 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Minimal pure policies retained from Mesa 31e9a6b2e95e30d84bf3177d1f497d063e59b6b2.
 * Original paths/functions and unchanged donor hashes are in compute_policy_reference.h.
 */
#ifndef STELA_AMD_COMPUTE_POLICY_REFERENCE_H
#define STELA_AMD_COMPUTE_POLICY_REFERENCE_H

/* Original function and statement bytes, compiled only with synthetic fixture
 * container types supplied by the test. No production device is initialized.
 */
/* si_shader.c:unsigned si_shader_encode_vgprs SHA256 774ccf4fd8f996df7b64fe4897fb6fe0b97fd27364436e6e5a5e2e76d5359fd4 */
/* si_shader.c:unsigned si_get_shader_prefetch_size SHA256 7f5bddb4f82f4a6b9cbdcc128df02fd3bdc2ed5bd476d29374f4d1c3c03e3b2f */
/* si_state_shaders.cpp:si_shader_mem_ordered SHA256 87de2d3ecac46beaa01d2a89a9dfd1040b0db0a5ff12f9ad6df07abf51f87ba9 */
/* si_compute.c:compute-resource-words SHA256 4e04d72ceea266c48d90ea9d02e01fa25ea4c544ba08acabe47e1124013c90af */

unsigned si_get_shader_prefetch_size(struct si_shader *shader)
{
   struct si_screen *sscreen = shader->selector->screen;

   /* This excludes arrays of constants after instructions. */
   return ac_get_instr_prefetch_size(sscreen->info.gfx_level,
                                     sscreen->info.instr_prefetch_distance,
                                     shader->complete_shader_binary_size);

}

unsigned si_shader_encode_vgprs(struct si_shader *shader)
{
   struct radeon_info *info = &shader->selector->screen->info;
   assert(info->gfx_level >= GFX10 || shader->wave_size == 64);

   return DIV_ROUND_UP(shader->config.num_vgprs,
                       (info->compiler_info.wave64_vgpr_encode_granularity *
                        (shader->wave_size == 32 ? 2 : 1))) - 1;
}

unsigned si_shader_encode_sgprs(struct si_shader *shader)
{
   if (shader->selector->screen->info.gfx_level >= GFX10)
      return 0; /* Gfx10+ don't have the SGPRS field and always allocate 128 SGPRs. */

   return shader->config.num_sgprs / 8 - 1;
}

bool si_shader_mem_ordered(struct si_shader *shader)
{
   struct si_screen *sscreen = shader->selector->screen;

   if (sscreen->info.gfx_level < GFX10 || sscreen->info.gfx_level >= GFX12)
      return false;

   /* Return true if both types of VMEM that return something are used. */
   return shader->info.uses_vmem_sampler_or_bvh &&
          (shader->info.uses_vmem_load_other ||
           shader->config.scratch_bytes_per_wave);
}


static void
reference_compute_words(struct si_shader *shader)
{
   struct si_screen *sscreen = shader->selector->screen;
   struct si_shader_selector *sel = shader->selector;
      shader->config.rsrc1 = S_00B848_VGPRS(si_shader_encode_vgprs(shader)) |
                             S_00B848_SGPRS(si_shader_encode_sgprs(shader)) |
                             S_00B848_DX10_CLAMP(sscreen->info.gfx_level < GFX12) |
                             S_00B848_MEM_ORDERED(si_shader_mem_ordered(shader)) |
                             S_00B848_FLOAT_MODE(shader->config.float_mode) |
                             /* This is needed for CWSR, but it causes halts to work differently. */
                             S_00B848_PRIV(sscreen->info.gfx_level == GFX11);

      shader->config.rsrc2 = S_00B84C_USER_SGPR(shader->info.cs_num_user_sgprs) |
                             S_00B84C_SCRATCH_EN(shader->config.scratch_bytes_per_wave > 0) |
                             S_00B84C_TGID_X_EN(shader->info.uses_sysval_workgroup_id_x) |
                             S_00B84C_TGID_Y_EN(shader->info.uses_sysval_workgroup_id_y) |
                             S_00B84C_TGID_Z_EN(shader->info.uses_sysval_workgroup_id_z) |
                             S_00B84C_TG_SIZE_EN(shader->info.uses_sgpr_tg_size) |
                             S_00B84C_TIDIG_COMP_CNT(shader->info.uses_sysval_local_invocation_id_z
                                                        ? 2
                                                        : shader->info.uses_sysval_local_invocation_id_y ? 1 : 0) |
                             S_00B84C_LDS_SIZE(ac_shader_encode_lds_size(shader->config.lds_size, sscreen->info.gfx_level, sel->stage));

      /* COMPUTE_PGM_RSRC3 is only present on GFX10+ and GFX940+. */
      shader->config.rsrc3 = S_00B8A0_SHARED_VGPR_CNT(shader->config.num_shared_vgprs / 8);

      if (sscreen->info.gfx_level >= GFX12)
         shader->config.rsrc3 |= S_00B8A0_INST_PREF_SIZE_GFX12(si_get_shader_prefetch_size(shader));
      else if (sscreen->info.gfx_level >= GFX11)
         shader->config.rsrc3 |= S_00B8A0_INST_PREF_SIZE_GFX11(si_get_shader_prefetch_size(shader));

}

#endif
