/*
 * Copyright 2012 Advanced Micro Devices, Inc.
 * Copyright 2013 Advanced Micro Devices, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Minimal pure policies retained from Mesa 31e9a6b2e95e30d84bf3177d1f497d063e59b6b2.
 * Original paths/functions and unchanged donor hashes are in compute_policy_reference.h.
 */
#include "compute_policy.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_shader_util.h"
#include "amd/common/sid.h"

static unsigned
get_shader_prefetch_size(const struct radeon_info *info, unsigned binary_size)
{
   /* This excludes arrays of constants after instructions. */
   return ac_get_instr_prefetch_size(info->gfx_level,
                                     info->instr_prefetch_distance,
                                     binary_size);

}

static unsigned
encode_vgprs(const struct radeon_info *info, unsigned wave_size,
             const struct ac_shader_config *config)
{
   assert(info->gfx_level >= GFX10 || wave_size == 64);

   return DIV_ROUND_UP(config->num_vgprs,
                       (info->compiler_info.wave64_vgpr_encode_granularity *
                        (wave_size == 32 ? 2 : 1))) - 1;
}

static unsigned
encode_sgprs(const struct radeon_info *info, const struct ac_shader_config *config)
{
   if (info->gfx_level >= GFX10)
      return 0; /* Gfx10+ don't have the SGPRS field and always allocate 128 SGPRs. */

   return config->num_sgprs / 8 - 1;
}

static bool
mem_ordered(const struct radeon_info *info,
             const struct stela_amd_compute_policy *state,
             const struct ac_shader_config *config)
{
   if (info->gfx_level < GFX10 || info->gfx_level >= GFX12)
      return false;

   /* Return true if both types of VMEM that return something are used. */
   return state->uses_vmem_sampler_or_bvh &&
          (state->uses_vmem_load_other ||
           config->scratch_bytes_per_wave);
}


void
stela_amd_compute_policy(const struct radeon_info *info,
                          const struct stela_amd_compute_policy *state,
                          struct ac_shader_config *config)
{
   config->rsrc1 = S_00B848_VGPRS(encode_vgprs(info, state->wave_size, config)) |
                          S_00B848_SGPRS(encode_sgprs(info, config)) |
                          S_00B848_DX10_CLAMP(info->gfx_level < GFX12) |
                          S_00B848_MEM_ORDERED(mem_ordered(info, state, config)) |
                          S_00B848_FLOAT_MODE(config->float_mode) |
                          /* This is needed for CWSR, but it causes halts to work differently. */
                          S_00B848_PRIV(info->gfx_level == GFX11);

   config->rsrc2 = S_00B84C_USER_SGPR(state->cs_num_user_sgprs) |
                          S_00B84C_SCRATCH_EN(config->scratch_bytes_per_wave > 0) |
                          S_00B84C_TGID_X_EN(state->uses_sysval_workgroup_id_x) |
                          S_00B84C_TGID_Y_EN(state->uses_sysval_workgroup_id_y) |
                          S_00B84C_TGID_Z_EN(state->uses_sysval_workgroup_id_z) |
                          S_00B84C_TG_SIZE_EN(state->uses_sgpr_tg_size) |
                          S_00B84C_TIDIG_COMP_CNT(state->uses_sysval_local_invocation_id_z
                                                     ? 2
                                                     : state->uses_sysval_local_invocation_id_y ? 1 : 0) |
                          S_00B84C_LDS_SIZE(ac_shader_encode_lds_size(config->lds_size, info->gfx_level, state->stage));

   /* COMPUTE_PGM_RSRC3 is only present on GFX10+ and GFX940+. */
   config->rsrc3 = S_00B8A0_SHARED_VGPR_CNT(config->num_shared_vgprs / 8);

   if (info->gfx_level >= GFX12)
      config->rsrc3 |= S_00B8A0_INST_PREF_SIZE_GFX12(get_shader_prefetch_size(info, state->binary_size));
   else if (info->gfx_level >= GFX11)
      config->rsrc3 |= S_00B8A0_INST_PREF_SIZE_GFX11(get_shader_prefetch_size(info, state->binary_size));
}
