/* SPDX-License-Identifier: MIT */
/* Stela's compute resource-word policy: each COMPUTE_PGM_RSRC field from the
 * compiler config and shader facts. Mesa's unchanged ac_* helpers supply the
 * per-generation LDS and instruction-prefetch encodings.
 */
#include "compute_policy.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_shader_util.h"
#include "amd/common/sid.h"

/* VGPR blocks minus one. Wave32 allocates in twice the wave64 granule. */
static unsigned
vgpr_blocks(const struct radeon_info *info, unsigned wave_size, unsigned vgprs)
{
   assert(info->gfx_level >= GFX10 || wave_size == 64);
   const unsigned granule =
      info->compiler_info.wave64_vgpr_encode_granularity * (wave_size == 32 ? 2 : 1);
   return DIV_ROUND_UP(vgprs, granule) - 1;
}

/* SGPR blocks of eight minus one; the compiler's count is block-aligned.
 * GFX10 onward has no field and always allocates 128 SGPRs.
 */
static unsigned
sgpr_blocks(const struct radeon_info *info, unsigned sgprs)
{
   return info->gfx_level >= GFX10 ? 0 : sgprs / 8 - 1;
}

/* GFX10 and GFX11 return sampler/BVH and other VMEM results out of order
 * unless MEM_ORDERED is set; a shader using both categories needs it.
 * Scratch accesses are VMEM loads too.
 */
static bool
mem_ordered(const struct radeon_info *info, const struct stela_amd_compute_policy *state,
            const struct ac_shader_config *config)
{
   return info->gfx_level >= GFX10 && info->gfx_level < GFX12 &&
          state->uses_vmem_sampler_or_bvh &&
          (state->uses_vmem_load_other || config->scratch_bytes_per_wave);
}

/* The local invocation ID components the hardware initializes, minus one. */
static unsigned
local_id_components(const struct stela_amd_compute_policy *state)
{
   if (state->uses_sysval_local_invocation_id_z)
      return 2;
   return state->uses_sysval_local_invocation_id_y ? 1 : 0;
}

/* Instruction prefetch size in RSRC3 starts at GFX11; GFX12 moved the field. */
static unsigned
instruction_prefetch(const struct radeon_info *info, unsigned binary_size)
{
   if (info->gfx_level < GFX11)
      return 0;
   const unsigned size =
      ac_get_instr_prefetch_size(info->gfx_level, info->instr_prefetch_distance, binary_size);
   return info->gfx_level >= GFX12 ? S_00B8A0_INST_PREF_SIZE_GFX12(size) :
                                     S_00B8A0_INST_PREF_SIZE_GFX11(size);
}

void
stela_amd_compute_policy(const struct radeon_info *info,
                         const struct stela_amd_compute_policy *state,
                         struct ac_shader_config *config)
{
   const enum amd_gfx_level gfx = info->gfx_level;
   config->rsrc1 = S_00B848_VGPRS(vgpr_blocks(info, state->wave_size, config->num_vgprs)) |
                   S_00B848_SGPRS(sgpr_blocks(info, config->num_sgprs)) |
                   S_00B848_DX10_CLAMP(gfx < GFX12) |
                   S_00B848_MEM_ORDERED(mem_ordered(info, state, config)) |
                   S_00B848_FLOAT_MODE(config->float_mode) |
                   /* GFX11 compute wave save/restore needs privileged waves. */
                   S_00B848_PRIV(gfx == GFX11);
   config->rsrc2 = S_00B84C_USER_SGPR(state->cs_num_user_sgprs) |
                   S_00B84C_SCRATCH_EN(config->scratch_bytes_per_wave > 0) |
                   S_00B84C_TGID_X_EN(state->uses_sysval_workgroup_id_x) |
                   S_00B84C_TGID_Y_EN(state->uses_sysval_workgroup_id_y) |
                   S_00B84C_TGID_Z_EN(state->uses_sysval_workgroup_id_z) |
                   S_00B84C_TG_SIZE_EN(state->uses_sgpr_tg_size) |
                   S_00B84C_TIDIG_COMP_CNT(local_id_components(state)) |
                   S_00B84C_LDS_SIZE(ac_shader_encode_lds_size(config->lds_size, gfx, state->stage));
   /* COMPUTE_PGM_RSRC3 exists on GFX10+ and GFX940+. */
   config->rsrc3 = S_00B8A0_SHARED_VGPR_CNT(config->num_shared_vgprs / 8) |
                   instruction_prefetch(info, state->binary_size);
}
