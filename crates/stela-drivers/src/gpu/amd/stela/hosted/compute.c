/* SPDX-License-Identifier: MIT */
#include "compute.h"
#include "compute_policy.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_shader_util.h"
#include "amd/common/sid.h"
#include "compiler/nir/nir.h"
#include <string.h>

static enum stela_amd_compute_status
buffer_status(enum stela_amd_buffer_status status)
{
   switch (status) {
   case STELA_AMD_BUFFER_OK: return STELA_AMD_COMPUTE_OK;
   case STELA_AMD_BUFFER_INVALID: return STELA_AMD_COMPUTE_INVALID;
   case STELA_AMD_BUFFER_UNSUPPORTED: return STELA_AMD_COMPUTE_UNSUPPORTED;
   case STELA_AMD_BUFFER_DEVICE_INFO_UNAVAILABLE: return STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE;
   }
   return STELA_AMD_COMPUTE_INVALID;
}

static bool
power_of_two(unsigned value)
{
   return value && !(value & (value - 1));
}

static bool
take_arg(const struct ac_shader_args *args, struct ac_arg arg,
          enum ac_arg_regfile file, unsigned size, unsigned offset,
          bool taken[AC_MAX_ARGS])
{
   if (!arg.used || arg.arg_index >= args->arg_count || taken[arg.arg_index] ||
       args->args[arg.arg_index].file != file || args->args[arg.arg_index].size != size ||
       args->args[arg.arg_index].offset != offset || args->args[arg.arg_index].skip ||
       args->args[arg.arg_index].pending_vmem || args->args[arg.arg_index].preserved)
      return false;
   taken[arg.arg_index] = true;
   return true;
}

/* Same VMEM categories as si_shader_variant_info.c for the supported global
 * integer-buffer path. Refuse unowned resource classes instead of assuming
 * their cache, descriptor or MEM_ORDERED policy. The original pure policy still
 * retains and tests both VMEM categories independently against its donor.
 */
static bool
shader_usage(const nir_shader *shader, struct stela_amd_compute_policy *state)
{
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type == nir_instr_type_tex)
               return false;
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            const nir_intrinsic_instr *intr = nir_instr_as_intrinsic(instr);
            switch (intr->intrinsic) {
            case nir_intrinsic_load_global:
            case nir_intrinsic_load_global_amd:
               state->uses_vmem_load_other = true;
               break;
            case nir_intrinsic_store_global:
            case nir_intrinsic_store_global_amd:
            case nir_intrinsic_load_scalar_arg_amd:
            case nir_intrinsic_load_scalar_arg_wg_div_amd:
            case nir_intrinsic_load_vector_arg_amd:
            case nir_intrinsic_load_ttmp_register_amd:
            case nir_intrinsic_load_ttmp_register_wg_div_amd:
            case nir_intrinsic_load_workgroup_id:
            case nir_intrinsic_load_local_invocation_id:
            case nir_intrinsic_load_shared:
            case nir_intrinsic_store_shared:
            case nir_intrinsic_barrier:
               break;
            default:
               return false;
            }
         }
      }
   }
   return true;
}

enum stela_amd_compute_status
stela_amd_build_compute_pipeline(const struct radeon_info *info,
                                 const struct stela_amd_compute_binary *binary,
                                 const struct stela_amd_buffer_view *code,
                                 const struct stela_amd_compute_binding *bindings,
                                 uint32_t binding_count,
                                 struct stela_amd_compute_pipeline *pipeline)
{
   if (!info || !binary || !binary->shader || !binary->args || !binary->config ||
       !code || !pipeline || (binding_count && !bindings) || binding_count > 8)
      return STELA_AMD_COMPUTE_INVALID;
   struct stela_amd_raw_buffer_facts facts;
   enum stela_amd_compute_status status =
      buffer_status(stela_amd_query_raw_buffer_facts(info, &facts));
   if (status != STELA_AMD_COMPUTE_OK)
      return status;
   const struct ac_compiler_info *compiler = &info->compiler_info;
   if (!info->num_se || !info->max_se || info->max_se > AMD_MAX_SE ||
       info->num_se > info->max_se ||
       !(S_00B858_SH0_CU_EN(info->spi_cu_en) |
         S_00B858_SH1_CU_EN(info->spi_cu_en)) ||
       info->num_cu < info->num_se || !info->max_good_cu_per_sa ||
       !info->max_sa_per_se || !compiler->max_waves_per_simd ||
       !compiler->num_simd_per_compute_unit || !compiler->max_sgpr_alloc ||
       !compiler->max_vgpr_alloc || !compiler->lds_size_per_workgroup ||
       !power_of_two(compiler->wave64_vgpr_encode_granularity) ||
       compiler->wave64_vgpr_encode_granularity > UINT32_MAX / 2)
      return STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE;
   if (ac_get_gfx_level(info->family) != info->gfx_level)
      return STELA_AMD_COMPUTE_INVALID;
   if (binary->family != info->family || binary->gfx_level != info->gfx_level)
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   if ((binary->wave_size != 32 && binary->wave_size != 64) ||
       (binary->wave_size == 32 && info->gfx_level < GFX10))
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   const nir_shader *shader = binary->shader;
   const struct ac_shader_args *args = binary->args;
   const struct ac_shader_config *config = binary->config;
   if (shader->info.stage != MESA_SHADER_COMPUTE || shader->info.workgroup_size_variable ||
       shader->info.cs.has_variable_shared_mem || args->return_count)
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   if (!binary->executable_bytes || binary->executable_bytes % 4 ||
       binary->code_bytes < binary->executable_bytes ||
       args->arg_count > AC_MAX_ARGS || !config->num_sgprs || !config->num_vgprs)
      return STELA_AMD_COMPUTE_INVALID;
   if (config->scratch_bytes_per_wave || args->ring_offsets.used)
      return STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE;
   if (config->num_sgprs > compiler->max_sgpr_alloc ||
       config->num_vgprs > compiler->max_vgpr_alloc ||
       config->num_sgprs < args->num_sgprs_used ||
       config->num_vgprs < args->num_vgprs_used ||
       (info->gfx_level < GFX10 && config->num_sgprs % 8) ||
       config->num_shared_vgprs % 8 ||
       (info->gfx_level < GFX10 && config->num_shared_vgprs &&
        (info->has_graphics || info->family < CHIP_GFX940)) ||
       config->lds_size != shader->info.shared_size ||
       config->lds_size > compiler->lds_size_per_workgroup)
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   if (config->float_mode > G_00B848_FLOAT_MODE(UINT32_MAX) ||
       config->num_shared_vgprs / 8 > G_00B8A0_SHARED_VGPR_CNT(UINT32_MAX))
      return STELA_AMD_COMPUTE_INVALID;
   const unsigned grain = compiler->wave64_vgpr_encode_granularity *
                          (binary->wave_size == 32 ? 2 : 1);
   if (config->num_vgprs > UINT32_MAX - grain + 1 ||
       DIV_ROUND_UP(config->num_vgprs, grain) - 1 >
       G_00B848_VGPRS(UINT32_MAX))
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   const unsigned lds_grain = ac_shader_get_lds_alloc_granularity(info->gfx_level);
   if (config->lds_size > UINT32_MAX - lds_grain + 1 ||
       ac_shader_encode_lds_size(config->lds_size, info->gfx_level, MESA_SHADER_COMPUTE) >
       G_00B84C_LDS_SIZE(UINT32_MAX) ||
       (info->gfx_level < GFX10 && config->num_sgprs / 8 - 1 >
        G_00B848_SGPRS(UINT32_MAX)))
      return STELA_AMD_COMPUTE_UNSUPPORTED;

   struct stela_amd_compute_pipeline result = {0};
   struct stela_amd_compute_policy policy = {
      .stage = shader->info.stage, .wave_size = binary->wave_size,
      .binary_size = binary->executable_bytes,
   };
   if (!shader->options || !shader->options->max_workgroup_invocations)
      return STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE;
   const unsigned max_threads = shader->options->max_workgroup_invocations;
   uint64_t threads = 1;
   for (unsigned axis = 0; axis < 3; axis++) {
      const unsigned block = shader->info.workgroup_size[axis];
      if (!block || block > max_threads)
         return STELA_AMD_COMPUTE_INVALID;
      threads *= block;
      result.block_size[axis] = block;
   }
   if (threads > max_threads || !shader_usage(shader, &policy))
      return STELA_AMD_COMPUTE_UNSUPPORTED;

   bool taken[AC_MAX_ARGS] = {false};
   unsigned user_count = 0;
   for (unsigned i = 0; i < binding_count; i++) {
      const struct stela_amd_compute_binding *binding = &bindings[i];
      if (!take_arg(args, binding->argument, AC_ARG_SGPR, 2, user_count, taken))
         return STELA_AMD_COMPUTE_INVALID;
      uint64_t address;
      status = buffer_status(stela_amd_buffer_view_address(info, &binding->view, &address));
      if (status != STELA_AMD_COMPUTE_OK)
         return status;
      result.user_sgprs[user_count++] = address;
      result.user_sgprs[user_count++] = address >> 32;
   }
   policy.cs_num_user_sgprs = user_count;
   result.user_sgpr_count = user_count;
   unsigned sgprs = user_count;
   for (unsigned axis = 0; axis < 3; axis++) {
      if (!args->workgroup_ids[axis].used || info->gfx_level >= GFX12)
         continue;
      if (!take_arg(args, args->workgroup_ids[axis], AC_ARG_SGPR, 1, sgprs++, taken))
         return STELA_AMD_COMPUTE_UNSUPPORTED;
   }
   policy.uses_sysval_workgroup_id_x = args->workgroup_ids[0].used;
   policy.uses_sysval_workgroup_id_y = args->workgroup_ids[1].used;
   policy.uses_sysval_workgroup_id_z = args->workgroup_ids[2].used;
   if (args->tg_size.used &&
       !take_arg(args, args->tg_size, AC_ARG_SGPR, 1, sgprs++, taken))
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   policy.uses_sgpr_tg_size = args->tg_size.used;
   if (args->scratch_offset.used &&
       !take_arg(args, args->scratch_offset, AC_ARG_SGPR, 1, sgprs++, taken))
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   unsigned vgprs = 0;
   if (args->local_invocation_ids_packed.used) {
      if (!compiler->local_invocation_ids_packed || args->local_invocation_id_x.used ||
          args->local_invocation_id_y.used || args->local_invocation_id_z.used ||
          !take_arg(args, args->local_invocation_ids_packed, AC_ARG_VGPR, 1, vgprs++, taken))
         return STELA_AMD_COMPUTE_UNSUPPORTED;
      /* This ABI declares the complete packed XYZ input. */
      policy.uses_sysval_local_invocation_id_y = true;
      policy.uses_sysval_local_invocation_id_z = true;
   } else {
      const struct ac_arg local[] = {args->local_invocation_id_x,
                                     args->local_invocation_id_y,
                                     args->local_invocation_id_z};
      for (unsigned axis = 0; axis < 3; axis++) {
         if (!local[axis].used)
            continue;
         if (compiler->local_invocation_ids_packed ||
             !take_arg(args, local[axis], AC_ARG_VGPR, 1, vgprs++, taken))
            return STELA_AMD_COMPUTE_UNSUPPORTED;
      }
      if ((local[2].used && !local[1].used) || (local[1].used && !local[0].used))
         return STELA_AMD_COMPUTE_UNSUPPORTED;
      policy.uses_sysval_local_invocation_id_y = local[1].used;
      policy.uses_sysval_local_invocation_id_z = local[2].used;
   }
   if (sgprs != args->num_sgprs_used || vgprs != args->num_vgprs_used)
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   for (unsigned i = 0; i < args->arg_count; i++) {
      if (!taken[i])
         return STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE;
   }

   if (info->instr_prefetch_distance > (UINT32_MAX - 128) / 64 ||
       binary->executable_bytes > UINT32_MAX - info->instr_prefetch_distance * 64 - 128)
      return STELA_AMD_COMPUTE_INVALID;
   const unsigned required_code_bytes =
      ac_align_shader_binary_for_prefetch(info->gfx_level, info->instr_prefetch_distance,
                                          binary->executable_bytes);
   if (code->required_alignment < 256 || code->range < required_code_bytes ||
       code->range < binary->code_bytes)
      return STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE;
   status = buffer_status(stela_amd_buffer_view_address(info, code, &result.program_va));
   if (status != STELA_AMD_COMPUTE_OK)
      return status;
   struct ac_shader_config finalized = *config;
   stela_amd_compute_policy(info, &policy, &finalized);
   result.rsrc1 = finalized.rsrc1;
   result.rsrc2 = finalized.rsrc2;
   result.rsrc3 = finalized.rsrc3;
   result.wave_size = binary->wave_size;
   const unsigned waves = DIV_ROUND_UP(threads, binary->wave_size);
   const unsigned threadgroups_per_cu = info->gfx_level >= GFX10 && waves == 1 ? 2 : 1;
   if (info->gfx_level == GFX9 &&
       info->max_good_cu_per_sa > G_00B854_WAVES_PER_SH(UINT32_MAX) /
                                 compiler->num_simd_per_compute_unit /
                                 compiler->max_waves_per_simd)
      return STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE;
   result.resource_limits = ac_get_compute_resource_limits(info, waves, 0, threadgroups_per_cu);
   uint32_t written;
   if (stela_amd_compute_pipeline(info, &result, NULL, 0, &written) !=
       STELA_AMD_COMMAND_BUFFER_TOO_SMALL || !written)
      return STELA_AMD_COMPUTE_UNSUPPORTED;
   *pipeline = result;
   return STELA_AMD_COMPUTE_OK;
}
