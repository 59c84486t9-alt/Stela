/* SPDX-License-Identifier: MIT */
/* A compute shader allocates exactly its fixed NIR shared size, within the
 * target's per-workgroup LDS limit. No vendor compiler algorithm is changed.
 */
#include "llvm_compute.h"
#include "amd/common/ac_binary.h"
#include "amd/common/ac_gpu_info.h"
#include "amd/common/ac_shader_util.h"
#include "amd/common/sid.h"
#include "compiler/nir/nir.h"
#include <stdint.h>

enum stela_amd_llvm_compute_status
stela_amd_llvm_finalize_compute_lds(const struct ac_compiler_info *compiler,
                                    const struct nir_shader *shader,
                                    struct ac_shader_config *config)
{
   if (!compiler || !shader || !config)
      return STELA_AMD_LLVM_COMPUTE_INVALID;
   if (compiler->gfx_level < GFX6 || compiler->gfx_level > GFX12_1 ||
       !compiler->lds_size_per_workgroup || shader->info.stage != MESA_SHADER_COMPUTE ||
       shader->info.workgroup_size_variable || shader->info.cs.has_variable_shared_mem)
      return STELA_AMD_LLVM_COMPUTE_UNSUPPORTED;
   const unsigned bytes = shader->info.shared_size;
   const unsigned grain = ac_shader_get_lds_alloc_granularity(compiler->gfx_level);
   if (bytes > compiler->lds_size_per_workgroup || bytes > UINT32_MAX - grain + 1 ||
       ac_shader_encode_lds_size(bytes, compiler->gfx_level, MESA_SHADER_COMPUTE) >
          G_00B84C_LDS_SIZE(UINT32_MAX))
      return STELA_AMD_LLVM_COMPUTE_UNSUPPORTED;
   if (config->lds_size && config->lds_size != bytes)
      return STELA_AMD_LLVM_COMPUTE_CONFIG_MISMATCH;
   config->lds_size = bytes;
   return STELA_AMD_LLVM_COMPUTE_OK;
}
