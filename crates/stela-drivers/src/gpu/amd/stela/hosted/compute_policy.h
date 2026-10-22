/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_COMPUTE_POLICY_H
#define STELA_AMD_COMPUTE_POLICY_H

#include "compiler/shader_enums.h"
#include <stdbool.h>

struct radeon_info;
struct ac_shader_config;

/* Private hosted policy inputs, populated from the actual compiler ABI/NIR.
 * These are shader facts, never hardware capability flags or a device query.
 * The checked compute adapter owns bounds and unsupported-path validation.
 */
struct stela_amd_compute_policy {
   mesa_shader_stage stage;
   unsigned wave_size;
   unsigned binary_size;
   unsigned cs_num_user_sgprs;
   bool uses_sysval_workgroup_id_x;
   bool uses_sysval_workgroup_id_y;
   bool uses_sysval_workgroup_id_z;
   bool uses_sysval_local_invocation_id_y;
   bool uses_sysval_local_invocation_id_z;
   bool uses_sgpr_tg_size;
   bool uses_vmem_sampler_or_bvh;
   bool uses_vmem_load_other;
};

/* Fills COMPUTE_PGM_RSRC1..3 from the compiler config and shader facts. The
 * checked adapter validates every field's capacity before calling this.
 */
void stela_amd_compute_policy(const struct radeon_info *info,
                              const struct stela_amd_compute_policy *state,
                              struct ac_shader_config *config);

#endif
