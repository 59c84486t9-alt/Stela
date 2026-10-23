/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_LLVM_COMPUTE_H
#define STELA_AMD_LLVM_COMPUTE_H

struct ac_compiler_info;
struct ac_shader_config;
struct nir_shader;

enum stela_amd_llvm_compute_status {
   STELA_AMD_LLVM_COMPUTE_OK,
   STELA_AMD_LLVM_COMPUTE_INVALID,
   STELA_AMD_LLVM_COMPUTE_UNSUPPORTED,
   STELA_AMD_LLVM_COMPUTE_CONFIG_MISMATCH,
};

/* Original LLVM .AMDGPU.config does not describe NIR's inttoptr-based LDS
 * allocation. After parsing the actual matching binary, retain the compute
 * frontend's exact fixed NIR allocation, as the original RadeonSI/RADV drivers
 * do. compiler must belong to that actual target/device and shader must be the
 * same specialized, final NIR used for compilation. This does not authenticate
 * independently supplied records, allocate storage, publish a VM or submit work.
 *
 * Only config.lds_size changes. Raw emitted rsrc2 remains untouched, including
 * its independent LDS field. The compute producer subsequently rebuilds PM4
 * from this final size through the original generation-specific encoding.
 * A zero parser value or matching already-finalized byte size is accepted;
 * incompatible values, variable storage and unrepresentable sizes are refused
 * atomically. Exact dynamic AS3 specialization belongs in the pipeline key.
 */
enum stela_amd_llvm_compute_status
stela_amd_llvm_finalize_compute_lds(const struct ac_compiler_info *compiler,
                                    const struct nir_shader *shader,
                                    struct ac_shader_config *config);

#endif
