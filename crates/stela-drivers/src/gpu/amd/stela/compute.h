/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_COMPUTE_H
#define STELA_AMD_COMPUTE_H

#include "buffer.h"
#include "amd/common/ac_shader_args.h"
#include "amd/common/amd_family.h"
#include "stela/amd_commands.h"

#ifdef __cplusplus
extern "C" {
#endif

struct nir_shader;
struct ac_shader_config;

enum stela_amd_compute_status {
   STELA_AMD_COMPUTE_OK,
   STELA_AMD_COMPUTE_INVALID,
   STELA_AMD_COMPUTE_UNSUPPORTED,
   STELA_AMD_COMPUTE_DEVICE_INFO_UNAVAILABLE,
   STELA_AMD_COMPUTE_RESOURCE_OWNER_UNAVAILABLE,
};

/* Same-process compiler output, not a guest ABI. All pointers borrow the actual
 * shader/options/argument layout that produced this binary. wave_size is the
 * actual compiler-selected wave; executable_bytes excludes trailing constants,
 * while code_bytes covers the actual complete resident code/data image.
 * This record neither creates device info nor establishes resource residency.
 */
struct stela_amd_compute_binary {
   const struct nir_shader *shader;
   const struct ac_shader_args *args;
   const struct ac_shader_config *config;
   enum radeon_family family;
   enum amd_gfx_level gfx_level;
   uint32_t wave_size;
   uint32_t executable_bytes;
   uint32_t code_bytes;
};

/* The actual frontend callback's SGPR address-pair argument and the real
 * resource owner's view. Its owner must retain the correct read/write rights,
 * address space, residency, VM/cache publication and lifetime through fence
 * completion. Those requirements are not represented by caller-set booleans.
 */
struct stela_amd_compute_binding {
   struct ac_arg argument;
   struct stela_amd_buffer_view view;
};

/* Hosted frontend -> existing native command encoder. info must be the actual
 * initialized device, with matching compiler, topology, VM and prefetch facts.
 * code is its real, published code allocation/view with sufficient retained
 * prefetch padding and 256-byte program alignment. No allocation, upload,
 * shader replacement, cache flush, device initialization or submission occurs.
 * Missing scratch/descriptor/sampler owners remain explicit refusals.
 * Output is unchanged on every error.
 */
enum stela_amd_compute_status
stela_amd_build_compute_pipeline(const struct radeon_info *info,
                                 const struct stela_amd_compute_binary *binary,
                                 const struct stela_amd_buffer_view *code,
                                 const struct stela_amd_compute_binding *bindings,
                                 uint32_t binding_count,
                                 struct stela_amd_compute_pipeline *pipeline);

#ifdef __cplusplus
}
#endif
#endif
