/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_COMMANDS_H
#define STELA_AMD_COMMANDS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct radeon_info;
struct ac_preamble_state;

/* Native backend interface, not a guest wire ABI. Device information must come
 * from the actual initialized GPU; pipeline resource words come from the shader
 * compiler. The caller owns GPU-VA mappings, residency, queue initialization,
 * scratch, cache barriers, fences and resource lifetimes through completion.
 * These functions encode commands only. They neither submit nor claim Metal
 * capability. A dispatch must follow the appropriate preamble and pipeline.
 */
enum stela_amd_command_status {
   STELA_AMD_COMMAND_OK,
   STELA_AMD_COMMAND_INVALID,
   STELA_AMD_COMMAND_UNSUPPORTED,
   STELA_AMD_COMMAND_BUFFER_TOO_SMALL,
};

#define STELA_AMD_COMPUTE_USER_SGPRS 16

struct stela_amd_compute_pipeline {
   uint64_t program_va;
   uint32_t rsrc1;
   uint32_t rsrc2;
   uint32_t rsrc3;
   uint32_t resource_limits;
   uint32_t block_size[3];
   uint32_t wave_size;
   uint32_t user_sgpr_count;
   uint32_t user_sgprs[STELA_AMD_COMPUTE_USER_SGPRS];
};

struct stela_amd_compute_dispatch {
   uint32_t size[3];
   /* false: complete threadgroups; true: threads, including a partial last
    * threadgroup as required by Metal dispatchThreads. */
   bool threads;
   bool ordered;
   /* Enable only when the native queue owner has allowed tunneling. */
   bool tunnel;
};

/* Output is unchanged on errors. BUFFER_TOO_SMALL reports the required dword
 * count through written; NULL output with zero capacity is a size query.
 * Invalid/unsupported inputs report zero written. No allocations are made.
 */
enum stela_amd_command_status
stela_amd_compute_preamble(const struct radeon_info *info,
                          const struct ac_preamble_state *state,
                          uint32_t *output, uint32_t capacity, uint32_t *written);

enum stela_amd_command_status
stela_amd_compute_pipeline(const struct radeon_info *info,
                          const struct stela_amd_compute_pipeline *pipeline,
                          uint32_t *output, uint32_t capacity, uint32_t *written);

enum stela_amd_command_status
stela_amd_compute_dispatch(const struct radeon_info *info,
                          const struct stela_amd_compute_pipeline *pipeline,
                          const struct stela_amd_compute_dispatch *dispatch,
                          uint32_t *output, uint32_t capacity, uint32_t *written);

#ifdef __cplusplus
}
#endif

#endif
