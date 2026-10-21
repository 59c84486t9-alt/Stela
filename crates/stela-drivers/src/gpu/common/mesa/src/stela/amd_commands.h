/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_COMMANDS_H
#define STELA_AMD_COMMANDS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

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

/* The Rust native facade checks these same layouts. This is a native x86-64
 * interface; it is never used as the translated ARM guest's wire format. */
#ifdef __cplusplus
#define STELA_AMD_STATIC_ASSERT static_assert
#else
#define STELA_AMD_STATIC_ASSERT _Static_assert
#endif
STELA_AMD_STATIC_ASSERT(sizeof(enum stela_amd_command_status) == 4, "status ABI");
STELA_AMD_STATIC_ASSERT(sizeof(struct stela_amd_compute_pipeline) == 112, "pipeline ABI");
STELA_AMD_STATIC_ASSERT(offsetof(struct stela_amd_compute_pipeline, block_size) == 24, "block ABI");
STELA_AMD_STATIC_ASSERT(offsetof(struct stela_amd_compute_pipeline, wave_size) == 36, "wave ABI");
STELA_AMD_STATIC_ASSERT(offsetof(struct stela_amd_compute_pipeline, user_sgprs) == 44, "SGPR ABI");
STELA_AMD_STATIC_ASSERT(sizeof(struct stela_amd_compute_dispatch) == 16, "dispatch ABI");
STELA_AMD_STATIC_ASSERT(offsetof(struct stela_amd_compute_dispatch, threads) == 12, "threads ABI");
STELA_AMD_STATIC_ASSERT(offsetof(struct stela_amd_compute_dispatch, ordered) == 13, "ordered ABI");
STELA_AMD_STATIC_ASSERT(offsetof(struct stela_amd_compute_dispatch, tunnel) == 14, "tunnel ABI");
#undef STELA_AMD_STATIC_ASSERT

/* Scalar native preamble interface avoids reproducing Mesa-private structure
 * layouts in Rust. This has exactly the same validation/output contract. */
enum stela_amd_command_status
stela_amd_compute_preamble_native(const struct radeon_info *info,
                                 uint64_t border_color_va, uint32_t dispatch_interleave,
                                 uint32_t *output, uint32_t capacity, uint32_t *written);

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
