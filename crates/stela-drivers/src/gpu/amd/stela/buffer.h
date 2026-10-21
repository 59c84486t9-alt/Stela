/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_BUFFER_H
#define STELA_AMD_BUFFER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct radeon_info;

/* Hosted native frontend interface, not a guest ABI or a buffer allocator.
 * info must be the actual initialized device information, including VM/cache
 * queries and compiler_info from the matching retained Mesa build. The owner
 * holds the real allocation's mappings, access rights and residency through GPU
 * completion. No flag here substitutes for that lifetime/permission contract.
 */
enum stela_amd_buffer_status {
   STELA_AMD_BUFFER_OK,
   STELA_AMD_BUFFER_INVALID,
   STELA_AMD_BUFFER_UNSUPPORTED,
   STELA_AMD_BUFFER_DEVICE_INFO_UNAVAILABLE,
};

struct stela_amd_buffer_view {
   uint64_t allocation_va;
   uint64_t allocation_bytes;
   uint64_t offset;
   uint64_t range;
   /* Required by the actual compiled resource binding, not guessed from an
    * Apple CPU profile or borrowed from another graphics API's alignment. */
   uint64_t required_alignment;
};

/* Facts only about this descriptor encoding and the supplied device. These are
 * not MTLDevice limits, a Metal GPU family, texture-format support or a promise
 * that robust accesses/cache/VM synchronization have been implemented.
 */
struct stela_amd_raw_buffer_facts {
   uint32_t descriptor_dwords;
   uint32_t descriptor_address_bits;
   uint32_t max_num_records; /* RAW stride is zero; NUM_RECORDS is exact bytes. */
   uint32_t cache_line_bytes;
   uint64_t allocation_alignment;
   uint64_t virtual_address_max; /* Original device query's exclusive limit. */
   uint64_t high_va_offset;
   uint64_t high_va_max;
   bool has_l2_uncached;
   bool has_smem_oob_access_bug;
   bool has_smem_with_null_prt_bug;
   bool has_desc_resource_level;
};

enum stela_amd_buffer_status
stela_amd_query_raw_buffer_facts(const struct radeon_info *info,
                                struct stela_amd_raw_buffer_facts *facts);

/* The same device/view/address validation used by the RAW builder, without its
 * UINT32 NUM_RECORDS restriction. Returns the owner's complete GPU VA, preserving
 * its canonical form; no descriptor, allocation or residency claim is created.
 * The current shared address encoding remains bounded to 48 bits. */
enum stela_amd_buffer_status
stela_amd_buffer_view_address(const struct radeon_info *info,
                              const struct stela_amd_buffer_view *view,
                              uint64_t *address);

/* Builds exactly the retained RAW descriptor (R32_FLOAT carrier, not a Metal
 * float-format capability). The output stays unchanged on errors. Empty/nil
 * views are refused; unbinding needs its own explicit frontend operation.
 * The exact range is preserved without API-specific bounds relaxation/padding.
 * A successful descriptor does not validate permissions or submit work. */
enum stela_amd_buffer_status
stela_amd_build_raw_buffer(const struct radeon_info *info,
                           const struct stela_amd_buffer_view *view,
                           uint32_t descriptor[4]);

#ifdef __cplusplus
}
#endif

#endif
