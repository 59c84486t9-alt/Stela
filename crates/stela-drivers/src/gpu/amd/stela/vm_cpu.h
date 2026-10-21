/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_VM_CPU_H
#define STELA_AMD_VM_CPU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Native CPU entry writer only. The owner has already waited on real BO/DMA
 * reservations, validated generation-specific PDE/PTE flags and exclusivity,
 * and keeps all table and backing DMA memory resident until hardware no longer
 * uses it. This API neither creates a VM nor publishes mappings to the GPU. */
struct stela_amd_vm_cpu_update {
   uint64_t table_bytes;
   uint64_t table_offset;
   uint64_t address;
   uint64_t flags;
   uint32_t count;
   uint32_t increment;
   /* Optional actual DMA CPU-page array. With no array, address is a contiguous
    * GPU physical address; with an array it is a byte offset into those pages. */
   const uint64_t *pages_addr;
   uint64_t num_pages;
   uint32_t cpu_page_shift;
   bool override_pte;
};

struct stela_amd_vm_cpu_ops {
   /* Return the real synchronous CPU mapping for the complete requested range,
    * or NULL. It stays mapped until this call returns. No ownership transfers. */
   void *(*map_table)(void *context, uint64_t offset, uint64_t bytes);
   /* Invoke the actual initialized GMC's override policy, including NUMA and
    * coherency where applicable. No guessed flags or substitute policy. */
   void (*override_flags)(void *context, uint64_t address, uint64_t *flags);
   /* Invoke the actual GMC PTE/PDE encoder and architecture-correct page write.
    * This must complete synchronously and cannot fail for the mapped range. */
   void (*set_pte_pde)(void *context, void *mapping, uint32_t index,
                       uint64_t address, uint64_t flags);
};

enum stela_amd_vm_cpu_status {
   STELA_AMD_VM_CPU_OK,
   STELA_AMD_VM_CPU_INVALID,
   STELA_AMD_VM_CPU_MAPPING_UNAVAILABLE,
};

/* Numeric bounds and DMA-array indices are checked before any callback or
 * destination write. All callbacks are mandatory; no successful defaults.
 * Pointers and context must satisfy their C lifetime/alignment contracts; written
 * must not alias inputs, context or destination memory.
 * Zero entries succeed without callbacks. Error results write zero entries.
 * On success the native owner still must complete the retained TLB-sequence,
 * memory-ordering, reset-lock and HDP/TLB commit before hardware may use changes.
 */
enum stela_amd_vm_cpu_status
stela_amd_vm_cpu_write(const struct stela_amd_vm_cpu_update *update,
                       const struct stela_amd_vm_cpu_ops *ops, void *context,
                       uint32_t *written);

#endif
