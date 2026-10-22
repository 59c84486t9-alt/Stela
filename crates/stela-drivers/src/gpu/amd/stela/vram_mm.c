/* SPDX-License-Identifier: MIT */
#include "vram_mm.h"
#include "../include/asic_reg/bif/bif_4_1_d.h"
#include "../amdgpu/amdgpu_mm_access_core.h"
#include <stdatomic.h>

static uint32_t read32(void *context, uint32_t reg)
{
   volatile uint32_t *pointer = (volatile uint32_t *)((uint8_t *)context + reg * 4u);
   /* Original x86 readl/writel carry a compiler memory clobber. Keep CPU
    * buffer accesses ordered too; volatile alone only orders device accesses.
    * UC/device ordering is still the real x86 platform owner's obligation. */
   atomic_signal_fence(memory_order_seq_cst);
   uint32_t value = *pointer;
   atomic_signal_fence(memory_order_seq_cst);
   return value;
}
static void write32(void *context, uint32_t reg, uint32_t value)
{
   volatile uint32_t *pointer = (volatile uint32_t *)((uint8_t *)context + reg * 4u);
   atomic_signal_fence(memory_order_seq_cst);
   *pointer = value;
   atomic_signal_fence(memory_order_seq_cst);
}

enum stela_amd_vram_mm_status
stela_amd_vram_mm_read(void *registers, size_t register_bytes,
                       uint64_t vram_bytes, uint64_t position,
                       uint32_t *data, size_t size)
{
   uintptr_t base = (uintptr_t)registers, destination = (uintptr_t)data;
   /* Every pointer addition and the original signed loff_t increment is bounded
    * before entering the common loop. Actual allocation/lifetime and native
    * owner/ordering proofs are the mandatory caller contract, not these ints. */
   if (!registers || base % sizeof(uint32_t) || position % sizeof(uint32_t) ||
       size % sizeof(uint32_t) || (size && (!data || destination % sizeof(uint32_t))))
      return STELA_AMD_VRAM_MM_INVALID;
   if (register_bytes / sizeof(uint32_t) <= mmMM_INDEX ||
       register_bytes / sizeof(uint32_t) <= mmMM_DATA ||
       register_bytes / sizeof(uint32_t) <= mmMM_INDEX_HI ||
       register_bytes > (size_t)PTRDIFF_MAX || register_bytes > UINTPTR_MAX - base ||
       size > (size_t)PTRDIFF_MAX || (size && size > UINTPTR_MAX - destination) ||
       vram_bytes > INT64_MAX || position > vram_bytes || size > vram_bytes - position ||
       /* Original hi=~0 sentinel cannot initialize a first all-ones HI value.
        * Do not guess prior hardware state or change the retained algorithm. */
       (size && (position >> 31) == UINT32_MAX))
      return STELA_AMD_VRAM_MM_BOUNDS;
   if (size && destination < base + register_bytes && base < destination + size)
      return STELA_AMD_VRAM_MM_INVALID;
   static const struct amdgpu_mm_access_ops ops = {read32, write32};
   amdgpu_mm_access_core(&ops, registers, (int64_t)position, data, size, false);
   return STELA_AMD_VRAM_MM_OK;
}
