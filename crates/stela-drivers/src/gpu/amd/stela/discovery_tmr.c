/* SPDX-License-Identifier: MIT */
#include "discovery_tmr.h"
#include "discovery_binary.h"
#include "vram_mm.h"
#include "../include/asic_reg/bif/bif_4_1_d.h"
#include "../amdgpu/amdgpu_discovery_tmr_core.h"
#include "../amdgpu/amdgpu_virt_bootstrap_core.h"
#include <stdatomic.h>
_Static_assert(sizeof(struct stela_amd_discovery_tmr) == 24, "TMR ABI");
_Static_assert(offsetof(struct stela_amd_discovery_tmr, size) == 16, "TMR size ABI");
struct native_tmr {
 void *registers;
 size_t bytes;
 uint64_t vram_bytes;
 void *sleep_context;
 void (*sleep_ms)(void *, unsigned);
};
static uint32_t read32(void *context, uint32_t reg)
{
 struct native_tmr *native = context;
 volatile uint32_t *pointer = (volatile uint32_t *)((uint8_t *)native->registers + reg * 4u);
 atomic_signal_fence(memory_order_seq_cst);
 uint32_t value = *pointer;
 atomic_signal_fence(memory_order_seq_cst);
 if (reg == mmRCC_CONFIG_MEMSIZE)
  native->vram_bytes = (uint64_t)value << 20;
 return value;
}
static void sleep_ms(void *context, unsigned milliseconds)
{
 struct native_tmr *native = context;
 native->sleep_ms(native->sleep_context, milliseconds);
}
static int read_vram(void *context, uint64_t offset, uint32_t *data, size_t size)
{
 struct native_tmr *native = context;
 return stela_amd_vram_mm_read(native->registers, native->bytes,
                               native->vram_bytes, offset, data, size) == STELA_AMD_VRAM_MM_OK
  ? STELA_AMD_TMR_OK : STELA_AMD_TMR_BOUNDS;
}
static int acpi_tmr(void *context, uint64_t *offset, uint64_t *size)
{
 (void)context; (void)offset; (void)size;
 /* Explicit missing actual ACPI/firmware owner, not a fabricated reply. */
 return STELA_AMD_TMR_SYSTEM_OWNER_UNAVAILABLE;
}
static bool direct_register(size_t bytes, uint32_t reg)
{
 return reg < bytes / sizeof(uint32_t);
}
int stela_amd_discovery_tmr_query(void *registers, size_t register_bytes,
 uint32_t asic_type, void *sleep_context,
 void (*sleep)(void *, unsigned), struct stela_amd_discovery_tmr *out)
{
 uintptr_t base = (uintptr_t)registers, destination = (uintptr_t)out;
 if (!registers || base % sizeof(uint32_t) || !out || destination % _Alignof(struct stela_amd_discovery_tmr) ||
     !sleep || asic_type >= CHIP_LAST)
  return STELA_AMD_TMR_INVALID;
 if (register_bytes > PTRDIFF_MAX || register_bytes > UINTPTR_MAX - base ||
     sizeof(*out) > UINTPTR_MAX - destination ||
     (destination < base + register_bytes && base < destination + sizeof(*out)))
  return STELA_AMD_TMR_BOUNDS;
 uint32_t identifier = 0;
 bool has_identifier = amdgpu_virt_bootstrap_iov_register(asic_type, &identifier);
 const uint32_t required[] = {mmMP0_SMN_C2PMSG_33, mmRCC_CONFIG_MEMSIZE,
  mmDRIVER_SCRATCH_0, mmDRIVER_SCRATCH_1, mmDRIVER_SCRATCH_2,
  mmMM_INDEX, mmMM_DATA, mmMM_INDEX_HI};
 for (unsigned i = 0; i < sizeof(required) / sizeof(required[0]); ++i)
  if (!direct_register(register_bytes, required[i]))
   return STELA_AMD_TMR_BOUNDS;
 if (has_identifier && !direct_register(register_bytes, identifier))
  return STELA_AMD_TMR_BOUNDS;
 struct native_tmr native = {registers, register_bytes, 0, sleep_context, sleep};
 /* This is the original selector's actual hardware observation, not a guessed
  * role from flags or a caller boolean. VF protocols remain original owners. */
 if (has_identifier && (read32(&native, identifier) & 1))
  return STELA_AMD_TMR_VF_OWNER_UNAVAILABLE;
 static const struct amdgpu_discovery_tmr_ops ops = {read32, sleep_ms, read_vram, acpi_tmr};
 struct amdgpu_discovery_tmr_state state = {0};
 int status = amdgpu_discovery_tmr_query_core(&ops, &native, false, false, 0, 0, &state);
 if (status)
  return status;
 if (state.is_sysmem)
  return STELA_AMD_TMR_SYSTEM_OWNER_UNAVAILABLE;
 if (!state.size || state.size % sizeof(uint32_t) || state.offset % sizeof(uint32_t) ||
     state.offset > native.vram_bytes || state.size > native.vram_bytes - state.offset)
  return STELA_AMD_TMR_BOUNDS;
 const struct stela_amd_discovery_tmr result = {
  .offset = state.offset, .vram_bytes = native.vram_bytes, .size = state.size,
 };
 *out = result;
 return STELA_AMD_TMR_OK;
}
