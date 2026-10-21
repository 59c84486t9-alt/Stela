/*
 * Copyright © 2017 Intel Corporation
 * SPDX-License-Identifier: MIT
 * Field policy adapted from retained iris_store_cs_state(),
 * iris_upload_gpgpu_walker() and crocus_upload_compute_state(). Actual bit
 * packing remains entirely in the original hosted XML-generated packers.
 */
#include "legacy_compute_internal.h"
#define __gen_address_type uint64_t
#define __gen_user_data void
static inline uint64_t combine_address(void *data, void *location,
                                       uint64_t address, uint32_t delta)
{
    (void)data; (void)location;
    return address + delta;
}
#define __gen_combine_address combine_address
#include "intel/genxml/gen_macros.h"
#include "intel/genxml/genX_pack.h"

void STELA_LEGACY_PACK(const struct stela_intel_legacy_state *state,
                       const struct stela_intel_legacy_placement *placement,
                       struct stela_intel_legacy_plan *plan)
{
    struct GENX(INTERFACE_DESCRIPTOR_DATA) descriptor = {
        .KernelStartPointer = state->kernel_offset,
        .BindingTablePointer = placement->binding_table_offset >> (GFX_VER >= 11 ? 3 : 0),
        .BindingTableEntryCount = MIN2(placement->binding_table_entries, 31),
        .NumberofThreadsinGPGPUThreadGroup = plan->dispatch.threads,
        .ConstantURBEntryReadLength = state->per_thread_regs,
#if GFX_VERx10 >= 75
        .CrossThreadConstantDataReadLength = state->cross_thread_regs,
#endif
        .SharedLocalMemorySize = state->slm_encoding,
        .BarrierEnable = state->uses_barrier,
#if GFX_VER >= 12
        .ThreadPreemptionDisable = true,
#endif
    };
    GENX(INTERFACE_DESCRIPTOR_DATA_pack)(NULL, plan->descriptor, &descriptor);
    struct GENX(MEDIA_VFE_STATE) vfe = {
        GENX(MEDIA_VFE_STATE_header),
        .PerThreadScratchSpace = state->scratch_encoding,
        .ScratchSpaceBasePointer = placement->scratch_address,
        .MaximumNumberofThreads = state->max_threads - 1,
#if GFX_VER < 11
        .ResetGatewayTimer = Resettingrelativetimerandlatchingtheglobaltimestamp,
#endif
#if GFX_VER <= 8
        .BypassGatewayControl = true,
#endif
#if GFX_VER == 7
        .GPGPUMode = true,
#endif
        .NumberofURBEntries = GFX_VER == 7 ? 0 : 2,
        .URBEntryAllocationSize = GFX_VER == 7 ? 0 : 2,
        .CURBEAllocationSize = state->curbe_regs,
    };
    GENX(MEDIA_VFE_STATE_pack)(NULL, plan->vfe, &vfe);
    plan->vfe_words = GENX(MEDIA_VFE_STATE_length);
    struct GENX(MEDIA_CURBE_LOAD) curbe = {
        GENX(MEDIA_CURBE_LOAD_header),
        .CURBETotalDataLength = plan->curbe_bytes,
        .CURBEDataStartAddress = placement->curbe_offset,
    };
    GENX(MEDIA_CURBE_LOAD_pack)(NULL, plan->curbe_load, &curbe);
    struct GENX(MEDIA_INTERFACE_DESCRIPTOR_LOAD) load = {
        GENX(MEDIA_INTERFACE_DESCRIPTOR_LOAD_header),
        .InterfaceDescriptorTotalLength = sizeof(plan->descriptor),
        .InterfaceDescriptorDataStartAddress = placement->descriptor_offset,
    };
    GENX(MEDIA_INTERFACE_DESCRIPTOR_LOAD_pack)(NULL, plan->descriptor_load, &load);
}
