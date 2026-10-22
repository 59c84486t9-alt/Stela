/* SPDX-License-Identifier: MIT */
#include "device.h"

NV_STATUS stela_nvidia_prepare_device(nv_state_t *nv, void *handle,
    const struct stela_nvidia_device_identity *id,
    const struct stela_nvidia_device_bar *bars, NvU32 count)
{
    NvU32 config[NVRM_PCICFG_NUM_DWORDS], used = 0;
    if (!nv || !handle || !id || !bars || count < 2 || count > NV_GPU_NUM_BARS ||
        id->domain > 0xffff || id->bus > 255 || id->slot > 31 || id->function > 7 ||
        id->vendor != 0x10de || id->device > 0xffff ||
        id->subsystem_vendor > 0xffff || id->subsystem > 0xffff)
        return NV_ERR_INVALID_ARGUMENT;
    if (nv->priv || nv->os_state || nv->dma_dev || nv->niso_dma_dev || nv->handle)
        return NV_ERR_INVALID_STATE;
    for (NvU32 i = 0; i < NVRM_PCICFG_NUM_DWORDS; ++i) {
        NV_STATUS status = os_pci_read_dword(handle, i * 4, &config[i]);
        if (status != NV_OK) return status;
    }
    if ((config[0] & 0xffff) != id->vendor || (config[0] >> 16) != id->device ||
        (config[11] & 0xffff) != id->subsystem_vendor || (config[11] >> 16) != id->subsystem ||
        ((config[3] >> 16) & 0x7f) != 0)
        return NV_ERR_INVALID_ARGUMENT;
    for (NvU32 i = 0; i < count; ++i) {
        const struct stela_nvidia_device_bar *bar = &bars[i];
        if (bar->index >= NVRM_PCICFG_NUM_BARS || !bar->physical || !bar->bytes ||
            bar->bytes > NV_U64_MAX - bar->physical || bar->prefetchable > 1 ||
            (i == NV_GPU_BAR_INDEX_REGS && bar->prefetchable))
            return NV_ERR_INVALID_ARGUMENT;
        NvU32 low = config[NVRM_PCICFG_BAR_OFFSET(bar->index) / 4];
        NvU32 type = low & NVRM_PCICFG_BAR_MEMTYPE_MASK;
        if ((low & NVRM_PCICFG_BAR_REQTYPE_MASK) != NVRM_PCICFG_BAR_REQTYPE_MEMORY ||
            (type != 0 && type != NVRM_PCICFG_BAR_MEMTYPE_64BIT) ||
            ((low >> 3) & 1) != bar->prefetchable)
            return NV_ERR_INVALID_ARGUMENT;
        NvU32 selected = 1U << bar->index;
        NvU64 address = low & NVRM_PCICFG_BAR_ADDR_MASK;
        if (type == NVRM_PCICFG_BAR_MEMTYPE_64BIT) {
            if (bar->index + 1 >= NVRM_PCICFG_NUM_BARS) return NV_ERR_INVALID_ARGUMENT;
            address |= (NvU64)config[NVRM_PCICFG_BAR_OFFSET(bar->index + 1) / 4] << 32;
            selected |= 1U << (bar->index + 1);
        }
        if ((used & selected) || address != bar->physical) return NV_ERR_INVALID_ARGUMENT;
        used |= selected;
    }
    /* Decode assigned memory resources as PCI resource metadata does, excluding
     * 64-bit upper slots. No destructive sizing or address-as-pointer use. */
    NvU32 memory = 0, first = NVRM_PCICFG_NUM_BARS;
    for (NvU32 i = 0; i < NVRM_PCICFG_NUM_BARS; ++i) {
        NvU32 low = config[NVRM_PCICFG_BAR_OFFSET(i) / 4];
        if (low & NVRM_PCICFG_BAR_REQTYPE_MASK) continue;
        NvU32 type = low & NVRM_PCICFG_BAR_MEMTYPE_MASK;
        if (type != 0 && type != NVRM_PCICFG_BAR_MEMTYPE_64BIT) return NV_ERR_NOT_SUPPORTED;
        NvU64 address = low & NVRM_PCICFG_BAR_ADDR_MASK;
        if (type == NVRM_PCICFG_BAR_MEMTYPE_64BIT) {
            if (i + 1 >= NVRM_PCICFG_NUM_BARS) return NV_ERR_INVALID_ARGUMENT;
            address |= (NvU64)config[NVRM_PCICFG_BAR_OFFSET(i + 1) / 4] << 32;
        }
        if (address) {
            memory |= 1U << i;
            if (first == NVRM_PCICFG_NUM_BARS) first = i;
        }
        if (type == NVRM_PCICFG_BAR_MEMTYPE_64BIT) ++i;
    }
    if (bars[NV_GPU_BAR_INDEX_REGS].index != first) return NV_ERR_INVALID_ARGUMENT;
    /* Preserve the original second loop's index skip exactly: j==REGS skips
     * the FIRST PCI INDEX, not the first valid memory resource. A layout that
     * would repeat REGS as FB cannot satisfy our distinct retained spans. */
    NvU32 j = 0;
    for (NvU32 i = 0; i < NVRM_PCICFG_NUM_BARS && j < NV_GPU_NUM_BARS; ++i) {
        if (j == NV_GPU_BAR_INDEX_REGS) {
            ++j;
            continue;
        }
        if (memory & (1U << i)) {
            if (j >= count || bars[j].index != i) return NV_ERR_INVALID_ARGUMENT;
            ++j;
        }
    }
    if (j != count) return NV_ERR_INVALID_ARGUMENT;
    /* Original POD type and original role constants; no private record mirror,
     * active RM flag, IRQ, firmware policy, mapping or DMA mask is supplied. */
    nv_state_t prepared = {0};
    prepared.pci_info.domain = id->domain;
    prepared.pci_info.bus = (NvU8)id->bus;
    prepared.pci_info.slot = (NvU8)id->slot;
    prepared.pci_info.function = (NvU8)id->function;
    prepared.pci_info.vendor_id = (NvU16)id->vendor;
    prepared.pci_info.device_id = (NvU16)id->device;
    prepared.subsystem_vendor = (NvU16)id->subsystem_vendor;
    prepared.subsystem_id = (NvU16)id->subsystem;
    prepared.handle = handle;
    for (NvU32 i = 0; i < NVRM_PCICFG_NUM_DWORDS; ++i) prepared.pci_cfg_space[i] = config[i];
    for (NvU32 i = 0; i < count; ++i) {
        prepared.bars[i].cpu_address = bars[i].physical;
        prepared.bars[i].size = bars[i].bytes;
        prepared.bars[i].offset = NVRM_PCICFG_BAR_OFFSET(bars[i].index);
    }
    *nv = prepared;
    nv->regs = &nv->bars[NV_GPU_BAR_INDEX_REGS];
    nv->fb = &nv->bars[NV_GPU_BAR_INDEX_FB];
    return NV_OK;
}
NV_STATUS stela_nvidia_prepared_device_retirable(const nv_state_t *nv, const void *handle)
{
    if (!nv || !handle || nv->handle != handle) return NV_ERR_INVALID_ARGUMENT;
    if (nv->priv || nv->flags || nv->queue || nv->event_list || nv->event_spinlock ||
        nv->kern_mappings || nv->rc_timer_enabled || nv->rmapi.hClient || nv->rmapi.hDevice ||
        nv->rmapi.hSubDevice || nv->rmapi.hI2C || nv->rmapi.hDisp)
        return NV_ERR_INVALID_STATE;
    for (NvU32 i = 0; i < NV_GPU_NUM_BARS; ++i)
        if (nv->bars[i].map || nv->bars[i].map_u) return NV_ERR_INVALID_STATE;
    return NV_OK;
}
