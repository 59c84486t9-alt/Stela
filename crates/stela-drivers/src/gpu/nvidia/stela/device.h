/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_DEVICE_H
#define STELA_NVIDIA_DEVICE_H
#include "services.h"
#include "os-interface.h"
#include <stddef.h>
/* Private same-CPU input ABI. Physical spans come only from retained canonical
 * Resources; neither this value record nor a PCI address grants ownership. */
struct stela_nvidia_device_bar { NvU64 physical, bytes; NvU32 index, prefetchable; };
struct stela_nvidia_device_identity {
    NvU32 domain, bus, slot, function, vendor, device, subsystem_vendor, subsystem;
};
_Static_assert(sizeof(struct stela_nvidia_device_bar) == 24, "device BAR input ABI");
_Static_assert(sizeof(struct stela_nvidia_device_identity) == 32, "identity input ABI");
/* CPU metadata construction only; all validation/config reads precede writes.
 * Roles are original NV_GPU_BAR_INDEX_{REGS,FB,IMEM}, never inferred from PA.
 * The zeroed actual nv_state_t is private, pinned and has no native callers. */
NV_STATUS stela_nvidia_prepare_device(nv_state_t *, void *,
    const struct stela_nvidia_device_identity *, const struct stela_nvidia_device_bar *, NvU32);
/* No reset/drain/free. Validate this still-uninitialized private state before
 * actual counter-checked service unbind. Failure preserves every slot. */
NV_STATUS stela_nvidia_prepared_device_retirable(const nv_state_t *, const void *);
#endif
