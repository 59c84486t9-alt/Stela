/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_PCI_H
#define STELA_NVIDIA_PCI_H

#include <stddef.h>
#include "nvtypes.h"

#if !NVOS_IS_FREEBSD
#error "native PCI hooks build in NVIDIA's FreeBSD configuration"
#endif

/* Native, same-CPU ABI, mirrored by nvidia::PciHandle. The physical device's
 * owner pins this handle and keeps its configuration space exclusively borrowed
 * until all RM users stop. Calls are serialized; neither callback may reenter
 * the driver. These are not guest pointers or a macOS transport.
 *
 * Width is 1, 2 or 4 bytes. Callbacks reject unaligned/out-of-page accesses
 * without touching hardware, returning 0; return 1 after a valid access.
 */
struct stela_nvidia_pci {
    void *context;
    NvU32 (*read)(void *, NvU32 offset, NvU32 width, NvU32 *value);
    NvU32 (*write)(void *, NvU32 offset, NvU32 width, NvU32 value);
};

_Static_assert(sizeof(NvU32) == 4, "PCI values use 32-bit integers");
_Static_assert(sizeof(struct stela_nvidia_pci) == 3 * sizeof(void *), "PCI handle size");
_Static_assert(offsetof(struct stela_nvidia_pci, read) == sizeof(void *), "PCI read offset");
_Static_assert(offsetof(struct stela_nvidia_pci, write) == 2 * sizeof(void *), "PCI write offset");

#endif
