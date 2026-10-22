/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_MMIO_H
#define STELA_NVIDIA_MMIO_H
#include "nvtypes.h"
#include "os/nv_memory_type.h"

#if !NVOS_IS_STELA || !NVOS_IS_UNIX || NVOS_IS_LINUX || NVOS_IS_MACINTOSH
#error "native physical mappings must select Stela's OS interface"
#endif

_Static_assert(NV_MEMORY_CACHED == 0 && NV_MEMORY_UNCACHED == 1 &&
               NV_MEMORY_WRITECOMBINED == 2 && NV_MEMORY_WRITEBACK == 5 &&
               NV_MEMORY_DEFAULT == 6 && NV_MEMORY_UNCACHED_WEAK == 7,
               "preserve original NVIDIA cache-mode values");

/* Native same-CPU ABI. A pinned installed Rust MmioServices retains the single
 * canonical native Authority and every published Mapping. It resolves the
 * complete physical/page span to an actual registered ResourceBacking; there
 * is no PA=VA conversion, BAR ownership inference or cached-RAM mapping here.
 * UC/default request genuine UC; WC requests genuine WC or fails. Other modes
 * fail. The real platform must enforce context/cache/root/TLB requirements.
 *
 * The native owner serializes all callbacks/install/uninstall in permitted
 * process/deferred context and keeps the installed services/global heap alive.
 * Unmap returns the exact pointer and requested byte count once, after ALL raw
 * CPU/device/callback/worker uses and posted/WC writes stop and drain. It cannot
 * report failure through the original void ABI: owner-visible Rust diagnostics
 * retain failures. Busy keeps the exact Mapping pending for explicit native-
 * owner quiescent drain; other failures retain uncertain owners through
 * canonical quarantine. Pending leases block uninstall and never resume raw
 * use after the initial unmap.
 * These pointers authorize raw access only, never safe Rust references.
 */
void *stela_nvidia_map_mmio(NvU64 physical, NvU64 bytes, NvU32 mode);
void stela_nvidia_unmap_mmio(void *address, NvU64 bytes);
#endif
