/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_MAPPING_H
#define STELA_NVIDIA_MAPPING_H

#include "nvtypes.h"

#if !NVOS_IS_FREEBSD
#error "native CPU mapping hooks build in NVIDIA's FreeBSD configuration"
#endif

/* Native same-CPU C ABI. The allocation is a pinned Rust Allocation accepting
 * only real canonical PinnedPages with an established CPU mapping/cache policy.
 * The caller serializes access and excludes callback/interrupt reentry. Indices
 * and offsets use the allocation's actual native page granule, never the guest's.
 * Only exact logical bytes are exposed; no page padding or cache-policy alias.
 *
 * Success returns CPU VA and a unique retained CPU-view token in *private; failure
 * returns NULL with *private NULL. Each view retains the actual pin independently
 * of the parent. Return each token once after CPU/device users stop, in the common
 * heap/backing's allowed process/deferred context. Free needs no live parent.
 * These are not guest, MMIO, VRAM, physical, IOVA or GPU-VA mapping services.
 */
void *stela_nvidia_map_ram(void *allocation, NvU64 page_index, NvU32 page_offset,
                          NvU64 bytes, void **private);
void stela_nvidia_unmap_ram(void *private);

#endif
