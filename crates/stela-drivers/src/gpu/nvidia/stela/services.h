/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_SERVICES_H
#define STELA_NVIDIA_SERVICES_H

#ifndef NVRM
#define NVRM
#endif
#ifndef NV_KERNEL_INTERFACE_LAYER
#define NV_KERNEL_INTERFACE_LAYER
#endif
#include "nv.h"
#include "os/nv_memory_type.h"

/* Mirror the stable vendor status/cache ABI used by Rust, against the actual
 * pinned declarations. A vendor update changing it must fail this build. */
_Static_assert(NV_OK == 0 && NV_ERR_INVALID_ADDRESS == 0x1e &&
               NV_ERR_INVALID_ARGUMENT == 0x1f && NV_ERR_INVALID_STATE == 0x40 &&
               NV_ERR_NO_MEMORY == 0x51 && NV_ERR_NOT_SUPPORTED == 0x56 &&
               NV_ERR_OPERATING_SYSTEM == 0x59, "native status ABI");
_Static_assert(NV_MEMORY_CACHED == 0 && NV_MEMORY_UNCACHED == 1 &&
               NV_MEMORY_WRITECOMBINED == 2 && sizeof(NvBool) == 1,
               "native cache/boolean ABI");

/* Native same-CPU ABI. Only the device owner binds this live pinned service;
 * its source/domain/requester facts are real platform resources, not guest
 * handles. Calls and final releases are serialized process/deferred operations,
 * never ISR allocation or completion. Stop callers and prove real hardware
 * quiescence before unbind/removal. MemoryServices refuses unbind while any
 * producer allocation or published DMA token remains; keep service/state live
 * until all those handles are freed/retired/quarantined and unbind succeeds.
 * Only CPU views and consumed quarantine may survive. Remaining RM/IRQ services
 * are prerequisites. Bind/unbind below are private helpers of the Rust owner;
 * use MemoryServices methods so their live-resource checks cannot be bypassed.
 */
NV_STATUS stela_nvidia_bind_memory(nv_state_t *, void *, NvU32, NvU8, NvU8, NvU8);
NV_STATUS stela_nvidia_unbind_memory(nv_state_t *, void *);
/* Storage facts only: no initialization or default device state is supplied. */
void stela_nvidia_state_layout(NvU64 *bytes, NvU64 *alignment);

/* RAM producer: nonzero native-size pages; CACHED/UNCACHED/WRITECOMBINED only,
 * node=-1 and no unencrypted request. Other orders/policies are explicit errors.
 * Source pins must have exact logical/reserved lengths, native granule and actual
 * cache attributes. True contiguity and force_dma32 are verified on physical
 * pages. Canonical pages are initially zeroed even if zeroed was not requested.
 * Contiguous PTE output has one physical base; otherwise count native physical
 * entries. All outputs remain unchanged on error. Allocation-private ownership
 * is unique and stays live/pinned through its one matching free; CPU views and
 * actual DMA leases retain the backing independently.
 *
 * DMA input addresses must match those physical PTEs and count/contiguity.
 * The retained allocation supplies the actual domain; arbitrary dma_dev values
 * are compared as opaque keys, never dereferenced to choose platform state.
 * Read-only means TO_DEVICE, otherwise BIDIRECTIONAL. Successful preparation
 * finishes real sync_for_device before publishing native IOVAs and a different
 * unique DMA-token ownership kind in *private. These are NEVER GPU virtual VAs.
 * Failures preserve input addresses/private and remove unpublished mappings, or
 * quarantine their actual pins/domain if removal is uncertain.
 *
 * Unmap requires caller-proven hardware completion, removed GPU bindings and
 * stopped/drained submissions/IRQ workers. It performs actual sync_for_cpu,
 * removal and invalidation. The original osIovaUnmap discards pOsData even on
 * error, so a valid retirement consumes *private: failure enters canonical,
 * observable quarantine with a real error, never releases uncertain pages.
 * Wrong device/count refuses the request without consuming a different token.
 */
NV_STATUS stela_nvidia_alloc_pages(void *, void *, NvU32, NvU64, NvBool, NvU32,
                                  NvBool, NvBool, NvS32, NvBool, NvU64 *, void **);
NV_STATUS stela_nvidia_free_pages(void *, NvU32, NvBool, NvU32, void *);
NV_STATUS stela_nvidia_dma_map(void *, NvU64, NvU64 *, NvBool, NvBool, void **);
NV_STATUS stela_nvidia_dma_unmap(void *, NvU64, void **);

#endif
