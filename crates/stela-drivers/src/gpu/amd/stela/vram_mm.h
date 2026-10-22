/* SPDX-License-Identifier: MIT */
#ifndef STELA_AMD_VRAM_MM_H
#define STELA_AMD_VRAM_MM_H
#include <stddef.h>
#include <stdint.h>

enum stela_amd_vram_mm_status {
   STELA_AMD_VRAM_MM_OK,
   STELA_AMD_VRAM_MM_INVALID,
   STELA_AMD_VRAM_MM_BOUNDS,
};

/* Native x86-64 synchronous original NO_KIQ MM_INDEX/MM_DATA read only. OK means
 * numeric preflight accepted and the original void transaction loop returned;
 * it is NOT a transport acknowledgement or proof that VRAM bytes are valid.
 * Discovery must still check its original signature/checksums and ownership.
 *
 * registers is the actual retained canonical UC register mapping of this same
 * AMD device, not physical/guest memory. data is exclusive live CPU RAM for the
 * complete indicated size; neither span may overlap. Both are DWORD aligned.
 * The owner retains genuine D0/bridge/reset/removal and MM-index/IRQ exclusion,
 * required native CPU/process context and ordered MMIO32 access semantics for
 * the entire call. No new lock, mapping, allocator, provider or guard is made.
 * vram_bytes is the actual accessible VRAM extent, not a host DMA/IOVA extent.
 * Only these three original direct registers are accessed; other registers
 * still require original PCIe/KIQ/RLCG/XCC dispatch. No pointer is retained.
 *
 * The first HI value must not equal the original all-ones cache sentinel. This
 * is an original-loop representation restriction, not a guessed GPU capacity.
 * All numeric errors leave registers/data untouched. An empty read performs no
 * MMIO, but still validates the window and position. After index writes there
 * is no rollback or failure-cleanup capability. Unexpected access faults must
 * follow the real platform's fail-stop/owner-retention policy. No hardware
 * status is invented for the original void transport. Callers serialize all
 * borrowed window accesses and destruction; no Rust references alias MMIO.
 */
enum stela_amd_vram_mm_status
stela_amd_vram_mm_read(void *registers, size_t register_bytes,
                       uint64_t vram_bytes, uint64_t position,
                       uint32_t *data, size_t size);
#endif
