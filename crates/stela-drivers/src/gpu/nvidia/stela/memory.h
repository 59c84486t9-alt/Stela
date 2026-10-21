/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_MEMORY_H
#define STELA_NVIDIA_MEMORY_H

#include "nvtypes.h"

#if !NVOS_IS_STELA || !NVOS_IS_UNIX || NVOS_IS_LINUX || NVOS_IS_MACINTOSH
#error "native metadata hooks must select Stela's OS interface"
#endif

/* Same native CPU/C ABI as Rust's extern C, including UEFI's calling convention.
 * Stela's existing global allocator owns the bytes. The native owner establishes
 * a live heap and obeys its context restrictions: no interrupt handlers, interrupt
 * reentry or allocator reentry. Free once, after every CPU user stops, before heap
 * teardown. NULL free is valid. Payloads have 16-byte alignment and uninitialized
 * contents. Zero bytes still returns a distinct freeable allocation. The output
 * is always written: NULL for either an invalid layout or real heap exhaustion.
 * These are CPU metadata pointers,
 * never guest/physical/device addresses, page pins, MMIO or cache-policy aliases.
 */
enum {
    STELA_NVIDIA_ALLOC_SUCCESS = 0,
    STELA_NVIDIA_ALLOC_INVALID_SIZE = 1,
    STELA_NVIDIA_ALLOC_OUT_OF_MEMORY = 2,
};
NvU32 stela_nvidia_alloc(NvU64 bytes, void **out);
void stela_nvidia_free(void *pointer);

_Static_assert(sizeof(NvU64) == 8, "allocation lengths are 64-bit");

#endif
