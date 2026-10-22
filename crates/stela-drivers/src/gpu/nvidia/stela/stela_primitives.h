/* SPDX-License-Identifier: MIT */
#ifndef STELA_NVIDIA_PRIMITIVES_H
#define STELA_NVIDIA_PRIMITIVES_H
#include <stddef.h>
#include "nvtypes.h"

#if !NVOS_IS_FREEBSD || !NVCPU_IS_X86_64
#error "these original RM primitives build for x86-64 in NVIDIA's FreeBSD configuration"
#endif

/* Declarations of the existing shared C runtime, not a private implementation.
 * Native UEFI resolves these to Rust's compiler_builtins; hosted tests use the
 * host C runtime. Calls require ordinary valid CPU buffers, nonoverlapping copy
 * ranges and terminated readable strings. They do not perform usercopy, MMIO
 * ordering, cache maintenance, pinning or allocation and establish no ISR state.
 */
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);

_Static_assert(sizeof(size_t) == sizeof(NvLength) && sizeof(NvLength) == 8,
               "native shared C runtime uses pointer-sized lengths");
_Static_assert(sizeof(NvU32) == 4 && sizeof(NvU8) == 1 && sizeof(NvS32) == sizeof(int),
               "preserve original RM primitive scalar ABI");
#endif
