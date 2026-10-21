/* SPDX-License-Identifier: MIT */
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wired CPU metadata from IOKit; allocation failure returns NULL. Free once,
 * with the original byte count. These calls may sleep: never invoke from an
 * interrupt handler or while holding a simple/spin lock. They do not pin
 * user pages or establish DMA mappings.
 */
void *stela_gpu_iokit_allocate_zeroed(size_t bytes, size_t alignment);
void stela_gpu_iokit_free(void *pointer, size_t bytes);

#ifdef __cplusplus
}
#endif
