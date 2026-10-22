/* SPDX-License-Identifier: MIT */
/* Test-object-only I/O instrumentation. No shipping source/provider hook. */
#ifndef STELA_AMD_VRAM_MM_TEST_IO_H
#define STELA_AMD_VRAM_MM_TEST_IO_H
#include "../stela/vram_mm.h"
uint32_t stela_amd_test_io_read(volatile uint32_t *);
void stela_amd_test_io_write(volatile uint32_t *, uint32_t);
enum stela_amd_vram_mm_status
stela_amd_vram_mm_test_read(void *, size_t, uint64_t, uint64_t, uint32_t *, size_t);
#endif
