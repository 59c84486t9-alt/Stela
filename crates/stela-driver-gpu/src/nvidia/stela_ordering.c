/* SPDX-License-Identifier: MIT */
/* os_flush_cpu_write_combine_buffer, as os-interface.h declares it, for
 * x86-64: sfence orders this CPU's earlier write-combining stores before its
 * later ones. It is not cache maintenance, posted-write completion or DMA
 * visibility. */
#include "os-interface.h"

#if !defined(NVCPU_X86_64)
#error "Stela's NVIDIA port builds for x86-64"
#endif

void NV_API_CALL os_flush_cpu_write_combine_buffer(void)
{
    __asm__ volatile("sfence" ::: "memory");
}
