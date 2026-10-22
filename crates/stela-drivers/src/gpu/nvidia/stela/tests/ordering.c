/* SPDX-License-Identifier: MIT
 * Compile/disassembly fixture only. This is not a CPU/GPU ordering litmus test.
 * Include the actual adapter so the emitted probe exposes its compiler clobber
 * and instruction between ordinary CPU stores, without calling hardware.
 */
#include "../stela_ordering.c"

void stela_nvidia_ordering_compile_probe(NvU32 *before, NvU32 *after);

void stela_nvidia_ordering_compile_probe(NvU32 *before, NvU32 *after)
{
    *before = 0x12345678;
    os_flush_cpu_write_combine_buffer();
    *after = 0x76543210;
}
