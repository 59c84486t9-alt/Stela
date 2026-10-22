/* SPDX-License-Identifier: MIT */
#include "x86emu/x86emu.h"

_Static_assert(sizeof(((X86EMU_sysEnv *)0)->mem_base) == sizeof(void *),
               "emulator host addresses must be pointer-sized");
_Static_assert(sizeof(((X86EMU_sysEnv *)0)->mem_size) == sizeof(void *),
               "emulator lengths must be pointer-sized");
_Static_assert(__builtin_offsetof(X86EMU_sysEnv, private) == 2 * sizeof(void *),
               "preserve the LP64 memory-state layout");

/* -Werror also rejects truncation of these concrete addresses above 4 GiB. */
const X86EMU_sysEnv high_memory = {
    .mem_base = 0x100001000ULL,
    .mem_size = 0x100002000ULL,
};
