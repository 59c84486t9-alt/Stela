/* SPDX-License-Identifier: MIT */
/* Forced into every Linux translation unit after Linux's compiler_types.h.
 * Linux places code and data in named sections for its own linker script:
 * init and exit code, read-mostly data, once flags, symbol and parameter
 * tables. Linux code links into Stela's images instead, which keep every
 * object in the platform's default sections and enumerate none of those
 * tables; Mach-O hosts also reject their names. */
#undef __section
#define __section(section)
#undef __noinstr_section
#define __noinstr_section(section) noinline notrace

/* Explicit driver and helper identities take precedence over the common one. */
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "stela-linux"
#endif
#ifndef KBUILD_MODFILE
#define KBUILD_MODFILE "stela-linux"
#endif

/* Linux's -fshort-wchar contract also applies to hosted ELF builds; without
 * it, an original L"..." is incompatible with EFI's 16-bit character ABI. */
#ifndef __ASSEMBLER__
_Static_assert(sizeof(*L"") == 2, "Linux compiler requires 16-bit wide literals");
#endif
/* Client calls cannot bypass the single boot-owned namespace authority. */
#include <stela/acpi_client.h>
