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
