/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_AUXV_H
#define STELA_LIBC_SYS_AUXV_H
#include <sys/cdefs.h>
__BEGIN_DECLS
#define AT_HWCAP 16
unsigned long getauxval(unsigned long type);
__END_DECLS
#endif
