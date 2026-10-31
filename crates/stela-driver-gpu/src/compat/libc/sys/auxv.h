/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_AUXV_H
#define STELA_LIBC_SYS_AUXV_H
#define AT_HWCAP 16
unsigned long getauxval(unsigned long type);
#endif
