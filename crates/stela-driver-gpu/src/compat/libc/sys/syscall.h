/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_SYSCALL_H
#define STELA_LIBC_SYS_SYSCALL_H
#define SYS_gettid 186
long syscall(long number, ...);
#endif
