/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SYS_SYSCALL_H
#define STELA_LIBC_SYS_SYSCALL_H
#include <sys/cdefs.h>
__BEGIN_DECLS
#define SYS_gettid 186
long syscall(long number, ...);
__END_DECLS
#endif
