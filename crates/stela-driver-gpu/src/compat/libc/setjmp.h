/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SETJMP_H
#define STELA_LIBC_SETJMP_H
#include <sys/cdefs.h>
__BEGIN_DECLS
typedef unsigned long jmp_buf[32];
__attribute__((returns_twice)) int setjmp(jmp_buf env);
_Noreturn void longjmp(jmp_buf env, int value);
__END_DECLS
#endif
