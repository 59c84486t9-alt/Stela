/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_SETJMP_H
#define STELA_LIBC_SETJMP_H
typedef unsigned long jmp_buf[32];
int setjmp(jmp_buf env);
_Noreturn void longjmp(jmp_buf env, int value);
#endif
