/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_TEST_HOST_H
#define STELA_LIBC_TEST_HOST_H
#include <stddef.h>

/* The test: its result is the program's exit status. */
int test(void);
_Noreturn void leave(int status);

extern size_t live_blocks;
extern unsigned int current_core;
extern unsigned int waits, wakes;
/* What a wait changes, as another processor would. */
extern volatile unsigned int *waited_word;
extern unsigned int waited_value;
#endif
