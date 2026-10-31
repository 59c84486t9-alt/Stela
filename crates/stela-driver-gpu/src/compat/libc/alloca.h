/* SPDX-License-Identifier: MIT */
#ifndef STELA_LIBC_ALLOCA_H
#define STELA_LIBC_ALLOCA_H
#define alloca(size) __builtin_alloca(size)
#endif
