/* SPDX-License-Identifier: MIT */
/* C++ reaches these headers too: LLVM and libc++ call the C library by C names. */
#ifndef STELA_LIBC_SYS_CDEFS_H
#define STELA_LIBC_SYS_CDEFS_H
#ifdef __cplusplus
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif
