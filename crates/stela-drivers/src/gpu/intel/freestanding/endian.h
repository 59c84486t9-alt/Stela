/* SPDX-License-Identifier: MIT */
/* The byte order, in glibc's names, from the compiler's; see assert.h. */
#ifndef STELA_FREESTANDING_ENDIAN_H
#define STELA_FREESTANDING_ENDIAN_H
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#define __BYTE_ORDER __BYTE_ORDER__
#endif
