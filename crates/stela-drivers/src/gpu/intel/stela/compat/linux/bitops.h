/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_BITOPS_H
#define STELA_LINUX_BITOPS_H
#include <linux/bits.h>
/* Linux's sign_extend64(): sign-extend from bit @index. */
static inline s64 sign_extend64(u64 value, int index)
{
	u8 shift = (u8)(63 - index);
	return (s64)(value << shift) >> shift;
}
#endif
