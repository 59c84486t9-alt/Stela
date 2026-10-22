/* SPDX-License-Identifier: MIT */
#ifndef STELA_LINUX_BITOPS_H
#define STELA_LINUX_BITOPS_H
#include <linux/bits.h>
#define BITS_PER_LONG (8 * (int)sizeof(long))
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
/* Non-atomic, as asm-generic/bitops/generic-non-atomic.h. */
static inline void __set_bit(unsigned long nr, volatile unsigned long *addr)
{
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p |= BIT_MASK(nr);
}
/* Linux's sign_extend64(): sign-extend from bit @index. */
static inline s64 sign_extend64(u64 value, int index)
{
	u8 shift = (u8)(63 - index);
	return (s64)(value << shift) >> shift;
}
#endif
