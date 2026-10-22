// SPDX-License-Identifier: MIT
/* Linux's software population counts, for arch_hweight.h. */
#include <linux/bitops.h>

unsigned long __sw_hweight64(__u64 w)
{
	w -= (w >> 1) & 0x5555555555555555ull;
	w = (w & 0x3333333333333333ull) + ((w >> 2) & 0x3333333333333333ull);
	w = (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0full;
	return (unsigned long)((w * 0x0101010101010101ull) >> 56);
}

unsigned int __sw_hweight32(unsigned int w)
{
	return (unsigned int)__sw_hweight64(w);
}

unsigned int __sw_hweight16(unsigned int w)
{
	return __sw_hweight32(w & 0xffff);
}

unsigned int __sw_hweight8(unsigned int w)
{
	return __sw_hweight32(w & 0xff);
}
