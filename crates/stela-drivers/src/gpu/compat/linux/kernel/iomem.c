// SPDX-License-Identifier: MIT
/* Linux's copies to and from I/O memory, a byte at a time: every mapping
 * accepts those, whatever its alignment. */
#include <linux/io.h>

void memcpy_fromio(void *dst, const volatile void __iomem *src, size_t count)
{
	u8 *to = dst;
	const volatile u8 __iomem *from = src;
	while (count--)
		*to++ = __raw_readb(from++);
}

void memcpy_toio(volatile void __iomem *dst, const void *src, size_t count)
{
	volatile u8 __iomem *to = dst;
	const u8 *from = src;
	while (count--)
		__raw_writeb(*from++, to++);
}

void memset_io(volatile void __iomem *addr, int val, size_t count)
{
	volatile u8 __iomem *to = addr;
	while (count--)
		__raw_writeb((u8)val, to++);
}
