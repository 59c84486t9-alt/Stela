// SPDX-License-Identifier: MIT
/* Linux's copies to and from I/O memory, a byte at a time: every mapping
 * accepts those, whatever its alignment. */
#include <linux/io.h>
#include <linux/mm.h>
#include <stela/linux.h>

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

/* Device memory is mapped by its device's owner, in whole pages. */
void __iomem *ioremap(phys_addr_t offset, size_t size)
{
	const struct stela_linux_owner *owner = stela_linux_owner();

	if (!owner->services->map_device) {
		stela_linux_unsupported("device memory mappings");
		return NULL;
	}
	phys_addr_t base = offset & PAGE_MASK;
	u8 *mapping = owner->services->map_device(owner->context, base,
						  PAGE_ALIGN(offset + size) - base);
	return mapping ? (void __iomem *)(mapping + (offset - base)) : NULL;
}

/* Uncached mappings serve every memremap flag: they order more strictly than
 * any flag asks. */
void *memremap(resource_size_t offset, size_t size, unsigned long flags)
{
	(void)flags;
	return (void __force *)ioremap(offset, size);
}

void memunmap(void *addr)
{
	iounmap((void __iomem __force *)addr);
}

void iounmap(volatile void __iomem *addr)
{
	const struct stela_linux_owner *owner = stela_linux_owner();

	if (addr)
		owner->services->unmap_device(owner->context,
					      (void *)((unsigned long)addr & PAGE_MASK));
}
