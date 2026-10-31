/* SPDX-License-Identifier: MIT */
#ifndef STELA_PCI_H
#define STELA_PCI_H
#include <linux/pci.h>

/* A function its owner built, on a bus with the owner's pci_ops. Adding
 * initializes its device; removing drops that reference. */
void stela_linux_pci_add_device(struct pci_dev *dev);
void stela_linux_pci_remove_device(struct pci_dev *dev);

/* A placed memory region of a function. */
struct stela_linux_pci_region {
	u64 start, size;
	unsigned long flags;
};

/* A physical function its owner enumerated. Configuration accesses return a
 * PCIBIOS result; dma_map returns DMA_MAPPING_ERROR when it cannot map, and
 * dma_limit is the highest address it hands out. */
struct stela_linux_pci_function {
	void *context;
	int (*read_config)(void *context, int where, int size, u32 *value);
	int (*write_config)(void *context, int where, int size, u32 value);
	dma_addr_t (*dma_map)(void *context, phys_addr_t physical, size_t size,
			      enum dma_data_direction direction);
	void (*dma_unmap)(void *context, dma_addr_t address, size_t size,
			  enum dma_data_direction direction);
	/* Move the function's interrupt from its line to a message and back. The
	 * irq stays the name Linux knows it by; enable returns a negative errno. */
	int (*enable_msi)(void *context);
	void (*disable_msi)(void *context);
	u64 dma_limit;
	unsigned int bus, devfn, irq;
	struct stela_linux_pci_region regions[PCI_STD_NUM_BARS];
};

_Static_assert(sizeof(struct stela_linux_pci_function) == 224, "Linux PCI function ABI");

/* Present function to Linux, which binds any driver matching it; NULL when out
 * of memory. stela_linux_pci_remove_device takes it away. */
struct pci_dev *stela_linux_pci_attach(const struct stela_linux_pci_function *function);
#endif
