/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_PCI_H
#define STELA_LINUX_PCI_H
#include <linux/container_of.h>
#include <linux/device-id/pci.h>
#include <linux/pci_ids.h>
#include <linux/types.h>
/* Stela's PCI owner reads identity from configuration space; a driver sees
 * only the fields Linux's pci_dev gives it for that identity. */
struct device {
};
struct pci_dev {
	struct device dev;
	unsigned short vendor;
	unsigned short device;
	u8 revision;
	unsigned int class;
};
#define to_pci_dev(n) container_of(n, struct pci_dev, dev)
/* Copyright Linux kernel contributors; from pci.h. */
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
struct pci_driver {
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *dev, const struct pci_device_id *id);
	void (*remove)(struct pci_dev *dev);
	void (*shutdown)(struct pci_dev *dev);
	int (*sriov_configure)(struct pci_dev *dev, int num_vfs);
};
#endif
