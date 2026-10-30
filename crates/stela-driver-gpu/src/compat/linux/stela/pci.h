/* SPDX-License-Identifier: MIT */
#ifndef STELA_PCI_H
#define STELA_PCI_H
#include <linux/pci.h>

/* A function its owner built, on a bus with the owner's pci_ops. Adding
 * initializes its device; removing drops that reference. */
void stela_linux_pci_add_device(struct pci_dev *dev);
void stela_linux_pci_remove_device(struct pci_dev *dev);
#endif
