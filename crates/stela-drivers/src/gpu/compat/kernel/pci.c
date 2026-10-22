// SPDX-License-Identifier: MIT
/* Linux's PCI core. Stela's own PCI owners enumerate, power and map
 * functions; Linux drivers only match against their tables here. */
#include <linux/pci.h>
#include <unsupported.h>

/* An ID field matches its value or, as PCI_ANY_ID, any value. */
static bool id_matches(u32 id, u32 value)
{
	return id == (u32)PCI_ANY_ID || id == value;
}

/* The first entry before the table's all-zero terminator that matches. */
const struct pci_device_id *pci_match_id(const struct pci_device_id *ids, struct pci_dev *dev)
{
	for (; ids && (ids->vendor || ids->subvendor || ids->class_mask); ids++)
		if (id_matches(ids->vendor, dev->vendor) && id_matches(ids->device, dev->device) &&
		    id_matches(ids->subvendor, dev->subsystem_vendor) &&
		    id_matches(ids->subdevice, dev->subsystem_device) &&
		    !((ids->class ^ dev->class) & ids->class_mask))
			return ids;
	return NULL;
}

/* Driver registration, probe, power management and removal, which Stela's
 * PCI owners perform instead of Linux's drivers. */
STELA_UNSUPPORTED(int, __pci_register_driver, struct pci_driver *, struct module *, const char *)
STELA_UNSUPPORTED(void, pci_unregister_driver, struct pci_driver *)
STELA_UNSUPPORTED(int, pci_enable_device, struct pci_dev *)
STELA_UNSUPPORTED(int, pcim_enable_device, struct pci_dev *)
STELA_UNSUPPORTED(void, pci_disable_device, struct pci_dev *)
STELA_UNSUPPORTED(void, pci_set_master, struct pci_dev *)
STELA_UNSUPPORTED(void, pci_dev_put, struct pci_dev *)
STELA_UNSUPPORTED(struct pci_dev *, pci_get_domain_bus_and_slot, int, unsigned int, unsigned int)
STELA_UNSUPPORTED(int, pci_wait_for_pending_transaction, struct pci_dev *)
STELA_UNSUPPORTED(int, pci_wake_from_d3, struct pci_dev *, bool)
