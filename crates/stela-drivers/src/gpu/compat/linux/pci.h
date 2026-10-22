/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_PCI_H
#define STELA_LINUX_PCI_H
#include <linux/compiler_types.h>
#include <linux/container_of.h>
#include <linux/device.h>
#include <linux/device/driver.h>
#include <linux/device-id/pci.h>
#include <linux/kobject.h>
#include <linux/pci_ids.h>
#include <linux/types.h>
struct attribute_group;
/* Stela's PCI owner reads identity from configuration space; a driver sees
 * only the fields Linux's pci_dev gives it for that identity. */
struct pci_bus {
	unsigned char number;
};
struct pci_dev {
	struct device dev;
	struct pci_bus *bus;
	unsigned short vendor;
	unsigned short device;
	unsigned short subsystem_vendor;
	unsigned short subsystem_device;
	u8 revision;
	unsigned int class;
};
#define to_pci_dev(n) container_of(n, struct pci_dev, dev)

/* Copyright Linux kernel contributors; from pci.h. */
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

typedef int __bitwise pci_power_t;
#define PCI_D0		((pci_power_t __force) 0)
#define PCI_D3cold	((pci_power_t __force) 4)
typedef unsigned int __bitwise pci_channel_state_t;
typedef unsigned int __bitwise pci_ers_result_t;

struct pci_error_handlers {
	/* PCI bus error detected on this device */
	pci_ers_result_t (*error_detected)(struct pci_dev *dev,
					   pci_channel_state_t error);

	/* MMIO has been re-enabled, but not DMA */
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *dev);

	/* PCI slot has been reset */
	pci_ers_result_t (*slot_reset)(struct pci_dev *dev);

	/* PCI function reset prepare or completed */
	void (*reset_prepare)(struct pci_dev *dev);
	void (*reset_done)(struct pci_dev *dev);

	/* Device driver may resume normal operations */
	void (*resume)(struct pci_dev *dev);

	/* Allow device driver to record more details of a correctable error */
	void (*cor_error_detected)(struct pci_dev *dev);
};

/* The driver description a source defines; Stela registers none. */
struct pci_driver {
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *dev, const struct pci_device_id *id);
	void (*remove)(struct pci_dev *dev);
	void (*shutdown)(struct pci_dev *dev);
	int (*sriov_configure)(struct pci_dev *dev, int num_vfs);
	const struct pci_error_handlers *err_handler;
	const struct attribute_group **dev_groups;
	struct device_driver driver;
};

/* Stela's PCI owner configures the function; a source that calls into the
 * PCI core declares the call it uses. */
static int pci_domain_nr(struct pci_bus *bus);
static struct pci_dev *pci_get_domain_bus_and_slot(int domain, unsigned int bus,
						   unsigned int devfn);
static void pci_dev_put(struct pci_dev *dev);
static int pci_enable_device(struct pci_dev *dev);
static void pci_disable_device(struct pci_dev *dev);
static void pci_set_master(struct pci_dev *dev);
static int pci_set_power_state(struct pci_dev *dev, pci_power_t state);
static bool pci_device_is_present(struct pci_dev *pdev);
static int pci_wait_for_pending_transaction(struct pci_dev *dev);
static int pci_wake_from_d3(struct pci_dev *dev, bool enable);
static void pci_ignore_hotplug(struct pci_dev *dev);
static void *pci_get_drvdata(struct pci_dev *pdev);
static void pci_set_drvdata(struct pci_dev *pdev, void *data);
static int pci_register_driver(struct pci_driver *drv);
static void pci_unregister_driver(struct pci_driver *dev);
#endif
