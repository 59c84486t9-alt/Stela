/* SPDX-License-Identifier: MIT */
#include "fixture.h"
#include <linux/pci_ids.h>
#include <linux/pci.h>
#include <linux/mod_devicetable.h>
#include <stela/registration.h>
/* Both TUs intentionally use the same static callback and parameter spellings. */
static int duplicate(void) { stela_registry_fixture_event(10); return 0; }
static void leave(void) { stela_registry_fixture_event(11); }
static int count;
static char *borrowed;
static int setup(char *value) { borrowed = value; stela_registry_fixture_event(12); return 1; }
static int early(char *value) { borrowed = value; stela_registry_fixture_event(13); return 0; }
static const struct pci_device_id ids[] = {
 { PCI_DEVICE(PCI_VENDOR_ID_NVIDIA, 0x1f02) }, { }
};
module_param(count, int, 0644);
MODULE_PARM_DESC(count, "first occurrence");
module_param(borrowed, charp, 0);
__setup("fixture=", setup);
early_param("fixture_early", early);
MODULE_DEVICE_TABLE(pci, ids);
MODULE_INFO(alias, "fixture:first");
MODULE_LICENSE("GPL");
/* Same target at several phases is intentional; no private fn-name identity. */
early_initcall(duplicate);
pure_initcall(duplicate);
core_initcall(duplicate);
core_initcall_sync(duplicate);
postcore_initcall(duplicate);
postcore_initcall_sync(duplicate);
arch_initcall(duplicate);
arch_initcall_sync(duplicate);
subsys_initcall(duplicate);
subsys_initcall_sync(duplicate);
fs_initcall(duplicate);
fs_initcall_sync(duplicate);
rootfs_initcall(duplicate);
device_initcall(duplicate);
device_initcall_sync(duplicate);
late_initcall(duplicate);
late_initcall_sync(duplicate);
console_initcall(duplicate);
module_init(duplicate);
module_exit(leave);

const struct kernel_param *stela_fixture_first_count(void)
{
 return &__param_count;
}

const struct kernel_param *stela_fixture_first_borrowed(void)
{
 return &__param_borrowed;
}
