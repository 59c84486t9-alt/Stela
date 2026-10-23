/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Stela's owner over the complete upstream I801 C driver. Platform
 * attachment remains with the caller, exactly as for the existing Rust engine.
 * IRQ, ACPI, mux, target, runtime power and Linux device registration are not
 * exposed by this polled adapter. No source extraction; one recorded upstream recovery patch. */
#include "driver.h"
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <stela/linux.h>
#include <stela/module.h>

static u8 owner_read8(const void __iomem *address);
static void owner_write8(u8 value, void __iomem *address);
static void owner_read8_rep(const void __iomem *address, void *buffer, unsigned long count);
static void owner_write8_rep(void __iomem *address, const void *buffer, unsigned long count);

/* The native owner supplies ordered register operations, for either real PIO
 * or an independent controller model. Linux's own register sequencing stays. */
#undef ioread8
#undef iowrite8
#undef ioread8_rep
#undef iowrite8_rep
#define ioread8 owner_read8
#define iowrite8 owner_write8
#define ioread8_rep owner_read8_rep
#define iowrite8_rep owner_write8_rep
#undef jiffies
static unsigned long stela_i801_jiffies;
#define jiffies stela_i801_jiffies

#include "i2c-i801.c"
#include <unsupported.h>

/* Whole-file linkage includes Linux's platform/probe/IRQ paths. This adapter
 * never registers a Linux device or enables FEATURE_IRQ/HOST_NOTIFY, and its
 * public operation enum cannot select arbitrary I2C block transfers. Missing
 * services in those unexposed paths stop explicitly if reached; none returns
 * a successful-looking platform/IRQ/configuration result. */
STELA_UNSUPPORTED(void, __init_swait_queue_head, struct swait_queue_head *, const char *, struct lock_class_key *)
STELA_UNSUPPORTED(void, complete, struct completion *)
STELA_UNSUPPORTED(unsigned long, wait_for_completion_timeout, struct completion *, unsigned long)
STELA_UNSUPPORTED(void *, devm_kmalloc, struct device *, size_t, gfp_t)
STELA_UNSUPPORTED(int, devm_request_threaded_irq, struct device *, unsigned int, irq_handler_t,
                  irq_handler_t, unsigned long, const char *, void *)
STELA_UNSUPPORTED(int, i2c_add_adapter, struct i2c_adapter *)
STELA_UNSUPPORTED(void, i2c_del_adapter, struct i2c_adapter *)
STELA_UNSUPPORTED(int, i2c_handle_smbus_host_notify, struct i2c_adapter *, unsigned short)
STELA_UNSUPPORTED(int, pci_read_config_byte, const struct pci_dev *, int, u8 *)
STELA_UNSUPPORTED(int, pci_read_config_word, const struct pci_dev *, int, u16 *)
STELA_UNSUPPORTED(int, pci_read_config_dword, const struct pci_dev *, int, u32 *)
STELA_UNSUPPORTED(int, pci_write_config_byte, const struct pci_dev *, int, u8)
STELA_UNSUPPORTED(void __iomem *, pcim_iomap_region, struct pci_dev *, int, const char *)
STELA_UNSUPPORTED(struct platform_device *, platform_device_register_full, const struct platform_device_info *)
STELA_UNSUPPORTED(void, platform_device_unregister, struct platform_device *)

struct stela_i801 {
    struct i801_priv device;
    struct pci_dev pci;
    struct stela_i801_io io;
    void *context;
    u64 epoch_us;
};

static struct stela_i801 *i801_owner(void)
{
    return stela_linux_owner()->context;
}

static u8 register_offset(const void __iomem *address)
{
    uintptr_t offset = (uintptr_t)address - (uintptr_t)i801_owner()->device.smba;
    if (offset >= 32) __builtin_trap();
    return (u8)offset;
}

static u8 owner_read8(const void __iomem *address)
{
    struct stela_i801 *owner = i801_owner();
    stela_i801_jiffies = (owner->io.now_us(owner->context) - owner->epoch_us) / 1000;
    return owner->io.read8(owner->context, register_offset(address));
}
static void owner_write8(u8 value, void __iomem *address)
{
    struct stela_i801 *owner = i801_owner();
    owner->io.write8(owner->context, register_offset(address), value);
}
static void owner_read8_rep(const void __iomem *address, void *buffer, unsigned long count)
{
    u8 *bytes = buffer;
    while (count--) *bytes++ = owner_read8(address);
}
static void owner_write8_rep(void __iomem *address, const void *buffer, unsigned long count)
{
    const u8 *bytes = buffer;
    while (count--) owner_write8(*bytes++, address);
}
static s64 now_ns(void *context)
{
    struct stela_i801 *owner = context;
    u64 elapsed = owner->io.now_us(owner->context) - owner->epoch_us;
    if (elapsed > INT64_MAX / 1000) __builtin_trap();
    return (s64)(elapsed * 1000);
}
static void delay(void *context, u64 minimum, u64 maximum, bool atomic)
{
    struct stela_i801 *owner = context;
    (void)maximum; (void)atomic;
    if (minimum > UINT32_MAX) __builtin_trap();
    owner->io.delay_us(owner->context, (u32)minimum);
    stela_i801_jiffies = (owner->io.now_us(owner->context) - owner->epoch_us) / 1000;
}
static void unsupported(void *context, const char *operation)
{
    (void)context; (void)operation;
    __builtin_trap();
}
static const struct stela_linux_services services = {
    .now_ns = now_ns, .delay_us = delay, .unsupported = unsupported,
};

void *stela_i801_create(const struct stela_i801_io *io, void *context, uint16_t device,
                        uint8_t host_configuration, uint32_t timeout_us, int buffer)
{
    if (!io || !io->read8 || !io->write8 || !io->now_us || !io->delay_us || !timeout_us)
        return NULL;
    struct stela_i801 *owner = kzalloc_obj(*owner);
    if (!owner) return NULL;
    owner->pci.vendor = PCI_VENDOR_ID_INTEL;
    owner->pci.device = device;
    owner->pci.dev.init_name = "stela-i801";
    const struct pci_device_id *id = pci_match_id(i801_ids, &owner->pci);
    if (!id) { kfree(owner); return NULL; }
    owner->io = *io;
    owner->context = context;
    owner->device.pci_dev = &owner->pci;
    owner->device.smba = (void __iomem *)(uintptr_t)0x1000;
    owner->device.original_hstcfg = host_configuration;
    owner->device.features = buffer ? id->driver_data & FEATURE_BLOCK_BUFFER : 0;
    owner->device.adapter.timeout = (timeout_us + 999ULL) / 1000;
    i2c_set_adapdata(&owner->device.adapter, &owner->device);
    mutex_init(&owner->device.acpi_lock);
    return owner;
}

void stela_i801_destroy(void *opaque)
{
    kfree(opaque);
}

int stela_i801_transfer(void *opaque, uint8_t address, uint8_t read, uint8_t command,
                        int protocol, uint8_t *bytes, uint8_t *length)
{
    struct stela_i801 *owner = opaque;
    if (!owner || !bytes || !length || *length > I2C_SMBUS_BLOCK_MAX) return -EINVAL;
    union i2c_smbus_data data = {};
    if (protocol == I2C_SMBUS_BLOCK_DATA) {
        data.block[0] = *length;
        memcpy(data.block + 1, bytes, *length);
    } else { data.word = (u16)((u16)bytes[0] | (u16)bytes[1] << 8); }
    const struct stela_linux_owner running = {.services = &services, .context = owner};
    owner->epoch_us = owner->io.now_us(owner->context);
    stela_linux_enter(&running);
    stela_i801_jiffies = (owner->io.now_us(owner->context) - owner->epoch_us) / 1000;
    int result = smbus_algorithm.smbus_xfer(&owner->device.adapter, address, 0,
                                           read, command, protocol, &data);
    stela_linux_exit();
    if (result) return result;
    if (protocol == I2C_SMBUS_BLOCK_DATA) {
        if (data.block[0] < 1 || data.block[0] > I2C_SMBUS_BLOCK_MAX) return -EPROTO;
        *length = data.block[0];
        memcpy(bytes, data.block + 1, *length);
    } else { bytes[0] = (u8)data.word; bytes[1] = (u8)(data.word >> 8); }
    return 0;
}
