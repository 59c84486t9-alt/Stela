/* SPDX-License-Identifier: MIT */
/* Stela's register access for Xe, in place of xe_mmio.c: each register
 * handle's tile names its device, whose native owner reads and writes BAR0
 * through its canonical uncached mapping. */
#include "device.h"
#include <linux/minmax.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include "regs/xe_gt_regs.h"
#include "xe_gt.h"
#include "xe_mmio.h"
#include "xe_sriov.h"

s64 stela_xe_now_ns(void *context)
{
    const struct stela_xe *dev = context;
    return dev->io->now_ns(dev->context);
}

void stela_xe_delay_us(void *context, u64 minimum, u64 maximum, bool atomic)
{
    const struct stela_xe *dev = context;
    dev->io->delay_us(dev->context, (u32)min_t(u64, minimum, U32_MAX),
                      (u32)min_t(u64, maximum, U32_MAX), atomic);
}

void stela_xe_unsupported(void *context, const char *operation)
{
    struct stela_xe *dev = context;
    if (!dev->unsupported) dev->unsupported = operation;
}

/* Linux bounds a handle's registers by XE_REG_ADDR_MAX; Stela checks each
 * access against the handle's own range instead. */
void xe_mmio_init(struct xe_mmio *mmio, struct xe_tile *tile, void __iomem *ptr, u32 size)
{
    *mmio = (struct xe_mmio){.tile = tile, .regs = ptr, .regs_size = size};
}

/* A GT sees its tile's registers; the media GT's own lie MEDIA_GT_GSI_OFFSET
 * into the tile, below MEDIA_GT_GSI_LENGTH. */
void xe_gt_mmio_init(struct xe_gt *gt)
{
    struct xe_tile *tile = gt_to_tile(gt);
    bool media = gt->info.type == XE_GT_TYPE_MEDIA;
    xe_mmio_init(&gt->mmio, tile, tile->mmio.regs, (u32)tile->mmio.regs_size);
    gt->mmio.adj_offset = media ? MEDIA_GT_GSI_OFFSET : 0;
    gt->mmio.adj_limit = media ? MEDIA_GT_GSI_LENGTH : 0;
    gt->mmio.sriov_vf_gt = IS_SRIOV_VF(tile_to_xe(tile)) ? gt : NULL;
}

void stela_xe_init(struct stela_xe *dev, struct xe_gt *gt, enum xe_gt_type type)
{
    struct xe_tile *tile = &dev->xe.tiles[0];
    dev->xe.sriov.__mode = XE_SRIOV_MODE_NONE;
    tile->xe = &dev->xe;
    xe_mmio_init(&tile->mmio, tile, NULL, SZ_4M);
    memset(gt, 0, sizeof(*gt));
    gt->tile = tile;
    gt->info.type = type;
    if (type == XE_GT_TYPE_MEDIA) tile->media_gt = gt;
    else tile->primary_gt = gt;
    xe_gt_mmio_init(gt);
}

/* Register access needs a device with registers: Stela's adapters that
 * build devices without them run no Linux code that reaches here. */
static struct stela_xe *device_of(struct xe_mmio *mmio)
{
    struct stela_xe *dev = stela_xe(tile_to_xe(mmio->tile));
    if (!dev->io) __builtin_trap();
    return dev;
}

/* The register's BAR0 offset, which must lie in the handle's register range. */
static u32 offset(struct stela_xe *dev, const struct xe_mmio *mmio, struct xe_reg reg)
{
    u32 addr = xe_mmio_adjusted_addr(mmio, reg.addr);
    dev->io->invariant(dev->context, !(addr & 3) && (u64)addr + 4 <= mmio->regs_size &&
                                         addr + 4 <= XE_REG_ADDR_MAX);
    return addr;
}

static void observe(struct stela_xe *dev, u32 addr, u32 value, bool write)
{
    if (dev->observe) dev->observe(dev, addr, value, write);
}

u32 xe_mmio_read32(struct xe_mmio *mmio, struct xe_reg reg)
{
    struct stela_xe *dev = device_of(mmio);
    u32 addr = offset(dev, mmio, reg);
    u32 value = dev->io->read32(dev->context, addr);
    observe(dev, addr, value, false);
    return value;
}

void xe_mmio_write32(struct xe_mmio *mmio, struct xe_reg reg, u32 val)
{
    struct stela_xe *dev = device_of(mmio);
    u32 addr = offset(dev, mmio, reg);
    observe(dev, addr, val, true);
    dev->io->write32(dev->context, addr, val);
}

int xe_mmio_write32_and_verify(struct xe_mmio *mmio, struct xe_reg reg, u32 val, u32 mask,
                               u32 eval)
{
    xe_mmio_write32(mmio, reg, val);
    return (xe_mmio_read32(mmio, reg) & mask) == eval ? 0 : -EINVAL;
}

int stela_intel_mmio_wait32(const struct stela_intel_activation_io *io, void *context,
    uint32_t offset, uint32_t mask, uint32_t value, uint32_t timeout_us, uint32_t *out,
    bool atomic)
{
    io->invariant(context, !(offset & 3) && (uint64_t)offset + 4 <= XE_REG_ADDR_MAX);
    int64_t end = io->now_ns(context) + (int64_t)timeout_us * 1000;
    uint32_t wait = 10, read = io->read32(context, offset);
    int ret = 0;
    while ((read & mask) != value) {
        int64_t now = io->now_ns(context);
        if (now > end) {
            read = io->read32(context, offset);
            ret = (read & mask) == value ? 0 : -ETIMEDOUT;
            break;
        }
        uint32_t left = (uint32_t)((end - now) / 1000) + 1;
        if (wait > left) wait = left;
        io->delay_us(context, wait, atomic ? wait : wait << 1, atomic);
        if (wait < 1000) wait <<= 1;
        read = io->read32(context, offset);
    }
    *out = read;
    return ret;
}

int xe_mmio_wait32(struct xe_mmio *mmio, struct xe_reg reg, u32 mask, u32 val, u32 timeout_us,
                   u32 *out_val, bool atomic)
{
    struct stela_xe *dev = device_of(mmio);
    u32 addr = offset(dev, mmio, reg), read;
    int ret = stela_intel_mmio_wait32(dev->io, dev->context, addr, mask, val, timeout_us, &read,
                                      atomic);
    observe(dev, addr, read, false);
    if (out_val) *out_val = read;
    return ret;
}
