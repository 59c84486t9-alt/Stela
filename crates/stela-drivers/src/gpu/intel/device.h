/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_DEVICE_H
#define STELA_INTEL_DEVICE_H
/* A Linux xe_device that Stela runs Linux code on, with the native owner of
 * its BAR0 registers, clock and delays. Every xe_device Stela creates is one;
 * each register handle reaches it through its tile. */
#include "activation.h"
#include "xe_device_types.h"
#include "xe_gt_types.h"
#include <stela/linux.h>

struct stela_xe {
    struct xe_device xe;
    const struct stela_intel_activation_io *io;
    void *context;
    /* Optional: sees each register access, before a write and after a read
     * or a wait's last read. */
    void (*observe)(struct stela_xe *dev, u32 addr, u32 value, bool write);
    /* The first operation Linux code reported unsupported for this device. */
    const char *unsupported;
};

static inline struct stela_xe *stela_xe(struct xe_device *xe)
{
    return container_of(xe, struct stela_xe, xe);
}

/* Services for Linux code run on a device's behalf, whose context is its
 * struct stela_xe: the owner's clock and delays, and graceful mode's record
 * of the first unsupported operation, after which the adapter fails its call
 * with -EOPNOTSUPP. */
s64 stela_xe_now_ns(void *context);
void stela_xe_delay_us(void *context, u64 minimum, u64 maximum, bool atomic);
void stela_xe_unsupported(void *context, const char *operation);

/* Links a device of one tile, whose registers are BAR0's first 4 MiB, and
 * one GT of the given type, as Linux's probe does before it touches either.
 * For adapters that build a device of their own; its info comes first. */
void stela_xe_init(struct stela_xe *dev, struct xe_gt *gt, enum xe_gt_type type);
#endif
