/* SPDX-License-Identifier: MIT */
/* The unchanged Linux xe_pat.c, which selects and programs the GPU's PAT
 * table, on a native device over the activated GPU's registers. */
#include "pat.h"
#include "device.h"
#include <linux/string.h>
#include <unsupported.h>
#include "xe_pat.c"

/* Stela programs only XeLP's direct table and never dumps it: admission
 * refuses the multicast profiles before any I/O. */
STELA_UNSUPPORTED(void, xe_gt_mcr_multicast_write, struct xe_gt *, struct xe_reg_mcr, u32)
STELA_UNSUPPORTED(u32, xe_gt_mcr_unicast_read_any, struct xe_gt *, struct xe_reg_mcr)

struct native_pat {
    struct stela_xe dev;
    struct xe_gt gt;
    struct stela_intel_pat_result *result;
    bool refused;
};

static struct native_pat *native_of(void *context)
{
    return container_of((struct stela_xe *)context, struct native_pat, dev);
}
static void observe(struct stela_xe *dev, u32 addr, u32 value, bool write)
{
    (void)addr; (void)value;
    if (write) native_of(dev)->result->writes++;
}
/* A missing table is an error message and a doubtful one a warning: either
 * refuses the attempt. */
static void log_event(void *context, int level, const char *message)
{
    (void)message;
    if (level < LOGLEVEL_DEBUG) native_of(context)->refused = true;
}
static void warn_event(void *context, const char *file, int line, const char *condition)
{
    (void)file; (void)line; (void)condition;
    native_of(context)->refused = true;
}
static const struct stela_linux_services services = {
    .log = log_event, .warn = warn_event, .unsupported = stela_xe_unsupported,
};

/* A native main GT of the device facts describe, whose register writes
 * result counts. */
static void prepare(struct native_pat *native, const struct stela_intel_activation_io *io,
                    void *context, const struct stela_intel_activation_facts *facts,
                    struct stela_intel_pat_result *result)
{
    memset(native, 0, sizeof(*native));
    native->dev.xe.info.platform = (enum xe_platform)facts->platform;
    native->dev.xe.info.graphics_verx100 = facts->graphics_verx100;
    native->dev.xe.info.media_verx100 = facts->media_verx100;
    native->dev.xe.info.is_dgfx = facts->discrete != 0;
    native->dev.xe.info.has_llc = facts->has_llc != 0;
    native->dev.io = io;
    native->dev.context = context;
    native->dev.observe = observe;
    stela_xe_init(&native->dev, &native->gt, XE_GT_TYPE_MAIN);
    native->result = result;
}

/* The device an attempt runs xe_pat.c on. Only the running Linux owner uses
 * it, so there is one. */
static struct native_pat native;

/* Stela programs only XeLP's direct table on an integrated GPU with LLC,
 * whose layout xe_pat.c selects without a warning. Linux warns only once per
 * boot when that LLC is missing, so Stela refuses that case itself. */
static int admit(const struct stela_intel_activation_facts *facts)
{
    if (facts->gt_type != XE_GT_TYPE_MAIN || !facts->graphics_verx100 || facts->discrete > 1 ||
        facts->has_llc > 1 || !(facts->initialized & XE_FW_GT) || !(facts->awake & XE_FW_GT) ||
        (!facts->discrete && !facts->has_llc))
        return -95;
    return 0;
}
/* The selected table, if Stela programs it: XeLP's, by its direct writes.
 * Programmer identity is policy, not table equality: DG2 uses the same
 * entries but requires its multicast MCR operations. */
static int admit_table(const struct native_pat *native, struct stela_intel_pat_result *result)
{
    const struct xe_device *xe = &native->dev.xe;
    if (xe->pat.ops != &xelp_pat_ops || native->refused || native->dev.unsupported ||
        xe->pat.n_entries != 4 || xe->pat.pat_ats || xe->pat.pat_primary_pta ||
        xe->pat.pat_media_pta)
        return -95;
    for (int i = 0; i < xe->pat.n_entries; i++) {
        uint32_t offset = (uint32_t)_PAT_INDEX(i);
        if (offset % 4 || offset > XE_REG_ADDR_MAX - 4) return -34;
    }
    result->n_entries = (uint32_t)xe->pat.n_entries;
    result->cache_none = xe->pat.idx[XE_CACHE_NONE];
    result->cache_wt = xe->pat.idx[XE_CACHE_WT];
    result->cache_wb = xe->pat.idx[XE_CACHE_WB];
    result->cache_none_compression = xe->pat.idx[XE_CACHE_NONE_COMPRESSION];
    result->cache_wb_compression = xe->pat.idx[XE_CACHE_WB_COMPRESSION];
    for (int i = 0; i < xe->pat.n_entries; i++) result->entries[i] = xe->pat.table[i].value;
    return 0;
}

int stela_intel_pat_program(const struct stela_intel_activation_io *io, void *context,
    const struct stela_intel_activation_facts *facts, struct stela_intel_pat_result *out)
{
    if (!io || !io->write32 || !io->invariant || !io->check_context || !facts || !out) return -22;
    if (!facts->platform || facts->platform > INT32_MAX) return -22;
    int status = admit(facts);
    if (status) return status;
    status = io->check_context(context);
    if (status) return status;
    struct stela_intel_pat_result result = {0};
    const struct stela_linux_owner owner = {.services = &services, .context = &native.dev};
    stela_linux_enter(&owner);
    prepare(&native, io, context, facts, &result);
    xe_pat_init_early(&native.dev.xe);
    status = admit_table(&native, &result);
    /* Whole original direct loop; no fallible operation/allocation after effects. */
    if (!status) xe_pat_init(&native.gt);
    stela_linux_exit();
    if (!status) *out = result;
    return status;
}
