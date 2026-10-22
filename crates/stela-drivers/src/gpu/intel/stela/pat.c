/* SPDX-License-Identifier: MIT */
/* Stela's environment for the unchanged Linux xe_pat.c, which follows. */
#include "pat.h"
#include <linux/array_size.h>
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_gt.h"
#include "xe_gt_mcr.h"
#include "xe_mmio.h"

struct native_pat {
    struct xe_device xe;
    struct xe_gt gt;
    struct stela_intel_pat_result *result;
    bool warning, missing;
};
/* Linux reports WARN_ON without naming a device. Attempts are serialized
 * so a warning names the active one; a concurrent attempt is refused. */
static struct native_pat *active;

static struct native_pat *native_of(struct xe_mmio *mmio)
{
    return container_of(container_of(mmio, struct xe_gt, mmio), struct native_pat, gt);
}
static void xe_mmio_write32(struct xe_mmio *mmio, struct xe_reg reg, u32 value)
{
    mmio->io->write32(mmio->context, reg.addr, value);
    native_of(mmio)->result->writes++;
}
/* Any warning, such as XeLP without LLC, refuses the attempt. */
static void stela_linux_warn(const char *file, int line, const char *condition)
{
    (void)file; (void)line; (void)condition;
    active->warning = true;
}
/* The only message is the missing-table error, which refuses the attempt. */
static void stela_drm_printk(const struct drm_device *drm, enum stela_drm_level level,
    const char *format, ...)
{
    (void)level; (void)format;
    container_of(container_of(drm, struct xe_device, drm), struct native_pat, xe)->missing = true;
}
/* Stela programs only XeLP's direct table and never dumps it: admission
 * refuses the multicast profiles before any I/O. */
static u32 xe_mmio_read32(struct xe_mmio *mmio, struct xe_reg reg)
{
    (void)mmio; (void)reg; __builtin_trap();
}
static u32 xe_gt_mcr_unicast_read_any(struct xe_gt *gt, struct xe_reg_mcr reg_mcr)
{
    (void)gt; (void)reg_mcr; __builtin_trap();
}
static void xe_gt_mcr_multicast_write(struct xe_gt *gt, struct xe_reg_mcr reg_mcr, u32 value)
{
    (void)gt; (void)reg_mcr; (void)value; __builtin_trap();
}
static unsigned int xe_force_wake_get(struct xe_force_wake *fw, unsigned int domains)
{
    (void)fw; (void)domains; __builtin_trap();
}
static void xe_force_wake_put(struct xe_force_wake *fw, unsigned int fw_ref)
{
    (void)fw; (void)fw_ref; __builtin_trap();
}
static void drm_printf(struct drm_printer *p, const char *f, ...)
{
    (void)p; (void)f; __builtin_trap();
}
static int stela_linux_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    (void)buf; (void)size; (void)fmt; __builtin_trap();
}

#include "xe_pat.c"

int stela_intel_pat_program(const struct stela_intel_activation_io *io, void *context,
 const struct stela_intel_activation_facts *facts, struct stela_intel_pat_result *out)
{
 if (!io || !io->write32 || !io->check_context || !facts || !out) return -22;
 if (!facts->platform || facts->platform > INT32_MAX) return -22;
 if (facts->gt_type != XE_GT_TYPE_MAIN || !facts->graphics_verx100 ||
     facts->discrete > 1 || facts->has_llc > 1 ||
     !(facts->initialized & XE_FW_GT) || !(facts->awake & XE_FW_GT)) return -95;
 int status = io->check_context(context);
 if (status) return status;
 struct stela_intel_pat_result result = {0};
 struct native_pat native = {
  .xe.info = {.platform = (enum xe_platform)facts->platform,
              .graphics_verx100 = facts->graphics_verx100, .media_verx100 = facts->media_verx100,
              .is_dgfx = facts->discrete != 0, .has_llc = facts->has_llc != 0,
              .is_sriov_vf = false /* activation admits only physical functions */},
  .gt = {.xe = &native.xe, .info.type = XE_GT_TYPE_MAIN, .mmio = {io, context}},
  .result = &result,
 };
 struct native_pat *idle = NULL;
 if (!__atomic_compare_exchange_n(&active, &idle, &native, false,
                                  __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
  return -EBUSY;
 xe_pat_init_early(&native.xe);
 __atomic_store_n(&active, NULL, __ATOMIC_RELEASE);
 /* Programmer identity is policy, not table equality: DG2 uses the same
  * entries but requires its multicast MCR operations. */
 const struct xe_device *xe = &native.xe;
 if (xe->pat.ops != &xelp_pat_ops || native.warning || native.missing || xe->pat.n_entries != 4 ||
     xe->pat.pat_ats || xe->pat.pat_primary_pta || xe->pat.pat_media_pta) return -95;
 for (int i = 0; i < xe->pat.n_entries; i++) {
  uint32_t offset = (uint32_t)_PAT_INDEX(i);
  if (offset % 4 || offset > XE_REG_ADDR_MAX - 4) return -34;
 }
 result.n_entries = (uint32_t)xe->pat.n_entries;
 result.cache_none = xe->pat.idx[XE_CACHE_NONE];
 result.cache_wt = xe->pat.idx[XE_CACHE_WT];
 result.cache_wb = xe->pat.idx[XE_CACHE_WB];
 result.cache_none_compression = xe->pat.idx[XE_CACHE_NONE_COMPRESSION];
 result.cache_wb_compression = xe->pat.idx[XE_CACHE_WB_COMPRESSION];
 for (int i = 0; i < xe->pat.n_entries; i++) result.entries[i] = xe->pat.table[i].value;
 /* Whole original direct loop; no fallible operation/allocation after effects. */
 xe_pat_init(&native.gt);
 *out = result;
 return 0;
}
