/* SPDX-License-Identifier: MIT */
#include "wopcm.h"
#include "firmware.h"
#include <linux/types.h>
#include "xe_platform_types.h"
#include "xe_wopcm_types.h"
#include "regs/xe_guc_regs.h"
_Static_assert(sizeof(struct xe_wopcm) == 12, "original WOPCM metadata ABI");
_Static_assert(sizeof(struct guc_doorbell_info) == 64, "original packed doorbell ABI");
_Static_assert(_Alignof(struct guc_doorbell_info) == 1, "original packed alignment");
#include <vdso/align.h>
/* Fixed scalar spellings from retained linux/sizes.h; no Linux services.
 * Original Linux core caller uses its existing size/ALIGN/min definitions. */
#include <linux/errno.h>
#include <linux/minmax.h>
#include <linux/sizes.h>
static void core_warn(void *, unsigned, bool);
#define XE_WOPCM_WARN(core, id, condition) core_warn((core)->context, (id), !!(condition))
#include "xe_wopcm_core.h"

struct native_wopcm {
    const struct stela_intel_activation_io *io;
    void *context;
    struct stela_intel_wopcm_result *result;
    struct stela_intel_activation *activation;
    uint32_t huc_disposition;
};
static u32 native_read(struct native_wopcm *native, struct xe_reg reg)
{
    native->io->invariant(native->context, !(reg.addr & 3) && reg.addr + 4 <= SZ_4M);
    u32 value = native->io->read32(native->context, reg.addr);
    if (reg.addr == DMA_GUC_WOPCM_OFFSET.addr) native->result->raw_offset = value;
    if (reg.addr == GUC_WOPCM_SIZE.addr) native->result->raw_size = value;
    return value;
}
static void native_write(struct native_wopcm *native, struct xe_reg reg, u32 value)
{
    native->io->invariant(native->context, !(reg.addr & 3) && reg.addr + 4 <= SZ_4M);
    ++native->result->writes; /* Exposure begins BEFORE real owner callback. */
    native->io->write32(native->context, reg.addr, value);
}
#define XE_MMIO_VERIFY_NAME native_verify
#define XE_MMIO_VERIFY_CONTEXT struct native_wopcm
#define XE_MMIO_VERIFY_WRITE native_write
#define XE_MMIO_VERIFY_READ native_read
#include "xe_mmio_verify.h"
static u32 core_read(void *context, struct xe_reg reg) { return native_read(context, reg); }
static int core_verify(void *context, struct xe_reg reg, u32 val, u32 mask, u32 eval)
{
    return native_verify(context, reg, val, mask, eval);
}
static bool default_huc_available(void *context)
{
    struct native_wopcm *native = context;
    native->io->invariant(native->context,
        native->huc_disposition == STELA_INTEL_HUC_ABSENT_ROLE ||
        native->huc_disposition == STELA_INTEL_HUC_ABSENT_CATALOG);
    /* Admission proved original unsupported role or missing default path.
     * Selected-but-unfetched/failed HuC can NEVER take this branch. */
    return false;
}
static void core_assert_held(void *context)
{
    struct native_wopcm *native = context;
    stela_intel_activation_assert_gt(native->activation);
}
static void core_warn(void *context, unsigned id, bool condition)
{
    struct native_wopcm *native = context;
    native->io->invariant(native->context, id < 9);
    if (condition) native->result->diagnostics |= UINT32_C(1) << (16 + id);
}
static void core_report(void *context, enum xe_wopcm_event event, u32 a, u32 b, u32 c)
{
    struct native_wopcm *native = context;
    (void)a; (void)b; (void)c;
    native->io->invariant(native->context, (unsigned)event < 10);
    native->result->diagnostics |= UINT32_C(1) << (unsigned)event;
}
int stela_intel_wopcm_prepare(const struct stela_intel_activation_io *io, void *context,
    struct stela_intel_activation *activation, uint32_t platform, uint32_t graphics_verx100, bool discrete,
    const uint8_t *guc_bytes, size_t guc_size, struct stela_intel_wopcm_result *out)
{
    if (!out) return -EINVAL;
    *out = (struct stela_intel_wopcm_result){0};
    if (!io || !io->read32 || !io->write32 || !io->invariant || !guc_bytes || !activation) return -EINVAL;
    struct stela_intel_huc_default huc;
    int status = stela_intel_huc_select_default(platform, graphics_verx100, false, &huc);
    if (status) return status;
    switch (huc.disposition) {
    case STELA_INTEL_HUC_ABSENT_ROLE:
    case STELA_INTEL_HUC_ABSENT_CATALOG:
        break;
    case STELA_INTEL_HUC_SELECTED:
        return -95; /* Genuine HuC input/availability still required. */
    default:
        return -EINVAL;
    }
    struct stela_intel_guc_metadata metadata;
    status = stela_intel_guc_parse(platform, guc_bytes, guc_size,
                                      &metadata, &out->firmware_diagnostics);
    if (status) return status;
    if (metadata.upload_bytes > UINT32_MAX - GUC_WOPCM_RESERVED - GUC_WOPCM_STACK_RESERVED)
        return -75;
    struct native_wopcm native = {io, context, out, activation, huc.disposition};
    static const struct xe_wopcm_core_ops ops = {
        core_read, core_verify, default_huc_available, core_assert_held, core_report,
    };
    const struct xe_wopcm_core core = {&native, &ops};
    struct xe_wopcm wopcm = {0};
    status = xe_wopcm_core_init(&wopcm, (enum xe_platform)platform, discrete,
                              metadata.upload_bytes, 0, &core);
    out->total_bytes = wopcm.size;
    out->guc_base = wopcm.guc.base;
    out->guc_bytes = wopcm.guc.size;
    return status;
}
