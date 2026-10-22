/* SPDX-License-Identifier: MIT */
#include "guc_reset.h"
#include <linux/types.h>
#include "xe_gt_type.h"
#include "xe_force_wake_domain_types.h"
#include "regs/xe_gt_regs.h"
#include "regs/xe_guc_regs.h"
#include "abi/guc_errors_abi.h"
#include <linux/bitfield.h>
#include <linux/errno.h>

/* Qualification proof, not a copied WA selector. This is the unchanged entry
 * emitted by the original OOB generator. Both original version-range branches
 * must exclude EVERY version admitted below. A new clause/token or overlap is
 * a hard compile failure requiring deliberate original-matcher qualification. */
#define XE_RTP_NAME(name) 0
#define XE_RTP_RULES(...) __VA_ARGS__
#define STELA_GUC_RESET_RANGE(first, last) \
    sizeof(struct { _Static_assert((first) > 1210 && (last) >= (first), \
        "native XeLP admission must exclude the actual original reset WA"); char proof; })
#define MEDIA_VERSION_RANGE(first, last) STELA_GUC_RESET_RANGE(first, last)
#define GRAPHICS_VERSION_RANGE(first, last) STELA_GUC_RESET_RANGE(first, last)
#define OR 0
static const size_t wa_qualification[][4] __attribute__((unused)) = {
#include "guc_reset_wa.inc"
};
_Static_assert(sizeof(wa_qualification) / sizeof(wa_qualification[0]) == 1, "one original reset WA entry");
#undef OR
#undef GRAPHICS_VERSION_RANGE
#undef MEDIA_VERSION_RANGE
#undef STELA_GUC_RESET_RANGE
#undef XE_RTP_RULES
#undef XE_RTP_NAME

struct native_reset {
    const struct stela_intel_activation_io *io;
    void *context;
    struct stela_intel_activation *activation;
    struct stela_intel_guc_reset_result *result;
};
static u32 native_read(struct native_reset *native, struct xe_reg reg)
{
    native->io->invariant(native->context, !(reg.addr & 3) && reg.addr <= SZ_4M - 4);
    u32 value = native->io->read32(native->context, reg.addr);
    if (reg.addr == GDRST.addr) native->result->gdrst = value;
    if (reg.addr == GUC_STATUS.addr) native->result->guc_status = value;
    return value;
}
static void native_write(struct native_reset *native, struct xe_reg reg, u32 value)
{
    native->io->invariant(native->context, !(reg.addr & 3) && reg.addr <= SZ_4M - 4);
    ++native->result->writes; /* Exposure recorded before actual owner callback. */
    native->io->write32(native->context, reg.addr, value);
}
static void native_rmw(struct native_reset *native, struct xe_reg reg, u32 clear, u32 set)
{
    u32 value = native_read(native, reg);
    value &= ~clear;
    value |= set;
    native_write(native, reg, value);
}
static int64_t add_us(int64_t time, int64_t us) { return time + us * 1000; }
#define XE_MMIO_POLL_NAME native_poll
#define XE_MMIO_POLL_CONTEXT struct native_reset
#define XE_MMIO_POLL_TIME int64_t
#define XE_MMIO_POLL_NOW(mmio) ((mmio)->io->now_ns((mmio)->context))
#define XE_MMIO_POLL_ADD_US add_us
#define XE_MMIO_POLL_READ native_read
#define XE_MMIO_POLL_BEFORE(a, b) ((a) < (b))
#define XE_MMIO_POLL_AFTER(a, b) ((a) > (b))
#define XE_MMIO_POLL_DELTA_US(a, b) (((a) - (b)) / 1000)
#define XE_MMIO_POLL_DELAY(mmio, wait, atomic) \
    (mmio)->io->delay_us((mmio)->context, (uint32_t)(wait), \
                         (uint32_t)((atomic) ? (wait) : ((wait) << 1)), (atomic))
#include "xe_mmio_poll.h"
#define XE_GUC_RESET_CONTEXT struct native_reset
#define XE_GUC_RESET_READ native_read
#define XE_GUC_RESET_WRITE native_write
#define XE_GUC_RESET_RMW native_rmw
#define XE_GUC_RESET_WAIT(n, reg, mask, value, timeout, out, atomic) \
    native_poll(n, reg, mask, value, timeout, out, atomic, true)
#define XE_GUC_RESET_ASSERT_HELD(n) stela_intel_activation_assert_gt((n)->activation)
#define XE_GUC_RESET_IS_VF(n) false
#define XE_GUC_RESET_VF_BOOTSTRAP(n) (-95)
/* Compile-time generated original-entry proof plus actual version preflight
 * makes this false; no default for an unqualified modern/media/VF path. */
#define XE_GUC_RESET_WA_14025883347(n) false
#define XE_GUC_RESET_WARN_READY(n, value) \
    ((n)->result->warnings |= 1u, (n)->result->ready_status = (value))
#define XE_GUC_RESET_WARN_SRAM(n, value) \
    ((n)->result->warnings |= 2u, (n)->result->sram_status = (value))
#define XE_GUC_RESET_ERROR_TIMEOUT(n, value) ((n)->result->gdrst = (value))
#define XE_GUC_RESET_ERROR_STATUS(n, value) ((n)->result->guc_status = (value))
#include "xe_guc_reset_core.h"

int stela_intel_guc_reset(const struct stela_intel_activation_io *io, void *context,
    struct stela_intel_activation *activation, const struct stela_intel_activation_facts *facts,
    struct stela_intel_guc_reset_result *out)
{
    if (!io || !io->check_context || !io->read32 || !io->write32 || !io->now_ns ||
        !io->delay_us || !io->invariant || !activation || !facts || !out) return -22;
    /* Current native method uses actual matched root-main XeLP facts, not CPU
     * or a curated PCI list. The original whole modern/WA/VF policy is retained
     * in the shared core but awaits its genuine owner/matcher prerequisites. */
    if (facts->gt_type != XE_GT_TYPE_MAIN || facts->tile_count != 1 || facts->max_gt_per_tile != 1 ||
        facts->graphics_verx100 < 1200 || facts->graphics_verx100 > 1210 ||
        facts->media_verx100 > 1210 || !(facts->initialized & XE_FW_GT) ||
        !(facts->awake & XE_FW_GT)) return -95;
    int status = io->check_context(context);
    if (status) return status;
    int64_t now = io->now_ns(context);
    if (now < 0 || now > INT64_MAX - INT64_C(100000000)) return -22;
    struct stela_intel_guc_reset_result result = {0};
    struct native_reset native = {io, context, activation, &result};
    status = xe_guc_reset_core(&native);
    *out = result; /* Actual failure observations must retain uncertain owner. */
    return status;
}
