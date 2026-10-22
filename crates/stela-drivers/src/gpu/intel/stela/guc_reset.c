/* SPDX-License-Identifier: MIT */
/* Stela's GuC reset: the register handshake of xe_guc_reset() in Linux's
 * xe_guc.c, over its unchanged register definitions, for the GTs that
 * activation admits. */
#include "guc_reset.h"
#include <linux/errno.h>
#include "regs/xe_gt_regs.h"
#include "regs/xe_guc_regs.h"
#include "xe_force_wake_types.h"
#include "xe_gt_types.h"

int stela_intel_guc_reset(const struct stela_intel_activation_io *io, void *context,
    const struct stela_intel_activation_facts *facts, struct stela_intel_guc_reset_result *out)
{
    if (!io || !io->check_context || !io->read32 || !io->write32 || !io->now_ns ||
        !io->delay_us || !io->invariant || !facts || !out) return -22;
    /* The root main GT of an XeLP device with the GT domain awake. Linux first
     * applies Wa_14025883347 on graphics 20.04-30.05 and media 13.01-35.03
     * (xe_wa_oob.rules), and a VF resets through its PF; neither is admitted. */
    if (facts->gt_type != XE_GT_TYPE_MAIN || facts->tile_count != 1 || facts->max_gt_per_tile != 1 ||
        facts->graphics_verx100 < 1200 || facts->graphics_verx100 > 1210 ||
        facts->media_verx100 > 1210 || !(facts->initialized & XE_FW_GT) ||
        !(facts->awake & XE_FW_GT)) return -95;
    int status = io->check_context(context);
    if (status) return status;
    int64_t now = io->now_ns(context);
    if (now < 0 || now > INT64_MAX - INT64_C(100000000)) return -22;
    struct stela_intel_guc_reset_result result = {.writes = 1};
    io->write32(context, GDRST.addr, GRDOM_GUC);
    status = stela_intel_mmio_wait32(io, context, GDRST.addr, GRDOM_GUC, 0, 5000,
                                     &result.gdrst, false);
    if (!status) {
        result.guc_status = io->read32(context, GUC_STATUS.addr);
        if (!(result.guc_status & GS_MIA_IN_RESET)) status = -EIO;
    }
    *out = result; /* Failure observations keep the owner uncertain. */
    return status;
}
