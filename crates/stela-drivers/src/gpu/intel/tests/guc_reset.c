/* SPDX-License-Identifier: MIT */
/* GuC reset handshake over a modelled register file and clock; never a
 * physical reset. */
#include "../guc_reset.h"
#include <stela/test.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "regs/xe_gt_regs.h"
#include "regs/xe_guc_regs.h"
#include "xe_force_wake_types.h"
#include "xe_gt_types.h"

struct model {
    int64_t ns;
    unsigned clear_after; /* GDRST reads before the reset completes; 0 never. */
    bool mia_reset;       /* GUC_STATUS reports the MIA core in reset. */
    int context;
    unsigned reads, writes, gdrst_reads;
    bool reset_written;
};
static int check(void *data) { return ((struct model *)data)->context; }
static uint32_t read32(void *data, uint32_t offset)
{
    struct model *m = data; ++m->reads;
    assert(m->reset_written);
    if (offset == GDRST.addr)
        return m->clear_after && ++m->gdrst_reads >= m->clear_after ? 0 : GRDOM_GUC;
    assert(offset == GUC_STATUS.addr);
    return m->mia_reset ? GS_MIA_IN_RESET : 0;
}
static void write32(void *data, uint32_t offset, uint32_t value)
{
    struct model *m = data; ++m->writes;
    assert(offset == GDRST.addr && value == GRDOM_GUC && !m->reset_written);
    m->reset_written = true;
}
static int64_t now(void *data) { return ((struct model *)data)->ns; }
static void delay(void *data, uint32_t minimum, uint32_t maximum, bool atomic)
{
    assert(minimum <= maximum && !atomic);
    ((struct model *)data)->ns += (int64_t)minimum * 1000;
}
static void invariant(void *data, bool condition) { (void)data; assert(condition); }
static const struct stela_intel_activation_io io = {
    .check_context = check, .read32 = read32, .write32 = write32, .now_ns = now,
    .delay_us = delay, .invariant = invariant,
};
static const struct stela_intel_activation_facts xelp = {
    .platform = 1, .graphics_verx100 = 1200, .media_verx100 = 1200, .tile_count = 1,
    .max_gt_per_tile = 1, .gt_type = XE_GT_TYPE_MAIN, .initialized = XE_FW_GT, .awake = XE_FW_GT,
};

int main(void)
{
    struct stela_intel_guc_reset_result out;
    /* The reset completes and the MIA core reports reset. */
    struct model m = {.clear_after = 3, .mia_reset = true};
    assert(!stela_intel_guc_reset(&io, &m, &xelp, &out));
    assert(out.writes == 1 && !out.gdrst && out.guc_status == GS_MIA_IN_RESET &&
           !out.warnings && !out.ready_status && !out.sram_status);
    assert(m.gdrst_reads == 3 && m.reads == 4);
    /* GDRST never clears within 5 ms. */
    m = (struct model){.mia_reset = true};
    assert(stela_intel_guc_reset(&io, &m, &xelp, &out) == -ETIMEDOUT);
    assert(out.writes == 1 && out.gdrst == GRDOM_GUC && !out.guc_status && m.ns >= 5000000);
    /* GDRST clears but the MIA core is not in reset. */
    m = (struct model){.clear_after = 1};
    assert(stela_intel_guc_reset(&io, &m, &xelp, &out) == -EIO);
    assert(out.writes == 1 && !out.gdrst && !out.guc_status);
    /* Outside the admitted GTs, or before the GT domain is awake: no I/O. */
    unsigned refusals = 0;
    for (unsigned variant = 0; variant < 9; ++variant) {
        struct stela_intel_activation_facts f = xelp;
        switch (variant) {
        case 0: f.gt_type = XE_GT_TYPE_MEDIA; break;
        case 1: f.tile_count = 2; break;
        case 2: f.max_gt_per_tile = 2; break;
        case 3: f.graphics_verx100 = 1199; break;
        case 4: f.graphics_verx100 = 1255; break;
        case 5: f.media_verx100 = 1300; break;
        case 6: f.initialized = 0; break;
        case 7: f.awake = 0; break;
        default: f.graphics_verx100 = 2004; break;
        }
        struct stela_intel_guc_reset_result before;
        memset(&before, 0xa5, sizeof(before));
        out = before;
        m = (struct model){.clear_after = 1, .mia_reset = true};
        assert(stela_intel_guc_reset(&io, &m, &f, &out) == -95);
        assert(!m.reads && !m.writes && !memcmp(&out, &before, sizeof(out)));
        ++refusals;
    }
    /* A lost owner context or missing callback refuses before any I/O. */
    m = (struct model){.clear_after = 1, .mia_reset = true, .context = -16};
    assert(stela_intel_guc_reset(&io, &m, &xelp, &out) == -16 && !m.writes);
    struct stela_intel_activation_io missing = io;
    missing.delay_us = NULL;
    assert(stela_intel_guc_reset(&missing, &m, &xelp, &out) == -22 && !m.writes);
    assert(stela_intel_guc_reset(&io, &m, NULL, &out) == -22 && !m.writes);
    printf("Intel GuC reset: completed, timed-out and not-in-reset handshakes, %u zero-I/O "
           "refusals; modelled registers only\n",
           refusals);
    return 0;
}
