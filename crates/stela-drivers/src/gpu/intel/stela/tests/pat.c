/* SPDX-License-Identifier: MIT */
/* The unchanged xe_pat.c in Stela's environment; modelled register writes,
 * CPU only. */
#include <stela/test.h>
#include "../pat.c"
struct stela_pat_test_policy {
    uint32_t profile, count, warning, missing, special;
    uint16_t indices[__XE_CACHE_LEVEL_COUNT];
    struct xe_pat_table_entry entries[32], ats, primary, media;
};
struct stela_pat_trace {
    uint32_t count, offset[34], value[34];
};
static struct stela_pat_trace trace;
static void native_write(void *context, uint32_t offset, uint32_t value)
{
    (void)context;
    assert(trace.count < 34);
    trace.offset[trace.count] = offset;
    trace.value[trace.count++] = value;
}
static int check(void *context) { return *(int *)context; }
static void invariant(void *context, bool condition)
{
    (void)context;
    assert(condition);
}
static const struct stela_intel_activation_io trace_io = {
    .write32 = native_write, .invariant = invariant};
static uint32_t profile(const struct xe_pat_ops *ops)
{
    const struct xe_pat_ops *profiles[] = {&xelp_pat_ops, &xehp_pat_ops, &xehpc_pat_ops,
        &xelpg_pat_ops, &xe2_pat_ops, &xe3p_xpc_pat_ops};
    for (uint32_t i = 0; i < ARRAY_SIZE(profiles); i++)
        if (ops == profiles[i]) return i + 1;
    assert(0 && "unknown PAT programmer");
}
/* Start from the XE2 programmer: the missing-table path keeps whatever ops
 * the device already had. */
static void selected(struct native_pat *pat, struct stela_pat_test_policy *out)
{
    pat->dev.xe.pat.ops = &xe2_pat_ops;
    const struct stela_linux_owner owner = {.services = &services, .context = &pat->dev};
    stela_linux_enter(&owner);
    xe_pat_init_early(&pat->dev.xe);
    stela_linux_exit();
    const struct xe_device *xe = &pat->dev.xe;
    *out = (struct stela_pat_test_policy){.profile = profile(xe->pat.ops),
        .count = (uint32_t)xe->pat.n_entries,
        .warning = pat->refused,
        .missing = !xe->pat.table};
    memcpy(out->indices, xe->pat.idx, sizeof(out->indices));
    if (xe->pat.n_entries)
        memcpy(out->entries, xe->pat.table, (size_t)xe->pat.n_entries * sizeof(*xe->pat.table));
    if (xe->pat.pat_ats) {
        out->special |= 1;
        out->ats = *xe->pat.pat_ats;
    }
    if (xe->pat.pat_primary_pta) {
        out->special |= 2;
        out->primary = *xe->pat.pat_primary_pta;
    }
    if (xe->pat.pat_media_pta) {
        out->special |= 4;
        out->media = *xe->pat.pat_media_pta;
    }
}
int main(void)
{
    const uint32_t versions[] = {0, 1100, 1200, 1210, 1211, 1250, 1255, 1260, 1270, 1271, 1274,
        1999, 2000, 2001, 2002, 2004, 2099, 3000, 3001, 3003, 3004, 3005, 3099, 3500, 3510, 3511,
        3512, 3599, 3600, 4000};
    _Static_assert(_PAT_INDEX(7) == 0x481c, "original first range end");
    _Static_assert(_PAT_INDEX(8) == 0x4848, "original second range start");
    _Static_assert(_PAT_INDEX(31) == 0x48a4, "original 32-entry span");
    unsigned cases = 0, traces = 0, held = 0;
    for (unsigned p = 0; p <= XE_NOVALAKE_P; p++)
        for (unsigned v = 0; v < ARRAY_SIZE(versions); v++)
            for (unsigned d = 0; d < 2; d++)
                for (unsigned llc = 0; llc < 2; llc++) {
                    // These cross-products do not describe any retained matched device and
                    // violate the original ops->entry_dump debug postcondition. Keep them
                    // explicit holds, not a successful policy/hardware qualification.
                    unsigned generation = versions[v] / 100;
                    if (generation >= 20 && generation != 20 && generation != 30 &&
                        generation != 35 && (p == XE_METEORLAKE || p == XE_PVC || p == XE_DG2)) {
                        ++held;
                        continue;
                    }
                    struct stela_pat_test_policy actual;
                    struct stela_intel_pat_result result = {0};
                    const struct stela_intel_activation_facts f = {.platform = p,
                        .graphics_verx100 = versions[v],
                        .media_verx100 = 1200,
                        .discrete = d,
                        .has_llc = llc};
                    struct native_pat pat = {0};
                    prepare(&pat, &trace_io, NULL, &f, &result);
                    selected(&pat, &actual);
                    ++cases;
                    if (actual.missing) continue;
                    /* Every selected table through the direct programmer, entry by entry. */
                    trace = (struct stela_pat_trace){0};
                    const struct stela_linux_owner owner = {
                        .services = &services, .context = &pat.dev};
                    stela_linux_enter(&owner);
                    program_pat(&pat.gt, pat.dev.xe.pat.table, pat.dev.xe.pat.n_entries);
                    stela_linux_exit();
                    unsigned n = actual.count;
                    for (unsigned i = 0; i < actual.count; i++)
                        assert(trace.offset[i] == _PAT_INDEX(i) &&
                            trace.value[i] == actual.entries[i].value);
                    /* Then the ATS entry, then the main GT's PTA entry. */
                    if (actual.special & 1) {
                        assert(trace.offset[n] == _PAT_ATS && trace.value[n] == actual.ats.value);
                        n++;
                    }
                    if (actual.special & 2) {
                        assert(trace.offset[n] == _PAT_PTA &&
                            trace.value[n] == actual.primary.value);
                        n++;
                    }
                    assert(trace.count == n);
                    const struct stela_pat_trace a = trace;
                    ++traces;
                    if (versions[v] == 2001) assert(actual.count == 28);
                    if (versions[v] / 100 == 20 || versions[v] / 100 == 30) {
                        for (unsigned i = 16; i < 20; i++) {
                            if (i == 16 && versions[v] / 100 == 30)
                                assert(actual.entries[i].valid == 1);
                            else
                                assert(actual.entries[i].value == 0 &&
                                    actual.entries[i].valid == 0 &&
                                    actual.entries[i].coh_mode == 0);
                        }
                    } // Original CLOS3 workaround.
                    if (versions[v] == 3511)
                        assert(actual.count == 32 && actual.indices[XE_CACHE_WT] == 3 &&
                            actual.special == 7);
                    if (versions[v] <= 1210 && p != XE_METEORLAKE && p != XE_PVC && p != XE_DG2) {
                        assert(actual.count == 4 && !actual.special &&
                            actual.indices[XE_CACHE_WB] == 0);
                        assert(actual.indices[XE_CACHE_NONE_COMPRESSION] == UINT16_MAX &&
                            actual.indices[XE_CACHE_WB_COMPRESSION] == UINT16_MAX);
                        assert(actual.entries[0].value == 3 && actual.entries[1].value == 1 &&
                            actual.entries[2].value == 2 && actual.entries[3].value == 0);
                        for (unsigned i = 0; i < 4; i++) assert(a.offset[i] == 0x4800 + 4 * i);
                    }
                }
    int context = 0;
    struct stela_intel_activation_io io = {
        .check_context = check, .write32 = native_write, .invariant = invariant};
    struct stela_intel_activation_facts facts = {.platform = XE_TIGERLAKE,
        .graphics_verx100 = 1200,
        .has_llc = 1,
        .gt_type = 1,
        .initialized = 1,
        .awake = 1};
    struct stela_intel_pat_result out, before;
    memset(&before, 0xa5, sizeof(before));
    unsigned refusals = 0;
    for (unsigned variant = 0; variant < 10; variant++) {
        struct stela_intel_activation_facts f = facts;
        out = before;
        trace = (struct stela_pat_trace){0};
        int expected = -95;
        switch (variant) {
        case 0: f.gt_type = 2; break;
        case 1: f.has_llc = 0; break;
        case 2: f.awake = 0; break;
        case 3:
            f.platform = XE_DG2;
            f.graphics_verx100 = 1255;
            f.discrete = 1;
            break;
        case 4:
            f.platform = XE_METEORLAKE;
            f.graphics_verx100 = 1270;
            break;
        case 5: f.graphics_verx100 = 4000; break;
        case 6:
            context = -16;
            expected = -16;
            break;
        case 7: f.awake = 2; break;
        case 8: f.has_llc = 2; break;
        case 9:
            f.platform = XE_METEORLAKE;
            f.graphics_verx100 = 4000;
            break;
        }
        assert(stela_intel_pat_program(&io, &context, &f, &out) == expected);
        assert(!trace.count && !memcmp(&out, &before, sizeof(out)));
        context = 0;
        ++refusals;
    }
    out = before;
    trace = (struct stela_pat_trace){0};
    assert(!stela_intel_pat_program(&io, &context, &facts, &out));
    assert(trace.count == 4 && out.writes == 4 && out.n_entries == 4 && out.cache_none == 3 &&
        out.cache_wt == 2 && out.cache_wb == 0);
    assert(out.cache_none_compression == UINT16_MAX && out.cache_wb_compression == UINT16_MAX);
    const uint32_t values[] = {3, 1, 2, 0};
    for (unsigned i = 0; i < 4; i++)
        assert(trace.offset[i] == 0x4800 + 4 * i && trace.value[i] == values[i] &&
            out.entries[i] == values[i]);
    printf("Intel PAT: %u unchanged-source policies, %u full direct/ATS/PTA traces, %u zero-I/O "
           "refusals; %u impossible platform/version holds; independent XeLP values/order/cache "
           "and modern limits; CPU only\n",
        cases, traces, refusals, held);
    return 0;
}
