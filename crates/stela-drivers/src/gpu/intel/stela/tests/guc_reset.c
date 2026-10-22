/* SPDX-License-Identifier: MIT */
/* Complete original/reset Linux-caller trace model, not physical hardware. */
#include "guc_reset_model.h"
#include "../guc_reset.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ETIMEDOUT 110
static void event(struct reset_test_model *m, u32 kind, u32 reg, u32 a, u32 b, u32 c)
{
    assert(m->events < 256);
    m->trace[m->events++] = (struct reset_test_event){kind, reg, a, b, c, m->ns};
}
u32 reset_test_read(struct reset_test_mmio *mmio, struct xe_reg reg)
{
    struct reset_test_model *m = mmio->owner;
    u32 value;
    switch (reg.addr) {
    case 0xc000: /* Actual GUC_STATUS */
        if (m->reset_written) value = m->mia_reset ? GS_MIA_IN_RESET : 0;
        else if (m->initial_reset) value = GS_MIA_IN_RESET;
        else if (m->idle_written && (uint64_t)(m->ns - m->idle_at) / 1000 >= m->ready_us)
            value = REG_FIELD_PREP(GS_UKERNEL_MASK, XE_GUC_LOAD_STATUS_READY);
        else value = 0;
        break;
    case 0xc010: value = m->boot_valid ? GUC_BOOT_UKERNEL_VALID : 0; break;
    case 0xc3e4: value = m->idle; break;
    case 0xc398:
        if (!m->sram_started) { m->sram_started = true; m->sram_at = m->ns; }
        value = (uint64_t)(m->ns - m->sram_at) / 1000 >= m->sram_us ? 0 : GUC_SRAM_HANDLING_MASK;
        break;
    case 0x941c:
        assert(m->reset_written);
        m->gdrst_reads++;
        value = ((uint64_t)(m->ns - m->reset_at) / 1000 >= m->clear_us ||
                 (m->gdrst_clear_read && m->gdrst_reads >= m->gdrst_clear_read)) ? 0 : GRDOM_GUC;
        break;
    default: abort();
    }
    event(m, 'R', reg.addr, value, 0, 0);
    return value;
}
void reset_test_write(struct reset_test_mmio *mmio, struct xe_reg reg, u32 value)
{
    struct reset_test_model *m = mmio->owner;
    event(m, 'W', reg.addr, value, 0, 0);
    if (reg.addr == GDRST.addr) {
        assert(value == GRDOM_GUC); m->reset_written = true; m->reset_at = m->ns;
    } else {
        assert(reg.addr == GUC_MAX_IDLE_COUNT.addr);
        assert(value == (m->idle | GUC_IDLE_FLOW_DISABLE));
        m->idle = value; m->idle_written = true; m->idle_at = m->ns;
    }
}
u32 reset_test_rmw(struct reset_test_mmio *mmio, struct xe_reg reg, u32 clear, u32 set)
{
    u32 value = reset_test_read(mmio, reg);
    value &= ~clear; value |= set;
    reset_test_write(mmio, reg, value);
    return value;
}
static int64_t model_add_us(int64_t time, int64_t us) { return time + us * 1000; }
static int64_t model_now(struct reset_test_mmio *mmio) { return mmio->owner->ns; }
static void model_delay(struct reset_test_mmio *mmio, int64_t wait, bool atomic)
{
    assert(!atomic); assert(wait >= 0 && wait <= 100000);
    event(mmio->owner, 'D', 0, (u32)wait, (u32)wait * 2, (u32)atomic);
    mmio->owner->ns += wait * 1000;
}
#define XE_MMIO_POLL_NAME model_poll
#define XE_MMIO_POLL_CONTEXT struct reset_test_mmio
#define XE_MMIO_POLL_TIME int64_t
#define XE_MMIO_POLL_NOW model_now
#define XE_MMIO_POLL_ADD_US model_add_us
#define XE_MMIO_POLL_READ reset_test_read
#define XE_MMIO_POLL_BEFORE(a, b) ((a) < (b))
#define XE_MMIO_POLL_AFTER(a, b) ((a) > (b))
#define XE_MMIO_POLL_DELTA_US(a, b) (((a) - (b)) / 1000)
#define XE_MMIO_POLL_DELAY model_delay
#include "xe_mmio_poll.h"
int reset_test_wait(struct reset_test_mmio *mmio, struct xe_reg reg, u32 mask, u32 value,
                    u32 timeout, u32 *out, bool atomic)
{
    event(mmio->owner, 'P', reg.addr, mask, value, timeout);
    return model_poll(mmio, reg, mask, value, timeout, out, atomic, true);
}
void reset_test_assert(struct reset_test_model *m, unsigned domains)
{
    assert(m->held && domains == 1); event(m, 'A', 0, domains, 0, 0);
}
bool reset_test_wa(struct reset_test_model *m, uint64_t id)
{
    assert(id == UINT64_C(14025883347)); event(m, 'Q', 0, (u32)m->wa, 0, 0); return m->wa;
}
int reset_test_bootstrap(struct reset_test_model *m)
{
    event(m, 'V', 0, (u32)m->bootstrap_status, 0, 0); return m->bootstrap_status;
}
void reset_test_diagnostic(struct reset_test_model *m, const char *format, u32 value)
{
    u32 kind;
    if (!strcmp(format, "GuC not ready after disabling idle flow (GUC_STATUS: 0x%x)\n")) {
        kind = 1; m->warnings |= 1;
    } else if (!strcmp(format, "SRAM handling not complete (GUC_SRAM_STATUS: 0x%x)\n")) {
        kind = 2; m->warnings |= 2;
    } else if (!strcmp(format, "GuC reset timed out, GDRST=%#x\n")) {
        kind = 3; m->errors |= 1;
    } else {
        assert(!strcmp(format, "GuC status: %#x, MIA core expected to be in reset\n"));
        kind = 4; m->errors |= 2;
    }
    event(m, 'L', 0, kind, value, 0);
}
static void reset_trace_test(void)
{
    size_t count = 0;
    const uint64_t ready[] = {0, 10, 100000, UINT64_MAX};
    const uint64_t sram[] = {0, 5000, UINT64_MAX};
    const uint64_t clear[] = {0, 10, 5000, 5001, UINT64_MAX};
    for (unsigned flags = 0; flags < 64; flags++)
    for (size_t r = 0; r < 4; r++) for (size_t s = 0; s < 3; s++)
    for (size_t g = 0; g < 5; g++) {
        struct reset_test_model a = {.held = true, .vf = !!(flags & 1), .wa = !!(flags & 2),
            .boot_valid = !!(flags & 4), .initial_reset = !!(flags & 8),
            .mia_reset = !!(flags & 16), .bootstrap_status = flags & 32 ? -95 : 0,
            .idle = 0x123456, .ready_us = ready[r], .sram_us = sram[s], .clear_us = clear[g]};
        struct reset_test_model b = a; a.mmio.owner = &a; b.mmio.owner = &b;
        int actual = reset_linux(&a), original = reset_donor(&b);
        assert(actual == original && a.events == b.events && a.ns == b.ns);
        assert(!memcmp(a.trace, b.trace, a.events * sizeof(a.trace[0])));
        if (a.vf) {
            assert(actual == a.bootstrap_status && a.events == 2 && !a.reset_written);
        } else {
            assert(a.reset_written);
            assert(actual == (clear[g] > 5000 ? -110 : a.mia_reset ? 0 : -5));
            unsigned expected = a.wa && !a.initial_reset && a.boot_valid ?
                (ready[r] > 100000 ? 1u : 0u) | (sram[s] > 5000 ? 2u : 0u) : 0;
            assert(a.warnings == expected);
            assert(a.idle_written == (a.wa && !a.initial_reset && a.boot_valid));
            assert(a.errors == (clear[g] > 5000 ? 1u : a.mia_reset ? 0u : 2u));
        }
        count++;
    }
    /* Independent final-reread oracle: stuck until the last reread at the real
     * 5000us deadline; succeeds without changing timeout or omitting effects. */
    struct reset_test_model m = {.held = true, .mia_reset = true, .clear_us = UINT64_MAX};
    m.mmio.owner = &m; assert(reset_linux(&m) == -110);
    u32 reads = m.gdrst_reads;
    m = (struct reset_test_model){.held = true, .mia_reset = true,
        .clear_us = UINT64_MAX, .gdrst_clear_read = reads};
    m.mmio.owner = &m; assert(reset_linux(&m) == 0 && m.ns == 5000000 && m.gdrst_reads == reads);
    printf("GuC reset original/Linux core: %zu complete traces + final-reread deadline oracle\n", count);
}

/* Native actual-State tests below use the real C activation entry and RAM-only
 * mandatory owner callbacks. They do not qualify a physical device/provider. */
struct native_model { bool timeout, missing_mia; size_t writes, reads; int64_t ns; u32 ack; };
static int context(void *p) { assert(p); return 0; }
static int prepare(void *p, u32 platform, u32 revision, bool discrete)
{ (void)p; (void)platform; (void)revision; (void)discrete; return 0; }
static u32 native_read(void *p, u32 reg)
{
    struct native_model *m = p; m->reads++;
    if (reg == 0x130044 || reg == 0xdfc) return m->ack;
    if (reg == 0xd8c) return (20u << 22) | (1u << 14);
    if (reg == 0x380d8c) return (13u << 22) | (1u << 14);
    if (reg == GDRST.addr) return m->timeout ? GRDOM_GUC : 0;
    assert(reg == GUC_STATUS.addr); return m->missing_mia ? 0 : GS_MIA_IN_RESET;
}
static void native_write(void *p, u32 reg, u32 value)
{
    struct native_model *m = p;
    if (reg == 0xa188) { m->ack = value & 1; return; }
    assert(reg == GDRST.addr && value == GRDOM_GUC); m->writes++;
}
static int64_t now(void *p) { return ((struct native_model *)p)->ns; }
static void delay(void *p, u32 min, u32 max, bool atomic)
{ assert(!atomic && max == min * 2); ((struct native_model *)p)->ns += (int64_t)min * 1000; }
static void invariant(void *p, bool condition) { (void)p; assert(condition); }
static void report(void *p, u32 mask, bool wake, int status, u32 value)
{ (void)p; (void)wake; (void)value; assert(mask == 1 && status == 0); }
static const struct stela_intel_activation_io io = {context, prepare, native_read, native_write,
    now, delay, invariant, report};
static void native_test(void)
{
    size_t cases = 0;
    for (unsigned mode = 0; mode < 4; mode++) {
        struct native_model m = {.timeout = mode == 1, .missing_mia = mode == 2};
        void *state = calloc(1, stela_intel_activation_size()); assert(state);
        assert(!stela_intel_activation_init(state, stela_intel_activation_size(), &io, &m,
            0x8086, mode == 3 ? 0xe202 : 0x9a49, 0x030000, 0, UINT64_C(16) << 20, false, true));
        struct stela_intel_guc_reset_result result, before;
        memset(&result, 0xa5, sizeof(result)); before = result;
        assert(stela_intel_activation_guc_reset(state, &result) == -22);
        assert(!m.writes && !memcmp(&before, &result, sizeof(result)));
        assert(!stela_intel_activation_wake(state));
        int ret = stela_intel_activation_guc_reset(state, &result);
        if (mode == 3) {
            assert(ret == -95 && !m.writes && !memcmp(&before, &result, sizeof(result)));
            assert(!stela_intel_activation_sleep(state));
        } else {
            assert(ret == (mode == 1 ? -110 : mode == 2 ? -5 : 0));
            assert(m.writes == 1 && result.writes == 1 && !result.warnings);
            assert(result.gdrst == (mode == 1 ? GRDOM_GUC : 0));
            if (mode) {
                struct stela_intel_activation_facts facts;
                assert(stela_intel_activation_facts(state, &facts) == -5);
                assert(stela_intel_activation_wake(state) == -5);
                assert(stela_intel_activation_sleep(state) == -5);
                assert(stela_intel_activation_guc_reset(state, &result) == -5);
            } else {
                assert(result.guc_status & GS_MIA_IN_RESET);
                assert(stela_intel_activation_guc_reset(state, &result) == -114);
                assert(!stela_intel_activation_sleep(state));
            }
            assert(m.writes == 1);
        }
        free(state); cases++;
    }
    /* Private adapter preflight uses an actual initialized State for the held
     * assertion; mutated scalar snapshots only exercise negative admission.
     * Sentinel output and effect counters must survive each error unchanged. */
    struct native_model m = {0};
    void *state = calloc(1, stela_intel_activation_size()); assert(state);
    assert(!stela_intel_activation_init(state, stela_intel_activation_size(), &io, &m,
        0x8086, 0x9a49, 0x030000, 0, UINT64_C(16) << 20, false, true));
    assert(!stela_intel_activation_wake(state));
    struct stela_intel_activation_facts actual;
    assert(!stela_intel_activation_facts(state, &actual));
    size_t refusals = 0;
    for (unsigned field = 0; field < 10; field++) {
        struct stela_intel_activation_facts facts = actual;
        switch (field) {
        case 0: facts.gt_type = 2; break;
        case 1: facts.tile_count = 2; break;
        case 2: facts.max_gt_per_tile = 2; break;
        case 3: facts.graphics_verx100 = 1199; break;
        case 4: facts.graphics_verx100 = 1211; break;
        case 5: facts.media_verx100 = 1211; break;
        case 6: facts.initialized = 0; break;
        case 7: facts.awake = 0; break;
        case 8: m.ns = -1; break;
        case 9: m.ns = INT64_MAX - INT64_C(99999999); break;
        default: abort();
        }
        struct stela_intel_guc_reset_result result, before;
        memset(&result, 0xa5, sizeof(result)); before = result;
        size_t reads = m.reads, writes = m.writes;
        int ret = stela_intel_guc_reset(&io, &m, state, &facts, &result);
        assert(ret == (field >= 8 ? -22 : -95));
        assert(reads == m.reads && writes == m.writes && !memcmp(&before, &result, sizeof(result)));
        m.ns = 0; refusals++;
    }
    /* Missing mandatory services cannot reach effects or poison the actual
     * State because of stale nonzero caller output. */
    struct stela_intel_activation_io missing = io; missing.now_ns = NULL;
    struct stela_intel_guc_reset_result result, before;
    memset(&result, 0xa5, sizeof(result)); before = result;
    size_t reads = m.reads, writes = m.writes;
    assert(stela_intel_guc_reset(&missing, &m, state, &actual, &result) == -22);
    assert(reads == m.reads && writes == m.writes && !memcmp(&before, &result, sizeof(result)));
    m.ns = INT64_MAX - INT64_C(99999999);
    assert(stela_intel_activation_guc_reset(state, &result) == -22);
    m.ns = 0;
    assert(!stela_intel_activation_guc_reset(state, &result));
    assert(!stela_intel_activation_sleep(state));
    free(state);
    printf("GuC reset native preflight: %zu zero-I/O refusals + missing service/stale-output safety\n", refusals + 1);
    printf("GuC reset actual C State: %zu success/failure/refusal cases; no hardware claim\n", cases);
}
int main(void) { reset_trace_test(); native_test(); return 0; }
