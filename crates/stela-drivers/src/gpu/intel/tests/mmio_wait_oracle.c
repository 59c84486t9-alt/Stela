/* SPDX-License-Identifier: MIT */
/* Compare complete original poll transcripts with the actual native adapter. */
#include "activation.h"
#include "xe_mmio.h"
#include "regs/xe_reg_defs.h"
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/errno.h>

extern int printf(const char *, ...);
extern int fflush(void *);
#define check(x) do { if (!(x)) { printf("line %u: %s\n", __LINE__, #x); fflush((void *)0); __builtin_trap(); } } while (0)

struct event { u64 a, b; unsigned kind; bool atomic; };
struct model {
    struct event trace[4096];
    unsigned count, reads, ready_at;
    s64 now;
    u32 clock_step;
    bool atomic;
};
static struct model actual, original, *current;
void stela_linux_warn(const char *file, int line, const char *condition, unsigned int flags)
{ (void)file; (void)line; (void)condition; (void)flags; check(false); }
static void record(unsigned kind, u64 a, u64 b, bool atomic)
{
    check(current->count < 4096);
    current->trace[current->count++] = (struct event){.a = a, .b = b, .kind = kind, .atomic = atomic};
}
static u32 read_peer(void *context, u32 offset)
{
    current = context;
    check(offset == 0x20);
    ++current->reads;
    u32 value = current->ready_at && current->reads >= current->ready_at ? 0x80000001u : 0x80000000u;
    record(1, offset, value, false);
    return value;
}
static s64 clock_peer(void *context)
{
    current = context;
    s64 now = current->now;
    record(2, (u64)now, 0, false);
    current->now += current->clock_step;
    return now;
}
static void delay_peer(void *context, u32 minimum, u32 maximum, bool atomic)
{
    current = context;
    check(atomic == current->atomic);
    record(3, minimum, maximum, atomic);
    current->now += (s64)minimum * 1000;
}
static void invariant(void *context, bool valid) { (void)context; check(valid); }
static const struct stela_intel_activation_io io = {
    .read32 = read_peer, .now_ns = clock_peer, .delay_us = delay_peer, .invariant = invariant,
};
u32 original_read32(struct xe_mmio *mmio, struct xe_reg reg)
{ (void)mmio; return read_peer(current, reg.addr); }
ktime_t ktime_get_raw(void) { return clock_peer(current); }
void original_udelay(unsigned long delay)
{ check(delay <= UINT32_MAX); delay_peer(current, (u32)delay, (u32)delay, true); }
void original_usleep_range(unsigned long minimum, unsigned long maximum)
{ check(maximum <= UINT32_MAX); delay_peer(current, (u32)minimum, (u32)maximum, false); }
int original_wait32(struct xe_mmio *, struct xe_reg, u32, u32, u32, u32 *, bool);

int main(void)
{
    const u32 durations[] = {0, 1, 3, 9, 10, 11, 100, 1000, 99999, 100000, 100001, 2000000, UINT32_MAX};
    const unsigned ready[] = {0, 1, 2, 3, 5, 12, 22, 40};
    const u32 steps[] = {0, 333, 1000000};
    unsigned cases = 0;
    for (unsigned atomic = 0; atomic < 2; ++atomic)
        for (unsigned d = 0; d < sizeof(durations) / sizeof(durations[0]); ++d)
            for (unsigned r = 0; r < sizeof(ready) / sizeof(ready[0]); ++r)
                for (unsigned s = 0; s < sizeof(steps) / sizeof(steps[0]); ++s) {
                    if (durations[d] == UINT32_MAX && !ready[r]) continue;
                    memset(&actual, 0, sizeof(actual));
                    actual.ready_at = ready[r]; actual.clock_step = steps[s]; actual.atomic = atomic != 0;
                    original = actual;
                    u32 a = 0xdeadbeef, b = 0xdeadbeef;
                    int actual_result = stela_intel_mmio_wait32(&io, &actual, 0x20, 1, 1, durations[d], &a, actual.atomic);
                    current = &original;
                    int original_result = original_wait32(NULL, XE_REG(0x20), 1, 1, durations[d], &b, original.atomic);
                    check(actual_result == original_result && a == b && actual.count == original.count && actual.reads == original.reads);
                    for (unsigned i = 0; i < actual.count; ++i)
                        check(actual.trace[i].kind == original.trace[i].kind && actual.trace[i].a == original.trace[i].a &&
                              actual.trace[i].b == original.trace[i].b && actual.trace[i].atomic == original.trace[i].atomic);
                    ++cases;
                }
    printf("original/native complete MMIO polling transcripts: %u\n", cases);
    return 0;
}
