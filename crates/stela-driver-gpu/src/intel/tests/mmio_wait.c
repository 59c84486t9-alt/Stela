/* SPDX-License-Identifier: MIT */
/* Actual native wait helper over a retained register/clock peer. */
#include "../activation.h"
#include "../device.h"
#include "xe_mmio.h"
#include <stela/test.h>
#include <linux/errno.h>
#include <linux/string.h>

struct peer {
    int64_t now;
    unsigned reads, delays, ready_at;
    uint32_t maximum_delay;
    bool atomic;
};
static uint32_t read32(void *context, uint32_t offset)
{
    struct peer *peer = context;
    assert(offset == 0x20);
    ++peer->reads;
    return peer->ready_at && peer->reads >= peer->ready_at ? 1 : 0;
}
static int64_t now_ns(void *context) { return ((struct peer *)context)->now; }
static void delay_us(void *context, uint32_t minimum, uint32_t maximum, bool atomic)
{
    struct peer *peer = context;
    assert(maximum >= minimum && atomic == peer->atomic);
    assert(maximum == (atomic ? minimum : minimum * 2));
    if (minimum > peer->maximum_delay) peer->maximum_delay = minimum;
    peer->now += (int64_t)minimum * 1000;
    ++peer->delays;
}
static void invariant(void *context, bool condition) { (void)context; assert(condition); }
static const struct stela_intel_activation_io io = {
    .read32 = read32, .now_ns = now_ns, .delay_us = delay_us, .invariant = invariant,
};

int main(void)
{
    uint32_t output;
    unsigned cases = 0;
    for (unsigned atomic = 0; atomic < 2; ++atomic) {
        for (unsigned invalid = 0; invalid < 3; ++invalid) {
            struct peer peer = {.now = invalid == 0 ? -1 : invalid == 1 ? INT64_MAX : INT64_MAX - 1999999999,
                                .ready_at = 1, .atomic = atomic != 0};
            output = 0xdeadbeef;
            assert(stela_intel_mmio_wait32(&io, &peer, 0x20, 1, 1, 2000000, &output, peer.atomic) == -EINVAL);
            assert(!peer.reads && !peer.delays && output == 0xdeadbeef);
            ++cases;
        }
        /* At a zero deadline the original polls once and performs its final
         * read without issuing any delay. Completion may arrive on that read. */
        for (unsigned ready = 1; ready <= 3; ++ready) {
            struct peer peer = {.ready_at = ready, .atomic = atomic != 0};
            output = 0xdeadbeef;
            int ret = stela_intel_mmio_wait32(&io, &peer, 0x20, 1, 1, 0, &output, peer.atomic);
            assert(ret == (ready <= 2 ? 0 : -ETIMEDOUT));
            assert(peer.reads == (ready == 1 ? 1u : 2u) && !peer.delays);
            assert(output == (ready <= 2 ? 1u : 0u));
            ++cases;
        }
        /* Original final read can observe completion after the nominal bound. */
        for (unsigned ready = 1; ready < 5; ++ready) {
            struct peer peer = {.ready_at = ready, .atomic = atomic != 0};
            output = 0xdeadbeef;
            int ret = stela_intel_mmio_wait32(&io, &peer, 0x20, 1, 1, 3, &output, peer.atomic);
            assert(ret == (ready <= 3 ? 0 : -ETIMEDOUT));
            assert(output == (ready <= 3 ? 1u : 0u));
            assert(peer.reads == (ready <= 3 ? ready : 3));
            assert(peer.delays == (ready == 1 ? 0u : 1u));
            ++cases;
        }
        /* The maximum uint32 duration must not turn left+1 into zero delay. */
        struct peer peer = {.now = INT64_MAX - (int64_t)UINT32_MAX * 1000,
                            .ready_at = 2, .atomic = atomic != 0};
        assert(!stela_intel_mmio_wait32(&io, &peer, 0x20, 1, 1, UINT32_MAX, &output, peer.atomic));
        assert(peer.reads == 2 && peer.delays == 1 && output == 1);
        ++cases;
        /* Both original backoff caps must be reached on a long wait. */
        peer = (struct peer){.ready_at = 0, .atomic = atomic != 0};
        assert(stela_intel_mmio_wait32(&io, &peer, 0x20, 1, 1, 2000000, &output, peer.atomic) == -ETIMEDOUT);
        assert(peer.maximum_delay == (atomic ? 5000u : 100000u));
        ++cases;
    }
    /* The Xe wrapper must not observe/store an uninitialized rejected read. */
    struct peer peer = {.now = INT64_MAX};
    struct stela_xe device;
    struct xe_gt gt = {0};
    memset(&device, 0, sizeof(device));
    device.io = &io; device.context = &peer;
    stela_xe_init(&device, &gt, XE_GT_TYPE_MAIN);
    output = 0xdeadbeef;
    assert(xe_mmio_wait32(&gt.mmio, XE_REG(0x20), 1, 1, 2000000, &output, false) == -EINVAL);
    assert(!peer.reads && !peer.delays && output == 0xdeadbeef);
    printf("intel_mmio_wait: %u peer scenarios\n", cases + 1);
    return 0;
}
