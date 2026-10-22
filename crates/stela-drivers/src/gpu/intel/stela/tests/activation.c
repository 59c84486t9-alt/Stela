/* SPDX-License-Identifier: MIT */
/* Offline MMIO model; never a production owner or physical activation. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../activation.c"

struct model {
    pthread_mutex_t lock;
    uint32_t graphics, media, ack, last_control;
    unsigned prepares, reads, writes, reports;
    bool wake_timeout, sleep_timeout, all_ones;
    int prepare_error;
};
static int check_context(void *data)
{
    struct model *m = data;
    int status = pthread_mutex_trylock(&m->lock);
    if (status == EBUSY) return 0;
    if (!status) assert(pthread_mutex_unlock(&m->lock) == 0);
    return -16;
}
static int prepare(void *data, uint32_t platform, uint32_t revision, bool discrete)
{
    struct model *m = data;
    (void)platform; (void)revision; (void)discrete;
    /* This records simulated preparation only. It never certifies native PM. */
    ++m->prepares;
    return m->prepare_error;
}
static uint32_t read_model(void *data, uint32_t offset)
{
    struct model *m = data; ++m->reads;
    if (offset == GMD_ID.addr) return m->graphics;
    if (offset == GMD_ID.addr + MEDIA_GT_GSI_OFFSET) return m->media;
    if (offset == XEHP_MTCFG_ADDR.addr) return 0;
    assert(offset == FORCEWAKE_ACK_GT.addr || offset == FORCEWAKE_ACK_GT_MTL.addr);
    return m->all_ones ? UINT32_MAX : m->ack;
}
static void write_model(void *data, uint32_t offset, uint32_t value)
{
    struct model *m = data; ++m->writes;
    assert(offset == FORCEWAKE_GT.addr);
    m->last_control = value;
    assert(value == (FORCEWAKE_MT_MASK(0) | FORCEWAKE_MT(0)) || value == FORCEWAKE_MT_MASK(0));
    if (value & 1) { if (!m->wake_timeout) m->ack = 1; }
    else if (!m->sleep_timeout) m->ack = 0;
}
static int64_t now(void *data)
{
    (void)data; struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec * INT64_C(1000000000) + t.tv_nsec;
}
static int64_t invalid_clock(void *data) { (void)data; return -1; }
static void delay(void *data, uint32_t minimum, uint32_t maximum, bool atomic)
{
    assert(minimum <= maximum);
    int64_t end = now(data) + (int64_t)minimum * 1000;
    if (atomic) while (now(data) < end) __asm__ volatile("pause");
    else {
        struct timespec t = {minimum / 1000000, (long)(minimum % 1000000) * 1000};
        while (nanosleep(&t, &t) && errno == EINTR) {}
    }
}
static void check(void *data, bool condition) { (void)data; assert(condition); }
static void report(void *data, uint32_t mask, bool wake, int status, uint32_t value)
{
    (void)wake; (void)status; (void)value; assert(mask == XE_FW_GT); ++((struct model *)data)->reports;
}
static const struct stela_intel_activation_io io = {check_context, prepare, read_model, write_model, now, delay, check, report};

int main(void)
{
    static_assert(sizeof(struct xe_reg) == 4);
    struct xe_reg r = {.addr = 1}; assert(r.raw == 1);
    r = (struct xe_reg){.masked = 1}; assert(r.raw == (1u << 22));
    r = (struct xe_reg){.mcr = 1}; assert(r.raw == (1u << 23));
    r = (struct xe_reg){.vf = 1}; assert(r.raw == (1u << 24));
    struct model m = {.lock = PTHREAD_MUTEX_INITIALIZER,
        .graphics = (1270 / 100u << 22) | (1270 % 100u << 14), .media = 1300 / 100u << 22};
    struct stela_intel_activation state, before; memset(&before, 0xa5, sizeof(before));
    /* The all-zero terminator is not a PCI device or a descriptor. */
    assert(stela_intel_activation_match(0, 0, 0, false, true) == -19);
    assert(stela_intel_activation_match(0x8086, 0xffff, 0x030000, false, true) == -19);
    unsigned matches = 0;
    for (size_t i = 0; i + 1 < ARRAY_SIZE(pciidlist); ++i) {
        const struct pci_device_id *p = &pciidlist[i];
        const struct xe_device_desc *desc = (const void *)p->driver_data;
        assert(pthread_mutex_lock(&m.lock) == 0);
        state = before;
        assert(stela_intel_activation_match(p->vendor, p->device, p->class, false, true) == 0);
        assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
            p->vendor, p->device, p->class, 0, UINT64_C(64) << 20, false, true) == 0);
        assert(state.facts.platform == (uint32_t)desc->platform &&
               state.facts.dma_bits == desc->dma_mask_size && !state.facts.awake);
        assert(stela_intel_activation_wake(&state) == 0 && state.facts.awake == XE_FW_GT);
        unsigned writes = m.writes;
        assert(stela_intel_activation_wake(&state) == 0 && m.writes == writes);
        assert(stela_intel_activation_sleep(&state) == 0 && m.writes == writes);
        assert(stela_intel_activation_sleep(&state) == 0 && !state.facts.awake);
        assert(stela_intel_activation_sleep(&state) == -22);
        assert(pthread_mutex_unlock(&m.lock) == 0); ++matches;
    }
    const struct pci_device_id *p = &pciidlist[0];
    state = before;
    assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
        p->vendor, p->device, p->class, 0, UINT64_C(64) << 20, false, true) == -16);
    assert(!memcmp(&state, &before, sizeof(state)));
    assert(pthread_mutex_lock(&m.lock) == 0);
    for (unsigned bad = 0; bad < 14; ++bad) {
        state = before; struct stela_intel_activation_io missing = io;
        if (bad == 0) missing.check_context = NULL;
        if (bad == 1) missing.prepare = NULL;
        if (bad == 2) missing.read32 = NULL;
        if (bad == 3) missing.write32 = NULL;
        if (bad == 4) missing.now_ns = NULL;
        if (bad == 5) missing.delay_us = NULL;
        if (bad == 6) missing.invariant = NULL;
        if (bad == 7) missing.report = NULL;
        m.prepare_error = bad == 12 ? -5 : 0;
        if (bad == 13) missing.now_ns = invalid_clock;
        int ret = stela_intel_activation_init(&state, sizeof(state), &missing, &m,
            bad == 8 ? 0 : p->vendor, p->device, p->class, 0,
            bad == 9 ? 4096 : UINT64_C(64) << 20, bad == 10, bad != 11);
        assert(ret && !memcmp(&state, &before, sizeof(state)));
    }
    m.prepare_error = 0;
    const struct pci_device_id *post = pciidlist;
    while (post->vendor && ((const struct xe_device_desc *)post->driver_data)->pre_gmdid_graphics_ip) ++post;
    assert(post->vendor);
    /* Unknown graphics IP, including an all-ones read, fails the probe. */
    for (unsigned bad = 0; bad < 2; ++bad) {
        state = before;
        m.graphics = bad == 0 ? UINT32_MAX : 63u << 22;
        m.media = 1300 / 100u << 22;
        assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
            post->vendor, post->device, post->class, 0, UINT64_C(64) << 20, false, true) == -19);
        assert(!memcmp(&state, &before, sizeof(state)));
    }
    /* Unknown media IP probes without media, as Linux does. */
    m.graphics = 1270 / 100u << 22 | 1270 % 100u << 14; m.media = 63u << 22;
    assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
        post->vendor, post->device, post->class, 0, UINT64_C(64) << 20, false, true) == 0);
    assert(state.facts.graphics_verx100 == 1270 && !state.facts.media_verx100);
    /* Hardware GMDID selection is exercised independently of PCI fixtures:
     * every original runtime IP entry, actual field layout and revision bits. */
    unsigned runtime_ips = 0;
    for (size_t i = 0; i < ARRAY_SIZE(graphics_ips); ++i) {
        uint32_t version = graphics_ips[i].verx100;
        m.graphics = version / 100u << 22 | version % 100u << 14 | 17;
        m.media = 1300 / 100u << 22 | 11;
        assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
            post->vendor, post->device, post->class, 0, UINT64_C(64) << 20, false, true) == 0);
        assert(state.facts.graphics_verx100 == version && state.facts.graphics_revision == 17 &&
               state.facts.media_revision == 11 && state.facts.gt_ack == FORCEWAKE_ACK_GT_MTL.addr);
        ++runtime_ips;
    }
    for (size_t i = 0; i < ARRAY_SIZE(media_ips); ++i) {
        uint32_t version = media_ips[i].verx100;
        m.media = version / 100u << 22 | version % 100u << 14 | 9;
        assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
            post->vendor, post->device, post->class, 0, UINT64_C(64) << 20, false, true) == 0);
        assert(state.facts.media_verx100 == version && state.facts.media_revision == 9);
        ++runtime_ips;
    }
    m.graphics = 1270 / 100u << 22 | 1270 % 100u << 14; m.media = 0;
    assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
        post->vendor, post->device, post->class, 0, UINT64_C(64) << 20, false, true) == 0);
    assert(state.facts.media_verx100 == 0);
    for (unsigned bad = 0; bad < 3; ++bad) {
        m.wake_timeout = bad == 0; m.sleep_timeout = bad == 1; m.all_ones = bad == 2; m.ack = 0;
        assert(stela_intel_activation_init(&state, sizeof(state), &io, &m,
            p->vendor, p->device, p->class, 0, UINT64_C(64) << 20, false, true) == 0);
        int64_t start = now(&m);
        int ret = stela_intel_activation_wake(&state);
        if (bad == 1) { assert(ret == 0); ret = stela_intel_activation_sleep(&state); }
        assert(ret == (bad == 2 ? -5 : -110));
        if (bad < 2) assert(now(&m) - start >= INT64_C(50000000));
        assert(state.poisoned && stela_intel_activation_wake(&state) == -5);
    }
    assert(pthread_mutex_unlock(&m.lock) == 0 && pthread_mutex_destroy(&m.lock) == 0);
    printf("Intel activation model: %u original PCI rows, 18 atomic refusals, 2 pure unmatched/terminator refusals, unknown and fused-off media, real-clock ACK timeout/all-ones checks, %u runtime IP entries; no physical hardware activation\n", matches, runtime_ips);
    return 0;
}
