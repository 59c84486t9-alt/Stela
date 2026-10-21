/* SPDX-License-Identifier: MIT */
#include "../ct.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { RING_WORDS = 512 };
struct model {
    uint32_t h2g_desc[16], g2h_desc[16];
    uint32_t h2g[RING_WORDS], g2h[RING_WORDS];
    char events[64];
    size_t event_count;
    bool discrete, media, dirty, released, flushed, acquired, consumed;
    unsigned int publications, notifications;
};

static void event(struct model *m, char code)
{
    assert(m->event_count + 1 < sizeof(m->events));
    m->events[m->event_count++] = code;
    m->events[m->event_count] = 0;
}

static uint32_t *region(struct model *m, enum stela_intel_ct_region r,
                         uint32_t word, uint32_t count)
{
    assert(count > 0);
    uint32_t size = (r == STELA_INTEL_CT_H2G_DESC || r == STELA_INTEL_CT_G2H_DESC) ?
                    16 : RING_WORDS;
    assert(word < size && count <= size - word);
    switch (r) {
    case STELA_INTEL_CT_H2G_DESC: return m->h2g_desc + word;
    case STELA_INTEL_CT_H2G_COMMANDS: return m->h2g + word;
    case STELA_INTEL_CT_G2H_DESC: return m->g2h_desc + word;
    case STELA_INTEL_CT_G2H_COMMANDS: return m->g2h + word;
    }
    assert(false);
    return NULL;
}

static void read_words(void *context, enum stela_intel_ct_region r, uint32_t word,
                        uint32_t *out, uint32_t count)
{
    struct model *m = context;
    if (r == STELA_INTEL_CT_G2H_COMMANDS) {
        assert(m->acquired);
        event(m, 'C');
    }
    memcpy(out, region(m, r, word, count), count * sizeof(uint32_t));
}

static void write_words(void *context, enum stela_intel_ct_region r, uint32_t word,
                         const uint32_t *in, uint32_t count)
{
    struct model *m = context;
    if (r == STELA_INTEL_CT_H2G_COMMANDS) {
        m->dirty = true; m->released = false; m->flushed = false;
        event(m, 'W');
    } else if (r == STELA_INTEL_CT_H2G_DESC) {
        assert(word == 1 && count == 1 && m->dirty && m->released && m->flushed);
        ++m->publications;
        m->dirty = false;
        event(m, 'T');
    } else if (r == STELA_INTEL_CT_G2H_DESC) {
        assert(word == 0 && count == 1 && m->consumed);
        m->acquired = false; m->consumed = false;
        event(m, 'H');
    } else {
        assert(false);
    }
    memcpy(region(m, r, word, count), in, count * sizeof(uint32_t));
}

static void zero_words(void *context, enum stela_intel_ct_region r,
                        uint32_t word, uint32_t count)
{
    struct model *m = context;
    assert(r == STELA_INTEL_CT_H2G_COMMANDS);
    m->dirty = true; m->released = false; m->flushed = false;
    memset(region(m, r, word, count), 0, count * sizeof(uint32_t));
    event(m, 'Z');
}

static void order(void *context, enum stela_intel_ct_order kind)
{
    struct model *m = context;
    switch (kind) {
    case STELA_INTEL_CT_ACQUIRE:
        m->acquired = true;
        event(m, 'A');
        break;
    case STELA_INTEL_CT_RELEASE:
        assert(m->dirty);
        m->released = true;
        if (!m->discrete) m->flushed = true;
        event(m, 'R');
        break;
    case STELA_INTEL_CT_CONSUME:
        assert(m->acquired);
        m->consumed = true;
        event(m, 'B');
        break;
    }
}

static void mmio_write(void *context, enum stela_intel_ct_mmio aperture,
                        uint32_t offset, uint32_t value)
{
    struct model *m = context;
    assert(value == 0);
    if (aperture == STELA_INTEL_CT_ROOT_TILE) {
        assert(m->discrete && m->dirty && m->released && offset == 0x1901f8);
        m->flushed = true;
        event(m, 'F');
    } else {
        assert(aperture == STELA_INTEL_CT_GT && !m->dirty);
        assert(offset == (m->media ? 0x190304u : 0x1901f0u));
        assert(m->notifications + 1 == m->publications);
        ++m->notifications;
        event(m, 'N');
    }
}

static const struct stela_intel_ct_io io = {
    read_words, write_words, zero_words, order, mmio_write,
};

static void attach(struct model *m, struct stela_intel_ct *ct, bool discrete, bool media)
{
    memset(m, 0, sizeof(*m));
    m->discrete = discrete; m->media = media;
    assert(stela_intel_ct_attach(ct, &io, m, RING_WORDS, RING_WORDS, discrete, media) == 0);
    assert(m->event_count == 0 && m->publications == 0);
}

static void packet_and_order_matrix(void)
{
    for (unsigned int variant = 0; variant < 4; ++variant) {
        for (uint32_t type = 0; type <= 2; ++type) {
            struct model m;
            struct stela_intel_ct ct;
            attach(&m, &ct, (variant & 1) != 0, (variant & 2) != 0);
            const uint32_t action[] = {0x01234567, 0x89abcdef, 0x10203040};
            assert(stela_intel_ct_send(&ct, action, 3, 0xabcd, type) == 0);
            assert(m.h2g[0] == 0xabcd0003);
            assert(m.h2g[1] == (type << 28 | action[0]));
            assert(m.h2g[2] == action[1] && m.h2g[3] == action[2]);
            assert(m.h2g_desc[1] == 4 && ct.h2g_tail == 4);
            assert(strcmp(m.events, m.discrete ? "WWRFTN" : "WWRTN") == 0);
            assert(m.publications == 1 && m.notifications == 1);
        }
    }
}

static void wrap_publishes_only_nops_and_requires_retry(void)
{
    struct model m;
    struct stela_intel_ct ct;
    attach(&m, &ct, true, false);
    m.h2g_desc[0] = 510; m.h2g_desc[1] = 510; ct.h2g_tail = 510;
    m.h2g[510] = UINT32_MAX; m.h2g[511] = UINT32_MAX;
    const uint32_t action[] = {42, 3, 4};
    assert(stela_intel_ct_send(&ct, action, 3, 9, 0) == -11);
    assert(m.h2g[510] == 0 && m.h2g[511] == 0 && m.h2g[0] == 0);
    assert(ct.h2g_tail == 0 && m.h2g_desc[1] == 0);
    assert(strcmp(m.events, "ZRFTN") == 0);
    m.event_count = 0;
    assert(stela_intel_ct_send(&ct, action, 3, 9, 0) == 0);
    assert(m.h2g[0] == 0x00090003 && m.h2g[1] == 42);
    assert(m.notifications == 2 && m.publications == 2);
}

static void receive_wrap_and_capacity(void)
{
    struct model m;
    struct stela_intel_ct ct;
    attach(&m, &ct, false, true);
    ct.g2h_head = 510; m.g2h_desc[0] = 510; m.g2h_desc[1] = 2;
    m.g2h[510] = 0xfffe0003; m.g2h[511] = 0xe0011234;
    m.g2h[0] = 0x55667788; m.g2h[1] = 0xabcdef01;
    uint32_t out[4] = {0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5};
    assert(stela_intel_ct_receive(&ct, out, 3) == -28);
    assert(ct.g2h_head == 510 && m.g2h_desc[0] == 510);
    for (unsigned int i = 0; i < 4; ++i) assert(out[i] == 0xa5a5a5a5);
    m.event_count = 0;
    assert(stela_intel_ct_receive(&ct, out, 4) == 4);
    const uint32_t expected[] = {0xfffe0003, 0xe0011234, 0x55667788, 0xabcdef01};
    assert(memcmp(out, expected, sizeof(out)) == 0);
    assert(ct.g2h_head == 2 && m.g2h_desc[0] == 2);
    assert(strcmp(m.events, "ACCCBH") == 0);
    m.event_count = 0;
    assert(stela_intel_ct_receive(&ct, out, 4) == 0 && m.event_count == 0);
}

static void failures_do_not_publish(void)
{
    struct model m;
    struct stela_intel_ct ct;
    attach(&m, &ct, false, false);
    struct stela_intel_ct before = ct;
    struct stela_intel_ct_io missing = io;
    missing.order = NULL;
    assert(stela_intel_ct_attach(&ct, &missing, &m, 512, 512, false, false) == -22);
    assert(memcmp(&ct, &before, sizeof(ct)) == 0);
    assert(stela_intel_ct_attach(&ct, &io, &m, 256, 512, false, false) == -22);
    assert(stela_intel_ct_attach(&ct, &io, &m, 513, 512, false, false) == -22);
    uint32_t action = 0;
    assert(stela_intel_ct_send(&ct, &action, 0, 0, 0) == -22);
    assert(stela_intel_ct_send(&ct, &action, 256, 0, 0) == -22);
    assert(stela_intel_ct_send(&ct, &action, 1, 0, 3) == -22);
    action = 0x80000000;
    assert(stela_intel_ct_send(&ct, &action, 1, 0, 0) == -22);
    action = 0;
    m.h2g_desc[0] = 1;
    assert(stela_intel_ct_send(&ct, &action, 1, 0, 0) == -16);
    assert(m.event_count == 0 && ct.h2g_tail == 0);
    m.h2g_desc[0] = 512;
    assert(stela_intel_ct_send(&ct, &action, 1, 0, 0) == -71);
    assert(stela_intel_ct_send(&ct, &action, 1, 0, 0) == -32);
    assert(m.event_count == 0);

    for (unsigned int fault = 0; fault < 5; ++fault) {
        attach(&m, &ct, false, false);
        uint32_t out[4] = {0xa5a5a5a5, 1, 2, 3};
        m.g2h_desc[1] = fault == 4 ? 512 : 2;
        m.g2h[0] = fault == 0 ? 0 : fault == 1 ? 3 : fault == 2 ? 0x1001 : 0x0101;
        assert(stela_intel_ct_receive(&ct, out, 4) == -71);
        assert(ct.g2h_head == 0 && m.g2h_desc[0] == 0 && out[0] == 0xa5a5a5a5);
        assert(stela_intel_ct_receive(&ct, out, 4) == -32);
    }
    attach(&m, &ct, false, false);
    m.h2g_desc[2] = 8;
    assert(stela_intel_ct_send(&ct, &action, 1, 0, 0) == -19);
    assert(stela_intel_ct_send(&ct, &action, 1, 0, 0) == -32);
    assert(m.publications == 0);
}

static uint32_t random_u32(uint32_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

static void independent_ring_sequences(void)
{
    struct model m;
    struct stela_intel_ct ct;
    attach(&m, &ct, true, true);
    uint32_t random = 0x51e1a;
    for (uint32_t i = 0; i < 2000; ++i) {
        uint32_t action[255];
        uint32_t words = 1 + random_u32(&random) % 255;
        for (uint32_t j = 0; j < words; ++j) action[j] = random_u32(&random);
        action[0] &= 0x0fffffff;
        uint32_t old_tail = ct.h2g_tail;
        m.event_count = 0;
        int err = stela_intel_ct_send(&ct, action, words, (uint16_t)i, 2);
        if (err == -11) {
            for (uint32_t j = old_tail; j < RING_WORDS; ++j) assert(m.h2g[j] == 0);
            /* Model firmware consuming published NOPs before the next retry. */
            m.h2g_desc[0] = m.h2g_desc[1];
            m.event_count = 0;
            old_tail = 0;
            err = stela_intel_ct_send(&ct, action, words, (uint16_t)i, 2);
        }
        assert(err == 0);
        assert(m.h2g[old_tail] == (i << 16 | words));
        assert(m.h2g[old_tail + 1] == (0x20000000 | action[0]));
        for (uint32_t j = 1; j < words; ++j) assert(m.h2g[old_tail + 1 + j] == action[j]);
        m.h2g_desc[0] = m.h2g_desc[1];

        uint32_t start = ct.g2h_head;
        uint32_t len = words + 1;
        m.g2h[start] = i << 16 | words;
        for (uint32_t j = 0; j < words; ++j) m.g2h[(start + 1 + j) % RING_WORDS] = action[j];
        m.g2h_desc[1] = (start + len) % RING_WORDS;
        uint32_t out[256];
        m.event_count = 0;
        assert(stela_intel_ct_receive(&ct, out, 256) == (int)len);
        assert(out[0] == (i << 16 | words));
        assert(memcmp(out + 1, action, words * sizeof(uint32_t)) == 0);
        assert(ct.g2h_head == (start + len) % RING_WORDS);
    }
}

int main(void)
{
    packet_and_order_matrix();
    wrap_publishes_only_nops_and_requires_retry();
    receive_wrap_and_capacity();
    failures_do_not_publish();
    independent_ring_sequences();
    puts("Intel GuC CT mapped I/O: 5 suites / 2000 bidirectional ring sequences passed");
    return 0;
}
