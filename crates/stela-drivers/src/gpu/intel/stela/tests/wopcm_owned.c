/* SPDX-License-Identifier: MIT */
/* Explicit pthread/RAM model of actual owned C entry; no native PCI/provider. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "../activation.c"
#include "../firmware.h"
#include "abi/uc_fw_abi.h"
#include "xe_guc.h"
struct model {
    pthread_mutex_t lock;
    u32 ack, offset, size;
    unsigned reads, writes, wopcm_reads, wopcm_writes, fail_at;
};
static int check(void *context)
{
    struct model *m = context;
    int status = pthread_mutex_trylock(&m->lock);
    if (status == EBUSY) return 0;
    if (!status) assert(!pthread_mutex_unlock(&m->lock));
    return -16;
}
static int prepare_model(void *c, u32 p, u32 r, bool d)
{
    (void)p; (void)r; (void)d; return check(c);
}
static u32 read_model(void *context, u32 reg)
{
    struct model *m = context; ++m->reads;
    assert(!check(m));
    if (reg == 0xd8c) return (20u << 22) | (1u << 14);
    if (reg == 0x380d8c) return (13u << 22) | (1u << 14);
    if (reg == 0xdfc || reg == 0x130044) return m->ack;
    assert(reg == 0xc050 || reg == 0xc340); ++m->wopcm_reads;
    return reg == 0xc050 ? m->size : m->offset;
}
static void write_model(void *context, u32 reg, u32 value)
{
    struct model *m = context; ++m->writes; assert(!check(m));
    if (reg == 0xa188) { assert(value == 0x10001 || value == 0x10000); m->ack = value & 1; return; }
    assert(reg == 0xc050 || reg == 0xc340); ++m->wopcm_writes;
    u32 *target = reg == 0xc050 ? &m->size : &m->offset;
    if (!(*target & 1)) *target = value | (m->fail_at == m->wopcm_writes ? 0u : 1u);
}
static int64_t now(void *context) { assert(!check(context)); return 0; }
static void delay(void *context, u32 a, u32 b, bool atomic)
{
    (void)a; (void)b; (void)atomic; assert(!check(context));
    assert(0 && "immediate simulated ACK must not enter poll delay");
}
static void invariant_model(void *context, bool condition) { assert(!check(context) && condition); }
static void report_model(void *context, u32 domains, bool wake, int status, u32 value)
{
    (void)wake; (void)value; assert(!check(context) && domains == 1 && !status);
}
static const struct stela_intel_activation_io io = {check, prepare_model, read_model, write_model, now, delay, invariant_model, report_model};
static void initialize_id(struct model *m, struct stela_intel_activation *s, u32 device)
{
    assert(!pthread_mutex_init(&m->lock, NULL)); assert(!pthread_mutex_lock(&m->lock));
    assert(!stela_intel_activation_init(s, sizeof(*s), &io, m, 0x8086,
        device, 0x030000, 0, 16*1024*1024, false, true));
}
static void finish(struct model *m)
{
    assert(!pthread_mutex_unlock(&m->lock)); assert(!pthread_mutex_destroy(&m->lock));
}
int main(void)
{
    struct uc_css_header css = {.header_size_dw = 32+64+64+1, .size_dw = 32+64+64+1+4,
        .rsa_info = {.key_size_dw = 64, .modulus_size_dw = 64, .exponent_size_dw = 1},
        .guc_info = {.sw_version = MAKE_GUC_VER(70,54,0)}};
    uint8_t bytes[400] = {0}; memcpy(bytes, &css, sizeof(css));
    unsigned cases = 0;
    for (unsigned mode = 0; mode < 8; ++mode) {
        struct model m = {0}; struct stela_intel_activation s; struct stela_intel_wopcm_result out;
        initialize_id(&m, &s, mode == 0 ? 0x9a49 : 0xe202);
        unsigned reads = m.reads, writes = m.writes;
        assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -22);
        assert(m.reads == reads && m.writes == writes); /* no actual GT ref */
        assert(!stela_intel_activation_wake(&s));
        if (mode == 0) {
            assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -95);
            assert(!out.writes && !m.wopcm_reads && !m.wopcm_writes);
            assert(!stela_intel_activation_sleep(&s));
        } else if (mode == 1 || mode == 2) {
            m.fail_at = mode;
            assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -22 && out.writes == mode);
            assert(s.poisoned && s.wopcm_uncertain && s.facts.awake && s.domains[XE_FW_DOMAIN_ID_GT].ref);
            reads = m.reads; writes = m.writes;
            struct stela_intel_activation_facts facts;
            assert(stela_intel_activation_facts(&s, &facts) == -5);
            assert(stela_intel_activation_wake(&s) == -5);
            assert(stela_intel_activation_sleep(&s) == -5);
            assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -5);
            assert(m.reads == reads && m.writes == writes && m.ack == 1);
            /* End only this RAM test mutex. No production reset/release exists. */
        } else if (mode == 3) {
            m.offset = 0x4001; m.size = 0x100001;
            assert(!stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out));
            assert(!out.writes && !m.wopcm_writes && out.guc_base == 0x4000 && out.guc_bytes == 0x100000);
            assert(m.wopcm_reads == 2 && out.total_bytes == 0x800000);
            assert(!stela_intel_activation_sleep(&s));
        } else if (mode == 4) {
            assert(stela_intel_activation_wopcm(&s, bytes, 127, &out) == -61);
            assert(!out.writes && !m.wopcm_reads);
            assert(!stela_intel_activation_sleep(&s));
        } else if (mode == 5) {
            assert(!pthread_mutex_unlock(&m.lock));
            reads = m.reads; writes = m.writes;
            assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -16);
            assert(m.reads == reads && m.writes == writes);
            assert(!pthread_mutex_lock(&m.lock));
            assert(!stela_intel_activation_sleep(&s));
        } else if (mode == 6) {
            unsigned ref = s.domains[XE_FW_DOMAIN_ID_GT].ref;
            s.domains[XE_FW_DOMAIN_ID_GT].ref = 0;
            assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -22);
            assert(!m.wopcm_reads && !out.writes); /* awake bit alone cannot grant access */
            s.domains[XE_FW_DOMAIN_ID_GT].ref = ref; assert(!stela_intel_activation_sleep(&s));
        } else {
            assert(!stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out));
            assert(out.writes == 2 && out.raw_offset == 0x4001 && out.raw_size == 0x7f3001);
            assert(out.guc_base == 0x4000 && out.guc_bytes == 0x7f3000);
            reads = m.reads; writes = m.writes;
            assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -114);
            assert(m.reads == reads && m.writes == writes);
            assert(!stela_intel_activation_sleep(&s));
        }
        finish(&m); ++cases;
    }
    const u32 no_huc_ids[] = {0x56a0, 0x46d0};
    unsigned catalog_admitted = 0, selected_refused = 0;
    for (unsigned i = 0; i < sizeof(no_huc_ids)/sizeof(no_huc_ids[0]); ++i) {
        struct model m = {0}; struct stela_intel_activation s; struct stela_intel_wopcm_result out;
        initialize_id(&m, &s, no_huc_ids[i]); assert(!stela_intel_activation_wake(&s));
        assert(!stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out));
        assert(out.writes == 2 && out.guc_base == 0x4000);
        assert(out.total_bytes == (i == 0 ? 0x400000 : 0x200000));
        assert(out.guc_bytes == (i == 0 ? 0x3f3000 : 0x1f3000));
        assert(!stela_intel_activation_sleep(&s)); finish(&m); ++catalog_admitted;
    }
    /* Every actual retained PCI row whose original main-GT default SELECTS
     * HuC must retain that prerequisite, regardless of GuC image validity. */
    for (unsigned i = 0; pciidlist[i].driver_data; ++i) {
        const struct stela_intel_pci_match *row = &pciidlist[i];
        const struct xe_device_desc *desc = row->driver_data;
        if (!desc->pre_gmdid_graphics_ip) continue;
        struct stela_intel_huc_default huc;
        assert(!stela_intel_huc_select_default((u32)desc->platform,
            desc->pre_gmdid_graphics_ip->verx100, false, &huc));
        if (huc.disposition != STELA_INTEL_HUC_SELECTED) continue;
        struct model m = {0}; struct stela_intel_activation s; struct stela_intel_wopcm_result out;
        initialize_id(&m, &s, row->device); assert(!stela_intel_activation_wake(&s));
        assert(stela_intel_activation_wopcm(&s, bytes, sizeof(bytes), &out) == -95);
        assert(!out.writes && !m.wopcm_reads && !m.wopcm_writes);
        assert(!stela_intel_activation_sleep(&s)); finish(&m); ++selected_refused;
    }
    printf("Intel owned WOPCM: %u actual-state/role/context/length/ref/write-failure/poison RAM cases; %u DG2/ADL-N admitted, %u selected-HuC PCI rows refused; no hardware/authentication\n", cases, catalog_admitted, selected_refused);
    return 0;
}
