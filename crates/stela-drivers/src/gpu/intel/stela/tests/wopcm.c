/* SPDX-License-Identifier: MIT */
/* The unchanged xe_wopcm.c in Stela's environment against the frozen donor
 * harness; modelled registers and firmware, never physical readback/upload. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../wopcm.c"
#include "wopcm_donor.h"
#include "xe_huc_role.h"
void stela_wopcm_record(struct stela_wopcm_model *m, uint32_t kind, uint32_t a, uint32_t b, uint32_t c)
{
    assert(m->used < 64); m->records[m->used++] = (struct stela_wopcm_record){kind, a, b, c};
}
u32 stela_wopcm_read(struct stela_wopcm_model *m, struct xe_reg reg)
{
    assert(reg.addr == GUC_WOPCM_SIZE.addr || reg.addr == DMA_GUC_WOPCM_OFFSET.addr);
    uint32_t value = reg.addr == GUC_WOPCM_SIZE.addr ? m->reg_size : m->reg_offset;
    stela_wopcm_record(m, 1, reg.addr, value, 0); return value;
}
void stela_wopcm_write(struct stela_wopcm_model *m, struct xe_reg reg, u32 value)
{
    assert(reg.addr == GUC_WOPCM_SIZE.addr || reg.addr == DMA_GUC_WOPCM_OFFSET.addr);
    stela_wopcm_record(m, 2, reg.addr, value, 0); ++m->writes;
    uint32_t *target = reg.addr == GUC_WOPCM_SIZE.addr ? &m->reg_size : &m->reg_offset;
    /* Model real write-once state and deliberately absent ACK on selected write.
     * Even failure retains written size/base bytes: it is not rollback. */
    if (!(*target & 1)) *target = value | (m->fail_write == m->writes ? 0u : 1u);
}
void stela_wopcm_assert(struct stela_wopcm_model *m)
{
    int result = pthread_mutex_trylock(m->lock);
    assert(result == EBUSY); stela_wopcm_record(m, 3, 0, 0, 0);
}
bool stela_wopcm_huc(struct stela_wopcm_model *m)
{
    stela_wopcm_record(m, 4, m->huc_available, 0, 0); return m->huc_available;
}
static struct stela_wopcm_model *asserted;
void stela_intel_activation_assert_gt(struct stela_intel_activation *activation)
{
    assert(!activation); stela_wopcm_assert(asserted);
}
static u32 read_io(void *m, u32 offset) { return stela_wopcm_read(m, XE_REG(offset)); }
static void write_io(void *m, u32 offset, u32 value) { stela_wopcm_write(m, XE_REG(offset), value); }
static void invariant_io(void *m, bool condition) { (void)m; assert(condition); }
static const struct stela_intel_activation_io io = {
    .read32 = read_io, .write32 = write_io, .invariant = invariant_io,
};
/* Linux's upload size is the CSS header plus the ucode, or zero when unavailable. */
static struct xe_uc_fw firmware(enum xe_uc_fw_type type, u32 upload, bool available)
{
    if (!available || !upload) return (struct xe_uc_fw){.type = type, .__status = XE_UC_FIRMWARE_MISSING};
    assert(upload >= sizeof(struct uc_css_header));
    return (struct xe_uc_fw){.type = type, .__status = XE_UC_FIRMWARE_AVAILABLE,
        .ucode_size = upload - (u32)sizeof(struct uc_css_header)};
}
static int stela(struct stela_wopcm_model *m, struct xe_wopcm *out, uint32_t *diagnostics)
{
    struct stela_intel_wopcm_result result = {0};
    struct native_wopcm native = {
        .xe.info = {.platform = m->platform, .is_dgfx = m->discrete},
        .gt = {
            .xe = &native.xe, .mmio = {&io, m},
            .uc.guc.fw = firmware(XE_UC_FW_TYPE_GUC, m->guc_fw_size, true),
            .uc.huc.fw = firmware(XE_UC_FW_TYPE_HUC, m->huc_fw_size, m->huc_available),
        },
        .result = &result,
    };
    asserted = m; active = &native;
    int status = xe_wopcm_init(&native.gt.uc.wopcm);
    active = NULL; asserted = NULL;
    assert(result.writes == m->writes);
    *out = native.gt.uc.wopcm; *diagnostics = result.diagnostics;
    return status;
}
/* Register traces and forcewake asserts match in order; the donor's messages
 * and warnings match Stela's diagnostics bits. HuC availability is inline. */
static int pair(struct stela_wopcm_model initial, struct xe_wopcm *result)
{
    struct stela_wopcm_model a = initial, b = initial;
    struct xe_wopcm wa = {0}, wb = {0};
    uint32_t diagnostics, expected = 0;
    int ar = stela(&a, &wa, &diagnostics);
    int br = stela_wopcm_donor(&b, &wb);
    assert(ar == br && !memcmp(&wa, &wb, sizeof(wa)));
    assert(a.writes == b.writes && a.reg_size == b.reg_size && a.reg_offset == b.reg_offset);
    unsigned used = 0;
    for (unsigned i = 0; i < b.used; ++i) {
        uint32_t kind = b.records[i].kind;
        if (kind >= 200) expected |= UINT32_C(1) << (16 + kind - 200);
        else if (kind >= 100) expected |= UINT32_C(1) << (kind - 100);
        else if (kind != 4) {
            assert(used < a.used && !memcmp(&a.records[used], &b.records[i], sizeof(b.records[i])));
            ++used;
        }
    }
    assert(used == a.used && diagnostics == expected);
    *result = wa; return ar;
}
int main(void)
{
    pthread_mutex_t mutex; assert(pthread_mutex_init(&mutex, NULL) == 0);
    assert(pthread_mutex_lock(&mutex) == 0);
    unsigned traces = 0, roles = 0;
    const u32 sizes[] = {0, 128, 129, 4095, 4096, 16383, 16384, 16385, 65536, 2*1024*1024, 8*1024*1024};
    for (unsigned platform = 1; platform <= XE_NOVALAKE_P; ++platform)
        for (unsigned dgfx = 0; dgfx < 2; ++dgfx)
            for (unsigned huc = 0; huc < 2; ++huc)
                for (unsigned lock = 0; lock < 4; ++lock)
                    for (unsigned fail = 0; fail < 3; ++fail)
                        for (unsigned i = 0; i < sizeof(sizes)/sizeof(sizes[0]); ++i) {
                            struct stela_wopcm_model input = {.platform = (enum xe_platform)platform,
                                .discrete = dgfx != 0, .huc_available = huc != 0,
                                .guc_fw_size = sizes[i], .huc_fw_size = huc ? sizes[1 + (i+4)%10] : 0,
                                .reg_offset = 0x10000 | (lock & 1),
                                .reg_size = 0x100000 | (lock >> 1), .fail_write = fail, .lock = &mutex};
                            struct xe_wopcm result; (void)pair(input, &result); ++traces;
                        }
    /* Independent expected boundaries/fields supplement source equivalence. */
    struct stela_wopcm_model input = {.platform = XE_METEORLAKE, .guc_fw_size = 128, .lock = &mutex};
    struct xe_wopcm result;
    assert(pair(input, &result) == 0);
    assert(result.size == 0x400000 && result.guc.base == 0x4000 && result.guc.size == 0x3f3000);
    assert(!(result.guc.base & 0x3fff) && !(result.guc.size & 0xfff));
    input.platform = XE_BATTLEMAGE; assert(pair(input, &result) == 0 && result.size == 0x800000);
    input.platform = XE_TIGERLAKE; assert(pair(input, &result) == 0 && result.size == 0x200000);
    input.discrete = true; assert(pair(input, &result) == 0 && result.size == 0x400000);
    input.reg_offset = 0x4001; input.reg_size = 0x10001;
    input.guc_fw_size = 0x10000 - 0x6000;
    assert(pair(input, &result) == 0 && result.guc.size == 0x10000);
    ++input.guc_fw_size; assert(pair(input, &result) == -E2BIG);
    input.guc_fw_size = 128; input.huc_available = true; input.huc_fw_size = 128;
    assert(pair(input, &result) == -E2BIG); /* exact16KiB HuC reserve no longer fits */
    input.huc_available = false; input.huc_fw_size = 0; input.reg_offset = 0x800001; input.reg_size = 0x1001;
    assert(pair(input, &result) == -E2BIG);
    input.platform = XE_NOVALAKE_P;
    input.reg_size = 0x10001;
    assert(pair(input, &result) == 0 && result.size == 0x1000000); /* source retained, not native admission */
    const unsigned versions[] = {0, 700, 1200, 1255, 1256, 1270, 2001, 3000, 3500, UINT32_MAX};
    for (unsigned media = 0; media < 2; ++media)
        for (unsigned i = 0; i < sizeof(versions)/sizeof(versions[0]); ++i) {
            assert(xe_huc_role_unsupported(media != 0, versions[i]) == stela_wopcm_donor_role(media != 0, versions[i]));
            ++roles;
        }
    assert(pthread_mutex_unlock(&mutex) == 0); assert(pthread_mutex_destroy(&mutex) == 0);
    printf("Intel WOPCM: %u unchanged-source/donor traces, %u original role cases, independent reserve/layout/generation bounds; no hardware readback/upload\n", traces, roles);
    return 0;
}
