/* SPDX-License-Identifier: MIT */
/* Original-object trace qualification, never physical register/firmware proof. */
#include "wopcm_donor.h"
#include "../../xe/xe_huc_role.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <vdso/align.h>
#define SZ_1K 0x00000400
#define SZ_4K 0x00001000
#define SZ_8K 0x00002000
#define SZ_16K 0x00004000
#define SZ_32K 0x00008000
#define SZ_2M 0x00200000
#define SZ_8M 0x00800000
#define SZ_16M 0x01000000
#define min(x, y) __builtin_elementwise_min((x), (y))
#define unlikely(value) __builtin_expect(!!(value), 0)
static void warn_core(void *, unsigned, bool);
#define XE_WOPCM_WARN(core, id, condition) warn_core((core)->context, (id), !!(condition))
#include "../../xe/xe_wopcm_core.h"
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
#define XE_MMIO_VERIFY_NAME checked_verify
#define XE_MMIO_VERIFY_CONTEXT struct stela_wopcm_model
#define XE_MMIO_VERIFY_WRITE stela_wopcm_write
#define XE_MMIO_VERIFY_READ stela_wopcm_read
#include "../../xe/xe_mmio_verify.h"
static u32 read_core(void *m, struct xe_reg reg) { return stela_wopcm_read(m, reg); }
static int verify_core(void *m, struct xe_reg reg, u32 val, u32 mask, u32 eval)
{
    return checked_verify(m, reg, val, mask, eval);
}
static bool huc_core(void *m) { return stela_wopcm_huc(m); }
static void assert_core(void *m) { stela_wopcm_assert(m); }
static void warn_core(void *m, unsigned id, bool condition)
{
    assert(id < 9); if (condition) stela_wopcm_record(m, 200 + id, 0, 0, 0);
}
static void report_core(void *m, enum xe_wopcm_event event, u32 a, u32 b, u32 c)
{
    if (event == XE_WOPCM_INVALID_LAYOUT) { a /= SZ_1K; b /= SZ_1K; c /= SZ_1K; }
    if (event == XE_WOPCM_GUC_SPACE || event == XE_WOPCM_HUC_SPACE ||
        event == XE_WOPCM_LOCKED || event == XE_WOPCM_CALCULATED) { a /= SZ_1K; b /= SZ_1K; }
    if (event == XE_WOPCM_TOTAL) a /= SZ_1K;
    stela_wopcm_record(m, 100 + (unsigned)event, a, b, c);
}
static const struct xe_wopcm_core_ops ops = {read_core, verify_core, huc_core, assert_core, report_core};
static int pair(struct stela_wopcm_model initial, struct xe_wopcm *result)
{
    struct stela_wopcm_model a = initial, b = initial;
    struct xe_wopcm wa = {0}, wb = {0};
    const struct xe_wopcm_core core = {&a, &ops};
    int ar = xe_wopcm_core_init(&wa, a.platform, a.discrete, a.guc_fw_size, a.huc_fw_size, &core);
    int br = stela_wopcm_donor(&b, &wb);
    assert(ar == br && !memcmp(&wa, &wb, sizeof(wa)));
    assert(a.writes == b.writes && a.reg_size == b.reg_size && a.reg_offset == b.reg_offset);
    assert(a.used == b.used && !memcmp(a.records, b.records, a.used * sizeof(a.records[0])));
    *result = wa; return ar;
}
int main(void)
{
    pthread_mutex_t mutex; assert(pthread_mutex_init(&mutex, NULL) == 0);
    assert(pthread_mutex_lock(&mutex) == 0);
    unsigned traces = 0, roles = 0;
    const u32 sizes[] = {0, 1, 128, 4095, 4096, 16383, 16384, 16385, 65536, 2*1024*1024, 8*1024*1024};
    for (unsigned platform = 1; platform <= XE_NOVALAKE_P; ++platform)
        for (unsigned dgfx = 0; dgfx < 2; ++dgfx)
            for (unsigned huc = 0; huc < 2; ++huc)
                for (unsigned lock = 0; lock < 4; ++lock)
                    for (unsigned fail = 0; fail < 3; ++fail)
                        for (unsigned i = 0; i < sizeof(sizes)/sizeof(sizes[0]); ++i) {
                            struct stela_wopcm_model input = {.platform = (enum xe_platform)platform,
                                .discrete = dgfx != 0, .huc_available = huc != 0,
                                .guc_fw_size = sizes[i], .huc_fw_size = huc ? sizes[(i+4)%11] : 0,
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
    input.guc_fw_size = 128; input.huc_fw_size = 1;
    assert(pair(input, &result) == -E2BIG); /* exact16KiB HuC reserve no longer fits */
    input.huc_fw_size = 0; input.reg_offset = 0x800001; input.reg_size = 0x1001;
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
    printf("Intel WOPCM: %u frozen-object/core traces, %u original role cases, independent reserve/layout/generation bounds; no hardware readback/upload\n", traces, roles);
    return 0;
}
