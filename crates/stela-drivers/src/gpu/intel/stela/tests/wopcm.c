/* SPDX-License-Identifier: MIT */
/* The unchanged xe_wopcm.c in Stela's environment over modelled registers
 * and firmware, never physical readback/upload. */
#include <stela/test.h>
#include "../wopcm.c"

/* GuC WOPCM size and offset registers: write-once, locked by bit 0. */
struct model {
    enum xe_platform platform;
    bool discrete, huc_available;
    uint32_t guc_fw_size, huc_fw_size, reg_offset, reg_size;
    unsigned fail_write, writes;
};
static u32 read_io(void *data, u32 offset)
{
    struct model *m = data;
    assert(offset == GUC_WOPCM_SIZE.addr || offset == DMA_GUC_WOPCM_OFFSET.addr);
    return offset == GUC_WOPCM_SIZE.addr ? m->reg_size : m->reg_offset;
}
static void write_io(void *data, u32 offset, u32 value)
{
    struct model *m = data;
    assert(offset == GUC_WOPCM_SIZE.addr || offset == DMA_GUC_WOPCM_OFFSET.addr);
    ++m->writes;
    uint32_t *target = offset == GUC_WOPCM_SIZE.addr ? &m->reg_size : &m->reg_offset;
    /* A failed write leaves the written value without the lock bit. */
    if (!(*target & 1)) *target = value | (m->fail_write == m->writes ? 0u : 1u);
}
static void invariant_io(void *m, bool condition) { (void)m; assert(condition); }
static const struct stela_intel_activation_io io = {
    .read32 = read_io, .write32 = write_io, .invariant = invariant_io,
};
/* Linux's upload size is the CSS header plus the ucode, or zero when unavailable. */
static void firmware(struct xe_uc_fw *fw, u32 upload, bool available)
{
    if (!available || !upload) {
        fw->__status = XE_UC_FIRMWARE_MISSING;
        fw->ucode_size = 0;
        return;
    }
    assert(upload >= sizeof(struct uc_css_header));
    fw->__status = XE_UC_FIRMWARE_AVAILABLE;
    fw->ucode_size = upload - (u32)sizeof(struct uc_css_header);
}
/* Each run starts from the given register state. */
static int run(struct model initial, struct xe_wopcm *out)
{
    struct model state = initial, *m = &state;
    struct stela_intel_wopcm_result result = {0};
    struct native_wopcm *local = calloc(1, sizeof(*local));
    assert(local);
    const struct stela_linux_owner owner = {.services = &services, .context = &local->dev};
    stela_linux_enter(&owner);
    prepare(local, &io, m, m->platform, m->discrete, 0, &result);
    firmware(&local->gt.uc.guc.fw, m->guc_fw_size, true);
    firmware(&local->gt.uc.huc.fw, m->huc_fw_size, m->huc_available);
    int status = xe_wopcm_init(&local->gt.uc.wopcm);
    stela_linux_exit();
    assert(result.writes == m->writes);
    *out = local->gt.uc.wopcm;
    free(local);
    return status;
}
int main(void)
{
    unsigned traces = 0;
    const u32 sizes[] = {
        0, 128, 129, 4095, 4096, 16383, 16384, 16385, 65536, 2 * 1024 * 1024, 8 * 1024 * 1024};
    for (unsigned platform = 1; platform <= XE_NOVALAKE_P; ++platform)
        for (unsigned dgfx = 0; dgfx < 2; ++dgfx)
            for (unsigned huc = 0; huc < 2; ++huc)
                for (unsigned lock = 0; lock < 4; ++lock)
                    for (unsigned fail = 0; fail < 3; ++fail)
                        for (unsigned i = 0; i < sizeof(sizes)/sizeof(sizes[0]); ++i) {
                            struct model input = {.platform = (enum xe_platform)platform,
                                .discrete = dgfx != 0,
                                .huc_available = huc != 0,
                                .guc_fw_size = sizes[i],
                                .huc_fw_size = huc ? sizes[1 + (i + 4) % 10] : 0,
                                .reg_offset = 0x10000 | (lock & 1),
                                .reg_size = 0x100000 | (lock >> 1),
                                .fail_write = fail};
                            struct xe_wopcm result; (void)run(input, &result); ++traces;
                        }
    /* Expected sizes, layouts and limits. */
    struct model input = {.platform = XE_METEORLAKE, .guc_fw_size = 128};
    struct xe_wopcm result;
    assert(run(input, &result) == 0);
    assert(result.size == 0x400000 && result.guc.base == 0x4000 && result.guc.size == 0x3f3000);
    assert(!(result.guc.base & 0x3fff) && !(result.guc.size & 0xfff));
    input.platform = XE_BATTLEMAGE; assert(run(input, &result) == 0 && result.size == 0x800000);
    input.platform = XE_TIGERLAKE; assert(run(input, &result) == 0 && result.size == 0x200000);
    input.discrete = true; assert(run(input, &result) == 0 && result.size == 0x400000);
    input.reg_offset = 0x4001; input.reg_size = 0x10001;
    input.guc_fw_size = 0x10000 - 0x6000;
    assert(run(input, &result) == 0 && result.guc.size == 0x10000);
    ++input.guc_fw_size; assert(run(input, &result) == -E2BIG);
    input.guc_fw_size = 128; input.huc_available = true; input.huc_fw_size = 128;
    assert(run(input, &result) == -E2BIG); /* exact16KiB HuC reserve no longer fits */
    input.huc_available = false;
    input.huc_fw_size = 0;
    input.reg_offset = 0x800001;
    input.reg_size = 0x1001;
    assert(run(input, &result) == -E2BIG);
    input.platform = XE_NOVALAKE_P;
    input.reg_size = 0x10001;
    assert(run(input, &result) == 0 &&
        result.size == 0x1000000); /* source retained, not native admission */
    printf("Intel WOPCM: %u unchanged-source register sequences, independent "
           "reserve/layout/generation bounds; no hardware readback/upload\n",
        traces);
    return 0;
}
