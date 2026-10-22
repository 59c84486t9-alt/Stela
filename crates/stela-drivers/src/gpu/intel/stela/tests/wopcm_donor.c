/* SPDX-License-Identifier: MIT */
/* Frozen original algorithms, separate object without LTO. Test scalar/MMIO
 * context and real pthread serialization only, no fabricated Linux objects. */
#include "wopcm_donor.h"
#include "../../xe/xe_uc_fw_types.h"
#include <assert.h>
#include <stdarg.h>
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
#define EINVAL 22
#define E2BIG 7
static _Thread_local struct stela_wopcm_model *active_model;
static void donor_log(struct stela_wopcm_model *model, const char *format, ...)
{
    va_list args; va_start(args, format);
    uint32_t event = 0, a = 0, b = 0, c = 0;
    if (strstr(format, "invalid GuC region")) {
        event = 0; a = va_arg(args, unsigned); b = va_arg(args, unsigned); c = va_arg(args, unsigned);
    } else if (strstr(format, "no space for")) {
        const char *type = va_arg(args, const char *);
        assert(!strcmp(type, "GuC") || !strcmp(type, "HuC"));
        event = !strcmp(type, "GuC") ? 1 : 2;
        a = va_arg(args, unsigned); b = va_arg(args, unsigned);
    } else if (strstr(format, "Failed to init")) event = 3;
    else if (strstr(format, "%s(%#x)")) {
        const char *name = va_arg(args, const char *);
        assert(!strcmp(name, "DMA_GUC_WOPCM_OFFSET") || !strcmp(name, "GUC_WOPCM_SIZE"));
        event = !strcmp(name, "DMA_GUC_WOPCM_OFFSET") ? 4 : 5;
        a = va_arg(args, unsigned); b = va_arg(args, unsigned);
    } else if (!strcmp(format, "WOPCM: %uK\n")) { event = 6; a = va_arg(args, unsigned); }
    else if (strstr(format, "already locked")) { event = 7; a = va_arg(args, unsigned); b = va_arg(args, unsigned); }
    else if (strstr(format, "Calculated")) { event = 8; a = va_arg(args, unsigned); b = va_arg(args, unsigned); }
    else { assert(strstr(format, "Unsuccessful")); event = 9; }
    va_end(args); stela_wopcm_record(model, 100 + event, a, b, c);
}
static void donor_warn(struct stela_wopcm_model *model, const char *expression, bool condition)
{
    const char *expressions[] = {"!(base & GUC_WOPCM_OFFSET_MASK)", "base & ~GUC_WOPCM_OFFSET_MASK",
        "!(size & GUC_WOPCM_SIZE_MASK)", "size & ~GUC_WOPCM_SIZE_MASK",
        "guc_fw_size >= wopcm->size", "huc_fw_size >= wopcm->size",
        "ctx_rsvd + WOPCM_RESERVED_SIZE >= wopcm->size", "!wopcm->guc.base", "!wopcm->guc.size"};
    unsigned i = 0;
    while (i < sizeof(expressions) / sizeof(expressions[0]) && strcmp(expression, expressions[i])) ++i;
    assert(i < sizeof(expressions) / sizeof(expressions[0]));
    if (condition) stela_wopcm_record(model, 200 + i, 0, 0, 0);
}
#define drm_err(device, ...) donor_log(xe, __VA_ARGS__)
#define drm_dbg(device, ...) donor_log(xe, __VA_ARGS__)
#define drm_notice(device, ...) donor_log(xe, __VA_ARGS__)
#define XE_WARN_ON(condition) donor_warn(xe, #condition, !!(condition))
#define IS_DGFX(xe) ((xe)->discrete)
#define xe_uc_fw_type_repr(type) ((type) == XE_UC_FW_TYPE_GUC ? "GuC" : "HuC")
#define xe_force_wake_assert_held(fw, domain) stela_wopcm_assert(gt)
#define wopcm_to_xe(wopcm) active_model
#define wopcm_to_gt(wopcm) active_model
#define xe_mmio_write32 stela_wopcm_write
#define xe_mmio_read32 stela_wopcm_read
#define xe_mmio_write32_and_verify donor_verify
#include "donor-verify.inc"
#include "donor-wopcm-constants.inc"
#define xe_wopcm_init donor_wopcm_init
#include "donor-wopcm-body.inc"
int stela_wopcm_donor(struct stela_wopcm_model *model, struct xe_wopcm *output)
{
    active_model = model;
    int status = donor_wopcm_init(output);
    active_model = NULL;
    return status;
}
bool stela_wopcm_donor_role(bool media_gt, unsigned graphics_verx100)
{
#include "donor-huc-role.inc"
}
