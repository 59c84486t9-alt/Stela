/* SPDX-License-Identifier: MIT */
/* Stela's environment for the unchanged Linux xe_wopcm.c, which follows. */
#include "wopcm.h"
#include "firmware.h"
#include <linux/array_size.h>
#include <stdarg.h>
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_mmio.h"
#include "xe_uc_fw.h"
#include "regs/xe_guc_regs.h"
_Static_assert(sizeof(struct xe_wopcm) == 12, "original WOPCM metadata ABI");
_Static_assert(sizeof(struct guc_doorbell_info) == 64, "original packed doorbell ABI");
_Static_assert(_Alignof(struct guc_doorbell_info) == 1, "original packed alignment");

struct native_wopcm {
    struct xe_device xe;
    struct xe_gt gt;
    struct stela_intel_wopcm_result *result;
};
/* Linux reports WARN_ON without naming a device. Attempts are serialized
 * so a warning names the active one; a concurrent attempt is refused. */
static struct native_wopcm *active;

static struct native_wopcm *native_of(struct xe_mmio *mmio)
{
    return container_of(container_of(mmio, struct xe_gt, mmio), struct native_wopcm, gt);
}
static void invariant(struct native_wopcm *native, bool condition)
{
    native->gt.mmio.io->invariant(native->gt.mmio.context, condition);
}
static bool same_text(const char *a, const char *b)
{
    while (*a && *a == *b) ++a, ++b;
    return *a == *b;
}
static u32 xe_mmio_read32(struct xe_mmio *mmio, struct xe_reg reg)
{
    struct native_wopcm *native = native_of(mmio);
    invariant(native, !(reg.addr & 3) && reg.addr + 4 <= XE_REG_ADDR_MAX);
    u32 value = mmio->io->read32(mmio->context, reg.addr);
    if (reg.addr == DMA_GUC_WOPCM_OFFSET.addr) native->result->raw_offset = value;
    if (reg.addr == GUC_WOPCM_SIZE.addr) native->result->raw_size = value;
    return value;
}
static void xe_mmio_write32(struct xe_mmio *mmio, struct xe_reg reg, u32 value)
{
    struct native_wopcm *native = native_of(mmio);
    invariant(native, !(reg.addr & 3) && reg.addr + 4 <= XE_REG_ADDR_MAX);
    ++native->result->writes; /* Exposure begins BEFORE real owner callback. */
    mmio->io->write32(mmio->context, reg.addr, value);
}
/* Diagnostics bits16..24 are xe_wopcm.c's warnings, in source order. */
static void stela_linux_warn(const char *file, int line, const char *condition)
{
    static const char *const conditions[] = {
        "!(base & GUC_WOPCM_OFFSET_MASK)", "base & ~GUC_WOPCM_OFFSET_MASK",
        "!(size & GUC_WOPCM_SIZE_MASK)", "size & ~GUC_WOPCM_SIZE_MASK",
        "guc_fw_size >= wopcm->size", "huc_fw_size >= wopcm->size",
        "ctx_rsvd + WOPCM_RESERVED_SIZE >= wopcm->size", "!wopcm->guc.base", "!wopcm->guc.size",
    };
    struct native_wopcm *native = active;
    unsigned id = 0;
    (void)file; (void)line;
    while (id < ARRAY_SIZE(conditions) && !same_text(condition, conditions[id])) ++id;
    invariant(native, id < ARRAY_SIZE(conditions));
    if (id < ARRAY_SIZE(conditions)) native->result->diagnostics |= UINT32_C(1) << (16 + id);
}
/* Diagnostics bits0..9 are xe_wopcm.c's messages, in source order. */
static void stela_drm_printk(const struct drm_device *drm, enum stela_drm_level level,
    const char *format, ...)
{
    static const char *const formats[] = {
        "WOPCM: invalid GuC region layout: %uK + %uK > %uK\n",
        "WOPCM: no space for %s: %uK < %uK\n",
        "Failed to init uC WOPCM registers!\n",
        "%s(%#x)=%#x\n",
        "WOPCM: %uK\n",
        "GuC WOPCM is already locked [%uK, %uK)\n",
        "Calculated GuC WOPCM [%uK, %uK)\n",
        "Unsuccessful WOPCM partitioning\n",
    };
    static const unsigned first_event[] = {0, 1, 3, 4, 6, 7, 8, 9};
    struct native_wopcm *native =
        container_of(container_of(drm, struct xe_device, drm), struct native_wopcm, xe);
    unsigned index = 0;
    (void)level;
    while (index < ARRAY_SIZE(formats) && !same_text(format, formats[index])) ++index;
    invariant(native, index < ARRAY_SIZE(formats));
    if (index == ARRAY_SIZE(formats)) return;
    unsigned event = first_event[index];
    if (index == 1 || index == 3) {
        va_list arguments;
        va_start(arguments, format);
        const char *name = va_arg(arguments, const char *);
        va_end(arguments);
        bool second = same_text(name, index == 1 ? "HuC" : "GUC_WOPCM_SIZE");
        invariant(native, second || same_text(name, index == 1 ? "GuC" : "DMA_GUC_WOPCM_OFFSET"));
        event += second;
    }
    native->result->diagnostics |= UINT32_C(1) << event;
}

#include "xe_wopcm.c"

int stela_intel_wopcm_prepare(const struct stela_intel_activation_io *io, void *context,
    uint32_t platform, uint32_t graphics_verx100, bool discrete,
    const uint8_t *guc_bytes, size_t guc_size, struct stela_intel_wopcm_result *out)
{
    if (!out) return -EINVAL;
    *out = (struct stela_intel_wopcm_result){0};
    if (!io || !io->read32 || !io->write32 || !io->invariant || !guc_bytes) return -EINVAL;
    struct stela_intel_huc_default huc;
    int status = stela_intel_huc_select_default(platform, graphics_verx100, false, &huc);
    if (status) return status;
    switch (huc.disposition) {
    case STELA_INTEL_HUC_ABSENT:
        break; /* Linux marks HuC NOT_SUPPORTED: unsupported role or no default path. */
    case STELA_INTEL_HUC_SELECTED:
        return -95; /* Genuine HuC input/availability still required. */
    default:
        return -EINVAL;
    }
    struct stela_intel_guc_metadata metadata;
    status = stela_intel_guc_parse(platform, guc_bytes, guc_size,
                                      &metadata, &out->firmware_diagnostics);
    if (status) return status;
    if (metadata.upload_bytes > UINT32_MAX - GUC_WOPCM_RESERVED - GUC_WOPCM_STACK_RESERVED)
        return -75;
    struct native_wopcm native = {
        .xe.info = {.platform = (enum xe_platform)platform, .is_dgfx = discrete},
        .xe.tiles[0].xe = &native.xe,
        .gt = {
            .tile = &native.xe.tiles[0], .mmio = {.io = io, .context = context},
            .uc.guc.fw = {.type = XE_UC_FW_TYPE_GUC, .__status = XE_UC_FIRMWARE_AVAILABLE,
                          .ucode_size = metadata.ucode_bytes},
            .uc.huc.fw = {.type = XE_UC_FW_TYPE_HUC, .__status = XE_UC_FIRMWARE_NOT_SUPPORTED},
        },
        .result = out,
    };
    struct native_wopcm *idle = NULL;
    if (!__atomic_compare_exchange_n(&active, &idle, &native, false,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return -EBUSY;
    status = xe_wopcm_init(&native.gt.uc.wopcm);
    __atomic_store_n(&active, NULL, __ATOMIC_RELEASE);
    out->total_bytes = native.gt.uc.wopcm.size;
    out->guc_base = native.gt.uc.wopcm.guc.base;
    out->guc_bytes = native.gt.uc.wopcm.guc.size;
    return status;
}
