/* SPDX-License-Identifier: MIT */
/* The unchanged Linux xe_wopcm.c, which partitions WOPCM for the GuC and
 * locks its registers, on a native device over the activated GPU's
 * registers. */
#include "wopcm.h"
#include "device.h"
#include "firmware.h"
#include <linux/string.h>
#include "xe_wopcm.c"

struct native_wopcm {
    struct stela_xe dev;
    struct xe_gt gt;
    struct stela_intel_wopcm_result *result;
};

static struct native_wopcm *native_of(void *context)
{
    return container_of((struct stela_xe *)context, struct native_wopcm, dev);
}
static void invariant(struct native_wopcm *native, bool condition)
{
    native->dev.io->invariant(native->dev.context, condition);
}

/* Exposure is counted before each write reaches the owner. */
static void observe(struct stela_xe *dev, u32 addr, u32 value, bool write)
{
    struct stela_intel_wopcm_result *result = native_of(dev)->result;
    if (write) ++result->writes;
    else if (addr == DMA_GUC_WOPCM_OFFSET.addr) result->raw_offset = value;
    else if (addr == GUC_WOPCM_SIZE.addr) result->raw_size = value;
}
/* Diagnostics bits 0..9 are xe_wopcm.c's messages, in source order; Stela
 * runs Linux code with drm.debug's driver category, so its debug messages
 * arrive too. */
static void log_event(void *context, int level, const char *message)
{
    static const char *const events[] = {
        "WOPCM: invalid GuC region layout", "WOPCM: no space for GuC",
        "WOPCM: no space for HuC", "Failed to init uC WOPCM registers!",
        "DMA_GUC_WOPCM_OFFSET(", "GUC_WOPCM_SIZE(", "WOPCM: ",
        "GuC WOPCM is already locked", "Calculated GuC WOPCM",
        "Unsuccessful WOPCM partitioning",
    };
    struct native_wopcm *native = native_of(context);
    unsigned event = 0;
    (void)level;
    while (event < ARRAY_SIZE(events) && !strstr(message, events[event])) ++event;
    invariant(native, event < ARRAY_SIZE(events));
    if (event < ARRAY_SIZE(events)) native->result->diagnostics |= UINT32_C(1) << event;
}
/* Diagnostics bits 16..24 are xe_wopcm.c's warnings, in source order. */
static void warn_event(void *context, const char *file, int line, const char *condition)
{
    static const char *const conditions[] = {
        "!(base & GUC_WOPCM_OFFSET_MASK)", "base & ~GUC_WOPCM_OFFSET_MASK",
        "!(size & GUC_WOPCM_SIZE_MASK)", "size & ~GUC_WOPCM_SIZE_MASK",
        "guc_fw_size >= wopcm->size", "huc_fw_size >= wopcm->size",
        "ctx_rsvd + WOPCM_RESERVED_SIZE >= wopcm->size", "!wopcm->guc.base", "!wopcm->guc.size",
    };
    struct native_wopcm *native = native_of(context);
    unsigned id = 0;
    (void)file; (void)line;
    while (id < ARRAY_SIZE(conditions) && strcmp(condition, conditions[id])) ++id;
    invariant(native, id < ARRAY_SIZE(conditions));
    if (id < ARRAY_SIZE(conditions)) native->result->diagnostics |= UINT32_C(1) << (16 + id);
}
static const struct stela_linux_services services = {
    .log = log_event, .warn = warn_event, .unsupported = stela_xe_unsupported,
};

/* A native of the given platform, with a GuC image of ucode_bytes and no
 * HuC, whose register accesses result records. Linux marks HuC
 * NOT_SUPPORTED for a GT without one or a platform without a default
 * image. */
static void prepare(struct native_wopcm *native, const struct stela_intel_activation_io *io,
                    void *context, enum xe_platform platform, bool discrete, u32 ucode_bytes,
                    struct stela_intel_wopcm_result *result)
{
    memset(native, 0, sizeof(*native));
    native->dev.xe.info.platform = platform;
    native->dev.xe.info.is_dgfx = discrete;
    native->dev.io = io;
    native->dev.context = context;
    native->dev.observe = observe;
    stela_xe_init(&native->dev, &native->gt, XE_GT_TYPE_MAIN);
    /* The activated GPU's GT domain, which its caller holds awake. */
    native->gt.pm.fw.gt = &native->gt;
    native->gt.pm.fw.awake_domains = XE_FW_GT;
    native->gt.uc.guc.fw.type = XE_UC_FW_TYPE_GUC;
    native->gt.uc.guc.fw.__status = XE_UC_FIRMWARE_AVAILABLE;
    native->gt.uc.guc.fw.ucode_size = ucode_bytes;
    native->gt.uc.huc.fw.type = XE_UC_FW_TYPE_HUC;
    native->gt.uc.huc.fw.__status = XE_UC_FIRMWARE_NOT_SUPPORTED;
    native->result = result;
}

/* The device an attempt runs xe_wopcm_init on. Only the running Linux owner
 * uses it, so there is one. */
static struct native_wopcm native;

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
    const struct stela_linux_owner owner = {.services = &services, .context = &native.dev};
    stela_linux_enter(&owner);
    prepare(&native, io, context, (enum xe_platform)platform, discrete, metadata.ucode_bytes,
            out);
    status = xe_wopcm_init(&native.gt.uc.wopcm);
    if (!status && native.dev.unsupported) status = -EOPNOTSUPP;
    out->total_bytes = native.gt.uc.wopcm.size;
    out->guc_base = native.gt.uc.wopcm.guc.base;
    out->guc_bytes = native.gt.uc.wopcm.guc.size;
    stela_linux_exit();
    return status;
}
