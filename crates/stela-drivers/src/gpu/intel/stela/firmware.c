/* SPDX-License-Identifier: MIT */
/* Stela's environment for the unchanged Linux xe_uc_fw.c, which follows. */
#include "firmware.h"
#include <stdarg.h>
#include <linux/array_size.h>
#include <linux/firmware.h>
#include <drm/drm_managed.h>
#include "xe_bo.h"
#include "xe_device.h"
#include "xe_force_wake.h"
#include "xe_gt_printk.h"
#include "xe_gt_sriov_vf.h"
#include "xe_huc_role.h"
#include "xe_map.h"
#include "xe_mmio.h"
#include "xe_uc_fw.h"
#include "abi/uc_fw_abi.h"
_Static_assert(sizeof(struct gsc_cpd_header_v2) == 20, "original CPD header ABI");
_Static_assert(sizeof(struct gsc_cpd_entry) == 24, "original CPD entry ABI");
_Static_assert(sizeof(struct gsc_manifest_header) == 128, "original manifest ABI");
_Static_assert(_Alignof(struct gsc_cpd_header_v2) == 1, "packed CPD marker access");
_Static_assert(_Alignof(struct gsc_cpd_entry) == 1, "packed CPD entry access");
_Static_assert(_Alignof(struct gsc_manifest_header) == 1, "packed manifest access");

struct native_fw {
    struct xe_device xe;
    struct xe_gt gt;
    uint32_t *diagnostics;
};

static void invariant(bool condition)
{
    if (!condition) __builtin_trap();
}
/* Upstream compares CPD entry names only against literals shorter than the
 * 12-byte name, so the comparison ends inside the entry. */
static int stela_linux_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) ++a, ++b;
    return (unsigned char)*a - (unsigned char)*b;
}
/* Diagnostics bits name xe_uc_fw.c's parse and version messages. Any other
 * message comes from a lifecycle Stela never enters. */
static void stela_drm_printk(const struct drm_device *drm, enum stela_drm_level level,
    const char *format, ...)
{
    static const struct { const char *format; uint32_t diagnostic; } messages[] = {
        {"%s firmware %s: unexpected header size: %zu != %zu\n", STELA_INTEL_GUC_HEADER_SIZE},
        {"Unsupported GuC v%u.%u.%u! v70.29.2 or newer is required\n", STELA_INTEL_GUC_TOO_OLD},
        {"%s firmware %s: unexpected version: %u.%u.%u != %u.%u.%u\n",
         STELA_INTEL_GUC_VERSION_MISMATCH},
        {"%s firmware (%u.%u.%u) is recommended, but only (%u.%u.%u) was found in %s\n",
         STELA_INTEL_GUC_RECOMMENDED_NEWER},
        {"Consider updating your linux-firmware pkg or downloading from %s\n",
         STELA_INTEL_GUC_RECOMMENDED_NEWER},
        {"invalid CPD header length %u!\n", STELA_INTEL_HUC_CPD_HEADER_LENGTH},
        {"FW too small! %zu < %zu\n", STELA_INTEL_HUC_CPD_SHORT_IMAGE},
        {"FW too small! %zu < %u\n", STELA_INTEL_HUC_CPD_SHORT_IMAGE},
        {"Failed to find %s manifest!\n", STELA_INTEL_HUC_CPD_MISSING_MANIFEST},
    };
    struct native_fw *native =
        container_of(container_of(drm, struct xe_device, drm), struct native_fw, xe);
    (void)level;
    if (!strcmp(format, "%s firmware %s: invalid size: %zu < %zu\n")) {
        va_list arguments;
        va_start(arguments, format);
        (void)va_arg(arguments, const char *);
        (void)va_arg(arguments, const char *);
        size_t actual = va_arg(arguments, size_t), needed = va_arg(arguments, size_t);
        va_end(arguments);
        /* The first size check is the header's; the second the whole image's. */
        bool header = actual < sizeof(struct uc_css_header) && needed == sizeof(struct uc_css_header);
        *native->diagnostics |= header ? STELA_INTEL_GUC_SHORT_HEADER : STELA_INTEL_GUC_SHORT_IMAGE;
        return;
    }
    unsigned index = 0;
    while (index < ARRAY_SIZE(messages) && strcmp(format, messages[index].format)) ++index;
    invariant(index < ARRAY_SIZE(messages));
    *native->diagnostics |= messages[index].diagnostic;
}
/* Stela selects and parses images only. Requests, BO placement, DMA upload,
 * printers and VF bootstrap belong to other owners; reaching one traps. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
static void stela_linux_warn(const char *file, int line, const char *condition) { __builtin_trap(); }
static bool xe_device_uc_enabled(struct xe_device *xe) { __builtin_trap(); }
static struct xe_tile *gt_to_tile(struct xe_gt *gt) { __builtin_trap(); }
static int firmware_request_nowarn(const struct firmware **fw, const char *name,
    struct device *device) { __builtin_trap(); }
static void release_firmware(const struct firmware *fw) { __builtin_trap(); }
static struct xe_bo *xe_managed_bo_create_from_data(struct xe_device *xe, struct xe_tile *tile,
    const void *data, size_t size, u32 flags) { __builtin_trap(); }
static u32 xe_bo_ggtt_addr(struct xe_bo *bo) { __builtin_trap(); }
static int drmm_add_action_or_reset(struct drm_device *dev, drmres_release_t action,
    void *data) { __builtin_trap(); }
static void xe_map_memcpy_from(struct xe_device *xe, void *dst, const struct iosys_map *src,
    size_t src_offset, size_t len) { __builtin_trap(); }
static void xe_gt_sriov_vf_guc_versions(struct xe_gt *gt, struct xe_uc_fw_version *wanted,
    struct xe_uc_fw_version *found) { __builtin_trap(); }
static struct drm_printer xe_gt_info_printer(struct xe_gt *gt) { __builtin_trap(); }
static void drm_printf(struct drm_printer *p, const char *f, ...) { __builtin_trap(); }
static void xe_force_wake_assert_held(struct xe_force_wake *fw,
    enum xe_force_wake_domains domain) { __builtin_trap(); }
static void xe_mmio_write32(struct xe_mmio *mmio, struct xe_reg reg, u32 val) { __builtin_trap(); }
static int xe_mmio_wait32(struct xe_mmio *mmio, struct xe_reg reg, u32 mask, u32 val,
    u32 timeout_us, u32 *out_val, bool atomic) { __builtin_trap(); }
#pragma clang diagnostic pop

#include "xe_uc_fw.c"

/* Fills a zeroed native. The firmware lives in the GT member upstream derives
 * its owner from. */
static struct xe_uc_fw *prepare(struct native_fw *native, uint32_t platform, bool media_gt,
                                enum xe_uc_fw_type type, uint32_t *diagnostics)
{
    native->xe.info.platform = (enum xe_platform)platform;
    native->gt.xe = &native->xe;
    native->gt.info.type = media_gt ? XE_GT_TYPE_MEDIA : XE_GT_TYPE_MAIN;
    native->diagnostics = diagnostics;
    struct xe_uc_fw *fw = type == XE_UC_FW_TYPE_GUC ? &native->gt.uc.guc.fw :
                          type == XE_UC_FW_TYPE_HUC ? &native->gt.uc.huc.fw : &native->gt.uc.gsc.fw;
    fw->type = type;
    return fw;
}
static int copy_selection(const struct xe_uc_fw *fw, uint8_t name[64],
                          uint32_t wanted[3], uint32_t *full_version)
{
    size_t n = 0;
    while (fw->path[n]) {
        if (n + 1 >= 64) return -36;
        name[n] = (uint8_t)fw->path[n];
        ++n;
    }
    wanted[0] = fw->versions.wanted.major;
    wanted[1] = fw->versions.wanted.minor;
    wanted[2] = fw->versions.wanted.patch;
    *full_version = fw->full_ver_required;
    return 0;
}
static struct xe_uc_fw *select_guc(struct native_fw *native, uint32_t platform,
                                   uint32_t *diagnostics)
{
    if (!platform || platform > INT32_MAX) return NULL;
    struct xe_uc_fw *fw = prepare(native, platform, false, XE_UC_FW_TYPE_GUC, diagnostics);
    uc_fw_auto_select(&native->xe, fw);
    return fw;
}
int stela_intel_guc_select(uint32_t platform, struct stela_intel_guc_selection *out)
{
    if (!out) return -EINVAL;
    struct native_fw native = {0};
    uint32_t diagnostics = 0;
    const struct xe_uc_fw *fw = select_guc(&native, platform, &diagnostics);
    if (!fw) return -EINVAL;
    if (!fw->path) return -ENOENT;
    struct stela_intel_guc_selection result = {0};
    int status = copy_selection(fw, result.name, result.wanted, &result.full_version);
    if (status) return status;
    *out = result;
    return 0;
}
int stela_intel_huc_select_default(uint32_t platform, uint32_t graphics_verx100,
                                 bool media_gt, struct stela_intel_huc_default *out)
{
    if (!out || !platform || platform > INT32_MAX || !graphics_verx100) return -EINVAL;
    struct stela_intel_huc_default result = {0};
    if (xe_huc_role_unsupported(media_gt, graphics_verx100)) {
        result.disposition = STELA_INTEL_HUC_ABSENT_ROLE;
    } else {
        struct native_fw native = {0};
        uint32_t diagnostics = 0;
        struct xe_uc_fw *fw = prepare(&native, platform, media_gt, XE_UC_FW_TYPE_HUC, &diagnostics);
        uc_fw_auto_select(&native.xe, fw);
        /* Original uc_fw_request: missing default path is NOT_SUPPORTED;
         * only missing GuC is mandatory -ENOENT. No status is fabricated here. */
        if (!fw->path) result.disposition = STELA_INTEL_HUC_ABSENT_CATALOG;
        else {
            result.disposition = STELA_INTEL_HUC_SELECTED;
            int status = copy_selection(fw, result.name, result.wanted, &result.full_version);
            if (status) return status;
        }
    }
    *out = result;
    return 0;
}
/* Original CSS type is packed; checked arithmetic precedes any narrowing in
 * the original algorithm. This does not impose hardware RSA/WOPCM policy. */
static int sizes_representable(const uint8_t *bytes, size_t size)
{
    if (size < sizeof(struct uc_css_header)) return 0; /* Original short-header diagnostic. */
    const struct uc_css_header *css = (const void *)bytes;
    uint64_t rsa_header = (uint64_t)css->rsa_info.key_size_dw +
                          css->rsa_info.modulus_size_dw + css->rsa_info.exponent_size_dw;
    if (css->header_size_dw < rsa_header || css->size_dw < css->header_size_dw) return -75;
    uint64_t ucode = (uint64_t)(css->size_dw - css->header_size_dw) * sizeof(uint32_t);
    uint64_t rsa = (uint64_t)css->rsa_info.key_size_dw * sizeof(uint32_t);
    if (ucode + sizeof(struct uc_css_header) > UINT32_MAX || rsa > UINT32_MAX) return -75;
    return 0;
}
int stela_intel_guc_parse(uint32_t platform, const uint8_t *bytes, size_t size,
                         struct stela_intel_guc_metadata *out, uint32_t *diagnostics)
{
    if (!diagnostics) return -EINVAL;
    *diagnostics = 0;
    if (!out || !bytes || size > PTRDIFF_MAX) return -EINVAL;
    struct native_fw native = {0};
    struct xe_uc_fw *fw = select_guc(&native, platform, diagnostics);
    if (!fw) return -EINVAL;
    if (!fw->path) return -ENOENT;
    int status = sizes_representable(bytes, size);
    if (status) { *diagnostics = STELA_INTEL_GUC_UNREPRESENTABLE; return status; }
    status = parse_headers(fw, &(const struct firmware){.size = size, .data = bytes});
    if (!status) status = xe_uc_fw_check_version_requirements(fw);
    if (status) return status;
    struct stela_intel_guc_metadata result = {
        .release = {fw->versions.found[XE_UC_FW_VER_RELEASE].major,
                    fw->versions.found[XE_UC_FW_VER_RELEASE].minor,
                    fw->versions.found[XE_UC_FW_VER_RELEASE].patch},
        .submission = {fw->versions.found[XE_UC_FW_VER_COMPATIBILITY].major,
                       fw->versions.found[XE_UC_FW_VER_COMPATIBILITY].minor,
                       fw->versions.found[XE_UC_FW_VER_COMPATIBILITY].patch},
        .ucode_bytes = fw->ucode_size, .rsa_bytes = fw->rsa_size,
        .upload_bytes = (uint32_t)sizeof(struct uc_css_header) + fw->ucode_size,
        .private_bytes = fw->private_data_size, .build_type = fw->build_type,
        .diagnostics = *diagnostics,
    };
    *out = result;
    return 0;
}

/* Upstream's int entry index must not overflow on a complete entry table, and
 * the CSS view it reaches, embedded or whole, passes the size preflight. Where
 * upstream stops first, its original diagnostics and errors are preserved. */
static int huc_representable(const uint8_t *bytes, size_t size)
{
    if (size < sizeof(struct gsc_cpd_header_v2) || !is_cpd_header(bytes))
        return sizes_representable(bytes, size);
    const struct gsc_cpd_header_v2 *header = (const void *)bytes;
    if (header->header_length < sizeof(*header)) return 0;
    uint64_t table = (uint64_t)header->header_length +
                     (uint64_t)header->num_of_entries * sizeof(struct gsc_cpd_entry);
    if (table > size) return 0;
    if (header->num_of_entries > INT32_MAX) return -75;
    u32 manifest = entry_offset(header, "HUCP.man");
    if (!manifest || manifest + sizeof(struct gsc_manifest_header) > size) return 0;
    u32 css = entry_offset(header, "huc_fw");
    return css <= size ? sizes_representable(bytes + css, size - css) : 0;
}
int stela_intel_huc_parse(uint32_t platform, uint32_t graphics_verx100, bool media_gt,
                         const uint8_t *bytes, size_t size, struct stela_intel_huc_metadata *out,
                         uint32_t *diagnostics)
{
    if (!diagnostics) return -EINVAL;
    *diagnostics = 0;
    /* Linux firmware buffers are page aligned and upstream reads the CPD
     * marker as a u32, so the image must be at least that aligned. */
    if (!bytes || !out || size > PTRDIFF_MAX || (uintptr_t)bytes % sizeof(u32)) return -EINVAL;
    struct stela_intel_huc_default selected;
    int status = stela_intel_huc_select_default(platform, graphics_verx100, media_gt, &selected);
    if (status) return status;
    if (selected.disposition != STELA_INTEL_HUC_SELECTED) return -95;
    /* Original HuC CPD/DMA parser explicitly does not support DG2's CSS-less
     * GSC loading path. No selection alias or invented CSS is permitted. */
    if (platform == XE_DG2) return -95;
    struct native_fw native = {0};
    struct xe_uc_fw *fw = prepare(&native, platform, media_gt, XE_UC_FW_TYPE_HUC, diagnostics);
    uc_fw_auto_select(&native.xe, fw);
    status = huc_representable(bytes, size);
    if (status) { *diagnostics = STELA_INTEL_GUC_UNREPRESENTABLE; return status; }
    status = parse_headers(fw, &(const struct firmware){.size = size, .data = bytes});
    if (!status) status = xe_uc_fw_check_version_requirements(fw);
    if (status) return status;
    struct stela_intel_huc_metadata result = {
        .release = {fw->versions.found[XE_UC_FW_VER_RELEASE].major,
                    fw->versions.found[XE_UC_FW_VER_RELEASE].minor,
                    fw->versions.found[XE_UC_FW_VER_RELEASE].patch},
        .ucode_bytes = fw->ucode_size, .rsa_bytes = fw->rsa_size,
        .upload_bytes = (uint32_t)sizeof(struct uc_css_header) + fw->ucode_size,
        .css_offset = fw->css_offset,
        .format = fw->has_gsc_headers ? STELA_INTEL_HUC_CPD_CSS : STELA_INTEL_HUC_CSS,
        .diagnostics = *diagnostics,
    };
    *out = result;
    return 0;
}
