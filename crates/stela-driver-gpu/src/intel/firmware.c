/* SPDX-License-Identifier: MIT */
/* The unchanged Linux xe_uc_fw.c and xe_huc.c, which select GuC and HuC
 * images and parse their headers, on a native device without registers.
 * Stela selects and parses images only: requests, BO placement, DMA upload,
 * HuC authentication and VF bootstrap belong to other owners. */
#include "firmware.h"
#include "device.h"
#include <linux/string.h>
#include <unsupported.h>
#include "xe_uc_fw.c"
#include "xe_huc.c"
_Static_assert(sizeof(struct gsc_cpd_header_v2) == 20, "original CPD header ABI");
_Static_assert(sizeof(struct gsc_cpd_entry) == 24, "original CPD entry ABI");
_Static_assert(sizeof(struct gsc_manifest_header) == 128, "original manifest ABI");
_Static_assert(_Alignof(struct gsc_cpd_header_v2) == 1, "packed CPD marker access");
_Static_assert(_Alignof(struct gsc_cpd_entry) == 1, "packed CPD entry access");
_Static_assert(_Alignof(struct gsc_manifest_header) == 1, "packed manifest access");

/* Image requests, BO placement and upload, HuC authentication through the
 * GSC and VF bootstrap follow parsing, in lifecycles Stela does not enter. */
STELA_UNSUPPORTED(void, xe_device_assert_mem_access, struct xe_device *)
STELA_UNSUPPORTED(u64, xe_ggtt_node_addr, const struct xe_ggtt_node *)
STELA_UNSUPPORTED(bool, xe_gsc_check_and_update_pending, struct xe_device *, struct iosys_map *,
                  u32, struct iosys_map *, u32)
STELA_UNSUPPORTED(u32, xe_gsc_emit_header, struct xe_device *, struct iosys_map *, u32, u8, u64,
                  u32)
STELA_UNSUPPORTED(int, xe_gsc_pkt_submit_kernel, struct xe_gsc *, u64, u32, u64, u32)
STELA_UNSUPPORTED(int, xe_gsc_read_out_header, struct xe_device *, struct iosys_map *, u32, u32,
                  u32 *)
STELA_UNSUPPORTED(void, xe_gt_sriov_vf_guc_versions, struct xe_gt *, struct xe_uc_fw_version *,
                  struct xe_uc_fw_version *)
STELA_UNSUPPORTED(int, xe_guc_auth_huc, struct xe_guc *, u32)
STELA_UNSUPPORTED(struct xe_bo *, xe_managed_bo_create_from_data, struct xe_device *,
                  struct xe_tile *, const void *, size_t, u32)
STELA_UNSUPPORTED(struct xe_bo *, xe_managed_bo_create_pin_map, struct xe_device *,
                  struct xe_tile *, size_t, u32)
STELA_UNSUPPORTED(int, xe_managed_bo_reinit_in_vram, struct xe_device *, struct xe_tile *,
                  struct xe_bo **)

struct native_fw {
    struct stela_xe dev;
    struct xe_gt gt;
    uint32_t *diagnostics;
};

static struct native_fw *native_of(void *context)
{
    return container_of((struct stela_xe *)context, struct native_fw, dev);
}
/* Diagnostics bits name xe_uc_fw.c's parse and version messages. Debug
 * messages carry no diagnosis; any other comes from a lifecycle Stela never
 * enters. */
static void log_event(void *context, int level, const char *message)
{
    static const struct { const char *text; uint32_t diagnostic; } messages[] = {
        {"unexpected header size", STELA_INTEL_GUC_HEADER_SIZE},
        {"or newer is required", STELA_INTEL_GUC_TOO_OLD},
        {"unexpected version", STELA_INTEL_GUC_VERSION_MISMATCH},
        {"is recommended, but only", STELA_INTEL_GUC_RECOMMENDED_NEWER},
        {"Consider updating your linux-firmware", STELA_INTEL_GUC_RECOMMENDED_NEWER},
        {"invalid CPD header length", STELA_INTEL_HUC_CPD_HEADER_LENGTH},
        {"FW too small!", STELA_INTEL_HUC_CPD_SHORT_IMAGE},
        {"manifest!", STELA_INTEL_HUC_CPD_MISSING_MANIFEST},
    };
    uint32_t *diagnostics = native_of(context)->diagnostics;
    if (level == LOGLEVEL_DEBUG) return;
    const char *needed = strstr(message, ": invalid size: ");
    if (needed) {
        /* "%zu < %zu": the header's check needs exactly a CSS header, the
         * whole image's more. */
        unsigned long long bytes = 0;
        for (needed = strstr(needed, " < ") + 3; *needed >= '0' && *needed <= '9'; ++needed)
            bytes = bytes * 10 + (unsigned)(*needed - '0');
        *diagnostics |= bytes == sizeof(struct uc_css_header) ? STELA_INTEL_GUC_SHORT_HEADER :
                                                               STELA_INTEL_GUC_SHORT_IMAGE;
        return;
    }
    unsigned index = 0;
    while (index < ARRAY_SIZE(messages) && !strstr(message, messages[index].text)) ++index;
    if (index == ARRAY_SIZE(messages)) __builtin_trap();
    *diagnostics |= messages[index].diagnostic;
}
static const struct stela_linux_services services = {
    .log = log_event, .unsupported = stela_xe_unsupported,
};

/* The device a call runs xe_uc_fw.c on. Only the running Linux owner uses
 * it, so there is one. */
static struct native_fw native;

/* Enters with a zeroed native of a GT of the given platform and role,
 * returning its firmware of the given type. */
static struct xe_uc_fw *enter(uint32_t platform, bool media_gt, enum xe_uc_fw_type type,
                              uint32_t *diagnostics)
{
    static const struct stela_linux_owner owner = {.services = &services, .context = &native.dev};
    stela_linux_enter(&owner);
    memset(&native, 0, sizeof(native));
    native.dev.xe.info.platform = (enum xe_platform)platform;
    stela_xe_init(&native.dev, &native.gt, media_gt ? XE_GT_TYPE_MEDIA : XE_GT_TYPE_MAIN);
    native.diagnostics = diagnostics;
    struct xe_uc_fw *fw = type == XE_UC_FW_TYPE_GUC ? &native.gt.uc.guc.fw :
                          type == XE_UC_FW_TYPE_HUC ? &native.gt.uc.huc.fw : &native.gt.uc.gsc.fw;
    fw->type = type;
    return fw;
}
/* Leaves, failing a call that reached an unsupported operation. */
static int leave(int status)
{
    if (!status && native.dev.unsupported) status = -EOPNOTSUPP;
    stela_linux_exit();
    return status;
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
static bool valid_platform(uint32_t platform)
{
    return platform && platform <= INT32_MAX;
}
int stela_intel_guc_select(uint32_t platform, struct stela_intel_guc_selection *out)
{
    if (!out || !valid_platform(platform)) return -EINVAL;
    uint32_t diagnostics = 0;
    struct xe_uc_fw *fw = enter(platform, false, XE_UC_FW_TYPE_GUC, &diagnostics);
    uc_fw_auto_select(&native.dev.xe, fw);
    struct stela_intel_guc_selection result = {0};
    int status = fw->path ? copy_selection(fw, result.name, result.wanted, &result.full_version) :
                            -ENOENT;
    status = leave(status);
    if (!status) *out = result;
    return status;
}
int stela_intel_huc_select_default(uint32_t platform, uint32_t graphics_verx100,
                                 bool media_gt, struct stela_intel_huc_default *out)
{
    if (!out || !valid_platform(platform) || !graphics_verx100) return -EINVAL;
    uint32_t diagnostics = 0;
    struct xe_uc_fw *fw = enter(platform, media_gt, XE_UC_FW_TYPE_HUC, &diagnostics);
    native.dev.xe.info.graphics_verx100 = graphics_verx100;
    /* Selection requests no image: in execlist mode xe_huc_init stops after
     * selecting, as Linux does without GuC submission. */
    native.dev.xe.info.force_execlist = true;
    struct stela_intel_huc_default result = {.disposition = STELA_INTEL_HUC_ABSENT};
    int status = xe_huc_init(&native.gt.uc.huc);
    /* NOT_SUPPORTED covers both a GT without HuC and a platform without a
     * default image; execlist mode leaves a selected image DISABLED. */
    if (!status && fw->status != XE_UC_FIRMWARE_NOT_SUPPORTED) {
        if (fw->status != XE_UC_FIRMWARE_DISABLED || !fw->path) __builtin_trap();
        result.disposition = STELA_INTEL_HUC_SELECTED;
        status = copy_selection(fw, result.name, result.wanted, &result.full_version);
    }
    status = leave(status);
    if (!status) *out = result;
    return status;
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
    if (!out || !bytes || size > PTRDIFF_MAX || !valid_platform(platform)) return -EINVAL;
    struct xe_uc_fw *fw = enter(platform, false, XE_UC_FW_TYPE_GUC, diagnostics);
    uc_fw_auto_select(&native.dev.xe, fw);
    int status = fw->path ? sizes_representable(bytes, size) : -ENOENT;
    if (status == -75) *diagnostics = STELA_INTEL_GUC_UNREPRESENTABLE;
    if (!status) status = parse_headers(fw, &(const struct firmware){.size = size, .data = bytes});
    if (!status) status = xe_uc_fw_check_version_requirements(fw);
    const struct stela_intel_guc_metadata result = {
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
    status = leave(status);
    if (!status) *out = result;
    return status;
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
    struct xe_uc_fw *fw = enter(platform, media_gt, XE_UC_FW_TYPE_HUC, diagnostics);
    uc_fw_auto_select(&native.dev.xe, fw);
    status = huc_representable(bytes, size);
    if (status == -75) *diagnostics = STELA_INTEL_GUC_UNREPRESENTABLE;
    if (!status) status = parse_headers(fw, &(const struct firmware){.size = size, .data = bytes});
    if (!status) status = xe_uc_fw_check_version_requirements(fw);
    const struct stela_intel_huc_metadata result = {
        .release = {fw->versions.found[XE_UC_FW_VER_RELEASE].major,
                    fw->versions.found[XE_UC_FW_VER_RELEASE].minor,
                    fw->versions.found[XE_UC_FW_VER_RELEASE].patch},
        .ucode_bytes = fw->ucode_size, .rsa_bytes = fw->rsa_size,
        .upload_bytes = (uint32_t)sizeof(struct uc_css_header) + fw->ucode_size,
        .css_offset = fw->css_offset,
        .format = fw->has_gsc_headers ? STELA_INTEL_HUC_CPD_CSS : STELA_INTEL_HUC_CSS,
        .diagnostics = *diagnostics,
    };
    status = leave(status);
    if (!status) *out = result;
    return status;
}
