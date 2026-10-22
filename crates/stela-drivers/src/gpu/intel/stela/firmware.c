/* SPDX-License-Identifier: MIT */
/* Original Xe notices and policies remain in the shared headers. */
#include "firmware.h"
#include <linux/types.h>
#include "xe_platform_types.h"
#include "xe_gt_type.h"
#include "xe_huc_role.h"
#include "xe_uc_fw_types.h"
#include "abi/uc_fw_abi.h"
_Static_assert(sizeof(struct gsc_cpd_header_v2) == 20, "original CPD header ABI");
_Static_assert(sizeof(struct gsc_cpd_entry) == 24, "original CPD entry ABI");
_Static_assert(sizeof(struct gsc_manifest_header) == 128, "original manifest ABI");
_Static_assert(_Alignof(struct gsc_cpd_header_v2) == 1, "packed CPD marker access");
_Static_assert(_Alignof(struct gsc_cpd_entry) == 1, "packed CPD entry access");
_Static_assert(_Alignof(struct gsc_manifest_header) == 1, "packed manifest access");
#include "xe_uc_fw_version.h"
#include <linux/array_size.h>
#include <linux/stringify.h>
#include <linux/bitfield.h>
#include <linux/errno.h>
/* Preserve original signed iteration / u32 metadata arithmetic unchanged.
 * Native entry points validate indices and byte-size representability first. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "xe_uc_fw_catalog.h"
#include "xe_uc_fw_css.h"
#pragma clang diagnostic pop

static int select_default(uint32_t platform, struct xe_uc_fw *fw)
{
    if (!platform || platform > INT32_MAX) return -EINVAL;
    fw->type = XE_UC_FW_TYPE_GUC;
    xe_uc_fw_select_default((enum xe_platform)platform, XE_GT_TYPE_MAIN, fw);
    return fw->path ? 0 : -ENOENT;
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
int stela_intel_guc_select(uint32_t platform, struct stela_intel_guc_selection *out)
{
    if (!out) return -EINVAL;
    struct xe_uc_fw fw = {0};
    int status = select_default(platform, &fw);
    if (status) return status;
    struct stela_intel_guc_selection result = {0};
    status = copy_selection(&fw, result.name, result.wanted, &result.full_version);
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
        struct xe_uc_fw fw = {.type = XE_UC_FW_TYPE_HUC};
        xe_uc_fw_select_default((enum xe_platform)platform,
            media_gt ? XE_GT_TYPE_MEDIA : XE_GT_TYPE_MAIN, &fw);
        /* Original uc_fw_request: missing default path is NOT_SUPPORTED;
         * only missing GuC is mandatory -ENOENT. No status is fabricated here. */
        if (!fw.path) result.disposition = STELA_INTEL_HUC_ABSENT_CATALOG;
        else {
            result.disposition = STELA_INTEL_HUC_SELECTED;
            int status = copy_selection(&fw, result.name, result.wanted, &result.full_version);
            if (status) return status;
        }
    }
    *out = result;
    return 0;
}
static void diagnostic(void *context, enum xe_uc_fw_css_diagnostic reason,
                       const struct xe_uc_fw *fw, size_t actual, size_t needed)
{
    (void)fw; (void)actual; (void)needed;
    if ((unsigned)reason >= 32) __builtin_trap();
    *(uint32_t *)context |= UINT32_C(1) << (unsigned)reason;
}
static void invariant(void *context, bool condition)
{
    (void)context;
    if (!condition) __builtin_trap();
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
    struct xe_uc_fw fw = {0};
    int status = select_default(platform, &fw);
    if (status) return status;
    status = sizes_representable(bytes, size);
    if (status) { *diagnostics = STELA_INTEL_GUC_UNREPRESENTABLE; return status; }
    const struct xe_uc_fw_css_ops ops = {diagnostics, diagnostic, invariant};
    status = xe_uc_fw_css_parse(&fw, bytes, size, &ops);
    if (status) return status;
    status = xe_uc_fw_css_check_version(&fw, &ops);
    if (status) return status;
    struct stela_intel_guc_metadata result = {
        .release = {fw.versions.found[XE_UC_FW_VER_RELEASE].major,
                    fw.versions.found[XE_UC_FW_VER_RELEASE].minor,
                    fw.versions.found[XE_UC_FW_VER_RELEASE].patch},
        .submission = {fw.versions.found[XE_UC_FW_VER_COMPATIBILITY].major,
                       fw.versions.found[XE_UC_FW_VER_COMPATIBILITY].minor,
                       fw.versions.found[XE_UC_FW_VER_COMPATIBILITY].patch},
        .ucode_bytes = fw.ucode_size, .rsa_bytes = fw.rsa_size,
        .upload_bytes = (uint32_t)sizeof(struct uc_css_header) + fw.ucode_size,
        .private_bytes = fw.private_data_size, .build_type = fw.build_type,
        .diagnostics = *diagnostics,
    };
    *out = result;
    return 0;
}

/* The shared core calls equality only with these original literal names and
 * includes their terminator. Native memcmp is bounded within the real 12-byte
 * entry name, including malformed entries with no NUL. No string reimplementation. */
static bool cpd_entry_equal(const void *entry, const char *name, size_t bytes)
{
    invariant(NULL, bytes > 0 && bytes <= sizeof(((struct gsc_cpd_entry *)0)->name));
    return !__builtin_memcmp(entry, name, bytes);
}
#define XE_UC_FW_CPD_ENTRY_EQUAL(entry, name, bytes) cpd_entry_equal(entry, name, bytes)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#include "xe_uc_fw_cpd.h"
#pragma clang diagnostic pop

static void cpd_diagnostic(void *context, enum xe_uc_fw_cpd_diagnostic reason,
                           const struct xe_uc_fw *fw, size_t actual, size_t needed)
{
    (void)fw; (void)actual; (void)needed;
    invariant(NULL, (unsigned)reason < 3);
    *(uint32_t *)context |= UINT32_C(1) << (8 + (unsigned)reason);
}
static int huc_css(void *context, struct xe_uc_fw *fw, const void *bytes, size_t size)
{
    invariant(NULL, fw->type == XE_UC_FW_TYPE_HUC);
    int status = sizes_representable(bytes, size);
    if (status) { *(uint32_t *)context |= STELA_INTEL_GUC_UNREPRESENTABLE; return status; }
    const struct xe_uc_fw_css_ops ops = {context, diagnostic, invariant};
    return xe_uc_fw_css_parse(fw, bytes, size, &ops);
}
/* The core's int loop index must not overflow on a representable complete
 * entry table. Preserve the original short-table diagnostic/error otherwise.
 * Header, entry and manifest types are genuinely packed; no aligned-u32 read.
 * sizeof(full header) >= sizeof(marker) before is_cpd_header is evaluated. */
static int cpd_representable(const uint8_t *bytes, size_t size)
{
    if (size < sizeof(struct gsc_cpd_header_v2) || !is_cpd_header(bytes)) return 0;
    const struct gsc_cpd_header_v2 *header = (const void *)bytes;
    if (header->header_length < sizeof(*header)) return 0;
    uint64_t table = (uint64_t)header->header_length +
                     (uint64_t)header->num_of_entries * sizeof(struct gsc_cpd_entry);
    if (table > size) return 0;
    return header->num_of_entries > INT32_MAX ? -75 : 0;
}
int stela_intel_huc_parse(uint32_t platform, uint32_t graphics_verx100, bool media_gt,
                         const uint8_t *bytes, size_t size, struct stela_intel_huc_metadata *out,
                         uint32_t *diagnostics)
{
    if (!diagnostics) return -EINVAL;
    *diagnostics = 0;
    if (!bytes || !out || size > PTRDIFF_MAX) return -EINVAL;
    struct stela_intel_huc_default selected;
    int status = stela_intel_huc_select_default(platform, graphics_verx100, media_gt, &selected);
    if (status) return status;
    if (selected.disposition != STELA_INTEL_HUC_SELECTED) return -95;
    /* Original HuC CPD/DMA parser explicitly does not support DG2's CSS-less
     * GSC loading path. No selection alias or invented CSS is permitted. */
    if (platform == XE_DG2) return -95;
    struct xe_uc_fw fw = {.type = XE_UC_FW_TYPE_HUC};
    xe_uc_fw_select_default((enum xe_platform)platform,
                           media_gt ? XE_GT_TYPE_MEDIA : XE_GT_TYPE_MAIN, &fw);
    status = cpd_representable(bytes, size);
    if (status) { *diagnostics = STELA_INTEL_GUC_UNREPRESENTABLE; return status; }
    const struct xe_uc_fw_cpd_ops ops = {diagnostics, cpd_diagnostic, invariant, huc_css, NULL};
    status = xe_uc_fw_huc_parse(&fw, bytes, size, (enum xe_platform)platform, &ops);
    if (status) return status;
    const struct xe_uc_fw_css_ops css_ops = {diagnostics, diagnostic, invariant};
    status = xe_uc_fw_css_check_version(&fw, &css_ops);
    if (status) return status;
    struct stela_intel_huc_metadata result = {
        .release = {fw.versions.found[XE_UC_FW_VER_RELEASE].major,
                    fw.versions.found[XE_UC_FW_VER_RELEASE].minor,
                    fw.versions.found[XE_UC_FW_VER_RELEASE].patch},
        .ucode_bytes = fw.ucode_size, .rsa_bytes = fw.rsa_size,
        .upload_bytes = (uint32_t)sizeof(struct uc_css_header) + fw.ucode_size,
        .css_offset = fw.css_offset,
        .format = fw.has_gsc_headers ? STELA_INTEL_HUC_CPD_CSS : STELA_INTEL_HUC_CSS,
        .diagnostics = *diagnostics,
    };
    *out = result;
    return 0;
}
