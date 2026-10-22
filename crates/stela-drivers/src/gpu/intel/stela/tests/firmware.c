/* SPDX-License-Identifier: MIT */
/* Offline parser/selector qualification; these bytes are not signed firmware. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../firmware.c"
#include "firmware_donor.h"

static void same_version(struct xe_uc_fw_version a, struct xe_uc_fw_version b)
{
    assert(a.major == b.major && a.minor == b.minor && a.patch == b.patch &&
           a.branch == b.branch && a.build == b.build);
}
static void same_fw(const struct xe_uc_fw *a, const struct xe_uc_fw *b)
{
    assert((a->path != NULL) == (b->path != NULL));
    if (a->path) assert(!strcmp(a->path, b->path));
    assert(a->type == b->type && a->full_ver_required == b->full_ver_required &&
           a->versions.wanted_type == b->versions.wanted_type);
    same_version(a->versions.wanted, b->versions.wanted);
    for (unsigned i = 0; i < XE_UC_FW_VER_TYPE_COUNT; ++i) same_version(a->versions.found[i], b->versions.found[i]);
    assert(a->ucode_size == b->ucode_size && a->rsa_size == b->rsa_size &&
           a->private_data_size == b->private_data_size && a->build_type == b->build_type);
    assert(!a->bo && !b->bo && a->status == XE_UC_FIRMWARE_UNINITIALIZED &&
           b->status == XE_UC_FIRMWARE_UNINITIALIZED);
}
static struct uc_css_header header(uint32_t release)
{
    return (struct uc_css_header){.header_size_dw = 32 + 64 + 64 + 1,
        .size_dw = 32 + 64 + 64 + 1 + 4,
        .rsa_info = {.key_size_dw = 64, .modulus_size_dw = 64, .exponent_size_dw = 1},
        .guc_info = {.sw_version = release, .submission_version = MAKE_GUC_VER(1, 26, 2),
                     .private_data_size = 4096, .ukernel_info = 1u << 2}};
}
int main(void)
{
    static_assert(sizeof(struct uc_css_header) == 128);
    static_assert(_Alignof(struct uc_css_header) == 1);
    static_assert(sizeof(struct stela_intel_guc_selection) == 80);
    static_assert(sizeof(struct stela_intel_guc_metadata) == 48);
    unsigned selectors = 0, guc_entries = 0, parsers = 0, versions = 0;
    for (unsigned platform = 0; platform <= XE_NOVALAKE_P; ++platform)
        for (unsigned gt = XE_GT_TYPE_MAIN; gt <= XE_GT_TYPE_MEDIA; ++gt)
            for (unsigned type = 0; type < XE_UC_FW_NUM_TYPES; ++type) {
                struct xe_uc_fw a = {.type = (enum xe_uc_fw_type)type}, b = {0};
                xe_uc_fw_select_default((enum xe_platform)platform, (enum xe_gt_type)gt, &a);
                stela_intel_fw_donor_select(platform, gt, type, &b);
                same_fw(&a, &b); ++selectors;
                if (type == XE_UC_FW_TYPE_GUC && gt == XE_GT_TYPE_MAIN && a.path) {
                    struct stela_intel_guc_selection output;
                    assert(stela_intel_guc_select(platform, &output) == 0);
                    assert(!strcmp((const char *)output.name, a.path) &&
                           output.wanted[0] == a.versions.wanted.major &&
                           output.wanted[1] == a.versions.wanted.minor &&
                           output.wanted[2] == a.versions.wanted.patch);
                    ++guc_entries;
                }
            }
    assert(guc_entries == 11);
    /* Default selection/status classification uses actual frozen source for
     * every original platform/type/GT. No test/source marks AVAILABLE. */
    unsigned defaults = 0, huc_defaults = 0;
    const unsigned gfx[] = {1200, 1255, 1256, 3500};
    for (unsigned platform = 1; platform <= XE_NOVALAKE_P; ++platform)
        for (unsigned gt = XE_GT_TYPE_MAIN; gt <= XE_GT_TYPE_MEDIA; ++gt)
            for (unsigned type = 0; type < XE_UC_FW_NUM_TYPES; ++type) {
                struct xe_uc_fw original = {0};
                stela_intel_fw_donor_select(platform, gt, type, &original);
                bool selected = original.path != NULL;
                int status = stela_intel_fw_donor_default_status(&original);
                assert(status == (!selected && type == XE_UC_FW_TYPE_GUC ? -2 : 0));
                assert(original.status == (selected ? XE_UC_FIRMWARE_SELECTED : XE_UC_FIRMWARE_NOT_SUPPORTED));
                assert(!original.bo); ++defaults;
                if (type != XE_UC_FW_TYPE_HUC) continue;
                for (unsigned i = 0; i < ARRAY_SIZE(gfx); ++i) {
                    struct stela_intel_huc_default out;
                    assert(!stela_intel_huc_select_default(platform, gfx[i], gt == XE_GT_TYPE_MEDIA, &out));
                    bool role = gt != XE_GT_TYPE_MEDIA && gfx[i] > 1255;
                    uint32_t disposition = role ? STELA_INTEL_HUC_ABSENT_ROLE :
                        selected ? STELA_INTEL_HUC_SELECTED : STELA_INTEL_HUC_ABSENT_CATALOG;
                    assert(out.disposition == disposition);
                    if (disposition == STELA_INTEL_HUC_SELECTED) {
                        assert(!strcmp((const char *)out.name, original.path));
                        assert(out.wanted[0] == original.versions.wanted.major &&
                               out.wanted[1] == original.versions.wanted.minor &&
                               out.wanted[2] == original.versions.wanted.patch &&
                               out.full_version == original.full_ver_required);
                    } else {
                        struct stela_intel_huc_default absent = {.disposition = disposition};
                        assert(!memcmp(&out, &absent, sizeof(out)));
                    }
                    ++huc_defaults;
                }
            }
    for (unsigned invalid = 0; invalid < 3; ++invalid) {
        struct stela_intel_huc_default out, before; memset(&before, 0xa5, sizeof(before)); out = before;
        assert(stela_intel_huc_select_default(invalid == 0 ? 0 : invalid == 1 ? UINT32_MAX : XE_DG2,
            invalid == 2 ? 0 : 1255, false, &out) == -EINVAL && !memcmp(&out, &before, sizeof(out)));
    }
    assert(stela_intel_huc_select_default(XE_DG2, 1255, false, NULL) == -EINVAL);
    /* Unaligned CPU view and genuinely absent optional modulus/exponent bytes. */
    uint8_t storage[401] = {0}, *bytes = storage + 1;
    struct uc_css_header css = header(MAKE_GUC_VER(70, 44, 1));
    memcpy(bytes, &css, sizeof(css));
    for (size_t size = 0; size <= 400; ++size) {
        struct xe_uc_fw a = {.type = XE_UC_FW_TYPE_GUC}, b = {0};
        xe_uc_fw_select_default(XE_TIGERLAKE, XE_GT_TYPE_MAIN, &a);
        stela_intel_fw_donor_select(XE_TIGERLAKE, XE_GT_TYPE_MAIN, XE_UC_FW_TYPE_GUC, &b);
        uint32_t ad = 0, bd = 0, nd = 0;
        const struct xe_uc_fw_css_ops ops = {&ad, diagnostic, invariant};
        int ar = xe_uc_fw_css_parse(&a, bytes, size, &ops);
        if (!ar) ar = xe_uc_fw_css_check_version(&a, &ops);
        int br = stela_intel_fw_donor_parse(&b, bytes, size, &bd);
        assert(ar == br && ad == bd); same_fw(&a, &b);
        struct stela_intel_guc_metadata out, before; memset(&before, 0xa5, sizeof(before)); out = before;
        assert(stela_intel_guc_parse(XE_TIGERLAKE, bytes, size, &out, &nd) == ar && nd == ad);
        if (ar) assert(!memcmp(&out, &before, sizeof(out)));
        else assert(out.ucode_bytes == 16 && out.rsa_bytes == 256 && out.upload_bytes == 144 &&
                    out.submission[0] == 1 && out.submission[1] == 26 && out.submission[2] == 2 &&
                    out.private_bytes == 4096 && out.build_type == 1);
        ++parsers;
    }
    const uint32_t releases[] = {MAKE_GUC_VER(69, 255, 255), MAKE_GUC_VER(70, 29, 1),
        MAKE_GUC_VER(70, 29, 2), MAKE_GUC_VER(70, 30, 0), MAKE_GUC_VER(70, 44, 0),
        MAKE_GUC_VER(70, 44, 1), MAKE_GUC_VER(70, 53, 0), MAKE_GUC_VER(70, 54, 0),
        MAKE_GUC_VER(70, 255, 255), MAKE_GUC_VER(71, 0, 0)};
    for (unsigned platform = XE_TIGERLAKE; platform <= XE_NOVALAKE_P; ++platform)
        for (size_t i = 0; i < ARRAY_SIZE(releases); ++i) {
            struct xe_uc_fw b = {0};
            stela_intel_fw_donor_select(platform, XE_GT_TYPE_MAIN, XE_UC_FW_TYPE_GUC, &b);
            if (!b.path) continue;
            css = header(releases[i]); memcpy(bytes, &css, sizeof(css));
            uint32_t expected = 0, actual = 0;
            int status = stela_intel_fw_donor_parse(&b, bytes, 400, &expected);
            struct stela_intel_guc_metadata out, before; memset(&before, 0xa5, sizeof(before)); out = before;
            assert(stela_intel_guc_parse(platform, bytes, 400, &out, &actual) == status && actual == expected);
            if (status) assert(!memcmp(&out, &before, sizeof(out)));
            ++parsers;
        }
    for (unsigned full = 0; full < 2; ++full)
        for (unsigned overridden = 0; overridden < 2; ++overridden)
            for (unsigned wanted_major = 0; wanted_major < 2; ++wanted_major)
                for (size_t i = 0; i < ARRAY_SIZE(releases); ++i) {
                    struct xe_uc_fw a = {.type = XE_UC_FW_TYPE_GUC,
                        .full_ver_required = full != 0, .user_overridden = overridden != 0,
                        .versions.wanted = {.major = wanted_major ? 70 : 0, .minor = 44, .patch = 1}};
                    a.versions.found[0] = (struct xe_uc_fw_version){
                        .major = (u16)(releases[i] >> 16), .minor = (u16)((releases[i] >> 8) & 255),
                        .patch = (u16)(releases[i] & 255)};
                    struct xe_uc_fw b = a; uint32_t ad = 0, bd = 0;
                    const struct xe_uc_fw_css_ops ops = {&ad, diagnostic, invariant};
                    int ar = xe_uc_fw_css_check_version(&a, &ops);
                    int br = stela_intel_fw_donor_version(&b, &bd);
                    assert(ar == br && ad == bd); same_fw(&a, &b); ++versions;
                }
    for (unsigned bad = 0; bad < 6; ++bad) {
        css = header(MAKE_GUC_VER(70, 44, 1));
        if (bad == 0) css.header_size_dw = 0;
        if (bad == 1) css.size_dw = css.header_size_dw - 1;
        if (bad == 2) { css.rsa_info.key_size_dw = UINT32_C(0x40000000); css.header_size_dw = css.rsa_info.key_size_dw + 32 + 64 + 1; css.size_dw = css.header_size_dw; }
        if (bad == 3) css.size_dw = css.header_size_dw + UINT32_C(0x40000000);
        if (bad == 4) css.rsa_info.modulus_size_dw = UINT32_MAX;
        if (bad == 5) css.size_dw = css.header_size_dw + (UINT32_MAX - 128) / 4 + 1;
        memcpy(bytes, &css, sizeof(css));
        struct stela_intel_guc_metadata out, before; memset(&before, 0xa5, sizeof(before)); out = before;
        uint32_t d = 0;
        assert(stela_intel_guc_parse(XE_TIGERLAKE, bytes, 400, &out, &d) == -75 &&
               d == STELA_INTEL_GUC_UNREPRESENTABLE && !memcmp(&out, &before, sizeof(out)));
    }
    css = header(MAKE_GUC_VER(70, 44, 1));
    ++css.header_size_dw; ++css.size_dw; memcpy(bytes, &css, sizeof(css));
    struct stela_intel_guc_metadata malformed, before;
    memset(&before, 0xa5, sizeof(before)); malformed = before; uint32_t diag = 0;
    assert(stela_intel_guc_parse(XE_TIGERLAKE, bytes, 400, &malformed, &diag) == -EPROTO &&
           diag == STELA_INTEL_GUC_HEADER_SIZE && !memcmp(&malformed, &before, sizeof(malformed)));
    struct stela_intel_guc_selection unavailable;
    assert(stela_intel_guc_select(XE_PVC, &unavailable) == -ENOENT);
    for (unsigned platform = XE_NOVALAKE_S; platform <= XE_NOVALAKE_P; ++platform) {
        struct stela_intel_guc_selection out, before; memset(&before, 0xa5, sizeof(before)); out = before;
        assert(stela_intel_guc_select(platform, &out) == -ENOENT && !memcmp(&out, &before, sizeof(out)));
    }
    printf("Intel GuC metadata: %u selector donor/core cases, %u original GuC entries, %u parser cases, %u version/override cases, 6 overflow refusals; %u frozen default-status and %u HuC role/catalog cases; no firmware authentication/upload\n", selectors, guc_entries, parsers, versions, defaults, huc_defaults);
    return 0;
}
