/* SPDX-License-Identifier: MIT */
/* Offline parser/selector qualification; these bytes are not signed firmware. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../firmware.c"

/* Upstream selection through the production adapter's GT. */
static struct xe_uc_fw *selected(struct native_fw *native, unsigned platform, unsigned gt,
                                 unsigned type, uint32_t *diagnostics)
{
    struct xe_uc_fw *fw = prepare(native, platform, gt == XE_GT_TYPE_MEDIA,
                                  (enum xe_uc_fw_type)type, diagnostics);
    uc_fw_auto_select(&native->xe, fw);
    return fw;
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
    unsigned guc_entries = 0, huc_defaults = 0, parsers = 0, versions = 0;
    /* Every main-GT GuC that upstream selects is what the native query reports. */
    for (unsigned platform = 0; platform <= XE_NOVALAKE_P; ++platform) {
        struct native_fw native = {0};
        uint32_t diagnostics = 0;
        const struct xe_uc_fw *fw = selected(&native, platform, XE_GT_TYPE_MAIN, XE_UC_FW_TYPE_GUC, &diagnostics);
        struct stela_intel_guc_selection output, before; memset(&before, 0xa5, sizeof(before)); output = before;
        int status = stela_intel_guc_select(platform, &output);
        if (!fw->path) {
            assert(status == (platform ? -ENOENT : -EINVAL) && !memcmp(&output, &before, sizeof(output)));
            continue;
        }
        assert(status == 0 && !strcmp((const char *)output.name, fw->path) &&
               output.wanted[0] == fw->versions.wanted.major &&
               output.wanted[1] == fw->versions.wanted.minor &&
               output.wanted[2] == fw->versions.wanted.patch);
        ++guc_entries;
    }
    assert(guc_entries == 11);
    /* HuC lives on the media GT, or on the main GT up to graphics 12.55. */
    const unsigned gfx[] = {1200, 1255, 1256, 3500};
    for (unsigned platform = 1; platform <= XE_NOVALAKE_P; ++platform)
        for (unsigned gt = XE_GT_TYPE_MAIN; gt <= XE_GT_TYPE_MEDIA; ++gt) {
            struct native_fw native = {0};
            uint32_t diagnostics = 0;
            const struct xe_uc_fw *fw = selected(&native, platform, gt, XE_UC_FW_TYPE_HUC, &diagnostics);
            for (unsigned i = 0; i < ARRAY_SIZE(gfx); ++i) {
                struct stela_intel_huc_default out;
                assert(!stela_intel_huc_select_default(platform, gfx[i], gt == XE_GT_TYPE_MEDIA, &out));
                bool huc_gt = gt == XE_GT_TYPE_MEDIA || gfx[i] <= 1255;
                if (huc_gt && fw->path) {
                    assert(out.disposition == STELA_INTEL_HUC_SELECTED);
                    assert(!strcmp((const char *)out.name, fw->path));
                    assert(out.wanted[0] == fw->versions.wanted.major &&
                           out.wanted[1] == fw->versions.wanted.minor &&
                           out.wanted[2] == fw->versions.wanted.patch &&
                           out.full_version == fw->full_ver_required);
                } else {
                    struct stela_intel_huc_default absent = {.disposition = STELA_INTEL_HUC_ABSENT};
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
    /* A 128-byte CSS header, 16 bytes of ucode and a 256-byte RSA key, from an
     * unaligned CPU view: shorter images report which part is missing. */
    uint8_t storage[401] = {0}, *bytes = storage + 1;
    struct uc_css_header css = header(MAKE_GUC_VER(70, 44, 1));
    memcpy(bytes, &css, sizeof(css));
    for (size_t size = 0; size <= 400; ++size) {
        struct stela_intel_guc_metadata out, before; memset(&before, 0xa5, sizeof(before)); out = before;
        uint32_t diagnostics = 0;
        int status = stela_intel_guc_parse(XE_TIGERLAKE, bytes, size, &out, &diagnostics);
        if (size < sizeof(css))
            assert(status == -ENODATA && diagnostics == STELA_INTEL_GUC_SHORT_HEADER);
        else if (size < 400)
            assert(status == -ENOEXEC && diagnostics == STELA_INTEL_GUC_SHORT_IMAGE);
        else
            assert(!status && !diagnostics && out.ucode_bytes == 16 && out.rsa_bytes == 256 &&
                   out.upload_bytes == 144 && out.submission[0] == 1 && out.submission[1] == 26 &&
                   out.submission[2] == 2 && out.private_bytes == 4096 && out.build_type == 1);
        if (status) assert(!memcmp(&out, &before, sizeof(out)));
        ++parsers;
    }
    /* Tiger Lake wants GuC 70.x at or above its catalog version, and every
     * GuC must be at least 70.29.2. */
    struct stela_intel_guc_selection tgl;
    assert(!stela_intel_guc_select(XE_TIGERLAKE, &tgl) && tgl.wanted[0] == 70);
    const struct { uint32_t release; int status; uint32_t diagnostics; } releases[] = {
        {MAKE_GUC_VER(69, 255, 255), -EINVAL, STELA_INTEL_GUC_TOO_OLD},
        {MAKE_GUC_VER(71, 0, 0), -ENOEXEC, STELA_INTEL_GUC_VERSION_MISMATCH},
        {MAKE_GUC_VER(70, tgl.wanted[1], tgl.wanted[2]), 0, 0},
        {MAKE_GUC_VER(70, 255, 255), 0, 0},
    };
    for (size_t i = 0; i < ARRAY_SIZE(releases); ++i) {
        css = header(releases[i].release); memcpy(bytes, &css, sizeof(css));
        struct stela_intel_guc_metadata out, before; memset(&before, 0xa5, sizeof(before)); out = before;
        uint32_t diagnostics = 0;
        int status = stela_intel_guc_parse(XE_TIGERLAKE, bytes, 400, &out, &diagnostics);
        assert(status == releases[i].status && diagnostics == releases[i].diagnostics);
        if (status) assert(!memcmp(&out, &before, sizeof(out)));
        else assert(out.release[0] == releases[i].release >> 16);
        ++versions;
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
    printf("Intel GuC metadata: %u GuC selections, %u HuC role/catalog cases, %u parser cases, %u version cases, 6 overflow refusals; no firmware authentication/upload\n", guc_entries, huc_defaults, parsers, versions);
    return 0;
}
