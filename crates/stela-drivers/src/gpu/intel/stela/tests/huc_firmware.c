/* SPDX-License-Identifier: MIT */
/* The native HuC parser against upstream xe_uc_fw.c run directly on the same
 * images. Inputs are synthetic unsigned data. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../firmware.c"

#define CSS_OFFSET 384u
#define MANIFEST_OFFSET 160u
#define IMAGE_BYTES (CSS_OFFSET + 400u)
static unsigned cases, checked_arithmetic;
static void css(uint8_t *bytes, uint32_t release)
{
    const struct uc_css_header header = {
        .header_size_dw = 32 + 64 + 64 + 1, .size_dw = 32 + 64 + 64 + 1 + 4,
        .rsa_info = {64, 64, 1}, .guc_info.sw_version = release,
    };
    memset(bytes, 0, 400); memcpy(bytes, &header, sizeof(header));
}
static void cpd(uint8_t bytes[IMAGE_BYTES])
{
    memset(bytes, 0, IMAGE_BYTES);
    struct gsc_cpd_header_v2 *h = (void *)bytes;
    h->header_marker = GSC_CPD_HEADER_MARKER;
    h->header_length = sizeof(*h); h->num_of_entries = 2;
    struct gsc_cpd_entry *entry = (void *)(bytes + h->header_length);
    memcpy(entry[0].name, "HUCP.man", sizeof("HUCP.man")); entry[0].offset = MANIFEST_OFFSET;
    memcpy(entry[1].name, "huc_fw", sizeof("huc_fw")); entry[1].offset = CSS_OFFSET;
    struct gsc_manifest_header *manifest = (void *)(bytes + MANIFEST_OFFSET);
    manifest->fw_version.major = 9; manifest->fw_version.minor = 8;
    manifest->fw_version.hotfix = 7; manifest->fw_version.build = 6;
    manifest->security_version = 42;
    css(bytes + CSS_OFFSET, MAKE_GUC_VER(1, 2, 3));
}
static void compare(unsigned platform, bool media_gt, const uint8_t *bytes, size_t size)
{
    assert(size <= IMAGE_BYTES);
    struct native_fw native = {0};
    uint32_t expected_diagnostics = 0, diagnostics;
    struct xe_uc_fw *upstream = prepare(&native, platform, media_gt, XE_UC_FW_TYPE_HUC,
                                        &expected_diagnostics);
    uc_fw_auto_select(&native.xe, upstream);
    assert(upstream->path);
    int expected = parse_headers(upstream, &(const struct firmware){.size = size, .data = bytes});
    if (!expected) expected = xe_uc_fw_check_version_requirements(upstream);
    const struct xe_uc_fw fw = *upstream;
    struct stela_intel_huc_metadata output, before;
    memset(&before, 0xa5, sizeof(before)); output = before;
    int status = stela_intel_huc_parse(platform, 1200, media_gt, bytes, size, &output, &diagnostics);
    if (status == -75 && expected == -EPROTO && expected_diagnostics == STELA_INTEL_GUC_HEADER_SIZE) {
        /* Deliberate wide-arithmetic preflight before original unsigned CSS
         * subtraction: rejected invalid directory-as-CSS, never success. */
        assert(diagnostics == STELA_INTEL_GUC_UNREPRESENTABLE && !memcmp(&output, &before, sizeof(output)));
        ++checked_arithmetic;
        return;
    }
    if (status != expected || diagnostics != expected_diagnostics)
        fprintf(stderr, "HuC case%u platform%u size%zu native%d/%x upstream%d/%x\n", cases, platform, size, status, diagnostics, expected, expected_diagnostics);
    assert(status == expected && diagnostics == expected_diagnostics);
    if (status) assert(!memcmp(&before, &output, sizeof(output)));
    else {
        assert(output.release[0] == fw.versions.found[XE_UC_FW_VER_RELEASE].major &&
               output.release[1] == fw.versions.found[XE_UC_FW_VER_RELEASE].minor &&
               output.release[2] == fw.versions.found[XE_UC_FW_VER_RELEASE].patch);
        assert(output.ucode_bytes == fw.ucode_size && output.rsa_bytes == fw.rsa_size &&
               output.upload_bytes == sizeof(struct uc_css_header) + fw.ucode_size &&
               output.css_offset == fw.css_offset &&
               output.format == (fw.has_gsc_headers ? STELA_INTEL_HUC_CPD_CSS : STELA_INTEL_HUC_CSS));
    }
    assert(!fw.bo && fw.status == XE_UC_FIRMWARE_UNINITIALIZED);
    ++cases;
}
int main(void)
{
    /* Upstream's is_cpd_header reads the marker as a u32, as Linux's page
     * aligned firmware buffers allow; Stela requires that alignment. */
    _Alignas(uint32_t) uint8_t bytes[IMAGE_BYTES + 1];
    _Static_assert(sizeof("HUCP.man") <= sizeof(((struct gsc_cpd_entry *)0)->name), "HuC literal");
    _Static_assert(sizeof("huc_fw") <= sizeof(((struct gsc_cpd_entry *)0)->name), "CSS literal");
    _Static_assert(sizeof("RBEP.man") <= sizeof(((struct gsc_cpd_entry *)0)->name), "GSC literal");
    for (unsigned platform = 1; platform <= XE_NOVALAKE_P; ++platform) {
        struct native_fw native = {0};
        uint32_t diagnostics = 0;
        struct xe_uc_fw *fw = prepare(&native, platform, false, XE_UC_FW_TYPE_HUC, &diagnostics);
        uc_fw_auto_select(&native.xe, fw);
        if (!fw->path) continue;
        css(bytes, MAKE_GUC_VER(1, 2, 3));
        compare(platform, false, bytes, 400); /* No GuC minimum version leakage. */
        cpd(bytes); compare(platform, true, bytes, IMAGE_BYTES);
    }
    cpd(bytes);
    for (size_t size = 0; size <= IMAGE_BYTES; ++size) compare(XE_TIGERLAKE, false, bytes, size);
    css(bytes, MAKE_GUC_VER(1, 2, 3));
    for (size_t size = 0; size <= 400; ++size) compare(XE_TIGERLAKE, false, bytes, size);
    for (unsigned change = 0; change < 20; ++change) {
        cpd(bytes);
        struct gsc_cpd_header_v2 *h = (void *)bytes;
        struct gsc_cpd_entry *entry = (void *)(bytes + sizeof(*h));
        switch (change) {
        case 0: h->header_marker ^= 1; break;
        case 1: h->header_length = sizeof(*h) - 1; break;
        case 2: h->num_of_entries = UINT32_MAX; break;
        case 3: h->header_length = UINT8_MAX; break;
        case 4: h->num_of_entries = 0; break;
        case 5: memset(entry[0].name, 0xff, sizeof(entry[0].name)); break;
        case 6: entry[0].name[sizeof("HUCP.man") - 1] = 'x'; break;
        case 7: entry[0].name[1] = 0; break;
        case 8: entry[0].offset = 0; break;
        case 9: entry[0].offset = GSC_CPD_ENTRY_OFFSET_MASK; break;
        case 10: entry[0].offset |= GSC_CPD_ENTRY_HUFFMAN_COMP; break; /* Original mask, not decompression. */
        case 11: entry[1].offset = IMAGE_BYTES + 1; break;
        case 12: entry[1].offset = IMAGE_BYTES; break;
        case 13: entry[1].offset = 0; break;
        case 14: memset(entry[1].name, 0xff, sizeof(entry[1].name)); break;
        case 15: entry[1].name[sizeof("huc_fw") - 1] = 'x'; break;
        case 16: h->num_of_entries = 3; entry[2] = entry[0]; entry[2].offset = IMAGE_BYTES; break;
        case 17: entry[0].name[11] = 0xff; entry[1].name[11] = 0xff; break; /* trailing bytes after NUL */
        case 18: memmove(bytes + CSS_OFFSET - 1, bytes + CSS_OFFSET, 400); entry[1].offset = CSS_OFFSET - 1; break;
        case 19: memmove(bytes + sizeof(*h) + 1, entry, 2 * sizeof(*entry)); ++h->header_length; break;
        }
        compare(XE_TIGERLAKE, false, bytes, IMAGE_BYTES);
    }
    /* Independent success fields: embedded CSS version wins over manifest;
     * source subview offset is retained but not counted in WOPCM transfer. */
    cpd(bytes); struct stela_intel_huc_metadata output; uint32_t d;
    assert(!stela_intel_huc_parse(XE_TIGERLAKE, 1200, false, bytes, IMAGE_BYTES, &output, &d));
    assert(output.release[0] == 1 && output.release[1] == 2 && output.release[2] == 3 &&
           output.css_offset == CSS_OFFSET && output.upload_bytes == 144 && output.rsa_bytes == 256 && !d);
    /* GSC original parser caller still sees manifest release/build/security
     * through the mandatory real adapter. No fake GSC object is constructed. */
    unsigned gsc_cases = 0;
    for (unsigned change = 0; change < 7; ++change) {
        _Alignas(uint32_t) uint8_t aligned[IMAGE_BYTES]; cpd(aligned);
        struct gsc_cpd_header_v2 *h = (void *)aligned;
        struct gsc_cpd_entry *entry = (void *)(aligned + sizeof(*h));
        memcpy(entry[0].name, "RBEP.man", sizeof("RBEP.man"));
        if (change == 1) memset(entry[0].name, 0xff, sizeof(entry[0].name));
        if (change == 2) entry[0].name[sizeof("RBEP.man") - 1] = 'x';
        if (change == 3) entry[0].name[2] = 0;
        if (change == 4) { h->num_of_entries = 3; entry[2] = entry[0]; entry[2].offset = IMAGE_BYTES; }
        if (change == 5) entry[0].name[11] = 0xff;
        if (change == 6) entry[0].offset |= GSC_CPD_ENTRY_HUFFMAN_COMP;
        struct native_fw native = {0};
        uint32_t diagnostics = 0;
        struct xe_uc_fw *a = prepare(&native, XE_METEORLAKE, false, XE_UC_FW_TYPE_GSC, &diagnostics);
        int status = parse_cpd_header(a, aligned, sizeof(aligned), "RBEP.man", NULL);
        uint32_t security = native.gt.uc.gsc.security_version;
        /* Only a missing manifest name fails; later entries, bytes after the
         * NUL and compression bits outside the offset mask do not matter. */
        bool missing = change >= 1 && change <= 3;
        assert(status == (missing ? -ENODATA : 0) &&
               diagnostics == (missing ? STELA_INTEL_HUC_CPD_MISSING_MANIFEST : 0u));
        if (!status) assert(a->versions.found[0].major == 9 && a->versions.found[0].minor == 8 &&
                             a->versions.found[0].patch == 7 && a->versions.found[0].build == 6 && security == 42);
        ++gsc_cases;
    }
    /* Invalid/absent/default role and malformed arithmetic preserve output. */
    for (unsigned bad = 0; bad < 7; ++bad) {
        cpd(bytes); struct stela_intel_huc_metadata before;
        memset(&before, 0xa5, sizeof(before)); output = before;
        if (bad >= 4) {
            struct uc_css_header *h = (void *)(bytes + CSS_OFFSET);
            if (bad == 4) h->size_dw = 0;
            if (bad == 5) h->rsa_info.key_size_dw = UINT32_MAX;
            if (bad == 6) h->size_dw = h->header_size_dw + UINT32_C(0x40000000);
        }
        int status = stela_intel_huc_parse(bad == 0 ? 0 : bad == 1 ? XE_DG2 : XE_TIGERLAKE,
            bad == 2 ? 1256 : bad == 3 ? 0 : 1200, false, bytes, IMAGE_BYTES, &output, &d);
        assert(status == (bad == 0 || bad == 3 ? -EINVAL : bad < 4 ? -95 : -75));
        assert(!memcmp(&output, &before, sizeof(output)));
    }
    /* A misaligned image is refused before any byte is read. */
    {
        struct stela_intel_huc_metadata before;
        memset(&before, 0xa5, sizeof(before)); output = before;
        assert(stela_intel_huc_parse(XE_TIGERLAKE, 1200, false, bytes + 1, 400, &output, &d) == -EINVAL &&
               !d && !memcmp(&output, &before, sizeof(output)));
    }
    printf("Intel HuC: %u CPD/CSS upstream comparisons, 1 misaligned refusal, 20 directory cases, %u original GSC build/security/name cases, %u strict wide-arithmetic refusals, 7 refusal/overflow cases; host images only, no authentication/BO/WOPCM readiness\n", cases, gsc_cases, checked_arithmetic);
    return 0;
}
