/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_FIRMWARE_H
#define STELA_INTEL_FIRMWARE_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Default GuC/HuC selection and checked CSS/CPD metadata only. No result owns a
 * GPU BO, address, firmware status, signature acceptance or hardware activity. */
struct stela_intel_guc_selection {
    uint8_t name[64];
    uint32_t wanted[3];
    uint32_t full_version;
};
struct stela_intel_guc_metadata {
    uint32_t release[3], submission[3];
    uint32_t ucode_bytes, rsa_bytes, upload_bytes, private_bytes, build_type;
    uint32_t diagnostics;
};
_Static_assert(sizeof(struct stela_intel_guc_selection) == 80, "selection ABI");
_Static_assert(offsetof(struct stela_intel_guc_selection, wanted) == 64, "selection version ABI");
_Static_assert(offsetof(struct stela_intel_guc_selection, full_version) == 76, "selection policy ABI");
_Static_assert(sizeof(struct stela_intel_guc_metadata) == 48, "metadata ABI");
_Static_assert(offsetof(struct stela_intel_guc_metadata, submission) == 12, "submission ABI");
_Static_assert(offsetof(struct stela_intel_guc_metadata, ucode_bytes) == 24, "size ABI");
_Static_assert(offsetof(struct stela_intel_guc_metadata, diagnostics) == 44, "diagnostic ABI");
/* Default-selection disposition only; these are NOT xe_uc_fw load statuses.
 * No provider lookup/failure, BO or availability state participates here. */
enum stela_intel_huc_disposition {
    STELA_INTEL_HUC_SELECTED = 1,
    STELA_INTEL_HUC_ABSENT_ROLE,
    STELA_INTEL_HUC_ABSENT_CATALOG,
};
struct stela_intel_huc_default {
    uint32_t disposition;
    uint8_t name[64];
    uint32_t wanted[3], full_version;
};
_Static_assert(sizeof(struct stela_intel_huc_default) == 84, "HuC selection ABI");
_Static_assert(offsetof(struct stela_intel_huc_default, wanted) == 68, "HuC version ABI");
/* Exact actual GT role + complete original default selector. No override mode.
 * A selected path remains a genuine prerequisite even when Provider fails.
 * Missing path is the original non-GuC NOT_SUPPORTED case, never AVAILABLE.
 * Actual native facts supply these scalars; result alone is no GPU capability.
 * Invalid input/error leaves the result unchanged. */
int stela_intel_huc_select_default(uint32_t platform, uint32_t graphics_verx100,
                                 bool media_gt, struct stela_intel_huc_default *);
enum stela_intel_guc_diagnostic {
    STELA_INTEL_GUC_TOO_OLD = 1u << 0,
    STELA_INTEL_GUC_VERSION_MISMATCH = 1u << 1,
    STELA_INTEL_GUC_RECOMMENDED_NEWER = 1u << 2,
    STELA_INTEL_GUC_SHORT_HEADER = 1u << 3,
    STELA_INTEL_GUC_HEADER_SIZE = 1u << 4,
    STELA_INTEL_GUC_SHORT_IMAGE = 1u << 5,
};
#define STELA_INTEL_GUC_UNREPRESENTABLE UINT32_C(0x80000000)
/* Actual root-main-GT platform comes from the live native owner. Missing
 * original entries fail -ENOENT; there are no newer-platform aliases. Outputs
 * remain unchanged on error. This cold metadata path performs no allocation. */
int stela_intel_guc_select(uint32_t platform, struct stela_intel_guc_selection *);
/* Borrowed immutable CPU image, never a guest/device/IOVA pointer. Full size
 * refers to that same allocation. Result unchanged on error; diagnostics always
 * describes this attempt, including accepted older recommended minor releases.
 * Overflow preflight is deliberately stricter than unchecked u32 wrap arithmetic
 * before invoking the original parser. Missing modulus/exponent stays allowed.
 * SHA256/provenance are carried by canonical Provider, not authenticated here. */
int stela_intel_guc_parse(uint32_t platform, const uint8_t *, size_t,
                         struct stela_intel_guc_metadata *, uint32_t *diagnostics);
struct stela_intel_huc_metadata {
    uint32_t release[3];
    uint32_t ucode_bytes, rsa_bytes, upload_bytes, css_offset, format, diagnostics;
};
enum stela_intel_huc_format {
    STELA_INTEL_HUC_CSS = 1,
    STELA_INTEL_HUC_CPD_CSS,
};
#define STELA_INTEL_HUC_CPD_HEADER_LENGTH (UINT32_C(1) << 8)
#define STELA_INTEL_HUC_CPD_SHORT_IMAGE (UINT32_C(1) << 9)
#define STELA_INTEL_HUC_CPD_MISSING_MANIFEST (UINT32_C(1) << 10)
_Static_assert(sizeof(struct stela_intel_huc_metadata) == 36, "HuC metadata ABI");
_Static_assert(offsetof(struct stela_intel_huc_metadata, css_offset) == 24, "HuC CSS subview ABI");
_Static_assert(offsetof(struct stela_intel_huc_metadata, diagnostics) == 32, "HuC diagnostics ABI");
/* Actual immutable provider CPU bytes, not BO-backed availability. Selects the
 * actual default/role; absence returns -95. CPD malformed errors never become
 * CSS fallback. Output unchanged on all errors; diagnostics describes attempt.
 * Metadata is not signature/authentication/CRC acceptance or WOPCM readiness. */
int stela_intel_huc_parse(uint32_t platform, uint32_t graphics_verx100, bool media_gt,
                         const uint8_t *, size_t, struct stela_intel_huc_metadata *,
                         uint32_t *diagnostics);
#endif
