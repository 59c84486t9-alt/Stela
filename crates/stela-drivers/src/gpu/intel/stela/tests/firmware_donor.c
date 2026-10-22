/* SPDX-License-Identifier: MIT */
/* Separately compiled frozen source policies; no Linux device/GT/BO objects or
 * services are fabricated. Only scalar spellings and diagnostics are bound. */
#include "../../xe/xe_scalar_types.h"
#include "../../xe/xe_platform_types.h"
#include "../../xe/xe_gt_type.h"
#include "../../xe/xe_uc_fw_types.h"
#include "../../xe/abi/uc_fw_abi.h"
#include "../../xe/xe_uc_fw_version.h"
#include "../firmware.h"
#include "firmware_donor.h"
#include <assert.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __stringify_1(x) #x
#define __stringify(x) __stringify_1(x)
#define FIELD_GET(mask, value) REG_FIELD_GET(mask, value)
#define unlikely(value) __builtin_expect(!!(value), 0)
#define EINVAL 22
#define ENOENT 2
#define ENOEXEC 8
#define ENODATA 61
#define EPROTO 71
#define xe_gt_assert(gt, condition) assert(condition)
#define xe_uc_fw_is_overridden(fw) ((fw)->user_overridden)
static _Thread_local uint32_t *active_diagnostics;
static void donor_warn(const char *format, size_t actual, size_t needed)
{
    if (strstr(format, "unexpected header size")) *active_diagnostics |= STELA_INTEL_GUC_HEADER_SIZE;
    else {
        assert(strstr(format, "invalid size"));
        *active_diagnostics |= actual < 128 && needed == 128 ? STELA_INTEL_GUC_SHORT_HEADER : STELA_INTEL_GUC_SHORT_IMAGE;
    }
}
static void donor_notice(const char *format)
{
    if (strstr(format, "unexpected version")) *active_diagnostics |= STELA_INTEL_GUC_VERSION_MISMATCH;
    else { assert(strstr(format, "recommended")); *active_diagnostics |= STELA_INTEL_GUC_RECOMMENDED_NEWER; }
}
static void donor_info(const char *format)
{
    assert(strstr(format, "linux-firmware"));
    *active_diagnostics |= STELA_INTEL_GUC_RECOMMENDED_NEWER;
}
#define drm_warn(device, format, type, path, actual, needed) donor_warn(format, actual, needed)
#define drm_notice(device, format, ...) donor_notice(format)
#define drm_info(device, format, ...) donor_info(format)
#define xe_gt_err(gt, format, ...) ((void)(format), *active_diagnostics |= STELA_INTEL_GUC_TOO_OLD)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "donor-fw-defs.inc"
void stela_intel_fw_donor_select(unsigned platform, unsigned gt, unsigned type, struct xe_uc_fw *uc_fw)
{
    enum xe_platform p = (enum xe_platform)platform;
    enum xe_gt_type gt_type = (enum xe_gt_type)gt;
    uc_fw->type = (enum xe_uc_fw_type)type;
#include "donor-fw-select.inc"
}
#define guc_read_css_info donor_guc_read_css_info
#define xe_uc_fw_check_version_requirements donor_check_version
#define parse_css_header donor_parse_css_header
#include "donor-fw-css.inc"
#pragma clang diagnostic pop
int stela_intel_fw_donor_parse(struct xe_uc_fw *fw, const void *bytes, size_t size, uint32_t *diagnostics)
{
    *diagnostics = 0; active_diagnostics = diagnostics;
    int result = donor_parse_css_header(fw, bytes, size);
    if (!result) result = donor_check_version(fw);
    active_diagnostics = NULL;
    return result;
}
int stela_intel_fw_donor_css(struct xe_uc_fw *fw, const void *bytes, size_t size, uint32_t *diagnostics)
{
    *diagnostics = 0; active_diagnostics = diagnostics;
    int result = donor_parse_css_header(fw, bytes, size);
    active_diagnostics = NULL;
    return result;
}

int stela_intel_fw_donor_version(struct xe_uc_fw *fw, uint32_t *diagnostics)
{
    *diagnostics = 0; active_diagnostics = diagnostics;
    int result = donor_check_version(fw);
    active_diagnostics = NULL;
    return result;
}

/* Original default-path status policy, test object only. This does not make
 * a native BO/firmware AVAILABLE and is not the Linux request/load lifecycle. */
#define XE_WARN_ON(condition) assert(!(condition))
#include "donor-fw-supported.inc"
#define xe_uc_fw_change_status(uc_fw, value) ((uc_fw)->__status = (value))
#undef xe_gt_err
#define xe_gt_err(gt, format, ...) ((void)(format))
int stela_intel_fw_donor_default_status(struct xe_uc_fw *uc_fw)
{
#include "donor-fw-default-status.inc"
    return 0; /* Stage boundary: selected path, not firmware request success. */
}
