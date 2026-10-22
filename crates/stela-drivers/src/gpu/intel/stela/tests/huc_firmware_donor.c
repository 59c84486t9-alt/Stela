/* SPDX-License-Identifier: MIT */
/* Frozen original CPD policy object, scalar diagnostics/platform adapters only.
 * No fake Linux GSC/GT/BO object or status/transport implementation. */
#include "../../xe/xe_scalar_types.h"
#include "../../xe/xe_platform_types.h"
#include "../../xe/xe_uc_fw_types.h"
#include "../../xe/abi/uc_fw_abi.h"
#include "../firmware.h"
#include "firmware_donor.h"
#include <assert.h>
#include <string.h>
#define EINVAL 22
#define ENOENT 2
#define ENODATA 61
static _Thread_local unsigned active_platform;
static _Thread_local uint32_t *active_diagnostics;
static _Thread_local uint32_t *active_security;
#define xe_assert(xe, condition) assert(condition)
static void report(const char *format)
{
    if (strstr(format, "invalid CPD")) *active_diagnostics |= STELA_INTEL_HUC_CPD_HEADER_LENGTH;
    else if (strstr(format, "Failed to find")) *active_diagnostics |= STELA_INTEL_HUC_CPD_MISSING_MANIFEST;
    else { assert(strstr(format, "FW too small")); *active_diagnostics |= STELA_INTEL_HUC_CPD_SHORT_IMAGE; }
}
#define xe_gt_err(gt, format, ...) report(format)
static int parse_css_header(struct xe_uc_fw *fw, const void *data, size_t size)
{
    return stela_intel_fw_donor_css(fw, data, size, active_diagnostics);
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wpointer-sign"
#include "donor-fw-cpd.inc"
#pragma clang diagnostic pop
int stela_intel_fw_donor_cpd(struct xe_uc_fw *fw, unsigned platform, const void *data,
                            size_t size, const char *manifest, const char *css,
                            uint32_t *security, uint32_t *diagnostics)
{
    *diagnostics = 0; active_platform = platform;
    active_diagnostics = diagnostics; active_security = security;
    int status = parse_cpd_header(fw, data, size, manifest, css);
    active_diagnostics = NULL; active_security = NULL;
    return status;
}
int stela_intel_fw_donor_huc(struct xe_uc_fw *fw, unsigned platform,
                            const void *data, size_t size, uint32_t *diagnostics)
{
    int status = stela_intel_fw_donor_cpd(fw, platform, data, size, "HUCP.man", "huc_fw", NULL, diagnostics);
    if (status == -ENOENT) status = stela_intel_fw_donor_css(fw, data, size, diagnostics);
    if (!status) {
        uint32_t version_diagnostics = 0;
        status = stela_intel_fw_donor_version(fw, &version_diagnostics);
        *diagnostics |= version_diagnostics;
    }
    return status;
}
