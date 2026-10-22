/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_FIRMWARE_DONOR_H
#define STELA_INTEL_FIRMWARE_DONOR_H
struct xe_uc_fw;
void stela_intel_fw_donor_select(unsigned platform, unsigned gt_type, unsigned type,
                                 struct xe_uc_fw *);
int stela_intel_fw_donor_parse(struct xe_uc_fw *, const void *, size_t, uint32_t *);
int stela_intel_fw_donor_version(struct xe_uc_fw *, uint32_t *);
int stela_intel_fw_donor_default_status(struct xe_uc_fw *);
int stela_intel_fw_donor_css(struct xe_uc_fw *, const void *, size_t, uint32_t *);
int stela_intel_fw_donor_cpd(struct xe_uc_fw *, unsigned platform, const void *, size_t,
                            const char *manifest, const char *css, uint32_t *security,
                            uint32_t *diagnostics);
int stela_intel_fw_donor_huc(struct xe_uc_fw *, unsigned platform, const void *, size_t,
                            uint32_t *diagnostics);
#endif
