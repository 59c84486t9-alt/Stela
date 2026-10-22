/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */
#ifndef XE_UC_FW_CSS_H
#define XE_UC_FW_CSS_H
/* Required diagnostic/invariant adapters; the original caller retains real
 * logging and GT assertions. No device, BO, status or OS service is emulated. */
enum xe_uc_fw_css_diagnostic {
	XE_UC_FW_CSS_GUC_TOO_OLD,
	XE_UC_FW_CSS_VERSION_MISMATCH,
	XE_UC_FW_CSS_RECOMMENDED_NEWER,
	XE_UC_FW_CSS_SHORT_HEADER,
	XE_UC_FW_CSS_HEADER_SIZE,
	XE_UC_FW_CSS_SHORT_IMAGE,
};
struct xe_uc_fw_css_ops {
	void *context;
	void (*report)(void *, enum xe_uc_fw_css_diagnostic,
		       const struct xe_uc_fw *, size_t, size_t);
	void (*invariant)(void *, bool);
};
static int xe_uc_fw_css_read_guc_info(struct xe_uc_fw *uc_fw, struct uc_css_guc_info *guc_info,
		const struct xe_uc_fw_css_ops *ops)
{
	struct xe_uc_fw_version *release = &uc_fw->versions.found[XE_UC_FW_VER_RELEASE];
	struct xe_uc_fw_version *compatibility = &uc_fw->versions.found[XE_UC_FW_VER_COMPATIBILITY];

	ops->invariant(ops->context, uc_fw->type == XE_UC_FW_TYPE_GUC);

	/* We don't support GuC releases older than 70.29.2 */
	if (MAKE_GUC_VER_STRUCT(*release) < MAKE_GUC_VER(70, 29, 2)) {
		ops->report(ops->context, XE_UC_FW_CSS_GUC_TOO_OLD, uc_fw, 0, 0);
		return -EINVAL;
	}

	compatibility->major = FIELD_GET(CSS_SW_VERSION_UC_MAJOR, guc_info->submission_version);
	compatibility->minor = FIELD_GET(CSS_SW_VERSION_UC_MINOR, guc_info->submission_version);
	compatibility->patch = FIELD_GET(CSS_SW_VERSION_UC_PATCH, guc_info->submission_version);

	uc_fw->build_type = FIELD_GET(CSS_UKERNEL_INFO_BUILDTYPE, guc_info->ukernel_info);
	uc_fw->private_data_size = guc_info->private_data_size;

	return 0;
}

static int xe_uc_fw_css_check_version(struct xe_uc_fw *uc_fw,
		const struct xe_uc_fw_css_ops *ops)
{
	struct xe_uc_fw_version *wanted = &uc_fw->versions.wanted;
	struct xe_uc_fw_version *found = &uc_fw->versions.found[uc_fw->versions.wanted_type];

	/* Driver has no requirement on any version, any is good. */
	if (!wanted->major)
		return 0;

	/*
	 * If full version is required, both major and minor should match.
	 * Otherwise, at least the major version.
	 */
	if (wanted->major != found->major ||
	    (uc_fw->full_ver_required &&
	     ((wanted->minor != found->minor) ||
	      (wanted->patch != found->patch)))) {
		ops->report(ops->context, XE_UC_FW_CSS_VERSION_MISMATCH, uc_fw, 0, 0);
		goto fail;
	}

	if (wanted->minor > found->minor ||
	    (wanted->minor == found->minor && wanted->patch > found->patch)) {
		ops->report(ops->context, XE_UC_FW_CSS_RECOMMENDED_NEWER, uc_fw, 0, 0);
	}

	return 0;

fail:
	if (uc_fw->user_overridden)
		return 0;

	return -ENOEXEC;
}

static int xe_uc_fw_css_parse(struct xe_uc_fw *uc_fw, const void *fw_data, size_t fw_size,
		const struct xe_uc_fw_css_ops *ops)
{
	struct xe_uc_fw_version *release = &uc_fw->versions.found[XE_UC_FW_VER_RELEASE];
	struct uc_css_header *css;
	size_t size;

	/* Check the size of the blob before examining buffer contents */
	if (unlikely(fw_size < sizeof(struct uc_css_header))) {
		ops->report(ops->context, XE_UC_FW_CSS_SHORT_HEADER, uc_fw,
			    fw_size, sizeof(struct uc_css_header));
		return -ENODATA;
	}

	css = (struct uc_css_header *)fw_data;

	/* Check integrity of size values inside CSS header */
	size = (css->header_size_dw - css->rsa_info.key_size_dw - css->rsa_info.modulus_size_dw -
		css->rsa_info.exponent_size_dw) * sizeof(u32);
	if (unlikely(size != sizeof(struct uc_css_header))) {
		ops->report(ops->context, XE_UC_FW_CSS_HEADER_SIZE, uc_fw,
			    fw_size, sizeof(struct uc_css_header));
		return -EPROTO;
	}

	/* uCode size must calculated from other sizes */
	uc_fw->ucode_size = (css->size_dw - css->header_size_dw) * sizeof(u32);

	/* now RSA */
	uc_fw->rsa_size = css->rsa_info.key_size_dw * sizeof(u32);

	/* At least, it should have header, uCode and RSA. Size of all three. */
	size = sizeof(struct uc_css_header) + uc_fw->ucode_size +
		uc_fw->rsa_size;
	if (unlikely(fw_size < size)) {
		ops->report(ops->context, XE_UC_FW_CSS_SHORT_IMAGE, uc_fw, fw_size, size);
		return -ENOEXEC;
	}

	/* Get version numbers from the CSS header */
	release->major = FIELD_GET(CSS_SW_VERSION_UC_MAJOR, css->guc_info.sw_version);
	release->minor = FIELD_GET(CSS_SW_VERSION_UC_MINOR, css->guc_info.sw_version);
	release->patch = FIELD_GET(CSS_SW_VERSION_UC_PATCH, css->guc_info.sw_version);

	if (uc_fw->type == XE_UC_FW_TYPE_GUC)
		return xe_uc_fw_css_read_guc_info(uc_fw, &css->guc_info, ops);

	return 0;
}
#endif
