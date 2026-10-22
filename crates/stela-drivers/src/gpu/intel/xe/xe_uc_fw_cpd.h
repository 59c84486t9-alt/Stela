/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_UC_FW_CPD_H
#define XE_UC_FW_CPD_H
#ifndef XE_UC_FW_CPD_ENTRY_EQUAL
#error "CPD requires the actual caller's bounded name equality binding"
#endif
/* Original parser policy. No BO, load state, signature or device service.
 * The original Linux caller retains real logging, assertions and GSC writes.
 * Native callers must preflight input arithmetic/iteration before this core. */
enum xe_uc_fw_cpd_diagnostic {
	XE_UC_FW_CPD_HEADER_LENGTH,
	XE_UC_FW_CPD_SHORT_IMAGE,
	XE_UC_FW_CPD_MISSING_MANIFEST,
};
struct xe_uc_fw_cpd_ops {
	void *context;
	void (*report)(void *, enum xe_uc_fw_cpd_diagnostic, const struct xe_uc_fw *, size_t, size_t);
	void (*invariant)(void *, bool);
	int (*parse_css)(void *, struct xe_uc_fw *, const void *, size_t);
	void (*gsc_manifest)(void *, struct xe_uc_fw *, const struct gsc_manifest_header *);
};
static bool is_cpd_header(const void *data)
{
	const struct gsc_cpd_header_v2 *header = data;

	return header->header_marker == GSC_CPD_HEADER_MARKER;
}

static u32 entry_offset(const struct gsc_cpd_header_v2 *header, const char *name, size_t name_bytes)
{
	const struct gsc_cpd_entry *entry;
	int i;

	entry = (void *)header + header->header_length;

	for (i = 0; i < header->num_of_entries; i++, entry++)
		if (XE_UC_FW_CPD_ENTRY_EQUAL(entry->name, name, name_bytes))
			return entry->offset & GSC_CPD_ENTRY_OFFSET_MASK;

	return 0;
}

/* Refer to the "GSC-based Firmware Layout" documentation entry for details */
static int xe_uc_fw_cpd_parse(struct xe_uc_fw *uc_fw, const void *data, size_t size,
			    const char *manifest_entry, size_t manifest_bytes,
			    const char *css_entry, size_t css_bytes, enum xe_platform platform,
			    const struct xe_uc_fw_cpd_ops *ops)
{
	const struct gsc_cpd_header_v2 *header = data;
	struct xe_uc_fw_version *release = &uc_fw->versions.found[XE_UC_FW_VER_RELEASE];
	const struct gsc_manifest_header *manifest;
	size_t min_size = sizeof(*header);
	u32 offset;

	/* manifest_entry is mandatory, css_entry is optional */
	ops->invariant(ops->context, manifest_entry && manifest_bytes && manifest_bytes <= 12);
	ops->invariant(ops->context, !css_entry || (css_bytes && css_bytes <= 12));

	if (size < min_size || !is_cpd_header(header))
		return -ENOENT;

	if (header->header_length < sizeof(struct gsc_cpd_header_v2)) {
		ops->report(ops->context, XE_UC_FW_CPD_HEADER_LENGTH, uc_fw, header->header_length, sizeof(*header));
		return -EINVAL;
	}

	min_size = header->header_length + sizeof(struct gsc_cpd_entry) * header->num_of_entries;
	if (size < min_size) {
		ops->report(ops->context, XE_UC_FW_CPD_SHORT_IMAGE, uc_fw, size, min_size);
		return -ENODATA;
	}

	/* Look for the manifest first */
	offset = entry_offset(header, manifest_entry, manifest_bytes);
	if (!offset) {
		ops->report(ops->context, XE_UC_FW_CPD_MISSING_MANIFEST, uc_fw, 0, 0);
		return -ENODATA;
	}

	min_size = offset + sizeof(struct gsc_manifest_header);
	if (size < min_size) {
		ops->report(ops->context, XE_UC_FW_CPD_SHORT_IMAGE, uc_fw, size, min_size);
		return -ENODATA;
	}

	manifest = data + offset;

	release->major = manifest->fw_version.major;
	release->minor = manifest->fw_version.minor;
	release->patch = manifest->fw_version.hotfix;

	if (uc_fw->type == XE_UC_FW_TYPE_GSC) {
		ops->invariant(ops->context, ops->gsc_manifest);
		ops->gsc_manifest(ops->context, uc_fw, manifest);
	}

	/* then optionally look for the css header */
	if (css_entry) {
		int ret;

		/*
		 * This section does not contain a CSS entry on DG2. We
		 * don't support DG2 HuC right now, so no need to handle
		 * it, just add a reminder in case that changes.
		 */
		ops->invariant(ops->context, platform != XE_DG2);

		offset = entry_offset(header, css_entry, css_bytes);

		/* the CSS header parser will check that the CSS header fits */
		if (offset > size) {
			ops->report(ops->context, XE_UC_FW_CPD_SHORT_IMAGE, uc_fw, size, offset);
			return -ENODATA;
		}

		ret = ops->parse_css(ops->context, uc_fw, data + offset, size - offset);
		if (ret)
			return ret;

		uc_fw->css_offset = offset;
	}

	uc_fw->has_gsc_headers = true;

	return 0;
}

/* Original HuC CPD-first dispatch. Only absent CPD falls through to CSS. */
static int xe_uc_fw_huc_parse(struct xe_uc_fw *uc_fw, const void *data, size_t size,
			    enum xe_platform platform, const struct xe_uc_fw_cpd_ops *ops)
{
	int ret;

	ret = xe_uc_fw_cpd_parse(uc_fw, data, size, "HUCP.man", sizeof("HUCP.man"),
			       "huc_fw", sizeof("huc_fw"), platform, ops);
	if (!ret || ret != -ENOENT)
		return ret;

	return ops->parse_css(ops->context, uc_fw, data, size);
}

#undef XE_UC_FW_CPD_ENTRY_EQUAL
#endif
