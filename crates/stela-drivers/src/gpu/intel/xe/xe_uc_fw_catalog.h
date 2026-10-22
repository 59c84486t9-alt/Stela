/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_UC_FW_CATALOG_H
#define XE_UC_FW_CATALOG_H
struct uc_fw_entry {
	enum xe_platform platform;
	enum xe_gt_type gt_type;

	struct {
		const char *path;
		u16 major;
		u16 minor;
		u16 patch;
		bool full_ver_required;
	};
};

struct fw_blobs_by_type {
	const struct uc_fw_entry *entries;
	u32 count;
};

/*
 * Add an "ANY" define just to convey the meaning it's given here.
 */
#define XE_GT_TYPE_ANY XE_GT_TYPE_UNINITIALIZED

#define XE_GUC_FIRMWARE_DEFS(fw_def, mmp_ver, major_ver)					\
	fw_def(PANTHERLAKE,	GT_TYPE_ANY,	major_ver(xe,	guc,	ptl,	70, 54, 0))	\
	fw_def(BATTLEMAGE,	GT_TYPE_ANY,	major_ver(xe,	guc,	bmg,	70, 54, 0))	\
	fw_def(LUNARLAKE,	GT_TYPE_ANY,	major_ver(xe,	guc,	lnl,	70, 53, 0))	\
	fw_def(METEORLAKE,	GT_TYPE_ANY,	major_ver(i915,	guc,	mtl,	70, 53, 0))	\
	fw_def(DG2,		GT_TYPE_ANY,	major_ver(i915,	guc,	dg2,	70, 53, 0))	\
	fw_def(DG1,		GT_TYPE_ANY,	major_ver(i915,	guc,	dg1,	70, 44, 1))	\
	fw_def(ALDERLAKE_N,	GT_TYPE_ANY,	major_ver(i915,	guc,	tgl,	70, 44, 1))	\
	fw_def(ALDERLAKE_P,	GT_TYPE_ANY,	major_ver(i915,	guc,	adlp,	70, 44, 1))	\
	fw_def(ALDERLAKE_S,	GT_TYPE_ANY,	major_ver(i915,	guc,	tgl,	70, 44, 1))	\
	fw_def(ROCKETLAKE,	GT_TYPE_ANY,	major_ver(i915,	guc,	tgl,	70, 44, 1))	\
	fw_def(TIGERLAKE,	GT_TYPE_ANY,	major_ver(i915,	guc,	tgl,	70, 44, 1))

#define XE_HUC_FIRMWARE_DEFS(fw_def, mmp_ver, no_ver)		\
	fw_def(PANTHERLAKE,	GT_TYPE_ANY,	no_ver(xe,	huc,		ptl))		\
	fw_def(BATTLEMAGE,	GT_TYPE_ANY,	no_ver(xe,	huc,		bmg))		\
	fw_def(LUNARLAKE,	GT_TYPE_ANY,	no_ver(xe,	huc,		lnl))		\
	fw_def(METEORLAKE,	GT_TYPE_ANY,	no_ver(i915,	huc_gsc,	mtl))		\
	fw_def(DG1,		GT_TYPE_ANY,	no_ver(i915,	huc,		dg1))		\
	fw_def(ALDERLAKE_P,	GT_TYPE_ANY,	no_ver(i915,	huc,		tgl))		\
	fw_def(ALDERLAKE_S,	GT_TYPE_ANY,	no_ver(i915,	huc,		tgl))		\
	fw_def(ROCKETLAKE,	GT_TYPE_ANY,	no_ver(i915,	huc,		tgl))		\
	fw_def(TIGERLAKE,	GT_TYPE_ANY,	no_ver(i915,	huc,		tgl))

/* for the GSC FW we match the compatibility version and not the release one */
#define XE_GSC_FIRMWARE_DEFS(fw_def, major_ver)		\
	fw_def(PANTHERLAKE,	GT_TYPE_ANY,	major_ver(xe,	gsc,	ptl,	105, 1, 0))	\
	fw_def(LUNARLAKE,	GT_TYPE_ANY,	major_ver(xe,	gsc,	lnl,	104, 1, 0))	\
	fw_def(METEORLAKE,	GT_TYPE_ANY,	major_ver(i915,	gsc,	mtl,	102, 1, 0))

#define MAKE_FW_PATH(dir__, uc__, shortname__, version__)			\
	__stringify(dir__) "/" __stringify(shortname__) "_" __stringify(uc__) version__ ".bin"

#define fw_filename_mmp_ver(dir_, uc_, shortname_, a, b, c)			\
	MAKE_FW_PATH(dir_, uc_, shortname_, "_" __stringify(a ## . ## b ## . ## c))
#define fw_filename_major_ver(dir_, uc_, shortname_, a, b, c)			\
	MAKE_FW_PATH(dir_, uc_, shortname_, "_" __stringify(a))
#define fw_filename_no_ver(dir_, uc_, shortname_)				\
	MAKE_FW_PATH(dir_, uc_, shortname_, "")
#define fw_filename_gsc(dir_, uc_, shortname_, a, b, c)				\
	MAKE_FW_PATH(dir_, uc_, shortname_, "_" __stringify(b))

#define uc_fw_entry_mmp_ver(dir_, uc_, shortname_, a, b, c)			\
	{ fw_filename_mmp_ver(dir_, uc_, shortname_, a, b, c),			\
	  a, b, c, true }
#define uc_fw_entry_major_ver(dir_, uc_, shortname_, a, b, c)			\
	{ fw_filename_major_ver(dir_, uc_, shortname_, a, b, c),		\
	  a, b, c }
#define uc_fw_entry_no_ver(dir_, uc_, shortname_)				\
	{ fw_filename_no_ver(dir_, uc_, shortname_),				\
	  0, 0 }
#define uc_fw_entry_gsc(dir_, uc_, shortname_, a, b, c)				\
	{ fw_filename_gsc(dir_, uc_, shortname_, a, b, c),			\
	  a, b, c }

/* All blobs need to be declared via MODULE_FIRMWARE() */
#define XE_UC_MODULE_FIRMWARE(platform__, gt_type__, fw_filename)		\
	MODULE_FIRMWARE(fw_filename);

#define XE_UC_FW_ENTRY(platform__, gt_type__, entry__)				\
	{									\
		.platform = XE_ ## platform__,					\
		.gt_type = XE_ ## gt_type__,					\
		entry__,							\
	},

/* Caller retains original type/GT assertions or validates native inputs. */
static inline void xe_uc_fw_select_default(enum xe_platform p,
		enum xe_gt_type gt_type, struct xe_uc_fw *uc_fw)
{
	static const struct uc_fw_entry entries_guc[] = {
		XE_GUC_FIRMWARE_DEFS(XE_UC_FW_ENTRY,
				     uc_fw_entry_mmp_ver,
				     uc_fw_entry_major_ver)
	};
	static const struct uc_fw_entry entries_huc[] = {
		XE_HUC_FIRMWARE_DEFS(XE_UC_FW_ENTRY,
				     uc_fw_entry_mmp_ver,
				     uc_fw_entry_no_ver)
	};
	static const struct uc_fw_entry entries_gsc[] = {
		XE_GSC_FIRMWARE_DEFS(XE_UC_FW_ENTRY, uc_fw_entry_gsc)
	};
	static const struct fw_blobs_by_type blobs_all[XE_UC_FW_NUM_TYPES] = {
		[XE_UC_FW_TYPE_GUC] = { entries_guc, ARRAY_SIZE(entries_guc) },
		[XE_UC_FW_TYPE_HUC] = { entries_huc, ARRAY_SIZE(entries_huc) },
		[XE_UC_FW_TYPE_GSC] = { entries_gsc, ARRAY_SIZE(entries_gsc) },
	};
	const struct uc_fw_entry *entries;
	u32 count;
	int i;

	entries = blobs_all[uc_fw->type].entries;
	count = blobs_all[uc_fw->type].count;

	for (i = 0; i < count && p <= entries[i].platform; i++) {
		if (p != entries[i].platform)
			continue;

		if (entries[i].gt_type != XE_GT_TYPE_ANY &&
		    entries[i].gt_type != gt_type)
			continue;

		uc_fw->path = entries[i].path;
		uc_fw->versions.wanted.major = entries[i].major;
		uc_fw->versions.wanted.minor = entries[i].minor;
		uc_fw->versions.wanted.patch = entries[i].patch;
		uc_fw->full_ver_required = entries[i].full_ver_required;

		if (uc_fw->type == XE_UC_FW_TYPE_GSC)
			uc_fw->versions.wanted_type = XE_UC_FW_VER_COMPATIBILITY;
		else
			uc_fw->versions.wanted_type = XE_UC_FW_VER_RELEASE;

		break;
	}
}
#endif
