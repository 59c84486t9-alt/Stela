/* SPDX-License-Identifier: MIT */
/* Copyright © 2023 Intel Corporation */
#ifndef XE_PAT_PROGRAM_H
#define XE_PAT_PROGRAM_H
#ifndef XE_PAT_PROGRAM_WRITE
#error "PAT programming requires actual ordered MMIO binding"
#endif
static inline void xe_pat_program_direct(void *context,
 const struct xe_pat_table_entry table[], int n_entries,
 const struct xe_pat_table_entry *pat_ats, const struct xe_pat_table_entry *pta_entry)
{
	for (int i = 0; i < n_entries; i++) {
		struct xe_reg reg = XE_REG(_PAT_INDEX(i));

		XE_PAT_PROGRAM_WRITE(context, reg, table[i].value);
	}

	if (pat_ats)
		XE_PAT_PROGRAM_WRITE(context, XE_REG(_PAT_ATS), pat_ats->value);

	if (pta_entry)
		XE_PAT_PROGRAM_WRITE(context, XE_REG(_PAT_PTA), pta_entry->value);
}
#undef XE_PAT_PROGRAM_WRITE
#endif
