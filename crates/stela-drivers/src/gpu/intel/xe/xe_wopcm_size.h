/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_WOPCM_SIZE_H
#define XE_WOPCM_SIZE_H
/* Default WOPCM size is 2MB from Gen11, 1MB on previous platforms */
/* FIXME: Larger size require for some platforms, do a proper probe sooner or later */
#define DGFX_WOPCM_SIZE			SZ_4M
#define LNL_WOPCM_SIZE			SZ_8M
#define MTL_WOPCM_SIZE			SZ_4M
#define WOPCM_SIZE			SZ_2M

static inline u32 xe_wopcm_default_size(enum xe_platform platform, bool discrete)
{
	if (platform >= XE_LUNARLAKE)
		return LNL_WOPCM_SIZE;
	else if (discrete)
		return DGFX_WOPCM_SIZE;
	else if (platform == XE_METEORLAKE)
		return MTL_WOPCM_SIZE;
	else
		return WOPCM_SIZE;
}

#endif
