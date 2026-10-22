/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GUC_H
#define STELA_XE_GUC_H
/* Copyright © 2022 Intel Corporation; from xe_guc.h. */
#define MAKE_GUC_VER(maj, min, pat)	(((maj) << 16) | ((min) << 8) | (pat))
#define MAKE_GUC_VER_STRUCT(ver)	MAKE_GUC_VER((ver).major, (ver).minor, (ver).patch)
#endif
