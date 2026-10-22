/* SPDX-License-Identifier: MIT */
/* Copyright © 2022 Intel Corporation */
#ifndef XE_UC_FW_VERSION_H
#define XE_UC_FW_VERSION_H
/*
 * GuC version number components are defined to be only 8-bit size,
 * so converting to a 32bit 8.8.8 integer allows simple (and safe)
 * numerical comparisons.
 */
#define MAKE_GUC_VER(maj, min, pat)	(((maj) << 16) | ((min) << 8) | (pat))
#define MAKE_GUC_VER_STRUCT(ver)	MAKE_GUC_VER((ver).major, (ver).minor, (ver).patch)
#endif
