/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_GSC_TYPES_H
#define STELA_XE_GSC_TYPES_H
#include <linux/types.h>
#include "xe_uc_fw_types.h"
/* Stela parses GSC manifests but runs no GSC proxy or loader worker. */
struct xe_gsc {
	struct xe_uc_fw fw;
	u32 security_version;
};
#endif
