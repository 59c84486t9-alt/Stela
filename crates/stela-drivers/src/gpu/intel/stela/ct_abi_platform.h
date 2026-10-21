/* SPDX-License-Identifier: MIT */
#ifndef STELA_INTEL_CT_ABI_PLATFORM_H
#define STELA_INTEL_CT_ABI_PLATFORM_H

#include "command_bits.h"
/* Scalar/compiler definitions used by the unchanged firmware descriptor ABI. */
#define __packed __attribute__((packed))
#define static_assert(condition) _Static_assert(condition, #condition)
#define FIELD_PREP(mask, value) REG_FIELD_PREP(mask, value)

#endif
