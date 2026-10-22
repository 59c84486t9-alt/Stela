/* SPDX-License-Identifier: MIT */
#ifndef STELA_XE_FORCE_WAKE_TYPES_H
#define STELA_XE_FORCE_WAKE_TYPES_H
#include "xe_force_wake_domain_types.h"
/* Forcewake references are held by the activation owner. */
struct stela_intel_activation;
struct xe_force_wake {
	struct stela_intel_activation *activation;
};
#endif
