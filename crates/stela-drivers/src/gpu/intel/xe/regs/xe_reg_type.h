/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */
#ifndef XE_REG_TYPE_H
#define XE_REG_TYPE_H
/**
 * XE_REG_ADDR_MAX - The upper limit on MMIO register address
 *
 * This macro specifies the upper limit (not inclusive) on MMIO register offset
 * supported by struct xe_reg and functions based on struct xe_mmio.
 *
 * Currently this is defined as 4 MiB.
 */
#define XE_REG_ADDR_MAX	SZ_4M

/**
 * struct xe_reg - Register definition
 *
 * Register definition to be used by the individual register. Although the same
 * definition is used for xe_reg and xe_reg_mcr, they use different internal
 * APIs for accesses.
 */
struct xe_reg {
	union {
		struct {
			/** @addr: address */
			u32 addr:const_ilog2(XE_REG_ADDR_MAX);
			/**
			 * @masked: register is "masked", with upper 16bits used
			 * to identify the bits that are updated on the lower
			 * bits
			 */
			u32 masked:1;
			/**
			 * @mcr: register is multicast/replicated in the
			 * hardware and needs special handling. Any register
			 * with this set should also use a type of xe_reg_mcr_t.
			 * It's only here so the few places that deal with MCR
			 * registers specially (xe_sr.c) and tests using the raw
			 * value can inspect it.
			 */
			u32 mcr:1;
			/**
			 * @vf: register is accessible from the Virtual Function.
			 */
			u32 vf:1;
		};
		/** @raw: Raw value with both address and options */
		u32 raw;
	};
};
static_assert(sizeof(struct xe_reg) == sizeof(u32));

#endif
