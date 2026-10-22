/* SPDX-License-Identifier: MIT */
/* Copyright © 2021-2023 Intel Corporation */
/* Required compile-time bindings, no fallback access operations. */
#if !defined(XE_MMIO_VERIFY_NAME) || !defined(XE_MMIO_VERIFY_CONTEXT) || \
    !defined(XE_MMIO_VERIFY_WRITE) || !defined(XE_MMIO_VERIFY_READ)
#error "MMIO verification requires actual read/write context bindings"
#endif
static int XE_MMIO_VERIFY_NAME(XE_MMIO_VERIFY_CONTEXT *mmio,
			       struct xe_reg reg, u32 val, u32 mask, u32 eval)
{
	u32 reg_val;

	XE_MMIO_VERIFY_WRITE(mmio, reg, val);
	reg_val = XE_MMIO_VERIFY_READ(mmio, reg);

	return (reg_val & mask) != eval ? -EINVAL : 0;
}
#undef XE_MMIO_VERIFY_NAME
#undef XE_MMIO_VERIFY_CONTEXT
#undef XE_MMIO_VERIFY_WRITE
#undef XE_MMIO_VERIFY_READ
