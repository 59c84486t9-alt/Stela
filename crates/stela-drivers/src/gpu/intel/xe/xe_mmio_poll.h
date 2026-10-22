// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021-2023 Intel Corporation
 */
/* Original masked/deadline/final-reread algorithm; includer binds actual I/O/time. */
static int XE_MMIO_POLL_NAME(XE_MMIO_POLL_CONTEXT *mmio, struct xe_reg reg, u32 mask, u32 val,
			    u32 timeout_us, u32 *out_val, bool atomic, bool expect_match)
{
	XE_MMIO_POLL_TIME cur = XE_MMIO_POLL_NOW(mmio);
	const XE_MMIO_POLL_TIME end = XE_MMIO_POLL_ADD_US(cur, timeout_us);
	int ret = -ETIMEDOUT;
	s64 wait = 10;
	u32 read;
	bool check;

	for (;;) {
		read = XE_MMIO_POLL_READ(mmio, reg);

		check = (read & mask) == val;
		if (!expect_match)
			check = !check;

		if (check) {
			ret = 0;
			break;
		}

		cur = XE_MMIO_POLL_NOW(mmio);
		if (!XE_MMIO_POLL_BEFORE(cur, end))
			break;

		if (XE_MMIO_POLL_AFTER(XE_MMIO_POLL_ADD_US(cur, wait), end))
			wait = XE_MMIO_POLL_DELTA_US(end, cur);

		if (atomic)
			XE_MMIO_POLL_DELAY(mmio, wait, true);
		else
			XE_MMIO_POLL_DELAY(mmio, wait, false);
		wait <<= 1;
	}

	if (ret != 0) {
		read = XE_MMIO_POLL_READ(mmio, reg);

		check = (read & mask) == val;
		if (!expect_match)
			check = !check;

		if (check)
			ret = 0;
	}

	if (out_val)
		*out_val = read;

	return ret;
}
