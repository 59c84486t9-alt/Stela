// SPDX-License-Identifier: MIT
/* What `llvm_test.c` reads as bitcode, with what the AIR compiler's first
 * passes take out: an always-inline call and a switch. */
static inline __attribute__((always_inline)) int twice(int value)
{
	return value * 2;
}

int pick(int value)
{
	switch (value) {
	case 1:
		return twice(value);
	case 2:
		return 5;
	default:
		return 0;
	}
}
