// SPDX-License-Identifier: MIT
/* Rust's UEFI target is soft-float, so an `extern "C"` float from it travels as
 * bits in an integer register where Mesa's C expects an SSE one. These are all
 * the floats that cross: bindgen's wrappers of the three conversions NAK calls,
 * which the build renames aside, and the float methods of `std`'s shim. */
#include <math.h>
#include <stdint.h>
#include <string.h>
#include "util/half_float.h"

static inline float float_of(uint32_t bits)
{
	float value;
	memcpy(&value, &bits, sizeof(value));
	return value;
}

static inline uint32_t bits_of(float value)
{
	uint32_t bits;
	memcpy(&bits, &value, sizeof(bits));
	return bits;
}

uint32_t _mesa_half_to_float__extern(uint16_t half)
{
	return bits_of(_mesa_half_to_float(half));
}

uint16_t _mesa_float_to_float16_rtne__extern(uint32_t value)
{
	return _mesa_float_to_float16_rtne(float_of(value));
}

uint16_t _mesa_double_to_float16_rtne__extern(uint64_t value)
{
	double wide;
	memcpy(&wide, &value, sizeof(wide));
	return _mesa_double_to_float16_rtne(wide);
}

uint32_t stela_libc_powf_bits(uint32_t base, uint32_t exponent)
{
	return bits_of(powf(float_of(base), float_of(exponent)));
}

uint32_t stela_libc_log2f_bits(uint32_t value)
{
	return bits_of(log2f(float_of(value)));
}

uint32_t stela_libc_roundf_bits(uint32_t value)
{
	return bits_of(roundf(float_of(value)));
}
