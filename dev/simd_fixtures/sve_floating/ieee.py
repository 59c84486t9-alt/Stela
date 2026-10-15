"""Exact rational primitives shared by independent numerical fixture models.

No host floating point is used. Callers own operation ordering, NaN priority,
control adaptation and architectural commit. Half-input flush suppression is an
explicit precision-conversion policy, rather than an arithmetic default.
"""

from dataclasses import dataclass
from enum import Enum
from fractions import Fraction

from .control import (
    FPCR_AH, FPCR_DN, FPCR_FIZ, FPCR_FZ, FPCR_FZ16,
    FPSR_INVALID, FPSR_OVERFLOW, FPSR_UNDERFLOW, FPSR_INEXACT,
    FPSR_INPUT_DENORMAL,
)

class Rounding(Enum):
    TIES_EVEN = 0
    POSITIVE = 1
    NEGATIVE = 2
    ZERO = 3
    ODD = 4



@dataclass(frozen=True)
class Format:
    bits: int
    exponent_bits: int
    fraction_bits: int

    @property
    def bias(self):
        return (1 << (self.exponent_bits - 1)) - 1

    @property
    def minimum_exponent(self):
        return 1 - self.bias

    @property
    def exponent_mask(self):
        return (1 << self.exponent_bits) - 1

    @property
    def fraction_mask(self):
        return (1 << self.fraction_bits) - 1

    def signed_zero(self, sign):
        return sign << (self.bits - 1)

    def infinity(self, sign):
        return self.signed_zero(sign) | self.exponent_mask << self.fraction_bits



FORMATS = {16: Format(16, 5, 10), 32: Format(32, 8, 23), 64: Format(64, 11, 52)}



BFLOAT = Format(16, 8, 7)



@dataclass(frozen=True)
class LaneResult:
    bits: int
    exceptions: int = 0



def power_two(exponent):
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)



def floor_log_two(value):
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    return exponent - (value < power_two(exponent))



def round_significand(value, sign, rounding):
    integer, remainder = divmod(value.numerator, value.denominator)
    if rounding == Rounding.ODD:
        return integer | bool(remainder), bool(remainder)
    increment = ((rounding == Rounding.TIES_EVEN and
                  (2 * remainder > value.denominator or
                   (2 * remainder == value.denominator and integer & 1))) or
                 (rounding == Rounding.POSITIVE and not sign and remainder != 0) or
                 (rounding == Rounding.NEGATIVE and sign and remainder != 0))
    return integer + bool(increment), bool(remainder)



def round_finite(value, output, fpcr, rounding):
    if not value:
        return LaneResult(0)
    sign = int(value < 0)
    value = abs(value)
    exponent = floor_log_two(value)
    alt = bool(fpcr & FPCR_AH)
    flush = bool(fpcr & (FPCR_FZ16 if output == FORMATS[16] else FPCR_FZ))
    if not alt and flush and exponent < output.minimum_exponent:
        return LaneResult(output.signed_zero(sign), FPSR_UNDERFLOW)
    quantum_exponent = max(exponent, output.minimum_exponent) - output.fraction_bits
    significand, inexact = round_significand(value / power_two(quantum_exponent), sign, rounding)
    if alt:
        # AH tests the precision-rounded value before constraining its exponent.
        unconstrained, _ = round_significand(
            value / power_two(exponent - output.fraction_bits), sign, rounding)
        # ODD only jams after this test in Arm pseudocode; it cannot affect
        # whether the unconstrained exponent crosses the normal threshold.
        if unconstrained >= 1 << (output.fraction_bits + 1):
            exponent += 1
        tiny = exponent < output.minimum_exponent
        if tiny and flush:
            return LaneResult(output.signed_zero(sign), FPSR_UNDERFLOW | FPSR_INEXACT)
    else:
        tiny = exponent < output.minimum_exponent
    status = (FPSR_INEXACT if inexact else 0) | (FPSR_UNDERFLOW if tiny and inexact else 0)
    if significand == 0:
        return LaneResult(output.signed_zero(sign), status)
    rounded_exponent = quantum_exponent + significand.bit_length() - 1
    if rounded_exponent > output.bias:
        infinity = (rounding == Rounding.TIES_EVEN or
                    (rounding == Rounding.POSITIVE and not sign) or
                    (rounding == Rounding.NEGATIVE and sign))
        result = output.infinity(sign) if infinity else output.infinity(sign) - 1
        return LaneResult(result, FPSR_OVERFLOW | FPSR_INEXACT)
    if rounded_exponent < output.minimum_exponent:
        encoded = significand
    else:
        shift = significand.bit_length() - output.fraction_bits - 1
        fraction = (significand >> shift) & output.fraction_mask
        encoded = (rounded_exponent + output.bias) << output.fraction_bits | fraction
    return LaneResult(output.signed_zero(sign) | encoded, status)



def unpack(bits, source, fpcr, *, ignore_half_flush=False, input_exceptions=True):
    sign = bits >> (source.bits - 1)
    exponent = bits >> source.fraction_bits & source.exponent_mask
    fraction = bits & source.fraction_mask
    if exponent == source.exponent_mask:
        category = 'infinity' if fraction == 0 else 'qnan' if fraction >> (source.fraction_bits - 1) else 'snan'
        return category, sign, Fraction(0), 0
    if exponent == 0:
        if not fraction:
            return 'zero', sign, Fraction(0), 0
        half = source == FORMATS[16]
        flush_half = half and not ignore_half_flush and bool(fpcr & FPCR_FZ16)
        flush_fz = not half and bool(fpcr & FPCR_FZ) and not bool(fpcr & FPCR_AH)
        flush_fiz = not half and bool(fpcr & FPCR_FIZ)
        if flush_half or flush_fz or flush_fiz:
            status = FPSR_INPUT_DENORMAL if flush_fz and input_exceptions else 0
            return 'zero', sign, Fraction(0), status
        value = fraction * power_two(source.minimum_exponent - source.fraction_bits)
        category = 'denormal'
    else:
        value = ((1 << source.fraction_bits) | fraction) * power_two(exponent - source.bias - source.fraction_bits)
        category = 'finite'
    return category, sign, -value if sign else value, 0



def convert_nan(bits, source, output, fpcr):
    if fpcr & FPCR_DN:
        sign = int(bool(fpcr & FPCR_AH))
        payload = 1 << (output.fraction_bits - 1)
    else:
        sign = bits >> (source.bits - 1)
        payload = bits & source.fraction_mask
        shift = output.fraction_bits - source.fraction_bits
        payload = payload << shift if shift >= 0 else payload >> -shift
        payload |= 1 << (output.fraction_bits - 1)
    return output.infinity(sign) | payload
