"""Exact, independent numerical reference for Arm's June 2026 FP8 helpers.

This is a mathematical model, not an original-Arm execution oracle. All finite
values, products and sums use integers and Fraction; no host float, APFloat or
production numerical helper participates. Callers own architectural state,
streaming exception-enable masking and instruction allocation.

Conversion results are (raw bits, cumulative FPSR exception bits). Effective
exception enables are an explicit unsupported boundary, since this pure model
cannot deliver an architectural FP trap. Dot arithmetic suppresses exceptions.
The ``single`` widening option is a numerical helper extension: June allocated
FP8 widening conversions produce half or BFloat16.
"""
from __future__ import annotations

from fractions import Fraction

FPCR_AH = 1 << 1
FP_EXCEPTION_ENABLE_MASK = 0x9F00
FPSR_INVALID = 1 << 0
FPSR_OVERFLOW = 1 << 2
FPSR_UNDERFLOW = 1 << 3
FPSR_INEXACT = 1 << 4
FPMR_SOURCE1_SHIFT = 0
FPMR_SOURCE2_SHIFT = 3
FPMR_DESTINATION_SHIFT = 6
FPMR_OSM = 1 << 14
FPMR_OSC = 1 << 15
FPMR_LSCALE_SHIFT = 16
FPMR_NSCALE_SHIFT = 24
FPMR_LSCALE2_SHIFT = 32
SELECTOR_MASK = 7
_FORMATS = {'half': (16, 5, 10, -14), 'bfloat16': (16, 8, 7, -126),
            'single': (32, 8, 23, -126)}
_FP8_FORMATS = {0: (8, 5, 2, -14), 1: (8, 4, 3, -6)}


class UnsupportedControl(ValueError):
    """The pure model cannot execute the requested architectural boundary."""


def _raw(value, width, name):
    if type(value) is not int or not 0 <= value < 1 << width:
        raise ValueError(f'{name} must be an unsigned {width}-bit integer')
    return value


def _controls(fpcr, fpmr, conversion):
    _raw(fpcr, 32, 'FPCR')
    _raw(fpmr, 64, 'FPMR')
    if conversion and fpcr & FP_EXCEPTION_ENABLE_MASK:
        raise UnsupportedControl('effective FP exception enables require a trap-capable observer')


def _format(name):
    try:
        return _FORMATS[name]
    except (KeyError, TypeError) as error:
        raise ValueError('format must be half, bfloat16 or single') from error


def _power(exponent):
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)


def _signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def _decode(bits, spec, fp8=False):
    width, exponent_bits, fraction_bits, minimum = spec
    _raw(bits, width, 'operand')
    sign = bits >> (width - 1)
    fraction = bits & ((1 << fraction_bits) - 1)
    exponent = bits >> fraction_bits & ((1 << exponent_bits) - 1)
    maximum_exponent = (1 << exponent_bits) - 1
    if fp8 and exponent_bits == 4:
        special = exponent == maximum_exponent and fraction == (1 << fraction_bits) - 1
        if special:
            return 'snan', sign, Fraction(0)
    elif exponent == maximum_exponent:
        kind = ('infinity' if fraction == 0 else
                'qnan' if fraction & (1 << (fraction_bits - 1)) else 'snan')
        return kind, sign, Fraction(0)
    if exponent == 0:
        value = fraction * _power(minimum - fraction_bits)
    else:
        value = ((1 << fraction_bits) + fraction) * _power(exponent + minimum - 1 - fraction_bits)
    return ('finite' if value else 'zero'), sign, -value if sign else value


def _decode_fp8(bits, selector):
    _raw(bits, 8, 'FP8 operand')
    if selector not in _FP8_FORMATS:
        return 'snan', bits >> 7, Fraction(0)
    return _decode(bits, _FP8_FORMATS[selector], True)


def _default_nan(spec, fpcr, fp8=False):
    width, exponent_bits, fraction_bits, _ = spec
    sign = int(bool(fpcr & FPCR_AH)) << (width - 1)
    payload = ((1 << fraction_bits) - 1 if fp8 and exponent_bits == 4
               else 1 << (fraction_bits - 1))
    return sign | (((1 << exponent_bits) - 1) << fraction_bits) | payload


def _infinity(spec, sign, fp8=False):
    width, exponent_bits, fraction_bits, _ = spec
    fraction = (1 << fraction_bits) - 1 if fp8 and exponent_bits == 4 else 0
    return sign << (width - 1) | ((1 << exponent_bits) - 1) << fraction_bits | fraction


def _maximum(spec, sign, fp8=False):
    width, exponent_bits, fraction_bits, _ = spec
    last = ((1 << exponent_bits) - 1) << fraction_bits
    last -= 2 if fp8 and exponent_bits == 4 else 1
    if fp8 and exponent_bits == 4:
        # E4M3's top exponent remains finite through fraction 110.
        last = (1 << (width - 1)) - 2
    return sign << (width - 1) | last


def _floor_log2(value):
    """Obtain binary exponent by integer bit lengths, then one exact comparison."""
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    return exponent - int(value < _power(exponent))


def _nearest_even(value):
    quotient, remainder = divmod(value.numerator, value.denominator)
    twice = 2 * remainder
    return quotient + int(twice > value.denominator or
                          (twice == value.denominator and quotient & 1))


def _round(value, spec, fpcr, saturate, fp8=False):
    """Quantize once on an exact integer lattice; track unconstrained tininess."""
    width, exponent_bits, fraction_bits, minimum = spec
    if not value:
        return 0, 0
    sign = int(value < 0)
    magnitude = abs(value)
    exponent = _floor_log2(magnitude)
    quantum = _power(max(exponent, minimum) - fraction_bits)
    units = magnitude / quantum
    rounded = _nearest_even(units)
    inexact = units.denominator != 1
    if exponent < minimum:
        encoded_exponent = int(rounded >= 1 << fraction_bits)
    else:
        encoded_exponent = exponent - minimum + 1
        if rounded == 1 << (fraction_bits + 1):
            rounded >>= 1
            encoded_exponent += 1
    status = FPSR_INEXACT if inexact else 0
    if inexact:
        if fpcr & FPCR_AH:
            # AH tests rounding with the normal precision and an unbounded
            # exponent, before imposing the destination's subnormal lattice.
            unconstrained = _nearest_even(magnitude / _power(exponent - fraction_bits))
            tiny = exponent + int(unconstrained == 1 << (fraction_bits + 1)) < minimum
        else:
            tiny = exponent < minimum
        if tiny:
            status |= FPSR_UNDERFLOW
    maximum_exponent = (1 << exponent_bits) - 1
    overflow = (encoded_exponent > maximum_exponent or
                (encoded_exponent == maximum_exponent and
                 (not fp8 or exponent_bits == 5 or rounded == (1 << (fraction_bits + 1)) - 1)))
    if overflow:
        bits = _maximum(spec, sign, fp8) if saturate else _infinity(spec, sign, fp8)
        return bits, status | FPSR_OVERFLOW | FPSR_INEXACT
    bits = (sign << (width - 1) | encoded_exponent << fraction_bits |
            rounded & ((1 << fraction_bits) - 1))
    return bits, status


def to_fp8(format, fpcr, fpmr, bits):
    """FPConvertFP8/BFConvertFP8 with RNE, OSC and signed NSCALE."""
    spec = _format(format)
    _controls(fpcr, fpmr, True)
    kind, sign, value = _decode(bits, spec)
    selector = fpmr >> FPMR_DESTINATION_SHIFT & SELECTOR_MASK
    if selector not in _FP8_FORMATS:
        return 0xFF, FPSR_INVALID
    destination = _FP8_FORMATS[selector]
    if kind in ('snan', 'qnan'):
        return _default_nan(destination, fpcr, True), FPSR_INVALID if kind == 'snan' else 0
    if kind == 'infinity':
        return (_maximum(destination, sign, True) if fpmr & FPMR_OSC else
                _infinity(destination, sign, True)), 0
    if kind == 'zero':
        return sign << 7, 0
    scale_width = 5 if format == 'half' else 8
    scale = _signed(fpmr >> FPMR_NSCALE_SHIFT & ((1 << scale_width) - 1), scale_width)
    return _round(value * _power(scale), destination, fpcr, bool(fpmr & FPMR_OSC), True)


def from_fp8(format, source2, fpcr, fpmr, bits):
    """FP8ConvertFP/FP8ConvertBF with RNE and source-specific downscaling."""
    destination = _format(format)
    if type(source2) is not bool:
        raise ValueError('source2 must be boolean')
    _controls(fpcr, fpmr, True)
    selector_shift = FPMR_SOURCE2_SHIFT if source2 else FPMR_SOURCE1_SHIFT
    kind, sign, value = _decode_fp8(bits, fpmr >> selector_shift & SELECTOR_MASK)
    if kind in ('snan', 'qnan'):
        return _default_nan(destination, fpcr), FPSR_INVALID if kind == 'snan' else 0
    if kind == 'infinity':
        return _infinity(destination, sign), 0
    if kind == 'zero':
        return sign << (destination[0] - 1), 0
    shift = FPMR_LSCALE2_SHIFT if source2 else FPMR_LSCALE_SHIFT
    scale = fpmr >> shift & (15 if format == 'half' else 63)
    return _round(value * _power(-scale), destination, fpcr, False)


def dot_add(format, fpcr, fpmr, addend, left, right):
    """One exact 1/2/4/8-way dot and add, RNE, OSM, no FP exceptions."""
    if format not in ('half', 'single'):
        raise ValueError('dot format must be half or single')
    spec = _format(format)
    _controls(fpcr, fpmr, False)
    if len(left) != len(right) or len(left) not in (1, 2, 4, 8):
        raise ValueError('dot requires matching 1/2/4/8-element FP8 inputs')
    accumulator = _decode(addend, spec)
    pairs = [(_decode_fp8(a, fpmr >> FPMR_SOURCE1_SHIFT & SELECTOR_MASK),
              _decode_fp8(b, fpmr >> FPMR_SOURCE2_SHIFT & SELECTOR_MASK))
             for a, b in zip(left, right)]
    operands = [accumulator] + [operand for pair in pairs for operand in pair]
    if any(kind in ('snan', 'qnan') for kind, _, _ in operands):
        return _default_nan(spec, fpcr)
    products = []
    for (kind_a, sign_a, value_a), (kind_b, sign_b, value_b) in pairs:
        if {kind_a, kind_b} == {'infinity', 'zero'}:
            return _default_nan(spec, fpcr)
        kind = ('infinity' if 'infinity' in (kind_a, kind_b) else
                'zero' if 'zero' in (kind_a, kind_b) else 'finite')
        products.append((kind, sign_a ^ sign_b, value_a * value_b))
    terms = [accumulator] + products
    infinity_signs = {sign for kind, sign, _ in terms if kind == 'infinity'}
    if len(infinity_signs) == 2:
        return _default_nan(spec, fpcr)
    if infinity_signs:
        return _infinity(spec, infinity_signs.pop())
    if all(kind == 'zero' and sign == accumulator[1] for kind, sign, _ in terms):
        return accumulator[1] << (spec[0] - 1)
    scale = fpmr >> FPMR_LSCALE_SHIFT & (15 if format == 'half' else 127)
    value = accumulator[2] + sum((product[2] for product in products), Fraction(0)) * _power(-scale)
    return _round(value, spec, fpcr, bool(fpmr & FPMR_OSM))[0]
