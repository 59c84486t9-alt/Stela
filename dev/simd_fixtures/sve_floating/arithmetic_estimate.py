"""Exact active-lane roots, architectural estimates and fused refinement.

FPCR is the effective control supplied by the execution adapter. Standard
estimates match the RPRES-disabled profile. The optional increased-precision
model is explicit and requires Single+AH; its presence does not establish native
RPRES support. No host floating-point approximation participates in this oracle.
"""

from enum import Enum
from fractions import Fraction
from math import isqrt

from .control import (
    FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_FZ16,
    FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, FP_EXCEPTION_ENABLE_MASK,
    FPSR_DIVIDE_BY_ZERO, FPSR_INEXACT, FPSR_INPUT_DENORMAL,
    FPSR_INVALID, FPSR_OVERFLOW, FPSR_UNDERFLOW,
)
from .conversion import UnsupportedFpControls
from .ieee import (
    FORMATS, LaneResult, Rounding, convert_nan, floor_log_two,
    power_two, round_finite, unpack,
)


class Kind(Enum):
    SQRT = 'sqrt'
    RECIPROCAL = 'reciprocal'
    RECIPROCAL_SQRT = 'reciprocal_sqrt'
    RECIPROCAL_EXPONENT = 'reciprocal_exponent'
    UNSIGNED_RECIPROCAL = 'unsigned_reciprocal'
    UNSIGNED_RECIPROCAL_SQRT = 'unsigned_reciprocal_sqrt'
    RECIPROCAL_STEP = 'reciprocal_step'
    RECIPROCAL_SQRT_STEP = 'reciprocal_sqrt_step'


_ESTIMATE_FRACTION_BITS = 8
_RPRES_INPUT_FRACTION_BITS = 11
_RPRES_RESULT_FRACTION_BITS = 12
_RECIPROCAL_NUMERATOR_BITS = 19
_RPRES_RECIPROCAL_NUMERATOR_BITS = 26
_RECIPROCAL_SQRT_NUMERATOR_BITS = 28
_RPRES_RECIPROCAL_SQRT_NUMERATOR_BITS = 39
_UNSIGNED_BITS = 32
_RECIPROCAL_ADDEND = 2
_RECIPROCAL_SQRT_ADDEND = 3
_NAN_CLASSES = ('qnan', 'snan')
_UNSIGNED_KINDS = (Kind.UNSIGNED_RECIPROCAL, Kind.UNSIGNED_RECIPROCAL_SQRT)
_STEP_KINDS = (Kind.RECIPROCAL_STEP, Kind.RECIPROCAL_SQRT_STEP)


def _default_nan(format_, fpcr):
    return format_.infinity(int(bool(fpcr & FPCR_AH))) | 1 << (format_.fraction_bits - 1)


def _table(scaled, square_root, increased_precision=False):
    input_bits = _RPRES_INPUT_FRACTION_BITS if increased_precision else _ESTIMATE_FRACTION_BITS
    unit = 1 << input_bits
    if square_root:
        if not unit // 2 <= scaled < unit * 2:
            raise ValueError('Reciprocal square-root table input outside its fixed-point range')
        midpoint = scaled * 2 + 1 if scaled < unit else ((scaled & ~1) + 1) * 2
        numerator_bits = (_RPRES_RECIPROCAL_SQRT_NUMERATOR_BITS if increased_precision
                          else _RECIPROCAL_SQRT_NUMERATOR_BITS)
        bound = isqrt(((1 << numerator_bits) - 1) // midpoint)
    else:
        if not unit <= scaled < unit * 2:
            raise ValueError('Reciprocal table input outside its fixed-point range')
        numerator_bits = (_RPRES_RECIPROCAL_NUMERATOR_BITS if increased_precision
                          else _RECIPROCAL_NUMERATOR_BITS)
        bound = (1 << numerator_bits) // (scaled * 2 + 1)
    return (bound + 1) // 2


def _unsigned(kind, bits):
    square_root = kind == Kind.UNSIGNED_RECIPROCAL_SQRT
    minimum = 1 << (_UNSIGNED_BITS - (2 if square_root else 1))
    if bits < minimum:
        return LaneResult((1 << _UNSIGNED_BITS) - 1)
    shift = _UNSIGNED_BITS - _ESTIMATE_FRACTION_BITS - 1
    return LaneResult(_table(bits >> shift, square_root) << shift)


def _sqrt(format_, fpcr, category, sign, value, status):
    if category == 'zero' or category == 'infinity' and not sign:
        return LaneResult(format_.signed_zero(sign) if category == 'zero' else format_.infinity(sign), status)
    if sign:
        return LaneResult(_default_nan(format_, fpcr), status | FPSR_INVALID)
    # The scaled radicand is an integer for every representable H/S/D input.
    exponent = floor_log_two(value) // 2
    quantum = power_two(exponent - format_.fraction_bits)
    radicand = value / (quantum * quantum)
    assert radicand.denominator == 1
    root = isqrt(radicand.numerator)
    remainder = radicand.numerator - root * root
    rounding = Rounding(fpcr >> FPCR_ROUNDING_SHIFT & FPCR_ROUNDING_MASK)
    increment = ((rounding == Rounding.TIES_EVEN and remainder > root) or
                 (rounding == Rounding.POSITIVE and remainder != 0))
    # A same-format positive root is normal and finite. Reuse the shared packer
    # on the exactly rounded dyadic value, adding the true root's inexact flag.
    result = round_finite((root + increment) * quantum, format_, fpcr, rounding)
    if category == 'denormal' and format_ != FORMATS[16] and fpcr & FPCR_AH:
        status |= FPSR_INPUT_DENORMAL
    return LaneResult(result.bits, status | (FPSR_INEXACT if remainder else 0))


def _reciprocal(format_, fpcr, bits, increased_precision):
    sign = bits & format_.signed_zero(1)
    fraction = bits & format_.fraction_mask
    exponent = bits >> format_.fraction_bits & format_.exponent_mask
    base_exponent = format_.bias * 2 - 1
    if exponent == 0 and fraction < 1 << (format_.fraction_bits - 2):
        rounding = Rounding(fpcr >> FPCR_ROUNDING_SHIFT & FPCR_ROUNDING_MASK)
        infinity = (rounding == Rounding.TIES_EVEN or
                    rounding == Rounding.POSITIVE and not sign or
                    rounding == Rounding.NEGATIVE and bool(sign))
        result = format_.infinity(0) if infinity else format_.infinity(0) - 1
        return LaneResult(sign | result, FPSR_OVERFLOW | FPSR_INEXACT)
    flush = fpcr & (FPCR_FZ16 if format_ == FORMATS[16] else FPCR_FZ)
    if flush and exponent >= base_exponent:
        return LaneResult(sign, FPSR_UNDERFLOW)
    if exponent == 0:
        if not fraction & 1 << (format_.fraction_bits - 1):
            exponent, fraction = -1, fraction << 2
        else:
            fraction <<= 1
        fraction &= format_.fraction_mask
    input_bits = _RPRES_INPUT_FRACTION_BITS if increased_precision else _ESTIMATE_FRACTION_BITS
    result_bits = _RPRES_RESULT_FRACTION_BITS if increased_precision else _ESTIMATE_FRACTION_BITS
    scaled = (1 << input_bits) | fraction >> (format_.fraction_bits - input_bits)
    significand = _table(scaled, False, increased_precision) << (format_.fraction_bits - result_bits)
    exponent = base_exponent - exponent
    encoded = (significand >> (1 - exponent) if exponent <= 0 else
               exponent << format_.fraction_bits | significand & format_.fraction_mask)
    return LaneResult(sign | encoded)


def _reciprocal_sqrt(format_, bits, increased_precision):
    fraction = bits & format_.fraction_mask
    exponent = bits >> format_.fraction_bits & format_.exponent_mask
    if exponent == 0:
        normalization = format_.fraction_bits - (fraction.bit_length() - 1)
        fraction = fraction << normalization & format_.fraction_mask
        exponent = 1 - normalization
    input_bits = _RPRES_INPUT_FRACTION_BITS if increased_precision else _ESTIMATE_FRACTION_BITS
    result_bits = _RPRES_RESULT_FRACTION_BITS if increased_precision else _ESTIMATE_FRACTION_BITS
    unit = 1 << input_bits
    scaled = (unit | fraction >> (format_.fraction_bits - input_bits) if exponent % 2 == 0 else
              unit // 2 | fraction >> (format_.fraction_bits - input_bits + 1))
    estimate = _table(scaled, True, increased_precision)
    exponent = (format_.bias * 3 - 1 - exponent) // 2
    return LaneResult(exponent << format_.fraction_bits |
                      (estimate - (1 << result_bits)) << (format_.fraction_bits - result_bits))


def _step(kind, format_, fpcr, left, right):
    # FPNeg uses the original AH control: a NaN sign is preserved under AH.
    category = unpack(left, format_, fpcr, input_exceptions=False)[0]
    if not (fpcr & FPCR_AH and category in _NAN_CLASSES):
        left ^= format_.signed_zero(1)
    operands = [unpack(bits, format_, fpcr) for bits in (left, right)]
    status = operands[0][3] | operands[1][3]
    nan_indices = [index for index, operand in enumerate(operands) if operand[0] in _NAN_CLASSES]
    if nan_indices:
        if fpcr & FPCR_AH and len(nan_indices) == 2:
            selected = 0
        else:
            selected = next((index for index in nan_indices if operands[index][0] == 'snan'), nan_indices[0])
        bits = convert_nan((left, right)[selected], format_, format_, fpcr)
        return LaneResult(bits, status | (FPSR_INVALID if any(op[0] == 'snan' for op in operands) else 0))
    infinite = [operand[0] == 'infinity' for operand in operands]
    zero = [operand[0] == 'zero' for operand in operands]
    square_root = kind == Kind.RECIPROCAL_SQRT_STEP
    addend = _RECIPROCAL_SQRT_ADDEND if square_root else _RECIPROCAL_ADDEND
    if infinite[0] and zero[1] or zero[0] and infinite[1]:
        value = Fraction(addend, 2 if square_root else 1)
    elif any(infinite):
        return LaneResult(format_.infinity(operands[0][1] ^ operands[1][1]), status)
    else:
        value = (addend + operands[0][2] * operands[1][2]) / (2 if square_root else 1)
    rounding = Rounding(fpcr >> FPCR_ROUNDING_SHIFT & FPCR_ROUNDING_MASK)
    if not value:
        return LaneResult(format_.signed_zero(int(rounding == Rounding.NEGATIVE)), status)
    result = round_finite(value, format_, fpcr, rounding)
    return LaneResult(result.bits, status | result.exceptions)


def evaluate_lane(kind, element_bits, fpcr, left, right=None, *, increased_precision=False):
    """Return exact bits/new status for one active lane; never simulate a trap.

    AH estimates/refinements suppress all fresh status and accept retained trap
    enables. SQRT retains its ordinary exception behavior under AH. Unsigned
    estimates require 32 bits and ignore every FP control. Increased precision
    models only Single+AH reciprocal/RSqrt estimates, independent of native support.
    """
    if not isinstance(kind, Kind) or element_bits not in FORMATS:
        raise ValueError('Expected a typed operation and 16, 32 or 64 bit element')
    if not 0 <= fpcr < 1 << 32 or not 0 <= left < 1 << element_bits:
        raise ValueError('Operand/control outside its bit width')
    if (kind in _STEP_KINDS) != (right is not None):
        raise ValueError('Only reciprocal refinement takes a second operand')
    if right is not None and not 0 <= right < 1 << element_bits:
        raise ValueError('Second operand outside its bit width')
    if increased_precision and not (element_bits == 32 and fpcr & FPCR_AH and
                                   kind in (Kind.RECIPROCAL, Kind.RECIPROCAL_SQRT)):
        raise ValueError('Increased precision requires Single+AH reciprocal estimate')
    if kind in _UNSIGNED_KINDS:
        if element_bits != _UNSIGNED_BITS:
            raise ValueError('Unsigned estimate requires a 32 bit element')
        return _unsigned(kind, left)
    suppressed = bool(fpcr & FPCR_AH) and kind != Kind.SQRT
    if not suppressed and fpcr & FP_EXCEPTION_ENABLE_MASK:
        raise UnsupportedFpControls('Enabled FP exceptions are unsupported before effects')
    controls = fpcr | FPCR_FIZ | FPCR_FZ if suppressed else fpcr
    if suppressed and kind in (Kind.RECIPROCAL, *_STEP_KINDS):
        controls &= ~(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT)
    format_ = FORMATS[element_bits]
    if kind in _STEP_KINDS:
        result = _step(kind, format_, controls, left, right)
    else:
        category, sign, value, status = unpack(left, format_, controls)
        if category in _NAN_CLASSES:
            result = LaneResult(convert_nan(left, format_, format_, controls),
                                status | (FPSR_INVALID if category == 'snan' else 0))
        elif kind == Kind.SQRT:
            result = _sqrt(format_, controls, category, sign, value, status)
        elif kind == Kind.RECIPROCAL_EXPONENT:
            exponent = left >> format_.fraction_bits & format_.exponent_mask
            exponent = format_.exponent_mask - 1 if not exponent else format_.exponent_mask ^ exponent
            result = LaneResult(format_.signed_zero(sign) | exponent << format_.fraction_bits, status)
        elif category == 'zero':
            result = LaneResult(format_.infinity(sign), status | FPSR_DIVIDE_BY_ZERO)
        elif kind == Kind.RECIPROCAL and category == 'infinity':
            result = LaneResult(format_.signed_zero(sign), status)
        elif kind == Kind.RECIPROCAL_SQRT and sign:
            result = LaneResult(_default_nan(format_, controls), status | FPSR_INVALID)
        elif category == 'infinity':
            result = LaneResult(0, status)
        else:
            result = (_reciprocal(format_, controls, left, increased_precision) if kind == Kind.RECIPROCAL else
                      _reciprocal_sqrt(format_, left, increased_precision))
            result = LaneResult(result.bits, result.exceptions | status)
    return LaneResult(result.bits, 0 if suppressed else result.exceptions)
