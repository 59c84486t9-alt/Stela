"""Exact active-lane SVE arithmetic using the shared integer/Fraction FP engine.

Controls are effective FPCR supplied by the streaming adapter. Results contain
fresh FPSR bits; vector selection, sticky accumulation and trap delivery belong
to the caller. AHP and NEP do not affect these scalar numerical operations.
"""

from dataclasses import dataclass
from enum import Enum
from fractions import Fraction

from .control import (
    FPCR_AH, FPCR_DN, FPCR_FZ, FPCR_FZ16,
    FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, FP_EXCEPTION_ENABLE_MASK,
    FPSR_DIVIDE_BY_ZERO, FPSR_INPUT_DENORMAL, FPSR_INVALID,
    FPSR_UNDERFLOW, FPSR_INEXACT,
)
from .conversion import UnsupportedFpControls
from .ieee import FORMATS, LaneResult, Rounding, round_finite, unpack


class BinaryOperation(Enum):
    ADD = 'add'
    SUBTRACT = 'subtract'
    MULTIPLY = 'multiply'
    DIVIDE = 'divide'
    ABSOLUTE_DIFFERENCE = 'absolute_difference'
    MULTIPLY_EXTENDED = 'multiply_extended'


class FusedOperation(Enum):
    ADD = 'add'
    SUBTRACT = 'subtract'
    NEGATED_ADD = 'negated_add'
    NEGATED_SUBTRACT = 'negated_subtract'


class MinMaxOperation(Enum):
    MINIMUM = 'minimum'
    MAXIMUM = 'maximum'
    MINIMUM_NUMBER = 'minimum_number'
    MAXIMUM_NUMBER = 'maximum_number'


class SignOperation(Enum):
    ABSOLUTE = 'absolute'
    NEGATE = 'negate'


_NAN_CLASSES = ('qnan', 'snan')


@dataclass(frozen=True)
class _Operand:
    bits: int
    category: str
    sign: int
    value: Fraction
    status: int


def _validate(operation, operation_type, element_bits, fpcr, operands, *, numerical=True):
    if not isinstance(operation, operation_type):
        raise ValueError('Arithmetic operation must be typed')
    if element_bits not in FORMATS:
        raise ValueError('Arithmetic requires 16, 32 or 64 bit elements')
    if (not 0 <= fpcr < 1 << 32
            or any(not 0 <= bits < 1 << element_bits for bits in operands)):
        raise ValueError('Operand/control outside its bit width')
    if numerical and fpcr & FP_EXCEPTION_ENABLE_MASK:
        raise UnsupportedFpControls('Enabled FP exceptions are unsupported before effects')
    return FORMATS[element_bits]


def _operand(bits, format_, fpcr):
    category, sign, value, status = unpack(bits, format_, fpcr)
    if category == 'zero':
        bits = format_.signed_zero(sign)
    return _Operand(bits, category, sign, value, status)


def _default_nan(format_, fpcr):
    return format_.infinity(int(bool(fpcr & FPCR_AH))) | 1 << (format_.fraction_bits - 1)


def _nan(format_, fpcr, operands):
    nans = [operand for operand in operands if operand.category in _NAN_CLASSES]
    if not nans:
        return None
    status = FPSR_INVALID if any(operand.category == 'snan' for operand in nans) else 0
    if fpcr & FPCR_AH and len(nans) >= 2:
        # FPProcessNaNs3 prioritizes N then M; FPProcessNaNs prioritizes N.
        candidates = operands[1:] if len(operands) == 3 else operands
        selected = next(operand for operand in candidates if operand.category in _NAN_CLASSES)
    else:
        selected = next((operand for operand in nans if operand.category == 'snan'), nans[0])
    bits = (_default_nan(format_, fpcr) if fpcr & FPCR_DN else
            selected.bits | 1 << (format_.fraction_bits - 1))
    return LaneResult(bits, status)


def _denormals(format_, fpcr, operands):
    return (FPSR_INPUT_DENORMAL if format_ != FORMATS[16] and fpcr & FPCR_AH
            and any(operand.category == 'denormal' for operand in operands) else 0)


def _rounded(value, format_, fpcr, zero_sign=None):
    rounding = Rounding(fpcr >> FPCR_ROUNDING_SHIFT & FPCR_ROUNDING_MASK)
    if not value:
        sign = int(rounding == Rounding.NEGATIVE) if zero_sign is None else zero_sign
        return LaneResult(format_.signed_zero(sign))
    return round_finite(value, format_, fpcr, rounding)


def sign_lane(operation, element_bits, fpcr, bits):
    """FPAbs/FPNeg preserve raw NaN signs under AH and never raise exceptions."""
    format_ = _validate(operation, SignOperation, element_bits, fpcr, (bits,), numerical=False)
    category, _, _, _ = unpack(bits, format_, fpcr, input_exceptions=False)
    if fpcr & FPCR_AH and category in _NAN_CLASSES:
        return LaneResult(bits)
    sign_mask = format_.signed_zero(1)
    result = bits & ~sign_mask if operation == SignOperation.ABSOLUTE else bits ^ sign_mask
    return LaneResult(result)


def binary_lane(operation, element_bits, fpcr, left, right):
    """Evaluate one binary operation; absolute difference transforms its result."""
    format_ = _validate(operation, BinaryOperation, element_bits, fpcr, (left, right))
    left, right = (_operand(bits, format_, fpcr) for bits in (left, right))
    status = left.status | right.status
    result = _nan(format_, fpcr, (left, right))
    if result is None:
        inf_left, inf_right = left.category == 'infinity', right.category == 'infinity'
        zero_left, zero_right = left.category == 'zero', right.category == 'zero'
        negative = left.sign ^ right.sign
        if operation in (BinaryOperation.ADD, BinaryOperation.SUBTRACT,
                         BinaryOperation.ABSOLUTE_DIFFERENCE):
            right_sign = right.sign ^ (operation != BinaryOperation.ADD)
            if inf_left and inf_right and left.sign != right_sign:
                result = LaneResult(_default_nan(format_, fpcr), FPSR_INVALID)
            elif inf_left or inf_right:
                result = LaneResult(format_.infinity(left.sign if inf_left else right_sign))
            else:
                value = (left.value + right.value if operation == BinaryOperation.ADD
                         else left.value - right.value)
                same_zero_sign = left.sign if zero_left and zero_right and left.sign == right_sign else None
                result = _rounded(value, format_, fpcr, same_zero_sign)
        elif operation in (BinaryOperation.MULTIPLY, BinaryOperation.MULTIPLY_EXTENDED):
            if (inf_left and zero_right) or (zero_left and inf_right):
                if operation == BinaryOperation.MULTIPLY_EXTENDED:
                    two = (format_.bias + 1) << format_.fraction_bits
                    result = LaneResult(two | format_.signed_zero(negative))
                else:
                    result = LaneResult(_default_nan(format_, fpcr), FPSR_INVALID)
            elif inf_left or inf_right:
                result = LaneResult(format_.infinity(negative))
            elif zero_left or zero_right:
                result = LaneResult(format_.signed_zero(negative))
            else:
                result = _rounded(left.value * right.value, format_, fpcr)
        else:
            if (inf_left and inf_right) or (zero_left and zero_right):
                result = LaneResult(_default_nan(format_, fpcr), FPSR_INVALID)
            elif inf_left or zero_right:
                result = LaneResult(format_.infinity(negative), 0 if inf_left else FPSR_DIVIDE_BY_ZERO)
            elif zero_left or inf_right:
                result = LaneResult(format_.signed_zero(negative))
            else:
                result = _rounded(left.value / right.value, format_, fpcr)
        if operation != BinaryOperation.DIVIDE or not zero_right:
            status |= _denormals(format_, fpcr, (left, right))
    if operation == BinaryOperation.ABSOLUTE_DIFFERENCE:
        absolute = sign_lane(SignOperation.ABSOLUTE, element_bits, fpcr, result.bits)
        result = LaneResult(absolute.bits, result.exceptions)
    return LaneResult(result.bits, status | result.exceptions)


def fused_lane(operation, element_bits, fpcr, addend, left, right):
    """Evaluate A + N*M after architectural FPNeg transforms, rounding once."""
    format_ = _validate(operation, FusedOperation, element_bits, fpcr, (addend, left, right))
    if operation in (FusedOperation.NEGATED_ADD, FusedOperation.NEGATED_SUBTRACT):
        addend = sign_lane(SignOperation.NEGATE, element_bits, fpcr, addend).bits
    if operation in (FusedOperation.SUBTRACT, FusedOperation.NEGATED_ADD):
        left = sign_lane(SignOperation.NEGATE, element_bits, fpcr, left).bits
    addend, left, right = (_operand(bits, format_, fpcr) for bits in (addend, left, right))
    operands = (addend, left, right)
    status = addend.status | left.status | right.status
    inf_left, inf_right = left.category == 'infinity', right.category == 'infinity'
    zero_left, zero_right = left.category == 'zero', right.category == 'zero'
    invalid_product = inf_left and zero_right or zero_left and inf_right
    result = _nan(format_, fpcr, operands)
    if result is not None:
        if not fpcr & FPCR_AH and addend.category == 'qnan' and invalid_product:
            result = LaneResult(_default_nan(format_, fpcr), result.exceptions | FPSR_INVALID)
        return LaneResult(result.bits, result.exceptions | status)
    product_sign = left.sign ^ right.sign
    product_infinite = inf_left or inf_right
    if (invalid_product or addend.category == 'infinity'
            and product_infinite and addend.sign != product_sign):
        return LaneResult(_default_nan(format_, fpcr), status | FPSR_INVALID)
    if addend.category == 'infinity' or product_infinite:
        sign = addend.sign if addend.category == 'infinity' else product_sign
        result = LaneResult(format_.infinity(sign))
    else:
        same_zero_sign = (addend.sign if addend.category == 'zero' and (zero_left or zero_right)
                          and addend.sign == product_sign else None)
        result = _rounded(addend.value + left.value * right.value, format_, fpcr, same_zero_sign)
    return LaneResult(result.bits, result.exceptions | status | _denormals(format_, fpcr, operands))


def _ordering(left, right):
    if left.category == right.category == 'zero':
        return 0
    if left.sign != right.sign:
        return -1 if left.sign else 1
    order = (left.bits > right.bits) - (left.bits < right.bits)
    return -order if left.sign else order


def minmax_lane(operation, element_bits, fpcr, left, right):
    """FPMin/Max and number variants retain distinct AH early-return behavior."""
    format_ = _validate(operation, MinMaxOperation, element_bits, fpcr, (left, right))
    minimum = operation in (MinMaxOperation.MINIMUM, MinMaxOperation.MINIMUM_NUMBER)
    number = operation in (MinMaxOperation.MINIMUM_NUMBER, MinMaxOperation.MAXIMUM_NUMBER)
    left, right = (_operand(bits, format_, fpcr) for bits in (left, right))
    status = left.status | right.status
    if fpcr & FPCR_AH and not number:
        if left.category == right.category == 'zero' and left.sign != right.sign:
            return LaneResult(right.bits, status)
        if left.category in _NAN_CLASSES or right.category in _NAN_CLASSES:
            return LaneResult(right.bits, status | FPSR_INVALID)
    both_nan = left.category in _NAN_CLASSES and right.category in _NAN_CLASSES
    if number and not (fpcr & FPCR_AH and both_nan):
        replacement = _operand(format_.infinity(int(not minimum)), format_, fpcr)
        if left.category == 'qnan' and right.category != 'qnan':
            left = replacement
        elif left.category != 'qnan' and right.category == 'qnan':
            right = replacement
    result = _nan(format_, fpcr, (left, right))
    if result is not None:
        return LaneResult(result.bits, status | result.exceptions)
    selected = left if _ordering(left, right) == (-1 if minimum else 1) else right
    if selected.category == 'zero':
        bits = (left.bits | right.bits if minimum else left.bits & right.bits) & format_.signed_zero(1)
    elif (selected.category == 'denormal' and fpcr & FPCR_AH and number
          and fpcr & (FPCR_FZ16 if element_bits == 16 else FPCR_FZ)):
        bits = format_.signed_zero(selected.sign)
        status |= FPSR_UNDERFLOW | FPSR_INEXACT
    else:
        bits = selected.bits
    return LaneResult(bits, status | _denormals(format_, fpcr, (left, right)))
