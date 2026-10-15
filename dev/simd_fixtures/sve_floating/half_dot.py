"""Exact Half FDOT and widening multiply-add models over original Z bytes."""

from dataclasses import dataclass
from enum import Enum

from .control import (
    FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT,
    FP_EXCEPTION_ENABLE_MASK, FPSR_INPUT_DENORMAL, FPSR_INVALID,
)
from .ieee import (
    FORMATS, LaneResult, Rounding, convert_nan, round_finite, unpack,
)

HALF = FORMATS[16]
SINGLE = FORMATS[32]
HALF_BYTES = HALF.bits // 8
SINGLE_BYTES = SINGLE.bits // 8
SEGMENT_BYTES = 16
MAXIMUM_VECTOR_BYTES = 256
NAN_CLASSES = ('snan', 'qnan')


class Kind(Enum):
    DOT = 'fdot'
    MULTIPLY_ADD_LONG = 'fmlal'
    MULTIPLY_SUBTRACT_LONG = 'fmlsl'


class UnsupportedControl(ValueError):
    """The shared execution profile must supply effective exception enables."""


@dataclass(frozen=True)
class Outcome:
    value: bytes
    fpsr: int
    exceptions: int


@dataclass(frozen=True)
class _Operand:
    bits: int
    format: object
    category: str
    sign: int
    value: object
    exceptions: int


def _operand(bits, format, fpcr):
    category, sign, value, exceptions = unpack(bits, format, fpcr)
    return _Operand(bits, format, category, sign, value, exceptions)


def _rounding(fpcr):
    return Rounding((fpcr >> FPCR_ROUNDING_SHIFT) & FPCR_ROUNDING_MASK)


def _default_nan(fpcr):
    return SINGLE.infinity(int(bool(fpcr & FPCR_AH))) | (1 << (SINGLE.fraction_bits - 1))


def _nan(operands, fpcr, *, alternative_priority=True):
    candidates = [op for op in operands if op.category in NAN_CLASSES]
    if not candidates:
        return None
    signaling = any(op.category == 'snan' for op in operands)
    if alternative_priority and fpcr & FPCR_AH and len(candidates) >= 2:
        selected = (operands[0] if len(operands) == 2 else
                    operands[1] if operands[1].category in NAN_CLASSES else operands[2])
    else:
        selected = next((op for op in operands if op.category == 'snan'), candidates[0])
    result = convert_nan(selected.bits, selected.format, SINGLE, fpcr)
    return LaneResult(result, FPSR_INVALID if signaling else 0)


def _rounded(value, fpcr):
    if not value:
        return LaneResult(SINGLE.signed_zero(_rounding(fpcr) == Rounding.NEGATIVE))
    return round_finite(value, SINGLE, fpcr, _rounding(fpcr))


def _add_single(left_bits, right_bits, fpcr):
    operands = [_operand(left_bits, SINGLE, fpcr), _operand(right_bits, SINGLE, fpcr)]
    left, right = operands
    status = left.exceptions | right.exceptions
    nan = _nan(operands, fpcr)
    if nan:
        return LaneResult(nan.bits, status | nan.exceptions)
    if left.category == right.category == 'infinity' and left.sign != right.sign:
        result = LaneResult(_default_nan(fpcr), FPSR_INVALID)
    elif left.category == 'infinity' or right.category == 'infinity':
        result = LaneResult(SINGLE.infinity(left.sign if left.category == 'infinity' else right.sign))
    elif left.category == right.category == 'zero' and left.sign == right.sign:
        result = LaneResult(SINGLE.signed_zero(left.sign))
    else:
        result = _rounded(left.value + right.value, fpcr)
    if fpcr & FPCR_AH and any(op.category == 'denormal' for op in operands):
        status |= FPSR_INPUT_DENORMAL
    return LaneResult(result.bits, status | result.exceptions)


def dot_lane(fpcr, addend, left, right):
    """FPDotAdd: fused two-product rounding, then separate accumulator add."""
    if fpcr & FP_EXCEPTION_ENABLE_MASK:
        raise UnsupportedControl('Retained FP exception enables require trap delivery')
    controls = fpcr & ~FPCR_AHP
    operands = [_operand(bits, HALF, controls) for bits in (*left, *right)]
    status = 0
    for operand in operands:
        status |= operand.exceptions
    result = _nan(operands, controls, alternative_priority=False)
    if result is None:
        pairs = [(operands[0], operands[2]), (operands[1], operands[3])]
        signs = [lhs.sign ^ rhs.sign for lhs, rhs in pairs]
        infinities = [lhs.category == 'infinity' or rhs.category == 'infinity' for lhs, rhs in pairs]
        zeros = [lhs.category == 'zero' or rhs.category == 'zero' for lhs, rhs in pairs]
        invalid = any({lhs.category, rhs.category} == {'infinity', 'zero'} for lhs, rhs in pairs)
        invalid |= all(infinities) and signs[0] != signs[1]
        if invalid:
            result = LaneResult(_default_nan(controls), FPSR_INVALID)
        elif any(infinities):
            result = LaneResult(SINGLE.infinity(signs[0] if infinities[0] else signs[1]))
        elif all(zeros) and signs[0] == signs[1]:
            result = LaneResult(SINGLE.signed_zero(signs[0]))
        else:
            result = _rounded(sum(lhs.value * rhs.value for lhs, rhs in pairs), controls)
    final = _add_single(addend, result.bits, fpcr)
    return LaneResult(final.bits, status | result.exceptions | final.exceptions)


def widening_lane(fpcr, addend, left, right, *, subtract=False):
    """FPMulAddH: classify original Half NaNs before one Single FMA rounding."""
    if fpcr & FP_EXCEPTION_ENABLE_MASK:
        raise UnsupportedControl('Retained FP exception enables require trap delivery')
    if subtract:
        is_nan = (left & HALF.infinity(0)) == HALF.infinity(0) and bool(left & HALF.fraction_mask)
        if not (fpcr & FPCR_AH and is_nan):
            left ^= HALF.signed_zero(1)
    accumulator = _operand(addend, SINGLE, fpcr)
    lhs, rhs = _operand(left, HALF, fpcr), _operand(right, HALF, fpcr)
    operands = [accumulator, lhs, rhs]
    status = accumulator.exceptions | lhs.exceptions | rhs.exceptions
    invalid_product = {lhs.category, rhs.category} == {'infinity', 'zero'}
    nan = _nan(operands, fpcr)
    if nan:
        if not fpcr & FPCR_AH and accumulator.category == 'qnan' and invalid_product:
            return LaneResult(_default_nan(fpcr), status | nan.exceptions | FPSR_INVALID)
        return LaneResult(nan.bits, status | nan.exceptions)
    sign_product = lhs.sign ^ rhs.sign
    infinite_product = lhs.category == 'infinity' or rhs.category == 'infinity'
    invalid = invalid_product or (accumulator.category == 'infinity' and infinite_product
                                  and accumulator.sign != sign_product)
    if invalid:
        result = LaneResult(_default_nan(fpcr), FPSR_INVALID)
    elif accumulator.category == 'infinity' or infinite_product:
        result = LaneResult(SINGLE.infinity(accumulator.sign if accumulator.category == 'infinity'
                                            else sign_product))
    elif (accumulator.category == 'zero' and (lhs.category == 'zero' or rhs.category == 'zero')
          and accumulator.sign == sign_product):
        result = LaneResult(SINGLE.signed_zero(sign_product))
    else:
        result = _rounded(accumulator.value + lhs.value * rhs.value, fpcr)
    if not invalid and fpcr & FPCR_AH and accumulator.category == 'denormal':
        status |= FPSR_INPUT_DENORMAL
    return LaneResult(result.bits, status | result.exceptions)


def evaluate(kind, destination, left, right, *, fpcr=0, fpsr=0, index=None, top=False):
    """Consume original equal active-VL bytes; indexed sources repeat per segment."""
    if not isinstance(kind, Kind):
        raise ValueError('Expected a typed Half dot or widening operation')
    length = len(destination)
    if not SEGMENT_BYTES <= length <= MAXIMUM_VECTOR_BYTES or length % SEGMENT_BYTES:
        raise ValueError('VL is 128..2048 bits in 128-bit steps')
    if len(left) != length or len(right) != length:
        raise ValueError('Original source/destination VLs must agree')
    if not 0 <= fpcr < 1 << 32 or not 0 <= fpsr < 1 << 32:
        raise ValueError('FP controls/status must fit32bits')
    if index is not None and (not isinstance(index, int) or not 0 <= index < (4 if kind == Kind.DOT else 8)):
        raise ValueError('Indexed Half group is outside128-bit segment')
    if top and kind == Kind.DOT:
        raise ValueError('FDOT has no top/bottom Half selector')
    result = bytearray(length)
    exceptions = 0
    read_half = lambda source, offset: int.from_bytes(source[offset:offset + HALF_BYTES], 'little')
    for offset in range(0, length, SINGLE_BYTES):
        addend = int.from_bytes(destination[offset:offset + SINGLE_BYTES], 'little')
        segment = offset - offset % SEGMENT_BYTES
        if kind == Kind.DOT:
            right_offset = offset if index is None else segment + index * SINGLE_BYTES
            lane = dot_lane(fpcr, addend,
                            (read_half(left, offset), read_half(left, offset + HALF_BYTES)),
                            (read_half(right, right_offset), read_half(right, right_offset + HALF_BYTES)))
        else:
            left_offset = offset + (HALF_BYTES if top else 0)
            right_offset = left_offset if index is None else segment + index * HALF_BYTES
            lane = widening_lane(fpcr, addend, read_half(left, left_offset), read_half(right, right_offset),
                                 subtract=kind == Kind.MULTIPLY_SUBTRACT_LONG)
        result[offset:offset + SINGLE_BYTES] = lane.bits.to_bytes(SINGLE_BYTES, 'little')
        exceptions |= lane.exceptions
    return Outcome(bytes(result), fpsr | exceptions, exceptions)
