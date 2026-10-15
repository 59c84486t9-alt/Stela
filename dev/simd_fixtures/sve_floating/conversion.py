"""Exact SVE conversion models, independent of a streaming-state ABI.

Numerical rules follow the pinned June 2026 Arm FPConvertSVE, FPToFixed,
FixedToFP and FPConvertBF helpers. Values use integer fields and Fraction;
Python/host floating point is never part of the oracle. FPCR arguments are
EFFECTIVE controls: the central execution profile must mask retained exception
enables for streaming without FA64 before calling these models, while preserving
the raw architectural FPCR. Remaining enables explicitly refuse before effects,
except FPConvertBF under AH, which suppresses numerical exceptions itself. This
model does not simulate trap delivery. Vector buffers contain current VL
only; the architectural setter owns the disposition of storage above VL.
"""

from dataclasses import dataclass
from enum import Enum
from fractions import Fraction

from .ieee import (
    BFLOAT, FORMATS, Format, LaneResult, Rounding,
    convert_nan, floor_log_two, power_two, round_finite, unpack,
)


from .control import (
    FPCR_AH, FPCR_AHP, FPCR_DN, FPCR_FIZ, FPCR_FZ, FPCR_FZ16,
    FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, FP_EXCEPTION_ENABLE_MASK,
    FPSR_INVALID, FPSR_OVERFLOW, FPSR_UNDERFLOW, FPSR_INEXACT,
    FPSR_INPUT_DENORMAL,
)


BITS_PER_BYTE = 8
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256
IMMEDIATE_BITS = 8
IMMEDIATE_FRACTION_BITS = 4
IMMEDIATE_EXPONENT_LOW_BITS = 2
IMMEDIATE_EXPONENT_SELECTOR_BIT = 6


class UnsupportedFpControls(ValueError):
    """Retained exception enables require a real trap-delivery boundary."""


class Kind(Enum):
    PRECISION = 'precision'
    PRECISION_ODD = 'precision_odd'
    SIGNED_TO_FP = 'signed_to_fp'
    UNSIGNED_TO_FP = 'unsigned_to_fp'
    FP_TO_SIGNED = 'fp_to_signed'
    FP_TO_UNSIGNED = 'fp_to_unsigned'
    BFLOAT = 'bfloat'


class Layout(Enum):
    UNPACKED = 'unpacked'
    WIDEN_TOP = 'widen_top'
    NARROW_TOP = 'narrow_top'


@dataclass(frozen=True)
class ConversionSpec:
    kind: Kind
    source_bits: int
    destination_bits: int
    layout: Layout = Layout.UNPACKED
    merging: bool = True

    def __post_init__(self):
        if not isinstance(self.kind, Kind) or not isinstance(self.layout, Layout):
            raise ValueError('Conversion kind and layout must be typed')
        if self.source_bits not in FORMATS or self.destination_bits not in FORMATS:
            raise ValueError('SVE conversions require 16, 32 or 64 bit operands')
        if self.kind == Kind.BFLOAT and (self.source_bits, self.destination_bits) != (32, 16):
            raise ValueError('BFCVT requires Single to BF16')
        if self.kind == Kind.PRECISION_ODD and (self.source_bits, self.destination_bits) != (64, 32):
            raise ValueError('FCVTX requires Double to Single')
        if self.layout == Layout.WIDEN_TOP:
            if self.kind != Kind.PRECISION or self.destination_bits != 2 * self.source_bits:
                raise ValueError('FCVTLT requires adjacent precision widening')
        if self.layout == Layout.NARROW_TOP:
            if self.kind not in (Kind.PRECISION, Kind.PRECISION_ODD, Kind.BFLOAT):
                raise ValueError('Top narrowing is a floating precision operation')
            if self.source_bits != 2 * self.destination_bits:
                raise ValueError('Top narrowing requires adjacent widths')


@dataclass(frozen=True)
class VectorResult:
    destination: bytes
    fpsr: int
    exceptions: int
    active_lanes: int


def conversion_lane(bits, source_bits, destination_bits, kind, fpcr=0):
    """Return bits/new flags for one active lane, with profile-effective FPCR."""
    if not isinstance(kind, Kind):
        raise ValueError('Conversion kind must be typed')
    if source_bits not in FORMATS or destination_bits not in FORMATS:
        raise ValueError('Invalid conversion width')
    if not 0 <= bits < 1 << source_bits or not 0 <= fpcr < 1 << 32:
        raise ValueError('Operand/control outside its bit width')
    if fpcr & FP_EXCEPTION_ENABLE_MASK and not (kind == Kind.BFLOAT and fpcr & FPCR_AH):
        raise UnsupportedFpControls('Enabled FP exceptions are unsupported before effects')
    source, output = FORMATS[source_bits], FORMATS[destination_bits]
    rounding = Rounding(fpcr >> FPCR_ROUNDING_SHIFT & FPCR_ROUNDING_MASK)
    if kind in (Kind.SIGNED_TO_FP, Kind.UNSIGNED_TO_FP):
        integer = bits
        if kind == Kind.SIGNED_TO_FP and integer >> (source_bits - 1):
            integer -= 1 << source_bits
        return round_finite(Fraction(integer), output, fpcr & ~FPCR_AHP, rounding)
    precision = kind in (Kind.PRECISION, Kind.PRECISION_ODD)
    bfloat = kind == Kind.BFLOAT
    if bfloat:
        if (source_bits, destination_bits) != (32, 16):
            raise ValueError('BFCVT requires Single to BF16')
        output = BFLOAT
        if fpcr & FPCR_AH:
            fpcr |= FPCR_FIZ | FPCR_FZ
            rounding = Rounding.TIES_EVEN
    if kind == Kind.PRECISION_ODD:
        if (source_bits, destination_bits) != (64, 32):
            raise ValueError('FCVTX requires Double to Single')
        rounding = Rounding.ODD
    controls = fpcr & ~FPCR_AHP
    if precision:
        controls &= ~FPCR_FZ16
    input_exceptions = not (fpcr & FPCR_AH and not precision)
    category, sign, value, status = unpack(bits, source, controls,
                                          ignore_half_flush=precision, input_exceptions=input_exceptions)
    if kind in (Kind.FP_TO_SIGNED, Kind.FP_TO_UNSIGNED):
        unsigned = kind == Kind.FP_TO_UNSIGNED
        minimum = 0 if unsigned else -(1 << (destination_bits - 1))
        maximum = (1 << (destination_bits - (not unsigned))) - 1
        if category in ('qnan', 'snan'):
            return LaneResult(0, status | FPSR_INVALID)
        if category == 'infinity':
            integer = minimum if sign else maximum
            return LaneResult(integer & ((1 << destination_bits) - 1), status | FPSR_INVALID)
        integer = abs(value.numerator) // value.denominator
        integer = -integer if value < 0 else integer
        invalid = not minimum <= integer <= maximum
        integer = max(minimum, min(maximum, integer))
        status |= FPSR_INVALID if invalid else FPSR_INEXACT if value != integer else 0
        return LaneResult(integer & ((1 << destination_bits) - 1), status)
    if category in ('qnan', 'snan'):
        result = convert_nan(bits, source, output, controls)
        status |= FPSR_INVALID if category == 'snan' else 0
    elif category == 'infinity':
        result = output.infinity(sign)
    elif category == 'zero':
        result = output.signed_zero(sign)
    else:
        rounded = round_finite(value, output, controls, rounding)
        result, status = rounded.bits, status | rounded.exceptions
        if precision and source_bits != 16 and fpcr & FPCR_AH and category == 'denormal':
            status |= FPSR_INPUT_DENORMAL
    if bfloat and fpcr & FPCR_AH:
        status = 0
    return LaneResult(result, status)


def evaluate_vector(spec, source, old_destination, predicate, fpcr=0, fpsr=0):
    """Snapshot bytes; predicate bit positions are architectural byte positions.

    An inactive top-narrowing slot always preserves its low half. Zeroing only
    clears that slot's high half, matching FCVTNT/FCVTXNT/BFCVTNT.
    """
    if not isinstance(spec, ConversionSpec):
        raise ValueError('Expected a typed conversion specification')
    source, old_destination, predicate = bytes(source), bytes(old_destination), bytes(predicate)
    size = len(source)
    if size != len(old_destination) or not MIN_VECTOR_BYTES <= size <= MAX_VECTOR_BYTES or size % MIN_VECTOR_BYTES:
        raise ValueError('Vector length must be 128..2048 bits in 128 bit steps')
    if len(predicate) * BITS_PER_BYTE != size:
        raise ValueError('Predicate must contain one bit per vector byte')
    if not 0 <= fpsr < 1 << 32:
        raise ValueError('FPSR outside its bit width')
    if not 0 <= fpcr < 1 << 32:
        raise ValueError('FPCR outside its bit width')
    slot_bits = max(spec.source_bits, spec.destination_bits)
    slot_bytes = slot_bits // BITS_PER_BYTE
    source_bytes = spec.source_bits // BITS_PER_BYTE
    destination_bytes = spec.destination_bits // BITS_PER_BYTE
    top = spec.layout == Layout.NARROW_TOP
    result = bytearray(old_destination if spec.merging or top else bytes(size))
    exceptions = active_lanes = 0
    for offset in range(0, size, slot_bytes):
        active = predicate[offset // BITS_PER_BYTE] >> (offset % BITS_PER_BYTE) & 1
        destination_offset = offset + destination_bytes if top else offset
        if not active:
            if top and not spec.merging:
                result[destination_offset:destination_offset + destination_bytes] = bytes(destination_bytes)
            continue
        source_offset = offset + source_bytes if spec.layout == Layout.WIDEN_TOP else offset
        bits = int.from_bytes(source[source_offset:source_offset + source_bytes], 'little')
        lane = conversion_lane(bits, spec.source_bits, spec.destination_bits, spec.kind, fpcr)
        active_lanes += 1
        exceptions |= lane.exceptions
        encoded = lane.bits
        width = destination_bytes if top else slot_bytes
        if spec.kind == Kind.FP_TO_SIGNED and encoded >> (spec.destination_bits - 1):
            encoded |= ((1 << slot_bits) - 1) ^ ((1 << spec.destination_bits) - 1)
        result[destination_offset:destination_offset + width] = encoded.to_bytes(width, 'little')
    return VectorResult(bytes(result), fpsr | exceptions, exceptions, active_lanes)


def expand_immediate(immediate, element_bits):
    """VFPExpandImm fields for FCPY/FDUP; no floating-point controls apply."""
    if not 0 <= immediate < 1 << IMMEDIATE_BITS or element_bits not in FORMATS:
        raise ValueError('Invalid FP immediate or element width')
    output = FORMATS[element_bits]
    selector = immediate >> IMMEDIATE_EXPONENT_SELECTOR_BIT & 1
    exponent = ((1 - selector) << (output.exponent_bits - 1) |
                (((1 << (output.exponent_bits - 3)) - 1) * selector) << IMMEDIATE_EXPONENT_LOW_BITS |
                immediate >> IMMEDIATE_FRACTION_BITS & 3)
    fraction = (immediate & ((1 << IMMEDIATE_FRACTION_BITS) - 1)) << (output.fraction_bits - IMMEDIATE_FRACTION_BITS)
    sign = immediate >> (IMMEDIATE_BITS - 1)
    return output.signed_zero(sign) | exponent << output.fraction_bits | fraction


def copy_immediate(old_destination, element_bits, immediate, predicate=None):
    """FCPY when predicate is supplied, otherwise unpredicated FDUP."""
    old_destination = bytes(old_destination)
    size = len(old_destination)
    if not MIN_VECTOR_BYTES <= size <= MAX_VECTOR_BYTES or size % MIN_VECTOR_BYTES:
        raise ValueError('Vector length must be 128..2048 bits in 128 bit steps')
    encoded = expand_immediate(immediate, element_bits)
    element_bytes = element_bits // BITS_PER_BYTE
    encoded = encoded.to_bytes(element_bytes, 'little')
    if predicate is not None:
        predicate = bytes(predicate)
        if len(predicate) * BITS_PER_BYTE != size:
            raise ValueError('Predicate must contain one bit per vector byte')
    result = bytearray(old_destination)
    for offset in range(0, size, element_bytes):
        if predicate is None or predicate[offset // BITS_PER_BYTE] >> (offset % BITS_PER_BYTE) & 1:
            result[offset:offset + element_bytes] = encoded
    return bytes(result)
