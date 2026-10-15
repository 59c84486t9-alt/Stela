"""Scalable arithmetic lane selection and instruction-wide staged results.

Numerical scalar helpers own rounding, NaNs and fresh exception events. This
module owns source snapshots, predication, per-segment indices, reduction order
and sticky status. Buffers contain current VL only; the architectural setter
owns the selected policy for storage above VL. Effective FPCR is supplied by the
streaming-profile adapter without changing raw architectural storage.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .arithmetic_scalar import (
    BinaryOperation, FusedOperation, MinMaxOperation, SignOperation,
    binary_lane, fused_lane, minmax_lane, sign_lane,
)
from .arithmetic_estimate import Kind as EstimateKind, evaluate_lane
from .arithmetic_special import logb_lane, scale_lane, reduce_tree, pairwise_inputs, complex_inputs
from .ieee import FORMATS
from .control import FPCR_AH

BITS_PER_BYTE = 8
SEGMENT_BITS = 128
MIN_VECTOR_BYTES = SEGMENT_BITS // BITS_PER_BYTE
MAX_VECTOR_BYTES = 256
COMPLEX_COMPONENTS = 2
FP_CONTROL_BYTES = 4


class SpecialOperation(Enum):
    LOGB = 'logb'
    SCALE = 'scale'
    CLAMP = 'clamp'
    COMPLEX_ADD = 'complex_add'
    COMPLEX_MULTIPLY_ADD = 'complex_multiply_add'


class Layout(Enum):
    ELEMENTWISE = 'elementwise'
    INDEXED = 'indexed'
    PAIRWISE = 'pairwise'
    SCALAR_REDUCTION = 'scalar_reduction'
    QUAD_REDUCTION = 'quad_reduction'


@dataclass(frozen=True)
class ArithmeticSpec:
    operation: BinaryOperation | FusedOperation | MinMaxOperation | SignOperation | SpecialOperation | EstimateKind
    element_bits: int
    layout: Layout = Layout.ELEMENTWISE
    index: int | None = None
    rotation: int = 0

    def __post_init__(self):
        operation_types = (BinaryOperation, FusedOperation, MinMaxOperation,
                           SignOperation, SpecialOperation, EstimateKind)
        if not isinstance(self.operation, operation_types) or not isinstance(self.layout, Layout):
            raise ValueError('Arithmetic operation and layout must be typed')
        if self.element_bits not in FORMATS:
            raise ValueError('Arithmetic elements must contain 16, 32 or 64 bits')
        if self.layout in (Layout.PAIRWISE, Layout.SCALAR_REDUCTION, Layout.QUAD_REDUCTION):
            if self.operation != BinaryOperation.ADD and not isinstance(self.operation, MinMaxOperation):
                raise ValueError('Pairwise/reduction requires add or min/max')
        complex_ = self.operation in (SpecialOperation.COMPLEX_ADD,
                                      SpecialOperation.COMPLEX_MULTIPLY_ADD)
        if complex_:
            rotations = (90, 270) if self.operation == SpecialOperation.COMPLEX_ADD else (0, 90, 180, 270)
            if self.rotation not in rotations:
                raise ValueError('Unallocated complex rotation')
        elif self.rotation:
            raise ValueError('Rotation belongs to complex arithmetic')
        if self.layout == Layout.INDEXED:
            allowed = (BinaryOperation.MULTIPLY, SpecialOperation.COMPLEX_MULTIPLY_ADD)
            if self.operation not in allowed and not isinstance(self.operation, FusedOperation):
                raise ValueError('No indexed encoding for operation')
            if complex_ and self.element_bits == 64:
                raise ValueError('No indexed Double complex encoding')
            elements = SEGMENT_BITS // self.element_bits
            if complex_:
                elements //= COMPLEX_COMPONENTS
            if type(self.index) is not int or not 0 <= self.index < elements:
                raise ValueError('Index exceeds its 128-bit segment')
        elif self.index is not None:
            raise ValueError('Only indexed instructions accept an index')
        unsigned = (EstimateKind.UNSIGNED_RECIPROCAL, EstimateKind.UNSIGNED_RECIPROCAL_SQRT)
        if self.operation in unsigned and self.element_bits != 32:
            raise ValueError('Unsigned estimates require 32-bit integer lanes')


@dataclass(frozen=True)
class ImmediateSource:
    bits: int


@dataclass(frozen=True)
class VectorResult:
    destination: bytes
    fpsr: int


def _active(predicate, lane, element_bytes):
    if predicate is None:
        return True
    bit = lane * element_bytes
    return bool(predicate[bit // BITS_PER_BYTE] >> (bit % BITS_PER_BYTE) & 1)


def _source_count(operation):
    if isinstance(operation, (BinaryOperation, MinMaxOperation)):
        return 2
    if isinstance(operation, FusedOperation):
        return 3
    if operation in (SpecialOperation.SCALE, SpecialOperation.COMPLEX_ADD,
                     EstimateKind.RECIPROCAL_STEP, EstimateKind.RECIPROCAL_SQRT_STEP):
        return 2
    if operation in (SpecialOperation.CLAMP, SpecialOperation.COMPLEX_MULTIPLY_ADD):
        return 3
    return 1


def _lane(operation, element_bits, fpcr, values, *, rpres=False):
    if isinstance(operation, BinaryOperation):
        return binary_lane(operation, element_bits, fpcr, *values)
    if isinstance(operation, FusedOperation):
        return fused_lane(operation, element_bits, fpcr, *values)
    if isinstance(operation, MinMaxOperation):
        return minmax_lane(operation, element_bits, fpcr, *values)
    if isinstance(operation, SignOperation):
        return sign_lane(operation, element_bits, fpcr, *values)
    if isinstance(operation, EstimateKind):
        enhanced = (rpres and element_bits == 32 and fpcr & FPCR_AH != 0
                    and operation in (EstimateKind.RECIPROCAL, EstimateKind.RECIPROCAL_SQRT))
        return evaluate_lane(operation, element_bits, fpcr, *values, increased_precision=bool(enhanced))
    if operation == SpecialOperation.LOGB:
        return logb_lane(element_bits, fpcr, *values)
    if operation == SpecialOperation.SCALE:
        return scale_lane(element_bits, fpcr, *values)
    if operation == SpecialOperation.CLAMP:
        # The architectural order is MaxNum(lower, value), then MinNum(result, upper).
        lower, value, upper = values
        maximum = minmax_lane(MinMaxOperation.MAXIMUM_NUMBER, element_bits, fpcr, lower, value)
        minimum = minmax_lane(MinMaxOperation.MINIMUM_NUMBER, element_bits, fpcr, maximum.bits, upper)
        return type(minimum)(minimum.bits, maximum.exceptions | minimum.exceptions)
    raise ValueError('Complex arithmetic needs independent component selection')


def _identity(operation, element_bits, fpcr):
    if operation == BinaryOperation.ADD:
        return 0
    format_ = FORMATS[element_bits]
    if operation in (MinMaxOperation.MINIMUM_NUMBER, MinMaxOperation.MAXIMUM_NUMBER):
        return format_.infinity(int(bool(fpcr & FPCR_AH))) | 1 << (format_.fraction_bits - 1)
    return format_.infinity(0 if operation == MinMaxOperation.MINIMUM else 1)


def evaluate_vector(spec, sources, old_destination, predicate=None, *, fpcr=0, fpsr=0, rpres=False):
    """Sources have semantic order: binary(N,M), fused(A,N,M), clamp(lower,value,upper).

    Complex add takes (old destination, M), and complex MLA takes (A,N,M).
    Source/old-destination snapshots may alias freely. Any refused numerical
    control leaves caller inputs untouched; no partial result escapes.
    """
    if not isinstance(spec, ArithmeticSpec):
        raise ValueError('Expected a typed arithmetic specification')
    old_destination = bytes(old_destination)
    sources = tuple(bytes(source) for source in sources)
    length = len(old_destination)
    if not MIN_VECTOR_BYTES <= length <= MAX_VECTOR_BYTES or length & (length - 1):
        raise ValueError('Streaming arithmetic requires 16..256 byte power-of-two lengths')
    if any(len(source) != length for source in sources):
        raise ValueError('Source and destination lengths differ')
    reduction = spec.layout in (Layout.SCALAR_REDUCTION, Layout.QUAD_REDUCTION)
    expected_sources = 1 if reduction else _source_count(spec.operation)
    if len(sources) != expected_sources:
        raise ValueError('Source count differs from operation')
    if predicate is not None:
        predicate = bytes(predicate)
        if len(predicate) * BITS_PER_BYTE != length:
            raise ValueError('Predicate contains one bit per vector byte')
    if not 0 <= fpcr < 1 << 32 or not 0 <= fpsr < 1 << 32:
        raise ValueError('FP control/status outside its bit width')
    if type(rpres) is not bool:
        raise ValueError('RPRES availability must be a declared boolean capability')
    element_bytes = spec.element_bits // BITS_PER_BYTE
    count = length // element_bytes
    lanes = tuple(tuple(int.from_bytes(source[offset:offset + element_bytes], 'little')
                        for offset in range(0, length, element_bytes)) for source in sources)
    result = bytearray(length if reduction else old_destination)

    def combine(left, right):
        nonlocal fpsr
        outcome = _lane(spec.operation, spec.element_bits, fpcr, (left, right), rpres=rpres)
        fpsr |= outcome.exceptions
        return outcome.bits

    def store(lane, value):
        offset = lane * element_bytes
        result[offset:offset + element_bytes] = value.to_bytes(element_bytes, 'little')

    if reduction:
        identity = _identity(spec.operation, spec.element_bits, fpcr)
        values = [value if _active(predicate, lane, element_bytes) else identity
                  for lane, value in enumerate(lanes[0])]
        positions = 1 if spec.layout == Layout.SCALAR_REDUCTION else SEGMENT_BITS // spec.element_bits
        for position in range(positions):
            store(position, reduce_tree(values[position::positions], combine))
        return VectorResult(bytes(result), fpsr)

    complex_add = spec.operation == SpecialOperation.COMPLEX_ADD
    complex_mla = spec.operation == SpecialOperation.COMPLEX_MULTIPLY_ADD
    for lane in range(count):
        if not _active(predicate, lane, element_bytes):
            continue
        if spec.layout == Layout.PAIRWISE:
            source, first, second = pairwise_inputs(lane)
            selected = lanes[0 if source == 'old_destination' else 1]
            values = (selected[first], selected[second])
        elif complex_add:
            opposite = lane ^ 1
            right = lanes[1][opposite]
            if (lane % COMPLEX_COMPONENTS == 0) == (spec.rotation == 90):
                right = sign_lane(SignOperation.NEGATE, spec.element_bits, fpcr, right).bits
            outcome = binary_lane(BinaryOperation.ADD, spec.element_bits, fpcr, lanes[0][lane], right)
            fpsr |= outcome.exceptions
            store(lane, outcome.bits)
            continue
        elif complex_mla:
            component = lane % COMPLEX_COMPONENTS
            left, right, negate = complex_inputs(lane // COMPLEX_COMPONENTS, spec.rotation // 90,
                                                 index=spec.index, element_bits=spec.element_bits)[component]
            multiplier = lanes[2][right]
            if negate:
                multiplier = sign_lane(SignOperation.NEGATE, spec.element_bits, fpcr, multiplier).bits
            outcome = fused_lane(FusedOperation.ADD, spec.element_bits, fpcr,
                                 lanes[0][lane], lanes[1][left], multiplier)
            fpsr |= outcome.exceptions
            store(lane, outcome.bits)
            continue
        else:
            values = [source[lane] for source in lanes]
            if spec.layout == Layout.INDEXED:
                segment_elements = SEGMENT_BITS // spec.element_bits
                index = lane - lane % segment_elements + spec.index
                values[-1] = lanes[-1][index]
        outcome = _lane(spec.operation, spec.element_bits, fpcr, values, rpres=rpres)
        fpsr |= outcome.exceptions
        store(lane, outcome.bits)
    return VectorResult(bytes(result), fpsr)


def model_snapshot(spec, source_registers, destination, predicate_register, initial, *, full_a64=False, rpres=False):
    """Apply a typed fixture to the shared full-state wire snapshot.

    The adapter reads captured controls rather than requested controls. An oracle
    that changed FPCR during setup remains a separate policy observation.
    """
    from dataclasses import replace
    from scalable_frame import (
        Component, FIXED_VECTOR_BYTES, PRIMARY_FPCR_OFFSET, PRIMARY_FPSR_OFFSET,
        PRIMARY_VECTOR_OFFSET, Provenance, SVCR_SM,
    )
    from .control import effective_fpcr
    required = Component.PRIMARY | Component.Z | Component.SVCR
    if predicate_register is not None:
        required |= Component.P
    if initial.valid & required != required:
        raise ValueError('Snapshot is missing required architectural components')
    sources = tuple(source_registers)
    registers = tuple(source for source in sources if not isinstance(source, ImmediateSource))
    if any(type(register) is not int or not 0 <= register < len(initial.z)
           for register in (*registers, destination)):
        raise ValueError('Vector register outside the architectural bank')
    source_bytes = []
    element_bytes = spec.element_bits // BITS_PER_BYTE
    for source in sources:
        if isinstance(source, ImmediateSource):
            if type(source.bits) is not int or not 0 <= source.bits < 1 << spec.element_bits:
                raise ValueError('Immediate exceeds its floating lane')
            source_bytes.append(source.bits.to_bytes(element_bytes, 'little') * (initial.svl_bytes // element_bytes))
        else:
            source_bytes.append(initial.z[source])
    if predicate_register is not None and (type(predicate_register) is not int
            or not 0 <= predicate_register < len(initial.p)):
        raise ValueError('Predicate register outside the architectural bank')
    fpcr = int.from_bytes(initial.primary[PRIMARY_FPCR_OFFSET:PRIMARY_FPCR_OFFSET + FP_CONTROL_BYTES], 'little')
    fpsr = int.from_bytes(initial.primary[PRIMARY_FPSR_OFFSET:PRIMARY_FPSR_OFFSET + FP_CONTROL_BYTES], 'little')
    effective = effective_fpcr(fpcr, streaming=bool(initial.control('svcr') & SVCR_SM),
                               full_a64=full_a64)
    predicate = None if predicate_register is None else initial.p[predicate_register]
    outcome = evaluate_vector(spec, tuple(source_bytes), initial.z[destination], predicate,
                              fpcr=effective, fpsr=fpsr, rpres=rpres)
    z = list(initial.z)
    z[destination] = outcome.destination
    primary = bytearray(initial.primary)
    vector_offset = PRIMARY_VECTOR_OFFSET + destination * FIXED_VECTOR_BYTES
    primary[vector_offset:vector_offset + FIXED_VECTOR_BYTES] = outcome.destination[:FIXED_VECTOR_BYTES]
    primary[PRIMARY_FPSR_OFFSET:PRIMARY_FPSR_OFFSET + FP_CONTROL_BYTES] = outcome.fpsr.to_bytes(FP_CONTROL_BYTES, 'little')
    return replace(initial, primary=bytes(primary), z=tuple(z), provenance=Provenance.MODEL)
