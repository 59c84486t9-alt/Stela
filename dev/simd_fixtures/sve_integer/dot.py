"""Pure SVE integer dot models; no GuestState or execution ABI dependencies.

The June 2026 canonical Apple candidate forms are separate from matrix/ZA forms.
All operands are original active-VL bytes, including aliased destination sources.
FDOT and floating widening MLA deliberately belong to another model module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterator, Sequence


BYTE_BITS = 8
SEGMENT_BITS = 128
MAX_VECTOR_BITS = 2048
REGISTER_COUNT = 32
VECTOR_LENGTHS = (128, 256, 512, 1024, 2048)
DIRECTED_PATTERNS = 6
REGISTER_MASK = REGISTER_COUNT - 1
SIZE_SHIFT = 22
SOURCE_SHIFT = 5
RIGHT_SHIFT = 16
INDEX_SHIFT = 19
DOUBLE_INDEX_SHIFT = 20
ROTATION_SHIFT = 10


class Kind(Enum):
    SIGNED = 'sdot'
    UNSIGNED = 'udot'
    SIGNED_UNSIGNED = 'sudot'
    UNSIGNED_SIGNED = 'usdot'
    COMPLEX = 'cdot'


@dataclass(frozen=True)
class Form:
    canonical: str
    kind: Kind
    mask: int
    value: int
    widths: tuple[int, ...]
    terms: int = 4
    indexed: bool = False
    variable_size: bool = False


FORMS = (
    Form('sdot_z_zzz_', Kind.SIGNED, 0xffa0fc00, 0x44800000, (32, 64), variable_size=True),
    Form('udot_z_zzz_', Kind.UNSIGNED, 0xffa0fc00, 0x44800400, (32, 64), variable_size=True),
    Form('sdot_z_zzzi_s', Kind.SIGNED, 0xffe0fc00, 0x44a00000, (32,), indexed=True),
    Form('sdot_z_zzzi_d', Kind.SIGNED, 0xffe0fc00, 0x44e00000, (64,), indexed=True),
    Form('udot_z_zzzi_s', Kind.UNSIGNED, 0xffe0fc00, 0x44a00400, (32,), indexed=True),
    Form('udot_z_zzzi_d', Kind.UNSIGNED, 0xffe0fc00, 0x44e00400, (64,), indexed=True),
    Form('sdot_z32_zzz_', Kind.SIGNED, 0xffe0fc00, 0x4400c800, (32,), terms=2),
    Form('udot_z32_zzz_', Kind.UNSIGNED, 0xffe0fc00, 0x4400cc00, (32,), terms=2),
    Form('sdot_z32_zzzi_', Kind.SIGNED, 0xffe0fc00, 0x4480c800, (32,), terms=2, indexed=True),
    Form('udot_z32_zzzi_', Kind.UNSIGNED, 0xffe0fc00, 0x4480cc00, (32,), terms=2, indexed=True),
    Form('sudot_z_zzzi_s', Kind.SIGNED_UNSIGNED, 0xffe0fc00, 0x44a01c00, (32,), indexed=True),
    Form('usdot_z_zzz_s', Kind.UNSIGNED_SIGNED, 0xffe0fc00, 0x44807800, (32,)),
    Form('usdot_z_zzzi_s', Kind.UNSIGNED_SIGNED, 0xffe0fc00, 0x44a01800, (32,), indexed=True),
    Form('cdot_z_zzz_', Kind.COMPLEX, 0xff20f000, 0x44001000, (32, 64), variable_size=True),
    Form('cdot_z_zzzi_s', Kind.COMPLEX, 0xffe0f000, 0x44a04000, (32,), indexed=True),
    Form('cdot_z_zzzi_d', Kind.COMPLEX, 0xffe0f000, 0x44e04000, (64,), indexed=True),
)
FORM_BY_ID = {form.canonical: form for form in FORMS}


@dataclass(frozen=True)
class Instruction:
    form: Form
    lane_bits: int
    destination: int
    left: int
    right: int
    index: int | None = None
    rotation: int = 0

    def __post_init__(self) -> None:
        if self.form not in FORMS or self.lane_bits not in self.form.widths:
            raise ValueError('Unallocated integer dot form or width')
        if any(not 0 <= register < REGISTER_COUNT for register in (
                self.destination, self.left, self.right)):
            raise ValueError('Z registers range from 0 through 31')
        if self.form.indexed:
            right_limit = 8 if self.lane_bits == 32 else 16
            if self.right >= right_limit or self.index is None:
                raise ValueError('Indexed dot right-register field is restricted')
            if not 0 <= self.index < SEGMENT_BITS // self.lane_bits:
                raise ValueError('Indexed dot selects a group in each 128-bit segment')
        elif self.index is not None:
            raise ValueError('Vector dot has no index')
        rotations = (0, 90, 180, 270) if self.form.kind == Kind.COMPLEX else (0,)
        if self.rotation not in rotations:
            raise ValueError('Only complex dot accepts quarter-turn rotations')

    @property
    def input_bits(self) -> int:
        return self.lane_bits // self.form.terms

    @property
    def word(self) -> int:
        word = self.form.value | self.destination | self.left << SOURCE_SHIFT
        if self.form.variable_size:
            size = self.lane_bits.bit_length() - 4
            word |= size << SIZE_SHIFT
        if self.index is None:
            word |= self.right << RIGHT_SHIFT
        else:
            index_shift = INDEX_SHIFT if self.lane_bits == 32 else DOUBLE_INDEX_SHIFT
            word |= self.right << RIGHT_SHIFT | self.index << index_shift
        if self.form.kind == Kind.COMPLEX:
            word |= (self.rotation // 90) << ROTATION_SHIFT
        return word


def decode(word: int) -> Instruction | None:
    """Decode only these 16 canonical forms; reserved CDOT sizes return None."""
    if not 0 <= word < 1 << 32:
        return None
    for form in FORMS:
        if word & form.mask != form.value:
            continue
        lane_bits = BYTE_BITS << ((word >> SIZE_SHIFT) & 3) if form.variable_size else form.widths[0]
        if lane_bits not in form.widths:
            return None
        if form.indexed:
            right_mask = 7 if lane_bits == 32 else 15
            right = (word >> RIGHT_SHIFT) & right_mask
            index_shift = INDEX_SHIFT if lane_bits == 32 else DOUBLE_INDEX_SHIFT
            index = (word >> index_shift) & (SEGMENT_BITS // lane_bits - 1)
        else:
            right = (word >> RIGHT_SHIFT) & REGISTER_MASK
            index = None
        rotation = 90 * ((word >> ROTATION_SHIFT) & 3) if form.kind == Kind.COMPLEX else 0
        return Instruction(form, lane_bits, word & REGISTER_MASK,
                           (word >> SOURCE_SHIFT) & REGISTER_MASK, right, index, rotation)
    return None


def _elements(data: bytes, width: int, signed: bool) -> list[int]:
    size = width // BYTE_BITS
    return [int.from_bytes(data[offset:offset + size], 'little', signed=signed)
            for offset in range(0, len(data), size)]


def evaluate(instruction: Instruction, accumulator: bytes, left: bytes, right: bytes) -> bytes:
    """Return active destination bytes, with exact modulo-lane accumulation.

    Indexing repeats the selected *group* from each corresponding 128-bit right
    segment. CDOT rotation follows integer-dot selector/sign semantics, which
    differ from floating complex multiplication and never set saturation status.
    """
    vl_bits = len(accumulator) * BYTE_BITS
    if not SEGMENT_BITS <= vl_bits <= MAX_VECTOR_BITS or vl_bits % SEGMENT_BITS:
        raise ValueError('VL must be a 128-bit multiple from 128 through 2048')
    if len(left) != len(accumulator) or len(right) != len(accumulator):
        raise ValueError('All original operands must contain the same active VL')
    signed_left = instruction.form.kind != Kind.UNSIGNED and instruction.form.kind != Kind.UNSIGNED_SIGNED
    signed_right = instruction.form.kind != Kind.UNSIGNED and instruction.form.kind != Kind.SIGNED_UNSIGNED
    lhs = _elements(left, instruction.input_bits, signed_left)
    rhs = _elements(right, instruction.input_bits, signed_right)
    accumulators = _elements(accumulator, instruction.lane_bits, False)
    lane_bytes = instruction.lane_bits // BYTE_BITS
    lane_mask = (1 << instruction.lane_bits) - 1
    lanes_per_segment = SEGMENT_BITS // instruction.lane_bits
    result = bytearray()
    for lane, initial in enumerate(accumulators):
        right_lane = lane if instruction.index is None else (
            lane - lane % lanes_per_segment + instruction.index)
        left_base = lane * instruction.form.terms
        right_base = right_lane * instruction.form.terms
        if instruction.form.kind == Kind.COMPLEX:
            rotation = instruction.rotation // 90
            select_real = rotation & 1
            select_imaginary = select_real ^ 1
            imaginary_sign = -1 if (rotation & 1) == (rotation >> 1) else 1
            delta = sum(lhs[left_base + pair * 2] * rhs[right_base + pair * 2 + select_real]
                        + imaginary_sign * lhs[left_base + pair * 2 + 1]
                        * rhs[right_base + pair * 2 + select_imaginary]
                        for pair in range(2))
        else:
            delta = sum(lhs[left_base + term] * rhs[right_base + term]
                        for term in range(instruction.form.terms))
        result.extend(((initial + delta) & lane_mask).to_bytes(lane_bytes, 'little'))
    return bytes(result)


def execute(instruction: Instruction, registers: Sequence[bytes]) -> tuple[bytes, ...]:
    """Snapshot all read roles before replacing the destination, preserving aliases."""
    if len(registers) != REGISTER_COUNT:
        raise ValueError('Execution requires exactly 32 Z registers')
    original = tuple(registers)
    result = list(original)
    result[instruction.destination] = evaluate(
        instruction, original[instruction.destination], original[instruction.left],
        original[instruction.right])
    return tuple(result)


@dataclass(frozen=True)
class Case:
    instruction: Instruction
    vl_bits: int
    pattern: int
    registers: tuple[bytes, ...]

    @property
    def expected(self) -> tuple[bytes, ...]:
        return execute(self.instruction, self.registers)


def _register_bytes(vl_bits: int, register: int, pattern: int, input_bits: int) -> bytes:
    length = vl_bits // BYTE_BITS
    if pattern == 0:
        return bytes((offset * 37 + register * 19 + (offset // 16) * 53) & 255
                     for offset in range(length))
    if pattern == 1:
        return bytes((0x80, 0xff, 0x7f, 0x00)[(offset + register) % 4]
                     for offset in range(length))
    if pattern == 2:
        return bytes([0xff if register & 1 else 0x80]) * length
    if pattern == 3:
        # Different 128-bit groups distinguish per-segment from low-128 indexing.
        return bytes(((offset // 16 + 1) * 17 + register + offset % 16) & 255
                     for offset in range(length))
    if pattern in (4, 5):
        # Exact signed minima expose PMADDWD pair overflow for halfword sources;
        # unsigned maxima expose illegal saturating pair sums and unsigned widening.
        value = 1 << (input_bits - 1) if pattern == 4 else (1 << input_bits) - 1
        element = value.to_bytes(input_bits // BYTE_BITS, 'little')
        return element * (vl_bits // input_bits)
    raise ValueError('Unknown directed dot pattern')


def instructions() -> Iterator[Instruction]:
    """Canonical widths/indexes/rotations, aliases and all register field values."""
    seen = set()
    for form in FORMS:
        for width in form.widths:
            indexes = range(SEGMENT_BITS // width) if form.indexed else (None,)
            rotations = (0, 90, 180, 270) if form.kind == Kind.COMPLEX else (0,)
            right_limit = (8 if width == 32 else 16) if form.indexed else REGISTER_COUNT
            # Original destination aliases either/both inputs; Z31 is an ordinary Z.
            triples = [(0, 1, 2), (1, 1, 2), (2, 1, 2), (2, 2, 2),
                       (0, 2, 2), (31, 31, right_limit - 1), (31, 1, 0)]
            triples += [(register, 1, 2) for register in range(REGISTER_COUNT)]
            triples += [(0, register, 2) for register in range(REGISTER_COUNT)]
            triples += [(0, 1, register) for register in range(right_limit)]
            for index in indexes:
                for rotation in rotations:
                    for destination, left, right in triples:
                        instruction = Instruction(form, width, destination, left, right, index, rotation)
                        if instruction.word not in seen:
                            seen.add(instruction.word)
                            yield instruction


def cases() -> Iterator[Case]:
    """Deterministic models for all requested VLs and six arithmetic patterns."""
    registers = {(vl, pattern, width): tuple(_register_bytes(vl, register, pattern, width)
                                            for register in range(REGISTER_COUNT))
                 for vl in VECTOR_LENGTHS for pattern in range(DIRECTED_PATTERNS)
                 for width in (8, 16)}
    for instruction in instructions():
        for vl in VECTOR_LENGTHS:
            for pattern in range(DIRECTED_PATTERNS):
                yield Case(instruction, vl, pattern,
                           registers[vl, pattern, instruction.input_bits])
