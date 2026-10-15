"""Pure streaming-SVE register extraction, broadcast and insertion effects.

The caller supplies complete active Z/P snapshots. Mode checks, backing storage,
outside-SVL policy and original/native transports belong to the shared boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import struct
from typing import Sequence

VECTOR_LENGTHS = (16, 32, 64, 128, 256)
VECTOR_REGISTER_COUNT = 32
GENERAL_REGISTER_COUNT = 31
PREDICATE_REGISTER_COUNT = 16
BITS_PER_BYTE = 8
GENERAL_REGISTER_BYTES = 8
GENERAL_REGISTER_MASK = (1 << (GENERAL_REGISTER_BYTES * BITS_PER_BYTE)) - 1
REGISTER_MASK = 31
SIZE_SHIFT = 22
SIZE_MASK = 3
SOURCE_SHIFT = 5
PREDICATE_SHIFT = 10
PREDICATE_MASK = 7
LAST_MASK = 0xff3fe000
DUP_IMMEDIATE_MASK = 0xff3fc000
DUP_IMMEDIATE = 0x2538c000
REGISTER_OPCODE_MASK = 0xff3ffc00
DUP_GENERAL = 0x05203800
INSR_GENERAL = 0x05243800
INSR_SCALAR = 0x05343800
DUP_INDEX_MASK = 0xff20fc00
DUP_INDEX = 0x05202000
IMMEDIATE_SHIFT = 5
IMMEDIATE_MASK = 255
IMMEDIATE_SCALE_SHIFT = 8
SHIFT_FLAG = 1 << 13
INDEX_SIZE_SHIFT = 16
INDEX_SIZE_MASK = 31
INDEX_HIGH_SHIFT = 22
INDEX_HIGH_MASK = 3
INDEX_HIGH_SCALE = 5
SCALAR_ELEMENT_BYTES = (1, 2, 4, 8)
INDEXED_ELEMENT_BYTES = (*SCALAR_ELEMENT_BYTES, 16)
INDEXED_SOURCE_BYTES = 64
FIXTURE_GOVERNING_PREDICATE = 7
FIXTURE_SOURCE_REGISTER = 5
FIXTURE_DISTINCT_REGISTER = 6
FIXTURE_FPCR = 0x03c00000
FIXTURE_FPSR = 0x0800001f


class Kind(Enum):
    LAST = "last"
    DUPLICATE_IMMEDIATE = "duplicate_immediate"
    DUPLICATE_GENERAL = "duplicate_general"
    DUPLICATE_ELEMENT = "duplicate_element"
    INSERT_GENERAL = "insert_general"
    INSERT_SCALAR = "insert_scalar"


class Destination(Enum):
    GENERAL = "general"
    SCALAR = "scalar"
    VECTOR = "vector"


class LastPosition(Enum):
    LAST_ACTIVE = "last_active"
    AFTER_LAST_ACTIVE = "after_last_active"


LAST_ENCODINGS = (
    ("lasta_r_p_z_", 0x0520a000, Destination.GENERAL, LastPosition.AFTER_LAST_ACTIVE, False),
    ("lastb_r_p_z_", 0x0521a000, Destination.GENERAL, LastPosition.LAST_ACTIVE, False),
    ("lasta_v_p_z_", 0x05228000, Destination.SCALAR, LastPosition.AFTER_LAST_ACTIVE, False),
    ("lastb_v_p_z_", 0x05238000, Destination.SCALAR, LastPosition.LAST_ACTIVE, False),
    ("clasta_r_p_z_", 0x0530a000, Destination.GENERAL, LastPosition.AFTER_LAST_ACTIVE, True),
    ("clastb_r_p_z_", 0x0531a000, Destination.GENERAL, LastPosition.LAST_ACTIVE, True),
    ("clasta_v_p_z_", 0x052a8000, Destination.SCALAR, LastPosition.AFTER_LAST_ACTIVE, True),
    ("clastb_v_p_z_", 0x052b8000, Destination.SCALAR, LastPosition.LAST_ACTIVE, True),
    ("clasta_z_p_zz_", 0x05288000, Destination.VECTOR, LastPosition.AFTER_LAST_ACTIVE, True),
    ("clastb_z_p_zz_", 0x05298000, Destination.VECTOR, LastPosition.LAST_ACTIVE, True),
)
CANONICAL_FORMS = tuple(row[0] for row in LAST_ENCODINGS) + (
    "dup_z_i_", "dup_z_r_", "dup_z_zi_", "insr_z_r_", "insr_z_v_",
)


@dataclass(frozen=True)
class Operand:
    form: str
    kind: Kind
    element_bytes: int
    destination: int
    source: int = 0
    predicate: int = 0
    destination_bank: Destination = Destination.VECTOR
    position: LastPosition = LastPosition.LAST_ACTIVE
    conditional: bool = False
    immediate: int = 0
    index: int = 0


@dataclass(frozen=True)
class Effects:
    vectors: tuple[bytes, ...]
    registers: tuple[int, ...]


def decode(word: int) -> Operand | None:
    if type(word) is not int or not 0 <= word < (1 << 32):
        raise ValueError("expected one unsigned A64 word")
    element_bytes = 1 << ((word >> SIZE_SHIFT) & SIZE_MASK)
    destination = word & REGISTER_MASK
    source = (word >> SOURCE_SHIFT) & REGISTER_MASK
    for form, value, bank, position, conditional in LAST_ENCODINGS:
        if word & LAST_MASK == value:
            return Operand(form, Kind.LAST, element_bytes, destination, source,
                           (word >> PREDICATE_SHIFT) & PREDICATE_MASK,
                           bank, position, conditional)
    if word & DUP_IMMEDIATE_MASK == DUP_IMMEDIATE:
        shifted = bool(word & SHIFT_FLAG)
        if element_bytes == 1 and shifted:
            raise ValueError("reserved DUP byte immediate shift")
        immediate = (word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK
        if immediate & (1 << (BITS_PER_BYTE - 1)):
            immediate -= 1 << BITS_PER_BYTE
        if shifted:
            immediate <<= IMMEDIATE_SCALE_SHIFT
        return Operand("dup_z_i_", Kind.DUPLICATE_IMMEDIATE, element_bytes,
                       destination, immediate=immediate)
    if word & REGISTER_OPCODE_MASK == DUP_GENERAL:
        return Operand("dup_z_r_", Kind.DUPLICATE_GENERAL, element_bytes, destination, source)
    if word & DUP_INDEX_MASK == DUP_INDEX:
        size = (word >> INDEX_SIZE_SHIFT) & INDEX_SIZE_MASK
        if size == 0:
            raise ValueError("reserved DUP indexed zero size")
        lowest = (size & -size).bit_length() - 1
        combined = (((word >> INDEX_HIGH_SHIFT) & INDEX_HIGH_MASK) << INDEX_HIGH_SCALE) | size
        return Operand("dup_z_zi_", Kind.DUPLICATE_ELEMENT, 1 << lowest,
                       destination, source, index=combined >> (lowest + 1))
    if word & REGISTER_OPCODE_MASK == INSR_GENERAL:
        return Operand("insr_z_r_", Kind.INSERT_GENERAL, element_bytes, destination, source)
    if word & REGISTER_OPCODE_MASK == INSR_SCALAR:
        return Operand("insr_z_v_", Kind.INSERT_SCALAR, element_bytes, destination, source)
    return None


def apply(operand: Operand, vectors: Sequence[bytes], predicates: Sequence[bytes],
          registers: Sequence[int], stack_pointer: int) -> Effects:
    """Return complete Z/GPR effects; preserve SP, predicates, flags, FP and RAM.

    GPR snapshots contain X0..X30. A scalar SIMD write clears all active Z bytes
    above its element width. Conditional scalar fallbacks still perform that
    narrowing write; only conditional vector fallback preserves its whole Z.
    """
    if (len(vectors) != VECTOR_REGISTER_COUNT or len(predicates) != PREDICATE_REGISTER_COUNT
            or len(registers) != GENERAL_REGISTER_COUNT):
        raise ValueError("complete Z, P and X0..X30 snapshots are required")
    vector_bytes = len(vectors[0])
    if vector_bytes not in VECTOR_LENGTHS:
        raise ValueError("invalid architectural streaming vector length")
    if any(len(vector) != vector_bytes for vector in vectors):
        raise ValueError("inconsistent Z register sizes")
    if any(len(predicate) != vector_bytes // BITS_PER_BYTE for predicate in predicates):
        raise ValueError("inconsistent packed predicate sizes")
    if any(type(value) is not int or not 0 <= value <= GENERAL_REGISTER_MASK
           for value in (*registers, stack_pointer)):
        raise ValueError("GPR and SP snapshots must be unsigned 64-bit values")
    width = operand.element_bytes
    if width not in (1, 2, 4, 8, 16) or (width == 16 and operand.kind is not Kind.DUPLICATE_ELEMENT):
        raise ValueError("unallocated element width")
    if not 0 <= operand.destination <= REGISTER_MASK or not 0 <= operand.source <= REGISTER_MASK:
        raise ValueError("invalid register index")
    if operand.kind is Kind.LAST and not 0 <= operand.predicate <= PREDICATE_MASK:
        raise ValueError("LAST governing predicate must be P0..P7")
    if operand.kind is Kind.DUPLICATE_ELEMENT and not 0 <= operand.index < 64:
        raise ValueError("invalid indexed DUP element index")
    sources = tuple(bytes(vector) for vector in vectors)
    old_registers = tuple(registers)
    result_vectors, result_registers = list(sources), list(old_registers)
    destination, source = operand.destination, operand.source
    original = sources[destination]
    if operand.kind is Kind.LAST:
        mask = int.from_bytes(predicates[operand.predicate], "little")
        last = next((offset for offset in range(vector_bytes - width, -1, -width)
                     if mask & (1 << offset)), None)
        if operand.conditional and last is None:
            if operand.destination_bank is Destination.VECTOR:
                return Effects(sources, old_registers)
            element = (original[:width] if operand.destination_bank is Destination.SCALAR else
                       (old_registers[destination] if destination != REGISTER_MASK else 0)
                       .to_bytes(GENERAL_REGISTER_BYTES, "little")[:width])
        else:
            if operand.position is LastPosition.LAST_ACTIVE:
                offset = last if last is not None else vector_bytes - width
            else:
                offset = (last + width) % vector_bytes if last is not None else 0
            element = sources[source][offset:offset + width]
        if operand.destination_bank is Destination.GENERAL:
            if destination != REGISTER_MASK:
                result_registers[destination] = int.from_bytes(element, "little")
        elif operand.destination_bank is Destination.SCALAR:
            result_vectors[destination] = element + bytes(vector_bytes - width)
        elif operand.destination_bank is Destination.VECTOR:
            result_vectors[destination] = element * (vector_bytes // width)
        else:
            raise ValueError("invalid destination bank")
    elif operand.kind is Kind.DUPLICATE_IMMEDIATE:
        element = (operand.immediate % (1 << (width * BITS_PER_BYTE))).to_bytes(width, "little")
        result_vectors[destination] = element * (vector_bytes // width)
    elif operand.kind is Kind.DUPLICATE_GENERAL:
        value = old_registers[source] if source != REGISTER_MASK else stack_pointer
        element = value.to_bytes(GENERAL_REGISTER_BYTES, "little")[:width]
        result_vectors[destination] = element * (vector_bytes // width)
    elif operand.kind is Kind.DUPLICATE_ELEMENT:
        offset = operand.index * width
        element = sources[source][offset:offset + width] if offset < vector_bytes else bytes(width)
        result_vectors[destination] = element * (vector_bytes // width)
    elif operand.kind in (Kind.INSERT_GENERAL, Kind.INSERT_SCALAR):
        if operand.kind is Kind.INSERT_SCALAR:
            element = sources[source][:width]
        else:
            value = old_registers[source] if source != REGISTER_MASK else 0
            element = value.to_bytes(GENERAL_REGISTER_BYTES, "little")[:width]
        result_vectors[destination] = element + original[:vector_bytes - width]
    else:
        raise ValueError("unknown rearrangement kind")
    return Effects(tuple(result_vectors), tuple(result_registers))


def _case_plans(vector_bytes: int):
    for _, opcode, _, _, _ in LAST_ENCODINGS:
        for size, width in enumerate(SCALAR_ELEMENT_BYTES):
            for mode, destination, source in (
                ("empty", FIXTURE_SOURCE_REGISTER, FIXTURE_SOURCE_REGISTER),
                ("last_wrap", REGISTER_MASK, REGISTER_MASK),
                ("middle", FIXTURE_SOURCE_REGISTER, FIXTURE_DISTINCT_REGISTER),
            ):
                word = (opcode | (size << SIZE_SHIFT)
                        | (FIXTURE_GOVERNING_PREDICATE << PREDICATE_SHIFT)
                        | (source << SOURCE_SHIFT) | destination)
                if mode == "empty":
                    mask = 0
                elif mode == "last_wrap":
                    mask = 1 << (vector_bytes - width)
                else:
                    mask = (1 << ((vector_bytes // width // 2) * width)) | 1
                yield word, mode, mask
    for size, _ in enumerate(SCALAR_ELEMENT_BYTES):
        for source in (FIXTURE_SOURCE_REGISTER, REGISTER_MASK):
            fields = (size << SIZE_SHIFT) | (source << SOURCE_SHIFT)
            yield DUP_GENERAL | fields | source, "SP" if source == REGISTER_MASK else "GPR", 0
            yield INSR_GENERAL | fields | source, "ZR" if source == REGISTER_MASK else "GPR", 0
            yield (INSR_SCALAR | fields | FIXTURE_SOURCE_REGISTER,
                   "V/Z alias" if source == FIXTURE_SOURCE_REGISTER else "distinct V", 0)
        for immediate, shift in ((128, 0), (127, 0), (0, 0), (255, int(size != 0))):
            word = (DUP_IMMEDIATE | (size << SIZE_SHIFT) | (shift * SHIFT_FLAG)
                    | (immediate << IMMEDIATE_SHIFT) | REGISTER_MASK)
            yield word, "immediate", 0
    for lowest, width in enumerate(INDEXED_ELEMENT_BYTES):
        maximum = INDEXED_SOURCE_BYTES // width - 1
        for index, mode in (
            (0, "first"),
            (maximum, "maximum encoded"),
            (min(vector_bytes // width, maximum), "out of SVL when encodable"),
        ):
            combined = (index << (lowest + 1)) | (1 << lowest)
            word = (DUP_INDEX | ((combined >> INDEX_HIGH_SCALE) << INDEX_HIGH_SHIFT)
                    | ((combined & INDEX_SIZE_MASK) << INDEX_SIZE_SHIFT)
                    | (FIXTURE_SOURCE_REGISTER << SOURCE_SHIFT) | FIXTURE_SOURCE_REGISTER)
            yield word, mode, 0


def lazy_cases(vector_bytes: int):
    """Yield shared original/native corpus cases without allocating a whole bank.

    Every case checks primary/Z/P/ZA/ZT0/SVCR/TPIDR2. FFR and FPMR have no
    original observer validity in this streaming cohort and receive no credit.
    """
    from dataclasses import replace
    import scalable_frame as frame

    frame.require_sme_length(vector_bytes)
    for index, (word, mode, mask) in enumerate(_case_plans(vector_bytes)):
        operand = decode(word)
        if operand is None:
            raise AssertionError("family fixture word did not decode")
        seed = f"extract-{vector_bytes}-{index}-{word:08x}".encode()
        initial = frame.seeded_snapshot(vector_bytes, seed)
        primary = bytearray(initial.primary)
        fpcr = FIXTURE_FPCR if index % 2 else 0
        fpsr = FIXTURE_FPSR if index % 2 else 0
        struct.pack_into("<II", primary, frame.PRIMARY_FPCR_OFFSET, fpcr, fpsr)
        predicate = mask
        if operand.kind is Kind.LAST:
            predicate |= sum(1 << bit for bit in range(vector_bytes)
                             if bit % operand.element_bytes)
        predicates = list(initial.p)
        predicates[FIXTURE_GOVERNING_PREDICATE] = predicate.to_bytes(vector_bytes // BITS_PER_BYTE, "little")
        initial = replace(initial, primary=bytes(primary), p=tuple(predicates),
                          controls={**initial.controls, "requested_fpcr": fpcr,
                                    "requested_fpsr": fpsr})
        projected = frame.snapshot_to_state(initial)
        effects = apply(operand, initial.z, initial.p, projected["x"], projected["sp"])
        expected = frame.snapshot_from_state(initial, {
            **projected, "x": list(effects.registers), "z": list(effects.vectors),
        })
        yield {"operation": {"word": word, "canonical_id": operand.form, "mode": mode},
               "initial": initial, "expected": expected, "required": int(initial.valid)}
