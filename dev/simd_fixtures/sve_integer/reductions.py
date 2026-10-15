"""Pure streaming SVE integer reductions, with snapshotted Z/P inputs.

Scalar V writes clear the current-SVL Z suffix. Bytes outside current SVL,
streaming permission, state storage and the host ABI belong to the shared core.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

BITS_PER_BYTE = 8
DOUBLEWORD_BYTES = 8
QUADWORD_BYTES = 16
VECTOR_LENGTHS = (16, 32, 64, 128, 256)
REDUCTION_MASK = 0xff3fe000
SIZE_SHIFT = 22
SIZE_MASK = 3
GOVERNING_SHIFT = 10
GOVERNING_REGISTER_MASK = 7
SOURCE_SHIFT = 5
VECTOR_REGISTER_MASK = 31
FPCR_ROUND_TOWARD_POSITIVE = 1 << 22
FPSR_QC_AND_EXCEPTION_FLAGS = 0x0800001f
REQUESTED_STORAGE_MASK = (1 << 32) - 1


class Kind(Enum):
    AND = "andv"
    OR = "orv"
    XOR = "eorv"
    SIGNED_ADD = "saddv"
    UNSIGNED_ADD = "uaddv"
    SIGNED_MAXIMUM = "smaxv"
    UNSIGNED_MAXIMUM = "umaxv"
    SIGNED_MINIMUM = "sminv"
    UNSIGNED_MINIMUM = "uminv"


class Output(Enum):
    SCALAR = "scalar"
    QUADWORD = "quadword"


ENCODINGS = (
    ("andv_r_p_z_", 0x041a2000, Kind.AND, Output.SCALAR),
    ("orv_r_p_z_", 0x04182000, Kind.OR, Output.SCALAR),
    ("eorv_r_p_z_", 0x04192000, Kind.XOR, Output.SCALAR),
    ("saddv_r_p_z_", 0x04002000, Kind.SIGNED_ADD, Output.SCALAR),
    ("uaddv_r_p_z_", 0x04012000, Kind.UNSIGNED_ADD, Output.SCALAR),
    ("smaxv_r_p_z_", 0x04082000, Kind.SIGNED_MAXIMUM, Output.SCALAR),
    ("umaxv_r_p_z_", 0x04092000, Kind.UNSIGNED_MAXIMUM, Output.SCALAR),
    ("sminv_r_p_z_", 0x040a2000, Kind.SIGNED_MINIMUM, Output.SCALAR),
    ("uminv_r_p_z_", 0x040b2000, Kind.UNSIGNED_MINIMUM, Output.SCALAR),
    ("addqv_z_p_z_", 0x04052000, Kind.UNSIGNED_ADD, Output.QUADWORD),
    ("andqv_z_p_z_", 0x041e2000, Kind.AND, Output.QUADWORD),
    ("eorqv_z_p_z_", 0x041d2000, Kind.XOR, Output.QUADWORD),
    ("orqv_z_p_z_", 0x041c2000, Kind.OR, Output.QUADWORD),
    ("smaxqv_z_p_z_", 0x040c2000, Kind.SIGNED_MAXIMUM, Output.QUADWORD),
    ("sminqv_z_p_z_", 0x040e2000, Kind.SIGNED_MINIMUM, Output.QUADWORD),
    ("umaxqv_z_p_z_", 0x040d2000, Kind.UNSIGNED_MAXIMUM, Output.QUADWORD),
    ("uminqv_z_p_z_", 0x040f2000, Kind.UNSIGNED_MINIMUM, Output.QUADWORD),
)
CANONICAL_FORMS = tuple(form for form, _, _, _ in ENCODINGS)


@dataclass(frozen=True)
class Operand:
    form: str
    kind: Kind
    output: Output
    element_bytes: int
    destination: int
    governing: int
    source: int

    @property
    def result_bytes(self) -> int:
        if self.output is Output.QUADWORD:
            return QUADWORD_BYTES
        return (DOUBLEWORD_BYTES if self.kind in (Kind.SIGNED_ADD, Kind.UNSIGNED_ADD)
                else self.element_bytes)


def decode(word: int) -> Operand | None:
    if type(word) is not int or not 0 <= word < 1 << 32:
        raise ValueError("instruction word must be u32")
    for form, value, kind, output in ENCODINGS:
        if word & REDUCTION_MASK != value:
            continue
        element_bytes = 1 << ((word >> SIZE_SHIFT) & SIZE_MASK)
        if kind is Kind.SIGNED_ADD and element_bytes == DOUBLEWORD_BYTES:
            return None
        return Operand(form, kind, output, element_bytes, word & VECTOR_REGISTER_MASK,
                       (word >> GOVERNING_SHIFT) & GOVERNING_REGISTER_MASK,
                       (word >> SOURCE_SHIFT) & VECTOR_REGISTER_MASK)
    return None


def _validate(operand: Operand, source: bytes, governing: bytes) -> None:
    if len(source) not in VECTOR_LENGTHS:
        raise ValueError("invalid architectural streaming vector length")
    if len(governing) != len(source) // BITS_PER_BYTE:
        raise ValueError("governing predicate length differs from vector length")
    if operand.element_bytes not in (1, 2, 4, DOUBLEWORD_BYTES):
        raise ValueError("invalid reduction element size")
    if operand.kind is Kind.SIGNED_ADD and operand.element_bytes == DOUBLEWORD_BYTES:
        raise ValueError("reserved signed doubleword reduction")
    if not any((operand.form, operand.kind, operand.output) == (form, kind, output)
               for form, _, kind, output in ENCODINGS):
        raise ValueError("unknown reduction form or kind")
    if (not 0 <= operand.destination <= VECTOR_REGISTER_MASK
            or not 0 <= operand.source <= VECTOR_REGISTER_MASK
            or not 0 <= operand.governing <= GOVERNING_REGISTER_MASK):
        raise ValueError("invalid reduction register index")


def apply(operand: Operand, source: bytes, governing: bytes) -> bytes:
    """Return exactly current-SVL destination bytes, including mandated V upper zeroing."""
    _validate(operand, source, governing)
    kind = operand.kind
    element_bits = operand.element_bytes * BITS_PER_BYTE
    element_mask = (1 << element_bits) - 1
    sign_bit = 1 << (element_bits - 1)
    signed = kind in (Kind.SIGNED_ADD, Kind.SIGNED_MAXIMUM, Kind.SIGNED_MINIMUM)
    if kind in (Kind.AND, Kind.UNSIGNED_MINIMUM):
        result = element_mask
    elif kind is Kind.SIGNED_MAXIMUM:
        result = -sign_bit
    elif kind is Kind.SIGNED_MINIMUM:
        result = sign_bit - 1
    else:
        result = 0
    lanes = QUADWORD_BYTES // operand.element_bytes if operand.output is Output.QUADWORD else 1
    results = [result] * lanes
    for offset in range(0, len(source), operand.element_bytes):
        predicate_byte, predicate_bit = divmod(offset, BITS_PER_BYTE)
        if not governing[predicate_byte] >> predicate_bit & 1:
            continue
        value = int.from_bytes(source[offset:offset + operand.element_bytes], "little", signed=signed)
        lane = offset // operand.element_bytes % lanes
        result = results[lane]
        if kind is Kind.AND:
            result &= value
        elif kind is Kind.OR:
            result |= value
        elif kind is Kind.XOR:
            result ^= value
        elif kind in (Kind.SIGNED_ADD, Kind.UNSIGNED_ADD):
            result += value
        elif kind in (Kind.SIGNED_MAXIMUM, Kind.UNSIGNED_MAXIMUM):
            result = max(result, value)
        else:
            result = min(result, value)
        results[lane] = result
    lane_bytes = operand.element_bytes if operand.output is Output.QUADWORD else operand.result_bytes
    result_mask = (1 << (lane_bytes * BITS_PER_BYTE)) - 1
    output = b"".join((value & result_mask).to_bytes(lane_bytes, "little") for value in results)
    return output + bytes(len(source) - len(output))


def _snapshot_case(form, value, kind, output, width, length, label, alias,
                   control_policy=False):
    import struct
    import scalable_frame as frame

    destination, source = (VECTOR_REGISTER_MASK, VECTOR_REGISTER_MASK) if alias else (0, 1)
    size = width.bit_length() - 1
    governing = GOVERNING_REGISTER_MASK
    word = (value | size << SIZE_SHIFT | governing << GOVERNING_SHIFT
            | source << SOURCE_SHIFT | destination)
    operand = decode(word)
    if operand is None:
        raise AssertionError("fixture word must decode to an allocated reduction")
    seed = f"{form}:{width}:{length}:{label}:{alias}".encode()
    initial = frame.seeded_snapshot(length, seed, svcr=frame.SVCR_MASK)
    mask = (1 << (width * BITS_PER_BYTE)) - 1
    sign = 1 << (width * BITS_PER_BYTE - 1)
    edges = (mask, 1, sign, sign - 1, 0, 2, mask - 1)
    values = [mask if label == "alias-overflow" else edges[index % len(edges)]
              for index in range(length // width)]
    data = b"".join(element.to_bytes(width, "little") for element in values)
    all_bits = (1 << length) - 1
    starts = sum(1 << offset for offset in range(0, length, width))
    if label == "empty":
        predicate = all_bits ^ starts  # Dirty interstitial bits are inactive.
    elif label == "sparse":
        predicate = 1 | (1 << (length - width)) | (all_bits ^ starts)
    else:
        predicate = all_bits
    vectors = list(initial.z)
    vectors[source] = data
    predicates = list(initial.p)
    predicates[governing] = predicate.to_bytes(length // BITS_PER_BYTE, "little")
    primary = bytearray(initial.primary)
    if control_policy:
        fpcr = fpsr = REQUESTED_STORAGE_MASK
    else:
        fpcr = FPCR_ROUND_TOWARD_POSITIVE if alias else 0
        fpsr = FPSR_QC_AND_EXCEPTION_FLAGS if alias else 0
    struct.pack_into("<II", primary, frame.PRIMARY_FPCR_OFFSET, fpcr, fpsr)
    controls = {**initial.controls, "requested_fpcr": fpcr, "requested_fpsr": fpsr}
    initial = frame.snapshot_from_banks(
        length, primary=bytes(primary), z=vectors, p=predicates,
        ffr=initial.ffr, za=initial.za, zt0=initial.zt0,
        valid=initial.valid, controls=controls)
    vectors = list(initial.z)
    vectors[destination] = apply(operand, initial.z[source], initial.p[governing])
    modeled = frame.snapshot_from_banks(
        length, primary=initial.primary, z=vectors, p=initial.p,
        ffr=initial.ffr, za=initial.za, zt0=initial.zt0,
        valid=initial.valid, controls=initial.controls)
    operation = {
        "word": word, "canonical_id": form, "kind": kind.value,
        "output": output.value, "element_bytes": width,
        "destination": destination, "governing": governing, "source": source,
        "label": label,
        "fp_control_policy": "requested-storage-only" if control_policy else "strict-direct",
    }
    # Unobserved FFR/FPMR diagnostic bytes do not grant architectural validity.
    return {"operation": operation, "initial": initial, "expected": modeled,
            "required": int(initial.valid)}


def lazy_cases(vector_bytes):
    """Yield the bounded strict direct cohort as complete immutable Snapshots."""
    if vector_bytes not in VECTOR_LENGTHS:
        raise ValueError("invalid architectural streaming vector length")
    length_index = VECTOR_LENGTHS.index(vector_bytes)
    for form, value, kind, output in ENCODINGS:
        widths = (1, 2, 4) if kind is Kind.SIGNED_ADD else (1, 2, 4, DOUBLEWORD_BYTES)
        for width_index, width in enumerate(widths):
            yield _snapshot_case(form, value, kind, output, width, vector_bytes,
                                 "all-edge", (length_index + width_index) % 2 == 0)
        width = widths[length_index % len(widths)]
        for label, alias in (("empty", False), ("sparse", True), ("alias-overflow", True)):
            yield _snapshot_case(form, value, kind, output, width, vector_bytes, label, alias)


def lazy_fp_storage_cases(vector_bytes):
    """Separate requested-storage probes; these cannot grant direct equality credit."""
    if vector_bytes not in VECTOR_LENGTHS:
        raise ValueError("invalid architectural streaming vector length")
    for label, alias in (("raw-storage-distinct", False), ("raw-storage-alias", True)):
        yield _snapshot_case(*ENCODINGS[0], 1, vector_bytes, label, alias, True)
