"""Pure streaming-SVE integer comparison operands and packed predicate effects.

No architectural state storage, host ABI, execution mode, or oracle substitutions
are owned here. All input vectors and the governing predicate are snapshots.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

BITS_PER_BYTE = 8
WIDE_BYTES = 8
SIZE_SHIFT = 22
RIGHT_SHIFT = 16
UNSIGNED_IMMEDIATE_SHIFT = 14
LEFT_SHIFT = 5
GOVERNING_SHIFT = 10
Z_REGISTER_MASK = 31
P_REGISTER_MASK = 15
GOVERNING_REGISTER_MASK = 7
NZCV_N = 1 << 31
NZCV_Z = 1 << 30
NZCV_C = 1 << 29
VECTOR_LENGTHS = (16, 32, 64, 128, 256)


class Relation(Enum):
    EQUAL = "eq"
    NOT_EQUAL = "ne"
    GREATER_EQUAL = "ge"
    GREATER = "gt"
    LESS_EQUAL = "le"
    LESS = "lt"


class RightKind(Enum):
    IMMEDIATE = "zi"
    VECTOR = "zz"
    WIDE_VECTOR = "zw"


@dataclass(frozen=True)
class Operand:
    form: str
    relation: Relation
    unsigned: bool
    element_bytes: int
    destination: int
    governing: int
    left: int
    right_kind: RightKind
    right: int


# Exact canonical masks from the pinned June 2026 A64 reference. Same-width
# LE/LT/LO/LS spellings are reversed-operand aliases and have no separate rows.
ENCODINGS = (
    ("cmpeq_p_p_zi_", 0xff20e010, 0x25008000, Relation.EQUAL, False, RightKind.IMMEDIATE),
    ("cmpeq_p_p_zw_", 0xff20e010, 0x24002000, Relation.EQUAL, False, RightKind.WIDE_VECTOR),
    ("cmpeq_p_p_zz_", 0xff20e010, 0x2400a000, Relation.EQUAL, False, RightKind.VECTOR),
    ("cmpge_p_p_zi_", 0xff20e010, 0x25000000, Relation.GREATER_EQUAL, False, RightKind.IMMEDIATE),
    ("cmpge_p_p_zw_", 0xff20e010, 0x24004000, Relation.GREATER_EQUAL, False, RightKind.WIDE_VECTOR),
    ("cmpge_p_p_zz_", 0xff20e010, 0x24008000, Relation.GREATER_EQUAL, False, RightKind.VECTOR),
    ("cmpgt_p_p_zi_", 0xff20e010, 0x25000010, Relation.GREATER, False, RightKind.IMMEDIATE),
    ("cmpgt_p_p_zw_", 0xff20e010, 0x24004010, Relation.GREATER, False, RightKind.WIDE_VECTOR),
    ("cmpgt_p_p_zz_", 0xff20e010, 0x24008010, Relation.GREATER, False, RightKind.VECTOR),
    ("cmphi_p_p_zi_", 0xff202010, 0x24200010, Relation.GREATER, True, RightKind.IMMEDIATE),
    ("cmphi_p_p_zw_", 0xff20e010, 0x2400c010, Relation.GREATER, True, RightKind.WIDE_VECTOR),
    ("cmphi_p_p_zz_", 0xff20e010, 0x24000010, Relation.GREATER, True, RightKind.VECTOR),
    ("cmphs_p_p_zi_", 0xff202010, 0x24200000, Relation.GREATER_EQUAL, True, RightKind.IMMEDIATE),
    ("cmphs_p_p_zw_", 0xff20e010, 0x2400c000, Relation.GREATER_EQUAL, True, RightKind.WIDE_VECTOR),
    ("cmphs_p_p_zz_", 0xff20e010, 0x24000000, Relation.GREATER_EQUAL, True, RightKind.VECTOR),
    ("cmple_p_p_zi_", 0xff20e010, 0x25002010, Relation.LESS_EQUAL, False, RightKind.IMMEDIATE),
    ("cmple_p_p_zw_", 0xff20e010, 0x24006010, Relation.LESS_EQUAL, False, RightKind.WIDE_VECTOR),
    ("cmplo_p_p_zi_", 0xff202010, 0x24202000, Relation.LESS, True, RightKind.IMMEDIATE),
    ("cmplo_p_p_zw_", 0xff20e010, 0x2400e000, Relation.LESS, True, RightKind.WIDE_VECTOR),
    ("cmpls_p_p_zi_", 0xff202010, 0x24202010, Relation.LESS_EQUAL, True, RightKind.IMMEDIATE),
    ("cmpls_p_p_zw_", 0xff20e010, 0x2400e010, Relation.LESS_EQUAL, True, RightKind.WIDE_VECTOR),
    ("cmplt_p_p_zi_", 0xff20e010, 0x25002000, Relation.LESS, False, RightKind.IMMEDIATE),
    ("cmplt_p_p_zw_", 0xff20e010, 0x24006000, Relation.LESS, False, RightKind.WIDE_VECTOR),
    ("cmpne_p_p_zi_", 0xff20e010, 0x25008010, Relation.NOT_EQUAL, False, RightKind.IMMEDIATE),
    ("cmpne_p_p_zw_", 0xff20e010, 0x24002010, Relation.NOT_EQUAL, False, RightKind.WIDE_VECTOR),
    ("cmpne_p_p_zz_", 0xff20e010, 0x2400a010, Relation.NOT_EQUAL, False, RightKind.VECTOR),
)


def decode(word: int) -> Operand | None:
    for form, mask, value, relation, unsigned, right_kind in ENCODINGS:
        if word & mask != value:
            continue
        element_bytes = 1 << ((word >> SIZE_SHIFT) & 3)
        if right_kind is RightKind.WIDE_VECTOR and element_bytes == WIDE_BYTES:
            return None
        right = (word >> RIGHT_SHIFT) & Z_REGISTER_MASK
        if right_kind is RightKind.IMMEDIATE:
            if unsigned:
                right = (word >> UNSIGNED_IMMEDIATE_SHIFT) & 127
            elif right & 16:
                right -= 32
        return Operand(form, relation, unsigned, element_bytes,
                       word & P_REGISTER_MASK,
                       (word >> GOVERNING_SHIFT) & GOVERNING_REGISTER_MASK,
                       (word >> LEFT_SHIFT) & Z_REGISTER_MASK, right_kind, right)
    return None


def compare(relation: Relation, left: int, right: int) -> bool:
    if relation is Relation.EQUAL:
        return left == right
    if relation is Relation.NOT_EQUAL:
        return left != right
    if relation is Relation.GREATER_EQUAL:
        return left >= right
    if relation is Relation.GREATER:
        return left > right
    if relation is Relation.LESS_EQUAL:
        return left <= right
    if relation is Relation.LESS:
        return left < right
    raise ValueError("unknown comparison relation")


def apply(operand: Operand, left: bytes, right: bytes | None,
          governing: bytes) -> tuple[bytes, int]:
    """Return the overwritten packed Pd and NZCV; inactive/interstitial bits clear."""
    vector_bytes = len(left)
    if vector_bytes not in VECTOR_LENGTHS:
        raise ValueError("invalid architectural streaming vector length")
    if len(governing) != vector_bytes // BITS_PER_BYTE:
        raise ValueError("governing predicate length differs from vector length")
    if operand.right_kind is not RightKind.IMMEDIATE and (right is None or len(right) != vector_bytes):
        raise ValueError("right vector length differs from left vector")
    element_bytes = operand.element_bytes
    if element_bytes not in (1, 2, 4, 8):
        raise ValueError("invalid element width")
    if operand.right_kind is RightKind.WIDE_VECTOR and element_bytes == WIDE_BYTES:
        raise ValueError("reserved doubleword wide comparison")
    result = bytearray(len(governing))
    first = last = None
    any_true = False
    for offset in range(0, vector_bytes, element_bytes):
        predicate_byte, predicate_bit = divmod(offset, BITS_PER_BYTE)
        if not (governing[predicate_byte] >> predicate_bit) & 1:
            continue
        left_element = int.from_bytes(left[offset:offset + element_bytes], "little", signed=not operand.unsigned)
        if operand.right_kind is RightKind.IMMEDIATE:
            right_element = operand.right
        else:
            right_offset = offset if operand.right_kind is RightKind.VECTOR else offset // WIDE_BYTES * WIDE_BYTES
            right_bytes = element_bytes if operand.right_kind is RightKind.VECTOR else WIDE_BYTES
            right_element = int.from_bytes(right[right_offset:right_offset + right_bytes], "little", signed=not operand.unsigned)
        condition = compare(operand.relation, left_element, right_element)
        if first is None:
            first = condition
        last = condition
        any_true |= condition
        result[predicate_byte] |= int(condition) << predicate_bit
    flags = (NZCV_N if first else 0) | (NZCV_Z if not any_true else 0) | (NZCV_C if not last else 0)
    return bytes(result), flags


def apply_banks(operand: Operand, vectors, predicates) -> tuple[tuple[bytes, ...], int]:
    """Snapshot Z/P inputs and return a new P bank plus the overwritten NZCV."""
    if len(vectors) != 32 or len(predicates) != 16:
        raise ValueError("expected 32 Z registers and 16 packed predicates")
    vector_bytes = len(vectors[0])
    if vector_bytes not in VECTOR_LENGTHS:
        raise ValueError("invalid architectural streaming vector length")
    if any(len(vector) != vector_bytes for vector in vectors):
        raise ValueError("inconsistent Z register lengths")
    if any(len(predicate) != vector_bytes // BITS_PER_BYTE for predicate in predicates):
        raise ValueError("inconsistent packed predicate lengths")
    if not 0 <= operand.destination < 16 or not 0 <= operand.governing < 8:
        raise ValueError("invalid comparison predicate register")
    if not 0 <= operand.left < 32:
        raise ValueError("invalid comparison left vector register")
    right = None
    if operand.right_kind is RightKind.IMMEDIATE:
        lower, upper = (0, 127) if operand.unsigned else (-16, 15)
        if not lower <= operand.right <= upper:
            raise ValueError("unallocated comparison immediate")
    else:
        if not 0 <= operand.right < 32:
            raise ValueError("invalid comparison right vector register")
        right = bytes(vectors[operand.right])
    result, flags = apply(operand, bytes(vectors[operand.left]), right,
                          bytes(predicates[operand.governing]))
    output = tuple(result if index == operand.destination else bytes(predicate)
                   for index, predicate in enumerate(predicates))
    return output, flags


def directed_words():
    """Every canonical form/size, immediate endpoints and register/Pd-Pg aliases."""
    aliases = ((0, 1, 2, 0), (31, 31, 7, 7), (1, 0, 0, 0))
    for form, mask, value, relation, unsigned, kind in ENCODINGS:
        for size in range(4):
            if kind is RightKind.WIDE_VECTOR and size == 3:
                continue
            for alias_index, (left, right, destination, governing) in enumerate(aliases):
                if kind is RightKind.IMMEDIATE:
                    right = (0, 127, 1)[alias_index] if unsigned else (0, 16, 15)[alias_index]
                    shift = UNSIGNED_IMMEDIATE_SHIFT if unsigned else RIGHT_SHIFT
                else:
                    shift = RIGHT_SHIFT
                yield (value | size << SIZE_SHIFT | right << shift |
                       left << LEFT_SHIFT | governing << GOVERNING_SHIFT | destination)


def lazy_cases(vector_bytes: int):
    """Complete scalable snapshots; model-only until the original observer runs."""
    from dataclasses import replace
    import struct
    from scalable_frame import (
        PRIMARY_NZCV_OFFSET, require_sme_length, seeded_snapshot, snapshot_from_banks,
    )

    require_sme_length(vector_bytes)
    all_bits = (1 << vector_bytes) - 1
    for word in directed_words():
        operand = decode(word)
        width = operand.element_bytes
        leading = sum(1 << offset for offset in range(0, vector_bytes, width))
        patterns = (("none", 0), ("all", all_bits),
                    ("irrelevant", all_bits ^ leading),
                    ("first_last", 1 | (1 << (vector_bytes - width))),
                    ("alternating", all_bits ^ sum(1 << offset for offset in range(0, vector_bytes, width * 2))))
        for pattern_name, pattern in patterns:
            initial = seeded_snapshot(vector_bytes, f"comparison:{word:08x}:{pattern_name}".encode())
            vectors = list(initial.z)
            bits = width * BITS_PER_BYTE
            values = (0, 1, (1 << (bits - 1)) - 1, 1 << (bits - 1),
                      (1 << bits) - 1, (1 << bits) - 2, 15, 16)
            vectors[operand.left] = b"".join(values[index % len(values)].to_bytes(width, "little")
                                             for index in range(vector_bytes // width))
            if operand.right_kind is RightKind.WIDE_VECTOR:
                wide = (0, 1, 255, 256, 1 << 32, (1 << 63) - 1, 1 << 63, (1 << 64) - 1)
                rotate = (word >> GOVERNING_SHIFT) & GOVERNING_REGISTER_MASK
                vectors[operand.right] = b"".join(wide[(index + rotate) % len(wide)].to_bytes(WIDE_BYTES, "little")
                                                  for index in range(vector_bytes // WIDE_BYTES))
            predicates = list(initial.p)
            predicates[operand.governing] = pattern.to_bytes(vector_bytes // BITS_PER_BYTE, "little")
            initial = snapshot_from_banks(vector_bytes, primary=initial.primary, z=vectors, p=predicates,
                                          ffr=initial.ffr, za=initial.za, zt0=initial.zt0,
                                          valid=initial.valid, controls=initial.controls)
            output, flags = apply_banks(operand, initial.z, initial.p)
            primary = bytearray(initial.primary)
            struct.pack_into("<I", primary, PRIMARY_NZCV_OFFSET, flags)
            expected = replace(initial, primary=bytes(primary), p=output)
            yield {"operation": {"word": word, "canonical_id": operand.form},
                   "initial": initial, "expected": expected, "required": int(initial.valid),
                   "operand": operand, "predicate_class": pattern_name}
