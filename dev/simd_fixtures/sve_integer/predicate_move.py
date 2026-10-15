"""Pure full-Z PMOV bitmap semantics; P has one packed bit per vector byte."""

from dataclasses import dataclass
from typing import Sequence

BITS_PER_BYTE = 8
VECTOR_REGISTERS = 32
PREDICATE_REGISTERS = 16
ELEMENT_BYTES = (1, 2, 4, 8)
VECTOR_LENGTHS = (16, 32, 64, 128, 256)
FORM_IDS = {1: "pmov_z_pi_b", 2: "pmov_z_pi_h", 4: "pmov_z_pi_s", 8: "pmov_z_pi_d"}
OPCODES = {1: 0x052B3800, 2: 0x052D3800, 4: 0x05693800, 8: 0x05A93800}
PREDICATE_SHIFT = 5
PORTION_LOW_SHIFT = 17
PORTION_HIGH_SHIFT = 22


@dataclass(frozen=True)
class Operand:
    destination: int
    predicate: int
    element_bytes: int
    portion: int = 0


def word(operand: Operand) -> int:
    validate(operand)
    return (OPCODES[operand.element_bytes] | operand.destination
            | operand.predicate << PREDICATE_SHIFT
            | (operand.portion & 3) << PORTION_LOW_SHIFT
            | (operand.portion >> 2) << PORTION_HIGH_SHIFT)


def validate(operand: Operand) -> None:
    if not 0 <= operand.destination < VECTOR_REGISTERS:
        raise ValueError("invalid Z destination")
    if not 0 <= operand.predicate < PREDICATE_REGISTERS:
        raise ValueError("invalid P source")
    if operand.element_bytes not in ELEMENT_BYTES:
        raise ValueError("unallocated element size")
    if not 0 <= operand.portion < operand.element_bytes:
        raise ValueError("unallocated portion index")


def apply(operand: Operand, vectors: Sequence[bytes], predicates: Sequence[bytes]) -> tuple[bytes, ...]:
    """Change exactly the selected Z bits; all other architectural banks survive."""
    validate(operand)
    if len(vectors) != VECTOR_REGISTERS or len(predicates) != PREDICATE_REGISTERS:
        raise ValueError("complete Z and P register files are required")
    length = len(vectors[0])
    if length not in VECTOR_LENGTHS or any(len(z) != length for z in vectors):
        raise ValueError("invalid streaming vector length")
    if any(len(p) != length // BITS_PER_BYTE for p in predicates):
        raise ValueError("invalid packed predicate length")
    elements = length // operand.element_bytes
    source = int.from_bytes(predicates[operand.predicate], "little")
    packed = sum(((source >> (e * operand.element_bytes)) & 1) << e
                 for e in range(elements))
    offset = elements * operand.portion
    mask = ((1 << elements) - 1) << offset
    previous = int.from_bytes(vectors[operand.destination], "little") if operand.portion else 0
    result = (previous & ~mask) | (packed << offset)
    output = list(vectors)
    output[operand.destination] = result.to_bytes(length, "little")
    return tuple(output)


def directed_operands() -> tuple[Operand, ...]:
    return tuple(Operand(destination, predicate, size, portion)
                 for size in ELEMENT_BYTES for portion in range(size)
                 for destination in (0, 15, 31) for predicate in (0, 7, 15))


def lazy_cases(vector_bytes: int):
    """Bounded full-bank cases for the shared scalable original/native adapter."""
    from dataclasses import replace
    from scalable_frame import PRIMARY_VECTOR_OFFSET, FIXED_VECTOR_BYTES, seeded_snapshot

    if vector_bytes not in VECTOR_LENGTHS:
        raise ValueError("invalid streaming vector length")
    all_bits = (1 << vector_bytes) - 1
    for operand in directed_operands():
        leading = sum(1 << e for e in range(0, vector_bytes, operand.element_bytes))
        patterns = (("none", 0), ("all", all_bits), ("leading", leading),
                    ("irrelevant", all_bits ^ leading),
                    ("edges", 1 | (1 << (vector_bytes - operand.element_bytes))),
                    ("alternating", sum(1 << e for e in range(0, vector_bytes, operand.element_bytes * 2))))
        for pattern_name, pattern in patterns:
            encoded = word(operand)
            seed = f"pmov:{encoded:08x}:{vector_bytes}:{pattern_name}".encode()
            initial = seeded_snapshot(vector_bytes, seed)
            predicates = list(initial.p)
            predicates[operand.predicate] = pattern.to_bytes(vector_bytes // BITS_PER_BYTE, "little")
            initial = replace(initial, p=tuple(predicates))
            vectors = apply(operand, initial.z, initial.p)
            primary = bytearray(initial.primary)
            start = PRIMARY_VECTOR_OFFSET + operand.destination * FIXED_VECTOR_BYTES
            primary[start:start + FIXED_VECTOR_BYTES] = vectors[operand.destination][:FIXED_VECTOR_BYTES]
            expected = replace(initial, primary=bytes(primary), z=vectors)
            yield {"operation": {"word": encoded, "canonical_id": FORM_IDS[operand.element_bytes]},
                   "initial": initial, "expected": expected,
                   "required": int(initial.valid),
                   "operand": operand, "predicate_class": pattern_name}
