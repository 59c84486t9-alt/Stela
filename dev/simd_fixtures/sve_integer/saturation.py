"""Pure streaming-SVE saturation/halving/absolute-difference semantics.

All source Z bytes are read before writing the destination. Predicates have one
packed bit per vector byte. These SVE saturating forms preserve FPSR.QC and NZCV;
mode, feature, prefix legality and transport belong to the shared boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

VECTOR_REGISTERS = 32
PREDICATE_REGISTERS = 16
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256
BITS_PER_BYTE = 8
REGISTER_MASK = 31
SIZE_SHIFT = 22
SOURCE_ONE_SHIFT = 5
SOURCE_TWO_SHIFT = 16
PREDICATE_SHIFT = 10
PREDICATE_MASK = 7
IMMEDIATE_SHIFT = 5
IMMEDIATE_MASK = 255
IMMEDIATE_SCALE_BIT = 13
IMMEDIATE_SCALE_SHIFT = 8
ROTATION_BIT = 10
FORMS = (
    {'id': 'saba_z_zzz_', 'mnemonic': 'SABA', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x4500f800', 'shape': 'three_register', 'widening': False, 'top': False, 'accumulate': True},
    {'id': 'sabalb_z_zzz_', 'mnemonic': 'SABALB', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x4500c000', 'shape': 'three_register', 'widening': True, 'top': False, 'accumulate': True},
    {'id': 'sabalt_z_zzz_', 'mnemonic': 'SABALT', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x4500c400', 'shape': 'three_register', 'widening': True, 'top': True, 'accumulate': True},
    {'id': 'sabd_z_p_zz_', 'mnemonic': 'SABD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x040c0000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sabdlb_z_zz_', 'mnemonic': 'SABDLB', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x45003000', 'shape': 'three_register', 'widening': True, 'top': False, 'accumulate': False},
    {'id': 'sabdlt_z_zz_', 'mnemonic': 'SABDLT', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x45003400', 'shape': 'three_register', 'widening': True, 'top': True, 'accumulate': False},
    {'id': 'shadd_z_p_zz_', 'mnemonic': 'SHADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44108000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'shsub_z_p_zz_', 'mnemonic': 'SHSUB', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44128000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'shsubr_z_p_zz_', 'mnemonic': 'SHSUBR', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44168000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqabs_z_p_z_m', 'mnemonic': 'SQABS', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x4408a000', 'shape': 'unary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqadd_z_p_zz_', 'mnemonic': 'SQADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44188000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqadd_z_zi_', 'mnemonic': 'SQADD', 'encoding_mask': '0xff3fc000', 'encoding_value': '0x2524c000', 'shape': 'immediate', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqadd_z_zz_', 'mnemonic': 'SQADD', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x04201000', 'shape': 'three_register', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqcadd_z_zz_', 'mnemonic': 'SQCADD', 'encoding_mask': '0xff3ff800', 'encoding_value': '0x4501d800', 'shape': 'complex', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqneg_z_p_z_m', 'mnemonic': 'SQNEG', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x4409a000', 'shape': 'unary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqsub_z_p_zz_', 'mnemonic': 'SQSUB', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x441a8000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqsub_z_zi_', 'mnemonic': 'SQSUB', 'encoding_mask': '0xff3fc000', 'encoding_value': '0x2526c000', 'shape': 'immediate', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqsub_z_zz_', 'mnemonic': 'SQSUB', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x04201800', 'shape': 'three_register', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'sqsubr_z_p_zz_', 'mnemonic': 'SQSUBR', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x441e8000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'srhadd_z_p_zz_', 'mnemonic': 'SRHADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44148000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'suqadd_z_p_zz_', 'mnemonic': 'SUQADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x441c8000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uaba_z_zzz_', 'mnemonic': 'UABA', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x4500fc00', 'shape': 'three_register', 'widening': False, 'top': False, 'accumulate': True},
    {'id': 'uabalb_z_zzz_', 'mnemonic': 'UABALB', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x4500c800', 'shape': 'three_register', 'widening': True, 'top': False, 'accumulate': True},
    {'id': 'uabalt_z_zzz_', 'mnemonic': 'UABALT', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x4500cc00', 'shape': 'three_register', 'widening': True, 'top': True, 'accumulate': True},
    {'id': 'uabd_z_p_zz_', 'mnemonic': 'UABD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x040d0000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uabdlb_z_zz_', 'mnemonic': 'UABDLB', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x45003800', 'shape': 'three_register', 'widening': True, 'top': False, 'accumulate': False},
    {'id': 'uabdlt_z_zz_', 'mnemonic': 'UABDLT', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x45003c00', 'shape': 'three_register', 'widening': True, 'top': True, 'accumulate': False},
    {'id': 'uhadd_z_p_zz_', 'mnemonic': 'UHADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44118000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uhsub_z_p_zz_', 'mnemonic': 'UHSUB', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44138000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uhsubr_z_p_zz_', 'mnemonic': 'UHSUBR', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44178000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uqadd_z_p_zz_', 'mnemonic': 'UQADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44198000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uqadd_z_zi_', 'mnemonic': 'UQADD', 'encoding_mask': '0xff3fc000', 'encoding_value': '0x2525c000', 'shape': 'immediate', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uqadd_z_zz_', 'mnemonic': 'UQADD', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x04201400', 'shape': 'three_register', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uqsub_z_p_zz_', 'mnemonic': 'UQSUB', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x441b8000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uqsub_z_zi_', 'mnemonic': 'UQSUB', 'encoding_mask': '0xff3fc000', 'encoding_value': '0x2527c000', 'shape': 'immediate', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uqsub_z_zz_', 'mnemonic': 'UQSUB', 'encoding_mask': '0xff20fc00', 'encoding_value': '0x04201c00', 'shape': 'three_register', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'uqsubr_z_p_zz_', 'mnemonic': 'UQSUBR', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x441f8000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'urhadd_z_p_zz_', 'mnemonic': 'URHADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x44158000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
    {'id': 'usqadd_z_p_zz_', 'mnemonic': 'USQADD', 'encoding_mask': '0xff3fe000', 'encoding_value': '0x441d8000', 'shape': 'binary_predicated', 'widening': False, 'top': False, 'accumulate': False},
)
CANONICAL_FORMS = tuple(row["id"] for row in FORMS)

@dataclass(frozen=True)
class Operand:
    form_id: str
    operation: str
    shape: str
    destination: int
    left: int
    right: int | None
    immediate: int | None
    predicate: int | None
    element_bytes: int
    widening: bool
    top: bool
    accumulate: bool
    rotate_270: bool

def decode(word: int) -> Operand | None:
    if type(word) is not int or not 0 <= word < (1 << 32):
        raise ValueError("expected one unsigned A64 word")
    form = next((f for f in FORMS if word & int(f['encoding_mask'], 16) == int(f['encoding_value'], 16)), None)
    if form is None:
        return None
    size = (word >> SIZE_SHIFT) & 3
    scaled = (word >> IMMEDIATE_SCALE_BIT) & 1
    if form['widening'] and size == 0:
        raise ValueError('reserved widening destination element size')
    if form['shape'] == 'immediate' and size == 0 and scaled:
        raise ValueError('reserved byte immediate shift')
    destination = word & REGISTER_MASK
    shape = form['shape']
    source = destination if shape in {'binary_predicated', 'immediate', 'complex'} else (word >> SOURCE_ONE_SHIFT) & REGISTER_MASK
    right_register = ((word >> SOURCE_ONE_SHIFT) & REGISTER_MASK) if shape in {'binary_predicated', 'complex'} else (((word >> SOURCE_TWO_SHIFT) & REGISTER_MASK) if shape == 'three_register' else None)
    immediate = (((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) << (IMMEDIATE_SCALE_SHIFT if scaled else 0)) if shape == 'immediate' else None
    predicate = ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) if shape in {'unary_predicated', 'binary_predicated'} else None
    return Operand(form['id'], form['mnemonic'], shape, destination, source, right_register, immediate, predicate,
                   1 << size, form['widening'], form['top'], form['accumulate'],
                   shape == 'complex' and bool((word >> ROTATION_BIT) & 1))


def signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def clamp(value: int, bits: int, unsigned: bool) -> int:
    lower = 0 if unsigned else -(1 << (bits - 1))
    upper = (1 << bits) - 1 if unsigned else (1 << (bits - 1)) - 1
    return min(upper, max(lower, value)) & ((1 << bits) - 1)


def scalar(mnemonic: str, a: int, b: int, bits: int) -> int:
    """Compute one lane in arbitrary precision before architectural truncation."""
    mask = (1 << bits) - 1
    unsigned = mnemonic.startswith('U')
    x, y = (a, b) if unsigned else (signed(a, bits), signed(b, bits))
    if mnemonic == 'SUQADD':
        return clamp(signed(a, bits) + b, bits, False)
    if mnemonic == 'USQADD':
        return clamp(a + signed(b, bits), bits, True)
    if mnemonic in {'SQADD', 'UQADD'}:
        return clamp(x + y, bits, unsigned)
    if mnemonic in {'SQSUB', 'UQSUB', 'SQSUBR', 'UQSUBR'}:
        return clamp(y - x if mnemonic.endswith('R') else x - y, bits, unsigned)
    if mnemonic in {'SQABS', 'SQNEG'}:
        return clamp(abs(signed(a, bits)) if mnemonic == 'SQABS' else -signed(a, bits), bits, False)
    if mnemonic in {'SHADD', 'UHADD', 'SRHADD', 'URHADD'}:
        return ((x + y + (1 if mnemonic in {'SRHADD', 'URHADD'} else 0)) >> 1) & mask
    if mnemonic in {'SHSUB', 'UHSUB', 'SHSUBR', 'UHSUBR'}:
        return ((y - x if mnemonic.endswith('R') else x - y) >> 1) & mask
    if mnemonic in {'SABD', 'UABD', 'SABA', 'UABA'}:
        return abs(x - y) & mask
    raise ValueError(mnemonic)


def read_lane(vector: bytes, index: int, bits: int) -> int:
    width = bits // BITS_PER_BYTE
    return int.from_bytes(vector[index * width:(index + 1) * width], 'little')


def apply(operand: Operand, vectors: Sequence[bytes], predicates: Sequence[bytes]) -> tuple[bytes, ...]:
    """Return the complete Z bank, changing only the declared destination."""
    if len(vectors) != VECTOR_REGISTERS or len(predicates) != PREDICATE_REGISTERS:
        raise ValueError("complete Z and P register files are required")
    vector_bytes = len(vectors[0])
    if not MIN_VECTOR_BYTES <= vector_bytes <= MAX_VECTOR_BYTES or vector_bytes & (vector_bytes - 1):
        raise ValueError("invalid streaming vector length")
    if any(len(vector) != vector_bytes for vector in vectors):
        raise ValueError("inconsistent Z lengths")
    if any(len(predicate) != vector_bytes // BITS_PER_BYTE for predicate in predicates):
        raise ValueError("inconsistent packed predicate lengths")
    if operand.element_bytes not in (1, 2, 4, 8):
        raise ValueError("unallocated element size")
    registers = (operand.destination, operand.left) + (() if operand.right is None else (operand.right,))
    if any(type(register) is not int or not 0 <= register < VECTOR_REGISTERS for register in registers):
        raise ValueError("invalid Z register")
    if operand.predicate is not None and not 0 <= operand.predicate <= PREDICATE_MASK:
        raise ValueError("invalid governing predicate")
    op = operand
    sources = tuple(bytes(vector) for vector in vectors)
    bits = op.element_bytes * BITS_PER_BYTE
    width = bits // BITS_PER_BYTE
    elements = vector_bytes // width
    old = sources[op.destination]
    left = sources[op.left]
    right = sources[op.right] if op.right is not None else None
    result = bytearray(old)
    governing = None if op.predicate is None else int.from_bytes(predicates[op.predicate], "little")
    for lane in range(elements):
        if governing is not None and not ((governing >> (lane * width)) & 1):
            continue
        if op.widening:
            narrow_bits = bits // 2
            narrow_lane = 2 * lane + int(op.top)
            a = read_lane(left, narrow_lane, narrow_bits)
            b = read_lane(right, narrow_lane, narrow_bits)
            if op.operation.startswith('S'):
                a, b = signed(a, narrow_bits), signed(b, narrow_bits)
            value = abs(a - b)
        elif op.operation == 'SQCADD':
            partner = lane ^ 1
            a = signed(read_lane(left, lane, bits), bits)
            b = signed(read_lane(right, partner, bits), bits)
            subtract = bool(lane % 2) == op.rotate_270
            value = clamp(a - b if subtract else a + b, bits, False)
        else:
            a = read_lane(left, lane, bits)
            b = op.immediate if op.immediate is not None else (read_lane(right, lane, bits) if right is not None else 0)
            if op.shape == 'immediate':
                x = a if op.operation.startswith('U') else signed(a, bits)
                value = clamp(x - b if 'SUB' in op.operation else x + b, bits, op.operation.startswith('U'))
            else:
                value = scalar(op.operation, a, b, bits)
        if op.accumulate:
            value += read_lane(old, lane, bits)
        result[lane * width:(lane + 1) * width] = (value & ((1 << bits) - 1)).to_bytes(width, 'little')
    output = list(sources)
    output[op.destination] = bytes(result)
    return tuple(output)


def encode(form: dict, size: int, destination: int, source: int, right: int, predicate: int = 0,
           immediate: int = 255, scaled: bool = False, rotate_270: bool = False) -> int:
    word = int(form['encoding_value'], 16) | (size << SIZE_SHIFT) | destination
    shape = form['shape']
    if shape == 'immediate':
        return word | (immediate << IMMEDIATE_SHIFT) | (int(scaled) << IMMEDIATE_SCALE_BIT)
    if shape in {'unary_predicated', 'three_register'}:
        word |= source << SOURCE_ONE_SHIFT
    if shape == 'three_register':
        word |= right << SOURCE_TWO_SHIFT
    if shape in {'binary_predicated', 'complex'}:
        word |= right << SOURCE_ONE_SHIFT
    if shape in {'unary_predicated', 'binary_predicated'}:
        word |= predicate << PREDICATE_SHIFT
    if shape == 'complex':
        word |= int(rotate_270) << ROTATION_BIT
    return word



def directed_operands() -> tuple[Operand, ...]:
    """Enumerate encoded forms, aliases, widths, immediate scales and rotations."""
    output = {}
    for form in FORMS:
        for size in range(4):
            if form["widening"] and size == 0:
                continue
            for destination, source, right in ((0, 1, 2), (0, 0, 2), (0, 1, 0), (0, 0, 0), (31, 31, 31)):
                for predicate in (0, 7):
                    for extra in (False, True):
                        word = encode(form, size, destination, source, right, predicate,
                                      scaled=extra and size != 0, rotate_270=extra)
                        output.setdefault(word, decode(word))
    return tuple(output.values())
