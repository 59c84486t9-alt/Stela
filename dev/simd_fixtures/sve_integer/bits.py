"""Pure predicated SVE integer bit operations; no host execution or support credit.

The shared execution boundary owns features, CheckSVEEnabled, CurrentVL and
MOVPRFX legality. Only seven merging Apple candidate forms are represented.
"""
from dataclasses import dataclass
import random

FOCUS = 'sve_integer_bits'
BITS_PER_BYTE = 8
VECTOR_REGISTERS = 32
PREDICATE_REGISTERS = 16
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256
ENCODING_MASK = 0xff3fe000
SIZE_SHIFT = 22
SIZE_MASK = 3
PREDICATE_SHIFT = 10
PREDICATE_MASK = 7
SOURCE_SHIFT = 5
REGISTER_MASK = 31
FORMS = {
    'cls': ('cls_z_p_z_m', 0x0418a000, ENCODING_MASK),
    'clz': ('clz_z_p_z_m', 0x0419a000, ENCODING_MASK),
    'cnt': ('cnt_z_p_z_m', 0x041aa000, ENCODING_MASK),
    'rbit': ('rbit_z_p_z_m', 0x05278000, ENCODING_MASK),
    'revb': ('revb_z_z_m', 0x05248000, ENCODING_MASK),
    'revh': ('revh_z_z_m', 0x05258000, ENCODING_MASK),
    'revw': ('revw_z_z_m', 0x05268000, ENCODING_MASK),
}
CANONICAL_FORMS = tuple(row[0] for row in FORMS.values())
REVERSE_GROUP_BYTES = {'revb': 1, 'revh': 2, 'revw': 4}


@dataclass(frozen=True)
class Operand:
    operation: str
    destination: int
    source: int
    element_bytes: int
    predicate: int


def _validate(operand):
    if (operand.operation not in FORMS or type(operand.element_bytes) is not int
            or operand.element_bytes not in (1, 2, 4, 8)):
        raise ValueError('unallocated SVE bit operation or element size')
    if operand.element_bytes <= REVERSE_GROUP_BYTES.get(operand.operation, 0):
        raise ValueError('reserved reverse-group element size')
    if any(type(index) is not int or not 0 <= index < VECTOR_REGISTERS
           for index in (operand.source, operand.destination)):
        raise ValueError('invalid Z register')
    if type(operand.predicate) is not int or not 0 <= operand.predicate <= PREDICATE_MASK:
        raise ValueError('governing predicate must be P0..P7')


def decode(word):
    """Return None for unrelated words; reject related reserved widths."""
    if type(word) is not int or not 0 <= word < 1 << 32:
        raise ValueError('expected one unsigned A64 word')
    for operation, (_, opcode, mask) in FORMS.items():
        if word & mask == opcode:
            operand = Operand(operation, word & REGISTER_MASK,
                              (word >> SOURCE_SHIFT) & REGISTER_MASK,
                              1 << ((word >> SIZE_SHIFT) & SIZE_MASK),
                              (word >> PREDICATE_SHIFT) & PREDICATE_MASK)
            _validate(operand)
            return operand
    return None


def encode(operand):
    _validate(operand)
    size = operand.element_bytes.bit_length() - 1
    return (FORMS[operand.operation][1] | size << SIZE_SHIFT
            | operand.predicate << PREDICATE_SHIFT
            | operand.source << SOURCE_SHIFT | operand.destination)


def lane(operation, value, element_bytes):
    """Mathematical unsigned element result, independent of x86 recipes."""
    _validate(Operand(operation, 0, 0, element_bytes, 0))
    bits = element_bytes * BITS_PER_BYTE
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError('element value exceeds its unsigned width')
    if operation == 'cls':
        normalized = value ^ (((1 << bits) - 1) if value >> (bits - 1) else 0)
        return bits - normalized.bit_length() - 1
    if operation == 'clz':
        return bits - value.bit_length()
    if operation == 'cnt':
        return bin(value).count('1')
    if operation == 'rbit':
        return int(f'{value:0{bits}b}'[::-1], 2)
    group_bits = REVERSE_GROUP_BYTES[operation] * BITS_PER_BYTE
    group_mask = (1 << group_bits) - 1
    result = 0
    for offset in range(0, bits, group_bits):
        result = (result << group_bits) | ((value >> offset) & group_mask)
    return result


def apply(operand, vectors, predicates):
    """Return the complete Z register bank, changing only destination.

    Inputs are snapshotted, including Zn == Zd. P bit at the element's first
    byte controls the whole element; other P bits are ignored. P, GPR/SP,
    NZCV, FPCR/FPSR, FFR, ZA/ZT and memory remain unchanged.
    """
    _validate(operand)
    if len(vectors) != VECTOR_REGISTERS or len(predicates) != PREDICATE_REGISTERS:
        raise ValueError('complete Z and P banks are required')
    vector_bytes = len(vectors[0])
    if not MIN_VECTOR_BYTES <= vector_bytes <= MAX_VECTOR_BYTES or vector_bytes % MIN_VECTOR_BYTES:
        raise ValueError('vector length must be a multiple of 16 bytes in 16..256')
    if any(len(vector) != vector_bytes for vector in vectors):
        raise ValueError('inconsistent Z register lengths')
    if any(len(predicate) != vector_bytes // BITS_PER_BYTE for predicate in predicates):
        raise ValueError('inconsistent packed P register lengths')
    result = [bytes(vector) for vector in vectors]
    source = result[operand.source]
    destination = bytearray(result[operand.destination])
    predicate = int.from_bytes(predicates[operand.predicate], 'little')
    width = operand.element_bytes
    for offset in range(0, vector_bytes, width):
        if predicate & (1 << offset):
            value = int.from_bytes(source[offset:offset + width], 'little')
            destination[offset:offset + width] = lane(operand.operation, value, width).to_bytes(width, 'little')
    result[operand.destination] = bytes(destination)
    return tuple(result)


def functions():
    """Operand coverage without scalable transport or native execution."""
    result = {}
    for operation in FORMS:
        for width in (1, 2, 4, 8):
            if width <= REVERSE_GROUP_BYTES.get(operation, 0):
                continue
            for destination, source, predicate in ((0, 1, 0), (31, 31, 7), (17, 5, 3)):
                operand = Operand(operation, destination, source, width, predicate)
                result[encode(operand)] = operand
    return result


def fixtures():
    """Directed mathematical fixtures; records do not imply ARM verification."""
    rng = random.Random(0x5a11b170)
    for word, operand in functions().items():
        bits = operand.element_bytes * BITS_PER_BYTE
        for vector_bytes in (16, 32, 64, 128, 256):
            width = operand.element_bytes
            lane_mask = sum(1 << offset for offset in range(0, vector_bytes, width))
            alternating = sum(1 << offset for offset in range(0, vector_bytes, width * 2))
            irrelevant = ((1 << vector_bytes) - 1) ^ lane_mask
            for predicate_class, predicate in (('none', 0), ('all', (1 << vector_bytes) - 1),
                                                ('alternating', alternating), ('irrelevant', irrelevant)):
                directed = (0, (1 << bits) - 1, 1 << (bits - 1), (1 << (bits - 1)) - 1)
                source = b''.join((directed[index] if index < len(directed)
                                   else rng.getrandbits(bits)).to_bytes(width, 'little')
                                  for index in range(vector_bytes // width))
                vectors = [rng.randbytes(vector_bytes) for _ in range(VECTOR_REGISTERS)]
                predicates = [rng.randbytes(vector_bytes // BITS_PER_BYTE) for _ in range(PREDICATE_REGISTERS)]
                vectors[operand.source] = source
                predicates[operand.predicate] = predicate.to_bytes(vector_bytes // BITS_PER_BYTE, 'little')
                yield {'kind': FOCUS, 'canonical_id': FORMS[operand.operation][0],
                       'word': word, 'operand': operand, 'vectors': tuple(vectors),
                       'predicates': tuple(predicates), 'predicate_class': predicate_class,
                       'expected_vectors': apply(operand, vectors, predicates)}


def cases(vector_bytes):
    """Common full-state transport; lifted from the retained original producer."""
    from scalable_frame import (SME_LENGTHS, seeded_snapshot, snapshot_from_state,
                                snapshot_to_state)
    if vector_bytes not in SME_LENGTHS:
        raise ValueError('streaming profile requires a supported SME vector length')
    for index, row in enumerate(fixtures()):
        if len(row['vectors'][0]) != vector_bytes:
            continue
        initial = seeded_snapshot(vector_bytes,
                                  f'sve-bits:{row["word"]:08x}:{index}'.encode())
        state = snapshot_to_state(initial)
        state['z'] = list(row['vectors'])
        state['p'] = [int.from_bytes(value, 'little') for value in row['predicates']]
        initial = snapshot_from_state(initial, state)
        result = dict(state)
        result['z'] = list(row['expected_vectors'])
        expected = snapshot_from_state(initial, result)
        yield {'operation': {'word': row['word'], 'canonical_id': row['canonical_id']},
               'initial': initial, 'expected': expected, 'required': int(initial.valid)}
