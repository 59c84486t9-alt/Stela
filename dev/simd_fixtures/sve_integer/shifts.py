"""Independent SVE shift fixture model.

Vectors are little-endian bytes of current streaming VL. Predicate bit index is
byte index; only the first predicate bit of each element controls that element.
All operands are snapshotted before commit, including destination/count aliases.
"""
from __future__ import annotations

from dataclasses import dataclass

BYTE_BITS = 8
MAX_VECTOR_BITS = 2048
MIN_VECTOR_BITS = 128
VECTOR_QUANTUM_BITS = 128
REGISTER_COUNT = 32
PREDICATE_COUNT = 16
FIELD_LAYOUTS = {'PREDICATED_IMMEDIATE': {'tszh': {'shift': 22, 'bits': 2},
                          'Pg': {'shift': 10, 'bits': 3},
                          'tszl': {'shift': 8, 'bits': 2},
                          'imm3': {'shift': 5, 'bits': 3},
                          'Zdn': {'shift': 0, 'bits': 5}},
 'PREDICATED_WIDE': {'size': {'shift': 22, 'bits': 2},
                     'Pg': {'shift': 10, 'bits': 3},
                     'Zm': {'shift': 5, 'bits': 5},
                     'Zdn': {'shift': 0, 'bits': 5}},
 'PREDICATED_ELEMENTS': {'size': {'shift': 22, 'bits': 2},
                         'Pg': {'shift': 10, 'bits': 3},
                         'Zm': {'shift': 5, 'bits': 5},
                         'Zdn': {'shift': 0, 'bits': 5}},
 'IMMEDIATE': {'tszh': {'shift': 22, 'bits': 2},
               'tszl': {'shift': 19, 'bits': 2},
               'imm3': {'shift': 16, 'bits': 3},
               'Zn': {'shift': 5, 'bits': 5},
               'Zd': {'shift': 0, 'bits': 5}},
 'WIDE': {'size': {'shift': 22, 'bits': 2},
          'Zm': {'shift': 16, 'bits': 5},
          'Zn': {'shift': 5, 'bits': 5},
          'Zd': {'shift': 0, 'bits': 5}},
 'XOR_ROTATE': {'tszh': {'shift': 22, 'bits': 2},
                'tszl': {'shift': 19, 'bits': 2},
                'imm3': {'shift': 16, 'bits': 3},
                'Zm': {'shift': 5, 'bits': 5},
                'Zdn': {'shift': 0, 'bits': 5}}}

ENCODINGS = (
    ('asrr_z_p_zz_', 'ASRR', 0xff3fe000, 0x04148000, 'PREDICATED_ELEMENTS'),
    ('lslr_z_p_zz_', 'LSLR', 0xff3fe000, 0x04178000, 'PREDICATED_ELEMENTS'),
    ('lsrr_z_p_zz_', 'LSRR', 0xff3fe000, 0x04158000, 'PREDICATED_ELEMENTS'),
    ('sqrshlr_z_p_zz_', 'SQRSHLR', 0xff3fe000, 0x440e8000, 'PREDICATED_ELEMENTS'),
    ('sqshlr_z_p_zz_', 'SQSHLR', 0xff3fe000, 0x440c8000, 'PREDICATED_ELEMENTS'),
    ('srshlr_z_p_zz_', 'SRSHLR', 0xff3fe000, 0x44068000, 'PREDICATED_ELEMENTS'),
    ('uqrshlr_z_p_zz_', 'UQRSHLR', 0xff3fe000, 0x440f8000, 'PREDICATED_ELEMENTS'),
    ('uqshlr_z_p_zz_', 'UQSHLR', 0xff3fe000, 0x440d8000, 'PREDICATED_ELEMENTS'),
    ('urshlr_z_p_zz_', 'URSHLR', 0xff3fe000, 0x44078000, 'PREDICATED_ELEMENTS'),

    ('asr_z_p_zi_', 'ASR', 0xff3fe000, 0x04008000, 'PREDICATED_IMMEDIATE'),
    ('asr_z_p_zw_', 'ASR', 0xff3fe000, 0x04188000, 'PREDICATED_WIDE'),
    ('asr_z_p_zz_', 'ASR', 0xff3fe000, 0x04108000, 'PREDICATED_ELEMENTS'),
    ('asr_z_zi_', 'ASR', 0xff20fc00, 0x04209000, 'IMMEDIATE'),
    ('asr_z_zw_', 'ASR', 0xff20fc00, 0x04208000, 'WIDE'),
    ('asrd_z_p_zi_', 'ASRD', 0xff3fe000, 0x04048000, 'PREDICATED_IMMEDIATE'),
    ('lsl_z_p_zi_', 'LSL', 0xff3fe000, 0x04038000, 'PREDICATED_IMMEDIATE'),
    ('lsl_z_p_zw_', 'LSL', 0xff3fe000, 0x041b8000, 'PREDICATED_WIDE'),
    ('lsl_z_p_zz_', 'LSL', 0xff3fe000, 0x04138000, 'PREDICATED_ELEMENTS'),
    ('lsl_z_zi_', 'LSL', 0xff20fc00, 0x04209c00, 'IMMEDIATE'),
    ('lsl_z_zw_', 'LSL', 0xff20fc00, 0x04208c00, 'WIDE'),
    ('lsr_z_p_zi_', 'LSR', 0xff3fe000, 0x04018000, 'PREDICATED_IMMEDIATE'),
    ('lsr_z_p_zw_', 'LSR', 0xff3fe000, 0x04198000, 'PREDICATED_WIDE'),
    ('lsr_z_p_zz_', 'LSR', 0xff3fe000, 0x04118000, 'PREDICATED_ELEMENTS'),
    ('lsr_z_zi_', 'LSR', 0xff20fc00, 0x04209400, 'IMMEDIATE'),
    ('lsr_z_zw_', 'LSR', 0xff20fc00, 0x04208400, 'WIDE'),
    ('sli_z_zzi_', 'SLI', 0xff20fc00, 0x4500f400, 'IMMEDIATE'),
    ('sqrshl_z_p_zz_', 'SQRSHL', 0xff3fe000, 0x440a8000, 'PREDICATED_ELEMENTS'),
    ('sqshl_z_p_zi_', 'SQSHL', 0xff3fe000, 0x04068000, 'PREDICATED_IMMEDIATE'),
    ('sqshl_z_p_zz_', 'SQSHL', 0xff3fe000, 0x44088000, 'PREDICATED_ELEMENTS'),
    ('sqshlu_z_p_zi_', 'SQSHLU', 0xff3fe000, 0x040f8000, 'PREDICATED_IMMEDIATE'),
    ('sri_z_zzi_', 'SRI', 0xff20fc00, 0x4500f000, 'IMMEDIATE'),
    ('srshl_z_p_zz_', 'SRSHL', 0xff3fe000, 0x44028000, 'PREDICATED_ELEMENTS'),
    ('srshr_z_p_zi_', 'SRSHR', 0xff3fe000, 0x040c8000, 'PREDICATED_IMMEDIATE'),
    ('srsra_z_zi_', 'SRSRA', 0xff20fc00, 0x4500e800, 'IMMEDIATE'),
    ('ssra_z_zi_', 'SSRA', 0xff20fc00, 0x4500e000, 'IMMEDIATE'),
    ('uqrshl_z_p_zz_', 'UQRSHL', 0xff3fe000, 0x440b8000, 'PREDICATED_ELEMENTS'),
    ('uqshl_z_p_zi_', 'UQSHL', 0xff3fe000, 0x04078000, 'PREDICATED_IMMEDIATE'),
    ('uqshl_z_p_zz_', 'UQSHL', 0xff3fe000, 0x44098000, 'PREDICATED_ELEMENTS'),
    ('urshl_z_p_zz_', 'URSHL', 0xff3fe000, 0x44038000, 'PREDICATED_ELEMENTS'),
    ('urshr_z_p_zi_', 'URSHR', 0xff3fe000, 0x040d8000, 'PREDICATED_IMMEDIATE'),
    ('ursra_z_zi_', 'URSRA', 0xff20fc00, 0x4500ec00, 'IMMEDIATE'),
    ('usra_z_zi_', 'USRA', 0xff20fc00, 0x4500e400, 'IMMEDIATE'),
    ('xar_z_zzi_', 'XAR', 0xff20fc00, 0x04203400, 'XOR_ROTATE'),
)
ROWS = [dict(id=form, mnemonic=mnemonic, mask=mask, value=value, fields=FIELD_LAYOUTS[layout])
        for form, mnemonic, mask, value, layout in ENCODINGS]

@dataclass(frozen=True)
class Instruction:
    form: str
    mnemonic: str
    element_bits: int
    destination: int
    source: int
    counts: int | None
    predicate: int | None
    immediate: int | None
    wide_counts: bool

def field(word, row, name):
    position = row['fields'][name]
    return (word >> position['shift']) & ((1 << position['bits']) - 1)

def decode(word):
    if not 0 <= word < 1 << 32:
        raise ValueError("instruction must fit unsigned32")
    for row in ROWS:
        if word & row['mask'] != row['value']:
            continue
        names = row['fields']
        immediate = None
        if 'tszh' in names:
            size = (field(word, row, 'tszh') << 2) | field(word, row, 'tszl')
            if size == 0:
                raise ValueError('unallocated element width')
            element_bits = BYTE_BITS << (size.bit_length() - 1)
            encoded = (size << 3) | field(word, row, 'imm3')
            immediate = (encoded - element_bits if row['mnemonic'].lower() in
                         {'lsl', 'sqshl', 'uqshl', 'sqshlu', 'sli'} else
                         2 * element_bits - encoded)
        else:
            size = field(word, row, 'size')
            if '_zw_' in row['id'] and size == 3:
                raise ValueError('wide count does not allocate 64-bit data lanes')
            element_bits = BYTE_BITS << size
        destination_name = next(n for n in ('Zdn', 'Zda', 'Zd') if n in names)
        destination = field(word, row, destination_name)
        source = field(word, row, 'Zn') if 'Zn' in names else destination
        mnemonic = row['mnemonic'].lower()
        reverse = mnemonic in {'asrr', 'lslr', 'lsrr', 'srshlr', 'urshlr', 'sqshlr', 'uqshlr', 'sqrshlr', 'uqrshlr'}
        if reverse:
            source = field(word, row, 'Zm')
        return Instruction(row['id'], mnemonic[:-1] if reverse else mnemonic, element_bits,
                           destination, source,
                           destination if reverse else field(word, row, 'Zm') if 'Zm' in names else None,
                           field(word, row, 'Pg') if 'Pg' in names else None,
                           immediate, '_zw_' in row['id'])
    raise ValueError('outside shift partition')

def signed(value, bits):
    return value - (1 << bits) if value >> (bits - 1) else value

def saturate(value, bits, signed_output):
    minimum = -(1 << (bits - 1)) if signed_output else 0
    maximum = (1 << (bits - int(signed_output))) - 1
    return min(maximum, max(minimum, value))

def lane(instruction, original, source, count):
    bits = instruction.element_bits
    mask = (1 << bits) - 1
    kind = instruction.mnemonic
    amount = instruction.immediate
    if kind in {'asr', 'lsr', 'lsl'}:
        amount = amount if amount is not None else min(count, bits)
        value = signed(source, bits) if kind == 'asr' else source
        result = value << amount if kind == 'lsl' else value >> amount
    elif kind == 'asrd':
        value = signed(source, bits)
        result = (value + ((1 << amount) - 1 if value < 0 else 0)) >> amount
    elif kind in {'srshr', 'urshr'}:
        value = signed(source, bits) if kind == 'srshr' else source
        result = (value + (1 << (amount - 1))) >> amount
    elif kind in {'sqshl', 'uqshl', 'sqshlu', 'srshl', 'urshl', 'sqrshl', 'uqrshl'}:
        signed_input = kind.startswith('s')
        value = signed(source, bits) if signed_input else source
        if amount is None:
            # ShiftSat consumes the complete signed element, unlike NEON's
            # low-byte variable shift count. It clamps to +/- (esize + 1).
            amount = min(bits + 1, max(-(bits + 1), signed(count, bits)))
        if amount >= 0:
            result = value << amount
        else:
            right = -amount
            rounded = kind in {'srshl', 'urshl', 'sqrshl', 'uqrshl'}
            result = (value + ((1 << (right - 1)) if rounded else 0)) >> right
        if kind in {'sqshl', 'uqshl', 'sqshlu', 'sqrshl', 'uqrshl'}:
            result = saturate(result, bits, kind in {'sqshl', 'sqrshl'})
    elif kind == 'sli':
        result = (original & ((1 << amount) - 1)) | (source << amount)
    elif kind == 'sri':
        low = (1 << (bits - amount)) - 1
        result = (original & ~low) | (source >> amount)
    elif kind in {'ssra', 'usra', 'srsra', 'ursra'}:
        value = signed(source, bits) if kind in {'ssra', 'srsra'} else source
        rounded = kind in {'srsra', 'ursra'}
        result = original + ((value + ((1 << (amount - 1)) if rounded else 0)) >> amount)
    elif kind == 'xar':
        value = source ^ count
        rotation = amount % bits
        result = (value >> rotation) | (value << ((bits - rotation) % bits))
    else:
        raise ValueError(kind)
    return result & mask

def execute(instruction, vectors, predicates, *, streaming=True):
    if not streaming:
        raise ValueError('Apple SME-only profile requires streaming mode')
    if len(vectors) != REGISTER_COUNT or len(predicates) != PREDICATE_COUNT:
        raise ValueError('wrong architectural register count')
    vector_bytes = len(vectors[0])
    vector_bits = vector_bytes * BYTE_BITS
    if (vector_bits < MIN_VECTOR_BITS or vector_bits > MAX_VECTOR_BITS or
            vector_bits % VECTOR_QUANTUM_BITS or
            any(len(vector) != vector_bytes for vector in vectors)):
        raise ValueError('invalid current vector length')
    old = bytes(vectors[instruction.destination])
    source = bytes(vectors[instruction.source])
    counts = bytes(vectors[instruction.counts]) if instruction.counts is not None else None
    predicate = predicates[instruction.predicate] if instruction.predicate is not None else None
    result = bytearray(old)
    lane_bytes = instruction.element_bits // BYTE_BITS
    for offset in range(0, vector_bytes, lane_bytes):
        if predicate is not None and not (predicate >> offset) & 1:
            continue
        original = int.from_bytes(old[offset:offset+lane_bytes], 'little')
        value = int.from_bytes(source[offset:offset+lane_bytes], 'little')
        count_bytes = 8 if instruction.wide_counts else lane_bytes
        count_offset = offset // 8 * 8 if instruction.wide_counts else offset
        count = int.from_bytes(counts[count_offset:count_offset+count_bytes], 'little') if counts is not None else 0
        result[offset:offset+lane_bytes] = lane(instruction, original, value, count).to_bytes(lane_bytes, 'little')
    output = list(vectors)
    output[instruction.destination] = bytes(result)
    return output


def apply(instruction, vectors, predicates):
    """Common fixture adapter; predicate storage may be bytes or packed integers."""
    packed = [value if isinstance(value, int) else int.from_bytes(value, 'little')
              for value in predicates]
    return tuple(execute(instruction, vectors, packed))


def encode(row, bits, amount, destination, source, counts, predicate):
    """Construct an allocated word from named canonical encoding fields."""
    values = {'size': bits.bit_length() - 4, 'Zd': destination,
              'Zdn': destination, 'Zn': source, 'Zm': counts, 'Pg': predicate}
    if 'tszh' in row['fields']:
        left = row['mnemonic'].lower() in {'lsl', 'sqshl', 'uqshl', 'sqshlu', 'sli'}
        packed = bits + amount if left else 2 * bits - amount
        size, low = divmod(packed, BYTE_BITS)
        values.update(tszh=size >> 2, tszl=size & 3, imm3=low)
    word = row['value']
    for name, value in values.items():
        if name in row['fields']:
            word |= value << row['fields'][name]['shift']
    decode(word)
    return word


def cases(vector_bytes):
    """Bounded full-state original/native inputs at one supported streaming VL.

    The shared frame owner provides dirty non-target banks, controls and scalar
    state. Counts cover complete-lane sign/range boundaries and low-byte aliases.
    """
    from scalable_frame import (seeded_snapshot, snapshot_from_state,
                                snapshot_to_state, require_sme_length)
    require_sme_length(vector_bytes)
    serial = 0
    for row in ROWS:
        for bits in (8, 16, 32, 64):
            if '_zw_' in row['id'] and bits == 64:
                continue
            immediate = 'tszh' in row['fields']
            left = row['mnemonic'].lower() in {'lsl', 'sqshl', 'uqshl', 'sqshlu', 'sli'}
            amounts = sorted({0 if left else 1, 1, bits // 2, bits - 1 if left else bits}) if immediate else [None]
            for amount in amounts:
                aliases = ((0, 1, 2, 0), (31, 31, 31, 7))
                if (not immediate and bits >= 32 and '_zz_' in row['id']
                        and row['mnemonic'] in {'ASR', 'LSL', 'LSR', 'ASRR', 'LSLR', 'LSRR'}):
                    # Direct per-element host mappings must snapshot partially
                    # aliased data/count/destination operands before publication.
                    aliases += ((0, 0, 2, 0), (0, 1, 0, 0), (0, 1, 1, 0))
                for destination, source, counts, predicate in aliases:
                    word = encode(row, bits, amount, destination, source, counts, predicate)
                    instruction = decode(word)
                    count_values = (-bits-2, -bits-1, -bits, -1, 0, 1, bits-1,
                                    bits, bits+1, bits+2, 0x100, 0x101,
                                    0x100000001, -(1 << (bits-1)), (1 << (bits-1))-1,
                                    1 << (bits-1), (1 << bits)-1)
                    count_bytes = 8 if instruction.wide_counts else bits // BYTE_BITS
                    count_lanes = vector_bytes // count_bytes
                    repetitions = 1 if immediate else (len(count_values) + count_lanes - 1) // count_lanes
                    for repetition in range(repetitions):
                        serial += 1
                        seed = f'sve-shifts:{word:08x}:{vector_bytes}:{repetition}'.encode()
                        initial = seeded_snapshot(vector_bytes, seed)
                        state = snapshot_to_state(initial)
                        lane_bytes = bits // BYTE_BITS
                        raw_mask = (1 << bits) - 1
                        values = (0, 1, raw_mask, 1 << (bits-1), (1 << (bits-1))-1,
                                  raw_mask-1, 3, (1 << (bits-1))+1)
                        state['z'][instruction.source] = b''.join(
                            values[(lane + repetition) % len(values)].to_bytes(lane_bytes, 'little')
                            for lane in range(vector_bytes // lane_bytes))
                        if instruction.counts is not None:
                            count_mask = (1 << (count_bytes * BYTE_BITS)) - 1
                            state['z'][instruction.counts] = b''.join(
                                (count_values[(lane + repetition * count_lanes) % len(count_values)] & count_mask).to_bytes(count_bytes, 'little')
                                for lane in range(count_lanes))
                        if instruction.predicate is not None:
                            # Alternating controlling bits plus every irrelevant
                            # predicate bit catches accidental byte predication.
                            lane_mask = sum(1 << byte for byte in range(0, vector_bytes, lane_bytes))
                            active = sum(1 << byte for byte in range(0, vector_bytes, lane_bytes * 2))
                            predicate_bits = ((1 << vector_bytes)-1 if serial % 2 else
                                              active | (((1 << vector_bytes)-1) ^ lane_mask))
                            state['p'][instruction.predicate] = predicate_bits
                        initial = snapshot_from_state(initial, state)
                        result = dict(state)
                        result['z'] = execute(instruction, state['z'], state['p'])
                        expected = snapshot_from_state(initial, result)
                        yield {'operation': {'word': word, 'canonical_id': row['id']},
                               'initial': initial, 'expected': expected,
                               'required': int(initial.valid)}
                        if (instruction.predicate is not None and repetition == 0
                                and amount == amounts[0] and destination == 0):
                            inactive = dict(state)
                            inactive['p'] = list(state['p'])
                            inactive['p'][instruction.predicate] = 0
                            empty = snapshot_from_state(initial, inactive)
                            yield {'operation': {'word': word, 'canonical_id': row['id']},
                                   'initial': empty, 'expected': empty,
                                   'required': int(empty.valid)}
