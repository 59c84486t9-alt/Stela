"""Classic .16B AES fixtures: independent polynomial model, complete state.

Scope: FEAT_AES, FP/AdvSIMD enabled and non-streaming; no upper scalable
register, disabled-access, physical timing or PSTATE.DIT verification claim.
The shared engine owns original/native execution, binaries and evidence.
"""
import random

from differential import State, seed_extended_state

FOCUS = 'aes'
CANONICAL_FORMS = (
    'AESE_B_cryptoaes', 'AESD_B_cryptoaes',
    'AESMC_B_cryptoaes', 'AESIMC_B_cryptoaes',
)
FORM_VALUES = {'aese': 0x4e284800, 'aesd': 0x4e285800,
               'aesmc': 0x4e286800, 'aesimc': 0x4e287800}
FORM_MASK = 0xfffffc00
FIELD_POLYNOMIAL = 0x11b
BYTE_MASK = 0xff
LIMB_MASK = (1 << 64) - 1
FORWARD_MATRIX = ((2, 3, 1, 1), (1, 2, 3, 1),
                  (1, 1, 2, 3), (3, 1, 1, 2))
INVERSE_MATRIX = ((14, 11, 13, 9), (9, 14, 11, 13),
                  (13, 9, 14, 11), (11, 13, 9, 14))


def field_multiply(left, right):
    """Schoolbook carryless polynomial product, then independent reduction."""
    product = 0
    for bit in range(8):
        if right & (1 << bit):
            product ^= left << bit
    for degree in range(14, 7, -1):
        if product & (1 << degree):
            product ^= FIELD_POLYNOMIAL << (degree - 8)
    return product


def field_inverse(value):
    result = 1
    factor = value
    power = 254
    while power:
        if power & 1:
            result = field_multiply(result, factor)
        factor = field_multiply(factor, factor)
        power >>= 1
    return result


def rotate_byte(value, amount):
    return ((value << amount) | (value >> (8 - amount))) & BYTE_MASK


def substitute_byte(value):
    inverse = field_inverse(value)
    result = inverse ^ 0x63
    for rotation in (1, 2, 3, 4):
        result ^= rotate_byte(inverse, rotation)
    return result


SBOX = tuple(substitute_byte(value) for value in range(256))
_inverse = [0] * 256
for _index, _value in enumerate(SBOX):
    _inverse[_value] = _index
INVERSE_SBOX = tuple(_inverse)
del _inverse, _index, _value


def shift_rows(value, inverse=False):
    direction = -1 if inverse else 1
    return bytes(value[4 * ((column + direction * row) % 4) + row]
                 for column in range(4) for row in range(4))


def mix_columns(value, inverse=False):
    matrix = INVERSE_MATRIX if inverse else FORWARD_MATRIX
    result = bytearray(16)
    for column in range(4):
        for row in range(4):
            output = 0
            for item in range(4):
                output ^= field_multiply(matrix[row][item], value[4 * column + item])
            result[4 * column + row] = output
    return bytes(result)


def operation(name, destination, source):
    if name not in FORM_VALUES or not (0 <= destination < 32 and 0 <= source < 32):
        raise ValueError('invalid classic AES form or vector register')
    return {'kind': FOCUS, 'name': name, 'd': destination, 'n': source, 'm': source,
            'lane': 1, 'bytes': 16, 'scalar': False, 'output_kind': 'vector',
            'word': FORM_VALUES[name] | (source << 5) | destination,
            'canonical_id': name.upper() + '_B_cryptoaes'}


def functions():
    return [operation(name, destination, source)
            for name in FORM_VALUES for destination in range(32) for source in range(32)]


def vector_bytes(state, register):
    low, high = state.v[register]
    return (low | (high << 64)).to_bytes(16, 'little')


def set_vector(state, register, value):
    packed = int.from_bytes(value, 'little')
    state.v[register][:] = [packed & LIMB_MASK, packed >> 64]


def expected(op, initial):
    state = State.from_buffer_copy(initial)
    value = vector_bytes(initial, op['n'])
    if op['name'] in ('aese', 'aesd'):
        old = vector_bytes(initial, op['d'])
        value = bytes(left ^ right for left, right in zip(value, old))
        inverse = op['name'] == 'aesd'
        table = INVERSE_SBOX if inverse else SBOX
        value = bytes(table[item] for item in shift_rows(value, inverse))
    else:
        value = mix_columns(value, op['name'] == 'aesimc')
    set_vector(state, op['d'], value)
    return state


def initial_state(index):
    rng = random.Random(0xae500000 + index)
    state = State()
    state.x[:] = [rng.getrandbits(64) for _ in range(31)]
    state.sp = 0x30000800
    state.nzcv = (index % 16) << 28
    state.reserved = rng.getrandbits(32)
    seed_extended_state(state, 0xae510000 + index)
    return state


def corpus():
    programs = functions()
    records = []
    lookup = {(op['name'], op['d'], op['n']): index for index, op in enumerate(programs)}

    def record(index, state, label):
        op = programs[index]
        runtime = False
        if label == 'all_register_pairs' and (op['d'], op['n']) in (
                (0, 1), (31, 31), (31, 0), (0, 31)):
            runtime = True
            state.fpcr = 0x07c00000 if op['d'] == 31 else 0
            state.fpsr = 0x0800001f if op['d'] == 31 else 0
        elif label == 'all_sbox_bytes_each_lane':
            runtime = vector_bytes(state, 1)[0] in (0, 1, 0x53, 0x63, 0x80, 0xff)
        elif label == 'column_basis':
            bit = int.from_bytes(vector_bytes(state, 1), 'little').bit_length() - 1
            runtime = bit in (0, 7, 8, 15, 31, 63, 64, 127)
        elif label == 'v31_alias_edges':
            runtime = True
        records.append({'function': index, 'initial': bytes(state), 'label': label,
                        'runtime': runtime})

    for index in range(len(programs)):
        record(index, initial_state(index), 'all_register_pairs')
    # Across 256 cyclic blocks, every byte value occurs in every one of 16 lanes.
    for name in ('aese', 'aesd'):
        index = lookup[name, 0, 1]
        for value in range(256):
            state = initial_state(len(records))
            set_vector(state, 0, bytes(16))
            set_vector(state, 1, bytes((value + lane) & BYTE_MASK for lane in range(16)))
            record(index, state, 'all_sbox_bytes_each_lane')
    # Linear column transforms: every basis bit, including all reduction bits.
    for name in ('aesmc', 'aesimc'):
        index = lookup[name, 0, 1]
        for bit in range(128):
            state = initial_state(len(records))
            set_vector(state, 0, bytes([BYTE_MASK] * 16))  # Stale destination.
            set_vector(state, 1, (1 << bit).to_bytes(16, 'little'))
            record(index, state, 'column_basis')
    for name in FORM_VALUES:
        index = lookup[name, 31, 31]
        for value in (0, 1, 0x80, 0xff):
            state = initial_state(len(records))
            set_vector(state, 31, bytes([value] * 16))
            record(index, state, 'v31_alias_edges')
    return programs, records


def chains():
    """Optional shared-runner sequences; expected() applies each step in order."""
    return [
        [operation('aese', 0, 1), operation('aesmc', 0, 0),
         operation('aesd', 31, 0), operation('aesimc', 31, 31)],
        [operation('aesimc', 2, 31), operation('aesmc', 31, 2),
         operation('aese', 31, 31), operation('aesd', 0, 31)],
    ]


def optional_opcodes(target_id):
    features = set(target_id.split('+')[1:])
    if 'aes' in features:
        return {'aesenclast', 'aesdeclast', 'aesenc', 'aesimc'}
    if 'ssse3' in features:
        return {'pshufb'}
    return set()
