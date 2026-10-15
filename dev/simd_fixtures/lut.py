"""AdvSIMD LUT words, full-state fixtures and independent packed-bit model."""
import struct

from differential import State, seed_extended_state

FOCUS = 'lut'
CANONICAL_FORMS = ('LUTI2_asimdtbl_L5', 'LUTI2_asimdtbl_L6',
                   'LUTI4_asimdtbl_L5', 'LUTI4_asimdtbl_L7')
FORMS = {
    CANONICAL_FORMS[0]: (0x4e801000, 2, 1, 4),
    CANONICAL_FORMS[1]: (0x4ec00000, 2, 2, 8),
    CANONICAL_FORMS[2]: (0x4e402000, 4, 1, 2),
    CANONICAL_FORMS[3]: (0x4e401000, 4, 2, 4),
}
ALIAS_ROLES = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1),
               (0, 31, 2), (31, 31, 2), (0, 31, 0), (31, 31, 31))
MASK64 = (1 << 64) - 1


def operation(canonical_id, segment=0, d=0, n=1, m=2):
    base, index_bits, element_bytes, segments = FORMS[canonical_id]
    if not 0 <= segment < segments or any(not 0 <= r < 32 for r in (d, n, m)):
        raise ValueError('LUT register or segment outside allocated range')
    shift = 12 if (index_bits, element_bytes) == (2, 2) else 14 if (index_bits, element_bytes) == (4, 1) else 13
    return {'kind': FOCUS, 'name': 'luti' + str(index_bits), 'word': base | segment << shift | m << 16 | n << 5 | d,
            'canonical_id': canonical_id, 'd': d, 'n': n, 'm': m,
            'bytes': 16, 'lane': element_bytes, 'output_lane': element_bytes,
            'output_kind': 'vector', 'scalar': False, 'upper': False,
            'index_bits': index_bits, 'segment': segment,
            'table_registers': 2 if (index_bits, element_bytes) == (4, 2) else 1}


def functions():
    return [operation(name, part, *roles) for name, (_, _, _, parts) in FORMS.items()
            for part in range(parts) for roles in ALIAS_ROLES]


def expected(op, initial):
    state = State.from_buffer_copy(initial)
    raw = bytes(initial)
    start = State.v.offset
    indices = int.from_bytes(raw[start + op['m'] * 16:start + (op['m'] + 1) * 16], 'little')
    table = b''.join(raw[start + ((op['n'] + r) % 32) * 16:start + ((op['n'] + r) % 32 + 1) * 16]
                     for r in range(op['table_registers']))
    result = bytearray()
    elements = 16 // op['lane']
    for lane in range(elements):
        index = (indices >> ((op['segment'] * elements + lane) * op['index_bits'])) & ((1 << op['index_bits']) - 1)
        result += table[index * op['lane']:(index + 1) * op['lane']]
    state.v[op['d']][:] = struct.unpack('<2Q', result)
    return state


def initial_state(pattern, flags):
    state = State()
    for register in range(31):
        state.x[register] = (0x9e3779b97f4a7c15 * (register + 1) + pattern) & MASK64
    state.sp = 0x7ffffff0
    state.nzcv = flags << 28
    state.reserved = 0x51ad1234
    seed_extended_state(state, pattern * 16 + flags)
    state.fpcr = (pattern % 4) << 22 | (0x07000000 if flags else 0)
    state.fpsr = 0x0800001f if flags else 0
    for register in range(32):
        if pattern < 4:
            value = bytes([pattern * 85]) * 16
        else:
            value = bytes((register * 53 + lane * 17 + pattern * 31) & 255 for lane in range(16))
        state.v[register][:] = struct.unpack('<2Q', value)
    return state


def corpus():
    operations = functions()
    return operations, [
        {'function': index, 'label': f'pattern_{pattern}_flags_{flags}',
         'initial': bytes(initial_state(pattern, flags)),
         'runtime': pattern == 5 and flags == 15 and (op['d'], op['n'], op['m']) in ALIAS_ROLES[:4]}
        for index, op in enumerate(operations) for pattern in range(6) for flags in (0, 15)]


def optional_opcodes(target_id):
    return {'pshufb'} if 'ssse3' in target_id.split('+') else set()
