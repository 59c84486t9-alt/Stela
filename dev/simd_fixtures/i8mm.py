"""Pure classic I8MM fixtures: original words and independent integer semantics."""
import struct

from differential import State, seed_extended_state

FOCUS = 'i8mm'
CANONICAL_FORMS = (
    'SMMLA_asimdsame2_G', 'UMMLA_asimdsame2_G', 'USMMLA_asimdsame2_G',
    'USDOT_asimdsame2_D', 'USDOT_asimdelem_D', 'SUDOT_asimdelem_D',
)
MATRIX_BASES = {'smmla': 0x4e80a400, 'ummla': 0x6e80a400, 'usmmla': 0x4e80ac00}
DOT_BASES = {'usdot': 0x0e809c00}
INDEXED_BASES = {'usdot': 0x0f80f000, 'sudot': 0x0f00f000}
MASK64 = (1 << 64) - 1
FPSR_QC = 1 << 27
ALIAS_ROLES = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1), (31, 31, 31), (31, 29, 31))


def operation(name, count=16, index=None, d=0, n=1, m=2):
    matrix = name in MATRIX_BASES
    if count not in (8, 16) or any(not 0 <= register < 32 for register in (d, n, m)):
        raise ValueError('I8MM vector width/register outside allocated range')
    if matrix:
        if count != 16 or index is not None:
            raise ValueError('I8MM matrices have only the full 128-bit unindexed form')
        base, canonical = MATRIX_BASES[name], name.upper() + '_asimdsame2_G'
    elif index is None:
        if name not in DOT_BASES:
            raise ValueError('Only USDOT has a mixed-sign vector encoding')
        base, canonical = DOT_BASES[name], 'USDOT_asimdsame2_D'
    else:
        if name not in INDEXED_BASES or not 0 <= index < 4:
            raise ValueError('I8MM indexed dots select one of four full-source dword groups')
        base, canonical = INDEXED_BASES[name], name.upper() + '_asimdelem_D'
        base |= (index & 1) << 21 | (index >> 1) << 11
    word = base | (count == 16) << 30 | m << 16 | n << 5 | d
    return {'kind': FOCUS, 'name': name, 'word': word, 'canonical_id': canonical,
        'd': d, 'n': n, 'm': m, 'lane': 1, 'output_lane': 4, 'bytes': count,
        'scalar': False, 'upper': False, 'output_kind': 'vector', 'index': index,
        'matrix': matrix, 'left_signed': name in ('smmla', 'sudot'),
        'right_signed': name in ('smmla', 'usmmla', 'usdot')}


def functions():
    layouts = [(name, 16, None) for name in MATRIX_BASES]
    layouts += [('usdot', count, None) for count in (8, 16)]
    layouts += [(name, count, index) for name in INDEXED_BASES
        for count in (8, 16) for index in range(4)]
    result = []
    for name, count, index in layouts:
        registers = [*ALIAS_ROLES, *((d, (d + 5) % 32, (d + 13) % 32) for d in range(32))]
        result.extend(operation(name, count, index, d, n, m) for d, n, m in registers)
    return result


def expected(op, initial):
    """Read old operands before writing; preserve all other 784-byte state fields."""
    state = State.from_buffer_copy(initial)
    left, right, previous = (initial.v[op[key]][0] | initial.v[op[key]][1] << 64 for key in ('n', 'm', 'd'))

    def byte(vector, position, signed):
        value = vector >> (8 * position) & 255
        return value - 256 if signed and value >= 128 else value

    result = 0
    for element in range(op['bytes'] // 4):
        if op['matrix']:
            row, column = divmod(element, 2)
            products = (byte(left, 8 * row + k, op['left_signed']) * byte(right, 8 * column + k, op['right_signed'])
                for k in range(8))
        else:
            group = element if op['index'] is None else op['index']
            products = (byte(left, 4 * element + k, op['left_signed']) * byte(right, 4 * group + k, op['right_signed'])
                for k in range(4))
        value = ((previous >> (32 * element) & 0xffffffff) + sum(products)) & 0xffffffff
        result |= value << (32 * element)
    state.v[op['d']][:] = [result & MASK64, result >> 64]
    return state


def initial_state(op, pattern, flags):
    state = State()
    for register in range(31):
        state.x[register] = (0x9e3779b97f4a7c15 * (register + 1) + pattern) & MASK64
    state.sp = 0x000000007ffffff0
    state.nzcv = flags << 28
    state.reserved = 0x51ad1234
    seed_extended_state(state, pattern * 16 + flags)
    # Every FP rounding mode and the standard AHP/DN/FZ controls must survive
    # unchanged; this family performs no FP arithmetic or status update.
    state.fpcr = (pattern % 4) << 22 | (0x07000000 if flags else 0)
    boundary = (0, 255, 128, 127, 1, 254, 129, 126)
    for register in range(32):
        if pattern < 4:
            values = bytes([boundary[pattern]]) * 16
        elif pattern == 7:
            values = bytes(8) + bytes([255]) * 8
        else:
            values = bytes(boundary[(register + byte + pattern) % len(boundary)] for byte in range(16))
        state.v[register][:] = struct.unpack('<2Q', values)
    if len({op['d'], op['n'], op['m']}) == 3:
        accumulators = (0, 0xffffffff, 0x7fffffff, 0x80000000)
        state.v[op['d']][:] = struct.unpack('<2Q', struct.pack('<4I',
            *(accumulators[(pattern + lane) % 4] for lane in range(4))))
        if pattern in (5, 6):
            state.v[op['n']][:] = [MASK64, MASK64]
            value = int.from_bytes(bytes([127 if pattern == 5 else 128]) * 8, 'little')
            state.v[op['m']][:] = [value, value]
            if op['name'] == 'sudot':
                state.v[op['n']][:], state.v[op['m']][:] = state.v[op['m']][:], state.v[op['n']][:]
        elif pattern >= 8:
            left = bytearray(16)
            left[pattern - 8] = 128
            state.v[op['n']][:] = struct.unpack('<2Q', left)
            state.v[op['m']][:] = struct.unpack('<2Q', bytes(17 * byte + 3 & 255 for byte in range(16)))
    state.fpsr = (state.fpsr & ~FPSR_QC) | (FPSR_QC if flags else 0)
    return state


def corpus():
    ops, records = functions(), []
    for index, op in enumerate(ops):
        # All register/alias roles get eight patterns; the distinct-register
        # representative additionally isolates every original source byte.
        patterns = range(24) if (op['d'], op['n'], op['m']) == ALIAS_ROLES[0] else range(8)
        for pattern in patterns:
            for flags in (0, 15):
                registers = (op['d'], op['n'], op['m'])
                runtime = (
                    registers == ALIAS_ROLES[0] and (pattern, flags) in ((5, 15), (8, 0))
                    or registers == ALIAS_ROLES[1] and (pattern, flags) == (4, 0)
                    or registers == ALIAS_ROLES[4] and (pattern, flags) == (6, 15)
                    or op['matrix'] and registers == ALIAS_ROLES[0] and (pattern, flags) == (3, 15)
                    or op['matrix'] and registers == ALIAS_ROLES[2] and (pattern, flags) == (2, 0)
                    or op['matrix'] and registers == ALIAS_ROLES[3] and (pattern, flags) == (3, 0)
                    or not op['matrix'] and op['name'] == 'usdot' and op['bytes'] == 8
                        and op['index'] is None and registers == ALIAS_ROLES[2] and (pattern, flags) == (1, 0)
                    or not op['matrix'] and op['name'] == 'usdot' and op['bytes'] == 8
                        and op['index'] is None and registers == ALIAS_ROLES[3] and (pattern, flags) == (3, 0)
                )
                records.append({'function': index, 'label': f'pattern_{pattern}_flags_{flags}',
                    'initial': bytes(initial_state(op, pattern, flags)), 'runtime': runtime})
    return ops, records


def optional_opcodes(target_id):
    return {'phaddd'} if 'ssse3' in target_id.split('+') else set()
