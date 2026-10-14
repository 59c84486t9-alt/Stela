"""Independent four-form SHA512 fixtures for the consolidated SIMD runner.

Only original instruction words and complete input states live here. The runner
owns original/native execution, source maps, artifacts, cache and evidence credit.
"""
import random

from differential import State, seed_extended_state

FOCUS = 'sha512'
MASK = (1 << 64) - 1
FORMS = {
    'sha512h': (0xce608000, 'SHA512H_QQV_cryptosha512_3'),
    'sha512h2': (0xce608400, 'SHA512H2_QQV_cryptosha512_3'),
    'sha512su0': (0xcec08000, 'SHA512SU0_VV2_cryptosha512_2'),
    'sha512su1': (0xce608800, 'SHA512SU1_VVV2_cryptosha512_3'),
}
CANONICAL_FORMS = tuple(canonical for _, canonical in FORMS.values())
PATTERNS = 72
ALIAS_LAYOUTS = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1),
                 (31, 31, 31), (0, 31, 31), (31, 29, 31), (31, 0, 1))
UNARY_LAYOUTS = ((0, 1, 0), (1, 1, 0), (31, 31, 0), (31, 0, 0), (0, 31, 0))


def operation(name, d=0, n=1, m=2):
    if name not in FORMS or any(not 0 <= register < 32 for register in (d, n, m)):
        raise ValueError('Invalid SHA512 form or vector register')
    base, canonical = FORMS[name]
    third = name != 'sha512su0'
    return {'name': name, 'kind': FOCUS, 'd': d, 'n': n, 'm': m if third else None,
            'lane': 8, 'bytes': 16, 'scalar': False, 'output_kind': 'vector',
            'canonical_id': canonical, 'word': base | d | (n << 5) | (m << 16 if third else 0)}


def functions():
    result = []
    for name in FORMS:
        layouts = UNARY_LAYOUTS if name == 'sha512su0' else ALIAS_LAYOUTS
        result.extend(dict(operation(name, d, n, m), layout='alias') for d, n, m in layouts)
        result.extend(dict(operation(name, d, (d + 5) % 32, (d + 13) % 32), layout='all_registers')
                      for d in range(32))
    return result


def expected(op, initial):
    """Bitvector math independent of the selected x86 scalar/SSE2 recipes."""
    result = State.from_buffer_copy(initial)
    w0, w1 = initial.v[op['d']]
    x0, x1 = initial.v[op['n']]

    def rotate(value, amount):
        return ((value >> amount) | (value << (64 - amount))) & MASK

    def large(value, rotations):
        return rotate(value, rotations[0]) ^ rotate(value, rotations[1]) ^ rotate(value, rotations[2])

    def small(value, rotations, amount):
        return rotate(value, rotations[0]) ^ rotate(value, rotations[1]) ^ (value >> amount)

    def choose(x, y, z):
        return (x & y) ^ ((~x & MASK) & z)

    def majority(x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    name = op['name']
    if name == 'sha512su0':
        low = w0 + small(w1, (1, 8), 7)
        high = w1 + small(x0, (1, 8), 7)
    else:
        y0, y1 = initial.v[op['m']]
        if name == 'sha512su1':
            low = w0 + small(x0, (19, 61), 6) + y0
            high = w1 + small(x1, (19, 61), 6) + y1
        elif name == 'sha512h':
            high = (choose(y1, x0, x1) + large(y1, (14, 18, 41)) + w1) & MASK
            temporary = (high + y0) & MASK
            low = choose(temporary, y1, x0) + large(temporary, (14, 18, 41)) + w0
        elif name == 'sha512h2':
            high = (majority(x0, y1, y0) + large(y0, (28, 34, 39)) + w1) & MASK
            low = majority(high, y0, y1) + large(high, (28, 34, 39)) + w0
        else:
            raise ValueError('Unknown SHA512 mathematical operation')
    result.v[op['d']][:] = (low & MASK, high & MASK)
    return result


def initial_state(function_index, pattern, flags):
    if not 0 <= pattern < PATTERNS or flags not in (0, 15):
        raise ValueError('Invalid SHA512 pattern or flags')
    state = State()
    generator = random.Random(0x51200000 + function_index * 4096 + pattern * 16 + flags)
    for register in range(31):
        state.x[register] = generator.getrandbits(64)
    state.sp = generator.getrandbits(64)
    state.nzcv = flags << 28
    state.reserved = 0x512ad123
    seed_extended_state(state, generator.getrandbits(64))
    for register in range(32):
        if pattern == 0:
            lanes = (0, 0)
        elif pattern == 1:
            lanes = (MASK, MASK)
        elif pattern == 2:
            lanes = (0xaaaaaaaaaaaaaaaa, 0x5555555555555555)
        elif pattern == 3:
            lanes = (0x0123456789abcdef ^ register, 0xfedcba9876543210 ^ (register << 32))
        elif pattern == 4:
            lanes = (1 << 63, 1)
        elif pattern == 5:
            lanes = (MASK - register, register + 1)
        elif pattern < 70:
            bit = (pattern - 6 + register) % 64
            lanes = (1 << bit, MASK ^ (1 << ((bit + 17) % 64)))
        else:
            continue  # Independent seeded random low/high qwords.
        state.v[register][:] = lanes
    state.fpsr = (state.fpsr & ~(1 << 27)) | ((1 << 27) if flags else 0)
    return state


def corpus():
    operations, records = functions(), []
    seen = set()
    for index, op in enumerate(operations):
        # Each form has exhaustive one-bit and boundary patterns; each alias has
        # eight boundaries/random states, and all register positions have two.
        representative = op['name'] not in seen
        patterns = range(PATTERNS) if representative else (0, 1, 2, 3, 4, 5, 70, 71)
        if op['layout'] == 'all_registers':
            patterns = (70, 71)
        seen.add(op['name'])
        for pattern in patterns:
            for flags in (0, 15):
                initial = initial_state(index, pattern, flags)
                runtime = op['layout'] == 'alias' and (
                    pattern in (0, 1, 4, 70, 71) if representative else pattern == 3)
                records.append({'function': index, 'runtime': runtime, 'label': f'{op["name"]}/{op["layout"]}/{pattern}/{flags}',
                                'pattern': pattern, 'flags': flags, 'initial': bytes(initial)})
    return operations, records
