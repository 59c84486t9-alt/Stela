"""Pinned classic SHA1/SHA256 fixtures for the consolidated SIMD engine.

Pure encoding, full-state corpus and independent integer model only. The engine
owns original/native execution, exact source identities, feature profiles and
oracle limitations. No arithmetic instruction reads or changes FPCR/FPSR/NZCV.
"""
import random
from differential import State, seed_extended_state

FOCUS = 'sha12'
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
FORMS = {
    'sha1c': ('SHA1C_QSV_cryptosha3', 0x5e000000),
    'sha1p': ('SHA1P_QSV_cryptosha3', 0x5e001000),
    'sha1m': ('SHA1M_QSV_cryptosha3', 0x5e002000),
    'sha1h': ('SHA1H_SS_cryptosha2', 0x5e280800),
    'sha1su0': ('SHA1SU0_VVV_cryptosha3', 0x5e003000),
    'sha1su1': ('SHA1SU1_VV_cryptosha2', 0x5e281800),
    'sha256h': ('SHA256H_QQV_cryptosha3', 0x5e004000),
    'sha256h2': ('SHA256H2_QQV_cryptosha3', 0x5e005000),
    'sha256su0': ('SHA256SU0_VV_cryptosha2', 0x5e282800),
    'sha256su1': ('SHA256SU1_VVV_cryptosha3', 0x5e006000),
}
CANONICAL_FORMS = tuple(value[0] for value in FORMS.values())
TWO_REGISTER_FORMS = frozenset(('sha1h', 'sha1su1', 'sha256su0'))
TERNARY_ROLES = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1),
                 (31, 31, 31), (0, 31, 31), (31, 29, 31), (31, 31, 29),
                 (31, 29, 30), (0, 31, 30), (0, 30, 31))
UNARY_ROLES = ((0, 1, 0), (1, 1, 0), (31, 31, 0), (0, 31, 0),
               (31, 0, 0), (31, 29, 0), (0, 30, 0))
PATTERN_COUNT = 16


def operation(name, d=0, n=1, m=2):
    if name not in FORMS or any(not 0 <= value < 32 for value in (d, n, m)):
        raise ValueError('invalid classic SHA operation/register')
    canonical_id, base = FORMS[name]
    if name in TWO_REGISTER_FORMS:
        m = 0
    return {'name': name, 'word': base | (n << 5) | d | (m << 16),
            'canonical_id': canonical_id, 'd': d, 'n': n, 'm': m,
            'lane': 4, 'bytes': 4 if name == 'sha1h' else 16,
            'scalar': name == 'sha1h', 'output_kind': 'vector'}


def functions():
    return [{**operation(name, d, n, m), 'role_index': role} for name in FORMS
            for role, (d, n, m) in enumerate(UNARY_ROLES if name in TWO_REGISTER_FORMS else TERNARY_ROLES)]


def _rol(value, amount):
    return ((value << amount) | (value >> (32 - amount))) & MASK32


def _ror(value, amount):
    return _rol(value, 32 - amount)


def _choose(a, b, c):
    return (a & b) ^ ((~a & MASK32) & c)


def _majority(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


def _sigma0(value):
    return _ror(value, 7) ^ _ror(value, 18) ^ (value >> 3)


def _sigma1(value):
    return _ror(value, 17) ^ _ror(value, 19) ^ (value >> 10)


def expected(op, initial):
    result = State.from_buffer_copy(initial)
    words = [list((vector[0] | (vector[1] << 64)) >> (i * 32) & MASK32 for i in range(4))
             for vector in initial.v]
    d, n, m = (words[op[key]][:] for key in ('d', 'n', 'm'))
    name = op['name']
    if name == 'sha1h':
        out = [_ror(n[0], 2), 0, 0, 0]
    elif name in ('sha1c', 'sha1p', 'sha1m'):
        a, b, c, d_word = d
        e = n[0]
        for word in m:
            f = _choose(b, c, d_word) if name == 'sha1c' else _majority(b, c, d_word) if name == 'sha1m' else b ^ c ^ d_word
            a, b, c, d_word, e = (_rol(a, 5) + f + e + word) & MASK32, a, _rol(b, 30), c, d_word
        out = [a, b, c, d_word]
    elif name == 'sha1su0':
        shifted = d[2:] + n[:2]
        out = [a ^ b ^ c for a, b, c in zip(d, shifted, m)]
    elif name == 'sha1su1':
        t = [a ^ b for a, b in zip(d, n[1:] + [0])]
        out = [_rol(value, 1) for value in t]
        out[3] ^= _rol(t[0], 2)
    elif name == 'sha256su0':
        out = [(a + _sigma0(b)) & MASK32 for a, b in zip(d, d[1:] + n[:1])]
    elif name == 'sha256su1':
        base = [(a + b) & MASK32 for a, b in zip(d, n[1:] + m[:1])]
        out = [(base[0] + _sigma1(m[2])) & MASK32, (base[1] + _sigma1(m[3])) & MASK32]
        out += [(base[2] + _sigma1(out[0])) & MASK32, (base[3] + _sigma1(out[1])) & MASK32]
    elif name in ('sha256h', 'sha256h2'):
        a, b, c, d_word = d if name == 'sha256h' else n
        e, f, g, h = n if name == 'sha256h' else d
        for word in m:
            t1 = h + (_ror(e, 6) ^ _ror(e, 11) ^ _ror(e, 25)) + _choose(e, f, g) + word
            t2 = (_ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)) + _majority(a, b, c)
            a, b, c, d_word, e, f, g, h = (t1 + t2) & MASK32, a, b, c, (d_word + t1) & MASK32, e, f, g
        out = [a, b, c, d_word] if name == 'sha256h' else [e, f, g, h]
    else:
        raise ValueError('unsupported classic SHA model operation')
    value = sum(word << (i * 32) for i, word in enumerate(out))
    result.v[op['d']][:] = [value & MASK64, value >> 64]
    return result


def state(op, pattern, flags):
    if not 0 <= pattern < PATTERN_COUNT or not 0 <= flags < 16:
        raise ValueError('classic SHA corpus index outside bounded scope')
    initial = State()
    seed = 0x534841120000 | (pattern << 8) | flags
    seed_extended_state(initial, seed)
    rng = random.Random(seed)
    initial.x[:] = [rng.getrandbits(64) for _ in initial.x]
    initial.sp = 0x240000008000
    initial.nzcv = flags << 28
    initial.reserved = 0x53484112
    initial.fpcr = (0, 0x07c00000, 0x00080000, 0x07c80000)[pattern % 4]
    initial.fpsr = (0, 0x0800009f, 0x08000000, 0x0000009f)[flags % 4]
    directed = (0, MASK32, 1, 0x80000000, 0x7fffffff, 0xfffffffe,
                0xaaaaaaaa, 0x55555555, 0x01020304, 0x10204080, 0x89abcdef, 0x76543210)
    for register in range(32):
        if pattern < 8:
            values = [directed[(register + lane + pattern) % len(directed)] for lane in range(4)]
        elif pattern < 12:
            values = [1 << ((register + 8 * (pattern - 8) + 2 * lane) % 32) for lane in range(4)]
        else:
            values = [rng.getrandbits(32) for _ in range(4)]
        value = sum(word << (i * 32) for i, word in enumerate(values))
        initial.v[register][:] = [value & MASK64, value >> 64]
    return initial


def optional_opcodes(target_id):
    features = set(target_id.split('+')[1:])
    expected = set()
    if 'sha' in features:
        expected.update(('sha1rnds4', 'sha1msg2', 'sha256rnds2', 'sha256msg1', 'sha256msg2'))
    if 'ssse3' in features:
        expected.add('palignr')
    return expected


def corpus():
    ops = functions()
    records = []
    for index, op in enumerate(ops):
        for pattern in range(PATTERN_COUNT):
            for flags in range(16):
                record = {'function': index, 'label': f'pattern_{pattern}_nzcv_{flags:x}',
                          'initial': bytes(state(op, pattern, flags))}
                if ((op['role_index'] == 0 and (pattern, flags) in ((0, 0), (9, 15), (10, 0), (15, 15)))
                        or (op['role_index'] in (1, 2, 3, 4, 6) and pattern == 12 and flags == 15)):
                    record['runtime'] = True
                records.append(record)
    return ops, records
