"""AdvSIMD FAMIN/MAX and FSCALE fixtures for the shared full-frame observer.

The integer/Fraction models are shared with the consolidated SVE numerical
fixtures. They provide a separate mathematical comparison, never an original
execution substitute. Source words are from the pinned June 2026 allocation.
"""
import hashlib
import struct

from differential import State, seed_extended_state
from .sve_floating.faminmax import Operation, evaluate_lane
from .sve_floating.arithmetic_special import scale_lane

FOCUS = 'extrema_scale_numerical'
CANONICAL_FORMS = tuple(name + suffix for name in ('FAMAX', 'FAMIN', 'FSCALE')
                        for suffix in ('_asimdsame_only', '_asimdsamefp16_only'))
BASES = {'famax': (0x0ea0dc00, 0x0ec01c00),
         'famin': (0x2ea0dc00, 0x2ec01c00),
         'fscale': (0x2ea0fc00, 0x2ec03c00)}
ROLES = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1), (31, 31, 31), (31, 30, 29))
CONTROLS = (0, 1 << 1, 1, 1 << 2, 1 << 24, 1 << 19, 1 << 25,
            1 << 26, (1 << 1) | (1 << 24), (1 << 1) | (1 << 25),
            1 << 22, 2 << 22, 3 << 22, 0x9f00)
MASK64 = (1 << 64) - 1


def operation(name, lane, width, d=0, n=1, m=2):
    if name not in BASES or (lane, width) not in ((2, 8), (2, 16), (4, 8), (4, 16), (8, 16)):
        raise ValueError('Unallocated absolute-extrema/scale arrangement')
    if any(not 0 <= register < 32 for register in (d, n, m)):
        raise ValueError('Vector register out of range')
    word = BASES[name][lane == 2] | (lane == 8) << 22 | (width == 16) << 30
    return dict(name=name, word=word | m << 16 | n << 5 | d,
                canonical_id=name.upper() + ('_asimdsamefp16_only' if lane == 2 else '_asimdsame_only'),
                d=d, n=n, m=m, lane=lane, bytes=width, scalar=False,
                merge='none', output_kind='vector', return_register=30)


def functions():
    return [operation(name, lane, width, *roles) for name in BASES
            for lane, width in ((2, 8), (2, 16), (4, 8), (4, 16), (8, 16))
            for roles in ROLES]


def expected(op, initial):
    state = State.from_buffer_copy(initial)
    bits = op['lane'] * 8
    mask = (1 << bits) - 1
    left, right = (initial.v[op[key]][0] | initial.v[op[key]][1] << 64 for key in ('n', 'm'))
    result = exceptions = 0
    for lane in range(op['bytes'] // op['lane']):
        a, b = (left >> (bits * lane) & mask), (right >> (bits * lane) & mask)
        if op['name'] == 'fscale':
            outcome = scale_lane(bits, initial.fpcr, a, b)
        else:
            kind = Operation.MINIMUM if op['name'] == 'famin' else Operation.MAXIMUM
            outcome = evaluate_lane(kind, bits, initial.fpcr, a, b)
        result |= outcome.bits << (bits * lane)
        exceptions |= outcome.exceptions
    state.v[op['d']][:] = [result & MASK64, result >> 64]
    state.fpsr |= exceptions
    return state


def corpus():
    ops, records = functions(), []
    for function, op in enumerate(ops):
        bits = op['lane'] * 8
        fraction = {16: 10, 32: 23, 64: 52}[bits]
        bias = {16: 15, 32: 127, 64: 1023}[bits]
        sign = 1 << (bits - 1)
        infinity = sign - (1 << fraction)
        one = bias << fraction
        numeric = (0, sign, 1, sign | 1, (1 << fraction) - 1, 1 << fraction,
                   one, sign | one, one + (1 << fraction), infinity - 1,
                   infinity, sign | infinity, infinity | 1,
                   sign | infinity | (1 << (fraction - 1)) | 13)
        controls = CONTROLS if (op['d'], op['n'], op['m']) == ROLES[0] else (0, 1 << 25, 0x9f00)
        for control in controls:
            patterns = range(len(numeric)) if control == 0 else range(0, len(numeric), 3)
            for pattern in patterns:
                state = State()
                seed_extended_state(state, function * 17 + pattern)
                state.fpcr, state.fpsr = control, (1 << 27) | (1 << 2)
                state.nzcv, state.reserved = 0xa0000000, 0x51ad1234
                for register in range(31):
                    state.x[register] = (register + 1) * 0x123456789
                state.sp = 0x7ffffff0
                a = numeric[pattern]
                b = ((-1, 0, 1, 2, -2, sign - 1, -sign)[pattern % 7] & (2 * sign - 1)
                     if op['name'] == 'fscale' else numeric[(pattern + 5) % len(numeric)])
                def vector(value, offset):
                    values = [value if lane % 2 == 0 else numeric[(pattern + lane + offset) % len(numeric)]
                              for lane in range(16 // op['lane'])]
                    if op['name'] == 'fscale' and offset == 1:
                        values = [value] * len(values)
                    return struct.unpack('<2Q', b''.join(v.to_bytes(op['lane'], 'little') for v in values))
                state.v[op['n']][:] = vector(a, 0)
                state.v[op['m']][:] = vector(b, 1)
                raw = bytes(state)
                records.append(dict(case=len(records), function=function, function_index=function,
                                    label=f'pattern_{pattern}_fpcr_{control:x}',
                                    initial=raw, initial_state_sha256=hashlib.sha256(raw).hexdigest()))
    return ops, records
