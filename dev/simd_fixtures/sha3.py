"""Pure classic SHA3 encoding/corpus/oracle fixtures for the shared SIMD engine."""
import ctypes
import random
import struct

from differential import State, seed_extended_state

FOCUS = 'sha3'
FORMS = {
    'eor3': ('EOR3_VVV16_crypto4', 0xce000000),
    'bcax': ('BCAX_VVV16_crypto4', 0xce200000),
    'rax1': ('RAX1_VVV2_cryptosha512_3', 0xce608c00),
    'xar': ('XAR_VVV2_crypto3_imm6', 0xce800000),
}
CANONICAL_FORMS = tuple(value[0] for value in FORMS.values())
MASK64 = (1 << 64) - 1
STANDARD_CONTROLS = (0, 1 << 22, 2 << 22, 3 << 22, 1 << 24, 1 << 25, 1 << 26, 0x07c00000)
EXTENDED_CONTROLS = (1, 2, 4, 1 << 19, 0x9f00, 0x07c89f07)


def operation(name, d=0, n=1, m=2, a=31, amount=0):
    if name not in FORMS or any(not isinstance(r, int) or not 0 <= r < 32 for r in (d, n, m, a)):
        raise ValueError('invalid classic SHA3 operation/register')
    if not isinstance(amount, int) or not 0 <= amount < 64 or (name != 'xar' and amount):
        raise ValueError('XAR rotation must be an immediate0..63; other forms have no immediate')
    canonical_id, base = FORMS[name]
    word = base | d | (n << 5) | (m << 16)
    result = {'kind': FOCUS, 'name': name, 'd': d, 'n': n, 'm': m,
        'lane': 8, 'bytes': 16, 'scalar': False, 'output_kind': 'vector',
        'canonical_id': canonical_id, 'word': word}
    if name in ('eor3', 'bcax'):
        result.update(a=a, word=word | (a << 10))
    elif name == 'xar':
        result.update(amount=amount, word=word | (amount << 10))
    return result


def alias_partitions(roles):
    """Restricted-growth strings enumerate each register equality partition once."""
    if not isinstance(roles, int) or not 1 <= roles <= 4:
        raise ValueError('classic SHA3 has one through four register roles')
    result = [(0,)]
    for _ in range(roles - 1):
        result = [prefix + (group,) for prefix in result for group in range(max(prefix) + 2)]
    return result


def functions():
    result = {}
    def add(op):
        result.setdefault(op['word'], op)
    for name in FORMS:
        roles = 4 if name in ('eor3', 'bcax') else 3
        for amount in range(64) if name == 'xar' else (0,):
            for partition in alias_partitions(roles):
                registers = [(0, 1, 2, 31)[group] for group in partition]
                options = dict(zip(('d', 'n', 'm', 'a'), registers))
                add(operation(name, **options, amount=amount))
        for register in range(32):
            add(operation(name, d=register, n=(register + 1) % 32,
                m=(register + 2) % 32, a=(register + 3) % 32,
                amount=register if name == 'xar' else 0))
        for role in range(roles):
            registers = [0, 1, 2, 3]
            registers[role] = 31
            add(operation(name, **dict(zip(('d', 'n', 'm', 'a'), registers)), amount=63 if name == 'xar' else 0))
    return list(result.values())


def chain():
    """One mixed alias chain for the shared engine's block/runtime checks."""
    return [operation('eor3', d=31, n=1, m=2, a=3),
        operation('bcax', d=2, n=31, m=2, a=3),
        operation('rax1', d=3, n=2, m=31),
        operation('xar', d=31, n=3, m=2, amount=63)]


def expected(op, initial):
    """Clone all architectural bytes; mathematical operations touch Vd only."""
    state = State.from_buffer_copy(initial)
    left = int(initial.v[op['n']][0]) | (int(initial.v[op['n']][1]) << 64)
    right = int(initial.v[op['m']][0]) | (int(initial.v[op['m']][1]) << 64)
    if op['name'] in ('eor3', 'bcax'):
        third = int(initial.v[op['a']][0]) | (int(initial.v[op['a']][1]) << 64)
        value = left ^ right ^ third if op['name'] == 'eor3' else left ^ (right & ~third)
    else:
        value = 0
        for lane in range(2):
            shift = lane * 64
            n, m = (left >> shift) & MASK64, (right >> shift) & MASK64
            if op['name'] == 'rax1':
                output = n ^ (((m * 2) & MASK64) | (m // (1 << 63)))
            elif op['name'] == 'xar':
                # Bit-index construction is independent of host shift/OR lowering.
                source = n ^ m
                output = sum(((source >> ((bit + op['amount']) % 64)) & 1) << bit for bit in range(64))
            else:
                raise ValueError('unknown classic SHA3 mathematical operation')
            value |= output << shift
    state.v[op['d']][:] = [value & MASK64, value >> 64]
    return state


def seed(initial, op, pattern, source=None, bit=None):
    sources = [op['n'], op['m']] + ([op['a']] if 'a' in op else [])
    if source is not None:
        if source not in sources or bit is None or not 0 <= bit < 128:
            raise ValueError('one-hot SHA3 witness needs a source role and bit0..127')
        for register in sources:
            initial.v[register][:] = [0, 0]
        initial.v[source][:] = [int(bit < 64) << (bit % 64), int(bit >= 64) << (bit % 64)]
    elif pattern < 8:
        # Exhaustive independent Boolean triples on distinct-source witnesses.
        for role, register in enumerate(sources):
            low = MASK64 if pattern & (1 << (2 - role)) else 0
            initial.v[register][:] = [low, low ^ MASK64]
    elif pattern == 8:
        for register in range(32):
            initial.v[register][:] = struct.unpack('<2Q', bytes((index + 17 * register) % 256 for index in range(16)))
    elif pattern == 9:
        for register in range(32):
            initial.v[register][:] = [0xaaaaaaaaaaaaaaaa ^ register, 0x5555555555555555 ^ (register << 32)]
    elif pattern != 10:
        raise ValueError('unknown SHA3 input pattern')
    return initial


def representatives(ops):
    result = []
    for name, amount in [('eor3', None), ('bcax', None), ('rax1', None),
            *[('xar', value) for value in (0, 1, 8, 16, 31, 32, 48, 63)]]:
        for index, op in enumerate(ops):
            sources = [op['n'], op['m']] + ([op['a']] if 'a' in op else [])
            if (op['name'] == name and (amount is None or op['amount'] == amount)
                    and len(set([op['d'], *sources])) == len(sources) + 1):
                result.append(index)
                break
        else:
            raise AssertionError(f'Missing distinct-source SHA3 representative: {name}/{amount}')
    return result


def initial_state(index, witness):
    state = State()
    rng = random.Random(index * 4096 + witness)
    for register in range(31):
        state.x[register] = rng.getrandbits(64)
    state.sp = 0xfeed000000001000
    state.reserved = 0x51ad1234
    state.nzcv = (witness % 16) << 28
    seed_extended_state(state, index * 4096 + witness)
    state.fpcr = STANDARD_CONTROLS[witness % len(STANDARD_CONTROLS)]
    state.fpsr = 0x0800009f if witness & 1 else 0
    return state


def corpus():
    ops = functions()
    cases = []
    selected = set(representatives(ops))
    runtime_aliases = set()
    for name in FORMS:
        for predicate in (
                lambda op: len({op[role] for role in ('d', 'n', 'm') + (('a',) if 'a' in op else ())}) == 1,
                lambda op: op['d'] == 31):
            runtime_aliases.add(next(index for index, op in enumerate(ops) if op['name'] == name and predicate(op)))
    for index, op in enumerate(ops):
        witnesses = [(pattern, None, None) for pattern in range(11)]
        if index in selected:
            sources = [op['n'], op['m']] + ([op['a']] if 'a' in op else [])
            witnesses.extend((10, source, bit) for source in sources for bit in range(128))
        for witness, (pattern, source, bit) in enumerate(witnesses):
            state = seed(initial_state(index, witness), op, pattern, source, bit)
            cases.append({'function': index, 'label': f'pattern_{pattern}' if source is None else f'one_hot_v{source}_bit{bit}',
                'initial': bytes(state),
                'runtime': (index in selected and pattern in (0, 8) and source is None)
                    or (index in runtime_aliases and pattern == 9 and source is None)})
        if index in selected:
            for control in EXTENDED_CONTROLS:
                state = initial_state(index, control)
                state.fpcr, state.fpsr = control, 0x0800009f
                cases.append({'function': index, 'label': f'extended_control_{control:08x}',
                    'initial': bytes(state), 'runtime': True})
    assert sum(record['runtime'] for record in cases) <= 96
    assert ctypes.sizeof(State) == 784
    return ops, cases
