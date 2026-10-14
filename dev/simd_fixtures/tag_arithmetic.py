"""Pure MTE register arithmetic for ATA0=1, TCF0=0, GCR.Exclude=0.

This profile has FEAT_MTE2 and no tag-memory or random-tag operation. The oracle
uses integer fields and mathematical signed values, independently of host recipes.
"""
import ctypes
import json
import random
import struct

from differential import ROOT, State, seed_extended_state

FOCUS = 'tag_arithmetic'
FORMS = {
    'addg': ('ADDG_64_addsub_immtags', 0x91800000, 0xffc00000),
    'subg': ('SUBG_64_addsub_immtags', 0xd1800000, 0xffc00000),
    'subp': ('SUBP_64S_dp_2src', 0x9ac00000, 0xffe0fc00),
    'subps': ('SUBPS_64S_dp_2src', 0xbac00000, 0xffe0fc00),
    'gmi': ('GMI_64G_dp_2src', 0x9ac01400, 0xffe0fc00),
}
CANONICAL_FORMS = tuple(value[0] for value in FORMS.values())
MASK64 = (1 << 64) - 1
TAG_SHIFT = 56
TAG_MASK = 15
TAG_FIELD = TAG_MASK << TAG_SHIFT
ADDRESS_GRANULE = 16
ADDRESS_OFFSET_MAX = 63 * ADDRESS_GRANULE
SIGN56 = 1 << 55
MOD56 = 1 << 56
RET = 0xd65f03c0
RUNTIME_RESERVED = {10, 30}


def operation(name, d=0, n=1, m=2, address_offset=0, tag_offset=0, soft_bits=0):
    if name not in FORMS or any(type(r) is not int or not 0 <= r < 32 for r in (d, n, m)):
        raise ValueError('Invalid tag arithmetic name/register')
    if (type(address_offset) is not int or not 0 <= address_offset <= ADDRESS_OFFSET_MAX
            or address_offset % ADDRESS_GRANULE or type(tag_offset) is not int or not 0 <= tag_offset <= TAG_MASK
            or type(soft_bits) is not int or not 0 <= soft_bits < 4):
        raise ValueError('Invalid tag arithmetic immediate/soft bits')
    is_offset = name in ('addg', 'subg')
    if not is_offset and (address_offset or tag_offset or soft_bits):
        raise ValueError('Register tag arithmetic has no immediate/soft bits')
    canonical, base, _ = FORMS[name]
    word = base | d | n << 5
    if is_offset:
        word |= (address_offset // ADDRESS_GRANULE) << 16 | tag_offset << 10 | soft_bits << 14
    else:
        word |= m << 16
    return {'kind': FOCUS, 'name': name, 'd': d, 'n': n, 'm': m,
            'address_offset': address_offset, 'tag_offset': tag_offset, 'soft_bits': soft_bits,
            'word': word, 'canonical_id': canonical, 'lane': 1, 'bytes': 8,
            'scalar': True, 'output_kind': 'gpr', 'written_gprs': [d] if d != 31 else [],
            'writes_sp': is_offset and d == 31, 'writes_nzcv': name == 'subps', 'written_vectors': []}


def validate_effects(op):
    """Derive permitted writes from encoded roles; never trust supplied metadata."""
    if op.get('kind') != FOCUS or op.get('name') not in FORMS:
        raise AssertionError('Not a tag arithmetic operation')
    name = op['name']
    canonical, base, mask = FORMS[name]
    word = op['word']
    d, n = word & 31, (word >> 5) & 31
    is_offset = name in ('addg', 'subg')
    if word & mask != base or op['canonical_id'] != canonical or (op['d'], op['n']) != (d, n):
        raise AssertionError('Tag arithmetic encoding/role metadata differs')
    if is_offset:
        if (op['address_offset'], op['tag_offset'], op['soft_bits']) != (
                ((word >> 16) & 63) * ADDRESS_GRANULE, (word >> 10) & TAG_MASK, (word >> 14) & 3):
            raise AssertionError('Tag arithmetic immediate metadata differs')
    elif (op['m'] != (word >> 16) & 31 or op['address_offset'] or op['tag_offset'] or op['soft_bits']):
        raise AssertionError('Tag arithmetic second-source metadata differs')
    effects = {'written_gprs': [d] if d != 31 else [], 'writes_sp': is_offset and d == 31,
               'writes_nzcv': name == 'subps', 'written_vectors': [], 'output_kind': 'gpr',
               'lane': 1, 'bytes': 8, 'scalar': True}
    if any(op.get(key) != value for key, value in effects.items()):
        raise AssertionError('Tag arithmetic architectural-effect metadata differs')
    return effects


def functions():
    result = {}
    def add(op):
        result.setdefault(op['word'], op)
    for name in FORMS:
        add(operation(name))
        if name in ('addg', 'subg'):
            for address in range(0, ADDRESS_OFFSET_MAX + 1, ADDRESS_GRANULE):
                for tag in range(TAG_MASK + 1):
                    add(operation(name, address_offset=address, tag_offset=tag))
            for soft in range(4):
                for address in (0, ADDRESS_GRANULE, ADDRESS_OFFSET_MAX):
                    for tag in (0, 1, TAG_MASK):
                        add(operation(name, address_offset=address, tag_offset=tag, soft_bits=soft))
        for register in range(32):
            add(operation(name, d=register, n=(register + 1) % 32, m=(register + 2) % 32))
        for d, n, m in ((0, 0, 0), (0, 0, 1), (0, 1, 0), (0, 1, 1),
                        (31, 1, 2), (0, 31, 2), (0, 1, 31), (31, 31, 31),
                        (31, 31, 1), (31, 1, 31), (0, 31, 31)):
            add(operation(name, d=d, n=n, m=m,
                          address_offset=ADDRESS_GRANULE if name in ('addg', 'subg') else 0,
                          tag_offset=1 if name in ('addg', 'subg') else 0))
    return list(result.values())


def source_value(initial, register, sp):
    return int(initial.sp if sp else 0) if register == 31 else int(initial.x[register])


def signed56(value):
    low = value % MOD56
    return low - MOD56 if low >= SIGN56 else low


def expected(op, initial):
    validate_effects(op)
    state = State.from_buffer_copy(initial)
    left = source_value(initial, op['n'], True)
    name = op['name']
    if name in ('addg', 'subg'):
        address = (left + (op['address_offset'] if name == 'addg' else -op['address_offset'])) % (1 << 64)
        tag = ((left // MOD56) + op['tag_offset']) % (TAG_MASK + 1)
        value = (address & (MASK64 ^ TAG_FIELD)) | tag << TAG_SHIFT
    elif name in ('subp', 'subps'):
        n = signed56(left)
        m = signed56(source_value(initial, op['m'], True))
        difference = n - m
        value = difference % (1 << 64)
        if name == 'subps':
            state.nzcv = (int(difference < 0) << 31 | int(difference == 0) << 30
                          | int(n % (1 << 64) >= m % (1 << 64)) << 29)
    else:
        value = source_value(initial, op['m'], False) | 1 << ((left // MOD56) % (TAG_MASK + 1))
    if op['d'] != 31:
        state.x[op['d']] = value
    elif name in ('addg', 'subg'):
        state.sp = value
    return state


def initial_state(index, witness):
    state = State()
    rng = random.Random(0x7a6a0000 + index * 4096 + witness)
    for register in range(31):
        state.x[register] = rng.getrandbits(64)
    state.sp = rng.getrandbits(64)  # Pure arithmetic accepts unaligned SP values.
    state.reserved = 0x51ad1234
    state.nzcv = (witness % 16) << 28
    seed_extended_state(state, index * 4096 + witness)
    state.fpcr = (0, 0x07c00000, 0x07c89f07, 1 << 22)[witness % 4]
    state.fpsr = 0x0800009f if witness & 1 else 0
    return state


def set_source(state, register, value, sp=True):
    if register != 31:
        state.x[register] = value & MASK64
    elif sp:
        state.sp = value & MASK64


def corpus():
    ops, cases = functions(), []
    runtime_forms = set()
    edges = ((0, 0), (MASK64, 1), (SIGN56 - 1, SIGN56), (SIGN56, SIGN56 - 1),
             (0x0ffffffffffffff0, 1), (0x1000000000000000, MASK64),
             (0xf0fffffffffffff0, 0xfedcba9876540000), (0xa500000000000001, 0x8000000000000000))
    for index, op in enumerate(ops):
        specs = [('random', None, None)]
        representative = (op['d'], op['n'], op['m']) == (0, 1, 2) and op['soft_bits'] == 0
        if representative and (op['name'] not in ('addg', 'subg')
                or op['address_offset'] in (0, 16, ADDRESS_OFFSET_MAX) and op['tag_offset'] in (0, 1, 15)):
            specs += [(f'edge_{edge}', left, right) for edge, (left, right) in enumerate(edges)]
            if op['address_offset'] == 0 and op['tag_offset'] == 0:
                specs += [(f'tag_{tag}_high_{high}', (high << 60) | tag << TAG_SHIFT | 0x123456789abcde,
                           0xfedcba9876540000) for tag in range(16) for high in range(16)]
        if representative and op['address_offset'] == 0 and op['tag_offset'] == 0:
            specs += [(f'prior_nzcv_{flags}', SIGN56, SIGN56 - 1) for flags in range(16)]
        for witness, (label, left, right) in enumerate(specs):
            state = initial_state(index, witness)
            if label.startswith('prior_nzcv_'):
                state.nzcv = int(label.rsplit('_', 1)[1]) << 28
            if left is not None:
                set_source(state, op['n'], left)
                if op['name'] not in ('addg', 'subg'):
                    set_source(state, op['m'], right, op['name'] != 'gmi')
            safe_runtime = not RUNTIME_RESERVED.intersection((op['d'], op['n'], op['m']))
            runtime = safe_runtime and ((op['canonical_id'] not in runtime_forms)
                or representative and label in ('edge_2', 'edge_3', 'edge_4')
                and (op['name'] not in ('addg', 'subg') or op['address_offset'] == 16 and op['tag_offset'] == 1))
            runtime |= safe_runtime and label == 'random' and (
                op['d'], op['n'], op['m']) in ((0, 0, 0), (0, 0, 1), (0, 1, 0), (0, 1, 1),
                (31, 1, 2), (0, 31, 2), (0, 1, 31), (31, 31, 31))
            runtime |= safe_runtime and label == 'random' and representative is False and (
                op['d'], op['n'], op['m']) == (0, 1, 2) and op['soft_bits'] != 0 and (
                op['address_offset'], op['tag_offset']) == (16, 1)
            if runtime:
                runtime_forms.add(op['canonical_id'])
            cases.append({'function': index, 'label': label, 'initial': bytes(state), 'runtime': runtime})
    assert sum(record['runtime'] for record in cases) <= 96
    assert ctypes.sizeof(State) == 784
    return ops, cases


def optional_opcodes(target_id):
    return set()


def validate_source_words(source, functions, allowed_mnemonics):
    """Exact source/metadata plus pinned facts; retain independent decoder limits."""
    import a64_checklist
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    facts = a64_checklist.validate(json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes()))
    decoder, words, fallbacks, aliases = Cs(CS_ARCH_ARM64, CS_MODE_ARM), [], [], []
    for function in functions:
        words.extend([*function['operations'], {'word': RET, 'kind': 'return'}])
    if source != b''.join(struct.pack('<I', op['word']) for op in words):
        raise AssertionError('Tag arithmetic source differs from declared exact words')
    for index, op in enumerate(words):
        decoded = list(decoder.disasm(struct.pack('<I', op['word']), index * 4))
        if op.get('kind') == FOCUS:
            validate_effects(op)
            fact = facts[op['canonical_id']]
            if op['word'] & int(fact['encoding_mask'], 16) != int(fact['encoding_value'], 16):
                raise AssertionError('Tag arithmetic word differs from pinned June facts')
            name = decoded[0].mnemonic if len(decoded) == 1 else None
            if name == 'cmpp' and op['name'] == 'subps' and op['d'] == 31:
                aliases.append({'word_index': index, 'decoded_alias': name})
            elif name != op['name']:
                # Nonzero SBZ op3 allows several constrained choices. Pinned
                # source permits execute-as0; genuine QEMU originals choose
                # UNDEF. Retain that classified difference without claiming
                # original/model equality for these variants.
                if name is None and op['name'] in ('addg', 'subg') and op['soft_bits']:
                    fallbacks.append({'word_index': index, 'word': f"{op['word']:08x}",
                                      'reason': 'decoder declines pinned soft-fixed op3 variant'})
                else:
                    raise AssertionError('Independent decoder differs for tag arithmetic')
        elif len(decoded) != 1 or decoded[0].mnemonic not in set(allowed_mnemonics) | {'ret'}:
            raise AssertionError('Independent decoder declined tag arithmetic harness word')
    return {'capstone_decode_fallback_words': len(fallbacks), 'fallbacks': fallbacks,
            'decoded_aliases': aliases, 'pinned_facts_sha256': a64_checklist.FACTS_SHA}
