"""Independent integer model for scalable-length/count arithmetic.

Predicates are little-endian packed byte-lane bits. PN is an interpretation of
P, and CNTP's four-bit PNn admits all sixteen predicate slots. The model uses
current architectural VL; no operation assumes the 128-bit minimum.
"""
from copy import deepcopy

from .counter import counter_bits

MASK64 = (1 << 64) - 1
REGISTER_MASK = 31
PREDICATE_MASK = 15
SIZE_SHIFT = 22
SIZE_MASK = 3
PATTERN_SHIFT = 5
MULTIPLIER_SHIFT = 16
PREDICATE_SHIFT = 5
GOVERNING_SHIFT = 10
IMMEDIATE_MASK = 63
IMMEDIATE_SIGN = 32
IMMEDIATE_MODULUS = 64
COUNTER_INVERT_BIT = 1 << 15
COUNTER_TYPE_MASK = 15
SVL_BYTES = (16, 32, 64, 128, 256)
FORMS = {
    'addpl_r_ri_': (0x04605000, 0xffe0f800),
    'addvl_r_ri_': (0x04205000, 0xffe0f800),
    'cntb_r_s_': (0x0420e000, 0xfff0fc00),
    'cntd_r_s_': (0x04e0e000, 0xfff0fc00),
    'cnth_r_s_': (0x0460e000, 0xfff0fc00),
    'cntp_r_p_p_': (0x25208000, 0xff3fc200),
    'cntp_r_pn_': (0x25208200, 0xff3ffa00),
    'cntw_r_s_': (0x04a0e000, 0xfff0fc00),
    'decb_r_rs_': (0x0430e400, 0xfff0fc00),
    'decd_r_rs_': (0x04f0e400, 0xfff0fc00),
    'decd_z_zs_': (0x04f0c400, 0xfff0fc00),
    'dech_r_rs_': (0x0470e400, 0xfff0fc00),
    'dech_z_zs_': (0x0470c400, 0xfff0fc00),
    'decp_r_p_r_': (0x252d8800, 0xff3ffe00),
    'decp_z_p_z_': (0x252d8000, 0xff3ffe00),
    'decw_r_rs_': (0x04b0e400, 0xfff0fc00),
    'decw_z_zs_': (0x04b0c400, 0xfff0fc00),
    'incb_r_rs_': (0x0430e000, 0xfff0fc00),
    'incd_r_rs_': (0x04f0e000, 0xfff0fc00),
    'incd_z_zs_': (0x04f0c000, 0xfff0fc00),
    'inch_r_rs_': (0x0470e000, 0xfff0fc00),
    'inch_z_zs_': (0x0470c000, 0xfff0fc00),
    'incp_r_p_r_': (0x252c8800, 0xff3ffe00),
    'incp_z_p_z_': (0x252c8000, 0xff3ffe00),
    'incw_r_rs_': (0x04b0e000, 0xfff0fc00),
    'incw_z_zs_': (0x04b0c000, 0xfff0fc00),
    'rdvl_r_i_': (0x04bf5000, 0xfffff800),
    'sqdecb_r_rs_sx': (0x0420f800, 0xfff0fc00),
    'sqdecb_r_rs_x': (0x0430f800, 0xfff0fc00),
    'sqdecd_r_rs_sx': (0x04e0f800, 0xfff0fc00),
    'sqdecd_r_rs_x': (0x04f0f800, 0xfff0fc00),
    'sqdecd_z_zs_': (0x04e0c800, 0xfff0fc00),
    'sqdech_r_rs_sx': (0x0460f800, 0xfff0fc00),
    'sqdech_r_rs_x': (0x0470f800, 0xfff0fc00),
    'sqdech_z_zs_': (0x0460c800, 0xfff0fc00),
    'sqdecp_r_p_r_sx': (0x252a8800, 0xff3ffe00),
    'sqdecp_r_p_r_x': (0x252a8c00, 0xff3ffe00),
    'sqdecp_z_p_z_': (0x252a8000, 0xff3ffe00),
    'sqdecw_r_rs_sx': (0x04a0f800, 0xfff0fc00),
    'sqdecw_r_rs_x': (0x04b0f800, 0xfff0fc00),
    'sqdecw_z_zs_': (0x04a0c800, 0xfff0fc00),
    'sqincb_r_rs_sx': (0x0420f000, 0xfff0fc00),
    'sqincb_r_rs_x': (0x0430f000, 0xfff0fc00),
    'sqincd_r_rs_sx': (0x04e0f000, 0xfff0fc00),
    'sqincd_r_rs_x': (0x04f0f000, 0xfff0fc00),
    'sqincd_z_zs_': (0x04e0c000, 0xfff0fc00),
    'sqinch_r_rs_sx': (0x0460f000, 0xfff0fc00),
    'sqinch_r_rs_x': (0x0470f000, 0xfff0fc00),
    'sqinch_z_zs_': (0x0460c000, 0xfff0fc00),
    'sqincp_r_p_r_sx': (0x25288800, 0xff3ffe00),
    'sqincp_r_p_r_x': (0x25288c00, 0xff3ffe00),
    'sqincp_z_p_z_': (0x25288000, 0xff3ffe00),
    'sqincw_r_rs_sx': (0x04a0f000, 0xfff0fc00),
    'sqincw_r_rs_x': (0x04b0f000, 0xfff0fc00),
    'sqincw_z_zs_': (0x04a0c000, 0xfff0fc00),
    'uqdecb_r_rs_uw': (0x0420fc00, 0xfff0fc00),
    'uqdecb_r_rs_x': (0x0430fc00, 0xfff0fc00),
    'uqdecd_r_rs_uw': (0x04e0fc00, 0xfff0fc00),
    'uqdecd_r_rs_x': (0x04f0fc00, 0xfff0fc00),
    'uqdecd_z_zs_': (0x04e0cc00, 0xfff0fc00),
    'uqdech_r_rs_uw': (0x0460fc00, 0xfff0fc00),
    'uqdech_r_rs_x': (0x0470fc00, 0xfff0fc00),
    'uqdech_z_zs_': (0x0460cc00, 0xfff0fc00),
    'uqdecp_r_p_r_uw': (0x252b8800, 0xff3ffe00),
    'uqdecp_r_p_r_x': (0x252b8c00, 0xff3ffe00),
    'uqdecp_z_p_z_': (0x252b8000, 0xff3ffe00),
    'uqdecw_r_rs_uw': (0x04a0fc00, 0xfff0fc00),
    'uqdecw_r_rs_x': (0x04b0fc00, 0xfff0fc00),
    'uqdecw_z_zs_': (0x04a0cc00, 0xfff0fc00),
    'uqincb_r_rs_uw': (0x0420f400, 0xfff0fc00),
    'uqincb_r_rs_x': (0x0430f400, 0xfff0fc00),
    'uqincd_r_rs_uw': (0x04e0f400, 0xfff0fc00),
    'uqincd_r_rs_x': (0x04f0f400, 0xfff0fc00),
    'uqincd_z_zs_': (0x04e0c400, 0xfff0fc00),
    'uqinch_r_rs_uw': (0x0460f400, 0xfff0fc00),
    'uqinch_r_rs_x': (0x0470f400, 0xfff0fc00),
    'uqinch_z_zs_': (0x0460c400, 0xfff0fc00),
    'uqincp_r_p_r_uw': (0x25298800, 0xff3ffe00),
    'uqincp_r_p_r_x': (0x25298c00, 0xff3ffe00),
    'uqincp_z_p_z_': (0x25298000, 0xff3ffe00),
    'uqincw_r_rs_uw': (0x04a0f400, 0xfff0fc00),
    'uqincw_r_rs_x': (0x04b0f400, 0xfff0fc00),
    'uqincw_z_zs_': (0x04a0c400, 0xfff0fc00),
}
CANONICAL_FORMS = tuple(FORMS)


def decode(word):
    matches = [name for name, (base, mask) in FORMS.items() if word & mask == base]
    if not matches:
        return None
    if len(matches) != 1:
        raise AssertionError('Overlapping canonical forms')
    name = matches[0]
    vector = '_z_' in name
    element_bytes = 1 << ((word >> SIZE_SHIFT) & SIZE_MASK)
    if vector and element_bytes == 1:
        raise ValueError('Reserved byte-sized vector adjustment')
    return {'canonical_id': name, 'word': word, 'destination': word & REGISTER_MASK,
            'element_bytes': element_bytes, 'vector': vector,
            'scalar_bits': 32 if name.endswith(('_sx', '_uw')) else 64,
            'signed': name.startswith('sq'), 'unsigned': name.startswith('uq'),
            'subtract': 'dec' in name, 'predicate': (word >> PREDICATE_SHIFT) & PREDICATE_MASK,
            'governing': (word >> GOVERNING_SHIFT) & PREDICATE_MASK,
            'pattern': (word >> PATTERN_SHIFT) & REGISTER_MASK,
            'multiplier': ((word >> MULTIPLIER_SHIFT) & PREDICATE_MASK) + 1}


def pattern_count(pattern, element_bytes, vl_bytes):
    """Reserved patterns are zero counts, not undefined instructions."""
    elements = vl_bytes // element_bytes
    fixed = tuple(range(9)) + (16, 32, 64, 128, 256)
    if pattern == 0:
        return 1 << (elements.bit_length() - 1)
    if pattern < len(fixed):
        return fixed[pattern] if fixed[pattern] <= elements else 0
    if pattern == 29:
        return elements - elements % 4
    if pattern == 30:
        return elements - elements % 3
    return elements if pattern == 31 else 0


def predicate_count(predicate, element_bytes, vl_bytes):
    return sum((predicate >> position) & 1 for position in range(0, vl_bytes, element_bytes))


def counter_count(counter, element_bytes, vl_bytes, vectors):
    """Expand the architectural counter bit set before counting requested lanes."""
    expanded = counter_bits(counter, vl_bytes)
    return predicate_count(expanded, element_bytes, vl_bytes * vectors)


def enabled(op, *, sve, sme, sme2, sve2p1, streaming):
    if op['canonical_id'] == 'cntp_r_pn_':
        return (sve2p1 and (sve or sme and streaming)) or (sme2 and sme and streaming)
    return (sme and streaming) or (sve and not streaming)


def apply(op, state, vl_bytes):
    """Return a full deep-copied state; only declared destination is modified.

    State uses x[0:31], sp, z[0:32] as byte strings, p[0:16] as packed
    integers. All other state (including NZCV and FPSR.QC) is preserved.
    Feature/mode admission is deliberately checked by enabled(), separately.
    """
    if vl_bytes not in SVL_BYTES:
        raise ValueError('SVL is outside the declared specialized SME profile')
    name, word = op['canonical_id'], op['word']
    if decode(word) != op:
        raise ValueError('Operation metadata differs from encoded operands')
    result = deepcopy(state)
    d = op['destination']
    if name.startswith(('addpl_', 'addvl_', 'rdvl_')):
        immediate = (word >> PATTERN_SHIFT) & IMMEDIATE_MASK
        if immediate & IMMEDIATE_SIGN:
            immediate -= IMMEDIATE_MODULUS
        amount = immediate * (vl_bytes // 8 if name.startswith('addpl_') else vl_bytes)
        source = (word >> MULTIPLIER_SHIFT) & REGISTER_MASK
        value = amount
        if not name.startswith('rdvl_'):
            value += state['sp'] if source == REGISTER_MASK else state['x'][source]
        if d != REGISTER_MASK:
            result['x'][d] = value & MASK64
        elif not name.startswith('rdvl_'):
            result['sp'] = value & MASK64
        return result
    if name == 'cntp_r_p_p_':
        count = predicate_count(state['p'][op['predicate']] & state['p'][op['governing']],
                                op['element_bytes'], vl_bytes)
    elif name == 'cntp_r_pn_':
        count = counter_count(state['p'][op['predicate']] & 0xffff, op['element_bytes'],
                              vl_bytes, 2 << ((word >> GOVERNING_SHIFT) & 1))
    elif 'incp_' in name or 'decp_' in name:
        count = predicate_count(state['p'][op['predicate']], op['element_bytes'], vl_bytes)
    else:
        count = pattern_count(op['pattern'], op['element_bytes'], vl_bytes) * op['multiplier']
    if name.startswith('cnt'):
        if d != REGISTER_MASK:
            result['x'][d] = count
        return result
    delta = -count if op['subtract'] else count
    bits = op['element_bytes'] * 8 if op['vector'] else op['scalar_bits']
    mask = (1 << bits) - 1
    def adjust(value):
        value &= mask
        if op['signed'] and value & (1 << (bits - 1)):
            value -= 1 << bits
        value += delta
        if op['signed']:
            value = min((1 << (bits - 1)) - 1, max(-(1 << (bits - 1)), value))
        elif op['unsigned']:
            value = min(mask, max(0, value))
        return value & mask
    if op['vector']:
        original = state['z'][d]
        if len(original) != vl_bytes:
            raise ValueError('Z state length differs from active VL')
        size = op['element_bytes']
        result['z'][d] = b''.join(adjust(int.from_bytes(original[n:n+size], 'little')).to_bytes(size, 'little')
                                 for n in range(0, vl_bytes, size))
    elif d != REGISTER_MASK:
        value = adjust(state['x'][d])
        if op['signed'] and bits == 32 and value & (1 << 31):
            value |= MASK64 ^ ((1 << 32) - 1)
        result['x'][d] = value
    return result


def expected(operation, initial, ram=None):
    """Recompute a complete portable snapshot from encoded operands."""
    from scalable_frame import snapshot_from_state, snapshot_to_state
    op = decode(operation['word'])
    if op is None or op['canonical_id'] != operation['canonical_id']:
        raise ValueError('Scalable arithmetic canonical identity differs')
    state = snapshot_to_state(initial)
    result = apply(op, state, initial.svl_bytes)
    frame = snapshot_from_state(initial, result)
    return frame, ram, None


def scalable_cases(svl_bytes):
    """Lazily yield full-bank cases, retaining only small operation descriptors."""
    from scalable_frame import seeded_snapshot, snapshot_from_state, snapshot_to_state
    if svl_bytes not in SVL_BYTES:
        raise ValueError('Unsupported SME streaming length')
    descriptors = set()
    for name, (base, mask) in FORMS.items():
        if '_z_p_' in name:
            base |= 1 << SIZE_SHIFT
        descriptors.add((base, 'dirty'))
        descriptors.add((base | REGISTER_MASK, 'dirty'))
        if name.startswith(('addvl_', 'addpl_', 'rdvl_')):
            for immediate in (0, 1, 31, 32, 63):
                word = (base & ~(IMMEDIATE_MASK << PATTERN_SHIFT)) | immediate << PATTERN_SHIFT
                descriptors.add((word, 'boundary'))
                if not name.startswith('rdvl_'):
                    descriptors.add((word | REGISTER_MASK << MULTIPLIER_SHIFT | REGISTER_MASK, 'boundary'))
        elif name == 'cntp_r_pn_':
            for size in range(4):
                for source in (0, 7, 8, 15):
                    for width in (0, 1):
                        word = base | size << SIZE_SHIFT | source << PREDICATE_SHIFT | width << GOVERNING_SHIFT
                        for edge in ('dirty', 'counter-zero', 'counter-one', 'counter-invert', 'counter-max'):
                            descriptors.add((word, edge))
        elif name == 'cntp_r_p_p_' or 'incp_' in name or 'decp_' in name:
            for size in range(4):
                if '_z_' in name and size == 0:
                    continue
                for source in (0, 7, 8, 15):
                    word = (base & ~(SIZE_MASK << SIZE_SHIFT)) | size << SIZE_SHIFT | source << PREDICATE_SHIFT
                    for edge in ('predicate-zero', 'predicate-one', 'predicate-leading', 'predicate-nonleading'):
                        descriptors.add((word, edge))
                    if name == 'cntp_r_p_p_':
                        descriptors.add((word | source << GOVERNING_SHIFT, 'dirty'))
        else:
            for pattern in (0, 1, 8, 9, 13, 14, 28, 29, 30, 31):
                for multiplier in (0, 15):
                    descriptors.add((base | pattern << PATTERN_SHIFT | multiplier << MULTIPLIER_SHIFT, 'boundary'))
        if name.startswith(('sq', 'uq')):
            for edge in ('zero', 'maximum', 'signed-minimum', 'signed-maximum'):
                descriptors.add((base, edge))
    for index, (word, edge) in enumerate(sorted(descriptors)):
        op = decode(word)
        initial = seeded_snapshot(svl_bytes, b'sve-address\0' + word.to_bytes(4, 'little') + edge.encode(),
                                  case_index=index, function_index=index)
        state = snapshot_to_state(initial)
        z, p = state['z'], state['p']
        if edge == 'boundary':
            state['x'] = [MASK64 - register for register in range(31)]
            state['sp'] = MASK64 - REGISTER_MASK
        if edge in ('zero', 'maximum', 'signed-minimum', 'signed-maximum'):
            bits = op['element_bytes'] * 8 if op['vector'] else op['scalar_bits']
            values = {'zero': 0, 'maximum': (1 << bits) - 1,
                      'signed-minimum': 1 << (bits - 1), 'signed-maximum': (1 << (bits - 1)) - 1}
            value = values[edge]
            if op['vector']:
                size = op['element_bytes']
                lanes = (value, 0, (1 << bits) - 1, 1 << (bits - 1))
                z[op['destination']] = b''.join(lanes[n % len(lanes)].to_bytes(size, 'little')
                                               for n in range(svl_bytes // size))
            elif op['destination'] != REGISTER_MASK:
                # Dirty upper W bits distinguish mandatory signed/unsigned extension.
                if bits == 32:
                    value |= 0x12345678 << 32
                state['x'][op['destination']] = value
        if edge.startswith('predicate-'):
            stride = op['element_bytes']
            leading = sum(1 << bit for bit in range(0, svl_bytes, stride))
            full = (1 << svl_bytes) - 1
            value = {'predicate-zero': 0, 'predicate-one': full,
                     'predicate-leading': leading, 'predicate-nonleading': full ^ leading}[edge]
            p[op['predicate']] = value
        if edge.startswith('counter-'):
            value = {'counter-zero': 0, 'counter-one': 3, 'counter-invert': 0x8001,
                     'counter-max': 0xffff}[edge]
            value |= ((1 << svl_bytes) - 1) ^ 0xffff
            p[op['predicate']] = value
        initial = snapshot_from_state(initial, state)
        output, _, fault = expected(op, initial)
        yield {'operation': op, 'initial': initial, 'expected': output,
               'required': initial.valid, 'fault': fault}
