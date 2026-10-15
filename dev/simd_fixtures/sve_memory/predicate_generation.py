"""Independent integer models for all 45 SVE predicate-generation forms.

Predicate registers hold one packed architectural bit per vector byte. PN8..15
are aliases of P8..15; their encoded counter value is not an expanded mask.
"""
from copy import deepcopy

BYTE_BITS = 8
MIN_VL_BITS = 128
MAX_VL_BITS = 2048
PREDICATE_REGISTERS = 16
PN_BASE = 8
GPR_ZERO = 31
N_FLAG, Z_FLAG, C_FLAG, V_FLAG = 1 << 31, 1 << 30, 1 << 29, 1 << 28
COUNTER_INVERT_SHIFT = 15
PATTERN_POWER_OF_TWO, PATTERN_MULTIPLE_FOUR, PATTERN_MULTIPLE_THREE, PATTERN_ALL = 0, 29, 30, 31



def validate_vl(vl_bits):
    if type(vl_bits) is not int or not MIN_VL_BITS <= vl_bits <= MAX_VL_BITS or vl_bits % MIN_VL_BITS:
        raise ValueError('Architectural VL must be 128..2048 bits in 128-bit steps')
    return vl_bits // BYTE_BITS


def predtest(mask, result, element_bytes, predicate_bits):
    active = [bit for bit in range(0, predicate_bits, element_bytes) if mask >> bit & 1]
    first = bool(active and result >> active[0] & 1)
    last = bool(active and result >> active[-1] & 1)
    none = not any(result >> bit & 1 for bit in active)
    return (N_FLAG if first else 0) | (Z_FLAG if none else 0) | (0 if last else C_FLAG)


def pattern_count(pattern, elements):
    if not 0 <= pattern < 32:
        raise ValueError('Pattern is a five-bit field')
    if pattern == PATTERN_POWER_OF_TWO:
        return 1 << (elements.bit_length() - 1)
    if pattern <= 8:
        count = pattern
    elif pattern <= 13:
        count = 1 << (pattern - 5)
    elif pattern == PATTERN_MULTIPLE_FOUR:
        return elements - elements % 4
    elif pattern == PATTERN_MULTIPLE_THREE:
        return elements - elements % 3
    elif pattern == PATTERN_ALL:
        return elements
    else:
        return 0
    return count if count <= elements else 0


def encode_counter(element_bytes, elements, count, invert=False):
    if element_bytes not in (1, 2, 4, 8) or not 0 <= count <= elements:
        raise ValueError('Invalid predicate counter')
    if count == 0:
        return 0
    if invert:
        count = elements - count
    elif count == elements:
        count, invert = 0, True
    # Low16 encodes inverted bit15, count above the element-size marker.
    return (int(invert) << COUNTER_INVERT_SHIFT) | (count << element_bytes.bit_length()) | element_bytes


def apply_basic(op, state, vl_bits):
    pl = validate_vl(vl_bits)
    result = deepcopy(state)
    name, d = op['name'], op['d']
    mask = (1 << pl) - 1
    predicates = state['p']
    if len(predicates) != PREDICATE_REGISTERS:
        raise ValueError('State must contain all16 architectural predicate registers')
    element_bytes = op['element_bytes']
    if name == 'pfalse':
        result['p'][d] = 0
    elif name in ('ptrue', 'ptrues'):
        count = pattern_count(op['pattern'], pl // element_bytes)
        value = sum(1 << (lane * element_bytes) for lane in range(count))
        result['p'][d] = value
        if name == 'ptrues':
            result['nzcv'] = predtest(value, value, element_bytes, pl)
    elif name == 'ptrue_pn':
        elements = pl // element_bytes
        result['p'][d] = encode_counter(element_bytes, elements, elements)
    elif name == 'pfirst':
        governed = predicates[op['g']] & mask
        value = predicates[d] & mask
        for bit in range(pl):
            if governed >> bit & 1:
                value |= 1 << bit
                break
        result['p'][d] = value
        result['nzcv'] = predtest(governed, value, 1, pl)
    elif name == 'pnext':
        governed, old = predicates[op['g']] & mask, predicates[d] & mask
        active = [bit for bit in range(0, pl, element_bytes) if old >> bit & 1]
        start = active[-1] + element_bytes if active else 0
        value = 0
        for bit in range(start, pl, element_bytes):
            if governed >> bit & 1:
                value = 1 << bit
                break
        result['p'][d] = value
        result['nzcv'] = predtest(governed, value, element_bytes, pl)
    elif name == 'ptest':
        result['nzcv'] = predtest(predicates[op['g']], predicates[op['n']], 1, pl)
    elif name in ('ctermeq', 'ctermne'):
        scalar_mask = (1 << op['scalar_bits']) - 1
        def source(index):
            return 0 if index == GPR_ZERO else state['x'][index] & scalar_mask
        equal = source(op['n']) == source(op['m'])
        term = equal if name == 'ctermeq' else not equal
        old_flags = state['nzcv']
        result['nzcv'] = old_flags & (Z_FLAG | C_FLAG)
        if term:
            result['nzcv'] |= N_FLAG
        elif not old_flags & C_FLAG:
            result['nzcv'] |= V_FLAG
    else:
        raise ValueError('Unowned predicate-generation operation')
    return result

# Canonical facts from pinned Arm June2026; no alias entries.
CANONICAL_FORMS = (
    ('brka_p_p_p_', 'brka', 0xffffc200, 0x25104000),
    ('brkas_p_p_p_z', 'brkas', 0xffffc210, 0x25504000),
    ('brkb_p_p_p_', 'brkb', 0xffffc200, 0x25904000),
    ('brkbs_p_p_p_z', 'brkbs', 0xffffc210, 0x25d04000),
    ('brkn_p_p_pp_', 'brkn', 0xffffc210, 0x25184000),
    ('brkns_p_p_pp_', 'brkns', 0xffffc210, 0x25584000),
    ('brkpa_p_p_pp_', 'brkpa', 0xfff0c210, 0x2500c000),
    ('brkpas_p_p_pp_', 'brkpas', 0xfff0c210, 0x2540c000),
    ('brkpb_p_p_pp_', 'brkpb', 0xfff0c210, 0x2500c010),
    ('brkpbs_p_p_pp_', 'brkpbs', 0xfff0c210, 0x2540c010),
    ('ctermeq_rr_', 'ctermeq', 0xffa0fc1f, 0x25a02000),
    ('ctermne_rr_', 'ctermne', 0xffa0fc1f, 0x25a02010),
    ('pfalse_p_', 'pfalse', 0xfffffff0, 0x2518e400),
    ('pfirst_p_p_p_', 'pfirst', 0xfffffe10, 0x2558c000),
    ('pnext_p_p_p_', 'pnext', 0xff3ffe10, 0x2519c400),
    ('ptest__p_p_', 'ptest', 0xffffc21f, 0x2550c000),
    ('ptrue_p_s_', 'ptrue', 0xff3ffc10, 0x2518e000),
    ('ptrue_pn_i_', 'ptrue', 0xff3ffff8, 0x25207810),
    ('ptrues_p_s_', 'ptrues', 0xff3ffc10, 0x2519e000),
    ('whilege_p_p_rr_', 'whilege', 0xff20ec10, 0x25200000),
    ('whilege_pn_rr_', 'whilege', 0xff20dc18, 0x25204010),
    ('whilege_pp_rr_', 'whilege', 0xff20fc11, 0x25205010),
    ('whilegt_p_p_rr_', 'whilegt', 0xff20ec10, 0x25200010),
    ('whilegt_pn_rr_', 'whilegt', 0xff20dc18, 0x25204018),
    ('whilegt_pp_rr_', 'whilegt', 0xff20fc11, 0x25205011),
    ('whilehi_p_p_rr_', 'whilehi', 0xff20ec10, 0x25200810),
    ('whilehi_pn_rr_', 'whilehi', 0xff20dc18, 0x25204818),
    ('whilehi_pp_rr_', 'whilehi', 0xff20fc11, 0x25205811),
    ('whilehs_p_p_rr_', 'whilehs', 0xff20ec10, 0x25200800),
    ('whilehs_pn_rr_', 'whilehs', 0xff20dc18, 0x25204810),
    ('whilehs_pp_rr_', 'whilehs', 0xff20fc11, 0x25205810),
    ('whilele_p_p_rr_', 'whilele', 0xff20ec10, 0x25200410),
    ('whilele_pn_rr_', 'whilele', 0xff20dc18, 0x25204418),
    ('whilele_pp_rr_', 'whilele', 0xff20fc11, 0x25205411),
    ('whilelo_p_p_rr_', 'whilelo', 0xff20ec10, 0x25200c00),
    ('whilelo_pn_rr_', 'whilelo', 0xff20dc18, 0x25204c10),
    ('whilelo_pp_rr_', 'whilelo', 0xff20fc11, 0x25205c10),
    ('whilels_p_p_rr_', 'whilels', 0xff20ec10, 0x25200c10),
    ('whilels_pn_rr_', 'whilels', 0xff20dc18, 0x25204c18),
    ('whilels_pp_rr_', 'whilels', 0xff20fc11, 0x25205c11),
    ('whilelt_p_p_rr_', 'whilelt', 0xff20ec10, 0x25200400),
    ('whilelt_pn_rr_', 'whilelt', 0xff20dc18, 0x25204410),
    ('whilelt_pp_rr_', 'whilelt', 0xff20fc11, 0x25205410),
    ('whilerw_p_rr_', 'whilerw', 0xff20fc10, 0x25203010),
    ('whilewr_p_rr_', 'whilewr', 0xff20fc10, 0x25203000),
)

def scalar_integer(value: int, bits: int, unsigned: bool) -> int:
    value &= (1 << bits) - 1
    return value if unsigned or value < (1 << (bits - 1)) else value - (1 << bits)


def comparison_count(mnemonic: str, first: int, limit: int, bits: int, elements: int) -> int:
    """Closed-form count; no iteration and no host-width arithmetic overflow."""
    unsigned = mnemonic in ('WHILELO', 'WHILELS', 'WHILEHI', 'WHILEHS')
    descending = mnemonic in ('WHILEGE', 'WHILEGT', 'WHILEHI', 'WHILEHS')
    inclusive = mnemonic in ('WHILELE', 'WHILELS', 'WHILEGE', 'WHILEHS')
    first, limit = (scalar_integer(x, bits, unsigned) for x in (first, limit))
    minimum = 0 if unsigned else -(1 << (bits - 1))
    maximum = (1 << bits) - 1 if unsigned else (1 << (bits - 1)) - 1
    # Inclusive endpoint bounds are true over the entire modular domain.
    if inclusive and limit == (minimum if descending else maximum):
        return elements
    distance = first - limit if descending else limit - first
    return max(0, min(elements, distance + int(inclusive)))


def flags(elements: int, count: int, descending: bool) -> int:
    first_active = count == elements if descending else count != 0
    last_active = count != 0 if descending else count == elements
    return (N_FLAG if first_active else 0) | (Z_FLAG if not count else 0) | (C_FLAG if not last_active else 0)



def decode(word):
    """Decode the exact45 owned canonical forms into ABI-independent fields."""
    if type(word) is not int or not 0 <= word < 1 << 32:
        raise ValueError('Instruction must be a32-bit word')
    for canonical, mnemonic, mask, value in CANONICAL_FORMS:
        if word & mask != value:
            continue
        op = {'word': word, 'canonical_id': canonical, 'name': mnemonic,
              'd': word & 15, 'g': word >> 10 & 15, 'n': word >> 5 & 31,
              'm': word >> 16 & 31, 'element_bytes': 1 << (word >> 22 & 3)}
        if mnemonic.startswith('while'):
            representation = 'pn' if '_pn_' in canonical else 'pp' if '_pp_' in canonical else 'p'
            op['representation'] = representation
            op['d'] = 8 + (word & 7) if representation == 'pn' else word & 14 if representation == 'pp' else word & 15
            op['scalar_bits'] = 32 << (word >> 12 & 1) if representation == 'p' and mnemonic not in ('whilerw', 'whilewr') else 64
            op['vector_count'] = 2 << (word >> 13 & 1) if representation == 'pn' else 2 if representation == 'pp' else 1
        elif mnemonic.startswith('brk'):
            op['element_bytes'] = 1
            op['n'] &= 15
            op['m'] &= 15
            op['merging'] = mnemonic in ('brka', 'brkb') and bool(word >> 4 & 1)
        elif canonical == 'ptrue_pn_i_':
            op['name'] = 'ptrue_pn'
            op['d'] = 8 + (word & 7)
        elif mnemonic in ('ptrue', 'ptrues'):
            op['pattern'] = word >> 5 & 31
        elif mnemonic in ('pfirst', 'pnext'):
            op['g'] = word >> 5 & 15
            if mnemonic == 'pfirst':
                op['element_bytes'] = 1
        elif mnemonic == 'ptest':
            op['element_bytes'] = 1
            op['n'] &= 15
        elif mnemonic in ('ctermeq', 'ctermne'):
            op['scalar_bits'] = 32 << (word >> 22 & 1)
        return op
    return None


def encode(canonical_id, **fields):
    """Encode validated architectural fields; no fixture-only alias rewriting."""
    form = next((f for f in CANONICAL_FORMS if f[0] == canonical_id), None)
    if form is None:
        raise ValueError('Unowned canonical form')
    _, name, mask, word = form
    specs = {}
    if name.startswith('while'):
        specs.update(element_bytes=(22, 3, 'size'), n=(5, 31, 'identity'), m=(16, 31, 'identity'))
        if '_pn_' in canonical_id:
            specs.update(d=(0, 7, 'counter'), vector_count=(13, 1, 'vectors'))
        elif '_pp_' in canonical_id:
            specs.update(d=(0, 14, 'pair'))
        else:
            specs.update(d=(0, 15, 'identity'))
            if name not in ('whilerw', 'whilewr'):
                specs.update(scalar_bits=(12, 1, 'width'))
    elif name.startswith('brk'):
        specs.update(d=(0, 15, 'identity'), g=(10, 15, 'identity'), n=(5, 15, 'identity'))
        if name.startswith('brkp'):
            specs.update(m=(16, 15, 'identity'))
        if name in ('brka', 'brkb'):
            specs.update(merging=(4, 1, 'identity'))
    elif canonical_id == 'ptrue_pn_i_':
        specs.update(d=(0, 7, 'counter'), element_bytes=(22, 3, 'size'))
    elif name in ('ptrue', 'ptrues'):
        specs.update(d=(0, 15, 'identity'), element_bytes=(22, 3, 'size'), pattern=(5, 31, 'identity'))
    elif name in ('pfirst', 'pnext'):
        specs.update(d=(0, 15, 'identity'), g=(5, 15, 'identity'))
        if name == 'pnext':
            specs.update(element_bytes=(22, 3, 'size'))
    elif name == 'pfalse':
        specs.update(d=(0, 15, 'identity'))
    elif name == 'ptest':
        specs.update(g=(10, 15, 'identity'), n=(5, 15, 'identity'))
    else:
        specs.update(n=(5, 31, 'identity'), m=(16, 31, 'identity'), scalar_bits=(22, 1, 'width'))
    if fields.keys() - specs.keys():
        raise ValueError('Field does not belong to canonical form')
    for key, value in fields.items():
        shift, field_mask, conversion = specs[key]
        if type(value) is bool:
            value = int(value)
        if type(value) is not int:
            raise ValueError('Operand field must be an integer')
        if conversion == 'size':
            if value not in (1, 2, 4, 8):
                raise ValueError('Invalid element width')
            value = value.bit_length() - 1
        elif conversion == 'width':
            if value not in (32, 64):
                raise ValueError('Invalid scalar width')
            value = value == 64
        elif conversion == 'counter':
            value -= 8
        elif conversion == 'vectors':
            if value not in (2, 4):
                raise ValueError('Invalid counter vector count')
            value = value == 4
        if value < 0 or value & ~field_mask:
            raise ValueError('Invalid operand field')
        word |= value << shift
    if word & mask != form[3]:
        raise AssertionError('Encoder changed canonical fixed bits')
    return decode(word)


def apply_break(op, state, vl_bits):
    predicate_bits = validate_vl(vl_bits)
    all_bits = (1 << predicate_bits) - 1
    old = tuple(value & all_bits for value in state['p'])
    name, d, g, n, m = (op[key] for key in ('name', 'd', 'g', 'n', 'm'))
    governor, operand, destination = old[g], old[n], old[d]
    active = [bit for bit in range(predicate_bits) if governor >> bit & 1]
    last = bool(active and operand >> active[-1] & 1)
    if name in ('brkn', 'brkns'):
        value = destination if last else 0
        test_mask = all_bits
    else:
        previous = name.startswith('brkp')
        before = name in ('brkb', 'brkbs', 'brkpb', 'brkpbs')
        running = last if previous else True
        breaking = old[m] if previous else operand
        value = 0
        for bit in range(predicate_bits):
            if governor >> bit & 1:
                if before:
                    running = running and not bool(breaking >> bit & 1)
                if running:
                    value |= 1 << bit
                if not before:
                    running = running and not bool(breaking >> bit & 1)
            elif op['merging'] and destination >> bit & 1:
                value |= 1 << bit
        test_mask = governor
    output = deepcopy(state)
    output['p'][d] = value
    if name in ('brkas', 'brkbs', 'brkns', 'brkpas', 'brkpbs'):
        output['nzcv'] = predtest(test_mask, value, 1, predicate_bits)
    return output


def apply_while(op, state, vl_bits):
    predicate_bits = validate_vl(vl_bits)
    name, stride, vectors = op['name'].upper(), op['element_bytes'], op['vector_count']
    read = lambda index: 0 if index == GPR_ZERO else state['x'][index]
    first, limit = read(op['n']), read(op['m'])
    elements = predicate_bits // stride * vectors
    descending = name in ('WHILEGE', 'WHILEGT', 'WHILEHI', 'WHILEHS')
    if name in ('WHILERW', 'WHILEWR'):
        delta = scalar_integer(limit, 64, True) - scalar_integer(first, 64, True)
        distance = (abs(delta) if name == 'WHILERW' else delta) // stride
        count = elements if distance <= 0 else min(elements, distance)
    else:
        count = comparison_count(name, first, limit, op['scalar_bits'], elements)
    output = deepcopy(state)
    output['nzcv'] = flags(elements, count, descending)
    if op['representation'] == 'pn':
        output['p'][op['d']] = encode_counter(stride, elements, count, descending)
    else:
        start = elements - count if descending else 0
        value = sum(1 << (index * stride) for index in range(start, start + count))
        mask = (1 << predicate_bits) - 1
        for index in range(vectors):
            output['p'][op['d'] + index] = value >> (index * predicate_bits) & mask
    return output


def apply(op, state, vl_bits):
    """Preserve complete caller state except decoded predicates and NZCV.

    Mode/feature traps belong to the shared execution profile. This semantic
    model grants no coverage by itself and never changes Z/FFR/ZA/RAM/FP state.
    """
    decoded = decode(op['word'])
    if decoded != op:
        raise ValueError('Operation metadata differs from original encoded word')
    if op['name'].startswith('while'):
        return apply_while(op, state, vl_bits)
    if op['name'].startswith('brk'):
        return apply_break(op, state, vl_bits)
    return apply_basic(op, state, vl_bits)


def expected(operation, initial, ram=None):
    """Adapt mathematical P/NZCV effects to the common full scalable frame."""
    from scalable_frame import snapshot_from_state, snapshot_to_state
    output = apply(operation, snapshot_to_state(initial), initial.svl_bytes * BYTE_BITS)
    return snapshot_from_state(initial, output), ram, None


def scalable_cases(svl_bytes):
    """Yield bounded lazy full-state cases for all45 forms and directed edges.

    Banks are generated per observation. Callers can process128 observations at
    a time without materializing large ZA frames for an entire family corpus.
    """
    from scalable_frame import (require_sme_length, seeded_snapshot,
                                snapshot_from_state, snapshot_to_state)
    require_sme_length(svl_bytes)
    words = set()
    operations = []
    def add(op):
        if op['word'] not in words:
            words.add(op['word'])
            operations.append(op)
    for canonical, name, _, value in CANONICAL_FORMS:
        add(decode(value))
        if name.startswith('while'):
            for element_bytes in (1, 2, 4, 8):
                for d, n, limit in ((0, 0, 1), (14, 31, 31), (0, 0, 0)):
                    fields = {'d': 8 if '_pn_' in canonical and d == 0 else d,
                              'n': n, 'm': limit, 'element_bytes': element_bytes}
                    add(encode(canonical, **fields))
                    if '_pn_' in canonical:
                        add(encode(canonical, **fields, vector_count=4))
                    elif '_pp_' not in canonical and name not in ('whilerw', 'whilewr'):
                        add(encode(canonical, **fields, scalar_bits=64))
        elif name.startswith('brk'):
            for d, g, n, source in ((0, 1, 2, 3), (15, 15, 15, 15), (0, 0, 1, 0), (0, 1, 0, 1)):
                fields = {'d': d, 'g': g, 'n': n}
                if name.startswith('brkp'):
                    fields['m'] = source
                add(encode(canonical, **fields))
                if name in ('brka', 'brkb'):
                    add(encode(canonical, **fields, merging=True))
        elif canonical == 'ptrue_pn_i_':
            for size in (1, 2, 4, 8):
                for d in (8, 15):
                    add(encode(canonical, d=d, element_bytes=size))
        elif name in ('ptrue', 'ptrues'):
            for size in (1, 2, 4, 8):
                for pattern in range(32):
                    add(encode(canonical, d=15, element_bytes=size, pattern=pattern))
        elif name in ('pfirst', 'pnext'):
            for d, g in ((0, 1), (15, 15), (0, 0)):
                for size in ((1, 2, 4, 8) if name == 'pnext' else (1,)):
                    fields = {'d': d, 'g': g}
                    if name == 'pnext':
                        fields['element_bytes'] = size
                    add(encode(canonical, **fields))
        elif name == 'ptest':
            for g, n in ((0, 1), (15, 15), (1, 0)):
                add(encode(canonical, g=g, n=n))
        elif name in ('ctermeq', 'ctermne'):
            for n, source in ((0, 1), (0, 0), (31, 31), (0, 31)):
                for width in (32, 64):
                    add(encode(canonical, n=n, m=source, scalar_bits=width))
    scalar_edges = (0, 1, (1 << 31) - 1, 1 << 31, (1 << 32) - 1,
                    (1 << 63) - 1, 1 << 63, (1 << 64) - 1)
    case_index = 0
    for function_index, op in enumerate(operations):
        # Dirty, empty, all-active and chunk/endpoint-oriented cohorts.
        for variant in range(4):
            initial = seeded_snapshot(svl_bytes, ('predicate-generation:' + str(op['word']) + ':' + str(variant)).encode(),
                                      case_index=case_index, function_index=function_index)
            state = snapshot_to_state(initial)
            state['nzcv'] = ((function_index + variant * 5) & 15) << 28
            if op['name'].startswith('while') or op['name'].startswith('cterm'):
                for register, value in ((op['n'], scalar_edges[(function_index + variant) % len(scalar_edges)]),
                                        (op['m'], scalar_edges[(function_index + variant + 1) % len(scalar_edges)])):
                    if register != GPR_ZERO:
                        state['x'][register] = value
            predicates = state['p']
            if variant == 1:
                predicates = [0] * PREDICATE_REGISTERS
            elif variant == 2:
                predicates = [(1 << svl_bytes) - 1] * PREDICATE_REGISTERS
            elif variant == 3:
                pl = svl_bytes
                boundary = sum(1 << bit for bit in (0, pl // 2 - 1, pl // 2, pl - 1))
                predicates = [boundary] * PREDICATE_REGISTERS
            state['p'] = predicates
            initial = snapshot_from_state(initial, state)
            final, _, _ = expected(op, initial)
            yield {'operation': op, 'initial': initial, 'expected': final,
                   'required': initial.valid, 'ram': None, 'expected_ram': None, 'fault': None}
            case_index += 1
