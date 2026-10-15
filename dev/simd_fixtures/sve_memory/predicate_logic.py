"""Pure packed-predicate semantics; no host execution or support-credit claim.

Predicate bit i corresponds to vector byte i. Groups preserve their entire
psize bits for ZIP/TRN/UZP/REV; PMOV/PEXT/PUNPK zero nonleading bits.
"""
from __future__ import annotations

from dataclasses import dataclass

from .counter import COUNTER_FORMAT_MASK, COUNTER_INVERT, counter_bits

BYTE_BITS = 8
P_REGISTER_MASK = 15
Z_REGISTER_MASK = 31
SOURCE_SHIFT = 5
RIGHT_SHIFT = 16
GOVERNOR_SHIFT = 10
SIZE_SHIFT = 22
SIZE_MASK = 3
NZCV_N = 1 << 31
NZCV_Z = 1 << 30
NZCV_C = 1 << 29
FORMS = (
    {'id': 'and_p_p_pp_z', 'mnemonic': 'AND', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25004000'},
    {'id': 'ands_p_p_pp_z', 'mnemonic': 'ANDS', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25404000'},
    {'id': 'bic_p_p_pp_z', 'mnemonic': 'BIC', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25004010'},
    {'id': 'bics_p_p_pp_z', 'mnemonic': 'BICS', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25404010'},
    {'id': 'eor_p_p_pp_z', 'mnemonic': 'EOR', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25004200'},
    {'id': 'eors_p_p_pp_z', 'mnemonic': 'EORS', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25404200'},
    {'id': 'nand_p_p_pp_z', 'mnemonic': 'NAND', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25804210'},
    {'id': 'nands_p_p_pp_z', 'mnemonic': 'NANDS', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25c04210'},
    {'id': 'nor_p_p_pp_z', 'mnemonic': 'NOR', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25804200'},
    {'id': 'nors_p_p_pp_z', 'mnemonic': 'NORS', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25c04200'},
    {'id': 'orn_p_p_pp_z', 'mnemonic': 'ORN', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25804010'},
    {'id': 'orns_p_p_pp_z', 'mnemonic': 'ORNS', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25c04010'},
    {'id': 'orr_p_p_pp_z', 'mnemonic': 'ORR', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25804000'},
    {'id': 'orrs_p_p_pp_z', 'mnemonic': 'ORRS', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25c04000'},
    {'id': 'pext_pn_rr_', 'mnemonic': 'PEXT', 'encoding_mask': '0xff3ffc10', 'encoding_value': '0x25207010'},
    {'id': 'pext_pp_rr_', 'mnemonic': 'PEXT', 'encoding_mask': '0xff3ffe10', 'encoding_value': '0x25207410'},
    {'id': 'pmov_p_zi_b', 'mnemonic': 'PMOV', 'encoding_mask': '0xfffffc10', 'encoding_value': '0x052a3800'},
    {'id': 'pmov_p_zi_d', 'mnemonic': 'PMOV', 'encoding_mask': '0xffb9fc10', 'encoding_value': '0x05a83800'},
    {'id': 'pmov_p_zi_h', 'mnemonic': 'PMOV', 'encoding_mask': '0xfffdfc10', 'encoding_value': '0x052c3800'},
    {'id': 'pmov_p_zi_s', 'mnemonic': 'PMOV', 'encoding_mask': '0xfff9fc10', 'encoding_value': '0x05683800'},
    {'id': 'psel_p_ppi_', 'mnemonic': 'PSEL', 'encoding_mask': '0xff20c210', 'encoding_value': '0x25204000'},
    {'id': 'punpkhi_p_p_', 'mnemonic': 'PUNPKHI', 'encoding_mask': '0xfffffe10', 'encoding_value': '0x05314000'},
    {'id': 'punpklo_p_p_', 'mnemonic': 'PUNPKLO', 'encoding_mask': '0xfffffe10', 'encoding_value': '0x05304000'},
    {'id': 'rev_p_p_', 'mnemonic': 'REV', 'encoding_mask': '0xff3ffe10', 'encoding_value': '0x05344000'},
    {'id': 'sel_p_p_pp_', 'mnemonic': 'SEL', 'encoding_mask': '0xfff0c210', 'encoding_value': '0x25004210'},
    {'id': 'trn1_p_pp_', 'mnemonic': 'TRN1', 'encoding_mask': '0xff30fe10', 'encoding_value': '0x05205000'},
    {'id': 'trn2_p_pp_', 'mnemonic': 'TRN2', 'encoding_mask': '0xff30fe10', 'encoding_value': '0x05205400'},
    {'id': 'uzp1_p_pp_', 'mnemonic': 'UZP1', 'encoding_mask': '0xff30fe10', 'encoding_value': '0x05204800'},
    {'id': 'uzp2_p_pp_', 'mnemonic': 'UZP2', 'encoding_mask': '0xff30fe10', 'encoding_value': '0x05204c00'},
    {'id': 'zip1_p_pp_', 'mnemonic': 'ZIP1', 'encoding_mask': '0xff30fe10', 'encoding_value': '0x05204000'},
    {'id': 'zip2_p_pp_', 'mnemonic': 'ZIP2', 'encoding_mask': '0xff30fe10', 'encoding_value': '0x05204400'},
)

@dataclass(frozen=True)
class Operand:
    form: str
    mnemonic: str
    destination: int
    source: int
    right: int = 0
    governor: int = 0
    element_bytes: int = 1
    part: int = 0
    immediate: int = 0
    index_register: int = 0


def decode(word: int) -> Operand | None:
    if type(word) is not int or not 0 <= word <= (1 << 32) - 1:
        raise ValueError('Expected one unsigned A64 instruction word')
    matches = [r for r in FORMS if word & int(r['encoding_mask'], 16) == int(r['encoding_value'], 16)]
    if not matches:
        return None
    assert len(matches) == 1
    row = matches[0]
    name, op = row['id'], row['mnemonic']
    d, n = word & P_REGISTER_MASK, (word >> SOURCE_SHIFT) & P_REGISTER_MASK
    m, g = (word >> RIGHT_SHIFT) & P_REGISTER_MASK, (word >> GOVERNOR_SHIFT) & P_REGISTER_MASK
    element_bytes = 1 << ((word >> SIZE_SHIFT) & SIZE_MASK)
    if name.startswith(('and', 'bic', 'eor', 'nand', 'nor', 'orn', 'orr', 'sel_')):
        return Operand(name, op, d, n, m, g)
    if name.startswith('pmov'):
        kind = name.rsplit('_', 1)[1]
        element_bytes = {'b': 1, 'h': 2, 's': 4, 'd': 8}[kind]
        imm = 0 if kind == 'b' else ((word >> 17) & 1) if kind == 'h' else ((word >> 17) & 3)
        if kind == 'd':
            imm |= ((word >> 22) & 1) << 2
        return Operand(name, op, d, (word >> SOURCE_SHIFT) & Z_REGISTER_MASK, element_bytes=element_bytes, immediate=imm)
    if name.startswith('psel'):
        tsz = (((word >> 22) & 1) << 3) | ((word >> 18) & 7)
        if tsz == 0:
            raise ValueError('Reserved PSEL size encoding')
        size = (tsz & -tsz).bit_length() - 1
        imm5 = ((word >> 23) & 1) << 4 | tsz
        return Operand(name, op, d, (word >> 10) & P_REGISTER_MASK,
                       (word >> 5) & P_REGISTER_MASK, element_bytes=1 << size,
                       immediate=imm5 >> (size + 1), index_register=12 + ((word >> 16) & 3))
    if name.startswith('pext'):
        part = ((word >> 8) & 3) if name.startswith('pext_pn') else ((word >> 8) & 1)
        return Operand(name, op, d, 8 + ((word >> 5) & 7), element_bytes=element_bytes, part=part)
    if name.startswith('punpk'):
        return Operand(name, op, d, n, element_bytes=2, part=int(op == 'PUNPKHI'))
    return Operand(name, op, d, n, m, element_bytes=element_bytes, part=int(op.endswith('2')))


def predicate_flags(mask: int, result: int, width: int) -> int:
    mask &= (1 << width) - 1
    masked = mask & result
    if not mask:
        return NZCV_Z | NZCV_C
    first = (mask & -mask).bit_length() - 1
    last = mask.bit_length() - 1
    return (NZCV_N if result >> first & 1 else 0) | (NZCV_Z if not masked else 0) | (0 if result >> last & 1 else NZCV_C)


def evaluate(operand: Operand, predicates: list[bytes], vectors: list[bytes],
             gpr: list[int], nzcv: int, vl_bits: int) -> tuple[list[bytes], int]:
    """Snapshot operands before writing; preserves every other input byte."""
    assert vl_bits in range(128, 2049, 128)
    width = vl_bits // BYTE_BITS
    assert len(predicates) == 16 and all(len(p) * BYTE_BITS == width for p in predicates)
    assert len(vectors) == 32 and all(len(z) * BYTE_BITS == vl_bits for z in vectors)
    p = [int.from_bytes(x, 'little') for x in predicates]
    n, m, g, s = p[operand.source] if operand.source < 16 else 0, p[operand.right], p[operand.governor], operand.element_bytes
    op = operand.mnemonic
    full = (1 << width) - 1
    flag_ops = {'ANDS': 'AND', 'BICS': 'BIC', 'EORS': 'EOR', 'NANDS': 'NAND', 'NORS': 'NOR', 'ORNS': 'ORN', 'ORRS': 'ORR'}
    base = flag_ops.get(op, op)
    values = {'AND': n & m, 'BIC': n & ~m, 'EOR': n ^ m,
              'NAND': ~(n & m), 'NOR': ~(n | m), 'ORN': n | ~m, 'ORR': n | m}
    outputs = {}
    if base in values:
        result = values[base] & g
        if op in flag_ops:
            nzcv = predicate_flags(g, result, width)
    elif op == 'SEL':
        result = (n & g) | (m & ~g & full)
    elif op == 'REV':
        group_mask = (1 << s) - 1
        result = sum(((n >> (i * s)) & group_mask) << (width - (i + 1) * s) for i in range(width // s))
    elif op.startswith(('ZIP', 'TRN', 'UZP')):
        group_mask = (1 << s) - 1
        a = [(n >> (i * s)) & group_mask for i in range(width // s)]
        b = [(m >> (i * s)) & group_mask for i in range(width // s)]
        part = operand.part
        if op.startswith('ZIP'):
            half = len(a) // 2
            groups = [v for pair in zip(a[part * half:(part + 1) * half], b[part * half:(part + 1) * half]) for v in pair]
        elif op.startswith('TRN'):
            groups = [v for pair in zip(a[part::2], b[part::2]) for v in pair]
        else:
            groups = a[part::2] + b[part::2]
        result = sum(v << (i * s) for i, v in enumerate(groups))
    elif op.startswith('PUNPK'):
        elements = width // 2
        result = sum((n >> (operand.part * elements + i) & 1) << (i * 2) for i in range(elements))
    elif op == 'PMOV':
        z = int.from_bytes(vectors[operand.source], 'little')
        elements = width // s
        result = sum((z >> (elements * operand.immediate + i) & 1) << (i * s) for i in range(elements))
    elif op == 'PSEL':
        index = ((gpr[operand.index_register] & 0xffffffff) + operand.immediate) % (width // s)
        result = n if m >> (index * s) & 1 else 0
    elif op == 'PEXT':
        expanded = counter_bits(n & 0xffff, width)
        elements = width // s
        parts = 2 if operand.form.startswith('pext_pp') else 1
        for output in range(parts):
            start = (operand.part * parts + output) * width
            outputs[(operand.destination + output) % 16] = sum((expanded >> (start + i * s) & 1) << (i * s) for i in range(elements))
        result = outputs[operand.destination]
    else:
        raise AssertionError(op)
    outputs[operand.destination] = result & full
    out = list(predicates)
    for d, value in outputs.items():
        out[d] = value.to_bytes(width // BYTE_BITS, 'little')
    return out, nzcv


def scalable_cases(svl_bytes):
    """Yield full-state cases lazily for the 31 packed-predicate forms.

    Each length has one immutable dirty seed. Cases replace only directed input
    operands, then model the instruction using the existing pure evaluator.
    Required components include untouched ZA/ZT0 and controls when valid; neither
    diagnostic FFR bytes nor an inaccessible FPMR receive observation credit.
    """
    from scalable_frame import (
        seeded_snapshot, snapshot_from_state, snapshot_to_state,
    )

    counter_bytes = 2
    counter_part_shift = 8
    counter_unused_high_bits = 0x7000
    pmov_slice_shift = 17
    psel_index_base = 12
    psel_size_low_shift = 18
    psel_size_high_shift = 22
    psel_immediate_high_shift = 23
    word_mask = (1 << 32) - 1
    gpr_mask = (1 << 64) - 1
    seed = seeded_snapshot(svl_bytes, b'sve-packed-predicate-adapter-v1')
    predicate_mask = (1 << svl_bytes) - 1
    alternating = sum(1 << bit for bit in range(0, svl_bytes, 2))
    edge_bits = 1 | (1 << (svl_bytes - 1))
    rows = {row['id']: row for row in FORMS}

    def encoded(form, fields):
        row = rows[form]
        mask = int(row['encoding_mask'], 16)
        word = int(row['encoding_value'], 16) | fields
        if word & mask != int(row['encoding_value'], 16):
            raise AssertionError('Adapter set a fixed encoding bit: ' + form)
        operand = decode(word)
        if operand is None or operand.form != form:
            raise AssertionError('Adapter source word has a different identity')
        return word, operand

    def case(form, fields, scenario, *, predicates=None, vectors=None, registers=None):
        word, operand = encoded(form, fields)
        state = snapshot_to_state(seed)
        for index, value in (registers or {}).items():
            state['x'][index] = value & gpr_mask
        for index, value in (predicates or {}).items():
            state['p'][index] = value & predicate_mask
        for index, value in (vectors or {}).items():
            state['z'][index] = value
        initial = snapshot_from_state(seed, state)
        result_p, result_nzcv = evaluate(
            operand, list(initial.p), list(initial.z),
            [*state['x'], state['sp']], state['nzcv'], svl_bytes * BYTE_BITS,
        )
        state['p'] = [int.from_bytes(row, 'little') for row in result_p]
        state['nzcv'] = result_nzcv
        expected = snapshot_from_state(initial, state)
        return {
            'operation': {'word': word, 'canonical_id': form, 'scenario': scenario},
            'initial': initial, 'expected': expected, 'required': initial.valid,
        }

    # Predicate logical operations test every source/destination overlap and
    # empty/edge governors, including dirty bits outside an element's low bit.
    logical_forms = tuple(row['id'] for row in FORMS
                          if row['mnemonic'] in ('AND', 'ANDS', 'BIC', 'BICS',
                              'EOR', 'EORS', 'NAND', 'NANDS', 'NOR', 'NORS',
                              'ORN', 'ORNS', 'ORR', 'ORRS', 'SEL'))
    logical_aliases = ((0, 1, 2, 3), (15, 15, 2, 3), (2, 1, 2, 3),
                       (3, 1, 2, 3), (7, 7, 7, 7))
    for form in logical_forms:
        for d, n, m, g in logical_aliases:
            fields = d | (n << SOURCE_SHIFT) | (m << RIGHT_SHIFT) | (g << GOVERNOR_SHIFT)
            yield case(form, fields, 'dirty-alias-' + '-'.join(map(str, (d, n, m, g))))
        fields = (1 << SOURCE_SHIFT) | (2 << RIGHT_SHIFT) | (3 << GOVERNOR_SHIFT)
        for label, governor in (('none', 0), ('all', predicate_mask), ('edges', edge_bits)):
            yield case(form, fields, 'governor-' + label,
                       predicates={1: alternating, 2: predicate_mask ^ alternating, 3: governor})

    # Permutations preserve entire multi-bit groups. Alternating dirty bits
    # distinguish them from implementations that accidentally keep leading bits.
    permutations = ('rev_p_p_', 'trn1_p_pp_', 'trn2_p_pp_', 'uzp1_p_pp_',
                    'uzp2_p_pp_', 'zip1_p_pp_', 'zip2_p_pp_')
    permutation_aliases = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (15, 15, 15))
    for form in permutations:
        for size in range(SIZE_MASK + 1):
            for d, n, m in permutation_aliases:
                fields = d | (n << SOURCE_SHIFT) | (size << SIZE_SHIFT)
                if form != 'rev_p_p_':
                    fields |= m << RIGHT_SHIFT
                yield case(form, fields, 'dirty-size-' + str(size) + '-alias-' + str(d))
                directed = {n: alternating}
                if m != n and form != 'rev_p_p_':
                    directed[m] = predicate_mask ^ alternating
                yield case(form, fields, 'alternating-size-' + str(size) + '-alias-' + str(d),
                           predicates=directed)
    for form in ('punpkhi_p_p_', 'punpklo_p_p_'):
        for d, n in ((0, 1), (1, 1), (15, 15), (15, 0)):
            fields = d | (n << SOURCE_SHIFT)
            yield case(form, fields, 'dirty-alias-' + str(d))
            yield case(form, fields, 'edge-alias-' + str(d), predicates={n: edge_bits})

    # PMOV selects one packed bit slice from Z, rather than reading one bit at
    # the beginning of each vector element. Exercise every allocated slice.
    for kind, size in (('b', 0), ('h', 1), ('s', 2), ('d', 3)):
        element_bytes = 1 << size
        elements = svl_bytes // element_bytes
        for part in range(element_bytes):
            slice_fields = ((part & SIZE_MASK) << pmov_slice_shift
                            if kind != 'b' else 0)
            if kind == 'd':
                slice_fields |= ((part >> 2) & 1) << SIZE_SHIFT
            for d, n in ((0, 0), (15, 31)):
                fields = d | (n << SOURCE_SHIFT) | slice_fields
                yield case('pmov_p_zi_' + kind, fields,
                           'dirty-slice-' + str(part) + '-source-' + str(n))
            selected_slice = (((1 << elements) - 1) << (elements * part)).to_bytes(svl_bytes, 'little')
            yield case('pmov_p_zi_' + kind, (31 << SOURCE_SHIFT) | 15 | slice_fields,
                       'isolated-slice-' + str(part), vectors={31: selected_slice})

    # PSEL uses W12..W15 plus the encoded immediate, wrapping within the
    # selected element count. High X bits must not affect that W calculation.
    for size in range(SIZE_MASK + 1):
        elements = svl_bytes >> size
        for immediate in range(16 >> size):
            imm5 = (immediate << (size + 1)) | (1 << size)
            size_encoding = imm5 & P_REGISTER_MASK
            selector = (((imm5 >> 4) & 1) << psel_immediate_high_shift
                        | ((size_encoding >> 3) & 1) << psel_size_high_shift
                        | (size_encoding & 7) << psel_size_low_shift)
            for index in range(4):
                fields = selector | (index << RIGHT_SHIFT) | (1 << GOVERNOR_SHIFT) | (2 << SOURCE_SHIFT)
                for label, value in (('first', 0), ('wrap', elements - immediate),
                                     ('word-max', gpr_mask)):
                    # Alternate destination aliases and selector polarity
                    # without reducing immediate/index coverage.
                    destination = (immediate + index) % 3
                    index_register = psel_index_base + index
                    selected = ((value & word_mask) + immediate) % elements
                    yield case('psel_p_ppi_', fields | destination,
                               label + '-size-' + str(size) + '-imm-' + str(immediate) + '-w-' + str(index_register),
                               predicates={2: 1 << (selected << size)},
                               registers={index_register: value})
                yield case('psel_p_ppi_', fields | 2,
                           'inactive-size-' + str(size) + '-imm-' + str(immediate) + '-w-' + str(psel_index_base + index),
                           predicates={2: 0}, registers={psel_index_base + index: 1 << 32})

    # PEXT consumes only the low 16 counter bits. Its counter element shape is
    # independent of the instruction size; mismatched shapes remain defined.
    for form, parts in (('pext_pn_rr_', 4), ('pext_pp_rr_', 2)):
        for size in range(SIZE_MASK + 1):
            for part in range(parts):
                counters = [('zero', 0), ('zero-invert-dirty', COUNTER_INVERT | counter_unused_high_bits)]
                for counter_size in range(SIZE_MASK + 1):
                    group = 1 << counter_size
                    maximum = svl_bytes * 4 // group
                    for count in (0, 1, maximum):
                        for inverted in (False, True):
                            value = ((count << (counter_size + 1)) | group
                                     | (COUNTER_INVERT if inverted else 0))
                            counters.append(('shape-' + str(counter_size) + '-count-' + str(count)
                                             + '-invert-' + str(int(inverted)), value))
                for ordinal, (label, counter) in enumerate(counters):
                    # Include destination/source aliases and wrapping paired
                    # destination P15/P0, with dirty unused predicate bits.
                    destination, source = ((0, 8), (15, 15), (8, 8))[ordinal % 3]
                    original = int.from_bytes(seed.p[source], 'little')
                    low_counter_mask = (1 << (counter_bytes * BYTE_BITS)) - 1
                    value = (original & ~low_counter_mask) | counter
                    fields = (destination | ((source - 8) << SOURCE_SHIFT)
                              | (size << SIZE_SHIFT) | (part << counter_part_shift))
                    yield case(form, fields, label + '-part-' + str(part) + '-size-' + str(size),
                               predicates={source: value})
