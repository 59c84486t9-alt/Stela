"""Ordinary private-RAM words and independent full-state/byte-memory model.

Encoders follow pinned architectural fields. The model uses mathematical byte
ranges, not compiler helpers. Interrupted source and Unicorn policies remain
separate; no emulator fault observation is a hardware exception claim.
"""
from collections import Counter
import random
import struct

from differential import MASK, State
from simd_fixtures.structure_memory import RAM_ADDRESS, RAM_BYTES, STATE_BYTES, memory_template

FOCUS = 'ordinary_memory'
UNPRIVILEGED = (
    ('STTRB_32_ldst_unpriv', 'sttrb', 1, 0, 0x38000800),
    ('STTRH_32_ldst_unpriv', 'sttrh', 2, 0, 0x78000800),
    ('STTR_32_ldst_unpriv', 'sttr', 4, 0, 0xb8000800),
    ('STTR_64_ldst_unpriv', 'sttr', 8, 0, 0xf8000800),
    ('LDTRB_32_ldst_unpriv', 'ldtrb', 1, 32, 0x38400800),
    ('LDTRH_32_ldst_unpriv', 'ldtrh', 2, 32, 0x78400800),
    ('LDTR_32_ldst_unpriv', 'ldtr', 4, 32, 0xb8400800),
    ('LDTR_64_ldst_unpriv', 'ldtr', 8, 64, 0xf8400800),
    ('LDTRSB_32_ldst_unpriv', 'ldtrsb', 1, 32, 0x38c00800),
    ('LDTRSB_64_ldst_unpriv', 'ldtrsb', 1, 64, 0x38800800),
    ('LDTRSH_32_ldst_unpriv', 'ldtrsh', 2, 32, 0x78c00800),
    ('LDTRSH_64_ldst_unpriv', 'ldtrsh', 2, 64, 0x78800800),
    ('LDTRSW_64_ldst_unpriv', 'ldtrsw', 4, 64, 0xb8800800),
)
PAIR_WIDTHS = ((4, False, '32', 0x28000000), (8, False, '64', 0xa8000000),
               (4, True, 'S', 0x2c000000), (8, True, 'D', 0x6c000000),
               (16, True, 'Q', 0xac000000))
PREFETCH_FORMS = {'immediate': ('PRFM_P_ldst_pos', 0xf9800000),
                  'register': ('PRFM_P_ldst_regoff', 0xf8a00800),
                  'literal': ('PRFM_P_loadlit', 0xd8000000),
                  'unscaled': ('PRFUM_P_ldst_unscaled', 0xf8800000)}


def registers(*values):
    if any(not isinstance(value, int) or not 0 <= value < 32 for value in values):
        raise ValueError('Invalid ordinary-memory register')


def unprivileged(canonical_id, rt=1, rn=5, offset=0):
    registers(rt, rn)
    if not -256 <= offset <= 255:
        raise ValueError('Unprivileged imm9 outside signed range')
    matches = [row for row in UNPRIVILEGED if row[0] == canonical_id]
    if len(matches) != 1:
        raise ValueError('Unknown unprivileged canonical form')
    _, name, width, output_bits, fixed = matches[0]
    loading = bool(output_bits)
    return {'kind': FOCUS, 'layout': 'unprivileged', 'canonical_id': canonical_id,
            'name': name, 'word': fixed | ((offset & 511) << 12) | rn << 5 | rt,
            'rt': rt, 'rn': rn, 'offset': offset, 'mode': 'offset', 'loading': loading,
            'element_bytes': width, 'total_bytes': width, 'output_bits': output_bits,
            'signed': name in ('ldtrsb', 'ldtrsh', 'ldtrsw'), 'vector': False,
            'written_gprs': [rt] if loading and rt != 31 else [], 'written_vectors': []}


def pair(width=8, loading=True, vector=False, rt=1, rt2=2, rn=5, offset=0):
    registers(rt, rt2, rn)
    matches = [row for row in PAIR_WIDTHS if row[:2] == (width, vector)]
    if len(matches) != 1 or offset % width or not -64 <= offset // width <= 63:
        raise ValueError('Invalid non-temporal pair width/scaled imm7')
    if loading and rt == rt2:
        raise ValueError('Duplicate load destination belongs to the selected-policy cohort')
    _, _, letter, fixed = matches[0]
    name = 'ldnp' if loading else 'stnp'
    destinations = [rt, rt2] if loading else []
    return {'kind': FOCUS, 'layout': 'pair', 'canonical_id': f'{name.upper()}_{letter}_ldstnapair_offs',
            'name': name, 'word': fixed | int(loading) << 22 | ((offset // width & 127) << 15) | rt2 << 10 | rn << 5 | rt,
            'rt': rt, 'rt2': rt2, 'rn': rn, 'offset': offset, 'mode': 'offset', 'loading': loading,
            'element_bytes': width, 'total_bytes': 2 * width, 'vector': vector,
            'written_gprs': [reg for reg in destinations if reg != 31] if not vector else [],
            'written_vectors': destinations if vector else []}


def prefetch(mode='immediate', hint=0, rn=5, rm=6, option=3, shift=False, offset=0):
    registers(hint, rn, rm)
    if mode not in PREFETCH_FORMS:
        raise ValueError('Unknown prefetch addressing form')
    canonical, word = PREFETCH_FORMS[mode]
    if mode == 'immediate':
        if offset % 8 or not 0 <= offset // 8 <= 4095:
            raise ValueError('Invalid prefetch scaled imm12')
        word |= (offset // 8) << 10 | rn << 5
    elif mode == 'unscaled':
        if not -256 <= offset <= 255:
            raise ValueError('Invalid prefetch signed imm9')
        word |= (offset & 511) << 12 | rn << 5
    elif mode == 'literal':
        if offset % 4 or not -(1 << 18) <= offset // 4 < 1 << 18:
            raise ValueError('Invalid prefetch signed imm19')
        word |= (offset // 4 & 0x7ffff) << 5
    else:
        if option not in (2, 3, 6, 7) or hint >= 24 or offset:
            raise ValueError('Reserved prefetch register option or neighboring RPRFM')
        word |= rm << 16 | option << 13 | int(shift) << 12 | rn << 5
    return {'kind': FOCUS, 'layout': 'prefetch', 'canonical_id': canonical,
            'name': 'prfum' if mode == 'unscaled' else 'prfm', 'word': word | hint,
            'hint': hint, 'rn': rn, 'rm': rm, 'option': option, 'shift': bool(shift),
            'offset': offset, 'mode': mode, 'loading': False, 'element_bytes': 0,
            'total_bytes': 0, 'written_gprs': [], 'written_vectors': []}


def shapes():
    return ([unprivileged(row[0]) for row in UNPRIVILEGED]
            + [pair(width, loading, vector) for width, vector, _, _ in PAIR_WIDTHS for loading in (False, True)]
            + [prefetch(mode) for mode in PREFETCH_FORMS])


CANONICAL_FORMS = tuple(sorted(op['canonical_id'] for op in shapes()))
CONSTRAINED_LOAD_FORMS = tuple(canonical for canonical in CANONICAL_FORMS if canonical.startswith('LDNP_'))


def functions():
    result, seen = [], set()
    def append(op):
        if op['word'] not in seen:
            seen.add(op['word'])
            result.append(op)
    for op in shapes():
        append(op)
        if op['layout'] == 'unprivileged':
            for offset in (-256, -1, 1, 255):
                append(unprivileged(op['canonical_id'], offset=offset))
            for register in range(32):
                for rt, rn in ((register, 5), (1, register), (register, register)):
                    append(unprivileged(op['canonical_id'], rt, rn))
        elif op['layout'] == 'pair':
            width, vector, loading = op['element_bytes'], op['vector'], op['loading']
            for offset in (-64 * width, -width, width, 63 * width):
                append(pair(width, loading, vector, offset=offset))
            for register in range(32):
                for rt, rt2, rn in ((register, (register + 1) % 32, 5),
                                     ((register + 1) % 32, register, 5),
                                     (1, 2, register), (register, (register + 1) % 32, register)):
                    append(pair(width, loading, vector, rt, rt2, rn))
                if not loading:
                    append(pair(width, False, vector, register, register))
        else:
            mode = op['mode']
            for hint in range(24 if mode == 'register' else 32):
                append(prefetch(mode, hint))
            for register in range(32):
                append(prefetch(mode, rn=register))
                if mode == 'register':
                    append(prefetch(mode, rm=register))
                    append(prefetch(mode, rn=register, rm=register))
            if mode == 'register':
                for option in (2, 3, 6, 7):
                    for shift in (False, True):
                        for hint in (0, 1, 2, 4, 16, 17, 18, 20):
                            append(prefetch(mode, hint, option=option, shift=shift))
            else:
                offsets = {'immediate': (8, 32760), 'unscaled': (-256, -1, 1, 255),
                           'literal': (-(1 << 20), -4, 4, (1 << 20) - 4)}[mode]
                for offset in offsets:
                    append(prefetch(mode, offset=offset))
    return result


CAPSTONE_ALIAS_GAPS = frozenset(('LDTRB_32_ldst_unpriv', 'LDTRH_32_ldst_unpriv',
    'LDTR_32_ldst_unpriv', 'LDTR_64_ldst_unpriv', 'LDTRSB_32_ldst_unpriv', 'LDTRSH_32_ldst_unpriv'))


def validate_source_words(source, functions, allowed_mnemonics, catalog=None):
    """Bound only the installed decoder's six legal LDTR base/destination gaps."""
    import json
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    import a64_checklist
    from differential import ROOT
    if catalog is None:
        catalog = json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
    a64_checklist.validate(catalog)
    facts = {row['id']: row for row in catalog['forms']}
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    operations = [op for function in functions for op in [*function['operations'], {'kind': 'return', 'word': 0xd65f03c0}]]
    if source != b''.join(struct.pack('<I', op['word']) for op in operations):
        raise AssertionError('Ordinary source words differ from exact fixture operations')
    fallback = []
    for index, op in enumerate(operations):
        word = op['word']
        decoded = list(decoder.disasm(struct.pack('<I', word), index * 4))
        if len(decoded) == 1:
            if decoded[0].mnemonic not in set(allowed_mnemonics) | {'ret'}:
                raise AssertionError('Independent decoder mnemonic differs for ordinary fixture')
            if op['kind'] == FOCUS and decoded[0].mnemonic != op['name']:
                raise AssertionError('Ordinary operation name differs from independent decoder')
            continue
        if (op.get('kind') != FOCUS or op.get('canonical_id') not in CAPSTONE_ALIAS_GAPS
                or op.get('layout') != 'unprivileged' or not op.get('loading')
                or op.get('rn') != op.get('rt') or not 0 <= op['rt'] < 31):
            raise AssertionError('Independent decoder declined an input outside the pinned LDTR alias gap')
        expected_op = unprivileged(op['canonical_id'], op['rt'], op['rn'], op['offset'])
        fact = facts[op['canonical_id']]
        if (op != expected_op or fact['mnemonic'].lower() != op['name']
                or word & int(fact['encoding_mask'], 0) != int(fact['encoding_value'], 0)):
            raise AssertionError('Pinned LDTR alias fallback word/metadata/fixed bits differ')
        fallback.append({'word_index': index, 'word': word, 'canonical_id': op['canonical_id']})
    return {'capstone_decode_fallback_words': len(fallback), 'fallbacks': fallback,
            'pinned_facts_sha256': a64_checklist.FACTS_SHA,
            'limits': 'Installed Capstone declines legal Rn=Rt!=31 loads for six LDTR forms. Only those exact fixture words use hash-validated pinned Arm fixed bits; all other words, including RET/prefix, require independent Capstone decoding.'}

def initial_state(op, seed, position, ram_address=RAM_ADDRESS):
    rng = random.Random(0x57e1a027 + seed)
    state = State.from_buffer_copy(rng.randbytes(STATE_BYTES))
    state.nzcv = (seed & 15) << 28
    state.fpcr = (0, 0x07ff2007, 0x00c09f00, 0x00400000)[seed % 4]
    state.fpsr = (0, 0x0800009f, 0xf800009f, 0x00000010)[seed % 4]
    state.sp = ram_address + 512
    base = ram_address + position - op['offset']
    if op['rn'] == 31:
        if op['layout'] != 'prefetch' and base % 16:
            raise ValueError('Success input requires aligned incoming SP')
        state.sp = base
    else:
        state.x[op['rn']] = base & MASK
    return state


def corpus():
    ops, cases, runtime_forms = functions(), [], set()
    representatives = {op['word'] for op in shapes()}
    for function, op in enumerate(ops):
        positions = [512]
        if op['word'] in representatives and op['layout'] != 'prefetch':
            positions = list(range(512, 520))
            if op['total_bytes'] > 1:
                positions.append(4096 - op['total_bytes'] // 2)
        if op['rn'] == 31 and op['layout'] != 'prefetch':
            positions = [512 + op['offset'] % 16]
        for position in positions:
            initial = initial_state(op, len(cases), position)
            runtime = op['canonical_id'] not in runtime_forms
            runtime_forms.add(op['canonical_id'])
            end = position + max(1, op['total_bytes']) - 1
            cases.append({'function': function, 'position': position, 'alignment': position % 8,
                          'path': 'crossing' if position // 4096 != end // 4096 else 'same_granule',
                          'runtime': runtime, 'initial': bytes(initial)})
    return ops, cases


def expected(op, initial, memory, ram_address=RAM_ADDRESS, accessible=None, readonly=False, policy='source'):
    """Exact byte footprint, staged loads and ascending store prefix.

    Unicorn pair vector loads commit the first element before a second-element
    fault. Unicorn crossing stores retain the same ascending byte prefix as source.
    These predictions are checked against retained original raw frames.
    """
    if policy not in ('source', 'unicorn'):
        raise ValueError('Unknown interrupted ordinary-memory policy')
    state, ram = State.from_buffer_copy(initial), bytearray(memory)
    limit = len(ram) if accessible is None else accessible
    if not 0 <= limit <= len(ram):
        raise ValueError('Accessible RAM bound differs')
    if op['layout'] == 'prefetch':
        return state, bytes(ram), None
    base = initial.sp if op['rn'] == 31 else initial.x[op['rn']]
    if op['rn'] == 31 and base % 16:
        return state, bytes(ram), {'kind': 'sp_alignment', 'address': base}
    address = (base + op['offset']) & MASK
    width, staged = op['element_bytes'], []
    destinations = [op['rt']] + ([op['rt2']] if op['layout'] == 'pair' else [])
    for ordinal, register in enumerate(destinations):
        element_address = (address + ordinal * width) & MASK
        position = element_address - ram_address
        valid = not readonly or op['loading']
        if not valid or not 0 <= position or position + width > limit:
            if not op['loading'] and valid and 0 <= position < limit:
                value = bytes(initial.v[register]) if op.get('vector') else (0 if register == 31 else initial.x[register]).to_bytes(8, 'little')
                count = min(width, limit - position)
                ram[position:position + count] = value[:count]
            fault_address = ram_address + max(position, limit) if valid and position >= 0 else element_address
            return state, bytes(ram), {'kind': 'memory', 'address': fault_address,
                                      'ordinal': ordinal, 'element_bytes': width, 'element_address': element_address}
        if op['loading']:
            value = int.from_bytes(ram[position:position + width], 'little', signed=op.get('signed', False))
            if op.get('vector'):
                staged.append((register, value))
                if policy == 'unicorn':
                    state.v[register][:] = [value & MASK, value >> 64]
            elif register != 31:
                bits = op.get('output_bits', width * 8)
                staged.append((register, value & ((1 << bits) - 1)))
        else:
            value = bytes(initial.v[register]) if op.get('vector') else (0 if register == 31 else initial.x[register]).to_bytes(8, 'little')
            ram[position:position + width] = value[:width]
    for register, value in staged:
        if op.get('vector'):
            state.v[register][:] = [value & MASK, value >> 64]
        else:
            state.x[register] = value
    return state, bytes(ram), None


def fault_operation(shape, case):
    rn, offset = case['rn'], case.get('offset', shape['offset'])
    if shape['layout'] == 'unprivileged':
        return unprivileged(shape['canonical_id'], case.get('rt', shape['rt']), rn, offset)
    if shape['layout'] == 'pair':
        return pair(shape['element_bytes'], shape['loading'], shape['vector'],
                    case.get('rt', shape['rt']), case.get('rt2', shape['rt2']), rn, offset)
    return prefetch(shape['mode'], case.get('hint', shape['hint']), rn=rn)


def fault_selection(first_access_only=False):
    selected = []
    for function, op in enumerate(shapes()):
        def append(protection, cut=0, rn=5, **values):
            selected.append({'function': function, 'rn': rn, 'cut': cut, 'protection': protection, **values})
        append('guard')
        if op['layout'] == 'prefetch':
            append('readonly')
            append('sp_alignment', rn=31)
            append('sp_alignment8', rn=31)
            continue
        for rn in (5, 31):
            append('guard', rn=rn, offset=16)
        for protection in ('sp_alignment', 'sp_alignment8'):
            append(protection, rn=31, offset=-1 if op['layout'] == 'unprivileged' else -op['element_bytes'])
        if not op['loading']:
            append('readonly')
        if not first_access_only:
            for cut in range(1, op['total_bytes']):
                append('structure_crossing', cut)
        if op['layout'] == 'unprivileged':
            append('guard', rt=31)
        elif not op.get('vector'):
            append('guard', rt=31)
            append('guard', rt2=31)
        if op['layout'] == 'pair' and not op['loading']:
            append('structure_crossing', op['element_bytes'], rt=31, rt2=31)
    return selected


def fault_cases():
    return fault_selection()


def constrained_load_encodings():
    """Exact allocated overlaps for the separate selected-NOP policy proof."""
    result = []
    for width, vector, _, _ in PAIR_WIDTHS:
        for register in range(32):
            op = pair(width, True, vector, register, (register + 1) % 32)
            result.append({'constraint': 'Unpredictable_LDPOVERLAP',
                           'selected_choice': 'source_permitted_selected_nop', 'canonical_id': op['canonical_id'],
                           'word': op['word'] & ~(31 << 10) | register << 10})
    return result


def declined_encodings():
    return []


def inventory():
    ops, cases = corpus()
    return {'canonical_forms': len(CANONICAL_FORMS), 'fully_implemented_forms': len(CANONICAL_FORMS),
            'constrained_operand_cohort': {'forms': list(CONSTRAINED_LOAD_FORMS),
                'inputs': len(constrained_load_encodings()), 'selected_choice': 'source_permitted_selected_nop',
                'equality_basis': 'Separate source-permitted policy proof; not direct original equality.'},
            'shape_index_arrangements': dict(Counter(op['layout'] for op in shapes())),
            'functions': len(ops), 'success_cases': len(cases), 'fault_cases': len(fault_cases()),
            'ram_bytes': RAM_BYTES, 'state_bytes': STATE_BYTES}
