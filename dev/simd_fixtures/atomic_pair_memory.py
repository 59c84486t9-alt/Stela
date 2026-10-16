"""CASP words and complete pair-atomic effects in the shared LSE2 RAM profile."""
from collections import Counter
from functools import lru_cache
import random
import struct

from differential import MASK, State
from simd_fixtures import atomic_memory as scalar

ROOT, RAM_ADDRESS, RAM_BYTES, STATE_BYTES = scalar.ROOT, scalar.RAM_ADDRESS, scalar.RAM_BYTES, scalar.STATE_BYTES
ORDERS, ORDER_SUFFIX, SCA_BYTES, RET = scalar.ORDERS, scalar.ORDER_SUFFIX, scalar.SCA_BYTES, scalar.RET
FOCUS = 'atomic_pair_memory'
WIDTHS = (4, 8)
EVEN_REGISTERS = tuple(range(0, 32, 2))
CASP_CLASS = 0x08207c00
CASP_CLASS_MASK = 0xbfa07c00
SIZE_SHIFT, ACQUIRE_SHIFT, RELEASE_SHIFT = 30, 22, 15
COMPARE_SHIFT, BASE_SHIFT = 16, 5
TEMPLATE_START, TEMPLATE_STRIDE = 256, 32
PAIR_SEED = 0xca5f0008
CASE_MODES = ('match', 'low_mismatch', 'high_mismatch')
ADDRESS_ROLES = ('separate', 'compare_low', 'compare_high')


def operation(width=8, order='relaxed', rs=0, rt=2, rn=5):
    if (width not in WIDTHS or order not in ORDERS or rs not in EVEN_REGISTERS or rt not in EVEN_REGISTERS
            or any(type(reg) is not int for reg in (rs, rt, rn)) or not 0 <= rn < 32):
        raise ValueError('CASP requires legal even first registers and W/X elements')
    name = 'casp' + ORDER_SUFFIX[ORDERS.index(order)]
    word = (CASP_CLASS | int(width == 8) << SIZE_SHIFT | int(order in ('acquire', 'acquire_release')) << ACQUIRE_SHIFT
            | int(order in ('release', 'acquire_release')) << RELEASE_SHIFT | rs << COMPARE_SHIFT | rn << BASE_SHIFT | rt)
    return {'kind': FOCUS, 'layout': 'casp', 'operation': 'casp', 'name': name,
            'canonical_id': f'{name.upper()}_CP{width * 8}_comswappr', 'word': word,
            'element_bytes': width, 'total_bytes': width * 2, 'rs': rs, 'rt': rt, 'rn': rn,
            'compare': [rs, rs + 1], 'source': [rt, rt + 1], 'order': order,
            'mode': 'offset', 'offset': 0, 'loading': True,
            'written_gprs': [register for register in (rs, rs + 1) if register != 31], 'written_vectors': []}


def shapes():
    return [operation(width, order) for width in WIDTHS for order in ORDERS]


CANONICAL_FORMS = tuple(sorted(op['canonical_id'] for op in shapes()))


def supported_on_profile(op, target):
    return op['total_bytes'] == 8 or 'cx16' in target.split('+')[1:]


def functions():
    result, seen = [], set()
    def append(op):
        if op['word'] not in seen:
            seen.add(op['word'])
            result.append(op)
    for shape in shapes():
        width, order = shape['element_bytes'], shape['order']
        append(shape)
        for rs in EVEN_REGISTERS:
            for rt in EVEN_REGISTERS:
                append(operation(width, order, rs, rt))
            for rt in (rs, (rs + 2) % 32):
                for rn in (rs, rs + 1, rt, rt + 1, 31):
                    append(operation(width, order, rs, rt, rn))
        for rn in range(32):
            append(operation(width, order, 0, 2, rn))
            append(operation(width, order, 30, 30, rn))
    return result


def address_role(op):
    if op['rn'] == op['rs']:
        return 'compare_low'
    if op['rn'] != 31 and op['rn'] == op['rs'] + 1:
        return 'compare_high'
    return 'separate'


@lru_cache(maxsize=1)
def template_positions():
    result = {}
    for width in WIDTHS:
        for mode in CASE_MODES:
            for role in ADDRESS_ROLES:
                for zero_high in (False, True):
                    for offset in range(SCA_BYTES - width * 2 + 1):
                        result[width, mode, role, zero_high, offset] = TEMPLATE_START + len(result) * TEMPLATE_STRIDE + offset
    return result


def compare_values(width, role, zero_high, position):
    mask = (1 << (width * 8)) - 1
    low, high = 0x8877665544332211 & mask, 0x1020304050607080 & mask
    if role == 'compare_low': low = (RAM_ADDRESS + position) & mask
    if role == 'compare_high': high = (RAM_ADDRESS + position) & mask
    return low, 0 if zero_high else high


def case_position(op, mode, offset=0):
    return template_positions()[op['element_bytes'], mode, address_role(op), op['rs'] == 30, offset]


def edge_positions(width):
    start = TEMPLATE_START + len(template_positions()) * TEMPLATE_STRIDE
    return [start + (WIDTHS.index(width) * 9 + index) * TEMPLATE_STRIDE for index in range(9)]


@lru_cache(maxsize=1)
def memory_template():
    memory = bytearray(random.Random(PAIR_SEED).randbytes(RAM_BYTES))
    for (width, mode, role, zero_high, _), position in template_positions().items():
        values = list(compare_values(width, role, zero_high, position))
        if mode != 'match': values[CASE_MODES.index(mode) - 1] ^= 1
        memory[position:position + width * 2] = b''.join(value.to_bytes(width, 'little') for value in values)
    for width in WIDTHS:
        edges = scalar.edge_values(width)
        for index, position in enumerate(edge_positions(width)):
            values = edges[index], edges[(index * 3 + 1) % len(edges)]
            memory[position:position + width * 2] = b''.join(value.to_bytes(width, 'little') for value in values)
    if edge_positions(WIDTHS[-1])[-1] + WIDTHS[-1] * 2 > len(memory):
        raise AssertionError('CASP template exceeds owned RAM')
    return bytes(memory)


def initial_state(op, seed, position, operand=None, compare=None, ram_address=RAM_ADDRESS):
    state = State.from_buffer_copy(random.Random(PAIR_SEED + seed).randbytes(STATE_BYTES))
    state.nzcv = (seed & 15) << 28
    state.fpcr, state.fpsr = (0x03c00000, 0x0800001f)
    width, mask = op['element_bytes'], (1 << (8 * op['element_bytes'])) - 1
    old = tuple(int.from_bytes(memory_template()[position + half * width:position + (half + 1) * width], 'little') for half in range(2))
    comparisons = old if compare is None else (compare, compare) if isinstance(compare, int) else compare
    replacements = (0xfedcba9876543210, 0x0123456789abcdef) if operand is None else (operand, operand) if isinstance(operand, int) else operand
    staged = [(op['compare'], comparisons)]
    if op['source'] != op['compare']: staged.append((op['source'], replacements))
    for registers, values in staged:
        for register, value in zip(registers, values):
            if register != 31:
                state.x[register] = (value & mask) | (0xa5c3e17b << 32 if width == 4 else 0)
    state.sp = ram_address + 512
    if op['rn'] == 31:
        if position % 16: raise ValueError('CASP success SP must be aligned16')
        state.sp = ram_address + position
    else:
        state.x[op['rn']] = ram_address + position
    return state


def expected(op, initial, memory, ram_address=RAM_ADDRESS, accessible=None, readonly=False, policy='source'):
    if policy != 'source': raise ValueError('CASP requires explicit source profile')
    state, ram = State.from_buffer_copy(initial), bytearray(memory)
    width, total = op['element_bytes'], op['total_bytes']
    address = initial.sp if op['rn'] == 31 else initial.x[op['rn']]
    if op['rn'] == 31 and address % 16:
        return state, bytes(ram), {'kind': 'sp_alignment', 'address': address}
    if address % SCA_BYTES + total > SCA_BYTES:
        return state, bytes(ram), {'kind': 'sca_alignment', 'address': address}
    position, limit = address - ram_address, len(ram) if accessible is None else accessible
    if not 0 <= limit <= len(ram): raise ValueError('Invalid CASP RAM bound')
    if readonly or position < 0 or position + total > limit:
        return state, bytes(ram), {'kind': 'memory', 'address': address if readonly or position < 0 else ram_address + max(position, limit)}
    mask = (1 << (width * 8)) - 1
    read_pair = lambda registers: tuple(0 if register == 31 else initial.x[register] & mask for register in registers)
    compare, replacement = read_pair(op['compare']), read_pair(op['source'])
    old = tuple(int.from_bytes(ram[position + half * width:position + (half + 1) * width], 'little') for half in range(2))
    if compare == old:
        ram[position:position + total] = b''.join(value.to_bytes(width, 'little') for value in replacement)
    for register, value in zip(op['compare'], old):
        if register != 31: state.x[register] = value
    return state, bytes(ram), None


@lru_cache(maxsize=1)
def corpus():
    operations, cases, runtime_forms = functions(), [], set()
    for function, op in enumerate(operations):
        for mode in CASE_MODES:
            position = case_position(op, mode)
            values = compare_values(op['element_bytes'], address_role(op), op['rs'] == 30, position)
            initial = initial_state(op, len(cases), position, compare=values)
            runtime = op['canonical_id'] not in runtime_forms and 30 not in op['written_gprs'] and op['rn'] != 30
            if runtime: runtime_forms.add(op['canonical_id'])
            cases.append({'function': function, 'position': position, 'alignment': position % 16,
                          'path': 'same_granule', 'runtime': runtime, 'compare_mode': mode,
                          'compare_matches': mode == 'match', 'initial': bytes(initial)})
        if op in shapes():
            for index, position in enumerate(edge_positions(op['element_bytes'])):
                initial = initial_state(op, len(cases), position, operand=scalar.edge_values(op['element_bytes'])[index])
                cases.append({'function': function, 'position': position, 'alignment': 0, 'path': 'same_granule',
                              'runtime': False, 'compare_mode': 'match', 'compare_matches': True, 'initial': bytes(initial)})
            for seed in range(16):
                position = case_position(op, 'match', seed % (SCA_BYTES - op['total_bytes'] + 1))
                values = compare_values(op['element_bytes'], address_role(op), False, position)
                initial = initial_state(op, seed, position, compare=values, operand=values)
                cases.append({'function': function, 'position': position, 'alignment': position % 16, 'path': 'same_granule',
                              'runtime': False, 'compare_mode': 'match', 'compare_matches': True, 'initial': bytes(initial)})
    return operations, cases


def validate_source_words(source, functions, allowed_mnemonics):
    import a64_checklist
    import json
    result = scalar.validate_source_words(source, functions, set(allowed_mnemonics) | {op['name'] for op in shapes()})
    facts = a64_checklist.validate(json.loads((ROOT / 'isa/a64-documented-checklist.json').read_bytes()))
    for function in functions:
        for op in function['operations']:
            if op.get('kind') == 'atomic_litmus_transfer':
                if op != scalar.ordinary_transfer(op['loading'], op['rt'], op['rn']):
                    raise AssertionError('CASP mixed ordinary source metadata differs')
            if op.get('kind') != FOCUS: continue
            if operation(op['element_bytes'], op['order'], op['rs'], op['rt'], op['rn']) != op:
                raise AssertionError('CASP source metadata differs from exact allocated word')
            fact = facts[op['canonical_id']]
            if op['word'] & int(fact['encoding_mask'], 16) != int(fact['encoding_value'], 16):
                raise AssertionError('CASP word differs from pinned source facts')
    return result


def fault_operation(shape, case):
    return operation(shape['element_bytes'], shape['order'], case.get('rs', shape['rs']), case.get('rt', shape['rt']), case['rn'])


def fault_initial_state(op, case, seed):
    old = int.from_bytes(b'\xa5' * op['element_bytes'], 'little')
    compare = [old, old]
    if not case.get('compare_matches'):
        compare[case.get('compare_half_mismatch', 0)] ^= 1
    return initial_state(op, seed, 512, operand=0, compare=compare)


def fault_selection(first_access_only=False):
    result = []
    for function, op in enumerate(shapes()):
        def append(protection, rn=5, **values):
            result.append({'function': function, 'rn': rn, 'protection': protection, 'cut': 0, **values})
        for protection, rn in (('guard', 5), ('guard', 31), ('sp_alignment', 31), ('sp_alignment8', 31)):
            append(protection, rn)
        for mode in ('match', 'low_mismatch', 'high_mismatch'):
            append('readonly', compare_matches=mode == 'match', compare_half_mismatch=0 if mode == 'low_mismatch' else 1)
        for offset in range(SCA_BYTES):
            append('mapped', low_offset=offset)
            append('guard', address_offset=offset)
        for cut in range(1, op['total_bytes'] + 1): append('structure_crossing', cut=cut)
        append('readonly', rs=30, rt=30)
        append('guard', rs=30, rt=30)
    return result


def fault_cases():
    return fault_selection()


def declined_encodings():
    result = []
    for op in shapes():
        for register in range(1, 32, 2):
            for field in ('rs', 'rt'):
                shift = COMPARE_SHIFT if field == 'rs' else 0
                word = op['word'] & ~(31 << shift) | register << shift
                result.append({'reason': 'odd_' + field + '_first_register', 'word': word})
        if op['total_bytes'] == 16:
            result.append({'reason': 'Cx16_host_capability', 'word': op['word'], 'canonical_id': op['canonical_id']})
    return result


def inventory():
    operations, cases = corpus()
    return {'canonical_forms': len(CANONICAL_FORMS), 'shape_index_arrangements': dict(Counter(op['layout'] for op in shapes())),
            'functions': len(operations), 'success_cases': len(cases), 'fault_cases': len(fault_cases()),
            'ram_bytes': RAM_BYTES, 'state_bytes': STATE_BYTES, 'profile': 'EL0_Normal_WB_LSE2_A0_nAA0_SCA16'}


def history_expected(op, initial, memory, ram_address=RAM_ADDRESS):
    if op['kind'] == FOCUS:
        return expected(op, initial, memory, ram_address)
    if op['kind'] == scalar.FOCUS:
        return scalar.expected(op, initial, memory, ram_address)
    if op != scalar.ordinary_transfer(op['loading'], op['rt'], op['rn']):
        raise AssertionError('CASP history includes an unreviewed ordinary operation')
    state, ram = State.from_buffer_copy(initial), bytearray(memory)
    address = initial.sp if op['rn'] == 31 else initial.x[op['rn']]
    position = address - ram_address
    if address % 8 or not 0 <= position <= len(ram) - 8:
        raise AssertionError('CASP mixed ordinary history must be aligned owned X64 RAM')
    if op['loading']:
        if op['rt'] != 31: state.x[op['rt']] = int.from_bytes(ram[position:position + 8], 'little')
    else:
        ram[position:position + 8] = (0 if op['rt'] == 31 else initial.x[op['rt']]).to_bytes(8, 'little')
    return state, bytes(ram), None


def original_concurrency_cases():
    """Eight overlapping atomic pairs: one complete operation per PE/trial."""
    result = []
    for width in WIDTHS:
        mask = (1 << (width * 8)) - 1
        label = 'W' if width == 4 else 'X'
        memory = bytearray(RAM_BYTES)
        memory[width:width * 2] = mask.to_bytes(width, 'little')
        for kind in ('counter', 'hint', 'mixed_cas', 'mixed_swp'):
            programs = [[operation(width, 'acquire_release')], [operation(width, 'acquire_release')]]
            if kind == 'hint': programs = [[operation(width, rs=0, rt=0)] for _ in range(2)]
            if kind == 'mixed_cas': programs[1] = [scalar.operation('cas', width, 'acquire_release', rs=0, rt=2, rn=5)]
            if kind == 'mixed_swp': programs[1] = [scalar.operation('swap', width, rs=0, rt=1, rn=5)]
            states = []
            for thread in range(2):
                state = State.from_buffer_copy(random.Random(PAIR_SEED + len(result) * 2 + thread).randbytes(STATE_BYTES))
                state.nzcv, state.fpcr, state.fpsr = thread << 28, 0x03c00000, 0x0800001f
                state.x[0], state.x[1], state.x[2], state.x[3] = 0, mask, thread + 1, mask ^ (thread + 1)
                if kind == 'mixed_cas' and thread == 1: state.x[2] = 3
                if kind == 'mixed_swp' and thread == 1: state.x[0] = 3
                state.x[5], state.x[6] = 0, 64
                states.append(bytes(state))
            result.append({'id': f'casp_{kind}_{label}', 'kind': 0, 'width': width * 2, 'threads': 2,
                'iterations': 4, 'alias': False, 'programs': programs, 'initial': states,
                'memory': bytes(memory), 'allowed_outcomes': None})
    return result


def concurrency_cases():
    result = []
    for case in original_concurrency_cases():
        result += [case, {**case, 'id': case['id'] + '_alias', 'alias': True}]
    for width in WIDTHS:
        case = next(case for case in original_concurrency_cases() if case['id'] == ('casp_counter_W' if width == 4 else 'casp_counter_X'))
        initial = State.from_buffer_copy(case['initial'][1])
        initial.x[0] = 0x8877665544332211
        result.append({**case, 'id': f'casp_mixed_store_{width * 8}', 'programs': [case['programs'][0], [scalar.ordinary_transfer(False, 0, 5)]],
                       'initial': [case['initial'][0], bytes(initial)]})
        result.append({**result[-1], 'id': result[-1]['id'] + '_alias', 'alias': True})
    return result


def concurrency_plan(case, offsets):
    if case['kind'] != 0 or case['width'] not in (8, 16):
        raise ValueError('CASP concurrency requires bounded kind0 byte histories')
    return scalar.concurrency_plan(case, offsets)


def linearization_allowed(history, initial_ram, ram_address=RAM_ADDRESS, final_ram=None):
    """CASP/scalar/ordinary effects share one bounded byte-history solver."""
    from simd_fixtures.memory_history import linearization_allowed as solve
    return solve(history, initial_ram, ram_address, final_ram, expected_operation=history_expected,
                 effective_address=lambda op, state: state.sp if op['rn'] == 31 else state.x[op['rn']])
