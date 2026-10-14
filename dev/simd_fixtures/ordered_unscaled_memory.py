"""Unscaled RCpc acquire/release words and independent full-state RAM model.

The pinned June 2026 integer forms use signed, unscaled imm9. The declared
Normal-WB profile has A=0, nAA=0, LSE2 and a 16-byte SCA granule. Source faults
and raw original observations are separate; this model invents no oracle policy.
"""
from collections import Counter
from functools import lru_cache
import json
import random
import struct

from differential import MASK, ROOT, State
from simd_fixtures import atomic_memory as scalar

FOCUS = 'ordered_unscaled_memory'
RAM_ADDRESS, RAM_BYTES, STATE_BYTES = scalar.RAM_ADDRESS, scalar.RAM_BYTES, scalar.STATE_BYTES
SCA_BYTES, RET = scalar.SCA_BYTES, scalar.RET
SP_ALIGNMENT_BYTES = 16
BASELINE_ATOMIC_BYTES = 8
CROSS8_TEMPLATE_BASE = 3072
CROSS8_TEMPLATE_WIDTH_STRIDE = 64
FIXTURE_SEED = 0x1da90013
FPCR_CASES = (0, 0x07ff2007, 0x00c09f00, 0x00400000)
FPSR_CASES = (0, 0x0800009f, 0xf800009f, 0x00000010)
HISTORY_THREADS = 2
HISTORY_CALLS_PER_THREAD = 4
HISTORY_WINDOW_BASE = 64
HISTORY_DISPLACEMENT = 17
FORM_MASK = 0xffe00c00
CLASS_MASK, CLASS_VALUE = 0x3f200c00, 0x19000000
OFFSET_BITS, OFFSET_SHIFT, REGISTER_BITS = 9, 12, 5
OFFSET_MASK = (1 << OFFSET_BITS) - 1
BASE_SHIFT = REGISTER_BITS
EDGE_OFFSETS = (-256, -255, -129, -128, -17, -16, -9, -8, -1,
                0, 1, 7, 8, 15, 16, 127, 128, 254, 255)
FORMS = (
    ('LDAPURB_32_ldapstl_unscaled', 'ldapurb', 1, 32, False, 0x19400000),
    ('LDAPURH_32_ldapstl_unscaled', 'ldapurh', 2, 32, False, 0x59400000),
    ('LDAPUR_32_ldapstl_unscaled', 'ldapur', 4, 32, False, 0x99400000),
    ('LDAPUR_64_ldapstl_unscaled', 'ldapur', 8, 64, False, 0xd9400000),
    ('LDAPURSB_32_ldapstl_unscaled', 'ldapursb', 1, 32, True, 0x19c00000),
    ('LDAPURSB_64_ldapstl_unscaled', 'ldapursb', 1, 64, True, 0x19800000),
    ('LDAPURSH_32_ldapstl_unscaled', 'ldapursh', 2, 32, True, 0x59c00000),
    ('LDAPURSH_64_ldapstl_unscaled', 'ldapursh', 2, 64, True, 0x59800000),
    ('LDAPURSW_64_ldapstl_unscaled', 'ldapursw', 4, 64, True, 0x99800000),
    ('STLURB_32_ldapstl_unscaled', 'stlurb', 1, 0, False, 0x19000000),
    ('STLURH_32_ldapstl_unscaled', 'stlurh', 2, 0, False, 0x59000000),
    ('STLUR_32_ldapstl_unscaled', 'stlur', 4, 0, False, 0x99000000),
    ('STLUR_64_ldapstl_unscaled', 'stlur', 8, 0, False, 0xd9000000),
)
CANONICAL_FORMS = tuple(sorted(row[0] for row in FORMS))
FORM_BY_ID = {row[0]: row for row in FORMS}


def operation(canonical_id='LDAPUR_64_ldapstl_unscaled', rt=1, rn=5, offset=0):
    if (canonical_id not in FORM_BY_ID or type(offset) is not int or not -256 <= offset <= 255
            or any(type(reg) is not int or not 0 <= reg < 32 for reg in (rt, rn))):
        raise ValueError('Invalid unscaled ordered form/register/signed imm9')
    _, name, width, output_bits, signed, fixed = FORM_BY_ID[canonical_id]
    loading = bool(output_bits)
    return {'kind': FOCUS, 'layout': 'ordered', 'operation': 'ldapur' if loading else 'stlur',
            'name': name, 'canonical_id': canonical_id,
            'word': fixed | ((offset & OFFSET_MASK) << OFFSET_SHIFT) | rn << BASE_SHIFT | rt,
            'element_bytes': width, 'total_bytes': width, 'rt': rt, 'rn': rn,
            'offset': offset, 'mode': 'offset', 'order': 'acquire' if loading else 'release',
            'loading': loading, 'output_bits': output_bits, 'signed': signed,
            'written_gprs': [rt] if loading and rt != 31 else [], 'written_vectors': []}


def shapes():
    return [operation(row[0]) for row in FORMS]


def supported_on_profile(op, target_id):
    """Require the independent capability only for potentially crossing8 loads."""
    if not op['loading'] or op['element_bytes'] == 1:
        return True
    if op['rn'] == 31:
        displacement, width = op['offset'], op['element_bytes']
        if displacement % SCA_BYTES + width > SCA_BYTES:
            return True  # Statically faults before any RAM load.
        if displacement % BASELINE_ATOMIC_BYTES + width <= BASELINE_ATOMIC_BYTES:
            return True
    return 'atomic-load16' in target_id.split('+')[1:]


def functions():
    result, seen = [], set()
    def append(op):
        if op['rn'] == 31 and op['offset'] % SCA_BYTES + op['element_bytes'] > SCA_BYTES:
            return  # Fault-only words have no original success capture.
        if op['word'] not in seen:
            seen.add(op['word'])
            result.append(op)
    for shape in shapes():
        canonical, width = shape['canonical_id'], shape['element_bytes']
        append(shape)
        for offset in EDGE_OFFSETS:
            append(operation(canonical, offset=offset))
            # Other SP offsets cannot produce a success frame under nAA=0.
            if offset % SCA_BYTES + width <= SCA_BYTES:
                append(operation(canonical, rn=31, offset=offset))
        for register in range(32):
            for rt, rn in ((register, 5), (1, register), (register, register)):
                append(operation(canonical, rt, rn))
        for register in (0, 7, 30, 31):
            for offset in (-256, -1, 1, 255):
                append(operation(canonical, register, register, offset))
    return result


def cross8_edge_positions(width):
    if width == 1:
        return ()
    start = (CROSS8_TEMPLATE_BASE + scalar.WIDTHS.index(width) * CROSS8_TEMPLATE_WIDTH_STRIDE
             + BASELINE_ATOMIC_BYTES + 1 - width)
    return (start, start + SCA_BYTES)


@lru_cache(maxsize=1)
def memory_template():
    """Extend a copy of shared edge RAM with signed cross8 payloads."""
    ram = bytearray(scalar.memory_template())
    for width in (2, 4, 8):
        for position, value in zip(cross8_edge_positions(width),
                                   ((1 << (8 * width - 1)) + 1, (1 << (8 * width - 1)) - 1)):
            ram[position:position + width] = value.to_bytes(width, 'little')
    return bytes(ram)


def initial_state(op, seed, position, operand=None, ram_address=RAM_ADDRESS):
    state = State.from_buffer_copy(random.Random(FIXTURE_SEED + seed).randbytes(STATE_BYTES))
    state.nzcv = (seed & 15) << 28
    state.fpcr = FPCR_CASES[seed % len(FPCR_CASES)]
    state.fpsr = FPSR_CASES[seed % len(FPSR_CASES)]
    state.sp = ram_address + 512
    if not op['loading'] and op['rt'] != 31:
        state.x[op['rt']] = (0x8000000080000080 if operand is None else operand) & MASK
    base = (ram_address + position - op['offset']) & MASK
    if op['rn'] == 31:
        if base % SP_ALIGNMENT_BYTES:
            raise ValueError('Success requires aligned incoming SP before offset')
        state.sp = base
    else:
        # Address wins on legal base/data aliases; the model reads this original source.
        state.x[op['rn']] = base
    return state


def effective_address(op, initial):
    base = initial.sp if op['rn'] == 31 else initial.x[op['rn']]
    return (base + op['offset']) & MASK


def snapshot_read(op, initial):
    address, width = effective_address(op, initial), op['element_bytes']
    return (op['loading'] and width > 1 and address % SCA_BYTES + width <= SCA_BYTES
            and address % BASELINE_ATOMIC_BYTES + width > BASELINE_ATOMIC_BYTES)


def corpus():
    ops, cases, runtime_forms = functions(), [], set()
    representatives = {op['word'] for op in shapes()}
    for function, op in enumerate(ops):
        width = op['element_bytes']
        positions = [scalar.edge_positions(width)[2]]
        if op['word'] in representatives:
            positions = [scalar.edge_positions(width)[index % 9] for index in range(16)]
            positions += [2560 + low for low in range(SCA_BYTES - width + 1)]
            positions += list(cross8_edge_positions(width))
        if op['rn'] == 31:
            positions = [2048 + op['offset'] % SP_ALIGNMENT_BYTES]
        for position in positions:
            initial = initial_state(op, len(cases), position)
            runtime = op['canonical_id'] not in runtime_forms
            runtime_forms.add(op['canonical_id'])
            cases.append({'function': function, 'position': position, 'alignment': position % SCA_BYTES,
                          'path': 'cross8' if snapshot_read(op, initial) else 'same_quantity',
                          'runtime': runtime, 'initial': bytes(initial)})
    return ops, cases


def expected(op, initial, memory, ram_address=RAM_ADDRESS, accessible=None, readonly=False, policy='source'):
    """Source-profile effects; faults never commit a destination or RAM prefix."""
    if policy != 'source':
        raise ValueError('Original effects require observed controls, not guessed ordered policy')
    state, ram = State.from_buffer_copy(initial), bytearray(memory)
    limit = len(ram) if accessible is None else accessible
    if not 0 <= limit <= len(ram):
        raise ValueError('Invalid ordered RAM bound')
    base = state.sp if op['rn'] == 31 else state.x[op['rn']]
    if op['rn'] == 31 and base % SP_ALIGNMENT_BYTES:
        return state, bytes(ram), {'kind': 'sp_alignment', 'address': base}
    address, width = (base + op['offset']) & MASK, op['element_bytes']
    if address % SCA_BYTES + width > SCA_BYTES:
        return state, bytes(ram), {'kind': 'sca_alignment', 'address': address}
    position = address - ram_address
    if (readonly and not op['loading']) or position < 0 or position + width > limit:
        fault_address = address if readonly or position < 0 else ram_address + max(position, limit)
        return state, bytes(ram), {'kind': 'memory', 'address': fault_address}
    if op['loading']:
        value = int.from_bytes(ram[position:position + width], 'little', signed=op['signed'])
        if op['rt'] != 31:
            state.x[op['rt']] = value & ((1 << op['output_bits']) - 1)
    else:
        value = 0 if op['rt'] == 31 else state.x[op['rt']]
        ram[position:position + width] = (value & ((1 << (width * 8)) - 1)).to_bytes(width, 'little')
    return state, bytes(ram), None


def validate_source_words(source, functions, allowed_mnemonics):
    import a64_checklist
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    catalog = json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
    facts = a64_checklist.validate(catalog)
    decoder, words = Cs(CS_ARCH_ARM64, CS_MODE_ARM), []
    for function in functions:
        words.extend([*function['operations'], {'word': RET, 'kind': 'return'}])
    if source != b''.join(struct.pack('<I', op['word']) for op in words):
        raise AssertionError('Ordered source bytes differ from exact declared words')
    for index, op in enumerate(words):
        decoded = list(decoder.disasm(struct.pack('<I', op['word']), index * 4))
        if len(decoded) != 1:
            raise AssertionError('Independent Capstone decoder declined unscaled ordered word')
        name = decoded[0].mnemonic
        if op['kind'] == FOCUS:
            if operation(op['canonical_id'], op['rt'], op['rn'], op['offset']) != op:
                raise AssertionError('Ordered word and operand metadata differ')
            fact = facts[op['canonical_id']]
            if (name != op['name'] or fact['mnemonic'].lower() != name
                    or op['word'] & int(fact['encoding_mask'], 16) != int(fact['encoding_value'], 16)):
                raise AssertionError('Ordered source differs from pinned fixed form/decoder')
        elif name not in set(allowed_mnemonics) | {'ret'}:
            raise AssertionError('Independent decoder declined ordered harness word')
    return {'capstone_decode_fallback_words': 0, 'pinned_facts_sha256': a64_checklist.FACTS_SHA}


def fault_operation(shape, case):
    return operation(shape['canonical_id'], rt=case.get('rt', shape['rt']),
                     rn=case['rn'], offset=case.get('offset', shape['offset']))


def fault_initial_state(op, case, seed):
    # The native observer supplies the actual base separately. Use a legal
    # temporary SP here; raw observed inputs own the eventual fault address.
    position = 512 + (op['offset'] % SP_ALIGNMENT_BYTES if op['rn'] == 31 else 0)
    return initial_state(op, seed, position, operand=0)


def fault_selection(first_access_only=False):
    result = []
    for function, shape in enumerate(shapes()):
        width = shape['element_bytes']
        def append(protection, rn=5, **values):
            result.append({'function': function, 'rn': rn, 'protection': protection, 'cut': 0, **values})
        for offset in (-256, -1, 0, 1, 255):
            append('guard', offset=offset)
            append('readonly', offset=offset)
        append('guard', rn=31)
        append('guard', rt=31)
        for offset in (-1, 15):
            append('sp_alignment', rn=31, offset=offset)
        for offset in (-8, 8):
            append('sp_alignment8', rn=31, offset=offset)
        if not first_access_only:
            for low in range(SCA_BYTES):
                append('mapped', low_offset=low)
                append('guard', address_offset=low)
            for cut in range(1, width + 1):
                append('structure_crossing', cut=cut)
        if width > 1:
            cross8_start = BASELINE_ATOMIC_BYTES + 1 - width
            for offset in (cross8_start, cross8_start - SCA_BYTES):
                append('mapped', rn=31, offset=offset, low_offset=offset % SCA_BYTES)
            cross_sca_start = SCA_BYTES + 1 - width
            for offset in (cross_sca_start, cross_sca_start - SCA_BYTES):
                append('mapped', rn=31, offset=offset, low_offset=offset % SCA_BYTES)
    return result


def fault_cases():
    return fault_selection()


def declined_encodings():
    result = []
    for size in range(4):
        for opcode in range(4):
            word = CLASS_VALUE | size << 30 | opcode << 22
            if word & FORM_MASK not in {row[-1] for row in FORMS}:
                result.append({'reason': 'reserved_unscaled_ordered_size_opcode', 'word': word})
    for shape in shapes():
        if shape['loading'] and shape['element_bytes'] > 1:
            result.append({'reason': 'AtomicLoad16_host_capability', 'word': shape['word'],
                           'canonical_id': shape['canonical_id']})
            offset = BASELINE_ATOMIC_BYTES + 1 - shape['element_bytes']
            op = operation(shape['canonical_id'], rn=31, offset=offset)
            result.append({'reason': 'AtomicLoad16_host_capability', 'word': op['word'],
                           'canonical_id': op['canonical_id']})
    return result


def inventory():
    ops, cases = corpus()
    return {'canonical_forms': len(CANONICAL_FORMS),
            'shape_index_arrangements': dict(Counter(op['layout'] for op in shapes())),
            'functions': len(ops), 'success_cases': len(cases), 'fault_cases': len(fault_cases()),
            'ram_bytes': RAM_BYTES, 'state_bytes': STATE_BYTES,
            'profile': 'EL0_Normal_WB_LSE2_A0_nAA0_SCA16',
            'limits': 'Source model only; actual original controls/exception observations remain separate. No disabled-feature, MMIO, whole-memory-model or hardware fault claim.'}


def concurrency_cases():
    """Thirteen own bounded read/release byte histories, without ordering litmus."""
    result = []
    for index, shape in enumerate(shapes()):
        width = shape['element_bytes']
        partner_id = next(row[0] for row in FORMS
                          if row[2] == width and bool(row[3]) != shape['loading'] and not row[4])
        # A store may alias its base without corrupting the next call's address.
        # Loads use a separate destination because their bases persist across calls.
        subject_rt = 1 if shape['loading'] else 5
        subject = operation(shape['canonical_id'], rt=subject_rt, rn=5, offset=HISTORY_DISPLACEMENT)
        partner = operation(partner_id, rt=0 if shape['loading'] else 1,
                            rn=6, offset=-HISTORY_DISPLACEMENT)
        position = HISTORY_WINDOW_BASE + BASELINE_ATOMIC_BYTES + 1 - width
        memory = bytearray(memory_template())
        negative, positive = (1 << (width * 8 - 1)) + 1, (1 << (width * 8 - 1)) - 1
        memory[position:position + width] = negative.to_bytes(width, 'little')
        states = []
        for thread in range(HISTORY_THREADS):
            state = State.from_buffer_copy(random.Random(FIXTURE_SEED + index * HISTORY_THREADS + thread).randbytes(STATE_BYTES))
            state.nzcv = thread << 28
            state.fpcr, state.fpsr = FPCR_CASES[1], FPSR_CASES[1]
            state.x[0], state.x[1] = positive, negative
            state.x[5] = position - HISTORY_DISPLACEMENT
            state.x[6] = position + HISTORY_DISPLACEMENT
            states.append(bytes(state))
        result.append({'id': 'ordered_unscaled_' + shape['canonical_id'], 'kind': 0,
                       'width': width, 'threads': HISTORY_THREADS,
                       'iterations': HISTORY_CALLS_PER_THREAD, 'alias': bool(index % 2),
                       'programs': [[subject], [partner]], 'initial': states,
                       'memory': bytes(memory), 'allowed_outcomes': None})
    return result


def concurrency_plan(case, offsets):
    if (case['kind'] != 0 or case['threads'] != HISTORY_THREADS
            or case['iterations'] != HISTORY_CALLS_PER_THREAD
            or case['width'] not in scalar.WIDTHS
            or any(len(program) != 1 for program in case['programs'])):
        raise ValueError('Unscaled ordered histories require the bounded two-thread byte plan')
    return scalar.concurrency_plan(case, offsets)


def history_expected(op, initial, memory, ram_address=RAM_ADDRESS):
    if op['kind'] == FOCUS:
        return expected(op, initial, memory, ram_address)
    if op['kind'] == scalar.FOCUS:
        return scalar.expected(op, initial, memory, ram_address)
    raise ValueError('Unknown operation in unscaled ordered byte history')


def linearization_allowed(history, initial_ram, ram_address=RAM_ADDRESS, final_ram=None):
    """Use the shared bounded solver with real imm9 effective addresses."""
    from simd_fixtures.memory_history import linearization_allowed as solve
    return solve(history, initial_ram, ram_address, final_ram, expected_operation=history_expected,
                 effective_address=effective_address)
