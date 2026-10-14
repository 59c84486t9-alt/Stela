"""Limited-order scalar transfers with no matching LORegion.

FEAT_LOR is present and LORID/LORC are zero. Arm specifies full acquire/release
semantics for unmatched accesses. Reuse the independent scalar RAM model and
bounded history solver; original controls are observations, not model guesses.
"""
from collections import Counter
import json
import struct

from differential import ROOT, State
from simd_fixtures import atomic_memory as scalar

FOCUS = 'limited_ordered_memory'
RAM_ADDRESS, RAM_BYTES, STATE_BYTES = scalar.RAM_ADDRESS, scalar.RAM_BYTES, scalar.STATE_BYTES
SCA_BYTES, RET = scalar.SCA_BYTES, scalar.RET
REGISTER_COUNT = 32
BASELINE_ATOMIC_BYTES = 8
LIMITED_ORDER_BIT = 1 << 15
HISTORY_THREADS, HISTORY_CALLS = 2, 4


def operation(kind='ldlar', width=8, rt=1, rn=5, sbo=31, rt2=31):
    if kind not in ('ldlar', 'stllr'):
        raise ValueError('Invalid limited-order operation')
    loading = kind == 'ldlar'
    op = scalar.operation('ldar' if loading else 'stlr', width,
                          'acquire' if loading else 'release', rt=rt, rn=rn, sbo=sbo, rt2=rt2)
    # The ordinary ordered decoder/model already owns the unmatched-region
    # semantics; retain its operation key and identify the original encoding.
    op.update(kind=FOCUS, name=kind + ('b' if width == 1 else 'h' if width == 2 else ''),
              word=op['word'] & ~LIMITED_ORDER_BIT)
    bits = 64 if width == BASELINE_ATOMIC_BYTES else 32
    op['canonical_id'] = f'{op["name"].upper()}_{"LR" if loading else "SL"}{bits}_ldstord'
    return op


def shapes():
    return [operation(kind, width) for kind in ('ldlar', 'stllr') for width in scalar.WIDTHS]


CANONICAL_FORMS = tuple(sorted(op['canonical_id'] for op in shapes()))
memory_template = scalar.memory_template
initial_state = scalar.initial_state
expected = scalar.expected
concurrency_plan = scalar.concurrency_plan
linearization_allowed = scalar.linearization_allowed


def supported_on_profile(op, target_id):
    return (not op['loading'] or op['element_bytes'] == 1 or op['rn'] == 31
            or 'atomic-load16' in target_id.split('+')[1:])


def functions():
    result, seen = [], set()
    def append(op):
        if op['word'] not in seen:
            seen.add(op['word'])
            result.append(op)
    for shape in shapes():
        kind = 'ldlar' if shape['loading'] else 'stllr'
        width = shape['element_bytes']
        append(shape)
        for register in range(REGISTER_COUNT):
            for rt, rn in ((register, 5), (1, register), (register, register)):
                append(operation(kind, width, rt, rn))
    return result


def corpus():
    ops, cases, runtime_forms = functions(), [], set()
    representatives = {op['word'] for op in shapes()}
    for function, op in enumerate(ops):
        width = op['element_bytes']
        positions = [scalar.edge_positions(width)[2]]
        if op['word'] in representatives:
            positions += [scalar.edge_positions(width)[index % 9] for index in range(16)]
            positions += [2560 + offset for offset in range(SCA_BYTES - width + 1)]
        if op['rn'] == 31:
            positions = [2048]
        for index, position in enumerate(positions):
            operand = scalar.edge_values(width)[index % len(scalar.edge_values(width))]
            initial = initial_state(op, len(cases), position, operand=operand)
            runtime = op['canonical_id'] not in runtime_forms
            runtime_forms.add(op['canonical_id'])
            cases.append({'function': function, 'position': position,
                          'alignment': position % SCA_BYTES, 'path': 'same_granule',
                          'runtime': runtime, 'initial': bytes(initial)})
    return ops, cases


def validate_source_words(source, functions, allowed_mnemonics):
    import a64_checklist
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    catalog = json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
    facts = a64_checklist.validate(catalog)
    decoder, words = Cs(CS_ARCH_ARM64, CS_MODE_ARM), []
    for function in functions:
        words.extend([*function['operations'], {'word': RET, 'kind': 'return'}])
    if source != b''.join(struct.pack('<I', op['word']) for op in words):
        raise AssertionError('Limited-order source bytes differ from declared words')
    for index, op in enumerate(words):
        decoded = list(decoder.disasm(struct.pack('<I', op['word']), index * 4))
        if len(decoded) != 1:
            raise AssertionError('Independent decoder declined limited-order word')
        name = decoded[0].mnemonic
        if op['kind'] == FOCUS:
            kind = 'ldlar' if op['loading'] else 'stllr'
            if operation(kind, op['element_bytes'], op['rt'], op['rn'], op['sbo'], op['rt2']) != op:
                raise AssertionError('Limited-order metadata differs from original word')
            fact = facts[op['canonical_id']]
            if (name != op['name'] or fact['mnemonic'].lower() != name
                    or op['word'] & int(fact['encoding_mask'], 16) != int(fact['encoding_value'], 16)):
                raise AssertionError('Limited-order source differs from pinned form/decoder')
        elif name not in set(allowed_mnemonics) | {'ret'}:
            raise AssertionError('Independent decoder declined limited-order harness word')
    return {'capstone_decode_fallback_words': 0, 'pinned_facts_sha256': a64_checklist.FACTS_SHA}


def fault_operation(shape, case):
    return operation('ldlar' if shape['loading'] else 'stllr', shape['element_bytes'],
                     rt=case.get('rt', shape['rt']), rn=case['rn'])


def fault_initial_state(op, case, seed):
    return initial_state(op, seed, 512, operand=0)


def fault_selection(first_access_only=False):
    result = []
    for function, shape in enumerate(shapes()):
        def append(protection, rn=5, **values):
            result.append({'function': function, 'rn': rn, 'protection': protection, 'cut': 0, **values})
        for protection in ('guard', 'readonly'):
            append(protection)
            append(protection, rt=31)
        append('guard', rn=31)
        append('sp_alignment', rn=31)
        append('sp_alignment8', rn=31)
        if not first_access_only:
            for low in range(SCA_BYTES):
                append('mapped', low_offset=low)
                append('guard', address_offset=low)
            for cut in range(1, shape['element_bytes'] + 1):
                append('structure_crossing', cut=cut)
    return result


def fault_cases():
    return fault_selection()


def declined_encodings():
    return [{'reason': 'AtomicLoad16_host_capability', 'word': op['word'],
             'canonical_id': op['canonical_id']} for op in shapes()
            if op['loading'] and op['element_bytes'] > 1]


def inventory():
    ops, cases = corpus()
    return {'canonical_forms': len(CANONICAL_FORMS),
            'shape_index_arrangements': dict(Counter(op['layout'] for op in shapes())),
            'functions': len(ops), 'success_cases': len(cases), 'fault_cases': len(fault_cases()),
            'ram_bytes': RAM_BYTES, 'state_bytes': STATE_BYTES,
            'profile': 'EL0_FEAT_LOR_LORID0_LORC0_Normal_WB_LSE2_A0_nAA0_SCA16',
            'limits': 'No configured LORegions, device memory, tagged dereference or full memory-model proof.'}


def concurrency_cases():
    result = []
    for shape in shapes():
        width = shape['element_bytes']
        subject = operation('ldlar' if shape['loading'] else 'stllr', width,
                            rt=1 if shape['loading'] else 5)
        partner = operation('stllr' if shape['loading'] else 'ldlar', width,
                            rt=0 if shape['loading'] else 1, rn=6)
        position = 64 + BASELINE_ATOMIC_BYTES + 1 - width
        states = []
        for thread in range(HISTORY_THREADS):
            state = initial_state(subject, len(result) * HISTORY_THREADS + thread, 512)
            state.x[0], state.x[1] = scalar.edge_values(width)[4:6]
            state.x[5] = state.x[6] = position
            states.append(bytes(state))
        result.append({'id': 'limited_' + shape['canonical_id'], 'kind': 0, 'width': width,
                       'threads': HISTORY_THREADS, 'iterations': HISTORY_CALLS,
                       'alias': bool(len(result) % 2), 'programs': [[subject], [partner]],
                       'initial': states, 'memory': memory_template(), 'allowed_outcomes': None})
    return result
