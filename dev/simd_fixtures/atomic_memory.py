"""Scalar LSE/ordered words and independent shared-Normal-WB byte model.

The declared profile has LSE2, A=0, nAA=0 and an aligned16-byte SCA granule.
Translation permission checks require writes for every CAS/RMW, including failed
CAS. Oracle deviations are retained observations, never alternate MMU semantics.
"""
from collections import Counter
from functools import lru_cache
import json
import random
import struct

from differential import MASK, ROOT, State
from simd_fixtures.structure_memory import RAM_ADDRESS, RAM_BYTES, STATE_BYTES

FOCUS = 'atomic_memory'
WIDTHS = (1, 2, 4, 8)
ORDERS = ('relaxed', 'acquire', 'release', 'acquire_release')
ORDER_SUFFIX = ('', 'a', 'l', 'al')
RMW_NAMES = ('add', 'clear', 'xor', 'set', 'signed_max', 'signed_min', 'unsigned_max', 'unsigned_min', 'swap')
RMW_MNEMONICS = ('ldadd', 'ldclr', 'ldeor', 'ldset', 'ldsmax', 'ldsmin', 'ldumax', 'ldumin', 'swp')
SCA_BYTES = 16
RET = 0xd65f03c0


def operation(kind='add', width=8, order='relaxed', rs=0, rt=1, rn=5, option=15, sbo=31, rt2=31):
    if (kind not in (*RMW_NAMES, 'cas', 'ldar', 'ldapr', 'stlr', 'dmb') or width not in WIDTHS
            or order not in ORDERS or any(type(reg) is not int or not 0 <= reg < 32 for reg in (rs, rt, rn, sbo, rt2))
            or not 0 <= option < 16):
        raise ValueError('Invalid atomic/ordered operand')
    size, bits = width.bit_length() - 1, 64 if width == 8 else 32
    width_suffix = 'b' if width == 1 else 'h' if width == 2 else ''
    if kind == 'dmb':
        name, canonical, word, layout, width = 'dmb', 'DMB_BO_barriers', 0xd50330bf | option << 8, 'barrier', 0
    elif kind in ('ldar', 'ldapr', 'stlr'):
        name, layout = kind + width_suffix, 'ordered'
        if kind == 'ldapr':
            word, canonical = 0x38a0c000 | size << 30 | sbo << 16, f'{name.upper()}_{bits}L_memop'
        else:
            word = (0x08c08000 if kind == 'ldar' else 0x08808000) | size << 30 | sbo << 16 | rt2 << 10
            canonical = f'{name.upper()}_{"LR" if kind == "ldar" else "SL"}{bits}_ldstord'
        word |= rn << 5 | rt
    else:
        suffix, layout = ORDER_SUFFIX[ORDERS.index(order)], 'cas' if kind == 'cas' else 'rmw'
        if kind == 'cas':
            name = 'cas' + suffix + width_suffix
            canonical = f'{name.upper()}_C{bits}_comswap'
            word = 0x08a07c00 | size << 30 | int(order in ('acquire', 'acquire_release')) << 22 | int(order in ('release', 'acquire_release')) << 15
        else:
            index = RMW_NAMES.index(kind)
            name = RMW_MNEMONICS[index] + suffix + width_suffix
            canonical = f'{name.upper()}_{bits}_memop'
            word = 0x38200000 | size << 30 | index << 12 | int(order in ('acquire', 'acquire_release')) << 23 | int(order in ('release', 'acquire_release')) << 22
        word |= rs << 16 | rn << 5 | rt
    destination = rs if layout == 'cas' else rt
    loading = layout in ('cas', 'rmw') or kind in ('ldar', 'ldapr')
    return {'kind': FOCUS, 'layout': layout, 'operation': kind, 'name': name, 'canonical_id': canonical,
            'word': word, 'element_bytes': width, 'total_bytes': width, 'rs': rs, 'rt': rt, 'rn': rn,
            'order': order, 'option': option, 'sbo': sbo, 'rt2': rt2, 'mode': 'offset', 'offset': 0,
            'loading': loading, 'written_gprs': [destination] if loading and destination != 31 else [],
            'written_vectors': []}


def shapes():
    return ([operation(kind, width, order) for kind in ('cas', *RMW_NAMES) for width in WIDTHS for order in ORDERS]
            + [operation(kind, width) for kind in ('ldar', 'stlr', 'ldapr') for width in WIDTHS]
            + [operation('dmb', option=option) for option in range(16)])


CANONICAL_FORMS = tuple(sorted({op['canonical_id'] for op in shapes()}))


def supported_on_profile(op, target):
    return (target != 'baseline' or op['operation'] not in ('ldar', 'ldapr')
            or op['element_bytes'] == 1 or op['rn'] == 31)


def functions():
    result, seen = [], set()
    def append(op):
        if op['word'] not in seen:
            seen.add(op['word'])
            result.append(op)
    for op in shapes():
        append(op)
        if op['layout'] == 'barrier':
            continue
        values = {'kind': op['operation'], 'width': op['element_bytes'], 'order': op['order']}
        append(operation(**values, rn=31))
        for index in range(32):
            append(operation(**values, rs=index, rt=(index + 1) % 32, rn=(index + 2) % 32))
        for register in (0, 7, 30, 31):
            other = (register + 1) % 31
            for rs, rt, rn in ((register, register, other), (register, other, register),
                               (other, register, register), (register, register, register)):
                append(operation(**values, rs=rs, rt=rt, rn=rn))
    return result


def edge_values(width):
    bits = width * 8
    mask, sign = (1 << bits) - 1, 1 << (bits - 1)
    return (0, 1, mask, mask - 1, sign, sign - 1, sign + 1, mask // 3, mask // 3 * 2)


def edge_positions(width):
    return [512 + WIDTHS.index(width) * 512 + index * 16 for index in range(9)]


def address_match_position(width):
    return 4096 + WIDTHS.index(width) * 256


@lru_cache(maxsize=1)
def memory_template():
    ram = bytearray(random.Random(0xa70c0173).randbytes(RAM_BYTES))
    for width in WIDTHS:
        for position, value in zip(edge_positions(width), edge_values(width)):
            ram[position:position + width] = value.to_bytes(width, 'little')
        position = address_match_position(width)
        ram[position:position + width] = ((RAM_ADDRESS + position) & ((1 << (8 * width)) - 1)).to_bytes(width, 'little')
    return bytes(ram)


def initial_state(op, seed, position, operand=None, compare=None, ram_address=RAM_ADDRESS):
    state = State.from_buffer_copy(random.Random(0xa70c0173 + seed).randbytes(STATE_BYTES))
    state.nzcv = (seed & 15) << 28
    state.fpcr = (0, 0x07ff2007, 0x00c09f00, 0x00400000)[seed % 4]
    state.fpsr = (0, 0x0800009f, 0xf800009f, 0x00000010)[seed % 4]
    state.sp = ram_address + 512
    if op['layout'] == 'barrier':
        return state
    if op['layout'] == 'cas':
        if op['rt'] != 31:
            state.x[op['rt']] = (0xfedcba9876543210 if operand is None else operand) & MASK
        if op['rs'] != 31:
            state.x[op['rs']] = (0x0123456789abcdef if compare is None else compare) & MASK
    elif op['layout'] == 'rmw' and op['rs'] != 31:
        state.x[op['rs']] = (0x8000000080000080 if operand is None else operand) & MASK
    elif op['operation'] == 'stlr' and op['rt'] != 31:
        state.x[op['rt']] = (0x0123456789abcdef if operand is None else operand) & MASK
    if op['rn'] == 31:
        if position % 16:
            raise ValueError('Success SP must be aligned16')
        state.sp = ram_address + position
    else:
        state.x[op['rn']] = ram_address + position
    return state


def corpus():
    ops, cases, runtime_forms = functions(), [], set()
    memory = memory_template()
    representatives = {op['word'] for op in shapes()}
    for function, op in enumerate(ops):
        width = op['element_bytes'] or 1
        specs = [(edge_positions(width)[2], None, None)]
        if op['layout'] == 'cas':
            position = (address_match_position(width) if op['rs'] == op['rn'] != 31 else
                        edge_positions(width)[0] if op['rs'] == 31 else edge_positions(width)[2])
            old = int.from_bytes(memory[position:position + width], 'little')
            specs = [(position, None, old), (edge_positions(width)[1], None, 0)]
        if op['word'] in representatives and op['layout'] != 'barrier':
            specs += [(edge_positions(width)[index % 9], edge_values(width)[(index * 5 + 1) % 9], None) for index in range(16)]
            specs += [(2560 + offset, 0, None) for offset in range(16 - width + 1)]
        for position, operand, compare in specs:
            initial = initial_state(op, len(cases), position, operand, compare)
            runtime = op['canonical_id'] not in runtime_forms
            runtime_forms.add(op['canonical_id'])
            old = int.from_bytes(memory[position:position + width], 'little')
            cases.append({'function': function, 'position': position, 'alignment': position % 16,
                          'path': 'same_granule', 'runtime': runtime,
                          'compare_matches': op['layout'] == 'cas' and (0 if op['rs'] == 31 else initial.x[op['rs']] & ((1 << (8 * width)) - 1)) == old,
                          'initial': bytes(initial)})
    return ops, cases


def rmw_value(kind, old, operand, width):
    bits, mask = 8 * width, (1 << (8 * width)) - 1
    signed = lambda value: value - (1 << bits) if value & (1 << (bits - 1)) else value
    if kind == 'add': result = old + operand
    elif kind == 'clear': result = old & ~operand
    elif kind == 'xor': result = old ^ operand
    elif kind == 'set': result = old | operand
    elif kind == 'signed_max': result = old if signed(old) >= signed(operand) else operand
    elif kind == 'signed_min': result = old if signed(old) <= signed(operand) else operand
    elif kind == 'unsigned_max': result = max(old, operand)
    elif kind == 'unsigned_min': result = min(old, operand)
    elif kind == 'swap': result = operand
    else: raise ValueError('Unknown mathematical atomic operation')
    return result & mask


def expected(op, initial, memory, ram_address=RAM_ADDRESS, accessible=None, readonly=False, policy='source'):
    if policy != 'source':
        raise ValueError('Atomic emulator effects require observed controls, not guessed policy')
    state, ram = State.from_buffer_copy(initial), bytearray(memory)
    if op['layout'] == 'barrier':
        return state, bytes(ram), None
    width = op['element_bytes']
    base = initial.sp if op['rn'] == 31 else initial.x[op['rn']]
    if op['rn'] == 31 and base % 16:
        return state, bytes(ram), {'kind': 'sp_alignment', 'address': base}
    if base % 16 + width > SCA_BYTES:
        return state, bytes(ram), {'kind': 'sca_alignment', 'address': base}
    position, limit = base - ram_address, len(ram) if accessible is None else accessible
    if not 0 <= limit <= len(ram):
        raise ValueError('Invalid atomic RAM bound')
    writes = op['layout'] in ('cas', 'rmw') or op['operation'] == 'stlr'
    if (readonly and writes) or position < 0 or position + width > limit:
        address = base if readonly or position < 0 else ram_address + max(position, limit)
        return state, bytes(ram), {'kind': 'memory', 'address': address}
    old, mask = int.from_bytes(ram[position:position + width], 'little'), (1 << (8 * width)) - 1
    read_reg = lambda register: 0 if register == 31 else initial.x[register] & mask
    if op['layout'] == 'cas':
        new = read_reg(op['rt']) if old == read_reg(op['rs']) else old
        if op['rs'] != 31: state.x[op['rs']] = old
    elif op['layout'] == 'rmw':
        new = rmw_value(op['operation'], old, read_reg(op['rs']), width)
        if op['rt'] != 31: state.x[op['rt']] = old
    elif op['operation'] == 'stlr':
        new = read_reg(op['rt'])
    else:
        new = old
        if op['rt'] != 31: state.x[op['rt']] = old
    if writes:
        ram[position:position + width] = new.to_bytes(width, 'little')
    return state, bytes(ram), None


def validate_source_words(source, functions, allowed_mnemonics):
    import a64_checklist
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    catalog = json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
    facts = a64_checklist.validate(catalog)
    decoder, words, aliases = Cs(CS_ARCH_ARM64, CS_MODE_ARM), [], []
    for function in functions:
        words.extend([*function['operations'], {'word': RET, 'kind': 'return'}])
    if source != b''.join(struct.pack('<I', op['word']) for op in words):
        raise AssertionError('Atomic source bytes differ from exact declared words')
    for index, op in enumerate(words):
        decoded = list(decoder.disasm(struct.pack('<I', op['word']), index * 4))
        if len(decoded) != 1:
            raise AssertionError('Independent Capstone decoder declined atomic word')
        name = decoded[0].mnemonic
        if op.get('kind') == FOCUS:
            rebuilt = operation(op['operation'], op['element_bytes'] or 8, op['order'], op['rs'], op['rt'], op['rn'],
                                op['option'], op['sbo'], op['rt2'])
            if rebuilt != op:
                raise AssertionError('Atomic word and operand metadata differ')
            fact = facts[op['canonical_id']]
            if op['word'] & int(fact['encoding_mask'], 16) != int(fact['encoding_value'], 16):
                raise AssertionError('Atomic word differs from pinned fixed facts')
            expected_name = op['name']
            store_alias = (op['layout'] == 'rmw' and op['operation'] != 'swap' and op['rt'] == 31
                           and op['order'] in ('relaxed', 'release') and name == 'st' + expected_name[2:])
            if name != expected_name and not store_alias:
                raise AssertionError('Atomic decoder mnemonic differs')
            if store_alias: aliases.append({'word_index': index, 'canonical_id': op['canonical_id'], 'decoded_alias': name})
        elif name not in set(allowed_mnemonics) | {'ret'}:
            raise AssertionError('Independent decoder declined atomic harness word')
    return {'capstone_decode_fallback_words': 0, 'decoded_store_aliases': aliases,
            'pinned_facts_sha256': a64_checklist.FACTS_SHA}


def fault_operation(shape, case):
    return operation(shape['operation'], shape['element_bytes'] or 8, shape['order'],
                     rs=case.get('rs', shape['rs']), rt=case.get('rt', shape['rt']),
                     rn=case['rn'], option=shape['option'])


def fault_selection(first_access_only=False):
    result = []
    for function, op in enumerate(shapes()):
        def append(protection, rn=5, **kwargs):
            result.append({'function': function, 'rn': rn, 'cut': 0, 'protection': protection, **kwargs})
        if op['layout'] == 'barrier':
            append('guard')
            continue
        append('guard')
        append('guard', rn=31)
        append('sp_alignment', rn=31)
        append('sp_alignment8', rn=31)
        append('readonly')
        if op['layout'] == 'cas': append('readonly', compare_matches=True)
        if not first_access_only:
            for offset in range(16):
                append('mapped', low_offset=offset)
                if op['rn'] != 31: append('guard', address_offset=offset)
            append('structure_crossing', cut=op['element_bytes'])
    return result


def fault_cases():
    return fault_selection()


def declined_encodings():
    result = [{'reason': 'reserved_rmw_operation', 'word': 0xf8200000 | opcode << 12} for opcode in range(9, 16)]
    result += [{'reason': 'AtomicLoad16_host_capability', 'word': operation(kind, width)['word'],
                'canonical_id': operation(kind, width)['canonical_id']}
               for kind in ('ldar', 'ldapr') for width in (2, 4, 8)]
    return result


def inventory():
    ops, cases = corpus()
    return {'canonical_forms': 173, 'shape_index_arrangements': dict(Counter(op['layout'] for op in shapes())),
            'functions': len(ops), 'success_cases': len(cases), 'fault_cases': len(fault_cases()),
            'ram_bytes': RAM_BYTES, 'state_bytes': STATE_BYTES, 'profile': 'EL0_Normal_WB_LSE2_A0_nAA0_SCA16'}


def linearization_allowed(history, initial_ram, ram_address=RAM_ADDRESS, final_ram=None):
    """Bounded exhaustive serializations respecting observed real-time edges."""
    if len(history) > 16:
        raise ValueError('Atomic linearization history exceeds16 operations')
    ranges = []
    for row in history:
        state = State.from_buffer_copy(bytes.fromhex(row['initial_state_hex']))
        op = row['operation']
        start = (state.sp if op['rn'] == 31 else state.x[op['rn']]) - row.get('ram_address', ram_address)
        ranges.append((start, start + op['element_bytes']))
    lower, upper = (min(start for start, _ in ranges), max(end for _, end in ranges)) if ranges else (0, 0)
    if not 0 <= lower <= upper <= len(initial_ram) or upper - lower > 256:
        raise ValueError('Linearization history exceeds bounded byte window')
    rejected = set()
    def search(remaining, ram):
        if not remaining: return final_ram is None or ram == final_ram
        key = remaining, ram[lower:upper]
        if key in rejected: return False
        for index in remaining:
            row = history[index]
            if any(history[other]['end'] < row['begin'] for other in remaining if other != index): continue
            initial = State.from_buffer_copy(bytes.fromhex(row['initial_state_hex']))
            state, updated, fault = expected(row['operation'], initial, ram, row.get('ram_address', ram_address))
            if fault or bytes(state).hex() != row['final_state_hex']: continue
            if search(tuple(other for other in remaining if other != index), updated): return True
        rejected.add(key)
        return False
    return search(tuple(range(len(history))), bytes(initial_ram))


def ordinary_transfer(loading, rt, rn):
    return {'kind': 'atomic_litmus_transfer', 'name': 'ldr' if loading else 'str',
            'word': (0xf9400000 if loading else 0xf9000000) | rn << 5 | rt,
            'canonical_id': 'LDR_64_ldst_pos' if loading else 'STR_64_ldst_pos',
            'layout': 'litmus_transfer', 'element_bytes': 8, 'total_bytes': 8,
            'loading': loading, 'rt': rt, 'rn': rn, 'written_gprs': [rt] if loading and rt != 31 else []}


def concurrency_cases():
    """Fixed native/original programs; control gates are outside each sequence."""
    result = []
    def add(identifier, kind, programs, width=8, iterations=8, alias=False, values=None, memory=None, allowed=None):
        states = []
        for thread in range(len(programs)):
            state = State.from_buffer_copy(random.Random(0xa70c2000 + len(result) * 8 + thread).randbytes(STATE_BYTES))
            state.nzcv, state.fpcr, state.fpsr = thread << 28, 0x03c00000, 0x0800001f
            state.x[0], state.x[1], state.x[5], state.x[6] = 1, 0, 0, 64
            if values:
                for register, value in values[thread].items(): state.x[register] = value & MASK
            states.append(bytes(state))
        result.append({'id': identifier, 'kind': kind, 'width': width, 'threads': len(programs),
                       'iterations': iterations, 'alias': alias, 'programs': programs, 'initial': states,
                       'memory': bytes(RAM_BYTES) if memory is None else memory, 'allowed_outcomes': allowed})
    for width in WIDTHS:
        for alias in (False, True):
            add(f'tickets_{width}_alias{int(alias)}', 1, [[operation('add', width)] for _ in range(2)],
                width, min(64, (1 << (width * 8)) // 4), alias)
    for width in (4, 8):
        add(f'cas_increment_{width}', 2, [[operation('cas', width, 'acquire_release')] for _ in range(2)], width, 32,
            values=[{0: 0}, {0: 0}])
    for width in (1, 8):
        add(f'swap_tokens_{width}', 3, [[operation('swap', width)] for _ in range(2)], width, 64,
            values=[{0: 1}, {0: 2}])
    for kind in RMW_NAMES:
        for width in (1, 8):
            memory = bytearray(RAM_BYTES)
            memory[:width] = (1 << (width * 8 - 1)).to_bytes(width, 'little')
            add(f'history_{kind}_{width}', 0, [[operation(kind, width)] for _ in range(2)], width, 4,
                values=[{0: (1 << (width * 8)) - 1}, {0: 1}], memory=bytes(memory))
    for width, offset in ((2, 7), (4, 5), (8, 1)):
        for load in ('ldar', 'ldapr'):
            memory = bytearray(random.Random(0xa70c8000 + width).randbytes(RAM_BYTES))
            mask = (1 << (width * 8)) - 1
            memory[offset:offset + width] = (0x1122334455667788 & mask).to_bytes(width, 'little')
            add(f'cross8_{load}_swap_{width}_offset{offset}', 0,
                [[operation('swap', width)], [operation(load, width)]], width, 4,
                values=[{0: 0x8899aabbccddeeff, 5: offset}, {5: offset}], memory=bytes(memory))
    add('history_overlapping_widths', 0, [[operation('add', width)] for width in WIDTHS], iterations=3,
        values=[{5: 0}, {5: 1}, {5: 2}, {5: 0}])
    swapped_bases = [{5: 0, 6: 64}, {5: 64, 6: 0}]
    for load, key in (('ldar', 'store_buffer_rcsc'), ('ldapr', 'store_buffer_rcpc')):
        add(key, 4, [[operation('stlr', rt=0, rn=5), operation(load, rt=1, rn=6)] for _ in range(2)],
            iterations=256, values=swapped_bases, allowed=key)
    for option, key in ((15, 'store_buffer_dmb_full'), (13, 'store_buffer_dmb_reads'), (14, 'store_buffer_dmb_writes')):
        add(key, 4, [[ordinary_transfer(False, 0, 5), operation('dmb', option=option), ordinary_transfer(True, 1, 6)] for _ in range(2)],
            iterations=256, values=swapped_bases, allowed=key)
    for load in ('ldar', 'ldapr'):
        add('publication_' + load, 4,
            [[ordinary_transfer(False, 0, 5), operation('stlr', rt=0, rn=6)],
             [operation(load, rt=1, rn=6), ordinary_transfer(True, 2, 5)]],
            iterations=256, allowed='publication_' + load)
    return result


def concurrency_plan(case, offsets):
    if (not 2 <= case['threads'] <= 4 or len(offsets) != case['threads'] or case['iterations'] > 256
            or case['kind'] == 0 and case['threads'] * case['iterations'] > 16):
        raise ValueError('Atomic concurrency plan exceeds fixed bounds')
    header = struct.pack('<Q6I4Q', 0x314e414c504d5441, case['kind'], case['threads'], case['iterations'],
                         case['threads'], case['width'], int(case['alias']), *offsets, *([0] * (4 - len(offsets))))
    return header + b''.join(case['initial']) + bytes((4 - case['threads']) * STATE_BYTES) + case['memory']


def relocate_state(initial, address):
    state = State.from_buffer_copy(initial)
    state.x[5] += address
    state.x[6] += address
    return state


def validate_preserved_program_state(program, initial, final):
    expected = State.from_buffer_copy(initial)
    written = {reg for op in program for reg in op.get('written_gprs', [])}
    for register in written: expected.x[register] = final.x[register]
    return bytes(expected) == bytes(final)


def validate_litmus_case(case, model):
    """Bind the restricted ordering ledger to exact programs and input meanings."""
    if case['kind'] != 4:
        return
    key = case['allowed_outcomes']
    words = [[op['word'] for op in program] for program in case['programs']]
    if (case['threads'] != 2 or case['width'] != 8 or case['alias'] or case['memory'] != bytes(RAM_BYTES)
            or words != model['program_words'].get(key)):
        raise AssertionError('Litmus programs/input memory differ from reviewed model')
    for thread, raw in enumerate(case['initial']):
        state = State.from_buffer_copy(raw)
        bases = (0, 64) if key.startswith('publication_') or thread == 0 else (64, 0)
        if state.x[0] != 1 or (state.x[5], state.x[6]) != bases:
            raise AssertionError('Litmus store value/locations differ from reviewed model')


def cas_counter_history_allowed(events, successes):
    """Exact no-wrap +1 CAS history: transition ranks and real-time order.

    Success k advances k→k+1 at phase2k+1; a failed read of k lies at phase2k.
    Equal phases are only failures observing the same value. A linearization
    exists exactly when every completed-before-invoked edge preserves phase.
    """
    if (type(successes) is not int or successes < 0
            or any(type(row['old']) is not int or not 0 <= row['old'] <= successes
                   or row['begin'] >= row['end'] for row in events)
            or sorted(row['old'] for row in events if row['success']) != list(range(successes))):
        return False
    phase = lambda row: 2 * row['old'] + int(row['success'])
    finished, cursor, maximum = sorted(events, key=lambda row: row['end']), 0, -1
    for row in sorted(events, key=lambda row: row['begin']):
        while cursor < len(finished) and finished[cursor]['end'] < row['begin']:
            maximum = max(maximum, phase(finished[cursor]))
            cursor += 1
        if maximum > phase(row):
            return False
    return True
