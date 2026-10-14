"""Structured AdvSIMD memory words and independent complete byte-state model.

The model indexes memory bytes directly from mathematical layout coordinates;
it imports no compiler decoder, access schedule, or emitted-code implementation.
Interrupted source-policy and QEMU observations are deliberately separate.
"""
from collections import Counter
import random
import struct

from differential import MASK, State

FOCUS = 'structure_memory'
ELEMENT_BYTES = (1, 2, 4, 8)
MODES = ('offset', 'immediate', 'register')
RAM_BYTES = 8192
# Above macOS executable PAGEZERO, with the same address in original and native
# observations. The memory observer supplies this range through lazy QEMU RAM.
RAM_ADDRESS = 0x140074000
STATE_BYTES = 784
MULTIPLE_OPCODES = {(1, 1): 7, (2, 1): 10, (3, 1): 6, (4, 1): 2,
                    (1, 2): 8, (1, 3): 4, (1, 4): 0}


def canonical_id(op):
    name, count, mode = op['name'].upper(), op['structures'], op['mode']
    if op['layout'] == 'multiple':
        count = op['runs'] if count == 1 else count
        if op['structures'] == 1:
            return (f'{name}_asisdlse_R{count}_{count}v' if mode == 'offset' else
                    f'{name}_asisdlsep_I{count}_i{count}' if mode == 'immediate' else
                    f'{name}_asisdlsep_R{count}_r{count}')
        return (f'{name}_asisdlse_R{count}' if mode == 'offset' else
                f'{name}_asisdlsep_I{count}_i' if mode == 'immediate' else
                f'{name}_asisdlsep_R{count}_r')
    if op['layout'] == 'replicate':
        return (f'{name}_asisdlso_R{count}' if mode == 'offset' else
                f'{name}_asisdlsop_R{count}_i' if mode == 'immediate' else
                f'{name}_asisdlsop_RX{count}_r')
    letter = {1: 'B', 2: 'H', 4: 'S', 8: 'D'}[op['element_bytes']]
    return (f'{name}_asisdlso_{letter}{count}_{count}{letter.lower()}' if mode == 'offset' else
            f'{name}_asisdlsop_{letter}{count}_i{count}{letter.lower()}' if mode == 'immediate' else
            f'{name}_asisdlsop_{letter}X{count}_r{count}{letter.lower()}')


def operation(layout, loading=True, structures=1, runs=1, vector_bytes=16,
              element_bytes=1, index=0, mode='offset', rt=31, rn=5, rm=6):
    if (layout not in ('multiple', 'lane', 'replicate') or mode not in MODES
            or element_bytes not in ELEMENT_BYTES or vector_bytes not in (8, 16)
            or not 1 <= structures <= 4 or not 1 <= runs <= 4
            or any(not 0 <= register < 32 for register in (rt, rn, rm))):
        raise ValueError('Invalid structured SIMD operand')
    if mode == 'register' and rm == 31:
        raise ValueError('Rm31 denotes transferred-byte immediate, not a register')
    size = element_bytes.bit_length() - 1
    word = (int(loading) << 22) | (rn << 5) | rt
    if mode != 'offset':
        word |= (1 << 23) | ((31 if mode == 'immediate' else rm) << 16)
    if layout == 'multiple':
        if (runs, structures) not in MULTIPLE_OPCODES or (structures != 1 and vector_bytes == 8 and element_bytes == 8) or index:
            raise ValueError('Unallocated multiple structure arrangement')
        word |= 0x0c000000 | (int(vector_bytes == 16) << 30) | (MULTIPLE_OPCODES[runs, structures] << 12) | (size << 10)
        total = runs * structures * vector_bytes
    else:
        if runs != 1:
            raise ValueError('Single structures have one run')
        r, opcode_low = (structures - 1) & 1, (structures - 1) >> 1
        word |= 0x0d000000 | (r << 21) | (opcode_low << 13)
        if layout == 'replicate':
            if not loading or index:
                raise ValueError('Replicate is load-only without a lane index')
            word |= (int(vector_bytes == 16) << 30) | (3 << 14) | (size << 10)
        else:
            if not 0 <= index < 16 // element_bytes:
                raise ValueError('Lane index outside V128')
            # Q:S:size encode index; they do not describe destination width.
            if element_bytes == 1:
                q, s, encoded_size, scale = index >> 3, index >> 2 & 1, index & 3, 0
            elif element_bytes == 2:
                q, s, encoded_size, scale = index >> 2, index >> 1 & 1, (index & 1) << 1, 1
            elif element_bytes == 4:
                q, s, encoded_size, scale = index >> 1, index & 1, 0, 2
            else:
                q, s, encoded_size, scale = index, 0, 1, 2
            word |= (q << 30) | (s << 12) | (encoded_size << 10) | (scale << 14)
        total = structures * element_bytes
    op = {'kind': FOCUS, 'layout': layout, 'loading': loading, 'structures': structures,
          'runs': runs, 'vector_bytes': vector_bytes, 'element_bytes': element_bytes,
          'index': index, 'mode': mode, 'rt': rt, 'rn': rn, 'rm': rm,
          'total_bytes': total, 'name': ('ld' if loading else 'st') + str(structures) + ('r' if layout == 'replicate' else ''),
          'word': word}
    op['canonical_id'] = canonical_id(op)
    return op


def shapes():
    result = []
    for loading in (False, True):
        for mode in MODES:
            for runs, structures in MULTIPLE_OPCODES:
                for vector_bytes in (8, 16):
                    for element_bytes in ELEMENT_BYTES:
                        if structures != 1 and vector_bytes == 8 and element_bytes == 8:
                            continue
                        result.append(operation('multiple', loading, structures, runs, vector_bytes, element_bytes, mode=mode))
            for structures in range(1, 5):
                for element_bytes in ELEMENT_BYTES:
                    for index in range(16 // element_bytes):
                        result.append(operation('lane', loading, structures, element_bytes=element_bytes, index=index, mode=mode))
    for mode in MODES:
        for structures in range(1, 5):
            for vector_bytes in (8, 16):
                for element_bytes in ELEMENT_BYTES:
                    result.append(operation('replicate', True, structures, vector_bytes=vector_bytes, element_bytes=element_bytes, mode=mode))
    return result


CANONICAL_FORMS = tuple(sorted({op['canonical_id'] for op in shapes()}))


def functions():
    result, seen = [], set()
    def append(op):
        if op['word'] not in seen:
            seen.add(op['word'])
            result.append(op)
    for op in shapes():
        append(op)
    representatives = {}
    for op in shapes():
        representatives.setdefault(op['canonical_id'], op)
    for op in representatives.values():
        for register in range(32):
            # Each form covers all starts (including V31 wrap), all bases and all
            # register increments. Equal numeric X/V indices are independent.
            values = {key: op[key] for key in ('layout', 'loading', 'structures', 'runs', 'vector_bytes', 'element_bytes', 'index', 'mode')}
            append(operation(**values, rt=register, rn=register, rm=register % 31))
            if op['mode'] == 'register':
                append(operation(**values, rt=register, rn=register % 31, rm=register % 31))
    return result


def memory_template():
    memory = bytearray(random.Random(0x57e1a150).randbytes(RAM_BYTES))
    memory[512:576] = bytes.fromhex('ffff0080ffff00ff') * 8
    return bytes(memory)


def initial_state(op, seed, position, ram_address=RAM_ADDRESS):
    rng = random.Random(0x57e1a150 + seed)
    state = State.from_buffer_copy(rng.randbytes(STATE_BYTES))
    state.nzcv = (seed & 15) << 28
    # Nonzero numerical enables, sticky flags and rounding fields are storage;
    # data movement must preserve them. Values are architectural QEMU readbacks.
    state.fpcr = (0, 0x07ff2007, 0x00c09f00, 0x00400000)[seed % 4]
    state.fpsr = (0, 0x0800009f, 0xf800009f, 0x00000010)[seed % 4]
    if seed % 8 == 0:
        for vector in state.v:
            vector[:] = [MASK, 0x8000ffff8000ffff]
    state.sp = ram_address + 512
    if op['mode'] == 'register':
        state.x[op['rm']] = (0, 17, MASK, 1 << 63)[seed % 4]
    if op['rn'] == 31:
        if position % 16:
            raise ValueError('Success input requires aligned original SP')
        state.sp = ram_address + position
    else:
        state.x[op['rn']] = ram_address + position
    # Rm=Rn deliberately uses the incoming full address as its increment.
    return state


def corpus():
    ops, cases = functions(), []
    shape_words = {op['word'] for op in shapes()}
    runtime_forms = set()
    for function, op in enumerate(ops):
        positions = list(range(512, 520)) + [4096 - max(1, op['total_bytes'] // 2)] if op['word'] in shape_words else [512]
        if op['rn'] == 31:
            positions = [512, 4096 - ((op['total_bytes'] + 15) // 16) * 16]
        for position in dict.fromkeys(positions):
            initial = initial_state(op, len(cases), position)
            runtime = op['canonical_id'] not in runtime_forms
            if runtime:
                runtime_forms.add(op['canonical_id'])
            cases.append({'function': function, 'position': position, 'alignment': position % 8,
                          'path': 'crossing' if position // 4096 != (position + op['total_bytes'] - 1) // 4096 else 'same_granule',
                          'runtime': runtime, 'initial': bytes(initial)})
    return ops, cases


def expected(op, initial, memory, ram_address=RAM_ADDRESS, accessible=None,
             readonly=False, policy='source'):
    """Return full state/RAM/fault under source policy or explicit QEMU policy.

    accessible is a byte count from the RAM base. A failed scalar read commits
    no lane. Source crossing stores retain their ascending-byte prefix; QEMU
    stores do not. QEMU LD/ST1 uses eight-byte units and delays Q0 upper clear.
    """
    if policy not in ('source', 'qemu'):
        raise ValueError('Unknown interrupted-memory policy')
    state, ram = State.from_buffer_copy(initial), bytearray(memory)
    limit = len(ram) if accessible is None else accessible
    if not 0 <= limit <= len(ram):
        raise ValueError('Accessible RAM bound differs')
    base = initial.sp if op['rn'] == 31 else initial.x[op['rn']]
    if op['rn'] == 31 and base % 16:
        return state, bytes(ram), {'kind': 'sp_alignment', 'address': base}
    start, width = base - ram_address, op['element_bytes']
    old = [bytearray(struct.pack('<2Q', *initial.v[reg])) for reg in range(32)]
    new = [bytearray(value) for value in old]
    qemu_ld1 = policy == 'qemu' and op['layout'] == 'multiple' and op['structures'] == 1
    unit = 8 if qemu_ld1 else width
    accesses = op['total_bytes'] // unit
    for ordinal in range(accesses):
        offset = ordinal * unit
        if op['layout'] == 'multiple':
            if qemu_ld1:
                run, lane = divmod(offset, op['vector_bytes'])
                reg, lane_offset = (op['rt'] + run) % 32, lane
            else:
                # Invert the memory layout rather than consuming a production
                # schedule: contiguous LD1 registers, interleaved LD2/3/4 lanes.
                run, within = divmod(ordinal, op['vector_bytes'] // width * op['structures'])
                lane, structure = divmod(within, op['structures'])
                reg, lane_offset = (op['rt'] + run + structure) % 32, lane * width
        else:
            reg, lane_offset = (op['rt'] + ordinal) % 32, op['index'] * width
        position = start + offset
        valid = not readonly or op['loading']
        successful = valid and 0 <= position and position + unit <= limit
        if not successful:
            if not op['loading'] and policy == 'source' and valid and 0 <= position < limit:
                count = min(unit, limit - position)
                ram[position:position + count] = old[reg][lane_offset:lane_offset + count]
            address = ram_address + max(position, limit) if valid and position >= 0 else base + offset
            return state, bytes(ram), {'kind': 'memory', 'address': address, 'ordinal': ordinal, 'element_bytes': unit,
                                     'element_address': base + offset}
        if op['loading']:
            value = ram[position:position + unit]
            if op['layout'] == 'replicate':
                new[reg][:] = value * (op['vector_bytes'] // width) + bytes(16 - op['vector_bytes'])
            else:
                new[reg][lane_offset:lane_offset + unit] = value
                if op['layout'] == 'multiple' and op['vector_bytes'] == 8 and policy == 'source':
                    new[reg][8:] = bytes(8)
            state.v[reg][:] = struct.unpack('<2Q', new[reg])
        else:
            ram[position:position + unit] = old[reg][lane_offset:lane_offset + unit]
    if op['loading'] and op['layout'] == 'multiple' and op['vector_bytes'] == 8 and policy == 'qemu':
        for slot in range(op['runs'] * op['structures']):
            state.v[(op['rt'] + slot) % 32][1] = 0
    if op['mode'] != 'offset':
        increment = op['total_bytes'] if op['mode'] == 'immediate' else initial.x[op['rm']]
        if op['rn'] == 31:
            state.sp = (base + increment) & MASK
        else:
            state.x[op['rn']] = (base + increment) & MASK
    return state, bytes(ram), None


def fault_cases():
    """All shape boundaries, plus every interleaving stage and byte cut."""
    result = []
    for function, op in enumerate(shapes()):
        width, total = op['element_bytes'], op['total_bytes']
        cuts = {0, total - width, (total // width // 2) * width}
        cuts.update(range(1, min(total, width * op['structures']) + 1))
        for cut in sorted(cuts - {total}):
            result.append({'function': function, 'cut': cut, 'protection': 'structure_crossing' if cut else 'guard'})
        if not op['loading']:
            result.append({'function': function, 'cut': 0, 'protection': 'readonly'})
    return result


def inventory():
    ops, cases = corpus()
    return {'canonical_forms': len(CANONICAL_FORMS), 'shape_index_arrangements': dict(Counter(op['layout'] for op in shapes())),
            'functions': len(ops), 'success_cases': len(cases), 'fault_cases': len(fault_cases()),
            'ram_bytes': RAM_BYTES, 'state_bytes': STATE_BYTES}
