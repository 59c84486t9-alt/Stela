#!/usr/bin/env python3
"""Three-way Apple A64 integer math: mathematical oracle, ARM, native x86."""
import argparse
import ctypes
import hashlib
import itertools
from functools import reduce
import json
import multiprocessing
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import state_dict as complete_state
from differential import ROOT, State, executable, reference, states
from evidence import write_evidence

RET = 0xd65f03c0
MASK = (1 << 64) - 1
MULTIPLY_FORMS = {
    'MADD32': 0x1b000000, 'MSUB32': 0x1b008000,
    'MADD64': 0x9b000000, 'MSUB64': 0x9b008000,
    'SMADDL': 0x9b200000, 'SMSUBL': 0x9b208000,
    'UMADDL': 0x9ba00000, 'UMSUBL': 0x9ba08000,
    'SMULH': 0x9b400000, 'UMULH': 0x9bc00000,
}
DIVIDE_FORMS = {'SDIV32': 0x1ac00c00, 'SDIV64': 0x9ac00c00,
                'UDIV32': 0x1ac00800, 'UDIV64': 0x9ac00800}
UNARY_FORMS = {'CLZ32': 0x5ac01000, 'CLZ64': 0xdac01000,
               'REV32': 0x5ac00800, 'REV16_32': 0x5ac00400,
               'CLS32': 0x5ac01400, 'CLS64': 0xdac01400,
               'RBIT32': 0x5ac00000, 'RBIT64': 0xdac00000,
               'REV64': 0xdac00c00, 'REV16_64': 0xdac00400, 'REV32_64': 0xdac00800}
CRC_FORMS = {'CRC32B': 0x1ac04000, 'CRC32H': 0x1ac04400,
             'CRC32W': 0x1ac04800, 'CRC32X': 0x9ac04c00,
             'CRC32CB': 0x1ac05000, 'CRC32CH': 0x1ac05400,
             'CRC32CW': 0x1ac05800, 'CRC32CX': 0x9ac05c00}
FORMS = {**MULTIPLY_FORMS, **DIVIDE_FORMS, **UNARY_FORMS, **CRC_FORMS}
MNEMONICS = {'madd', 'msub', 'mul', 'mneg', 'smaddl', 'smsubl', 'smull', 'smnegl',
              'umaddl', 'umsubl', 'umull', 'umnegl', 'smulh', 'umulh', 'sdiv', 'udiv',
              'clz', 'cls', 'rbit', 'rev', 'rev16', 'rev32', 'ret',
              'crc32b', 'crc32h', 'crc32w', 'crc32x', 'crc32cb', 'crc32ch', 'crc32cw', 'crc32cx'}


def encoding(form, destination, left, right=0, accumulator=31):
    if form in UNARY_FORMS:
        return FORMS[form] | (left << 5) | destination
    return (FORMS[form] | (right << 16) | (0 if form in DIVIDE_FORMS or form in CRC_FORMS else accumulator << 10)
            | (left << 5) | destination)


def cases():
    result = []
    overlaps = [(0, 1, 2, 3), (1, 1, 2, 3), (2, 1, 2, 3), (3, 1, 2, 3),
                (1, 1, 1, 1), (0, 1, 1, 3), (0, 1, 2, 1), (0, 1, 2, 2),
                (31, 1, 2, 3), (0, 31, 2, 3), (0, 1, 31, 3),
                (0, 1, 2, 31), (0, 31, 31, 31), (31, 31, 31, 31)]
    for form in MULTIPLY_FORMS:
        for destination in range(32):
            result.append({'form': form, 'kind': 'all_registers',
                           'words': [encoding(form, destination, (destination + 5) % 32,
                                              (destination + 13) % 32, (destination + 19) % 32), RET]})
        for destination, left, right, accumulator in overlaps:
            result.append({'form': form, 'kind': 'overlap_or_zero',
                           'words': [encoding(form, destination, left, right, accumulator), RET]})
        result.append({'form': form, 'kind': 'boundaries',
                       'words': [encoding(form, 0, 1, 2, 3), RET]})
        # Results feed later inputs in each role; final Rd=Ra aliases the
        # accumulator while earlier results remain visible in complete state.
        result.append({'form': form, 'kind': 'dependency_chain',
                       'words': [encoding(form, 0, 1, 2, 3), encoding(form, 4, 0, 0, 0),
                                 encoding(form, 3, 4, 0, 3), RET]})
    # All ignored Ra fields must behave alike for both high-product opcodes.
    for form in ('SMULH', 'UMULH'):
        for accumulator in range(32):
            result.append({'form': form, 'kind': 'ignored_accumulator',
                           'words': [encoding(form, 0, 1, 2, accumulator), RET]})
    assert len(result) == 544, 'Preserve every original multiply program'
    overlaps = [(0, 1, 2), (1, 1, 2), (2, 1, 2), (1, 1, 1),
                (0, 1, 1), (31, 1, 2), (0, 31, 2), (0, 1, 31),
                (0, 31, 31), (31, 31, 31), (30, 30, 30), (0, 0, 0)]
    for form in DIVIDE_FORMS:
        for destination in range(32):
            result.append({'form': form, 'kind': 'all_registers',
                           'words': [encoding(form, destination, (destination + 5) % 32,
                                              (destination + 13) % 32), RET]})
        for destination, left, right in overlaps:
            result.append({'form': form, 'kind': 'overlap_or_zero',
                           'words': [encoding(form, destination, left, right), RET]})
        result.append({'form': form, 'kind': 'boundaries',
                       'words': [encoding(form, 0, 1, 2), RET]})
        result.append({'form': form, 'kind': 'dependency_chain',
                       'words': [encoding(form, 0, 1, 2), encoding(form, 4, 0, 0),
                                 encoding(form, 1, 4, 0), encoding(form, 0, 0, 1), RET]})
        # q = n / d; r = n - q*d, preserving all quotient and remainder state.
        result.append({'form': form, 'kind': 'remainder_combo',
                       'words': [encoding(form, 4, 1, 2),
                                 encoding('MSUB' + form[-2:], 0, 4, 2, 1), RET]})
        other = ('UDIV' if form.startswith('SDIV') else 'SDIV') + form[-2:]
        result.append({'form': form, 'kind': 'mixed_signedness_chain',
                       'words': [encoding(form, 0, 1, 2), encoding(other, 4, 0, 2),
                                 encoding(form, 2, 4, 0), RET]})
        # Cross exceptional operands with actual encoded aliases. Rn==Rm can
        # only observe one value; ZR cannot be initialized to a requested value.
        for destination, left, right in ((1, 1, 2), (2, 1, 2), (31, 1, 2),
                                          (1, 1, 1), (0, 1, 1), (0, 31, 2),
                                          (0, 1, 31), (31, 31, 31)):
            result.append({'form': form, 'kind': 'alias_boundaries',
                           'words': [encoding(form, destination, left, right), RET]})
    assert len(result) == 768, 'Preserve every original multiply/divide program'
    for form in UNARY_FORMS:
        # All 1,024 Rd/Rn encodings, grouped by destination to avoid 4,096 CLI
        # launches. Sequential alias effects are evaluated by both oracles.
        for destination in range(32):
            result.append({'form': form, 'kind': 'all_register_pairs',
                           'words': [encoding(form, destination, source)
                                     for source in range(32)] + [RET]})
            result.append({'form': form, 'kind': 'in_place',
                           'words': [encoding(form, destination, destination), RET]})
        for destination, source in ((0, 1), (1, 1), (31, 1), (0, 31), (31, 31), (30, 30)):
            result.append({'form': form, 'kind': 'unary_boundaries',
                           'words': [encoding(form, destination, source), RET]})
        result.append({'form': form, 'kind': 'unary_dependency_chain',
                       'words': [encoding(form, 0, 1), encoding(form, 4, 0),
                                 encoding(form, 2, 2), encoding(form, 0, 4),
                                 encoding(form, 31, 0), encoding(form, 0, 31), RET]})
    result.append({'form': 'CLZ64', 'kind': 'mixed_unary_chain',
                   'words': [encoding('REV16_32', 0, 1), encoding('CLZ64', 4, 0),
                             encoding('REV32', 2, 0), encoding('CLZ32', 0, 2), RET]})
    result.extend(crc_cases())
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        for word in case['words']:
            decoded = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if decoded is None or decoded.mnemonic not in MNEMONICS:
                raise AssertionError(f'Independent decoder rejected {word:#x}')
    return result


def crc_cases():
    result = []
    for form in CRC_FORMS:
        for destination in range(32):
            result.append({'form': form, 'kind': 'all_registers',
                           'words': [encoding(form, destination, (destination + 5) % 32,
                                              (destination + 13) % 32), RET]})
        for destination, left, right in ((0, 1, 2), (1, 1, 2), (2, 1, 2), (1, 1, 1),
                                          (0, 1, 1), (31, 1, 2), (0, 31, 2), (0, 1, 31),
                                          (0, 31, 31), (31, 31, 31), (30, 30, 30), (0, 0, 0)):
            result.append({'form': form, 'kind': 'crc_boundaries',
                           'words': [encoding(form, destination, left, right), RET]})
        result.append({'form': form, 'kind': 'dependency_chain',
                       'words': [encoding(form, 0, 1, 2), encoding(form, 4, 0, 0),
                                 encoding(form, 2, 4, 2), encoding(form, 0, 2, 4), RET]})
        if form in ('CRC32B', 'CRC32CB'):
            result.append({'form': form, 'kind': 'crc_table_entries',
                           'words': [encoding(form, 0, 1, 2), RET]})
    return result


def crc_reference(accumulator, value, bits, castagnoli):
    """Independent literal Arm reflection + unbounded polynomial long division.

    This does not reproduce the emitter's reflected nibble-table recurrence.
    Neither initial nor final XOR belongs to a single architectural CRC update.
    """
    def reverse(number, width):
        return int(f'{number & ((1 << width) - 1):0{width}b}'[::-1], 2)
    dividend = (reverse(accumulator, 32) << bits) ^ (reverse(value, bits) << 32)
    polynomial = (1 << 32) | CRC_NORMAL_POLYNOMIALS[castagnoli]
    while dividend.bit_length() > 32:
        dividend ^= polynomial << (dividend.bit_length() - 33)
    return reverse(dividend, 32)


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def quotient(numerator, denominator, bits, is_signed):
    """Unbounded integer oracle; no float or Python floor-division sign rule."""
    mask = (1 << bits) - 1
    numerator, denominator = numerator & mask, denominator & mask
    if denominator == 0:
        return 0
    if is_signed:
        numerator, denominator = signed(numerator, bits), signed(denominator, bits)
        value = abs(numerator) // abs(denominator)
        if (numerator < 0) != (denominator < 0):
            value = -value
    else:
        value = numerator // denominator
    # In particular signed MIN/-1 wraps to MIN, rather than trapping as IDIV does.
    return value & mask


def unary_reference(form, value):
    bits = 64 if form.endswith('64') else 32
    value &= (1 << bits) - 1
    if form.startswith('CLZ'):
        return bits - value.bit_length()
    if form.startswith('CLS'):
        digits = f'{value:0{bits}b}'
        return len(list(itertools.takewhile(lambda b: b == digits[0], digits))) - 1
    if form.startswith('RBIT'):
        return int(f'{value:0{bits}b}'[::-1], 2)
    # Independent byte-array transformations, not the emitter's BSWAP/ROR path.
    data = value.to_bytes(bits // 8, 'little')
    group = 2 if form.startswith('REV16_') else 4 if form == 'REV32_64' else len(data)
    return int.from_bytes(b''.join(data[i:i+group][::-1] for i in range(0, len(data), group)), 'little')


def mathematical_reference(words, initial):
    registers = list(initial.x)
    for word in words[:-1]:
        destination, left, right, accumulator = (word & 31, (word >> 5) & 31,
                                                 (word >> 16) & 31, (word >> 10) & 31)
        operands = [registers[r] if r != 31 else 0 for r in (left, right, accumulator)]
        first, second, added = operands
        bits = 64 if word >> 31 else 32
        unary = next((form for form, base in UNARY_FORMS.items()
                      if word & 0xfffffc00 == base), None)
        if unary is not None:
            if destination != 31:
                registers[destination] = unary_reference(unary, first)
            continue
        if word & CRC_CLASS_MASK == CRC_CLASS_VALUE:
            value = crc_reference(first, second, crc_data_bits(word), bool(word & CRC_CASTAGNOLI_BIT))
            if destination != 31:
                registers[destination] = value
            continue
        if word & 0x7fe0f800 == 0x1ac00800:
            value = quotient(first, second, bits, bool(word & (1 << 10)))
            if destination != 31:
                registers[destination] = value
            continue
        opcode = (word >> 21) & 7
        if opcode == 0:
            mask = (1 << bits) - 1
            product = (first & mask) * (second & mask)
        elif opcode in (1, 5):
            mask = MASK
            product = (signed(first, 32) * signed(second, 32) if opcode == 1 else
                       (first & 0xffffffff) * (second & 0xffffffff))
        elif opcode in (2, 6):
            mask = MASK
            product = (signed(first, 64) * signed(second, 64) if opcode == 2 else first * second)
            product >>= 64
            added = 0  # Ra is ignored even if its encoding is noncanonical.
        else:
            raise AssertionError('Unexpected mathematical fixture opcode')
        value = (added - product if word & (1 << 15) else added + product) & mask
        if destination != 31:
            registers[destination] = value
    return {**complete_state(initial), 'x': registers, 'sp': initial.sp, 'nzcv': initial.nzcv, 'reserved': initial.reserved}


def native_state(code, initial):
    state = State.from_buffer_copy(initial)
    with executable(code) as address:
        ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(address)(ctypes.byref(state))
    return complete_state(state)


def boundary_values(form):
    bits = 32 if form.endswith('32') or form.endswith('L') else 64
    sign, mask = 1 << (bits - 1), (1 << bits) - 1
    if form in UNARY_FORMS:
        if form.startswith(('CLZ', 'CLS', 'RBIT')):
            values = [0] + [1 << bit for bit in range(bits)]
            values += [(1 << bit) - 1 for bit in range(1, bits + 1)]
            if not form.startswith('CLZ'):
                values += [mask ^ value for value in values]
        else:
            values = [0, 1, mask, 0x01234567, 0x89abcdef, 0xaabbccdd,
                      0x00112233, 0xff00ff00, 0x00ff00ff, 0x80000000,
                      0x00008000, 0x7fffffff, 0x0000ffff, 0xffff0000,
                      0xaaaaaaaa, 0x55555555]
            if bits == 64:
                values += [0x0123456789abcdef, 0xff00ff0000ff00ff, 0x8000000000000000,
                           0xaaaaaaaa55555555, 0xffff00000000ffff]
        return ((value, 0, 0) for value in dict.fromkeys(values))
    values = (0, 1, 2, sign - 1, sign, mask, 0xaaaaaaaaaaaaaaaa & mask,
              0x5555555555555555 & mask)
    if form in DIVIDE_FORMS:
        values += (3, sign + 1, mask - 1, mask - 2)
        return ((n, d, 0) for n, d in itertools.product(values, values))
    accumulators = (0,) if form.endswith('H') else (0, 1, MASK, 1 << 63)
    return itertools.product(values, values, accumulators)


def case_boundaries(case):
    if case['kind'] == 'crc_table_entries':
        return [(0, byte, 0) for byte in range(1 << CRC_BYTE_BITS)]
    if case['kind'] == 'crc_boundaries':
        bits = crc_data_bits(FORMS[case['form']])
        values = [0, (1 << bits) - 1, 1 << (bits - 1), 0x0123456789abcdef & ((1 << bits) - 1)]
        # Every input bit and every accumulator bit independently affects CRC.
        return [(a, v, 0) for a in (0, 1, 0xffffffff, 0x80000000) for v in values] + [
            (0, 1 << bit, 0) for bit in range(bits)] + [(1 << bit, 0, 0) for bit in range(32)]
    if case['kind'] == 'unary_boundaries':
        return boundary_values(case['form'])
    if case['kind'] in ('boundaries', 'remainder_combo'):
        return boundary_values(case['form'])
    if case['kind'] == 'alias_boundaries':
        bits = 32 if case['form'].endswith('32') else 64
        minimum, minus_one = 1 << (bits - 1), (1 << bits) - 1
        return ((n, d, 0) for n, d in ((0, 0), (minimum, minus_one),
                                      (minimum, 1), (minus_one, minimum),
                                      (minimum, 0), (minus_one, 0),
                                      (3, 2), (minus_one - 2, 2), (3, minus_one - 1)))
    return [None]


def initialize_boundary(case, state, boundary):
    poison = 0xdeadc0de00000000 if case['form'].endswith(('32', 'L')) else 0
    if case['form'] in CRC_FORMS:
        left, right = (case['words'][0] >> 5) & 31, (case['words'][0] >> 16) & 31
        if left != 31:
            state.x[left] = boundary[0] | 0xdeadc0de00000000
        if right != 31 and right != left:
            bits = crc_data_bits(FORMS[case['form']])
            state.x[right] = boundary[1] | (MASK ^ ((1 << bits) - 1))
        return
    if case['kind'] == 'unary_boundaries':
        source = (case['words'][0] >> 5) & 31
        if source != 31:
            state.x[source] = boundary[0] | poison
        return
    if case['kind'] != 'alias_boundaries':
        state.x[1], state.x[2], state.x[3] = (boundary[0] | poison,
                                              boundary[1] | poison, boundary[2])
        return
    word = case['words'][0]
    left, right = (word >> 5) & 31, (word >> 16) & 31
    if left != 31:
        state.x[left] = boundary[0] | poison
    if right != 31 and right != left:
        state.x[right] = boundary[1] | poison


def execute_cases(compiled):
    comparisons = 0
    counts = {'multiply': {'programs': 0, 'comparisons': 0},
              'divide': {'programs': 0, 'comparisons': 0},
              'unary': {'programs': 0, 'comparisons': 0},
              'crc': {'programs': 0, 'comparisons': 0}}
    crc_profiles = {target: {'programs': 0, 'comparisons': 0}
                    for target in ('baseline', 'sse4.2')}
    group_corpora = {name: hashlib.sha256() for name in counts}
    legacy_corpus = hashlib.sha256()
    incoming = states(all_flags=True)
    corpus = hashlib.sha256()
    rng = random.Random(0x534f52455454414d)
    # Independently generated whole-register states add cases unrelated to the
    # shared test runner's seed, with all valid incoming architectural NZCV bits.
    for index in range(16):
        state = State()
        for register in range(31):
            state.x[register] = rng.getrandbits(64)
        state.sp, state.nzcv, state.reserved = (rng.getrandbits(64) & ~15, index << 28,
                                                rng.getrandbits(32))
        incoming.append(state)
    for case in compiled:
        group_name = ('crc' if case['form'] in CRC_FORMS else 'unary' if case['form'] in UNARY_FORMS else
                      'divide' if case['form'] in DIVIDE_FORMS else 'multiply')
        group = counts[group_name]
        group['programs'] += 1
        if group_name == 'crc':
            crc_profiles[case['target_cpu']]['programs'] += 1
        code = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        boundaries = case_boundaries(case)
        for boundary in boundaries:
            # Boundaries exercise all 16 flags; ordinary/overlap/chain cases
            # also exercise seeded random states across every register.
            for initial in incoming[:16] if boundary is not None else incoming:
                state = State.from_buffer_copy(initial)
                if boundary is not None:
                    initialize_boundary(case, state, boundary)
                corpus.update(code)
                corpus.update(bytes(state))
                group_corpora[group_name].update(code)
                group_corpora[group_name].update(bytes(state))
                if group_name in ('multiply', 'divide'):
                    legacy_corpus.update(code)
                    legacy_corpus.update(bytes(state))
                expected_math = mathematical_reference(case['words'], state)
                expected_arm = {**reference(code, state), 'reserved': state.reserved}
                actual = native_state(case['native'], state)
                if expected_math != expected_arm or expected_arm != actual:
                    raise AssertionError(json.dumps({**{k: v for k, v in case.items() if k != 'native'},
                                                     'initial': list(state.x), 'incoming_nzcv': state.nzcv,
                                                     'mathematical': expected_math, 'arm': expected_arm,
                                                     'native': actual}, indent=2))
                comparisons += 1
                group['comparisons'] += 1
                if group_name == 'crc':
                    crc_profiles[case['target_cpu']]['comparisons'] += 1
    assert counts['multiply'] == {'programs': 544, 'comparisons': 51904}
    assert counts['divide'] == {'programs': 224, 'comparisons': 28928}
    for name, group in counts.items():
        group['state_corpus_sha256'] = group_corpora[name].hexdigest()
    return {'programs': len(compiled), 'three_way_register_state_comparisons': comparisons,
            'groups': counts, 'crc_profiles': crc_profiles, 'state_corpus_sha256': corpus.hexdigest(),
            'legacy_multiply_divide_state_corpus_sha256': legacy_corpus.hexdigest()}


def worker(pipe, compiled):
    try:
        pipe.send(execute_cases(compiled))
    except BaseException as error:
        pipe.send({'error': repr(error)})
    finally:
        pipe.close()


def bounded_cases(compiled):
    context = multiprocessing.get_context('spawn')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, compiled))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + 600
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'Integer-math worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'Integer-math suite failed: {result}, exit={process.exitcode}')
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def unary_blocks(cli, directory, forms=UNARY_FORMS, target='native'):
    """Unchanged ARM RET and native shared block dispatch, with disk reuse."""
    from differential import initialize_arm, capture_arm, seed_extended_state
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import arm64_const as arm
    base, stop = 0x100000, 0x100800
    source, state_path = directory / 'unary.arm64', directory / 'unary-state.json'
    rows = []
    incoming = states(all_flags=True)[:16]
    for form in forms:
        words = [encoding(form, 0, 1, 2), RET]
        code = struct.pack('<2I', *words)
        source.write_bytes(code)
        for flag, template in enumerate(incoming):
            initial = State.from_buffer_copy(template)
            seed_extended_state(initial, (flag + FORMS[form]).to_bytes(8, 'little'))
            initial.nzcv = flag << 28
            initial.x[1] = (0, MASK, 1 << 63, 0x0123456789abcdef)[flag % 4]
            initial.x[30] = stop
            expected = mathematical_reference(words, initial)
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            machine.mem_map(base, 4096); machine.mem_write(base, code)
            machine.reg_write(arm.UC_ARM64_REG_PSTATE, 0)
            initialize_arm(machine, initial)
            machine.emu_start(base, stop, count=4)
            assert machine.reg_read(arm.UC_ARM64_REG_PC) == stop
            assert complete_state(capture_arm(machine, initial)) == expected
            state_path.write_text(json.dumps(complete_state(initial)))
            native = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source),
                '--state', str(state_path), '--guest-base', hex(base), '--stop-pc', hex(stop),
                '--block-budget', '1', '--cpu-target', target,
                '--cache-dir', str(directory / ('unary-cache-' + target))], timeout=15))
            assert native['state'] == expected and native['pc'] == stop
            assert native['source_sha256'] == hashlib.sha256(code).hexdigest()
            assert native['abi'] == 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
            assert native['complete_binary_verified'] is False
            outcome = native['outcome']
            assert outcome['reason'] == {'kind': 'stop_address'} and outcome['blocks_executed'] == 1
            assert outcome['compiled_blocks'] == int(flag == 0) and outcome['disk_cache_hits'] == int(flag != 0)
            rows.append({'form': form, 'flags': flag, 'target': target, 'original': expected, 'native': native})
    return rows


# Own research encodings. Each opcode/operand assignment is defined once here;
# candidate algorithms below name the operation instead of spelling machine bytes.
CRC_X86 = {
    'load_accumulator_rdi': bytes.fromhex('488b87'),
    'load_data_rdi': bytes.fromhex('488b8f'),
    'store_result_rdi': bytes.fromhex('488987'),
    'truncate_byte_data': bytes.fromhex('0fb6c9'),
    'truncate_halfword_data': bytes.fromhex('0fb7c9'),
    'table_base_rip': bytes.fromhex('4c8d05'),
    'merge_word_data': bytes.fromhex('31c8'),
    'select_high_data_word': bytes.fromhex('48c1e920'),
    'index_low_byte': bytes.fromhex('0fb6d0'),
    'index_low_nibble': bytes.fromhex('89c283e20f'),
    'shift_accumulator_byte': bytes.fromhex('c1e808'),
    'shift_accumulator_nibble': bytes.fromhex('c1e804'),
    'xor_table_entry': bytes.fromhex('41330490'),
    'shift_accumulator_bit': bytes.fromhex('d1e8'),
    'carry_bit_mask': bytes.fromhex('19d2'),
    'mask_polynomial_imm32': bytes.fromhex('81e2'),
    'xor_remainder_mask': bytes.fromhex('31d0'),
    'jump_table_rel32': bytes.fromhex('e9'),
    'return': bytes.fromhex('c3'),
}
CRC_SIZE_SHIFT, CRC_SIZE_MASK = 10, 3
CRC_CASTAGNOLI_BIT, CRC_DOUBLEWORD_BIT = 1 << 12, 1 << 31
CRC_CLASS_MASK, CRC_CLASS_VALUE = 0x7fe0e000, 0x1ac04000
CRC_REFLECTED_POLYNOMIALS = {False: 0xedb88320, True: 0x82f63b78}
CRC_NORMAL_POLYNOMIALS = {False: 0x04c11db7, True: 0x1edc6f41}
CRC_ACCUMULATOR_BITS, CRC_WORD_BITS, CRC_BYTE_BITS = 32, 32, 8
CRC_REGISTER_BYTES, CRC_TABLE_ENTRY_BYTES = 8, 4
CRC_BENCHMARK_CALLS, CRC_BENCHMARK_SAMPLES = 1000000, 7


def crc_data_bits(word):
    return CRC_BYTE_BITS << ((word >> CRC_SIZE_SHIFT) & CRC_SIZE_MASK)


def crc_supported_targets(cli):
    """Use the compiler's CPUID-checked native target, never assumed host flags."""
    with tempfile.TemporaryDirectory(prefix='stela-crc-capability-') as temporary:
        directory = Path(temporary)
        source = directory / 'probe.arm64'
        source.write_bytes(struct.pack('<II', CRC_FORMS['CRC32CB'], RET))
        manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(source),
            '--cpu-target', 'native', '--output-dir', str(directory / 'output')]))
    native = manifest['target_cpu']
    available = 'sse4.2' in native.split('+')
    targets = ['baseline', 'sse4.2'] if available else ['baseline']
    return targets, {'native_target': native, 'sse4.2_available': available,
                     'checked_profile': 'executed' if available else 'unavailable; no hardware comparison credit'}


def crc_candidate(form, dependent, table_bits):
    """Research-only register recurrence, sharing the full native GuestState ABI."""
    bits = crc_data_bits(CRC_FORMS[form])
    poly = CRC_REFLECTED_POLYNOMIALS[bool(CRC_FORMS[form] & CRC_CASTAGNOLI_BIT)]
    code = bytearray()
    def emit(name):
        code.extend(CRC_X86[name])
    emit('load_accumulator_rdi')
    code.extend(struct.pack('<I', 0 if dependent else CRC_REGISTER_BYTES))
    emit('load_data_rdi')
    code.extend(struct.pack('<I', 2 * CRC_REGISTER_BYTES))
    if bits < CRC_WORD_BITS:
        emit('truncate_byte_data' if bits == CRC_BYTE_BITS else 'truncate_halfword_data')
    address_patch = None
    if table_bits:
        emit('table_base_rip')
        address_patch = len(code)
        code.extend(bytes(struct.calcsize('<i')))
    emit('merge_word_data')
    for part in range(2 if bits > CRC_WORD_BITS else 1):
        if part:
            emit('select_high_data_word')
            emit('merge_word_data')
        for _ in range(min(bits, CRC_WORD_BITS) // (table_bits or 1)):
            if table_bits:
                suffix = 'byte' if table_bits == CRC_BYTE_BITS else 'nibble'
                emit('index_low_' + suffix)
                emit('shift_accumulator_' + suffix)
                emit('xor_table_entry')
            else:
                emit('shift_accumulator_bit')
                emit('carry_bit_mask')
                emit('mask_polynomial_imm32')
                code.extend(struct.pack('<I', poly))
                emit('xor_remainder_mask')
    if table_bits:
        emit('jump_table_rel32')
        code.extend(struct.pack('<i', CRC_TABLE_ENTRY_BYTES << table_bits))
        struct.pack_into('<i', code, address_patch, len(code) - address_patch - struct.calcsize('<i'))
        for entry in range(1 << table_bits):
            remainder = entry
            for _ in range(table_bits):
                remainder = (remainder >> 1) ^ (poly if remainder & 1 else 0)
            code.extend(struct.pack('<I', remainder))
    emit('store_result_rdi')
    code.extend(struct.pack('<I', 0))
    emit('return')
    return bytes(code)


def crc_reserved(cli, directory, targets):
    from differential import initialize_arm, capture_arm
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_ERR_EXCEPTION
    from unicorn import arm64_const as arm
    base = 0x100000
    original_checks, native_declines = 0, 0
    for form, valid in CRC_FORMS.items():
        invalid = valid ^ CRC_DOUBLEWORD_BIT
        source = directory / 'reserved.arm64'
        source.write_bytes(struct.pack('<II', invalid, RET))
        for initial in states(all_flags=True)[:16]:
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            machine.mem_map(base, 4096)
            machine.mem_write(base, source.read_bytes())
            initialize_arm(machine, initial)
            try:
                machine.emu_start(base, base + 4, count=1)
            except UcError as error:
                assert error.errno == UC_ERR_EXCEPTION
            else:
                raise AssertionError(f'Reserved CRC encoding executed: {form}')
            assert machine.reg_read(arm.UC_ARM64_REG_PC) == base
            assert complete_state(capture_arm(machine, initial)) == complete_state(initial)
            original_checks += 1
        for target in targets:
            output = directory / f'reserved-{form}-{target}'
            process = subprocess.run([str(cli), 'compile-leaf', str(source), '--cpu-target', target,
                                      '--output-dir', str(output)], capture_output=True, text=True)
            assert process.returncode != 0 and 'unsupported' in process.stderr.lower()
            assert not output.exists()
            native_declines += 1
    return {'reserved_forms': len(CRC_FORMS), 'original_undefined_full_state_pc_checks': original_checks,
            'native_explicit_declines': native_declines,
            'limits': 'Unicorn undefined exception with unchanged modeled state; guest exception delivery is outside profile.'}


def crc_repeated_state(form, dependent, state, calls):
    """Independent GF(2) affine powering checks dependent timed final state."""
    bits = crc_data_bits(CRC_FORMS[form])
    castagnoli = bool(CRC_FORMS[form] & CRC_CASTAGNOLI_BIT)
    result = complete_state(state)
    if not dependent:
        result['x'][0] = crc_reference(state.x[1], state.x[2], bits, castagnoli)
        return result
    constant = crc_reference(0, state.x[2], bits, castagnoli)
    columns = [crc_reference(1 << bit, state.x[2], bits, castagnoli) ^ constant
               for bit in range(CRC_ACCUMULATOR_BITS)]
    def apply(matrix, value):
        return reduce(int.__xor__,
            (column for bit, column in enumerate(matrix) if value & (1 << bit)), 0)
    value = state.x[0] & 0xffffffff
    while calls:
        if calls & 1:
            value = apply(columns, value) ^ constant
        constant = apply(columns, constant) ^ constant
        columns = [apply(columns, column) for column in columns]
        calls >>= 1
    result['x'][0] = value
    return result


def crc_mapping_benchmark(cli):
    """Actual translated output and rejected baseline candidates, timed inside C."""
    from capstone import CS_ARCH_X86, CS_MODE_64
    import platform
    import statistics
    from contextlib import ExitStack
    root = ROOT / '.stela/research/crc-mapping' / str(time.time_ns())
    root.mkdir(parents=True, exist_ok=True)
    library_path = root / ('timing.dylib' if platform.system() == 'Darwin' else 'timing.so')
    command = ['clang', '-O3', '-std=c11', '-fPIC', '-Wall', '-Wextra', '-Werror',
               '-dynamiclib' if platform.system() == 'Darwin' else '-shared',
               str(ROOT / 'dev/native-benchmark.c'), '-o', str(library_path)]
    subprocess.run(command, check=True)
    library = ctypes.CDLL(str(library_path))
    function_type = ctypes.CFUNCTYPE(None, ctypes.POINTER(State))
    library.stela_benchmark.argtypes = [function_type, ctypes.POINTER(State), ctypes.c_uint64,
                                        ctypes.POINTER(ctypes.c_uint64)]
    library.stela_benchmark.restype = ctypes.c_uint64
    targets, host_capability = crc_supported_targets(cli)
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    rows, compiler = [], None
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    for form in CRC_FORMS:
        for dependent in (False, True):
            source = struct.pack('<II', encoding(form, 0, 0 if dependent else 1, 2), RET)
            source_path = root / 'source.arm64'
            source_path.write_bytes(source)
            recipes = {}
            for target in targets:
                output = root / f'{form}-{int(dependent)}-{target}-output'
                manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(source_path),
                    '--cpu-target', target, '--output-dir', str(output)]))
                observed = manifest['compiler_source_sha256']
                assert compiler is None or compiler == observed, 'Compiler changed during CRC mapping'
                compiler = observed
                recipes[target] = (output / 'native.bin').read_bytes()
            recipes['bit_recurrence'] = crc_candidate(form, dependent, 0)
            recipes['nibble_table'] = crc_candidate(form, dependent, 4)
            with ExitStack() as stack:
                functions = {name: function_type(stack.enter_context(executable(code)))
                             for name, code in recipes.items()}
                for name, function in functions.items():
                    for initial in states(all_flags=True):
                        state = State.from_buffer_copy(initial)
                        expected = mathematical_reference(list(struct.unpack('<II', source)), state)
                        expected_arm = {**reference(source, state), 'reserved': state.reserved}
                        function(ctypes.byref(state))
                        assert complete_state(state) == expected == expected_arm, (form, name)
                for name, code in recipes.items():
                    instructions, offset, tables, table_bases = [], 0, [], []
                    while offset < len(code):
                        instruction = next(decoder.disasm(code[offset:], offset, count=1), None)
                        assert instruction is not None
                        instructions.append([offset, instruction.mnemonic, instruction.op_str])
                        if instruction.mnemonic == 'lea':
                            table_bases.append(instruction.address + instruction.size + instruction.operands[1].mem.disp)
                        offset += instruction.size
                        if instruction.mnemonic == 'jmp':
                            target = int(instruction.op_str, 0)
                            tables.append([offset, target])
                            offset = target
                        if instruction.mnemonic == 'ret':
                            break
                    assert offset == len(code)
                    assert table_bases == [start for start, end in tables]
                    for start, end in tables:
                        table_bits = (end - start).bit_length() - 1 - 2
                        for entry in range(1 << table_bits):
                            observed, = struct.unpack_from('<I', code, start + entry * CRC_TABLE_ENTRY_BYTES)
                            if table_bits == CRC_BYTE_BITS:
                                assert observed == crc_reference(0, entry, CRC_BYTE_BITS,
                                                               bool(CRC_FORMS[form] & CRC_CASTAGNOLI_BIT))
                    assert name != 'baseline' or not any(i[1] == 'crc32' for i in instructions)
                    path = root / f'{form}-{int(dependent)}-{name}.bin'
                    path.write_bytes(code)
                    wall_samples, cpu_samples, checksum = [], [], ctypes.c_uint64()
                    state = states(all_flags=True)[7]
                    state.x[0], state.x[1], state.x[2] = 0x89abcdef, 0x76543210, 0x0123456789abcdef
                    functions[name](ctypes.byref(state))  # warm table/code caches
                    for _ in range(CRC_BENCHMARK_SAMPLES):
                        expected_state = crc_repeated_state(form, dependent, state, CRC_BENCHMARK_CALLS)
                        cpu_start = time.process_time_ns()
                        elapsed = library.stela_benchmark(functions[name], ctypes.byref(state),
                                                           CRC_BENCHMARK_CALLS, ctypes.byref(checksum))
                        cpu_samples.append(time.process_time_ns() - cpu_start)
                        wall_samples.append(elapsed)
                        assert complete_state(state) == expected_state, (form, name, 'timed final state')
                        if not dependent:
                            assert checksum.value == (state.x[0] * CRC_BENCHMARK_CALLS) & MASK
                    rows.append({'form': form, 'dependent': dependent, 'recipe': name,
                                 'native_sha256': hashlib.sha256(code).hexdigest(),
                                 'source_sha256': hashlib.sha256(source).hexdigest(),
                                 'artifact': str(path.relative_to(ROOT)), 'bytes_without_ret': len(code) - 1,
                                 'embedded_data_bytes': sum(end - start for start, end in tables),
                                 'executable_bytes_without_ret': len(code) - 1 - sum(end - start for start, end in tables),
                                 'instructions_without_ret': len(instructions) - 1,
                                 'disassembly': instructions, 'embedded_table_ranges': tables,
                                 'calls_per_sample': CRC_BENCHMARK_CALLS, 'wall_samples_ns': wall_samples,
                                 'cpu_samples_ns': cpu_samples, 'checksum': checksum.value,
                                 'median_ns_per_call': statistics.median(wall_samples) / CRC_BENCHMARK_CALLS})
    assert executable_hash == hashlib.sha256(cli.read_bytes()).hexdigest(), 'CLI changed during CRC mapping'
    report = {'kind': 'crc_mapping_candidate_benchmark', 'host_capability': host_capability, 'passed': True, 'rows': rows,
              'compiler_source_sha256': compiler, 'host': platform.platform(),
              'clang_version': subprocess.check_output(['clang', '--version'], text=True).strip(),
              'command': command, 'timing_library_sha256': hashlib.sha256(library_path.read_bytes()).hexdigest(),
              'compiler_executable_sha256': hashlib.sha256(cli.read_bytes()).hexdigest(),
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'timing_source_sha256': hashlib.sha256((ROOT / 'dev/native-benchmark.c').read_bytes()).hexdigest(),
              'limits': 'GuestState indirect-call microbenchmark, seven warm-cache samples per recipe, '
                        'dependent accumulator and independent inputs; host instructions include state loads/stores '
                        'and table-skipping JMP; body byte counts include immutable table, exclude RET; '
                        'full-state ARM/math/native comparison precedes timing; independent GF(2) affine powering checks full state after every timed batch, independent checksum validated. CPU times include the Python/ctypes '
                        'call boundary; no baseline subtraction, application or cold-I-cache performance claim. '
                        'PCLMUL polynomial reduction is not measured or implemented; x86 CRC32 is Castagnoli only.'}
    snapshot = write_evidence(ROOT / '.stela/crc-mapping-report.json', report)
    print(json.dumps({'snapshot': str(snapshot), 'rows': len(rows), 'passed': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true', help='Use the already built CLI')
    parser.add_argument('--crc-mapping-benchmark', action='store_true',
                        help='Compare actual CRC output with baseline candidates using shared native timer')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    if arguments.crc_mapping_benchmark:
        crc_mapping_benchmark(cli)
        return
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    targets, host_capability = crc_supported_targets(cli)
    compiled = cases()
    compiled = [dict(case, target_cpu=target) for case in compiled
                for target in (targets if case['form'] in CRC_FORMS else ('baseline',))]
    compiler = None
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='stela-integer-math-') as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
            corpus.update(source)
            input_path = directory / 'source.bin'
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(input_path),
                                                          '--output-dir', str(output), '--cpu-target', case['target_cpu']]))
            if compiler is not None and compiler != manifest['compiler_source_sha256']:
                raise AssertionError('Compiler changed during integer-math suite')
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
        result = bounded_cases(compiled)
        block_cases = unary_blocks(cli, directory)
        crc_block_cases = [row for target in targets
                           for row in unary_blocks(cli, directory, CRC_FORMS, target)]
        reserved_crc = crc_reserved(cli, directory, targets)
    if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise AssertionError('Compiler executable changed during integer-math suite')
    report = {'kind': 'integer_math_arm_vs_native_x86', 'passed': True, **result,
              'operations': list(FORMS),
              'scalar_unary_forms': len(UNARY_FORMS), 'unary_block_state_comparisons': len(block_cases),
              'unary_block_cases': block_cases,
              'crc_forms': len(CRC_FORMS), 'crc_block_state_comparisons': len(crc_block_cases),
              'crc_block_cases': crc_block_cases,
              'crc_targets': targets, 'crc_host_capability': host_capability, 'crc_reserved': reserved_crc,
              'crc_three_way_register_state_comparisons': result['groups']['crc']['comparisons'],
              'reference': 'Unicorn ARM64 2.1.4 and independent unbounded signed/unsigned integer arithmetic',
              'native': 'CRC baseline byte tables and checked SSE4.2 Castagnoli; baseline x86-64 integer products, guarded division, leading-zero and byte-reversal code in isolated worker; SIGFPE and other worker failures fail the suite; no LZCNT requirement',
              'tested_state': ["V0..V31, FPCR and FPSR preservation", 'x0..x30', 'SP and reserved ABI field preservation',
                               'all 16 incoming NZCV combinations',
                               'W32 upper-half clearing', 'signed/unsigned long source truncation',
                               'ZR sources/discarded destinations', 'all destination registers',
                               'source/destination/accumulator overlaps', 'dependency chains',
                               'high 64 product bits', 'ignored high-product Ra encodings',
                               'SDIV/UDIV 32/64, truncation toward zero, zero divisors',
                               'signed MIN/-1 produces MIN without host SIGFPE',
                               'division/remainder combinations and mixed-signedness chains',
                               'All eleven scalar unary forms: CLZ/CLS/RBIT32/64, REV32/64, REV16_32/64 and REV32_64; all leading-sign counts, every one-bit reversal and byte-container patterns',
                               'all 1024 Rd/Rn unary encodings per form, in-place/discard/ZR operands',
                               'unary and mixed-width dependency chains with dirty W upper halves',
                               'CRC IEEE/Castagnoli B/H/W/X, every accumulator/data bit, all 256 byte table entries, dirty source upper bits, all register roles and aliases, original RET/native block dispatch in each supported profile',
                               'eight reserved sf/size combinations: original undefined full-state/PC preservation and native explicit declines'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'CRC uses uncomplemented polynomial remainder, all eight forms under baseline and SSE4.2; no guest memory access, full PSTATE/DIT excluded. Integer instruction results and complete GPR/SP/NZCV/reserved/V/FP state; unary cohort also executes original RET and native shared block dispatch. Full PSTATE/DIT, system instructions, guest exceptions, memory, SIMD instructions, PAC and OS boot are not covered.'}
    write_evidence(ROOT / '.stela/integer-math-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
