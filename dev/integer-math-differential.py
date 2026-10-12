#!/usr/bin/env python3
"""Three-way Apple A64 integer math: mathematical oracle, ARM, native x86."""
import argparse
import ctypes
import hashlib
import itertools
import json
import multiprocessing
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
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
FORMS = {**MULTIPLY_FORMS, **DIVIDE_FORMS}
MNEMONICS = {'madd', 'msub', 'mul', 'mneg', 'smaddl', 'smsubl', 'smull', 'smnegl',
              'umaddl', 'umsubl', 'umull', 'umnegl', 'smulh', 'umulh', 'sdiv', 'udiv', 'ret'}


def encoding(form, destination, left, right, accumulator=31):
    return (FORMS[form] | (right << 16) | (0 if form in DIVIDE_FORMS else accumulator << 10)
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
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        for word in case['words']:
            decoded = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if decoded is None or decoded.mnemonic not in MNEMONICS:
                raise AssertionError(f'Independent decoder rejected {word:#x}')
    return result


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


def mathematical_reference(words, initial):
    registers = list(initial.x)
    for word in words[:-1]:
        destination, left, right, accumulator = (word & 31, (word >> 5) & 31,
                                                 (word >> 16) & 31, (word >> 10) & 31)
        operands = [registers[r] if r != 31 else 0 for r in (left, right, accumulator)]
        first, second, added = operands
        bits = 64 if word >> 31 else 32
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
    return {'x': registers, 'sp': initial.sp, 'nzcv': initial.nzcv, 'reserved': initial.reserved}


def native_state(code, initial):
    state = State.from_buffer_copy(initial)
    with executable(code) as address:
        ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(address)(ctypes.byref(state))
    return {'x': list(state.x), 'sp': state.sp, 'nzcv': state.nzcv, 'reserved': state.reserved}


def boundary_values(form):
    bits = 32 if form.endswith('32') or form.endswith('L') else 64
    sign, mask = 1 << (bits - 1), (1 << bits) - 1
    values = (0, 1, 2, sign - 1, sign, mask, 0xaaaaaaaaaaaaaaaa & mask,
              0x5555555555555555 & mask)
    if form in DIVIDE_FORMS:
        values += (3, sign + 1, mask - 1, mask - 2)
        return ((n, d, 0) for n, d in itertools.product(values, values))
    accumulators = (0,) if form.endswith('H') else (0, 1, MASK, 1 << 63)
    return itertools.product(values, values, accumulators)


def case_boundaries(case):
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
              'divide': {'programs': 0, 'comparisons': 0}}
    group_corpora = {name: hashlib.sha256() for name in counts}
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
        group_name = 'divide' if case['form'] in DIVIDE_FORMS else 'multiply'
        group = counts[group_name]
        group['programs'] += 1
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
    assert counts['multiply'] == {'programs': 544, 'comparisons': 51904}
    for name, group in counts.items():
        group['state_corpus_sha256'] = group_corpora[name].hexdigest()
    return {'programs': len(compiled), 'three_way_register_state_comparisons': comparisons,
            'groups': counts, 'state_corpus_sha256': corpus.hexdigest()}


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true', help='Use the already built CLI')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    compiled = cases()
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
                                                          '--output-dir', str(output)]))
            if compiler is not None and compiler != manifest['compiler_source_sha256']:
                raise AssertionError('Compiler changed during integer-math suite')
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
        result = bounded_cases(compiled)
    if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise AssertionError('Compiler executable changed during integer-math suite')
    report = {'kind': 'integer_math_arm_vs_native_x86', 'passed': True, **result,
              'operations': list(FORMS),
              'reference': 'Unicorn ARM64 2.1.4 and independent unbounded signed/unsigned integer arithmetic',
              'native': 'baseline x86-64 integer products and guarded division in isolated worker; SIGFPE and other worker failures fail the suite',
              'tested_state': ['x0..x30', 'SP and reserved ABI field preservation',
                               'all 16 incoming NZCV combinations',
                               'W32 upper-half clearing', 'signed/unsigned long source truncation',
                               'ZR sources/discarded destinations', 'all destination registers',
                               'source/destination/accumulator overlaps', 'dependency chains',
                               'high 64 product bits', 'ignored high-product Ra encodings',
                               'SDIV/UDIV 32/64, truncation toward zero, zero divisors',
                               'signed MIN/-1 produces MIN without host SIGFPE',
                               'division/remainder combinations and mixed-signedness chains'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'Integer register results, SP and NZCV only. Full PSTATE, system instructions, guest exceptions, memory, SIMD, PAC, runtime dispatch and OS boot are not covered.'}
    write_evidence(ROOT / '.stela/integer-math-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
