#!/usr/bin/env python3
"""Three-way carry and extended-register arithmetic; complete architectural state."""
import hashlib
import json
import multiprocessing
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import state_dict as complete_state
from differential import compiler_cli, ROOT, State, arithmetic, native, reference, states
from evidence import write_evidence

RET = 0xd65f03c0
MASK = (1 << 64) - 1
LEGACY_CARRY_CORPUS = '5cea082d8e1f903412a26c0fc364f6508686c0f7488880531215721f92de74ab'


def encoding(width, subtract, flags, destination, left, right):
    return ((width << 31) | (subtract << 30) | (flags << 29)
            | 0x1a000000 | (right << 16) | (left << 5) | destination)


def carry_cases():
    result = []
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for destination in range(32):
                    result.append({'words': [encoding(width, subtract, flags, destination,
                                                       (destination + 5) % 32, (destination + 13) % 32), RET],
                                   'kind': 'all_registers'})
                for destination, left, right in ((0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 1, 2),
                                                 (0, 31, 2), (0, 1, 31), (0, 31, 31), (31, 31, 31),
                                                 (0, 1, 1), (30, 0, 7)):
                    result.append({'words': [encoding(width, subtract, flags, destination, left, right), RET],
                                   'kind': 'boundaries', 'width': width, 'left': left, 'right': right})
                # Low-to-high four-limb chains exercise freshly saved C and
                # deliberate nonflag carry operations that preserve guest NZCV.
                for mixed_flags in (False, True):
                    words = [encoding(width, subtract, flags if not mixed_flags else int(limb % 2 == 0),
                                      limb, limb, limb + 4) for limb in range(4)]
                    result.append({'words': words + [RET], 'kind': 'dependency_chain', 'width': width})
                # Nonflag ADD clobbers host carry before the ARM carry consumer.
                result.append({'words': [arithmetic(0, 0, width, 28, 28, 1),
                                          encoding(width, subtract, flags, 0, 31, 31), RET],
                               'kind': 'host_flag_clobber'})
                # Carry flag itself becomes a value; nonflag variants must leave
                # all incoming N/Z/V bits intact, including with discarded Rd.
                result.append({'words': [encoding(width, subtract, flags, 31, 1, 2),
                                          encoding(width, 0, 0, 0, 31, 31), RET],
                               'kind': 'discarded_result_carry_consumer'})
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        for word in case['words']:
            decoded = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if decoded is None or decoded.mnemonic not in ('adc', 'adcs', 'sbc', 'sbcs', 'ngc', 'ngcs', 'add', 'ret'):
                raise AssertionError(f'Independent decoder rejected {word:#x}')
    return result


def carry_reference(words, initial):
    registers = list(initial.x)
    nzcv = initial.nzcv
    for word in words[:-1]:
        bits = 64 if word >> 31 else 32
        mask = (1 << bits) - 1
        destination, left, right = word & 31, (word >> 5) & 31, (word >> 16) & 31
        first = (registers[left] if left != 31 else 0) & mask
        if word & 0x1f800000 == 0x11000000:
            # The only noncarry fixture instruction is nonflag ADD #1.
            if ((word >> 10) & 0xfff) != 1 or word & (3 << 29):
                raise AssertionError('Unexpected mathematical fixture')
            value = (first + 1) & mask
        else:
            second = (registers[right] if right != 31 else 0) & mask
            carry = (nzcv >> 29) & 1
            subtract = bool(word & (1 << 30))
            total = first - second - (1 - carry) if subtract else first + second + carry
            value = total & mask
            if word & (1 << 29):
                sign = 1 << (bits - 1)
                first_signed = first - (1 << bits) if first & sign else first
                second_signed = second - (1 << bits) if second & sign else second
                signed_total = (first_signed - second_signed - (1 - carry) if subtract else
                                first_signed + second_signed + carry)
                negative = int(bool(value & sign))
                zero = int(value == 0)
                outgoing_carry = int(total >= 0) if subtract else int(total > mask)
                overflow = int(not -sign <= signed_total < sign)
                nzcv = (negative << 31) | (zero << 30) | (outgoing_carry << 29) | (overflow << 28)
        if destination != 31:
            registers[destination] = value
    return {**complete_state(initial), 'x': registers, 'sp': initial.sp, 'nzcv': nzcv}


def extended_encoding(width, subtract, flags, destination, left, right, option, shift):
    return ((width << 31) | (subtract << 30) | (flags << 29) | 0x0b200000
            | (right << 16) | (option << 13) | (shift << 10) | (left << 5) | destination)


def extended_cases():
    result = []
    aliases = [(1, 1, 2), (2, 1, 2), (0, 1, 1), (1, 1, 1), (31, 31, 31),
               (0, 31, 2), (0, 1, 31), (31, 1, 2), (31, 31, 2), (30, 30, 30)]
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for option in range(8):
                    for shift in range(5):
                        fields = {'family': 'extended', 'width': width, 'subtract': subtract,
                                  'flags': flags, 'option': option, 'shift': shift}
                        result.append({**fields, 'kind': 'all_registers', 'words': [
                            extended_encoding(width, subtract, flags, d, (d + 5) % 32,
                                              (d + 13) % 32, option, shift) for d in range(32)] + [RET]})
                        result.append({**fields, 'kind': 'extended_boundaries', 'words': [
                            extended_encoding(width, subtract, flags, 0, 1, 2, option, shift), RET]})
                        for d, n, m in aliases:
                            result.append({**fields, 'kind': 'extended_aliases', 'words': [
                                extended_encoding(width, subtract, flags, d, n, m, option, shift), RET]})
                # New flags flow through a real carry consumer, and nonflag
                # extended arithmetic must retain the incoming architectural C.
                result.append({'family': 'extended', 'kind': 'extended_chain',
                    'width': width, 'words': [extended_encoding(width, subtract, flags, 0, 1, 2, 4, 3),
                    encoding(width, 0, 0, 4, 31, 31),
                    extended_encoding(width, subtract, flags, 1, 0, 4, 6, 4), RET]})
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        for word in case['words']:
            decoded = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if decoded is None or decoded.mnemonic not in ('add', 'adds', 'sub', 'subs', 'cmp', 'cmn', 'adc', 'ret'):
                raise AssertionError(f'Independent decoder rejected extended word {word:#x}')
    return result


def extend_value(value, width, option, shift):
    bits = 32 << width
    source_bits = min(8 << (option & 3), bits)
    low = value & ((1 << source_bits) - 1)
    if option & 4 and low & (1 << (source_bits - 1)):
        low -= 1 << source_bits
    return (low << shift) & ((1 << bits) - 1)


def mathematical_reference(words, initial):
    state = State.from_buffer_copy(initial)
    for word in words[:-1]:
        if word & 0x1fe00000 != 0x0b200000:
            result = carry_reference([word, RET], state)
            state.x[:], state.sp, state.nzcv = result['x'], result['sp'], result['nzcv']
            continue
        width, subtract, flags = word >> 31, bool(word & (1 << 30)), bool(word & (1 << 29))
        bits, d, n, m = 32 << width, word & 31, (word >> 5) & 31, (word >> 16) & 31
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        first = (state.sp if n == 31 else state.x[n]) & mask
        second = extend_value(state.x[m] if m != 31 else 0, width, (word >> 13) & 7, (word >> 10) & 7)
        total = first - second if subtract else first + second
        value = total & mask
        if flags:
            signed_first = first - (1 << bits) if first & sign else first
            signed_second = second - (1 << bits) if second & sign else second
            signed_total = signed_first - signed_second if subtract else signed_first + signed_second
            state.nzcv = (int(bool(value & sign)) << 31) | (int(value == 0) << 30) | (
                int(total >= 0 if subtract else total > mask) << 29) | (int(not -sign <= signed_total < sign) << 28)
        if d != 31:
            state.x[d] = value
        elif not flags:
            state.sp = value
    return complete_state(state)


def extended_boundary_pairs(case):
    bits = 32 << case['width']
    mask, sign = (1 << bits) - 1, 1 << (bits - 1)
    source_bits = min(8 << (case['option'] & 3), bits)
    source_mask, source_sign = (1 << source_bits) - 1, 1 << (source_bits - 1)
    right_values = {0, 1, source_sign - 1, source_sign, source_sign + 1, source_mask - 1, source_mask}
    right_values |= {value | (MASK ^ source_mask) for value in tuple(right_values)}
    pairs = set()
    for right in right_values:
        extended = extend_value(right, case['width'], case['option'], case['shift'])
        left_values = {0, 1, mask, sign - 1, sign}
        for target in (0, sign - 1, sign, mask):
            left_values.add((target + extended if case['subtract'] else target - extended) & mask)
        pairs.update((left, right) for left in left_values)
    return sorted(pairs)


def initialize_extended_inputs(case, state, pair):
    word = case['words'][0]
    n, m = (word >> 5) & 31, (word >> 16) & 31
    poison = 0xdeadc0de00000000 if case['width'] == 0 else 0
    first, second = pair
    if n == 31:
        state.sp = first | poison
    else:
        state.x[n] = first | poison
    # Rm==31 is always ZR, even when Rn/Rd designate SP. For a real alias,
    # both operands necessarily observe the last assigned physical register.
    if m != 31:
        state.x[m] = second | poison


def boundary_pairs(width):
    bits = 32 << width
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    return [(0, 0), (0, 1), (1, 0), (1, 1), (mask, 0), (mask, 1), (mask, mask),
            (sign - 1, 0), (sign - 1, 1), (sign - 1, sign - 1),
            (sign, 0), (sign, 1), (sign, mask), (sign, sign), (0, mask),
            (0xaaaaaaaaaaaaaaaa & mask, 0x5555555555555555 & mask)]


def execute_cases(compiled):
    comparisons = 0
    counts = {'carry': {'programs': 0, 'comparisons': 0}, 'extended': {'programs': 0, 'comparisons': 0}}
    corpus = hashlib.sha256()
    initial_states = states(all_flags=True)
    for case in compiled:
        family = case.get('family', 'carry')
        counts[family]['programs'] += 1
        code = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        pairs = boundary_pairs(case['width']) if case['kind'] in ('boundaries', 'dependency_chain') else [None]
        if case['kind'] == 'extended_boundaries':
            pairs = extended_boundary_pairs(case)
        elif case['kind'] == 'extended_aliases':
            bits = 32 << case['width']
            source_sign = 1 << (min(8 << (case['option'] & 3), bits) - 1)
            pairs = [(0, (1 << bits) - 1), ((1 << bits) - 1, source_sign),
                     (1 << (bits - 1), source_sign - 1), ((1 << (bits - 1)) - 1, source_sign + 1)]
        for pair in pairs:
            for initial in initial_states:
                state = State.from_buffer_copy(initial)
                if pair is not None:
                    if family == 'extended':
                        initialize_extended_inputs(case, state, pair)
                    else:
                    # Poison upper halves in W32 fixtures; the operands truncate
                    # and the destination must clear those bits, including aliases.
                        poison = 0xdeadc0de00000000 if case['width'] == 0 else 0
                        inputs = (zip((case['left'], case['right']), pair) if case['kind'] == 'boundaries' else
                                  [(limb, pair[0]) for limb in range(4)] +
                                  [(limb + 4, pair[1]) for limb in range(4)])
                        for register, value in inputs:
                            if register != 31:
                                state.x[register] = value | poison
                state.reserved = 0x5a17c0de
                corpus.update(code); corpus.update(bytes(state))
                expected_math = mathematical_reference(case['words'], state)
                expected_arm = reference(code, state)
                actual = native(case['native'], state)
                if expected_math != expected_arm or expected_arm != actual:
                    raise AssertionError(json.dumps({**{k: v for k, v in case.items() if k != 'native'},
                                                     'initial': list(state.x), 'incoming_nzcv': state.nzcv,
                                                     'mathematical': expected_math, 'arm': expected_arm,
                                                     'native': actual}, indent=2))
                comparisons += 1
                counts[family]['comparisons'] += 1
    assert counts['carry'] == {'programs': 368, 'comparisons': 28928}
    return {'programs': len(compiled), 'three_way_register_state_comparisons': comparisons,
            'groups': counts, 'state_corpus_sha256': corpus.hexdigest(),
            'carry_three_way_register_state_comparisons': counts['carry']['comparisons'],
            'extended_three_way_register_state_comparisons': counts['extended']['comparisons']}


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
                raise AssertionError(f'Arithmetic worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'Arithmetic suite failed: {result}, exit={process.exitcode}')
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def extended_blocks(cli, directory):
    """Run every option/shift through original RET and the shared native dispatcher."""
    from differential import initialize_arm, capture_arm
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import arm64_const as arm
    base, stop = 0x100000, 0x100800
    source, state_path = directory / 'extended.arm64', directory / 'extended-state.json'
    checks = cold = disk = 0
    corpus = hashlib.sha256()
    samples = []
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for option in range(8):
                    for shift in range(5):
                        d = 31 if (option + shift) % 3 == 0 else 0
                        n = 31 if (option + shift) % 2 == 0 else 1
                        m = 31 if (option + shift) % 5 == 0 else 2
                        code = struct.pack('<2I', extended_encoding(width, subtract, flags, d, n, m, option, shift), RET)
                        source.write_bytes(code)
                        for index, template in enumerate(states(all_flags=True)):
                            initial = State.from_buffer_copy(template)
                            initial.reserved, initial.x[30] = 0x5a17c0de, stop
                            expected = mathematical_reference(list(struct.unpack('<2I', code)), initial)
                            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                            machine.mem_map(base, 4096); machine.mem_write(base, code)
                            machine.reg_write(arm.UC_ARM64_REG_PSTATE, 0)
                            initialize_arm(machine, initial)
                            machine.emu_start(base, stop, count=4)
                            assert machine.reg_read(arm.UC_ARM64_REG_PC) == stop
                            assert complete_state(capture_arm(machine, initial)) == expected
                            state_path.write_text(json.dumps(complete_state(initial)))
                            result = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source),
                                '--state', str(state_path), '--guest-base', hex(base), '--stop-pc', hex(stop),
                                '--block-budget', '1', '--cache-dir', str(directory / 'extended-cache')], timeout=15))
                            assert result['state'] == expected and result['pc'] == stop
                            assert result['source_sha256'] == hashlib.sha256(code).hexdigest()
                            assert result['abi'] == 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
                            assert result['complete_binary_verified'] is False
                            outcome = result['outcome']
                            assert outcome['reason'] == {'kind': 'stop_address'} and outcome['blocks_executed'] == 1
                            assert outcome['compiled_blocks'] == int(index == 0)
                            assert outcome['disk_cache_hits'] == int(index != 0)
                            checks += 1; cold += outcome['compiled_blocks']; disk += outcome['disk_cache_hits']
                            corpus.update(code); corpus.update(bytes(initial))
                            corpus.update(json.dumps(result, sort_keys=True, separators=(',', ':')).encode())
                            if option == 0 and shift == 0 and index == 0:
                                samples.append(result)
    return {'original_arm_math_native_state_pc_comparisons': checks, 'cold_compiles': cold,
            'disk_cache_hits': disk, 'result_corpus_sha256': corpus.hexdigest(), 'samples': samples}


def reject_reserved_extended(cli, directory):
    from differential import initialize_arm
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_ERR_EXCEPTION
    from unicorn import arm64_const as arm
    source = directory / 'reserved.arm64'
    comparisons = 0
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for option in range(8):
                    for shift in (5, 6, 7):
                        word = extended_encoding(width, subtract, flags, 0, 1, 2, option, shift)
                        code = struct.pack('<2I', word, RET)
                        source.write_bytes(code)
                        output = directory / f'reserved-{word:08x}'
                        native = subprocess.run([str(cli), 'compile-leaf', str(source), '--output-dir', str(output)],
                                                capture_output=True, text=True, timeout=15)
                        assert native.returncode and not output.exists(), native.stderr
                        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                        machine.mem_map(0x100000, 4096); machine.mem_write(0x100000, code)
                        initialize_arm(machine, states(all_flags=True)[0])
                        try:
                            machine.emu_start(0x100000, 0x100008, count=1)
                        except UcError as error:
                            assert error.errno == UC_ERR_EXCEPTION and machine.reg_read(arm.UC_ARM64_REG_PC) == 0x100000
                        else:
                            raise AssertionError(f'Reserved extended shift executed: {word:#x}')
                        comparisons += 1
    return comparisons


def main():
    cli = compiler_cli(__doc__)
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    compiled = carry_cases()
    legacy = hashlib.sha256(b''.join(struct.pack('<' + 'I' * len(c['words']), *c['words']) for c in compiled)).hexdigest()
    assert legacy == LEGACY_CARRY_CORPUS
    compiled += extended_cases()
    compiler = None
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='stela-arithmetic-') as temporary:
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
                raise AssertionError('Compiler changed during carry suite')
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
        result = bounded_cases(compiled)
        blocks = extended_blocks(cli, directory)
        reserved = reject_reserved_extended(cli, directory)
    assert hashlib.sha256(cli.read_bytes()).hexdigest() == executable_hash
    report = {'kind': 'add_sub_arithmetic_arm_vs_native_x86', 'passed': True, **result,
              'operations': ['ADC', 'ADCS', 'SBC/NGC', 'SBCS/NGCS',
                             'ADD/ADDS/SUB/SUBS extended W32/X64, including CMP/CMN aliases'],
              'reference': 'Unicorn ARM64 2.1.4 and independent unbounded signed/unsigned integer arithmetic',
              'native': 'direct x86-64 calls in isolated worker',
              'tested_state': ["V0..V31, FPCR and FPSR preservation", 'x0..x30', 'SP preservation', 'all 16 incoming NZCV combinations',
                               'W32 upper-half clearing', 'ZR sources/discarded destinations',
                               'carry/borrow and signed overflow boundaries', 'carry dependency chains',
                               'all eight extensions and five legal shifts per width/op/flags',
                               'SP left/nonflag destination versus ZR right/flag destination',
                               'extended-result aliases, sign-extension and fresh-flag chains'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'legacy_carry_corpus_sha256': legacy, 'extended_block_dispatch': blocks,
              'reserved_shift_original_undefined_native_declines': reserved,
              'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'Register arithmetic and complete GPR/SP/NZCV/reserved/V/FP state, plus real RET/shared block dispatch. Full PSTATE, guest exception delivery, memory, SIMD arithmetic, PAC and OS boot are not covered.'}
    write_evidence(ROOT / '.stela/arithmetic-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
