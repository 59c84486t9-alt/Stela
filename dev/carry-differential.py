#!/usr/bin/env python3
"""Compare ADC/SBC results and NZCV with ARM and independent integer arithmetic."""
import hashlib
import json
import multiprocessing
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import ROOT, State, arithmetic, native, reference, states
from evidence import write_evidence

RET = 0xd65f03c0


def encoding(width, subtract, flags, destination, left, right):
    return ((width << 31) | (subtract << 30) | (flags << 29)
            | 0x1a000000 | (right << 16) | (left << 5) | destination)


def cases():
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


def mathematical_reference(words, initial):
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
    return {'x': registers, 'sp': initial.sp, 'nzcv': nzcv}


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
    initial_states = states(all_flags=True)
    for case in compiled:
        code = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        pairs = boundary_pairs(case['width']) if case['kind'] in ('boundaries', 'dependency_chain') else [None]
        for pair in pairs:
            for initial in initial_states:
                state = State.from_buffer_copy(initial)
                if pair is not None:
                    # Poison upper halves in W32 fixtures; the operands truncate
                    # and the destination must clear those bits, including aliases.
                    poison = 0xdeadc0de00000000 if case['width'] == 0 else 0
                    inputs = (zip((case['left'], case['right']), pair) if case['kind'] == 'boundaries' else
                              [(limb, pair[0]) for limb in range(4)] +
                              [(limb + 4, pair[1]) for limb in range(4)])
                    for register, value in inputs:
                        if register != 31:
                            state.x[register] = value | poison
                expected_math = mathematical_reference(case['words'], state)
                expected_arm = reference(code, state)
                actual = native(case['native'], state)
                if expected_math != expected_arm or expected_arm != actual:
                    raise AssertionError(json.dumps({**{k: v for k, v in case.items() if k != 'native'},
                                                     'initial': list(state.x), 'incoming_nzcv': state.nzcv,
                                                     'mathematical': expected_math, 'arm': expected_arm,
                                                     'native': actual}, indent=2))
                comparisons += 1
    return {'programs': len(compiled), 'three_way_register_state_comparisons': comparisons}


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
        deadline = time.monotonic() + 180
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'Carry worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'Carry suite failed: {result}, exit={process.exitcode}')
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def main():
    subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    compiled = cases()
    compiler = None
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='stela-carry-') as temporary:
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
    report = {'kind': 'add_sub_carry_arm_vs_native_x86', 'passed': True, **result,
              'operations': ['ADC', 'ADCS', 'SBC/NGC', 'SBCS/NGCS'],
              'reference': 'Unicorn ARM64 2.1.4 and independent unbounded signed/unsigned integer arithmetic',
              'native': 'direct x86-64 calls in isolated worker',
              'tested_state': ['x0..x30', 'SP preservation', 'all 16 incoming NZCV combinations',
                               'W32 upper-half clearing', 'ZR sources/discarded destinations',
                               'carry/borrow and signed overflow boundaries', 'carry dependency chains'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'compiler_executable_sha256': hashlib.sha256(cli.read_bytes()).hexdigest(),
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'Register arithmetic and NZCV only. Full PSTATE, system instructions, guest exceptions, memory, SIMD, PAC, runtime dispatch and OS boot are not covered.'}
    write_evidence(ROOT / '.stela/carry-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
