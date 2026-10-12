#!/usr/bin/env python3
"""Compare CSEL/CSINC/CSINV/CSNEG with original ARM and a Boolean/integer oracle."""
import argparse
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


def encoding(width, operation, condition, destination, left, right):
    return ((width << 31) | ((operation >> 1) << 30) | 0x1a800000
            | (right << 16) | (condition << 12) | ((operation & 1) << 10)
            | (left << 5) | destination)


def holds(condition, flags):
    n, z, c, v = (bool(flags & (1 << bit)) for bit in (31, 30, 29, 28))
    # Written independently of the emitter's bit manipulation and Jcc recipe.
    predicates = (z, not z, c, not c, n, not n, v, not v,
                  c and not z, not c or z, n == v, n != v,
                  not z and n == v, z or n != v, True, True)
    return predicates[condition]


def cases():
    result = []
    roles = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 1, 2),
             (0, 31, 2), (0, 1, 31), (0, 31, 31), (31, 31, 31),
             (0, 1, 1), (30, 0, 7))
    for width in (0, 1):
        for operation in range(4):
            for condition in range(16):
                for destination, left, right in roles:
                    result.append({'words': [encoding(width, operation, condition, destination, left, right), RET],
                                   'kind': 'single', 'width': width, 'left': left, 'right': right})
        for condition in range(16):
            # Read freshly stored guest flags after CMP, then clobber host flags
            # with nonflag ADD and ZR loads between dependent selects.
            result.append({'words': [arithmetic(1, 1, width, 31, 1, 1),
                                      arithmetic(0, 0, width, 28, 28, 1),
                                      encoding(width, 1, condition, 1, 31, 2),
                                      encoding(width, 2, condition ^ 1, 2, 1, 31),
                                      encoding(width, 3, condition, 0, 2, 1), RET],
                           'kind': 'dependency_chain', 'width': width, 'left': 1, 'right': 2})
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    allowed = {'csel', 'csinc', 'csinv', 'csneg', 'cinc', 'cinv', 'cneg',
               'cset', 'csetm', 'cmp', 'add', 'ret'}
    for case in result:
        for word in case['words']:
            instruction = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if instruction is None or instruction.mnemonic not in allowed:
                raise AssertionError(f'Independent decoder rejected {word:#x}: {instruction}')
    return result


def mathematical_reference(words, initial):
    registers, nzcv = list(initial.x), initial.nzcv
    for word in words[:-1]:
        bits = 64 if word >> 31 else 32
        mask = (1 << bits) - 1
        destination, left = word & 31, (word >> 5) & 31
        first = (registers[left] if left != 31 else 0) & mask
        if word & 0x1f800000 == 0x11000000:
            immediate = (word >> 10) & 0xfff
            subtract, flags = bool(word & (1 << 30)), bool(word & (1 << 29))
            total = first - immediate if subtract else first + immediate
            value = total & mask
            if flags:
                sign = 1 << (bits - 1)
                signed_first = first - (1 << bits) if first & sign else first
                signed_total = signed_first - immediate if subtract else signed_first + immediate
                nzcv = ((int(bool(value & sign)) << 31) | (int(value == 0) << 30)
                        | (int(total >= 0 if subtract else total > mask) << 29)
                        | (int(not -sign <= signed_total < sign) << 28))
        else:
            right = (word >> 16) & 31
            second = (registers[right] if right != 31 else 0) & mask
            operation = (((word >> 30) & 1) << 1) | ((word >> 10) & 1)
            false_values = (second, second + 1, ~second, -second)
            value = (first if holds((word >> 12) & 15, nzcv) else false_values[operation]) & mask
        if destination != 31:
            registers[destination] = value
    return {'x': registers, 'sp': initial.sp, 'nzcv': nzcv}


def execute_cases(compiled):
    comparisons = 0
    corpus = hashlib.sha256()
    # Each operand pair sees every incoming NZCV state, with dirty W upper bits.
    pairs = ((0, 0), (0, 1), (1, 0), ((1 << 64) - 1, (1 << 64) - 1),
             (0x8000000080000000, 0x7fffffff7fffffff),
             (0xdeadbeefffffffff, 0xcafebabe00000000))
    initial_states = states(all_flags=True)
    for case in compiled:
        code = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        for first, second in pairs:
            for initial in initial_states:
                state = State.from_buffer_copy(initial)
                for register, value in ((case['left'], first), (case['right'], second)):
                    if register != 31:
                        state.x[register] = value
                corpus.update(code)
                corpus.update(bytes(state))
                expected_math = mathematical_reference(case['words'], state)
                expected_arm = reference(code, state)
                actual = native(case['native'], state)
                if expected_math != expected_arm or expected_arm != actual:
                    raise AssertionError(json.dumps({**{k: v for k, v in case.items() if k != 'native'},
                                                     'initial': list(state.x), 'incoming_nzcv': state.nzcv,
                                                     'mathematical': expected_math, 'arm': expected_arm,
                                                     'native': actual}, indent=2))
                comparisons += 1
    return {'programs': len(compiled), 'three_way_register_state_comparisons': comparisons,
            'state_corpus_sha256': corpus.hexdigest()}


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
        deadline = time.monotonic() + 300
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'Conditional-select worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'Conditional-select suite failed: {result}, exit={process.exitcode}')
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
    compiled, compiler, corpus = cases(), None, hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='stela-select-') as temporary:
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
                raise AssertionError('Compiler changed during conditional-select suite')
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
        result = bounded_cases(compiled)
    if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise AssertionError('Compiler executable changed during conditional-select suite')
    report = {'kind': 'conditional_select_arm_vs_native_x86', 'passed': True, **result,
              'operations': ['CSEL', 'CSINC/CINC/CSET', 'CSINV/CINV/CSETM', 'CSNEG/CNEG'],
              'reference': 'Unicorn ARM64 2.1.4 and independent Boolean/integer arithmetic',
              'native': 'branchless baseline x86-64 selection in isolated worker',
              'tested_state': ['x0..x30', 'SP and NZCV preservation', 'all 16 conditions including AL/NV',
                               'all 16 incoming NZCV combinations', 'freshly generated guest flags',
                               'W32 upper-half clearing', 'ZR sources and discarded destinations',
                               'source/destination overlap', 'increment and negation wraparound'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'Bounded integer register semantics, not full PSTATE, application loading, guest exceptions or macOS boot.'}
    write_evidence(ROOT / '.stela/conditional-select-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
