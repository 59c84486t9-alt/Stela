#!/usr/bin/env python3
"""Compare original ADR/ADRP with native leaf/block output and independent math.

Wrapping-address cases use only native output and mathematical expectations;
Unicorn is deliberately not presented as evidence for unmappable guest PCs.
"""
import argparse
import ctypes
import hashlib
import json
import multiprocessing
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn import arm64_const as arm
from differential import ROOT, MASK, ARM_REGISTERS, State, executable, states, arithmetic
from evidence import write_evidence

RET = 0xd65f03c0
NOP = 0xd503201f


class BlockExit(ctypes.Structure):
    _fields_ = [('next_pc', ctypes.c_uint64), ('kind', ctypes.c_uint64)]


def encoding(page, immediate, destination):
    if not -(1 << 20) <= immediate < (1 << 20) or not 0 <= destination < 32:
        raise ValueError('ADR/ADRP immediate or destination out of bounds')
    value = immediate % (1 << 21)
    return (0x90000000 if page else 0x10000000) | ((value % 4) << 29) | ((value // 4) << 5) | destination


def make_case(page, immediate, destination, base=0x100ff8, prefix=1, chain=False, wrap=False):
    operations = [('nop',)] * prefix + [('address', page, immediate, destination)]
    if chain:
        # Consume the freshly formed address as a register operand, then replace
        # it from a later instruction PC. This catches stale-PC reuse.
        operations.extend([('add', 8, destination, 7), ('address', not page, -1, destination)])
    words = []
    for operation in operations:
        if operation[0] == 'nop':
            words.append(NOP)
        elif operation[0] == 'address':
            _, mode, offset, register = operation
            words.append(encoding(mode, offset, register))
        else:
            _, register, source, immediate = operation
            words.append(arithmetic(0, 0, 1, register, source, immediate))
    words.append(RET)
    return {'base': base, 'words': words, 'operations': operations, 'wrapping_math_only': wrap}


def cases():
    result = []
    offsets = (-(1 << 20), -(1 << 20) + 1, -4096, -4, -3, -2, -1, 0, 1, 2, 3, 4095, (1 << 20) - 1)
    for page in (False, True):
        for offset in offsets:
            for destination in range(32):
                result.append(make_case(page, offset, destination))
            # Bases span both 4 KiB and 16 KiB page edges. Prefixes ensure
            # instruction PC differs from the region's base.
            for base, prefix in ((0x100ffc, 1), (0x101000, 0), (0x103ff8, 3), (0x104000, 2)):
                for destination in (0, 30, 31):
                    result.append(make_case(page, offset, destination, base, prefix))
        for base in (0x100ff8, 0x103ff8):
            for offset in (-1, 0, 1):
                result.append(make_case(page, offset, 7, base, 2, chain=True))
        # Source PCs remain representable and aligned; only computed data
        # addresses wrap. Full source ranges do not cross the 64-bit boundary.
        for base, offset in ((0, -(1 << 20)), (0, -1), (MASK - 15, (1 << 20) - 1), (MASK - 15, 1)):
            for destination in (0, 30, 31):
                result.append(make_case(page, offset, destination, base, 1, wrap=True))
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        decoded = list(decoder.disasm(source, case['base']))
        if len(decoded) != len(case['words']) or any(instruction.mnemonic not in ('adr', 'adrp', 'nop', 'add', 'ret') for instruction in decoded):
            raise AssertionError(f'Independent decoder rejected {case}')
    return result


def snapshot(state):
    return {'x': list(state.x), 'sp': state.sp, 'nzcv': state.nzcv, 'reserved': state.reserved}


def mathematical_reference(case, initial):
    result = snapshot(initial)
    for index, operation in enumerate(case['operations']):
        pc = case['base'] + index * 4
        if operation[0] == 'address':
            _, page, immediate, destination = operation
            # Fixture metadata supplies the signed value; do not share the
            # compiler's bit extraction or sign-extension implementation.
            value = ((pc // 4096) * 4096 + immediate * 4096 if page else pc + immediate) % (1 << 64)
        elif operation[0] == 'add':
            _, destination, source, immediate = operation
            value = (result['x'][source] + immediate) % (1 << 64)
        else:
            continue
        if destination != 31:
            result['x'][destination] = value
    return result


def original_arm(machine, case, initial):
    for register, value in zip(ARM_REGISTERS, initial.x):
        machine.reg_write(register, value)
    machine.reg_write(arm.UC_ARM64_REG_SP, initial.sp)
    machine.reg_write(arm.UC_ARM64_REG_NZCV, initial.nzcv)
    # Execute the actual address instructions, stopping before the harness-owned
    # RET. X30 is free to be an instruction destination and may be noncanonical.
    end = case['base'] + len(case['operations']) * 4
    machine.emu_start(case['base'], end, count=len(case['operations']))
    if machine.reg_read(arm.UC_ARM64_REG_PC) != end:
        raise AssertionError('ARM reference did not reach the expected leaf boundary')
    return {'x': [machine.reg_read(register) for register in ARM_REGISTERS],
            'sp': machine.reg_read(arm.UC_ARM64_REG_SP),
            'nzcv': machine.reg_read(arm.UC_ARM64_REG_NZCV) & 0xf0000000,
            'reserved': initial.reserved}


def execute_cases(compiled):
    counts = {'programs': len(compiled), 'three_way_register_state_comparisons': 0,
              'wrapping_native_vs_math_comparisons': 0, 'native_block_exit_checks': 0}
    incoming = states(all_flags=True)
    for index, state in enumerate(incoming):
        # Distinct dirty upper halves and an unaligned SP prove neither ADR nor
        # discarded XZR destinations read or write SP or perform memory accesses.
        state.sp = 0xfeed000000000003 + index
        state.reserved = 0xa5c39e71
        for register in range(31):
            state.x[register] |= 0xdeadbeef00000000
    corpus = hashlib.sha256()
    for case in compiled:
        machine = None
        if not case['wrapping_math_only']:
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            start = case['base'] // 4096 * 4096
            machine.mem_map(start, 0x3000)
            machine.mem_write(case['base'], struct.pack('<' + 'I' * len(case['words']), *case['words']))
        with executable(case['leaf']) as leaf_address, executable(case['block']) as block_address:
            leaf = ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(leaf_address)
            block = ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(block_address)
            for initial in incoming:
                expected = mathematical_reference(case, initial)
                if machine is not None:
                    arm_state = original_arm(machine, case, initial)
                    if expected != arm_state:
                        raise AssertionError(json.dumps({'case': case['operations'], 'base': case['base'], 'math': expected, 'arm': arm_state}))
                for mode, function in (('leaf', leaf), ('block', block)):
                    state = State.from_buffer_copy(initial)
                    returned = function(ctypes.byref(state))
                    if snapshot(state) != expected:
                        raise AssertionError(json.dumps({'mode': mode, 'case': case['operations'], 'base': case['base'], 'expected': expected, 'native': snapshot(state)}))
                    if mode == 'block':
                        if returned.kind != 4 or returned.next_pc != expected['x'][30]:
                            raise AssertionError('Block RET exit differs from independently computed X30')
                        counts['native_block_exit_checks'] += 1
                    key = 'wrapping_native_vs_math_comparisons' if machine is None else 'three_way_register_state_comparisons'
                    counts[key] += 1
                corpus.update(struct.pack('<Q', case['base']))
                corpus.update(bytes(initial))
    return {**counts, 'state_corpus_sha256': corpus.hexdigest()}


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
                raise AssertionError(f'PC-relative worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'PC-relative suite failed: {result}, exit={process.exitcode}')
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
    with tempfile.TemporaryDirectory(prefix='stela-pcrel-') as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
            corpus.update(struct.pack('<Q', case['base']))
            corpus.update(source)
            input_path = directory / 'source.bin'
            input_path.write_bytes(source)
            for mode in ('leaf', 'block'):
                output = directory / f'{index}-{mode}'
                manifest = json.loads(subprocess.check_output([str(cli), f'compile-{mode}', str(input_path),
                                                              '--guest-base', hex(case['base']), '--output-dir', str(output)]))
                if compiler is not None and compiler != manifest['compiler_source_sha256']:
                    raise AssertionError('Compiler changed during PC-relative suite')
                compiler = manifest['compiler_source_sha256']
                actual_pcs = [row[0] for row in manifest['source_map']]
                expected_pcs = [case['base'] + offset * 4 for offset in range(len(case['words']))]
                if actual_pcs != expected_pcs:
                    raise AssertionError(f'{mode} source map lost guest PCs: {actual_pcs} != {expected_pcs}')
                case[mode] = (output / 'native.bin').read_bytes()
                offsets = [row[1] for row in manifest['source_map']]
                if offsets != sorted(set(offsets)) or offsets[0] != 0 or offsets[-1] >= len(case[mode]):
                    raise AssertionError(f'{mode} source map lacks nonempty ordered native intervals: {offsets}')
        result = bounded_cases(compiled)
    if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise AssertionError('Compiler executable changed during PC-relative suite')
    report = {'kind': 'pc_relative_arm_vs_native_x86', 'passed': True, **result,
              'operations': ['ADR', 'ADRP'],
              'reference': 'Unicorn ARM64 2.1.4 and independent unbounded fixture arithmetic',
              'native': 'baseline x86-64 leaf and block ABIs in isolated worker',
              'tested_state': ['x0..x30', 'SP, NZCV and reserved-word preservation', 'all 16 incoming NZCV combinations',
                               'all destinations including discarded XZR', 'dirty GPR upper halves', 'per-instruction guest PC and source maps',
                               '4 KiB ADRP granule across 4 KiB and 16 KiB boundaries', 'signed 21-bit extrema and immlo combinations',
                               'address result consumption and repeated destination writes', 'native block RET result after X30 replacement'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'Unicorn stops before harness-owned RET. Wrapping guest data addresses have native/math evidence only; no original-ARM claim for those cases. No application loading, memory dereferences, guest faults or macOS boot.'}
    write_evidence(ROOT / '.stela/pc-relative-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
