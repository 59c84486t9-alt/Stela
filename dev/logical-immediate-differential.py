#!/usr/bin/env python3
"""Exhaust logical-immediate masks and compare emitted x86 with original ARM."""
import hashlib
import json
import multiprocessing
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_ERR_EXCEPTION
from unicorn import arm64_const as arm
from differential import ARM_REGISTERS, BASE, MASK, ROOT, State, native, reference, states
from evidence import write_evidence

RET = 0xd65f03c0


def encoding(width, opcode, n, rotation, size, destination, source):
    return ((width << 31) | (opcode << 29) | 0x12000000 | (n << 22)
            | (rotation << 16) | (size << 10) | (source << 5) | destination)


def masks(width):
    """Independently enumerate valid encodings by constructing each bit."""
    bits = 32 << width
    result = {}
    for element in (2, 4, 8, 16, 32, 64):
        if element > bits:
            continue
        for ones in range(1, element):
            for rotation in range(64):
                mask = sum(1 << bit for bit in range(bits)
                           if (bit + rotation) % element < ones)
                key = (int(element == 64), rotation, ((-2 * element) | (ones - 1)) & 63)
                if key in result:
                    raise AssertionError("Duplicate independent encoding")
                result[key] = mask
    return result


def cases():
    result = []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for width in (0, 1):
        entries = sorted(masks(width))
        for opcode in range(4):
            # Every result survives in its own register. Source x29 is unchanged;
            # batches include aliases of rotations with ignored high bits.
            for offset in range(0, len(entries), 28):
                batch = entries[offset:offset + 28]
                words = [encoding(width, opcode, *key, destination, 29)
                         for destination, key in enumerate(batch)]
                for word in words:
                    decoded = next(decoder.disasm(struct.pack('<I', word), BASE), None)
                    if decoded is None or decoded.mnemonic not in ('and', 'orr', 'eor', 'ands'):
                        raise AssertionError(f"Independent decoder rejected {word:#x}")
                result.append({'words': words + [RET], 'kind': 'all_masks',
                               'width': width, 'opcode': opcode, 'encodings': batch})
        # Rd=31 differs between SP-writing logical operations and TST. Rn=31
        # reads zero, even when SP holds a nonzero value. Include MOV aliases,
        # in-place operations, x30, and sign/high-bit/W32 zero-extension cases.
        directed = [(0, 0, 0), (0, 1, 0), (0, 63, 60), (0, 32, 15),
                    (0, 17, 30), (0, 31, 0)]
        if width:
            directed += [(1, 0, 62), (1, 1, 0), (1, 63, 62), (1, 32, 31)]
        for opcode in range(4):
            for key in directed:
                for destination, source in ((0, 0), (30, 0), (31, 0), (0, 31), (31, 31)):
                    result.append({'words': [encoding(width, opcode, *key, destination, source), RET],
                                   'kind': 'register_roles', 'width': width, 'opcode': opcode,
                                   'encodings': [key], 'destination': destination, 'source': source})
    return result


def execute_cases(compiled):
    comparisons = 0
    initial_states = states(all_flags=True)
    values = [0, MASK, 1, 0x80000000, 0x7fffffff, 0xffffffff,
              0x8000000000000000, 0x7fffffffffffffff,
              0xaaaaaaaaaaaaaaaa, 0x5555555555555555,
              0x0123456789abcdef, 0xfedcba9876543210,
              0xffff0000ffff0000, 0x0000ffff0000ffff, MASK - 1, 2]
    for case in compiled:
        code = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        for index, initial in enumerate(initial_states):
            state = State.from_buffer_copy(initial)
            state.x[29] = state.x[0] = values[index]
            expected = reference(code, state)
            actual = native(case['native'], state)
            if expected != actual:
                raise AssertionError(json.dumps({**{k: v for k, v in case.items() if k != 'native'},
                                                 'initial': list(state.x), 'nzcv': state.nzcv,
                                                 'expected': expected, 'actual': actual}, indent=2))
            # An independent mathematical result check catches a correlated
            # source encoding or oracle mistake in the exhaustive mask batches.
            if case['kind'] == 'all_masks':
                bitmask = (1 << (32 << case['width'])) - 1
                source = state.x[29] & bitmask
                known_masks = masks_by_width[case['width']]
                for destination, key in enumerate(case['encodings']):
                    immediate = known_masks[tuple(key)]
                    opcode = case['opcode']
                    value = (source & immediate if opcode in (0, 3) else
                             source | immediate if opcode == 1 else source ^ immediate)
                    if actual['x'][destination] != value:
                        raise AssertionError('Independent logical result differs')
            comparisons += 1
    return {'programs': len(compiled), 'register_state_comparisons': comparisons}


masks_by_width = {width: masks(width) for width in (0, 1)}


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
        deadline = time.monotonic() + 240
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'Logical-immediate worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'Logical-immediate suite failed: {result}, exit={process.exitcode}')
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def undefined_cases():
    for width in (0, 1):
        # N=1/W32, reserved all-one elements, and invalid 0/1-bit
        # selectors, including extreme/high ignored rotation bits.
        for n, size in ((1, 0), (1, 62), (1, 63), (0, 31), (0, 47),
                        (0, 55), (0, 59), (0, 61), (0, 62), (0, 63)):
            for rotation in (0, 1, 31, 63):
                if (n, rotation, size) not in masks_by_width[width]:
                    for opcode in range(4):
                        yield encoding(width, opcode, n, rotation, size, 0, 0)


def verify_undefined(cli, directory):
    count = 0
    for word in undefined_cases():
        source = struct.pack('<II', word, RET)
        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        machine.mem_map(BASE, 0x1000)
        machine.mem_write(BASE, source)
        state = states()[0]
        for register, value in zip(ARM_REGISTERS, state.x):
            machine.reg_write(register, value)
        machine.reg_write(arm.UC_ARM64_REG_SP, state.sp)
        machine.reg_write(arm.UC_ARM64_REG_NZCV, state.nzcv)
        try:
            machine.emu_start(BASE, BASE + len(source), count=1)
        except UcError as error:
            if error.errno != UC_ERR_EXCEPTION:
                raise
        else:
            raise AssertionError(f'ARM accepted reserved encoding {word:#x}')
        if (machine.reg_read(arm.UC_ARM64_REG_PC) != BASE or
                [machine.reg_read(register) for register in ARM_REGISTERS] != list(state.x) or
                machine.reg_read(arm.UC_ARM64_REG_SP) != state.sp or
                machine.reg_read(arm.UC_ARM64_REG_NZCV) != state.nzcv):
            raise AssertionError('Undefined instruction changed architectural state')
        input_path = directory / 'undefined.bin'
        input_path.write_bytes(source)
        output = directory / 'undefined-output'
        result = subprocess.run([str(cli), 'compile-leaf', str(input_path), '--output-dir', str(output)],
                                capture_output=True, text=True)
        if result.returncode == 0 or 'unsupported ARM64 semantics' not in result.stderr:
            raise AssertionError(f'Compiler accepted or misclassified {word:#x}: {result.stderr}')
        if output.exists():
            raise AssertionError('Rejected instruction produced an artifact')
        count += 1
    return count


def main():
    subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    compiled = cases()
    compiler = None
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='stela-logical-immediate-') as temporary:
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
                raise AssertionError('Compiler changed during logical-immediate suite')
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
        rejected = verify_undefined(cli, directory)
        result = bounded_cases(compiled)
    report = {'kind': 'logical_immediate_arm_vs_native_x86', 'passed': True, **result,
              'valid_mask_encodings_per_operation': {str(32 << width): len(masks_by_width[width])
                                                     for width in (0, 1)},
              'logical_operations': ['AND', 'ORR/MOV', 'EOR', 'ANDS/TST'],
              'undefined_instruction_rejections': rejected,
              'reference': 'Unicorn ARM64 2.1.4 and independent bit-by-bit mask construction',
              'native': 'direct x86-64 calls in isolated worker',
              'tested_state': ['x0..x30', 'SP/WSP destinations and ZR sources', 'all 16 incoming NZCV combinations'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'compiler_executable_sha256': hashlib.sha256(cli.read_bytes()).hexdigest(),
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'All legal immediate encodings and operation results are exercised in register batches. NZCV is checked after each batch and after directed individual cases, not at every intermediate instruction. Undefined instructions are rejected at compilation; no native guest exception delivery. No memory accesses, SIMD, PAC, runtime dispatch or OS boot.'}
    write_evidence(ROOT / '.stela/logical-immediate-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
