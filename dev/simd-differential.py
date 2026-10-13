#!/usr/bin/env python3
"""Original ARM, independent byte math and native x86 SIMD data movement.

Only reviewed B/H/S/D/Q immediate transfers and MOVI D/2D byte masks are tested.
Single-operation leaf mini-functions expose each result in a fresh complete
state; mixed chains additionally compare final state and RAM. Representative
block cases execute the original RET and native block exit ABI.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
import hashlib
import importlib.util
import json
import mmap
import multiprocessing
from pathlib import Path
import random
import signal
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_ERR_FETCH_UNMAPPED
from unicorn import arm64_const as arm
from differential import (ROOT, BASE, MASK, State, states, executable, initialize_arm,
                          capture_arm, state_dict, seed_extended_state, parse_fault_record, move)
from evidence import write_evidence

RET = 0xd65f03c0
STOP = 0x220000100000
RAM_BYTES = 0x4000
LEAF_ABI = 'x86_64-sysv-guest-state-v3-direct-ram'
BLOCK_ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
WIDTHS = (1, 2, 4, 8, 16)
MODES = ('unsigned', 'unscaled', 'pre', 'post')


class BlockExit(ctypes.Structure):
    _fields_ = [('next_pc', ctypes.c_uint64), ('kind', ctypes.c_uint64)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def memory_encoding(width, loading, rt, rn, offset, mode):
    if width not in WIDTHS or not 0 <= rt < 32 or not 0 <= rn < 32:
        raise ValueError('invalid SIMD memory width/register')
    size = 0 if width == 16 else width.bit_length() - 1
    opcode = int(loading) | (2 if width == 16 else 0)
    if mode == 'unsigned':
        if offset < 0 or offset % width or offset // width > 4095:
            raise ValueError('SIMD unsigned offset outside scaled12 range')
        return (size << 30) | 0x3d000000 | (opcode << 22) | ((offset // width) << 10) | (rn << 5) | rt
    if mode not in MODES or not -256 <= offset <= 255:
        raise ValueError('SIMD signed offset outside signed9 range')
    indexing = {'unscaled': 0, 'post': 1, 'pre': 3}[mode]
    return (size << 30) | 0x3c000000 | (opcode << 22) | ((offset & 511) << 12) | (indexing << 10) | (rn << 5) | rt


def movi_encoding(two_lanes, mask, rt):
    if not 0 <= mask < 256 or not 0 <= rt < 32:
        raise ValueError('invalid MOVI mask/register')
    return 0x2f00e400 | (int(two_lanes) << 30) | ((mask >> 5) << 16) | ((mask & 31) << 5) | rt


def memory_op(width, loading, rt, rn, offset, mode):
    return {'kind': 'memory', 'width': width, 'loading': loading, 'rt': rt, 'rn': rn,
            'offset': offset, 'mode': mode,
            'word': memory_encoding(width, loading, rt, rn, offset, mode)}


def movi_op(two_lanes, mask, rt):
    return {'kind': 'movi', 'two_lanes': two_lanes, 'mask': mask, 'rt': rt,
            'word': movi_encoding(two_lanes, mask, rt)}


def canonical_form(operation):
    if operation['kind'] == 'movi':
        return 'MOVI_2D' if operation['two_lanes'] else 'MOVI_D'
    return f"{'LDR' if operation['loading'] else 'STR'}_{operation['width']}_{operation['mode']}"


def programs():
    result = []
    for two_lanes in (False, True):
        for mask in range(256):
            for rt in (0, 31):
                result.append({'kind': 'exhaustive_movi', 'operations': [movi_op(two_lanes, mask, rt)], 'flags': 16})
    for two_lanes in (False, True):
        for rt in range(32):
            result.append({'kind': 'all_movi_registers', 'operations': [movi_op(two_lanes, 0xa5, rt)], 'flags': 1})
    roles = ((0, 0), (31, 31), (7, 7), (31, 0), (0, 31), (31, 29))
    for width in WIDTHS:
        for loading in (False, True):
            for mode in MODES:
                offsets = (0, width, 4095 * width) if mode == 'unsigned' else (-256, -1, 0, 255)
                for offset in offsets:
                    for rt, rn in roles:
                        result.append({'kind': 'memory_boundaries', 'operations': [memory_op(width, loading, rt, rn, offset, mode)], 'flags': 16})
                for rt in range(32):
                    result.append({'kind': 'all_vector_registers', 'operations': [memory_op(width, loading, rt, (rt + 1) % 32, 0, mode)], 'flags': 1})
            for rn in range(32):
                result.append({'kind': 'all_base_registers', 'operations': [memory_op(width, loading, rn, rn, 16, 'pre' if rn % 2 else 'post')], 'flags': 1})
    # Bounded mixed-width/mask chains observe scalar upper-zero, full Q storage,
    # cross-bank aliases, independent writebacks and original aligned SP recovery.
    for rt in (0, 31):
        result.extend([
            {'kind': 'mixed_chain', 'operations': [movi_op(True, 0xa5, rt), memory_op(16, False, rt, 0, 0, 'unsigned'), memory_op(1, True, rt, 0, 0, 'unsigned'), memory_op(16, False, rt, 0, 16, 'unsigned')], 'flags': 16},
            {'kind': 'mixed_chain', 'operations': [movi_op(True, 0xff, rt), memory_op(8, True, rt, 0, 0, 'unsigned'), memory_op(16, False, rt, 0, 16, 'unsigned')], 'flags': 16},
            {'kind': 'stack_chain', 'operations': [movi_op(True, 0x81, rt), memory_op(16, False, rt, 31, -16, 'pre'), memory_op(16, True, rt, 31, 16, 'post')], 'flags': 16},
            {'kind': 'mixed_chain', 'operations': [movi_op(True, 0x80, rt), movi_op(False, 0x01, rt), memory_op(16, False, rt, 0, 0, 'unsigned')], 'flags': 16},
        ])
    blocks = []
    for width in WIDTHS:
        for loading in (False, True):
            for mode in MODES:
                blocks.append({'kind': 'block', 'operations': [memory_op(width, loading, 31, 0, 16, mode)], 'flags': 16})
    for two_lanes in (False, True):
        blocks.append({'kind': 'block', 'operations': [movi_op(two_lanes, 0xa5, 31)], 'flags': 16})
    return result, blocks


def mathematical(operations, initial, memory, ram_address):
    state = State.from_buffer_copy(initial)
    ram = bytearray(memory)
    for operation in operations:
        rt = operation['rt']
        if operation['kind'] == 'movi':
            # Per-byte independent expansion, separate from compiler bit masks.
            lane = sum((255 if operation['mask'] & (1 << byte) else 0) << (8 * byte) for byte in range(8))
            state.v[rt][:] = [lane, lane if operation['two_lanes'] else 0]
            continue
        rn, width, mode, offset = (operation[k] for k in ('rn', 'width', 'mode', 'offset'))
        base = state.sp if rn == 31 else state.x[rn]
        if rn == 31 and base % 16:
            raise ValueError('oracle received misaligned incoming SP')
        effective = (base + (0 if mode == 'post' else offset)) & MASK
        position = effective - ram_address
        if not 0 <= position <= len(ram) - width:
            raise ValueError('oracle memory access outside owned RAM')
        if operation['loading']:
            value = int.from_bytes(ram[position:position + width], 'little')
            state.v[rt][:] = [value & MASK, value >> 64]
        else:
            value = state.v[rt][0] | (state.v[rt][1] << 64)
            ram[position:position + width] = value.to_bytes(16, 'little')[:width]
        if mode in ('pre', 'post'):
            if rn == 31:
                state.sp = (base + offset) & MASK
            else:
                state.x[rn] = (base + offset) & MASK
    return state, bytes(ram)


def validate_manifest(manifest, source, native, block):
    if (manifest['schema_version'] != 1 or manifest['abi'] != (BLOCK_ABI if block else LEAF_ABI)
            or manifest['guest_base'] != BASE or manifest['source_sha256'] != digest(source)
            or manifest['native_sha256'] != digest(native) or manifest['native_bytes'] != len(native)
            or manifest['verified'] is not False):
        raise AssertionError('SIMD manifest does not bind original/native bytes and ABI')
    consumed = manifest['source_bytes'] if block else manifest['guest_instructions'] * 4
    mapping = manifest['source_map']
    if (consumed != len(source) or [row[0] for row in mapping] != list(range(BASE, BASE + len(source), 4))
            or any(not 0 <= row[1] < len(native) for row in mapping)
            or any(a[1] >= b[1] for a, b in zip(mapping, mapping[1:]))):
        raise AssertionError('SIMD source map omits or merges original instructions')
    return [row[1] for row in mapping]


def compile_batch(cli, directory, functions, index, block=False):
    words, entries = [], []
    for function in functions:
        entries.append(len(words))
        words.extend(operation['word'] for operation in function['operations'])
        words.append(RET)
    source = struct.pack('<' + 'I' * len(words), *words)
    disassembly = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(source, BASE))
    if len(disassembly) != len(words) or any(i.mnemonic not in {'ldr', 'str', 'ldur', 'stur', 'movi', 'ret'} for i in disassembly):
        raise AssertionError('Independent decoder declined SIMD fixture')
    path = directory / f'program-{index}.arm64'
    path.write_bytes(source)
    output = directory / f'native-{index}'
    manifest = json.loads(subprocess.check_output([str(cli), 'compile-block' if block else 'compile-leaf', str(path), '--guest-base', hex(BASE), '--output-dir', str(output)], timeout=60))
    native = (output / 'native.bin').read_bytes()
    offsets = validate_manifest(manifest, source, native, block)
    if not block:
        for entry, function in zip(entries, functions):
            if native[offsets[entry + len(function['operations'])]] != 0xc3:
                raise AssertionError('Independent mini-function has no exact host RET boundary')
    return {'functions': functions, 'source': source, 'native': native, 'entries': entries,
            'offsets': [offsets[entry] for entry in entries], 'block': block,
            'compiler': manifest['compiler_source_sha256'],
            'receipt': {'functions': len(functions), 'source_bytes': len(source), 'source_sha256': digest(source),
                        'native_bytes': len(native), 'native_sha256': digest(native),
                        'source_map_sha256': digest(json.dumps(manifest['source_map']).encode()), 'block': block}}


def initial_case(function, index, flags, ram_address, original_ram, templates):
    initial = State.from_buffer_copy(templates[flags % 16])
    initial.nzcv = flags << 28
    initial.x[30] = STOP
    seed_extended_state(initial, (index << 8) | flags)
    ram = bytearray(original_ram)
    memories = [operation for operation in function['operations'] if operation['kind'] == 'memory']
    if len(memories) == 1:
        operation = memories[0]
        rn, offset, mode, width = (operation[k] for k in ('rn', 'offset', 'mode', 'width'))
        position = (0x600, 0x601, 0xfff, 0xff9, 0x1000, 0x1001)[flags % 6]
        if rn == 31:
            base = (ram_address + position - (0 if mode == 'post' else offset)) & ~15
        else:
            base = ram_address + position - (0 if mode == 'post' else offset)
        if rn == 31:
            initial.sp = base
        else:
            initial.x[rn] = base
        effective = base + (0 if mode == 'post' else offset)
        position = effective - ram_address
        value = (0, (1 << 128) - 1, 0x80000000000000018000000000000001, 0x0123456789abcdeffedcba9876543210)[flags % 4]
        ram[position:position + width] = value.to_bytes(16, 'little')[:width]
    elif memories:
        initial.x[0] = ram_address + 0x600
        initial.sp = ram_address + 0x1000
    return initial, bytes(ram)


def execute_batches(batches, pipe):
    counts = Counter()
    observed_forms, masks, vectors, bases = set(), {False: set(), True: set()}, set(), set()
    movi_destinations = {False: set(), True: set()}
    templates = states(all_flags=True)
    original_ram = random.Random(0x51d5c0de).randbytes(RAM_BYTES)
    state_corpus = hashlib.sha256()
    with mmap.mmap(-1, RAM_BYTES, prot=mmap.PROT_READ | mmap.PROT_WRITE) as ram:
        marker = ctypes.c_char.from_buffer(ram)
        address = ctypes.addressof(marker)
        del marker
        for batch_index, batch in enumerate(batches):
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            machine.mem_map(BASE, ((len(batch['source']) + 4095) // 4096) * 4096)
            machine.mem_write(BASE, batch['source'])
            machine.mem_map(address, RAM_BYTES)
            with executable(batch['native']) as native_address:
                for function_index, (function, entry, offset) in enumerate(zip(batch['functions'], batch['entries'], batch['offsets'])):
                    original_entry = BASE + entry * 4
                    native = (ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State)) if batch['block'] else ctypes.CFUNCTYPE(None, ctypes.POINTER(State)))(native_address + offset)
                    for flags_index in range(function['flags']):
                        flags = flags_index if function['flags'] == 16 else (batch_index + function_index) % 16
                        initial, memory = initial_case(function, batch_index * 512 + function_index, flags, address, original_ram, templates)
                        expected, expected_ram = mathematical(function['operations'], initial, memory, address)
                        initialize_arm(machine, initial)
                        machine.mem_write(address, memory)
                        boundary = expected.x[30] if batch['block'] else original_entry + len(function['operations']) * 4
                        try:
                            machine.emu_start(original_entry, boundary, count=len(function['operations']) + int(batch['block']))
                        except UcError as error:
                            if not batch['block'] or error.errno != UC_ERR_FETCH_UNMAPPED or machine.reg_read(arm.UC_ARM64_REG_PC) != boundary:
                                raise
                        if machine.reg_read(arm.UC_ARM64_REG_PC) != boundary:
                            raise AssertionError('Original SIMD program missed its exact boundary')
                        original = capture_arm(machine, initial)
                        original_memory = bytes(machine.mem_read(address, RAM_BYTES))
                        actual = State.from_buffer_copy(initial)
                        ram[:] = memory
                        returned = native(ctypes.byref(actual))
                        if (bytes(original) != bytes(expected) or bytes(actual) != bytes(expected)
                                or original_memory != expected_ram or ram[:] != expected_ram):
                            raise AssertionError(json.dumps({'function': function, 'flags': flags, 'initial': state_dict(initial),
                                'expected': state_dict(expected), 'original': state_dict(original), 'native': state_dict(actual),
                                'RAM_sha256': [digest(x) for x in (expected_ram, original_memory, ram[:])]}, indent=2))
                        if batch['block']:
                            if (returned.next_pc, returned.kind) != (expected.x[30], 4):
                                raise AssertionError('Native SIMD block did not return actual RET tuple')
                            counts['native_block_exit_checks'] += 1
                        state_corpus.update(bytes(initial))
                        counts[function['kind']] += 1
                        for operation in function['operations']:
                            observed_forms.add(canonical_form(operation))
                            vectors.add(operation['rt'])
                            if operation['kind'] == 'movi':
                                masks[operation['two_lanes']].add(operation['mask'])
                                movi_destinations[operation['two_lanes']].add(operation['rt'])
                            else:
                                bases.add(operation['rn'])
            pipe.send({'progress': batch_index + 1, 'batches': len(batches), 'comparisons': sum(v for k, v in counts.items() if k != 'native_block_exit_checks')})
    if len(observed_forms) != 42 or any(values != set(range(256)) for values in masks.values()) or any(values != set(range(32)) for values in movi_destinations.values()) or vectors != set(range(32)) or bases != set(range(32)):
        raise AssertionError('Not all canonical forms/masks/register roles were observed')
    total = sum(v for k, v in counts.items() if k != 'native_block_exit_checks')
    return {'three_way_register_state_comparisons': total, 'state_memory_comparisons': total,
            'native_block_exit_checks': counts.pop('native_block_exit_checks'), 'comparisons_by_kind': dict(counts),
            'canonical_forms_observed': sorted(observed_forms), 'movi_masks_observed_per_width': {str(k): len(v) for k, v in masks.items()},
            'movi_destinations_observed_per_width': {str(k): sorted(v) for k, v in movi_destinations.items()},
            'vector_registers_observed': sorted(vectors), 'base_registers_observed': sorted(bases),
            'state_corpus_sha256': state_corpus.hexdigest()}


def worker(pipe, batches):
    try:
        pipe.send({'result': execute_batches(batches, pipe)})
    except BaseException as error:
        pipe.send({'error': repr(error)})
    finally:
        pipe.close()


def bounded_cases(batches):
    context = multiprocessing.get_context('spawn')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, batches))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + 600
        while True:
            if receive.poll(1):
                message = receive.recv()
                if 'progress' in message:
                    print(f"SIMD {message['progress']}/{message['batches']}: {message['comparisons']} complete states+RAM", flush=True)
                    continue
                break
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'SIMD worker failed/timed out: {process.exitcode}')
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in message:
            raise AssertionError(f'SIMD worker failed: {message}, exit={process.exitcode}')
        return message['result']
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def fault_cases():
    cases = []
    for width in WIDTHS:
        for loading in (False, True):
            for mode in MODES:
                offset = {'unsigned': 0, 'unscaled': -16, 'pre': -16, 'post': 16}[mode]
                for rn in (0, 31):
                    cases.append({'width': width, 'loading': loading, 'mode': mode, 'offset': offset, 'rn': rn, 'protection': 'guard'})
                if not loading:
                    cases.append({'width': width, 'loading': loading, 'mode': mode, 'offset': offset, 'rn': 0, 'protection': 'readonly'})
            for mode in ('unsigned', 'pre', 'post'):
                cases.append({'width': width, 'loading': loading, 'mode': mode, 'offset': -16 if mode == 'pre' else 16 if mode == 'post' else 0, 'rn': 31, 'protection': 'sp_alignment'})
    for mode in MODES:
        cases.append({'width': 16, 'loading': True, 'mode': mode, 'offset': 0 if mode == 'unsigned' else -16, 'rn': 0, 'protection': 'crossing'})
    return cases


def verify_faults(cli, directory, compiler):
    spec = importlib.util.spec_from_file_location('simd_original_faults', ROOT / 'dev/memory-faults.py')
    faults = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(faults)
    observer = directory / 'simd-fault-observer'
    source_path = ROOT / 'dev/native-memory-faults.c'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(source_path), '-o', str(observer)], check=True)
    observations = []
    for index, case in enumerate(fault_cases()):
        operation = memory_op(case['width'], case['loading'], 31, case['rn'], case['offset'], case['mode'])
        source = struct.pack('<3I', move(2, 1, 7, 99), operation['word'], RET)
        path, output = directory / f'fault-{index}.arm64', directory / f'fault-{index}.native'
        path.write_bytes(source)
        manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(path), '--guest-base', hex(BASE), '--output-dir', str(output)], timeout=30))
        native = (output / 'native.bin').read_bytes()
        validate_manifest(manifest, source, native, False)
        if manifest['compiler_source_sha256'] != compiler:
            raise AssertionError('Fault compiler identity changed')
        pre_offset = case['offset'] if case['mode'] in ('unscaled', 'pre') else 0
        data = subprocess.check_output([str(observer), str(output / 'native.bin'), case['protection'], str(case['rn']), str(pre_offset)], timeout=10)
        (code_address, ram_address, page_size), initial, (number, native_pc, fault_address), actual, ram = parse_fault_record(data)
        if len(ram) != page_size or not number:
            raise AssertionError('SIMD fault observer did not report bounded fault RAM')
        native_offset = native_pc - code_address
        mapped = [guest for guest, offset in manifest['source_map'] if offset <= native_offset]
        if not mapped or mapped[-1] != BASE + 4:
            raise AssertionError('SIMD fault source map did not identify memory instruction')
        if case['protection'] == 'sp_alignment':
            expected = State.from_buffer_copy(initial)
            expected.x[7] = 99
            expected_ram, original_faults = b'\xa5' * page_size, None
            if number != signal.SIGILL:
                raise AssertionError('SIMD incoming SP check did not precede access')
        else:
            if number not in (signal.SIGSEGV, signal.SIGBUS):
                raise AssertionError('SIMD memory fault has unexpected host signal')
            expected, expected_ram, original_faults = faults.arm_fault(source, initial, ram_address, page_size, case['protection'] == 'readonly')
            if any(item['pc'] != BASE + 4 for item in original_faults):
                raise AssertionError('Original SIMD fault PC differs')
            base = initial.sp if case['rn'] == 31 else initial.x[case['rn']]
            effective = base + (0 if case['mode'] == 'post' else case['offset'])
            wanted_address = ram_address + page_size if case['protection'] == 'crossing' else effective
            if fault_address != wanted_address:
                raise AssertionError('SIMD host fault address differs')
        if bytes(actual) != bytes(expected) or ram != expected_ram:
            raise AssertionError(f'SIMD fault changed V/GPR/base state or RAM: {case}')
        observations.append({**case, 'passed': True, 'source_sha256': digest(source), 'native_sha256': digest(native),
                             'guest_fault_pc': BASE + 4, 'native_fault_offset': native_offset,
                             'native_signal': number, 'original_faults': original_faults})
    return {'fault_boundary_comparisons': len(observations), 'fault_results': observations,
            'fault_observer_source_sha256': digest(source_path.read_bytes()), 'fault_observer_executable_sha256': digest(observer.read_bytes()),
            'shared_fault_oracle_sha256': digest((ROOT / 'dev/memory-faults.py').read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    cli_hash = digest(cli.read_bytes())
    source_paths = [Path(__file__), ROOT / 'dev/differential.py', ROOT / 'dev/memory-faults.py', ROOT / 'dev/native-memory-faults.c']
    identities = {str(path): digest(path.read_bytes()) for path in source_paths}
    leaf, blocks = programs()
    batches, compiler = [], None
    with tempfile.TemporaryDirectory(prefix='stela-simd-') as temporary:
        directory = Path(temporary)
        for index, functions in enumerate([leaf[i:i + 512] for i in range(0, len(leaf), 512)] + [[case] for case in blocks]):
            block = index >= (len(leaf) + 511) // 512
            batch = compile_batch(cli, directory, functions, index, block)
            if compiler is not None and compiler != batch['compiler']:
                raise AssertionError('Compiler changed during SIMD suite')
            compiler = batch['compiler']
            batches.append(batch)
        result = bounded_cases(batches)
        result.update(verify_faults(cli, directory, compiler))
    if digest(cli.read_bytes()) != cli_hash or any(digest(path.read_bytes()) != identities[str(path)] for path in source_paths):
        raise AssertionError('SIMD compiler executable or shared sources changed during evidence collection')
    report = {'kind': 'simd_arm_vs_native_x86', 'passed': True, **result,
              'leaf_mini_functions': len(leaf), 'block_programs': len(blocks),
              'compilation_batches': [batch['receipt'] for batch in batches],
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_hash,
              'harness_source_sha256': identities[str(Path(__file__))], 'shared_runner_sha256': identities[str(ROOT / 'dev/differential.py')],
              'shared_sources_sha256': {str(path.relative_to(ROOT)): identities[str(path)] for path in source_paths[1:]},
              'guest_state_bytes': ctypes.sizeof(State), 'leaf_abi': LEAF_ABI, 'block_abi': BLOCK_ABI,
              'tested_state': ['x0..x30', 'SP', 'NZCV', 'reserved metadata', 'V0..V31 full128', 'FPCR', 'FPSR', 'all private RAM bytes'],
              'limits': 'Only42 reviewed data-movement forms, not SIMD arithmetic/FP arithmetic/PAC/MMIO/atomics/concurrency/process loading. Native execution is isolated and bounded. Leaf RET is harness-owned; representative block cases execute originalRET and check native return tuple. IncomingSPalignment faults follow declared enabled policy; Unicorn does not enforce that check. Qstores have no128-bit atomicity/rollback claim; fault tests use wholly inaccessible/readonly stores and crosspageQloads. No guest syndrome/exception delivery or full binary verification.'}
    destination = ROOT / '.stela/simd-differential-report.json'
    snapshot = write_evidence(destination, report)
    print(json.dumps({key: value for key, value in report.items() if key not in ('fault_results', 'compilation_batches')}, indent=2))


if __name__ == '__main__':
    main()
