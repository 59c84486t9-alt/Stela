#!/usr/bin/env python3
"""Original ARM, independent byte math and native x86 SIMD data movement.

Reviewed single B/H/S/D/Q transfers, MOVI D/2D and paired S/D/Q transfers are tested.
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
PAIR_WIDTHS = (4, 8, 16)
PAIR_MODES = ('offset', 'pre', 'post')


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


def pair_encoding(width, loading, rt, rt2, rn, offset, mode):
    if width not in PAIR_WIDTHS or any(not 0 <= register < 32 for register in (rt, rt2, rn)):
        raise ValueError('invalid SIMD pair width/register')
    if mode not in PAIR_MODES or offset % width or not -64 <= offset // width <= 63:
        raise ValueError('SIMD pair offset outside signed7 scaled range')
    opcode = {4: 0, 8: 1, 16: 2}[width]
    index = {'post': 1, 'offset': 2, 'pre': 3}[mode]
    return (opcode << 30) | 0x2c000000 | (index << 23) | (int(loading) << 22) | (((offset // width) & 127) << 15) | (rt2 << 10) | (rn << 5) | rt


def pair_op(width, loading, rt, rt2, rn, offset, mode):
    return {'kind': 'pair', 'width': width, 'loading': loading, 'rt': rt, 'rt2': rt2, 'rn': rn,
            'offset': offset, 'mode': mode, 'word': pair_encoding(width, loading, rt, rt2, rn, offset, mode)}


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
    if operation['kind'] == 'pair':
        return f"{'LDP' if operation['loading'] else 'STP'}_{operation['width']}_{operation['mode']}"
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


def pair_programs():
    result, blocks = [], []
    roles = ((0, 1, 0), (31, 0, 31), (0, 31, 31), (31, 30, 0),
             (7, 7, 7), (0, 0, 0), (31, 31, 31), (0, 7, 7))
    for width in PAIR_WIDTHS:
        for loading in (False, True):
            for mode in PAIR_MODES:
                for scaled in (-64, -1, 0, 1, 63):
                    for rt, rt2, rn in roles:
                        if loading and rt == rt2:
                            continue
                        result.append({'kind': 'pair_boundaries', 'operations': [pair_op(width, loading, rt, rt2, rn, scaled * width, mode)], 'flags': 16})
                for register in range(32):
                    for position in (0, 1):
                        rt, rt2 = (register, (register + 11) % 32) if position == 0 else ((register + 11) % 32, register)
                        result.append({'kind': 'pair_all_vector_positions', 'operations': [pair_op(width, loading, rt, rt2, (register + 1) % 32, 0, mode)], 'flags': 1})
                    result.append({'kind': 'pair_all_bases', 'operations': [pair_op(width, loading, register, (register + 1) % 32, register, 2 * width, mode)], 'flags': 1})
                    if not loading:
                        result.append({'kind': 'pair_duplicate_stores', 'operations': [pair_op(width, False, register, register, register, 0, mode)], 'flags': 1})
                blocks.append({'kind': 'pair_block', 'operations': [pair_op(width, loading, 0, 31, 0, 16, mode)], 'flags': 16})
        frame = max(16, 2 * width)
        result.append({'kind': 'pair_stack_chain', 'operations': [movi_op(True, 0xa5, 0), movi_op(True, 0x5a, 31),
            pair_op(width, False, 0, 31, 31, -frame, 'pre'), memory_op(1, True, 0, 31, 0, 'unsigned'),
            pair_op(width, True, 0, 31, 31, frame, 'post')], 'flags': 16})
        result.append({'kind': 'pair_mixed_chain', 'operations': [pair_op(width, False, 0, 31, 0, 0, 'offset'),
            memory_op(16, True, 7, 0, 0, 'unsigned'), pair_op(16, False, 7, 7, 0, 64, 'offset'),
            pair_op(width, True, 0, 31, 0, 0, 'offset')], 'flags': 16})
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
        registers = [rt, operation['rt2']] if operation['kind'] == 'pair' else [rt]
        if operation['loading'] and len(registers) == 2 and registers[0] == registers[1]:
            raise ValueError('constrained-unpredictable duplicate SIMD pair load')
        if not 0 <= position <= len(ram) - width * len(registers):
            raise ValueError('oracle memory access outside owned RAM')
        if operation['loading']:
            values = [int.from_bytes(ram[position + slot * width:position + (slot + 1) * width], 'little')
                      for slot in range(len(registers))]
            for register, value in zip(registers, values):
                state.v[register][:] = [value & MASK, value >> 64]
        else:
            values = [state.v[register][0] | (state.v[register][1] << 64) for register in registers]
            for slot, value in enumerate(values):
                ram[position + slot * width:position + (slot + 1) * width] = value.to_bytes(16, 'little')[:width]
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
    if len(disassembly) != len(words) or any(i.mnemonic not in {'ldr', 'str', 'ldur', 'stur', 'ldp', 'stp', 'movi', 'ret', 'and', 'bic', 'orr', 'orn', 'eor', 'bsl', 'bit', 'bif', 'add', 'sub', 'abs', 'neg', 'mov'} for i in disassembly):
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
    memories = [operation for operation in function['operations'] if operation['kind'] in ('memory', 'pair')]
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
        for slot in range(2 if operation['kind'] == 'pair' else 1):
            # Distinct neighboring values prove both pair positions and order.
            element = value if slot == 0 else value ^ 0xfedcba98765432100123456789abcdef
            ram[position + slot * width:position + (slot + 1) * width] = element.to_bytes(16, 'little')[:width]
    elif memories:
        initial.x[0] = ram_address + 0x600
        initial.sp = ram_address + 0x1000
    return initial, bytes(ram)


def execute_batches(batches, pipe):
    cohort_counts = {'single': Counter(), 'pair': Counter()}
    corpus_by_cohort = {'single': hashlib.sha256(), 'pair': hashlib.sha256()}
    pair_forms, pair_registers, pair_bases, duplicate_stores = set(), {}, {}, {}
    observed_forms, masks, vectors, bases = set(), {False: set(), True: set()}, set(), set()
    movi_destinations = {False: set(), True: set()}
    templates = states(all_flags=True)
    original_ram = random.Random(0x51d5c0de).randbytes(RAM_BYTES)
    with mmap.mmap(-1, RAM_BYTES, prot=mmap.PROT_READ | mmap.PROT_WRITE) as ram:
        marker = ctypes.c_char.from_buffer(ram)
        address = ctypes.addressof(marker)
        del marker
        for batch_index, batch in enumerate(batches):
            cohort = batch['cohort']
            counts = cohort_counts[cohort]
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
                        corpus_by_cohort[cohort].update(bytes(initial))
                        counts[function['kind']] += 1
                        for operation in function['operations']:
                            form = canonical_form(operation)
                            if cohort == 'pair' and operation['kind'] == 'pair':
                                pair_forms.add(form)
                                positions = pair_registers.setdefault(form, [set(), set()])
                                positions[0].add(operation['rt'])
                                positions[1].add(operation['rt2'])
                                pair_bases.setdefault(form, set()).add(operation['rn'])
                                if not operation['loading'] and operation['rt'] == operation['rt2']:
                                    duplicate_stores.setdefault(form, set()).add(operation['rt'])
                            elif cohort == 'single':
                                observed_forms.add(form)
                                vectors.add(operation['rt'])
                                if operation['kind'] == 'movi':
                                    masks[operation['two_lanes']].add(operation['mask'])
                                    movi_destinations[operation['two_lanes']].add(operation['rt'])
                                else:
                                    bases.add(operation['rn'])
            pipe.send({'progress': batch_index + 1, 'batches': len(batches), 'comparisons': sum(v for counter in cohort_counts.values() for k, v in counter.items() if k != 'native_block_exit_checks')})
    if len(observed_forms) != 42 or any(values != set(range(256)) for values in masks.values()) or any(values != set(range(32)) for values in movi_destinations.values()) or vectors != set(range(32)) or bases != set(range(32)):
        raise AssertionError('Not all canonical forms/masks/register roles were observed')
    if (len(pair_forms) != 18 or any(position != set(range(32)) for positions in pair_registers.values() for position in positions)
            or any(values != set(range(32)) for values in pair_bases.values()) or len(duplicate_stores) != 9
            or any(values != set(range(32)) for values in duplicate_stores.values())):
        raise AssertionError('Not every pair form/register position/base/duplicate-store role was observed')
    single, pair = cohort_counts['single'], cohort_counts['pair']
    total = sum(v for k, v in single.items() if k != 'native_block_exit_checks')
    pair_total = sum(v for k, v in pair.items() if k != 'native_block_exit_checks')
    return {'three_way_register_state_comparisons': total, 'state_memory_comparisons': total,
            'native_block_exit_checks': single.pop('native_block_exit_checks'), 'comparisons_by_kind': dict(single),
            'pair_three_way_register_state_comparisons': pair_total, 'pair_state_memory_comparisons': pair_total,
            'pair_native_block_exit_checks': pair.pop('native_block_exit_checks'), 'pair_comparisons_by_kind': dict(pair),
            'total_three_way_register_state_comparisons': total + pair_total,
            'canonical_forms_observed': sorted(observed_forms), 'pair_canonical_forms_observed': sorted(pair_forms),
            'movi_masks_observed_per_width': {str(k): len(v) for k, v in masks.items()},
            'movi_destinations_observed_per_width': {str(k): sorted(v) for k, v in movi_destinations.items()},
            'vector_registers_observed': sorted(vectors), 'base_registers_observed': sorted(bases),
            'pair_vector_positions_by_form': {form: [sorted(v) for v in positions] for form, positions in sorted(pair_registers.items())},
            'pair_base_registers_by_form': {form: sorted(v) for form, v in sorted(pair_bases.items())},
            'duplicate_store_registers_by_form': {form: sorted(v) for form, v in sorted(duplicate_stores.items())},
            'state_corpus_sha256': corpus_by_cohort['single'].hexdigest(), 'pair_state_corpus_sha256': corpus_by_cohort['pair'].hexdigest()}


def worker(pipe, batches):
    try:
        pipe.send({'result': execute_integer_batches(batches) if batches[0].get('cohort')=='integer' else execute_batches(batches, pipe)})
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


def pair_fault_cases():
    cases = []
    for width in PAIR_WIDTHS:
        for loading in (False, True):
            for mode in PAIR_MODES:
                for rn in (0, 31):
                    cases.append({'pair': True, 'width': width, 'loading': loading, 'rt': 0, 'rt2': 31,
                                  'rn': rn, 'mode': mode, 'offset': -16 if mode != 'post' else 16, 'protection': 'guard'})
                    # S/D post-indexed second-element boundary cannot have an
                    # aligned incoming SP; pre/offset can compensate by -width.
                    if rn != 31 or width == 16 or mode != 'post':
                        cases.append({'pair': True, 'width': width, 'loading': loading, 'rt': 0, 'rt2': 31,
                                      'rn': rn, 'mode': mode, 'offset': -width if mode != 'post' else 16, 'protection': 'pair_second'})
                    if rn == 31:
                        cases.append({'pair': True, 'width': width, 'loading': loading, 'rt': 0, 'rt2': 31,
                                      'rn': rn, 'mode': mode, 'offset': -16 if mode == 'pre' else 0, 'protection': 'sp_alignment'})
                if not loading:
                    cases.append({'pair': True, 'width': width, 'loading': False, 'rt': 0, 'rt2': 31, 'rn': 0,
                                  'mode': mode, 'offset': -16 if mode != 'post' else 16, 'protection': 'readonly'})
                    for rt, rt2 in ((0, 31), (0, 0), (31, 31)):
                        cases.append({'pair': True, 'width': width, 'loading': False, 'rt': rt, 'rt2': rt2, 'rn': 0,
                                      'mode': mode, 'offset': -width if mode != 'post' else 16, 'protection': 'pair_readonly'})
    return cases


def declined_pair_encodings():
    result = []
    for width in PAIR_WIDTHS:
        for mode in PAIR_MODES:
            for register in (0, 7, 31):
                result.append({'reason': 'constrained_duplicate_load', 'word': pair_encoding(width, True, register, register, 0, 0, mode)})
    for mode in PAIR_MODES:
        result.append({'reason': 'reserved_opc', 'word': (pair_encoding(16, True, 0, 1, 0, 0, mode) & ~(3 << 30)) | (3 << 30)})
    for width in PAIR_WIDTHS:
        result.append({'reason': 'non_temporal_pair_outside_profile', 'word': pair_encoding(width, True, 0, 1, 0, 0, 'offset') & ~(3 << 23)})
    return result


def verify_declined_pairs(cli, directory):
    results = []
    for index, case in enumerate(declined_pair_encodings()):
        path, output = directory / f'declined-{index}.arm64', directory / f'declined-{index}.native'
        path.write_bytes(struct.pack('<2I', case['word'], RET))
        completed = subprocess.run([str(cli), 'compile-leaf', str(path), '--guest-base', hex(BASE), '--output-dir', str(output)], capture_output=True, text=True, timeout=30)
        if completed.returncode == 0 or (output / 'native.bin').exists():
            raise AssertionError(f'Unsupported SIMD pair was emitted: {case}')
        results.append({**case, 'source_sha256': digest(path.read_bytes()), 'error': completed.stderr.strip()})
    return {'declined_pair_inputs_before_execution': len(results), 'declined_pair_results': results}


def validate_pair_fault_state(case, initial, native, original, first_element):
    """Keep staged native policy separate from exact Unicorn observations."""
    staged = State.from_buffer_copy(initial)
    staged.x[7] = 99
    if bytes(native) != bytes(staged):
        raise AssertionError('Failed pair committed a V destination, base or other state')
    if case['protection'] == 'sp_alignment':
        if original is not None:
            raise AssertionError('SP alignment policy must not claim original execution')
        return 'sp_policy_only'
    if original is None:
        raise AssertionError('Pair memory fault is missing original observation')
    expected_original = State.from_buffer_copy(staged)
    second_load = case['loading'] and case['protection'] == 'pair_second'
    if second_load:
        if len(first_element) != case['width']:
            raise AssertionError('First-load observation has incorrect byte extent')
        value = int.from_bytes(first_element, 'little')
        expected_original.v[case['rt']][:] = [value & MASK, value >> 64]
    if bytes(original) != bytes(expected_original):
        raise AssertionError('Original pair fault differs beyond its exact observed first-load effect')
    return 'unicorn_second_load_divergence' if second_load else 'original_native_full_state_equal'


def verify_faults(cli, directory, compiler):
    spec = importlib.util.spec_from_file_location('simd_original_faults', ROOT / 'dev/memory-faults.py')
    faults = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(faults)
    observer = directory / 'simd-fault-observer'
    source_path = ROOT / 'dev/native-memory-faults.c'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(source_path), '-o', str(observer)], check=True)
    observations = {'single': [], 'pair': []}
    partial_stores = 0
    pair_classifications = Counter()
    for index, case in enumerate(fault_cases() + pair_fault_cases()):
        paired = case.get('pair', False)
        operation = (pair_op(case['width'], case['loading'], case['rt'], case['rt2'], case['rn'], case['offset'], case['mode'])
                     if paired else memory_op(case['width'], case['loading'], 31, case['rn'], case['offset'], case['mode']))
        source = struct.pack('<3I', move(2, 1, 7, 99), operation['word'], RET)
        path, output = directory / f'fault-{index}.arm64', directory / f'fault-{index}.native'
        path.write_bytes(source)
        manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(path), '--guest-base', hex(BASE), '--output-dir', str(output)], timeout=30))
        native = (output / 'native.bin').read_bytes()
        validate_manifest(manifest, source, native, False)
        if manifest['compiler_source_sha256'] != compiler:
            raise AssertionError('Fault compiler identity changed')
        pre_offset = case['offset'] if case['mode'] in ('unscaled', 'offset', 'pre') else 0
        arguments = [str(observer), str(output / 'native.bin'), case['protection'], str(case['rn']), str(pre_offset)]
        if case['protection'] in ('pair_second', 'pair_readonly'):
            arguments.append(str(case['width']))
        data = subprocess.check_output(arguments, timeout=10)
        (code_address, ram_address, page_size), initial, (number, native_pc, fault_address), actual, ram = parse_fault_record(data)
        observed_bytes = page_size * (2 if case['protection'] == 'pair_readonly' else 1)
        if len(ram) != observed_bytes or not number:
            raise AssertionError('SIMD fault observer did not report bounded fault RAM')
        native_offset = native_pc - code_address
        mapped = [guest for guest, offset in manifest['source_map'] if offset <= native_offset]
        if not mapped or mapped[-1] != BASE + 4:
            raise AssertionError('SIMD fault source map did not identify memory instruction')
        if case['protection'] == 'sp_alignment':
            expected = State.from_buffer_copy(initial)
            expected.x[7] = 99
            expected_ram, original_faults = b'\xa5' * observed_bytes, None
            if number != signal.SIGILL:
                raise AssertionError('SIMD incoming SP check did not precede access')
        else:
            if number not in (signal.SIGSEGV, signal.SIGBUS):
                raise AssertionError('SIMD memory fault has unexpected host signal')
            expected, expected_ram, original_faults = faults.arm_fault(source, initial, ram_address, page_size, case['protection'] == 'readonly', second_readonly=case['protection'] == 'pair_readonly')
            if any(item['pc'] != BASE + 4 for item in original_faults):
                raise AssertionError('Original SIMD fault PC differs')
            base = initial.sp if case['rn'] == 31 else initial.x[case['rn']]
            effective = base + (0 if case['mode'] == 'post' else case['offset'])
            wanted_address = ram_address + page_size if case['protection'] in ('crossing', 'pair_second', 'pair_readonly') else effective
            if fault_address != wanted_address:
                raise AssertionError('SIMD host fault address differs')
        if ram != expected_ram or (not paired and bytes(actual) != bytes(expected)):
            raise AssertionError(f'SIMD fault changed V/GPR/base state or RAM: {case}')
        classification = None
        if paired:
            classification = validate_pair_fault_state(case, initial, actual, expected if original_faults is not None else None, b'\xa5' * case['width'])
            pair_classifications[classification] += 1
            expect_partial = not case['loading'] and case['protection'] in ('pair_second', 'pair_readonly')
            changed = ram != b'\xa5' * observed_bytes
            if changed != expect_partial:
                raise AssertionError('Pair fault has unexpected first-element visibility')
            if expect_partial:
                first = (initial.v[case['rt']][0] | initial.v[case['rt']][1] << 64).to_bytes(16, 'little')[:case['width']]
                if ram[page_size - case['width']:page_size] != first:
                    raise AssertionError('Second-element fault did not retain exact first store')
                partial_stores += 1
        observations['pair' if paired else 'single'].append({**case, **({'native_fault_policy_verified': True} if paired else {'passed': True}),
                             'source_sha256': digest(source), 'native_sha256': digest(native),
                             'guest_fault_pc': BASE + 4, 'native_fault_offset': native_offset,
                             'native_signal': number, 'original_faults': original_faults,
                             **({'fault_state_classification': classification,
                                 'original_native_full_state_equal': bytes(actual) == bytes(expected) if original_faults is not None else None,
                                 'initial_state_hex': bytes(initial).hex(),
                                 'native_state_hex': bytes(actual).hex(),
                                 'original_state_hex': bytes(expected).hex() if original_faults is not None else None,
                                 'native_ram_sha256': digest(ram), 'original_ram_sha256': digest(expected_ram) if original_faults is not None else None}
                                if paired else {})})
    if pair_classifications != Counter({'original_native_full_state_equal': 88, 'unicorn_second_load_divergence': 16, 'sp_policy_only': 18}):
        raise AssertionError(f'Unexpected pair fault observation classes: {pair_classifications}')
    return {'fault_boundary_comparisons': len(observations['single']), 'fault_results': observations['single'],
            'pair_fault_boundary_comparisons': len(observations['pair']), 'pair_fault_results': observations['pair'],
            'pair_partial_first_store_comparisons': partial_stores,
            'pair_native_staged_fault_policy_comparisons': len(observations['pair']),
            'pair_original_native_fault_full_state_equal_comparisons': pair_classifications['original_native_full_state_equal'],
            'pair_unicorn_second_load_fault_divergences': pair_classifications['unicorn_second_load_divergence'],
            'pair_sp_alignment_policy_only_comparisons': pair_classifications['sp_policy_only'],
            'fault_observer_source_sha256': digest(source_path.read_bytes()), 'fault_observer_executable_sha256': digest(observer.read_bytes()),
            'shared_fault_oracle_sha256': digest((ROOT / 'dev/memory-faults.py').read_bytes())}



INTEGER_BASES = {'and':0x0e201c00,'bic':0x0e601c00,'orr':0x0ea01c00,'orn':0x0ee01c00,
                 'eor':0x2e201c00,'bsl':0x2e601c00,'bit':0x2ea01c00,'bif':0x2ee01c00,
                 'add':0x0e208400,'sub':0x2e208400,'abs':0x0e20b800,'neg':0x2e20b800}


def integer_programs():
    configurations=[]
    for name,base in INTEGER_BASES.items():
        if name in ('add','sub','abs','neg'):
            configurations.extend((name,base|(q<<30)|(size<<22),8<<q,1<<size)
                for q in (0,1) for size in range(4) if size!=3 or q)
            configurations.append((name,(0x5ee08400 if name=='add' else 0x7ee08400 if name=='sub'
                                         else 0x5ee0b800 if name=='abs' else 0x7ee0b800),8,8))
        else: configurations.extend((name,base|(q<<30),8<<q,1) for q in (0,1))
    programs=[]
    for name,base,width,lane in configurations:
        def operation(d,n,m):
            unary=name in ('abs','neg')
            return {'kind':'integer','name':name,'width':width,'lane':lane,'d':d,'n':n,'m':m,
                    'word':base|(n<<5)|d|(0 if unary else m<<16)}
        for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,30),(0,31,31),(31,0,31)):
            programs.append({'operations':[operation(d,n,m)]})
        programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def integer_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v]
    for op in operations:
        name,width,lane,d,n,m=(op[k] for k in ('name','width','lane','d','n','m'))
        mask=(1<<(width*8))-1
        a,b,old=(vectors[r]&mask for r in (n,m,d))
        logical={'and':a&b,'bic':a&~b,'orr':a|b,'orn':a|~b,'eor':a^b,
                 'bsl':(old&a)|(~old&b),'bit':(old&~b)|(a&b),'bif':(old&b)|(a&~b)}
        if name in logical: value=logical[name]&mask
        else:
            value=0;bits=lane*8;lane_mask=(1<<bits)-1
            for offset in range(0,width*8,bits):
                left,right=(v>>offset&lane_mask for v in (a,b))
                signed=left-(1<<bits) if left&(1<<(bits-1)) else left
                result=left+right if name=='add' else left-right if name=='sub' else abs(signed) if name=='abs' else -signed
                value|=(result&lane_mask)<<offset
        vectors[d]=value # Q=0/scalar writes clear every upper vector bit.
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors]}


def execute_integer_batches(batches):
    corpus,comparisons=hashlib.sha256(),0
    for batch in batches:
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        machine.mem_map(BASE,(len(batch['source'])+4095)&~4095);machine.mem_write(BASE,batch['source'])
        with executable(batch['native']) as address:
            for function,entry,offset in zip(batch['functions'],batch['entries'],batch['offsets']):
                native=ctypes.CFUNCTYPE(None,ctypes.POINTER(State))(address+offset)
                operations=function['operations'];lane=operations[0]['lane'];bits=lane*8
                for flags in (0,15):
                    for pattern in range(5):
                        initial=State.from_buffer_copy(states(all_flags=True)[flags]);initial.nzcv=flags<<28
                        initial.reserved=0x51ad1234
                        seed_extended_state(initial,pattern*16+flags)
                        if pattern<4:
                            values=(0,(1<<bits)-1,1<<(bits-1),(1<<(bits-1))-1,1)
                            for register in range(32):
                                value=sum(values[(register+i+pattern)%len(values)]<<(i*bits) for i in range(128//bits))
                                initial.v[register][:]=[value&MASK,value>>64]
                        initialize_arm(machine,initial)
                        end=BASE+(entry+len(operations))*4
                        machine.emu_start(BASE+entry*4,end,count=len(operations)+1)
                        assert machine.reg_read(arm.UC_ARM64_REG_PC)==end
                        original=state_dict(capture_arm(machine,initial))
                        mathematical=integer_mathematical(operations,initial)
                        actual=State.from_buffer_copy(initial);native(ctypes.byref(actual));actual=state_dict(actual)
                        if mathematical!=original or original!=actual:
                            raise AssertionError(json.dumps({'operations':operations,'initial':state_dict(initial),
                                'math':mathematical,'arm':original,'native':actual}))
                        corpus.update(struct.pack('<'+'I'*len(operations),*(op['word'] for op in operations)))
                        corpus.update(bytes(initial));comparisons+=1
    return {'three_way_register_state_comparisons':comparisons,'state_corpus_sha256':corpus.hexdigest()}


def run_integer_cohort(cli):
    functions=integer_programs();started=time.monotonic()
    cli_hash,harness_hash=digest(cli.read_bytes()),digest(Path(__file__).read_bytes())
    with tempfile.TemporaryDirectory(prefix='stela-simd-integer-') as temporary:
        batch=compile_batch(cli,Path(temporary),functions,0);batch['cohort']='integer'
        result=bounded_cases([batch])
    assert digest(cli.read_bytes())==cli_hash and digest(Path(__file__).read_bytes())==harness_hash
    report={'kind':'simd_integer_arm_vs_native_x86','passed':True,**result,'programs':len(functions),
        'compiler_source_sha256':batch['compiler'],'compiler_executable_sha256':cli_hash,
        'harness_source_sha256':harness_hash,'shared_runner_sha256':digest((ROOT/'dev/differential.py').read_bytes()),
        'corpus_sha256':digest(batch['source']),'compilation':batch['receipt'],
        'verification_wall_seconds':time.monotonic()-started,
        'limits':'Focused non-saturating integer/logical SIMD semantics with FP/AdvSIMD enabled; no FP arithmetic, traps, disabled-feature behavior or application-performance claim. Leaf RET is harness-owned.'}
    write_evidence(ROOT/'.stela/simd-integer-differential-report.json',report)
    print(json.dumps(report,indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--focus', choices=['integer'], help='Only the focused SIMD integer implementation cohort')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    if arguments.focus:
        run_integer_cohort(cli)
        return
    cli_hash = digest(cli.read_bytes())
    source_paths = [Path(__file__), ROOT / 'dev/differential.py', ROOT / 'dev/memory-faults.py', ROOT / 'dev/native-memory-faults.c']
    identities = {str(path): digest(path.read_bytes()) for path in source_paths}
    leaf, blocks = programs()
    pair_leaf, pair_blocks = pair_programs()
    batches, compiler = [], None
    destination = ROOT / '.stela/simd-differential-report.json'
    previous_evidence = digest(destination.read_bytes()) if destination.exists() else None
    with tempfile.TemporaryDirectory(prefix='stela-simd-') as temporary:
        directory = Path(temporary)
        jobs = []
        for cohort, functions, representative in [('single', leaf, blocks), ('pair', pair_leaf, pair_blocks)]:
            jobs.extend((cohort, functions[i:i + 512], False) for i in range(0, len(functions), 512))
            jobs.extend((cohort, [case], True) for case in representative)
        for index, (cohort, functions, block) in enumerate(jobs):
            batch = compile_batch(cli, directory, functions, index, block)
            batch['cohort'] = cohort
            batch['receipt']['cohort'] = cohort
            if compiler is not None and compiler != batch['compiler']:
                raise AssertionError('Compiler changed during SIMD suite')
            compiler = batch['compiler']
            batches.append(batch)
        result = bounded_cases(batches)
        result.update(verify_faults(cli, directory, compiler))
        result.update(verify_declined_pairs(cli, directory))
    if digest(cli.read_bytes()) != cli_hash or any(digest(path.read_bytes()) != identities[str(path)] for path in source_paths):
        raise AssertionError('SIMD compiler executable or shared sources changed during evidence collection')
    report = {'kind': 'simd_arm_vs_native_x86', 'passed': True, **result,
              'leaf_mini_functions': len(leaf), 'block_programs': len(blocks),
              'pair_leaf_mini_functions': len(pair_leaf), 'pair_block_programs': len(pair_blocks),
              'previous_evidence_sha256': previous_evidence,
              'cohort_source_sha256': {cohort: digest(b''.join(batch['source'] for batch in batches if batch['cohort'] == cohort)) for cohort in ('single', 'pair')},
              'compilation_batches': [batch['receipt'] for batch in batches],
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_hash,
              'harness_source_sha256': identities[str(Path(__file__))], 'shared_runner_sha256': identities[str(ROOT / 'dev/differential.py')],
              'shared_sources_sha256': {str(path.relative_to(ROOT)): identities[str(path)] for path in source_paths[1:]},
              'guest_state_bytes': ctypes.sizeof(State), 'leaf_abi': LEAF_ABI, 'block_abi': BLOCK_ABI,
              'tested_state': ['x0..x30', 'SP', 'NZCV', 'reserved metadata', 'V0..V31 full128', 'FPCR', 'FPSR', 'all private RAM bytes'],
              'limits': 'Separate42single/MOVI and18paired data-movement forms, not SIMD arithmetic/FP arithmetic/PAC/MMIO/atomics/concurrency/process loading. Native execution is isolated and bounded. Leaf RET is harness-owned; representative block cases execute originalRET and check native return tuple. IncomingSPalignment faults follow declared enabled policy; Unicorn does not enforce that check. Pair loads stage both destinations under the declared native fault policy:122 native-policy checks,88 original/native full-state equal observations,16 explicitly retained Unicorn second-load divergences,18 SP-policy-only checks. Arm ASL reads whole Mem before vector assignments; Unicorn/current QEMU vector paths perform sequential loads. These observations establish neither an emulator defect nor Apple hardware/guest-fault conformance. Second-store faults preserve the completed first element under this private-RAM profile. Qstores have no128-bit atomicity/rollback claim; fault tests use wholly inaccessible/readonly stores and crosspageQloads. No guest syndrome/exception delivery or full binary verification.'}
    destination = ROOT / '.stela/simd-differential-report.json'
    snapshot = write_evidence(destination, report)
    print(json.dumps({key: value for key, value in report.items() if key not in ('fault_results', 'pair_fault_results', 'declined_pair_results', 'compilation_batches')}, indent=2))


if __name__ == '__main__':
    main()
