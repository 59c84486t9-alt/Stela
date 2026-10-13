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
import math
import multiprocessing
from pathlib import Path
import random
import signal
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_X86, CS_MODE_64
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


def validate_manifest(manifest, source, native, block, target_cpu=None):
    if target_cpu is not None and manifest.get("target_cpu") != target_cpu:
        raise AssertionError("SIMD manifest CPU requirements differ from selection")
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


def compile_batch(cli, directory, functions, index, block=False, cpu_target="baseline", target_id="x86_64-baseline"):
    words, entries = [], []
    for function in functions:
        entries.append(len(words))
        words.extend(operation['word'] for operation in function['operations'])
        words.append(RET)
    source = struct.pack('<' + 'I' * len(words), *words)
    disassembly = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(source, BASE))
    if len(disassembly) != len(words) or any(i.mnemonic not in {'ldr', 'str', 'ldur', 'stur', 'ldp', 'stp', 'movi', 'ret', 'and', 'bic', 'orr', 'orn', 'eor', 'bsl', 'bit', 'bif', 'add', 'sub', 'abs', 'neg', 'mov', 'cmeq', 'cmgt', 'cmge', 'cmhi', 'cmhs', 'cmlt', 'cmle', 'cmtst', 'dup', 'ins', 'smov', 'umov', 'ext', 'rev16', 'rev32', 'rev64', 'zip1', 'zip2', 'uzp1', 'uzp2', 'trn1', 'trn2', 'tbl', 'tbx', 'shl', 'sshr', 'ushr', 'srshr', 'urshr', 'ssra', 'usra', 'srsra', 'ursra', 'sli', 'sri', 'shrn', 'shrn2', 'rshrn', 'rshrn2', 'sshll', 'sshll2', 'ushll', 'ushll2', 'sxtl', 'sxtl2', 'uxtl', 'uxtl2', 'smin', 'smax', 'umin', 'umax', 'sminp', 'smaxp', 'uminp', 'umaxp', 'sminv', 'smaxv', 'uminv', 'umaxv', 'addv', 'addp', 'saddlv', 'uaddlv', 'cnt', 'clz', 'cls', 'rbit', 'mvn', 'not', 'sqadd', 'uqadd', 'sqsub', 'uqsub', 'sqabs', 'sqneg', 'suqadd', 'usqadd', 'sqxtn', 'sqxtn2', 'uqxtn', 'uqxtn2', 'sqxtun', 'sqxtun2', 'mul', 'mla', 'mls', 'smull', 'smull2', 'umull', 'umull2', 'smlal', 'smlal2', 'umlal', 'umlal2', 'smlsl', 'smlsl2', 'umlsl', 'umlsl2', 'saddl', 'saddl2', 'uaddl', 'uaddl2', 'ssubl', 'ssubl2', 'usubl', 'usubl2', 'saddw', 'saddw2', 'uaddw', 'uaddw2', 'ssubw', 'ssubw2', 'usubw', 'usubw2', 'sabd', 'uabd', 'saba', 'uaba', 'sabdl', 'sabdl2', 'uabdl', 'uabdl2', 'sabal', 'sabal2', 'uabal', 'uabal2', 'shadd', 'uhadd', 'srhadd', 'urhadd', 'shsub', 'uhsub', 'addhn', 'addhn2', 'raddhn', 'raddhn2', 'subhn', 'subhn2', 'rsubhn', 'rsubhn2', 'saddlp', 'uaddlp', 'sadalp', 'uadalp', 'xtn', 'xtn2', 'shll', 'shll2', 'mvni', 'fmov'} for i in disassembly):
        raise AssertionError('Independent decoder declined SIMD fixture')
    path = directory / f'program-{index}.arm64'
    path.write_bytes(source)
    output = directory / f'native-{index}'
    manifest = json.loads(subprocess.check_output([str(cli), 'compile-block' if block else 'compile-leaf', str(path), '--guest-base', hex(BASE), '--output-dir', str(output), '--cpu-target', cpu_target], timeout=60))
    native = (output / 'native.bin').read_bytes()
    offsets = validate_manifest(manifest, source, native, block, target_id)
    if not block:
        for entry, function in zip(entries, functions):
            if native[offsets[entry + len(function['operations'])]] != 0xc3:
                raise AssertionError('Independent mini-function has no exact host RET boundary')
    return {'functions': functions, 'source': source, 'native': native, 'entries': entries,
            'offsets': [offsets[entry] for entry in entries], 'block': block,
            'compiler': manifest['compiler_source_sha256'],
            'receipt': {'functions': len(functions), 'source_bytes': len(source), 'source_sha256': digest(source),
                        'native_bytes': len(native), 'native_sha256': digest(native),
                        'source_map_sha256': digest(json.dumps(manifest['source_map']).encode()), 'block': block,
                        'target_cpu': manifest['target_cpu']}}


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
        pipe.send({'result': execute_register_batches(batches) if batches[0].get('cohort') in REGISTER_COHORTS else execute_batches(batches, pipe)})
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
    compares={'cmeq':0x2e208c00,'cmgt':0x0e203400,'cmge':0x0e203c00,'cmhi':0x2e203400,
              'cmhs':0x2e203c00,'cmtst':0x0e208c00,'cmeq0':0x0e209800,'cmgt0':0x0e208800,
              'cmge0':0x2e208800,'cmlt0':0x0e20a800,'cmle0':0x2e209800}
    for name,base in compares.items():
        configurations.extend((name,base|(q<<30)|(size<<22),8<<q,1<<size)
            for q in (0,1) for size in range(4) if size!=3 or q)
        configurations.append((name,base|0x50c00000,8,8))
    programs=[]
    for name,base,width,lane in configurations:
        def operation(d,n,m):
            unary=name in ('abs','neg') or name.endswith('0')
            return {'kind':'integer','name':name,'width':width,'lane':lane,'d':d,'n':n,'m':m,
                    'word':base|(n<<5)|d|(0 if unary else m<<16)}
        for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,30),(0,31,31),(31,0,31)):
            programs.append({'operations':[operation(d,n,m)]})
        programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def rearrange_programs():
    configurations=[]
    for name,base in [('dupg',0x0e000c00),('dupv',0x0e000400),('dups',0x5e000400),
                      ('insg',0x4e001c00),('insv',0x6e000400),('smov',0x0e002c00),('umov',0x0e003c00)]:
        for q in ((1,) if name in ('dups','insg','insv') else (0,1)):
            for imm5 in range(1,32):
                if not imm5&15: continue
                lane=(imm5&-imm5);size=lane.bit_length()-1
                if name.startswith('dup') and name!='dups' and not q and size==3: continue
                if name=='smov' and size>=2+q: continue
                if name=='umov' and ((q==1)!=(size==3)): continue
                indices={0,15,(imm5>>(size+1))*lane,lane-1} if name=='insv' else {0}
                for imm4 in sorted(indices):
                    configurations.append({'name':name,'base':base|(q<<30)|(imm5<<16)|(imm4<<11),
                        'lane':lane,'bytes':8<<q,'index':imm5>>(size+1),'source_index':imm4>>size})
    for q in (0,1):
        for offset in range(8<<q):
            configurations.append({'name':'ext','base':0x2e000000|(q<<30)|(offset<<11),'lane':1,'bytes':8<<q,'offset':offset})
        for name,base,container in [('rev16',0x0e201800,2),('rev32',0x2e200800,4),('rev64',0x0e200800,8)]:
            for size in range(container.bit_length()-1):
                configurations.append({'name':name,'base':base|(q<<30)|(size<<22),'lane':1<<size,'bytes':8<<q,'container':container})
        for name,base in [('zip1',0x0e003800),('zip2',0x0e007800),('uzp1',0x0e001800),('uzp2',0x0e005800),('trn1',0x0e002800),('trn2',0x0e006800)]:
            for size in range(4):
                if size==3 and not q: continue
                configurations.append({'name':name,'base':base|(q<<30)|(size<<22),'lane':1<<size,'bytes':8<<q})
        for preserve in (0,1):
            for regs in range(1,5):
                configurations.append({'name':'tbx' if preserve else 'tbl','base':0x0e000000|(q<<30)|(preserve<<12)|((regs-1)<<13),'lane':1,'bytes':8<<q,'registers':regs})
    programs=[]
    for config in configurations:
        def operation(d,n,m):
            # Only EXT/ZIP/UZP/TRN/TBL/TBX have a second vector field.
            binary=config['name'] in ('ext','tbl','tbx') or config['name'].startswith(('zip','uzp','trn'))
            return {**config,'kind':'rearrange','d':d,'n':n,'m':m,
                    'word':config['base']|(n<<5)|d|(m<<16 if binary else 0)}
        for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31),(0,31,31),(31,29,31)):
            programs.append({'operations':[operation(d,n,m)]})
        programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def rearrange_mathematical(operations,initial):
    vectors=[list(struct.pack('<2Q',*v)) for v in initial.v]
    gprs=list(initial.x)
    for op in operations:
        name,d,n,m,lane,width=(op[k] for k in ('name','d','n','m','lane','bytes'))
        a,b,old=vectors[n][:],vectors[m][:],vectors[d][:]
        if name in ('dupg','dupv','dups','insg','insv','smov','umov'):
            index=op['index'];source_index=op['source_index'] if name=='insv' else index
            element=list((0 if n==31 else gprs[n]).to_bytes(8,'little')[:lane]) if name in ('dupg','insg') else a[source_index*lane:(source_index+1)*lane]
            if name in ('smov','umov'):
                value=int.from_bytes(bytes(element),'little',signed=name=='smov')
                if d!=31: gprs[d]=value&((1<<(64 if width==16 else 32))-1)
                continue
            if name.startswith('ins'):
                result=old;result[index*lane:(index+1)*lane]=element
            else:
                active=lane if name=='dups' else width
                result=element*(active//lane)+[0]*(16-active)
        elif name=='ext': result=(a[:width]+b[:width])[op['offset']:op['offset']+width]+[0]*(16-width)
        elif name.startswith('rev'):
            container=op['container'];result=[]
            for start in range(0,width,container):
                elements=[a[i:i+lane] for i in range(start,start+container,lane)]
                result+=sum(reversed(elements),[])
            result+=[0]*(16-width)
        elif name.startswith(('zip','uzp','trn')):
            left=[a[i:i+lane] for i in range(0,width,lane)]
            right=[b[i:i+lane] for i in range(0,width,lane)]
            part=int(name[-1])-1
            if name.startswith('zip'):
                half=len(left)//2
                pairs=zip(left[part*half:(part+1)*half],right[part*half:(part+1)*half])
                elements=[e for pair in pairs for e in pair]
            elif name.startswith('uzp'): elements=(left+right)[part::2]
            else: elements=[e for pair in zip(left[part::2],right[part::2]) for e in pair]
            result=sum(elements,[])+[0]*(16-width)
        else:
            table=sum((vectors[(n+i)%32][:] for i in range(op['registers'])),[])
            result=[table[index] if index<len(table) else old[i] if name=='tbx' else 0 for i,index in enumerate(b[:width])]+[0]*(16-width)
        assert len(result)==16
        vectors[d]=result
    return {**state_dict(initial),'x':gprs,'v':[list(struct.unpack('<2Q',bytes(v))) for v in vectors]}


def shift_programs():
    # Encodings are independently constructed from the reviewed source fields.
    ordinary={'shl':0x0f005400,'sli':0x2f005400,'sri':0x2f004400,
              'sshr':0x0f000400,'ushr':0x2f000400,'srshr':0x0f002400,'urshr':0x2f002400,
              'ssra':0x0f001400,'usra':0x2f001400,'srsra':0x0f003400,'ursra':0x2f003400}
    configurations=[]
    for name,base in ordinary.items():
        for scalar in (False,True):
            for q in ((1,) if scalar else (0,1)):
                for lane in ((8,) if scalar else (1,2,4,8)):
                    if not q and lane==8: continue
                    bits=lane*8;left=name in ('shl','sli')
                    for amount in range(0 if left else 1,bits if left else bits+1):
                        immediate=bits+amount if left else bits*2-amount
                        configurations.append({'name':name,'base':base|(q<<30)|(int(scalar)<<28)|(immediate<<16),
                            'lane':lane,'output_lane':lane,'bytes':8 if scalar else 8<<q,'amount':amount,
                            'scalar':scalar,'upper':False,'boundary':amount in (0 if left else 1,bits//2,bits-1 if left else bits)})
    for name,base in [('shrn',0x0f008400),('rshrn',0x0f008c00),('sshll',0x0f00a400),('ushll',0x2f00a400)]:
        narrow=name in ('shrn','rshrn')
        for upper in (False,True):
            for encoded_lane in (1,2,4):
                bits=encoded_lane*8
                for amount in range(1 if narrow else 0,bits+1 if narrow else bits):
                    immediate=bits*2-amount if narrow else bits+amount
                    configurations.append({'name':name,'base':base|(int(upper)<<30)|(immediate<<16),
                        'lane':encoded_lane*2 if narrow else encoded_lane,'output_lane':encoded_lane if narrow else encoded_lane*2,
                        'bytes':8 if narrow else 16,'amount':amount,'scalar':False,'upper':upper,
                        'boundary':amount in (1 if narrow else 0,bits//2,bits if narrow else bits-1)})
    programs=[]
    for config in configurations:
        def operation(d,n):
            return {**config,'kind':'shift','d':d,'n':n,'word':config['base']|(n<<5)|d}
        for d,n in ((0,1),(31,31),(31,0)):
            programs.append({'operations':[operation(d,n)]})
        if config['boundary']:
            programs.append({'operations':[operation(d,(d+7)%32) for d in range(32)]})
    return programs


def shift_mathematical(operations,initial):
    vectors=[int.from_bytes(struct.pack('<2Q',*v),'little') for v in initial.v]
    for op in operations:
        name,d,n,lane,out_lane,width,amount=(op[k] for k in ('name','d','n','lane','output_lane','bytes','amount'))
        source,old=vectors[n],vectors[d];result=0
        in_bits,out_bits=lane*8,out_lane*8
        if name in ('sshll','ushll') and op['upper']: source>>=64
        for index in range(width//out_lane):
            value=source>>(index*in_bits)&((1<<in_bits)-1)
            previous=old>>(index*out_bits)&((1<<out_bits)-1)
            signed=name in ('sshr','srshr','ssra','srsra','sshll')
            if signed and value&(1<<(in_bits-1)): value-=1<<in_bits
            if name in ('shl','sli','sshll','ushll'): shifted=value<<amount
            else:
                round_bias=1<<(amount-1) if name in ('srshr','urshr','srsra','ursra','rshrn') else 0
                shifted=(value+round_bias)>>amount
            if name in ('ssra','usra','srsra','ursra'): shifted+=previous
            elif name=='sli': shifted|=previous&((1<<amount)-1)
            elif name=='sri': shifted|=previous&~((1<<(out_bits-amount))-1)
            result|=(shifted&((1<<out_bits)-1))<<(index*out_bits)
        if name in ('shrn','rshrn') and op['upper']: result=(old&MASK)|(result<<64)
        vectors[d]=result
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors]}


def reduction_programs():
    configurations=[]
    bases={'smin':0x0e206c00,'smax':0x0e206400,'umin':0x2e206c00,'umax':0x2e206400,
        'sminp':0x0e20ac00,'smaxp':0x0e20a400,'uminp':0x2e20ac00,'umaxp':0x2e20a400,
        'sminv':0x0e31a800,'smaxv':0x0e30a800,'uminv':0x2e31a800,'umaxv':0x2e30a800,
        'addv':0x0e31b800,'addp':0x0e20bc00,'saddlv':0x0e303800,'uaddlv':0x2e303800,
        'cnt':0x0e205800,'clz':0x2e204800,'cls':0x0e204800,'rbit':0x2e605800,'not':0x2e205800}
    for name,base in bases.items():
        for q in (0,1):
            for size in (range(4) if name=='addp' else (0,) if name in ('cnt','rbit','not') else range(3)):
                if size==3 and not q: continue
                if name.endswith('v') and size==2 and not q: continue
                configurations.append({'name':name,'base':base|(q<<30)|(size<<22),'lane':1<<size,'bytes':8<<q})
    configurations.append({'name':'addp_scalar','base':0x5ef1b800,'lane':8,'bytes':16})
    programs=[]
    for config in configurations:
        def operation(d,n,m):
            name=config['name'];binary=(name in ('smin','smax','umin','umax') or name.endswith('p'))
            return {**config,'kind':'reduction','d':d,'n':n,'m':m,
                    'word':config['base']|(n<<5)|d|(m<<16 if binary else 0)}
        for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31),(0,31,31),(31,29,31)):
            programs.append({'operations':[operation(d,n,m)]})
        programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def reduction_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v]
    for op in operations:
        name,d,n,m,lane,width=(op[k] for k in ('name','d','n','m','lane','bytes'))
        bits=lane*8;mask=(1<<bits)-1
        signed=name.startswith('s')
        def lanes(vector):
            values=[vector>>offset&mask for offset in range(0,width*8,bits)]
            return [v-(1<<bits) if signed and v&(1<<(bits-1)) else v for v in values]
        a,b=lanes(vectors[n]),lanes(vectors[m]);out_bits=bits
        if name=='addp_scalar': result=[sum(a)]
        elif name in ('cnt','rbit','not','clz','cls'):
            result=[]
            for value in a:
                if name=='cnt': value=value.bit_count()
                elif name=='rbit': value=int(f'{value:08b}'[::-1],2)
                elif name=='not': value=~value
                elif name=='clz': value=bits-value.bit_length()
                else:
                    if value&(1<<(bits-1)): value^=mask
                    value=bits-value.bit_length()-1
                result.append(value)
        else:
            operation=min if 'min' in name else max if 'max' in name else sum
            if name.endswith('v'):
                result=[operation(a)]
                if name in ('saddlv','uaddlv'): out_bits*=2
            elif name.endswith('p'):
                values=a+b;result=[operation(values[i:i+2]) for i in range(0,len(values),2)]
            else: result=[operation([left,right]) for left,right in zip(a,b)]
        vectors[d]=sum((v&((1<<out_bits)-1))<<(i*out_bits) for i,v in enumerate(result))
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors]}


def saturating_programs():
    bases={'sqadd':0x0e200c00,'uqadd':0x2e200c00,'sqsub':0x0e202c00,'uqsub':0x2e202c00,
        'sqabs':0x0e207800,'sqneg':0x2e207800,'suqadd':0x0e203800,'usqadd':0x2e203800,
        'sqxtn':0x0e214800,'uqxtn':0x2e214800,'sqxtun':0x2e212800}
    programs=[]
    for name,base in bases.items():
        narrow=name in ('sqxtn','uqxtn','sqxtun')
        for scalar in (False,True):
            for q in ((1,) if scalar else (0,1)):
                for size in range(3 if narrow else 4):
                    if not scalar and not narrow and not q and size==3: continue
                    lane=1<<size
                    config={'name':name,'base':base|(int(scalar)<<28)|(q<<30)|(size<<22),
                        'lane':lane*2 if narrow else lane,'output_lane':lane,
                        'bytes':lane if scalar else 8 if narrow else 8<<q,'upper':narrow and not scalar and q==1,
                        'source_bytes':lane*2 if narrow and scalar else 16 if narrow else lane if scalar else 8<<q}
                    def operation(d,n,m):
                        return {**config,'kind':'saturating','d':d,'n':n,'m':m,
                            'word':config['base']|(n<<5)|d|(m<<16 if name in ('sqadd','uqadd','sqsub','uqsub') else 0)}
                    for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31),(0,31,31),(31,29,31)):
                        programs.append({'operations':[operation(d,n,m)]})
                    programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def saturating_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v];fpsr=initial.fpsr
    for op in operations:
        name,d,n,m,lane,out_lane,width=(op[k] for k in ('name','d','n','m','lane','output_lane','bytes'))
        a,b,old=vectors[n],vectors[m],vectors[d]
        in_bits,out_bits=lane*8,out_lane*8;in_mask=(1<<in_bits)-1;out_mask=(1<<out_bits)-1
        signed_result=name in ('sqadd','sqsub','sqabs','sqneg','suqadd','sqxtn')
        low=-(1<<(out_bits-1)) if signed_result else 0
        high=(1<<(out_bits-int(signed_result)))-1;result=0
        def signed(value,bits): return value-(1<<bits) if value&(1<<(bits-1)) else value
        for index in range(width//out_lane):
            left=a>>(index*in_bits)&in_mask;right=b>>(index*in_bits)&in_mask
            previous=old>>(index*out_bits)&out_mask
            if name.startswith('sq'): left=signed(left,in_bits)
            if name in ('sqadd','sqsub'): right=signed(right,in_bits)
            if name in ('sqadd','uqadd'): value=left+right
            elif name in ('sqsub','uqsub'): value=left-right
            elif name=='sqabs': value=abs(left)
            elif name=='sqneg': value=-left
            elif name=='suqadd': value=left+signed(previous,out_bits)
            elif name=='usqadd': value=signed(left,in_bits)+previous
            else: value=left
            clamped=min(high,max(low,value))
            if clamped!=value: fpsr|=1<<27
            result|=(clamped&out_mask)<<(index*out_bits)
        if op['upper']: result=(old&MASK)|(result<<64)
        vectors[d]=result
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors],'fpsr':fpsr}


def product_programs():
    bases={'mul':0x0e209c00,'mla':0x0e209400,'mls':0x2e209400,
        'smull':0x0e20c000,'umull':0x2e20c000,'smlal':0x0e208000,'umlal':0x2e208000,'smlsl':0x0e20a000,'umlsl':0x2e20a000,
        'saddl':0x0e200000,'uaddl':0x2e200000,'ssubl':0x0e202000,'usubl':0x2e202000,
        'saddw':0x0e201000,'uaddw':0x2e201000,'ssubw':0x0e203000,'usubw':0x2e203000,
        'sabd':0x0e207400,'uabd':0x2e207400,'saba':0x0e207c00,'uaba':0x2e207c00,
        'sabdl':0x0e207000,'uabdl':0x2e207000,'sabal':0x0e205000,'uabal':0x2e205000}
    programs=[]
    for name,base in bases.items():
        widen=name not in ('mul','mla','mls','sabd','uabd','saba','uaba')
        product=name in ('mul','mla','mls','smull','umull','smlal','umlal','smlsl','umlsl')
        difference=name in ('sabd','uabd','saba','uaba','sabdl','uabdl','sabal','uabal')
        accumulation='add' if name in ('mla','smlal','umlal','saba','uaba','sabal','uabal') else 'sub' if name in ('mls','smlsl','umlsl') else None
        for q in (0,1):
            for size in range(3):
                lane=1<<size
                config={'name':name,'base':base|(q<<30)|(size<<22),'lane':lane,'output_lane':lane*2 if widen else lane,
                    'bytes':16 if widen else 8<<q,'upper':widen and q==1,'signed':name.startswith('s'),
                    'wide_left':name.endswith('w'),'operation':'product' if product else 'difference' if difference else 'sub' if 'sub' in name else 'add',
                    'accumulate':accumulation}
                def operation(d,n,m): return {**config,'kind':'product','d':d,'n':n,'m':m,'word':config['base']|(m<<16)|(n<<5)|d}
                for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31),(0,31,31),(31,29,31)):
                    programs.append({'operations':[operation(d,n,m)]})
                programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def product_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v]
    for op in operations:
        d,n,m,lane,out_lane,width=(op[k] for k in ('d','n','m','lane','output_lane','bytes'))
        left,right,old=vectors[n],vectors[m],vectors[d]
        in_bits,out_bits=lane*8,out_lane*8
        left_bits=out_bits if op['wide_left'] else in_bits
        if op['upper']:
            if not op['wide_left']: left>>=64
            right>>=64
        result=0
        for index in range(width//out_lane):
            a=left>>(index*left_bits)&((1<<left_bits)-1);b=right>>(index*in_bits)&((1<<in_bits)-1)
            if op['signed']:
                if a&(1<<(left_bits-1)): a-=1<<left_bits
                if b&(1<<(in_bits-1)): b-=1<<in_bits
            value=a*b if op['operation']=='product' else abs(a-b) if op['operation']=='difference' else a-b if op['operation']=='sub' else a+b
            previous=old>>(index*out_bits)&((1<<out_bits)-1)
            if op['accumulate']=='add': value=previous+value
            elif op['accumulate']=='sub': value=previous-value
            result|=(value&((1<<out_bits)-1))<<(index*out_bits)
        vectors[d]=result
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors]}


def halving_programs():
    bases={'shadd':0x0e200400,'uhadd':0x2e200400,'srhadd':0x0e201400,'urhadd':0x2e201400,'shsub':0x0e202400,'uhsub':0x2e202400,
        'addhn':0x0e204000,'raddhn':0x2e204000,'subhn':0x0e206000,'rsubhn':0x2e206000,
        'saddlp':0x0e202800,'uaddlp':0x2e202800,'sadalp':0x0e206800,'uadalp':0x2e206800,'xtn':0x0e212800,'shll':0x2e213800}
    programs=[]
    for name,base in bases.items():
        high=name.endswith('hn');pair=name.endswith('lp');truncate=name=='xtn';shift=name=='shll'
        for q in (0,1):
            for size in range(3):
                lane=1<<size
                config={'name':name,'base':base|(q<<30)|(size<<22),'lane':lane*2 if high or truncate else lane,
                    'output_lane':lane*2 if pair or shift else lane,'bytes':8 if high or truncate else 16 if shift else 8<<q,
                    'upper':bool(q) if high or truncate or shift else False,'signed':name in ('shadd','srhadd','shsub','saddlp','sadalp','shll'),
                    'operation':'high' if high else 'pair' if pair else 'truncate' if truncate else 'shift' if shift else 'half',
                    'subtract':'sub' in name,'round':name in ('srhadd','urhadd','raddhn','rsubhn'),'accumulate':name in ('sadalp','uadalp')}
                def operation(d,n,m):
                    return {**config,'kind':'halving','d':d,'n':n,'m':m,'word':config['base']|(n<<5)|d|(m<<16 if high or config['operation']=='half' else 0)}
                for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31),(0,31,31),(31,29,31)):
                    programs.append({'operations':[operation(d,n,m)]})
                programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def halving_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v]
    for op in operations:
        d,n,m,lane,out_lane,width=(op[k] for k in ('d','n','m','lane','output_lane','bytes'))
        left,right,old=vectors[n],vectors[m],vectors[d];in_bits,out_bits=lane*8,out_lane*8
        if op['operation']=='shift' and op['upper']: left>>=64
        def value(vector,index):
            v=vector>>(index*in_bits)&((1<<in_bits)-1)
            if op['signed'] and v&(1<<(in_bits-1)): v-=1<<in_bits
            return v
        result=0
        for index in range(width//out_lane):
            if op['operation']=='pair': v=value(left,index*2)+value(left,index*2+1)
            elif op['operation']=='shift': v=value(left,index)<<in_bits
            elif op['operation']=='truncate': v=value(left,index)
            else:
                a,b=value(left,index),value(right,index)
                v=a-b if op['subtract'] else a+b
                amount=out_bits if op['operation']=='high' else 1
                if op['round']: v+=1<<(amount-1)
                v>>=amount
            if op['accumulate']: v+=old>>(index*out_bits)&((1<<out_bits)-1)
            result|=(v&((1<<out_bits)-1))<<(index*out_bits)
        if op['operation'] in ('high','truncate') and op['upper']: result=(old&MASK)|(result<<64)
        vectors[d]=result
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors]}


def immediate_programs():
    programs=[]
    for q in (0,1):
        for op in (0,1):
            for cmode in range(16):
                if cmode==15 and op and not q: continue
                for imm in range(256):
                    d=imm%32
                    word=0x0f000400|(q<<30)|(op<<29)|(cmode<<12)|((imm>>5)<<16)|((imm&31)<<5)|d
                    operation={'kind':'constant','format':'modified','word':word,'d':d,'lane':1,'bytes':8<<q,
                               'op':op,'cmode':cmode,'imm':imm,'half':False}
                    programs.append({'operations':[operation]})
        for imm in range(256):
            d=imm%32
            word=0x0f00fc00|(q<<30)|((imm>>5)<<16)|((imm&31)<<5)|d
            programs.append({'operations':[{'kind':'constant','format':'modified','word':word,'d':d,'lane':2,'bytes':8<<q,
                             'op':0,'cmode':15,'imm':imm,'half':True}]})
    for lane,base in [(2,0x1ee01000),(4,0x1e201000),(8,0x1e601000)]:
        for imm in range(256):
            d=imm%32
            programs.append({'operations':[{'kind':'constant','format':'scalar_float','word':base|(imm<<13)|d,
                             'd':d,'lane':lane,'bytes':lane,'imm':imm}]})
    moves=[(0x1ee04000,2,'vector',False,False),(0x1e204000,4,'vector',False,False),(0x1e604000,8,'vector',False,False),
           (0x1ee60000,2,'from_vector',False,False),(0x9ee60000,2,'from_vector',False,True),
           (0x1e260000,4,'from_vector',False,False),(0x9e660000,8,'from_vector',False,True),(0x9eae0000,8,'from_vector',True,True),
           (0x1ee70000,2,'to_vector',False,False),(0x9ee70000,2,'to_vector',False,True),
           (0x1e270000,4,'to_vector',False,False),(0x9e670000,8,'to_vector',False,True),(0x9eaf0000,8,'to_vector',True,True)]
    for base,lane,direction,upper,x64 in moves:
        def operation(d,n): return {'kind':'fp_move','word':base|(n<<5)|d,'d':d,'n':n,'lane':lane,'bytes':lane,
                                    'direction':direction,'upper':upper,'x64':x64}
        for d,n in [(0,1),(1,1),(31,0),(0,31),(31,31),(7,7)]: programs.append({'operations':[operation(d,n)]})
        programs.append({'operations':[operation(d,(d+9)%32) for d in range(32)]})
    return programs


def immediate_float_bits(imm,lane):
    # Independent exact numeric construction; compiler constructs IEEE fields.
    exponent=(imm>>4)&7
    exponent=exponent+1 if exponent<4 else exponent-7
    value=math.ldexp(1+(imm&15)/16,exponent)
    if imm&128: value=-value
    return int.from_bytes(struct.pack({2:'<e',4:'<f',8:'<d'}[lane],value),'little')


def immediate_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v];gprs=list(initial.x)
    for op in operations:
        d,lane=op['d'],op['lane']
        if op['kind']=='fp_move':
            n=op['n'];mask=(1<<(lane*8))-1
            if op['direction']=='from_vector':
                value=vectors[n]>>(64 if op['upper'] else 0)&mask
                if d!=31: gprs[d]=value
            else:
                value=(0 if n==31 else gprs[n])&mask if op['direction']=='to_vector' else vectors[n]&mask
                vectors[d]=(vectors[d]&MASK)|(value<<64) if op['upper'] else value
            continue
        imm,width=op['imm'],op['bytes']
        action='move'
        if op['format']=='scalar_float': value=immediate_float_bits(imm,lane)
        else:
            cmode=op['cmode'];inverse=op['op']
            if op['half'] or cmode==15:
                element_bytes=2 if op['half'] else 8 if inverse else 4
                element=immediate_float_bits(imm,element_bytes)
            elif cmode<8: element_bytes=4;element=imm<<((cmode//2)*8)
            elif cmode<12: element_bytes=2;element=imm<<(((cmode-8)//2)*8)
            elif cmode<14:
                element_bytes=4;ones_bytes=1 if cmode==12 else 2
                element=int.from_bytes(b'\xff'*ones_bytes+bytes([imm])+b'\0'*(3-ones_bytes),'little')
            elif inverse:
                element_bytes=8;element=int.from_bytes(bytes(255 if imm&(1<<i) else 0 for i in range(8)),'little')
            else: element_bytes=1;element=imm
            value=sum(element<<(i*element_bytes*8) for i in range(width//element_bytes))
            if cmode<12 and cmode%2: action='bic' if inverse else 'orr'
            elif inverse and cmode<14: value^=(1<<(width*8))-1
        active_mask=(1<<(width*8))-1
        if action=='orr': value|=vectors[d]
        elif action=='bic': value=vectors[d]&~value
        vectors[d]=value&active_mask
    return {**state_dict(initial),'x':gprs,'v':[[v&MASK,v>>64] for v in vectors]}


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
                if name.startswith('cm'):
                    if name.endswith('0'): right=0
                    signed_right=right-(1<<bits) if right&(1<<(bits-1)) else right
                    condition={'cmeq':left==right,'cmgt':signed>signed_right,'cmge':signed>=signed_right,
                               'cmhi':left>right,'cmhs':left>=right,'cmlt':signed<0,'cmle':signed<=0,
                               'cmtst':bool(left&right)}[name.rstrip('0')]
                    result=lane_mask if condition else 0
                else: result=left+right if name=='add' else left-right if name=='sub' else abs(signed) if name=='abs' else -signed
                value|=(result&lane_mask)<<offset
        vectors[d]=value # Q=0/scalar writes clear every upper vector bit.
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors]}


REGISTER_COHORTS={
    'integer':(integer_programs,integer_mathematical),
    'rearrange':(rearrange_programs,rearrange_mathematical),
    'shifts':(shift_programs,shift_mathematical),
    'reductions':(reduction_programs,reduction_mathematical),
    'saturating':(saturating_programs,saturating_mathematical),
    'products':(product_programs,product_mathematical),
    'halving':(halving_programs,halving_mathematical),
    'immediates':(immediate_programs,immediate_mathematical),
}


def execute_register_batches(batches):
    corpus,comparisons=hashlib.sha256(),0
    templates=states(all_flags=True)
    for batch in batches:
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        if batch['cohort']=='immediates': machine.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
        machine.mem_map(BASE,(len(batch['source'])+4095)&~4095);machine.mem_write(BASE,batch['source'])
        with executable(batch['native']) as address:
            for function,entry,offset in zip(batch['functions'],batch['entries'],batch['offsets']):
                native=ctypes.CFUNCTYPE(None,ctypes.POINTER(State))(address+offset)
                operations=function['operations'];lane=operations[0]['lane'];bits=lane*8
                rearrange=batch.get('cohort')=='rearrange'
                table=rearrange and operations[0]['name'] in ('tbl','tbx')
                reduction=batch.get('cohort')=='reductions'
                bit_bytes=reduction and operations[0]['name'] in ('cnt','rbit')
                leading=reduction and operations[0]['name'] in ('clz','cls')
                saturation=batch.get('cohort')=='saturating'
                products=batch.get('cohort')=='products'
                halving=batch.get('cohort')=='halving'
                immediates=batch.get('cohort')=='immediates'
                patterns=(2 if operations[0]['kind']=='constant' else 8) if immediates else 9 if halving else 7 if saturation or products else 256//operations[0]['bytes'] if table or bit_bytes else bits+3 if leading else 5
                for flags in (0,15):
                    for pattern in range(patterns):
                        initial=State.from_buffer_copy(templates[flags]);initial.nzcv=flags<<28
                        initial.reserved=0x51ad1234
                        seed_extended_state(initial,pattern*16+flags)
                        if pattern<4:
                            values=(0,(1<<bits)-1,1<<(bits-1),(1<<(bits-1))-1,1)
                            if batch.get('cohort')=='shifts':
                                midpoint=1<<max(0,operations[0]['amount']-1)
                                values+=tuple(v&((1<<bits)-1) for v in (midpoint-1,midpoint,midpoint+1,-midpoint-1,-midpoint,-midpoint+1))
                            if bits==64: values+=(0x80000000,0x7fffffff,0xffffffff00000000,0xffffffff80000000,0xffffffff7fffffff,0xffffffff)
                            for register in range(32):
                                value=sum(values[(register+i+pattern)%len(values)]<<(i*bits) for i in range(128//bits))
                                initial.v[register][:]=[value&MASK,value>>64]
                        if bit_bytes:
                            for register in range(32):
                                values=bytes((pattern*operations[0]['bytes']+i+register)%256 for i in range(16))
                                initial.v[register][:]=struct.unpack('<2Q',values)
                        if leading and pattern<=bits:
                            # Every zero/sign leading count, plus dirty upper lanes and all-one input.
                            lane_mask=(1<<bits)-1
                            for register in range(32):
                                values=[((1<<((pattern+register+i)%(bits+1)))-1) for i in range(128//bits)]
                                if flags: values=[value^lane_mask for value in values]
                                value=sum(v<<(i*bits) for i,v in enumerate(values))
                                initial.v[register][:]=[value&MASK,value>>64]
                        if table:
                            # The output lanes collectively cover every unsigned index 0..255, including all table edges.
                            for op in operations:
                                indices=bytes((pattern*op['bytes']+i)%256 for i in range(16))
                                initial.v[op['m']][:]=struct.unpack('<2Q',indices)
                        if saturation:
                            out_bits=operations[0]['output_lane']*8
                            if pattern<5:
                                minimum=1<<(out_bits-1);maximum=minimum-1;unsigned_maximum=(1<<out_bits)-1
                                values=[0,1,-1,minimum,minimum-1,minimum+1,-minimum,-minimum-1,-minimum+1,maximum,maximum+1,unsigned_maximum,unsigned_maximum+1]
                                for register in range(32):
                                    value=sum((values[(pattern+register+i)%len(values)]&((1<<bits)-1))<<(i*bits) for i in range(128//bits))
                                    initial.v[register][:]=[value&MASK,value>>64]
                            elif pattern==5:
                                # Zero every active source lane; force MIN/all-one in inactive lanes.
                                active=operations[0]['source_bytes']
                                for register in range(32):
                                    values=bytearray(b'\xff'*16);values[:active]=b'\0'*active
                                    for byte in range(active,16,lane):
                                        values[byte:byte+lane]=(1<<(bits-1)).to_bytes(lane,'little')
                                    initial.v[register][:]=struct.unpack('<2Q',values)
                            initial.fpsr=(initial.fpsr&~(1<<27))|((1<<27) if flags else 0)
                        if products:
                            if pattern<5:
                                values=(0,1,(1<<bits)-1,1<<(bits-1),(1<<(bits-1))-1,(1<<bits)-2,(1<<(bits-1))+1)
                                for register in range(32):
                                    value=sum(values[(pattern+register+i)%len(values)]<<(i*bits) for i in range(128//bits))
                                    initial.v[register][:]=[value&MASK,value>>64]
                            elif pattern==5:
                                for register in range(32):
                                    low=sum(((register+i+1)&((1<<bits)-1))<<(i*bits) for i in range(64//bits))
                                    high=sum((((1<<bits)-1-register-i)&((1<<bits)-1))<<(i*bits) for i in range(64//bits))
                                    initial.v[register][:]=[low,high]
                        if halving:
                            if pattern<7:
                                midpoint=1<<(operations[0]['output_lane']*8-1)
                                values=(0,1,(1<<bits)-1,1<<(bits-1),(1<<(bits-1))-1,midpoint-1,midpoint,midpoint+1,~midpoint)
                                for register in range(32):
                                    value=sum((values[(pattern+register+i)%len(values)]&((1<<bits)-1))<<(i*bits) for i in range(128//bits))
                                    initial.v[register][:]=[value&MASK,value>>64]
                            elif pattern==7:
                                for register in range(32):
                                    low=sum(((register+i+1)&((1<<bits)-1))<<(i*bits) for i in range(64//bits))
                                    high=sum((((1<<bits)-1-register-i)&((1<<bits)-1))<<(i*bits) for i in range(64//bits))
                                    initial.v[register][:]=[low,high]
                        if immediates:
                            if operations[0]['kind']=='constant':
                                for vector in initial.v: vector[:]=[MASK if pattern==0 else 0]*2
                            elif pattern<7:
                                exponent_bits={2:5,4:8,8:11}[lane];fraction_bits=bits-exponent_bits-1
                                infinity=((1<<exponent_bits)-1)<<fraction_bits
                                values=(0,1<<(bits-1),infinity,infinity|(1<<(bits-1)),infinity|1,infinity|(1<<(fraction_bits-1))|3,1)
                                value=values[pattern]
                                for register in range(32):
                                    payload=value if pattern not in (4,5) else value|(register&3)
                                    full=sum(payload<<(i*bits) for i in range(128//bits))
                                    initial.v[register][:]=[full&MASK,full>>64]
                                    if register<31: initial.x[register]=(payload|((0xdeadbeefdeadbeef<<bits)&MASK))&MASK
                        initialize_arm(machine,initial)
                        end=BASE+(entry+len(operations))*4
                        machine.emu_start(BASE+entry*4,end,count=len(operations)+1)
                        assert machine.reg_read(arm.UC_ARM64_REG_PC)==end
                        original=state_dict(capture_arm(machine,initial))
                        mathematical=REGISTER_COHORTS[batch['cohort']][1](operations,initial)
                        actual=State.from_buffer_copy(initial);native(ctypes.byref(actual));actual=state_dict(actual)
                        if mathematical!=original or original!=actual:
                            raise AssertionError(json.dumps({'operations':operations,'initial':state_dict(initial),
                                'math':mathematical,'arm':original,'native':actual}))
                        corpus.update(struct.pack('<'+'I'*len(operations),*(op['word'] for op in operations)))
                        corpus.update(bytes(initial));comparisons+=1
    return {'three_way_register_state_comparisons':comparisons,'state_corpus_sha256':corpus.hexdigest()}


def run_register_cohort(cli, focus):
    functions=REGISTER_COHORTS[focus][0]();started=time.monotonic()
    cli_hash,harness_hash=digest(cli.read_bytes()),digest(Path(__file__).read_bytes())
    info=json.loads(subprocess.check_output([str(cli),'cpu-info']))
    selections=[('baseline','x86_64-baseline')]
    if focus not in ('shifts','immediates') and info['detected_target']!='x86_64-baseline': selections.append(('native',info['detected_target']))
    profiles={}
    with tempfile.TemporaryDirectory(prefix='stela-simd-integer-') as temporary:
        for index,(selection,target_id) in enumerate(selections):
            batch=compile_batch(cli,Path(temporary),functions,index,cpu_target=selection,target_id=target_id)
            batch['cohort']=focus
            result=bounded_cases([batch])
            decoded=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(batch['native'],0))
            assert sum(i.size for i in decoded)==len(batch['native'])
            mnemonics=Counter(i.mnemonic for i in decoded)
            optional={o['mnemonic'] for o in info['simd_opcodes'] if o['minimum_target']!='x86_64-baseline'}
            used=sorted(optional & mnemonics.keys())
            expected=set()
            if focus=='integer':
                if '+ssse3' in target_id: expected.update(('pabsb','pabsw','pabsd'))
                if '+sse4.1' in target_id: expected.add('pcmpeqq')
                if '+sse4.2' in target_id: expected.add('pcmpgtq')
            elif focus=='rearrange' and '+ssse3' in target_id: expected.add('pshufb')
            elif focus=='reductions':
                if '+ssse3' in target_id: expected.add('pshufb')
                if '+sse4.1' in target_id: expected.update(('pminsb','pmaxsb','pminuw','pmaxuw','pminsd','pmaxsd','pminud','pmaxud'))
            elif focus=='saturating':
                if '+ssse3' in target_id: expected.update(('pabsb','pabsw','pabsd'))
                if '+sse4.1' in target_id: expected.add('packusdw')
                if '+sse4.2' in target_id: expected.add('pcmpgtq')
            elif focus=='products':
                if '+sse4.1' in target_id: expected.update(('pmulld','pmuldq'))
                if '+sse4.2' in target_id: expected.add('pcmpgtq')
            elif focus=='halving':
                if '+ssse3' in target_id: expected.add('pmaddubsw')
                if '+sse4.1' in target_id: expected.update(('pmovsxdq','pmovzxdq'))
            assert set(used)==expected,(target_id,used,expected)
            profiles[selection]={**result,'compilation':batch['receipt'],'optional_opcodes_used':used,
                'packed_shifts_used':sorted({o['mnemonic'] for o in info['simd_immediate_shifts']} & mnemonics.keys())}
    assert digest(cli.read_bytes())==cli_hash and digest(Path(__file__).read_bytes())==harness_hash
    baseline=profiles['baseline']
    report={'kind':f'simd_{focus}_arm_vs_native_x86','passed':True,
        'three_way_register_state_comparisons':baseline['three_way_register_state_comparisons'],
        'state_corpus_sha256':baseline['state_corpus_sha256'],'programs':len(functions),
        'compiler_source_sha256':batch['compiler'],'compiler_executable_sha256':cli_hash,
        'harness_source_sha256':harness_hash,'shared_runner_sha256':digest((ROOT/'dev/differential.py').read_bytes()),
        'corpus_sha256':digest(batch['source']),'compilation':baseline['compilation'],'cpu_profiles':profiles,
        'original_cpu_model':'MAX (FP16 enabled)' if focus=='immediates' else 'default',
        'total_profile_comparisons':sum(p['three_way_register_state_comparisons'] for p in profiles.values()),
        'verification_wall_seconds':time.monotonic()-started,
        'limits':f'Focused {focus} SIMD semantics with FP/AdvSIMD enabled; no FP arithmetic, traps, disabled-feature behavior or application-performance claim. Leaf RET is harness-owned.'}
    write_evidence(ROOT/f'.stela/simd-{focus}-differential-report.json',report)
    print(json.dumps(report,indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--focus', choices=list(REGISTER_COHORTS), help='Only the focused SIMD register implementation cohort')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    if arguments.focus:
        run_register_cohort(cli, arguments.focus)
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
