#!/usr/bin/env python3
"""Original ARM, independent math and native x86 SIMD/FP verification.

Reviewed single B/H/S/D/Q transfers, MOVI D/2D and paired S/D/Q transfers are tested.
Single-operation leaf mini-functions expose each result in a fresh complete
state; mixed chains additionally compare final state and RAM. Representative
block cases execute the original RET and native block exit ABI.
Scalar numerical blocks use pinned original/core outcomes and actual Rust
runtime completion; unsupported controls remain distinct from successful runs.
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
import os
import shutil
import socket
from pathlib import Path
import random
import signal
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_ARM, UC_MODE_64, UC_HOOK_CODE, UC_ERR_FETCH_UNMAPPED
from unicorn import arm64_const as arm
from unicorn import x86_const as intel
from unicorn import __version__ as unicorn_version
from differential import (ROOT, BASE, MASK, State, states, executable, initialize_arm,
                          capture_arm, state_dict, seed_extended_state, parse_fault_record, move)
from evidence import retain_native_evidence, write_evidence

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


def validate_manifest(manifest, source, native, block, target_cpu=None, guest_base=BASE):
    if target_cpu is not None and manifest.get("target_cpu") != target_cpu:
        raise AssertionError("SIMD manifest CPU requirements differ from selection")
    if (manifest['schema_version'] != 1 or manifest['abi'] != (BLOCK_ABI if block else LEAF_ABI)
            or manifest['guest_base'] != guest_base or manifest['source_sha256'] != digest(source)
            or manifest['native_sha256'] != digest(native) or manifest['native_bytes'] != len(native)
            or manifest['verified'] is not False):
        raise AssertionError('SIMD manifest does not bind original/native bytes and ABI')
    consumed = manifest['source_bytes'] if block else manifest['guest_instructions'] * 4
    mapping = manifest['source_map']
    if (consumed != len(source) or [row[0] for row in mapping] != list(range(guest_base, guest_base + len(source), 4))
            or any(not 0 <= row[1] < len(native) for row in mapping)
            or any(a[1] >= b[1] for a, b in zip(mapping, mapping[1:]))):
        raise AssertionError('SIMD source map omits or merges original instructions')
    return [row[1] for row in mapping]


def compile_batch(cli, directory, functions, index, block=False, cpu_target="baseline", target_id="x86_64-baseline", guest_base=BASE):
    words, entries = [], []
    for function in functions:
        entries.append(len(words))
        words.extend(operation['word'] for operation in function['operations'])
        words.append(RET)
    source = struct.pack('<' + 'I' * len(words), *words)
    disassembly = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(source, BASE))
    if len(disassembly) != len(words) or any(i.mnemonic not in {'ldr', 'str', 'ldur', 'stur', 'ldp', 'stp', 'movi', 'ret', 'and', 'bic', 'orr', 'orn', 'eor', 'bsl', 'bit', 'bif', 'add', 'sub', 'abs', 'neg', 'mov', 'cmeq', 'cmgt', 'cmge', 'cmhi', 'cmhs', 'cmlt', 'cmle', 'cmtst', 'dup', 'ins', 'smov', 'umov', 'ext', 'rev16', 'rev32', 'rev64', 'zip1', 'zip2', 'uzp1', 'uzp2', 'trn1', 'trn2', 'tbl', 'tbx', 'shl', 'sshr', 'ushr', 'srshr', 'urshr', 'ssra', 'usra', 'srsra', 'ursra', 'sli', 'sri', 'shrn', 'shrn2', 'rshrn', 'rshrn2', 'sshll', 'sshll2', 'ushll', 'ushll2', 'sxtl', 'sxtl2', 'uxtl', 'uxtl2', 'smin', 'smax', 'umin', 'umax', 'sminp', 'smaxp', 'uminp', 'umaxp', 'sminv', 'smaxv', 'uminv', 'umaxv', 'addv', 'addp', 'saddlv', 'uaddlv', 'cnt', 'clz', 'cls', 'rbit', 'mvn', 'not', 'sqadd', 'uqadd', 'sqsub', 'uqsub', 'sqabs', 'sqneg', 'suqadd', 'usqadd', 'sqxtn', 'sqxtn2', 'uqxtn', 'uqxtn2', 'sqxtun', 'sqxtun2', 'mul', 'mla', 'mls', 'smull', 'smull2', 'umull', 'umull2', 'smlal', 'smlal2', 'umlal', 'umlal2', 'smlsl', 'smlsl2', 'umlsl', 'umlsl2', 'saddl', 'saddl2', 'uaddl', 'uaddl2', 'ssubl', 'ssubl2', 'usubl', 'usubl2', 'saddw', 'saddw2', 'uaddw', 'uaddw2', 'ssubw', 'ssubw2', 'usubw', 'usubw2', 'sabd', 'uabd', 'saba', 'uaba', 'sabdl', 'sabdl2', 'uabdl', 'uabdl2', 'sabal', 'sabal2', 'uabal', 'uabal2', 'shadd', 'uhadd', 'srhadd', 'urhadd', 'shsub', 'uhsub', 'addhn', 'addhn2', 'raddhn', 'raddhn2', 'subhn', 'subhn2', 'rsubhn', 'rsubhn2', 'saddlp', 'uaddlp', 'sadalp', 'uadalp', 'xtn', 'xtn2', 'shll', 'shll2', 'mvni', 'fmov', 'pmul', 'pmull', 'pmull2', 'sqdmulh', 'sqrdmulh', 'sqdmull', 'sqdmull2', 'sqdmlal', 'sqdmlal2', 'sqdmlsl', 'sqdmlsl2', 'sshl', 'ushl', 'srshl', 'urshl', 'sqshl', 'uqshl', 'sqrshl', 'uqrshl', 'sqshlu', 'fcsel', 'fabs', 'fneg', 'sqshrn', 'sqshrn2', 'sqrshrn', 'sqrshrn2', 'uqshrn', 'uqshrn2', 'uqrshrn', 'uqrshrn2', 'sqshrun', 'sqshrun2', 'sqrshrun', 'sqrshrun2', 'sdot', 'udot', 'sqrdmlah', 'sqrdmlsh', 'fadd', 'fsub', 'fmul', 'fdiv'} for i in disassembly):
        raise AssertionError('Independent decoder declined SIMD fixture')
    path = directory / f'program-{index}.arm64'
    path.write_bytes(source)
    output = directory / f'native-{index}'
    manifest = json.loads(subprocess.check_output([str(cli), 'compile-block' if block else 'compile-leaf', str(path), '--guest-base', hex(guest_base), '--output-dir', str(output), '--cpu-target', cpu_target], timeout=60))
    native = (output / 'native.bin').read_bytes()
    offsets = validate_manifest(manifest, source, native, block, target_id, guest_base)
    if not block:
        for entry, function in zip(entries, functions):
            if native[offsets[entry + len(function['operations'])]] != 0xc3:
                raise AssertionError('Independent mini-function has no exact host RET boundary')
    return {'functions': functions, 'source': source, 'native': native, 'entries': entries,
            'offsets': [offsets[entry] for entry in entries], 'block': block,
            'compiler': manifest['compiler_source_sha256'],'manifest':manifest,'instruction_offsets':offsets,
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
        if batches[0].get('cohort') == 'scalar_numerical':
            result = execute_scalar_numerical_batches(batches)
        else:
            result = execute_register_batches(batches) if batches[0].get('cohort') in REGISTER_COHORTS else execute_batches(batches, pipe)
        pipe.send({'result': result})
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


def register_shift_programs():
    bases={'sshl':0x0e204400,'ushl':0x2e204400,'srshl':0x0e205400,'urshl':0x2e205400,
           'sqshl':0x0e204c00,'uqshl':0x2e204c00,'sqrshl':0x0e205c00,'uqrshl':0x2e205c00}
    configurations=[]
    for name,base in bases.items():
        saturating='q' in name
        for scalar in (False,True):
            for q in ((1,) if scalar else (0,1)):
                for size in (range(4) if saturating or not scalar else (3,)):
                    if not q and size==3: continue
                    configurations.append({'name':name,'base':base|(q<<30)|(int(scalar)<<28)|(size<<22),
                        'lane':1<<size,'bytes':1<<size if scalar else 8<<q,'scalar':scalar,
                        'signed':name.startswith('s'),'unsigned_result':name.startswith('u'),
                        'round':'r' in name,'saturating':saturating,'immediate':False})
    for name,base in [('sqshl',0x0f007400),('uqshl',0x2f007400),('sqshlu',0x2f006400)]:
        for scalar in (False,True):
            for q in ((1,) if scalar else (0,1)):
                for size in range(4):
                    if not q and size==3: continue
                    bits=8<<size
                    for amount in sorted({0,1,bits//2,bits-1}):
                        configurations.append({'name':name,'base':base|(q<<30)|(int(scalar)<<28)|((bits+amount)<<16),
                            'lane':1<<size,'bytes':1<<size if scalar else 8<<q,'scalar':scalar,
                            'signed':name!='uqshl','unsigned_result':name!='sqshl','round':False,
                            'saturating':True,'immediate':True,'amount':amount})
    programs=[]
    for config in configurations:
        def operation(d,n,m):
            return {**config,'kind':'register_shift','d':d,'n':n,'m':m,
                    'word':config['base']|(n<<5)|d|(0 if config['immediate'] else m<<16)}
        for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(0,1,1),(31,31,31),(31,29,31)):
            programs.append({'operations':[operation(d,n,m)]})
        programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def register_shift_counts(bits):
    return sorted({-128,-127,-65,-64,-63,-bits-1,-bits,1-bits,-2,-1,0,1,2,bits-1,bits,bits+1,63,64,65,126,127})


def register_shift_pattern_count(operations):
    if operations[0]['immediate']:
        return 12 if operations[0]['amount']==1 else 8
    return len(register_shift_counts(operations[0]['lane']*8))+2


def register_shift_seed(initial,operations,pattern,flags):
    op=operations[0];lane=op['lane'];bits=lane*8;mask=(1<<bits)-1
    values=(0,1,-1,1<<(bits-1),(1<<(bits-1))-1,-2,2,(1<<(bits-1))+1)
    for register in range(32):
        value=sum((values[(register+index+pattern)%len(values)]&mask)<<(index*bits) for index in range(128//bits))
        initial.v[register][:]=[value&MASK,value>>64]
    if op['immediate'] and op['amount']==1 and 6<=pattern<10:
        # Exact last-valid / first-saturating inputs for doubled signed and
        # unsigned results. Uniform active lanes also expose scalar and Q=0 QC.
        if op['unsigned_result'] and not op['signed']:
            boundaries=((1<<(bits-1))-1,1<<(bits-1),(1<<(bits-1))+1,0)
        else:
            half=1<<(bits-2)
            boundaries=(-half,-half-1,half-1,half)
        value=boundaries[pattern-6]&mask
        repeated=sum(value<<(index*bits) for index in range(128//bits))
        for register in range(32):
            initial.v[register][:]=[repeated&MASK,repeated>>64]
    counts=register_shift_counts(bits)
    if not op['immediate']:
        for operation in operations:
            value=0
            for index in range(128//bits):
                count=counts[(pattern+index)%len(counts)]
                # Deliberately unrelated high count bits; only the signed low byte counts.
                poison=(0xa5c37e19d2b48000^(operation['m']<<8)^(index<<16))&mask&~255
                value|=(poison|(count&255))<<(index*bits)
            initial.v[operation['m']][:]=[value&MASK,value>>64]
    if pattern==register_shift_pattern_count(operations)-2:
        # Active source zero cannot saturate even at a huge positive count;
        # inactive MIN lanes must never publish QC.
        for operation in operations:
            if operation['n']==operation['m'] and not op['immediate']: continue
            value=sum((1<<(bits-1))<<(index*bits) for index in range(op['bytes']//lane,128//bits))
            initial.v[operation['n']][:]=[value&MASK,value>>64]
            if not op['immediate']:
                count_value=sum((127 if index<op['bytes']//lane else 1)<<(index*bits) for index in range(128//bits))
                initial.v[operation['m']][:]=[count_value&MASK,count_value>>64]
    initial.fpsr=(initial.fpsr&~(1<<27))|((1<<27) if flags else 0)


def register_shift_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v];fpsr=initial.fpsr
    for op in operations:
        bits=op['lane']*8;mask=(1<<bits)-1;source,counts=vectors[op['n']],vectors[op['m']];result=0
        for index in range(op['bytes']//op['lane']):
            value=(source>>(index*bits))&mask
            if op['signed'] and value&(1<<(bits-1)): value-=1<<bits
            count=op['amount'] if op['immediate'] else (counts>>(index*bits))&255
            if not op['immediate'] and count>=128: count-=256
            # Arbitrary precision math independently models the unclamped shift;
            # ShiftSat only reduces counts that already have identical outcomes.
            shifted=value<<count if count>=0 else (value+((1<<(-count-1)) if op['round'] else 0))>>-count
            if op['saturating']:
                low,high=(0,mask) if op['unsigned_result'] else (-(1<<(bits-1)),(1<<(bits-1))-1)
                bounded=max(low,min(high,shifted))
                if bounded!=shifted: fpsr|=1<<27
                shifted=bounded
            result|=(shifted&mask)<<(index*bits)
        vectors[op['d']]=result
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors],'fpsr':fpsr}


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


def doubling_product_programs():
    configurations=[]
    bases={'sqdmulh':(0x0e20b400,0x0f00c000),'sqrdmulh':(0x2e20b400,0x0f00d000),
        'sqdmull':(0x0e20d000,0x0f00b000),'sqdmlal':(0x0e209000,0x0f003000),'sqdmlsl':(0x0e20b000,0x0f007000)}
    for name,(register,indexed) in bases.items():
        high=name.endswith('h')
        for scalar in (False,True):
            for element in (False,True):
                for q in ((1,) if scalar else (0,1)):
                    for size in (1,2):
                        lane=1<<size
                        for index in (range(16//lane) if element else (None,)):
                            base=(indexed if element else register)|(int(scalar)<<28)|(q<<30)|(size<<22)
                            if element:
                                base|=((index>> (2 if size==1 else 1))<<11)|(((index>>1) if size==1 else index)&1)<<21
                                if size==1: base|=(index&1)<<20
                            configurations.append({'name':name,'base':base,'lane':lane,'output_lane':lane if high else lane*2,
                                'bytes':(lane if high else lane*2) if scalar else 8<<q if high else 16,
                                'upper':not high and not scalar and bool(q),'index':index})
    for name,base,sizes in [('pmul',0x2e209c00,(0,)),('pmull',0x0e20e000,(0,3))]:
        for q in (0,1):
            for size in sizes:
                lane=1<<size
                configurations.append({'name':name,'base':base|(q<<30)|(size<<22),'lane':lane,
                    'output_lane':lane if name=='pmul' else lane*2,'bytes':8<<q if name=='pmul' else 16,
                    'upper':name=='pmull' and bool(q),'index':None})
    programs=[]
    for config in configurations:
        def operation(d,n,m):
            if config['index'] is not None and config['lane']==2: m&=15
            return {**config,'kind':'doubling_product','d':d,'n':n,'m':m,'word':config['base']|(m<<16)|(n<<5)|d}
        for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31),(0,31,31),(31,29,31)):
            programs.append({'operations':[operation(d,n,m)]})
        programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def doubling_product_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v];fpsr=initial.fpsr
    for op in operations:
        name,d,n,m,lane,out_lane,width=(op[k] for k in ('name','d','n','m','lane','output_lane','bytes'))
        bits,out_bits=lane*8,out_lane*8;a,b,old=vectors[n],vectors[m],vectors[d]
        if op['upper']: a>>=64
        if op['upper'] and op['index'] is None: b>>=64
        def signed(value,width): return value-(1<<width) if value&(1<<(width-1)) else value
        def clamp(value,width):
            nonlocal fpsr
            result=min((1<<(width-1))-1,max(-(1<<(width-1)),value))
            if result!=value: fpsr|=1<<27
            return result
        result=0
        for i in range(width//out_lane):
            left=a>>(i*bits)&((1<<bits)-1)
            right=b>>((op['index'] if op['index'] is not None else i)*bits)&((1<<bits)-1)
            if name.startswith('p'):
                value=0
                for bit in range(bits):
                    if right&(1<<bit): value^=left<<bit
            else:
                value=2*signed(left,bits)*signed(right,bits)
                if name.endswith('h'):
                    if name=='sqrdmulh': value+=1<<(bits-1)
                    value=clamp(value>>bits,bits)
                else:
                    value=clamp(value,out_bits)
                    if name in ('sqdmlal','sqdmlsl'):
                        previous=signed(old>>(i*out_bits)&((1<<out_bits)-1),out_bits)
                        value=clamp(previous+(-value if name=='sqdmlsl' else value),out_bits)
            result|=(value&((1<<out_bits)-1))<<(i*out_bits)
        vectors[d]=result
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors],'fpsr':fpsr}


def seed_doubling_products(initial,operations,pattern,flags):
    bits=operations[0]['lane']*8;mask=(1<<bits)-1;minimum=1<<(bits-1)
    values=(0,1,mask,minimum,minimum-1,minimum+1,mask-1,1<<(bits-2),(1<<(bits-2))+1)
    for register in range(32):
        if pattern<7:
            lanes=[values[(pattern+register+i)%len(values)] for i in range(128//bits)]
        elif pattern==7: lanes=[minimum]*(128//bits) # MIN*MIN and stage-one saturation
        elif pattern==8:
            op=operations[0];active=op['bytes'] if op['name'].endswith('h') or op['name']=='pmul' else op['bytes']//2
            start=64 if op['upper'] else 0
            lanes=[0 if start<=i*bits<start+active*8 else minimum for i in range(128//bits)]
        else: continue # random independent original full-width state
        value=sum(v<<(i*bits) for i,v in enumerate(lanes));initial.v[register][:]=[value&MASK,value>>64]
    initial.fpsr=(initial.fpsr&~(1<<27))|((1<<27) if flags else 0)



FPSR_QC = 1 << 27
VECTOR_BYTES = 16
VECTOR_HALF_BYTES = 8
SIMD_Q_BIT = 1 << 30
SIMD_SCALAR_BIT = 1 << 28
NARROW_SHIFT_BASES = {
    'sqshrn': 0x0f009400, 'sqrshrn': 0x0f009c00,
    'uqshrn': 0x2f009400, 'uqrshrn': 0x2f009c00,
    'sqshrun': 0x2f008400, 'sqrshrun': 0x2f008c00,
}


def narrowing_shift_programs():
    """All legal immediates; bounded aliases and boundary register chains."""
    programs = []
    for name, base in NARROW_SHIFT_BASES.items():
        for output_lane in (1, 2, 4):
            output_bits = output_lane * 8
            for scalar, upper in ((False, False), (False, True), (True, False)):
                for amount in range(1, output_bits + 1):
                    encoded = base | ((2 * output_bits - amount) << 16)
                    if scalar:
                        encoded |= SIMD_Q_BIT | SIMD_SCALAR_BIT
                    elif upper:
                        encoded |= SIMD_Q_BIT
                    config = {
                        'kind': 'narrowing_shift', 'name': name,
                        'lane': output_lane * 2, 'output_lane': output_lane,
                        'bytes': output_lane if scalar else VECTOR_HALF_BYTES,
                        'scalar': scalar, 'upper': upper, 'amount': amount,
                        'signed': not name.startswith('u'),
                        'unsigned_result': name.startswith('u') or name.endswith('un'),
                        'round': 'rsh' in name,
                    }

                    def operation(d, n):
                        return {**config, 'd': d, 'n': n, 'word': encoded | (n << 5) | d}

                    for d, n in ((0, 1), (31, 31), (31, 0)):
                        programs.append({'operations': [operation(d, n)]})
                    if amount in (1, output_bits // 2, output_bits):
                        programs.append({'operations': [operation(d, (d + 7) % 32) for d in range(32)]})
    return programs


def narrowing_shift_mathematical(operations, initial):
    vectors = [lo | (hi << 64) for lo, hi in initial.v]
    fpsr = initial.fpsr
    for op in operations:
        input_bits, output_bits = op['lane'] * 8, op['output_lane'] * 8
        source, previous = vectors[op['n']], vectors[op['d']]
        lower = 0 if op['unsigned_result'] else -(1 << (output_bits - 1))
        upper = (1 << (output_bits - int(not op['unsigned_result']))) - 1
        result = 0
        for index in range(op['bytes'] // op['output_lane']):
            value = (source >> (index * input_bits)) & ((1 << input_bits) - 1)
            if op['signed'] and value & (1 << (input_bits - 1)):
                value -= 1 << input_bits
            if op['round']:
                value += 1 << (op['amount'] - 1)
            shifted = value >> op['amount']
            saturated = min(upper, max(lower, shifted))
            if shifted != saturated:
                fpsr |= FPSR_QC
            result |= (saturated & ((1 << output_bits) - 1)) << (index * output_bits)
        if op['upper']:
            result = (previous & MASK) | (result << 64)
        vectors[op['d']] = result
    return {**state_dict(initial), 'v': [[value & MASK, value >> 64] for value in vectors], 'fpsr': fpsr}


def seed_narrowing_shifts(initial, operations, pattern, flags):
    op = operations[0]
    bits, output_bits, amount = op['lane'] * 8, op['output_lane'] * 8, op['amount']
    mask = (1 << bits) - 1
    rounding = (1 << (amount - 1)) if op['round'] else 0
    low = 0 if op['unsigned_result'] else -(1 << (output_bits - 1))
    high = (1 << (output_bits - int(not op['unsigned_result']))) - 1
    thresholds = tuple((bound << amount) - rounding + delta
                       for bound in (low, high, high + 1) for delta in (-1, 0, 1))
    values = thresholds + (0, 1, -1, 1 << (bits - 1), (1 << (bits - 1)) - 1, mask)
    for register in range(32):
        if pattern < 9:
            lanes = [thresholds[(pattern + i) % len(thresholds)] & mask for i in range(128 // bits)]
        elif pattern == 9:
            lanes = [values[9 + (register + i) % 6] & mask for i in range(128 // bits)]
        elif pattern == 10:
            # Every active source is zero; inactive scalar lanes would saturate.
            active = op['bytes'] // op['output_lane']
            lanes = [0 if i < active else 1 << (bits - 1) for i in range(128 // bits)]
        else:
            continue  # Retain independently seeded random full-state inputs.
        value = sum(lane << (i * bits) for i, lane in enumerate(lanes))
        initial.v[register][:] = [value & MASK, value >> 64]
    initial.fpsr = (initial.fpsr & ~FPSR_QC) | (FPSR_QC if flags else 0)


DOT_REGISTER_BASES = {'sdot': 0x0e009400, 'udot': 0x2e009400}
DOT_INDEXED_BASES = {'sdot': 0x0f00e000, 'udot': 0x2f00e000}
ROUND_PRODUCT_REGISTER_BASES = {'sqrdmlah': 0x2e008400, 'sqrdmlsh': 0x2e008c00}
ROUND_PRODUCT_INDEXED_BASES = {'sqrdmlah': 0x2f00d000, 'sqrdmlsh': 0x2f00f000}


def dot_round_product_programs():
    programs = []
    configurations = []
    for name in DOT_REGISTER_BASES:
        for q in (0, 1):
            for index in (None, 0, 1, 2, 3):
                encoded = (DOT_REGISTER_BASES if index is None else DOT_INDEXED_BASES)[name]
                encoded |= (2 << 22) | (q << 30)
                if index is not None:
                    encoded |= ((index >> 1) << 11) | ((index & 1) << 21)
                configurations.append((encoded, {
                    'kind': 'dot_round_product', 'name': name, 'lane': 1,
                    'output_lane': 4, 'bytes': 8 << q, 'scalar': False,
                    'index': index, 'upper': False,
                }))
    for name in ROUND_PRODUCT_REGISTER_BASES:
        for scalar in (False, True):
            for q in ((1,) if scalar else (0, 1)):
                for size in (1, 2):
                    lane = 1 << size
                    for index in (None, *range(VECTOR_BYTES // lane)):
                        encoded = (ROUND_PRODUCT_REGISTER_BASES if index is None else ROUND_PRODUCT_INDEXED_BASES)[name]
                        encoded |= (size << 22) | (q << 30) | (SIMD_SCALAR_BIT if scalar else 0)
                        if index is not None:
                            encoded |= (index >> (2 if lane == 2 else 1)) << 11
                            encoded |= (((index >> 1) if lane == 2 else index) & 1) << 21
                            if lane == 2:
                                encoded |= (index & 1) << 20
                        configurations.append((encoded, {
                            'kind': 'dot_round_product', 'name': name, 'lane': lane,
                            'output_lane': lane, 'bytes': lane if scalar else 8 << q,
                            'scalar': scalar, 'index': index, 'upper': False,
                        }))
    for encoded, config in configurations:
        def operation(d, n, m):
            if config['index'] is not None and config['lane'] == 2:
                m &= 15
            return {**config, 'd': d, 'n': n, 'm': m, 'word': encoded | (m << 16) | (n << 5) | d}

        for d, n, m in ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1), (31, 31, 31), (31, 29, 31)):
            programs.append({'operations': [operation(d, n, m)]})
        programs.append({'operations': [operation(d, (d + 5) % 32, (d + 13) % 32) for d in range(32)]})
    return programs


def dot_round_product_mathematical(operations, initial):
    vectors = [lo | (hi << 64) for lo, hi in initial.v]
    fpsr = initial.fpsr

    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    for op in operations:
        left, right, previous = (vectors[op[key]] for key in ('n', 'm', 'd'))
        bits, output_bits = op['lane'] * 8, op['output_lane'] * 8
        input_mask, output_mask = (1 << bits) - 1, (1 << output_bits) - 1
        result = 0
        for lane in range(op['bytes'] // op['output_lane']):
            accumulator = (previous >> (lane * output_bits)) & output_mask
            if op['name'] in DOT_REGISTER_BASES:
                value = accumulator
                for byte in range(op['output_lane']):
                    a = (left >> ((lane * op['output_lane'] + byte) * bits)) & input_mask
                    right_lane = lane if op['index'] is None else op['index']
                    b = (right >> ((right_lane * op['output_lane'] + byte) * bits)) & input_mask
                    if op['name'] == 'sdot':
                        a, b = signed(a, bits), signed(b, bits)
                    value += a * b
            else:
                a = signed((left >> (lane * bits)) & input_mask, bits)
                right_lane = lane if op['index'] is None else op['index']
                b = signed((right >> (right_lane * bits)) & input_mask, bits)
                product = 2 * a * b
                if op['name'] == 'sqrdmlsh':
                    product = -product
                # One unbounded fused expression: no intermediate saturation or rounding.
                rounded = ((signed(accumulator, bits) << bits) + product + (1 << (bits - 1))) >> bits
                value = min((1 << (bits - 1)) - 1, max(-(1 << (bits - 1)), rounded))
                if value != rounded:
                    fpsr |= FPSR_QC
            result |= (value & output_mask) << (lane * output_bits)
        vectors[op['d']] = result
    return {**state_dict(initial), 'v': [[value & MASK, value >> 64] for value in vectors], 'fpsr': fpsr}


def seed_dot_round_products(initial, operations, pattern, flags):
    op = operations[0]
    bits = op['lane'] * 8
    minimum, mask = 1 << (bits - 1), (1 << bits) - 1
    values = (0, 1, mask, minimum, minimum - 1, minimum + 1, mask - 1, 1 << (bits - 2))
    for register in range(32):
        if pattern < 6:
            lanes = [values[(pattern + register + i) % len(values)] for i in range(128 // bits)]
        elif pattern in (6, 7):
            lanes = [minimum] * (128 // bits)
        elif pattern == 8:
            # Saturation in inactive scalar/Q=0 source lanes must not set QC.
            lanes = [0 if i * op['lane'] < op['bytes'] else minimum for i in range(128 // bits)]
        else:
            continue
        value = sum(value << (i * bits) for i, value in enumerate(lanes))
        initial.v[register][:] = [value & MASK, value >> 64]
    if pattern in (6, 7) and op['name'] in ROUND_PRODUCT_REGISTER_BASES:
        # With distinct registers: MIN*MIN cancels a negative accumulator on add,
        # or positive accumulator on subtract; staged product saturation is wrong.
        accumulator = mask if op['name'] == 'sqrdmlah' else minimum - 1
        if pattern == 7:
            accumulator = minimum - 1 if op['name'] == 'sqrdmlah' else minimum
        value = sum(accumulator << (i * bits) for i in range(128 // bits))
        initial.v[op['d']][:] = [value & MASK, value >> 64]
    if pattern == 9 and op['name'] in ROUND_PRODUCT_REGISTER_BASES:
        # Exact half-product: subtraction rounds the negative product as part
        # of the fused expression; subtracting an already-rounded product fails.
        for key, lane_value in (('d', 0), ('n', 1), ('m', 1 << (bits - 2))):
            value = sum(lane_value << (i * bits) for i in range(128 // bits))
            initial.v[op[key]][:] = [value & MASK, value >> 64]
    initial.fpsr = (initial.fpsr & ~FPSR_QC) | (FPSR_QC if flags else 0)


def indexed_product_programs():
    # Explicit Arm indexed encodings, independent from the Rust decoder catalog.
    bases={'mul':0x0f008000,'mla':0x2f000000,'mls':0x2f004000,
        'smull':0x0f00a000,'umull':0x2f00a000,'smlal':0x0f002000,
        'umlal':0x2f002000,'smlsl':0x0f006000,'umlsl':0x2f006000}
    programs=[]
    for name,base in bases.items():
        widen=name not in ('mul','mla','mls')
        for q in (0,1):
            for size in (1,2):
                lane=1<<size
                for index in range(16//lane):
                    h=index>>(2 if lane==2 else 1)
                    l=(index>>(1 if lane==2 else 0))&1
                    encoded=base|(q<<30)|(size<<22)|(h<<11)|(l<<21)
                    if lane==2: encoded|=(index&1)<<20
                    config={'kind':'indexed_product','name':name,'lane':lane,
                        'output_lane':lane*2 if widen else lane,'bytes':16 if widen else 8<<q,
                        'signed':name.startswith('s'),'upper':widen and bool(q),'index':index,
                        'accumulate':'add' if name in ('mla','smlal','umlal') else 'sub' if name in ('mls','smlsl','umlsl') else None}
                    def operation(d,n,m):
                        if lane==2: m&=15
                        return {**config,'d':d,'n':n,'m':m,'word':encoded|(m<<16)|(n<<5)|d}
                    for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31),(0,31,31),
                                  (31,29,31),(15,15,15),(15,31,15),(31,15,15),(0,0,0)):
                        programs.append({'operations':[operation(d,n,m)]})
                    programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def indexed_product_mathematical(operations,initial):
    vectors=[lo|(hi<<64) for lo,hi in initial.v]
    for op in operations:
        lane,out_lane=op['lane'],op['output_lane'];bits,out_bits=lane*8,out_lane*8
        mask,out_mask=(1<<bits)-1,(1<<out_bits)-1
        left,right,old=(vectors[op[k]] for k in ('n','m','d'))
        if op['upper']: left>>=64
        selected=right>>(op['index']*bits)&mask
        if op['signed'] and selected&(1<<(bits-1)): selected-=1<<bits
        result=0
        for i in range(op['bytes']//out_lane):
            value=left>>(i*bits)&mask
            if op['signed'] and value&(1<<(bits-1)): value-=1<<bits
            value*=selected
            previous=old>>(i*out_bits)&out_mask
            if op['accumulate']=='add': value=previous+value
            elif op['accumulate']=='sub': value=previous-value
            result|=(value&out_mask)<<(i*out_bits)
        vectors[op['d']]=result
    return {**state_dict(initial),'v':[[v&MASK,v>>64] for v in vectors]}


def seed_indexed_products(initial,operations,pattern,flags):
    bits=operations[0]['lane']*8;mask=(1<<bits)-1;minimum=1<<(bits-1)
    values=(0,1,mask,minimum,minimum-1,minimum+1,mask-1)
    for register in range(32):
        if pattern<7:
            lanes=[values[(pattern+register+i)%len(values)] for i in range(128//bits)]
        elif pattern==7:
            # Every source element differs, including low/high-half positions.
            lanes=[((register+1)*257+(i+1)*37)&mask for i in range(128//bits)]
        else: continue # Independently seeded random complete state.
        value=sum(v<<(i*bits) for i,v in enumerate(lanes));initial.v[register][:]=[value&MASK,value>>64]
    initial.fpsr=(initial.fpsr&~(1<<27))|((1<<27) if flags else 0)


def floating_bit_programs():
    """Canonical forms have multiple arrangements; keep both counts explicit."""
    configurations=[]
    for ftype,lane in ((0,4),(1,8),(3,2)):
        for condition in range(16):
            configurations.append({'name':'fcsel','base':0x1e200c00|(ftype<<22)|(condition<<12),
                'lane':lane,'bytes':lane,'scalar':True,'condition':condition})
        for name,base in (('fabs',0x1e20c000),('fneg',0x1e214000)):
            configurations.append({'name':name,'base':base|(ftype<<22),'lane':lane,'bytes':lane,'scalar':True})
    for name,half,ordinary in (('fabs',0x0ef8f800,0x0ea0f800),('fneg',0x2ef8f800,0x2ea0f800)):
        for lane in (2,4,8):
            for q in ((1,) if lane==8 else (0,1)):
                base=(half if lane==2 else ordinary|((lane==8)<<22))|(q<<30)
                configurations.append({'name':name,'base':base,'lane':lane,'bytes':8<<q,'scalar':False})
    programs=[]
    for config in configurations:
        def operation(d,n,m):
            word=config['base']|(n<<5)|d
            if config['name']=='fcsel': word|=m<<16
            return {**config,'kind':'floating_bits','d':d,'n':n,'m':m,'word':word}
        for d,n,m in ((0,1,2),(1,1,2),(2,1,2),(31,31,31)):
            programs.append({'operations':[operation(d,n,m)]})
        programs.append({'operations':[operation(d,(d+5)%32,(d+13)%32) for d in range(32)]})
    return programs


def floating_bit_mathematical(operations,initial):
    """Field classification follows FPUnpack(FALSE); it ignores AHP for FP16."""
    vectors=[lo|(hi<<64) for lo,hi in initial.v]
    flags=initial.nzcv>>28;n,z,c,v=(bool(flags&(1<<bit)) for bit in (3,2,1,0))
    predicates=(z,c,n,v,c and not z,n==v,not z and n==v,True)
    for op in operations:
        lane,bits,d,source=op['lane'],op['lane']*8,op['d'],vectors[op['n']]
        mask=(1<<bits)-1
        if op['name']=='fcsel':
            cond=op['condition'];holds=predicates[cond//2]
            if cond<14 and cond&1: holds=not holds
            result=(source if holds else vectors[op['m']])&mask
        else:
            result=0
            exponent_bits={2:5,4:8,8:11}[lane];fraction_bits=bits-exponent_bits-1
            for index in range(op['bytes']//lane):
                value=source>>(index*bits)&mask
                exponent=value>>fraction_bits&((1<<exponent_bits)-1)
                fraction=value&((1<<fraction_bits)-1)
                nan=exponent==((1<<exponent_bits)-1) and fraction!=0
                if not (initial.fpcr&2 and nan):
                    value=(value&~(1<<(bits-1))) if op['name']=='fabs' else value^(1<<(bits-1))
                result|=value<<(index*bits)
            if op['scalar'] and initial.fpcr&4: result|=vectors[d]&~mask
        vectors[d]=result
    return {**state_dict(initial),'v':[[value&MASK,value>>64] for value in vectors]}


def seed_floating_bits(initial,operations,pattern):
    bits=operations[0]['lane']*8;fraction=bits-{16:5,32:8,64:11}[bits]-1
    infinity=((1<<(bits-fraction-1))-1)<<fraction;sign=1<<(bits-1)
    values=(0,sign,infinity,infinity|sign,infinity|1,infinity|sign|1,
        infinity|(1<<(fraction-1)),infinity|sign|(1<<(fraction-1))|3,
        1,sign|1,(1<<fraction)-1,1<<fraction,infinity-1,sign|(infinity-1))
    for register in range(32):
        if pattern<len(values):
            value=sum(values[(pattern+register+index)%len(values)]<<(index*bits) for index in range(128//bits))
            initial.v[register][:]=[value&MASK,value>>64]


def floating_bit_cases(functions,exhaustive_half=True):
    templates=states(all_flags=True)
    for index,function in enumerate(functions):
        operations=function['operations'];select=operations[0]['name']=='fcsel'
        controls=(0,7,0x07c80000,0x07c80007) if select else tuple(low|high for high in (0,0x07c80000) for low in range(8))
        for control in controls:
            for pattern in range(15):
                for flags in (range(16) if select and pattern==0 else (0,15)):
                    initial=State.from_buffer_copy(templates[flags]);seed_extended_state(initial,index*65536+pattern*16+flags)
                    initial.reserved=0x51ad1234;initial.nzcv=flags<<28;initial.fpcr=control
                    initial.fpsr=(1<<27)|0x9f if flags else 0
                    seed_floating_bits(initial,operations,pattern)
                    yield index,initial
    if exhaustive_half:
        for name in ('fabs','fneg'):
            index=next(i for i,f in enumerate(functions) if len(f['operations'])==1 and
                all(f['operations'][0].get(k)==v for k,v in {'name':name,'lane':2,'bytes':16,'scalar':False,'d':0,'n':1}.items()))
            for ah in (0,2):
                for first in range(0,65536,8):
                    initial=State();seed_extended_state(initial,first+ah);initial.fpcr=0x07c80005|ah;initial.fpsr=(1<<27)|0x9f
                    value=sum((first+lane)<<(lane*16) for lane in range(8))
                    initial.v[1][:]=[value&MASK,value>>64]
                    yield index,initial


def floating_qemu_source(functions,count):
    """Owned bare-metal transport. Only .inst lines are acceptance instructions."""
    lines=['.arch armv8.7-a+fp16','.text','.global _start','_start:',
        'mov x0,#0x300000','msr cpacr_el1,x0','isb',
        'mov x19,#0x41000000','mov x20,#0x49000000','mov x23,#0x40070000','add x23,x23,#0x1000',
        'adrp x21,functions','add x21,x21,:lo12:functions',f'add x24,x21,#{len(functions)*8}',
        f'movz x22,#{count&65535}',f'movk x22,#{count>>16},lsl#16','again:']
    for table in ('x21','x24'):
        lines+=['ldr w0,[x19,#264]','msr nzcv,x0','ldr w0,[x19,#784]','msr fpcr,x0','ldr w0,[x19,#788]','msr fpsr,x0']
        lines.extend(f'ldr q{i},[x19,#{272+i*16}]' for i in range(32))
        lines+=['ldr x0,[x19]',f'ldr x0,[{table},x0,lsl#3]','blr x0']
        lines.extend(f'str q{i},[x20,#{i*16}]' for i in range(32))
        lines+=['mrs x0,nzcv','str w0,[x20,#512]','mrs x0,fpcr','str w0,[x20,#516]',
            'mrs x0,fpsr','str w0,[x20,#520]','mov w0,#0x1234','str w0,[x20,#524]','add x20,x20,#528']
    lines+=['add x19,x19,#800','subs x22,x22,#1','b.ne again',
        'mov x0,#0x1234','mov x1,#0x40070000','str x0,[x1]','completed: b completed']
    for index,function in enumerate(functions):
        lines.append(f'function_{index}:')
        lines.extend(f'.inst 0x{op["word"]:08x}' for op in function['operations'])
        lines.append('ret')
    for index,function in enumerate(functions):
        lines.append(f'component_{index}:')
        for op in function['operations']:
            if op['scalar']:
                lines.append(f'.inst 0x{op["word"]:08x}')
                continue
            # Independent original scalar FPAbs/FPNeg checks each vector lane.
            # Preserve the unmodified original-vector result in its own record;
            # this decomposition is explicitly a component oracle, not equality
            # between the original vector instruction and the QEMU model.
            lines+=['str q31,[x23]','str q30,[x23,#16]',f'str q{op["n"]},[x23,#32]','movi v31.2d,#0']
            lane=op['lane'];suffix={2:'h',4:'s',8:'d'}[lane];ftype={2:3,4:0,8:1}[lane]
            scalar=(0x1e20c000 if op['name']=='fabs' else 0x1e214000)|(ftype<<22)|(30<<5)|30
            for element in range(op['bytes']//lane):
                lines.extend([f'ldr {suffix}30,[x23,#{32+element*lane}]',f'.inst 0x{scalar:08x}',
                    f'ins v31.{suffix}[{element}],v30.{suffix}[0]'])
            lines+=['str q31,[x23,#64]','ldr q31,[x23]','ldr q30,[x23,#16]',f'ldr q{op["d"]},[x23,#64]']
        lines.append('ret')
    lines+=['.section .rodata','.balign 8','functions:']
    lines.extend(f'.quad function_{index}' for index in range(len(functions)))
    lines.extend(f'.quad component_{index}' for index in range(len(functions)))
    return '\n'.join(lines)+'\n'


def floating_qemu_results(functions):
    """Execute unchanged original A64 with AFP; cache only hash-bound results."""
    qemu=ROOT/'.tools/qemu/bin/qemu-system-aarch64'
    if not qemu.exists():
        found=shutil.which('qemu-system-aarch64')
        if not found: raise AssertionError('AFP verification requires qemu-system-aarch64 with FEAT_AFP')
        qemu=Path(found)
    version=subprocess.check_output([str(qemu),'--version'],text=True).splitlines()[0]
    binaries=[qemu,*sorted((ROOT/'.tools/qemu/Cellar/qemu').glob('*/bin/qemu-system-aarch64'))]
    identities={str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path):digest(path.read_bytes()) for path in binaries}
    inputs=bytearray();count=0
    for index,initial in floating_bit_cases(functions):
        inputs+=struct.pack('<Q',index)+bytes(initial)+bytes(8);count+=1
    if not 0<count<=160000: raise AssertionError(f'QEMU fixture RAM bounds exceeded: {count}')
    assembly=floating_qemu_source(functions,count)
    key=digest(bytes(inputs)+assembly.encode()+json.dumps(identities,sort_keys=True).encode()+Path(__file__).read_bytes())
    directory=ROOT/'.stela/native-evidence/floating-original-qemu'/key;directory.mkdir(parents=True,exist_ok=True)
    receipt_path=directory/'receipt.json';result_path=directory/'results.bin'
    if receipt_path.exists():
        receipt=json.loads(receipt_path.read_text())
        for name,info in receipt['files'].items():
            if digest((directory/name).read_bytes())!=info['sha256']: raise AssertionError('Immutable QEMU evidence changed')
        return result_path.read_bytes(),receipt
    (directory/'inputs.bin').write_bytes(inputs);(directory/'guest.S').write_text(assembly)
    subprocess.run(['clang','--target=aarch64-unknown-none-elf','-c',str(directory/'guest.S'),'-o',str(directory/'guest.o')],check=True)
    lld=shutil.which('ld.lld')
    if not lld:
        candidates=sorted((ROOT/'.tools/rust/rustup/toolchains').glob('*/lib/rustlib/*/bin/rust-lld'))
        if not candidates: raise AssertionError('QEMU oracle ELF requires ld.lld or installed Rust rust-lld')
        lld=str(candidates[0])
    env=os.environ.copy()
    if Path(lld).name=='rust-lld' and os.uname().sysname=='Darwin': env['DYLD_LIBRARY_PATH']=str(Path(lld).resolve().parents[3])
    subprocess.run([lld,*(['-flavor','gnu'] if Path(lld).name=='rust-lld' else []),'-m','aarch64elf',
        '-Ttext','0x40080000','-e','_start',str(directory/'guest.o'),'-o',str(directory/'guest.elf')],check=True,env=env)
    # QMP dumps final RAM; no semihosting, guest libraries or external binaries.
    with tempfile.TemporaryDirectory(prefix='stela-fp-qmp-') as temporary:
        endpoint=Path(temporary)/'qmp'
        command=[str(qemu),'-machine','virt','-cpu','max','-accel','tcg','-m','512M','-display','none','-serial','none',
            '-monitor','none','-nic','none','-kernel',str(directory/'guest.elf'),'-device',
            f'loader,file={directory/"inputs.bin"},addr=0x41000000,force-raw=on','-qmp',f'unix:{endpoint},server=on,wait=off','-S']
        (directory/'command.json').write_text(json.dumps(command,indent=2)+'\n')
        with (directory/'stderr.log').open('wb') as log:
            process=subprocess.Popen(command,stdout=log,stderr=log)
            connection=None;stream=None
            try:
                deadline=time.monotonic()+15
                while not endpoint.exists():
                    if process.poll() is not None or time.monotonic()>deadline: raise AssertionError('QEMU failed before QMP connection')
                    time.sleep(0.02)
                connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(10);connection.connect(str(endpoint))
                stream=connection.makefile('rwb');json.loads(stream.readline())
                def request(name,arguments=None):
                    data={'execute':name}
                    if arguments is not None: data['arguments']=arguments
                    stream.write(json.dumps(data).encode()+b'\n');stream.flush()
                    while True:
                        reply=json.loads(stream.readline())
                        if 'error' in reply: raise AssertionError(reply)
                        if 'return' in reply: return reply['return']
                request('qmp_capabilities');request('cont');deadline=time.monotonic()+60
                while True:
                    marker=request('human-monitor-command',{'command-line':'xp /1gx 0x40070000'})
                    if marker.strip().endswith('0x0000000000001234'): break
                    if process.poll() is not None or time.monotonic()>deadline:
                        raise AssertionError(f'QEMU original fixture failed or timed out: {marker}')
                    time.sleep(0.02)
                request('stop')
                request('human-monitor-command',{'command-line':f'pmemsave 0x49000000 {count*1056} "{result_path}"'})
                request('quit');process.wait(timeout=5)
            finally:
                if stream is not None: stream.close()
                if connection is not None: connection.close()
                if process.poll() is None: process.kill();process.wait(timeout=5)
    results=result_path.read_bytes()
    if len(results)!=count*1056: raise AssertionError('QEMU returned a truncated register result stream')
    files={name:{'path':str((directory/name).relative_to(ROOT)),'sha256':digest((directory/name).read_bytes()),
        'bytes':(directory/name).stat().st_size} for name in ('inputs.bin','guest.S','guest.elf','results.bin','command.json','stderr.log')}
    receipt={'engine':version,'cpu':'max','transport':'owned bare-metal A64 fixture, QMP physical RAM dump',
        'qemu_executable_sha256':identities,'cases':count,'files':files,
        'limits':'Original emulator execution, no Apple hardware claim. Captures all V registers, NZCV, FPCR and FPSR after each fixture; GPRs/SP are harness transport, not original architectural comparisons. Native/math comparisons additionally check every byte of GuestState. No disabled-FP trap or SME streaming claim.'}
    receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
    return results,receipt


def execute_floating_bit_batches(batches):
    corpus=hashlib.sha256();comparisons=0;unicorn_comparisons=0;original_equal=0;component_equal=0;divergences=[];divergence_count=0;dynamic=[]
    receipts=[]
    for batch in batches:
        results,receipt=floating_qemu_results(batch['functions']);receipts.append(receipt)
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM);machine.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
        machine.mem_map(BASE,(len(batch['source'])+4095)&~4095);machine.mem_write(BASE,batch['source'])
        with executable(batch['native']) as address:
            natives=[ctypes.CFUNCTYPE(None,ctypes.POINTER(State))(address+offset) for offset in batch['offsets']]
            for case,(index,initial) in enumerate(floating_bit_cases(batch['functions'])):
                operations=batch['functions'][index]['operations']
                expected=floating_bit_mathematical(operations,initial)
                observations=[]
                for component in (0,1):
                    original=State.from_buffer_copy(initial)
                    fields=struct.unpack_from('<64Q4I',results,case*1056+component*528)
                    for register in range(32): original.v[register][:]=fields[register*2:register*2+2]
                    original.nzcv,original.fpcr,original.fpsr=fields[64:67]
                    if fields[67]!=0x1234: raise AssertionError('QEMU result sentinel missing')
                    observations.append(state_dict(original))
                original,component=observations
                actual=State.from_buffer_copy(initial);natives[index](ctypes.byref(actual))
                if component!=expected or state_dict(actual)!=expected:
                    raise AssertionError(json.dumps({'operations':operations,'initial':state_dict(initial),
                        'math':expected,'qemu_original':original,'qemu_scalar_component':component,'native':state_dict(actual)}))
                component_equal+=1
                if original==expected: original_equal+=1
                else:
                    if operations[0]['scalar'] or not initial.fpcr&2: raise AssertionError('Unexpected original QEMU divergence')
                    legacy_state=State.from_buffer_copy(initial);legacy_state.fpcr&=~2
                    legacy=floating_bit_mathematical(operations,legacy_state);legacy['fpcr']=initial.fpcr
                    if original!=legacy: raise AssertionError('QEMU difference is larger than exact vector AH NaN sign handling')
                    divergence_count+=1
                    if len(divergences)<32:
                        divergences.append({'operations':operations,'initial_state_sha256':digest(bytes(initial)),
                            'requested_fpcr':initial.fpcr,'original_v':original['v'],'spec_native_v':expected['v'],
                            'classification':'QEMU10 vector FABS/FNEG ignores AH for NaN signs; scalar component oracle matches pinned specification'})
                # Unicorn MAX implements FP16/FZ16 but not AFP. Never erase controls to
                # turn a divergent original observation into an equality claim.
                if initial.fpcr==0:
                    initialize_arm(machine,initial);entry=batch['entries'][index];end=BASE+(entry+len(operations))*4
                    machine.emu_start(BASE+entry*4,end,count=len(operations)+1)
                    if machine.reg_read(arm.UC_ARM64_REG_PC)!=end or state_dict(capture_arm(machine,initial))!=expected:
                        raise AssertionError('Unicorn baseline differs from pinned FP bit semantics')
                    unicorn_comparisons+=1
                corpus.update(struct.pack('<Q',index));corpus.update(bytes(initial));comparisons+=1
            rows=[]
            representatives={}
            for index,function in enumerate(batch['functions']):
                if len(function['operations'])==1:
                    shape=json.dumps(native_operation_shape(function['operations'][0]),sort_keys=True)
                    representatives.setdefault(shape,index)
            for index in representatives.values():
                operation=batch['functions'][index]['operations'][0];entry=batch['entries'][index]
                start=batch['instruction_offsets'][entry];end=batch['instruction_offsets'][entry+1]+1
                for control in (0,2,4,6):
                    for pattern in (4,8):
                        initial=State();seed_extended_state(initial,index*16+pattern);seed_floating_bits(initial,[operation],pattern);initial.fpcr=control
                        expected=floating_bit_mathematical([operation],initial);actual=State.from_buffer_copy(initial);natives[index](ctypes.byref(actual))
                        emulated,counts=emulate_native_trace(batch['native'],start,end,initial)
                        if state_dict(actual)!=expected or state_dict(emulated)!=expected: raise AssertionError('FP bit dynamic x86 trace disagrees')
                        rows.append({'shape':native_operation_shape(operation),'fpcr':control,'pattern':pattern,
                            'native_function_sha256':digest(batch['native'][start:end]),**counts})
            dynamic.append({'reference':f'Unicorn {unicorn_version} x86 Haswell trace and actual host CPU; QEMU original results checked separately',
                'complete_state_math_actual_native_emulator_comparisons':len(rows),'cases':rows,
                'limits':'Executed instruction counts include dynamic AH/NEP branches, exclude harness RET in body totals; no hardware-cycle or application-performance claim.'})
    probe=Uc(UC_ARCH_ARM64,UC_MODE_ARM);probe.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
    controls=[]
    for value in (7,1<<19,0x9f00):
        probe.reg_write(arm.UC_ARM64_REG_FPCR,value);controls.append({'requested_fpcr':value,'observed_fpcr':probe.reg_read(arm.UC_ARM64_REG_FPCR)})
    if [row['observed_fpcr'] for row in controls]!=[0,1<<19,0]: raise AssertionError('Unicorn FP capabilities changed; review oracle classification')
    return {'three_way_register_state_comparisons':original_equal,'qemu_original_vector_control_math_native_comparisons':original_equal,
        'complete_native_state_math_comparisons':comparisons,'qemu_original_scalar_component_math_native_comparisons':component_equal,
        'qemu_original_exact_vector_ah_divergences':divergence_count,'qemu_original_divergence_examples':divergences,
        'unicorn_original_complete_state_math_native_comparisons':unicorn_comparisons,'unicorn_missing_control_observations':controls,
        'qemu_original_evidence':receipts,'state_corpus_sha256':corpus.hexdigest(),'dynamic_x86_trace':dynamic,
        'limits':'QEMU independently executes unchanged original FP instructions across AFP controls; complete native state compared to independent field oracle. QEMU captures V0..V31/NZCV/FPCR/FPSR, while GPR/SP use fixture transport. QEMU10 vector AH NaN sign divergences are exact classified observations, not direct-original verification; independent original scalar-per-lane decomposition is supplementary. No numerical FP arithmetic, guest exception delivery, streaming SME, or complete binary execution claim.'}


REGISTER_COHORTS={
    'integer':(integer_programs,integer_mathematical),
    'rearrange':(rearrange_programs,rearrange_mathematical),
    'shifts':(shift_programs,shift_mathematical),
    'register_shifts':(register_shift_programs,register_shift_mathematical),
    'reductions':(reduction_programs,reduction_mathematical),
    'saturating':(saturating_programs,saturating_mathematical),
    'products':(product_programs,product_mathematical),
    'indexed_products':(indexed_product_programs,indexed_product_mathematical),
    'doubling_products':(doubling_product_programs,doubling_product_mathematical),
    'narrowing_shifts':(narrowing_shift_programs,narrowing_shift_mathematical),
    'dot_round_products':(dot_round_product_programs,dot_round_product_mathematical),
    'halving':(halving_programs,halving_mathematical),
    'immediates':(immediate_programs,immediate_mathematical),
    'floating_bits':(floating_bit_programs,floating_bit_mathematical),
}


def execute_register_batches(batches):
    if batches[0]['cohort']=='floating_bits': return execute_floating_bit_batches(batches)
    corpus,comparisons=hashlib.sha256(),0
    dynamic=[]
    templates=states(all_flags=True)
    for batch in batches:
        machine=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        if batch['cohort'] in ('immediates','dot_round_products'): machine.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
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
                if batch.get('cohort')=='doubling_products': patterns=10
                if batch.get('cohort')=='indexed_products': patterns=9
                if batch.get('cohort')=='register_shifts': patterns=register_shift_pattern_count(operations)
                if batch.get('cohort')=='narrowing_shifts': patterns=12
                if batch.get('cohort')=='dot_round_products': patterns=11
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
                        if batch.get('cohort')=='doubling_products': seed_doubling_products(initial,operations,pattern,flags)
                        if batch.get('cohort')=='indexed_products': seed_indexed_products(initial,operations,pattern,flags)
                        if batch.get('cohort')=='register_shifts': register_shift_seed(initial,operations,pattern,flags)
                        if batch.get('cohort')=='narrowing_shifts': seed_narrowing_shifts(initial,operations,pattern,flags)
                        if batch.get('cohort')=='dot_round_products': seed_dot_round_products(initial,operations,pattern,flags)
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
        dynamic.append(count_representative_native_paths(batch))
    return {'three_way_register_state_comparisons':comparisons,'state_corpus_sha256':corpus.hexdigest(),
        'dynamic_x86_trace':dynamic}


def native_mnemonic(mnemonic):
    # Capstone names immediate operand-half selections as PCLMUL aliases.
    aliases={'pclmullqlqdq','pclmulhqlqdq','pclmullqhqdq','pclmulhqhqdq'}
    return 'pclmulqdq' if mnemonic in aliases else mnemonic


def decode_native_stream(native):
    decoded=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(native,0))
    position=0
    for instruction in decoded:
        if instruction.address!=position or instruction.size<=0:
            raise AssertionError('Native disassembly has a gap or invalid instruction size')
        position+=instruction.size
    if position!=len(native) or not decoded:
        raise AssertionError('Native disassembly did not consume the complete binary')
    return decoded


def native_operation_shape(operation):
    keys=('name','lane','output_lane','bytes','scalar','index','upper','immediate','amount')
    shape={key:operation[key] for key in keys if key in operation}
    if operation.get('kind')=='register_shift' and not operation.get('immediate'):
        shape['counts']='signed_low_byte_per_lane'
    return shape


def native_binary_accounting(batch,decoded=None):
    decoded=decode_native_stream(batch['native']) if decoded is None else decoded
    boundaries={instruction.address:index for index,instruction in enumerate(decoded)}
    boundaries[len(batch['native'])]=len(decoded)
    offsets=batch['instruction_offsets'];guest_operations=0;body_bytes=0;body_instructions=0
    shapes={};ret_instructions=0
    if len(offsets)!=sum(len(f['operations'])+1 for f in batch['functions']):
        raise AssertionError('Native accounting needs one source-map boundary per guest operation and RET')
    for function,entry in zip(batch['functions'],batch['entries']):
        operations=function['operations'];guest_operations+=len(operations)
        for index in range(len(operations)):
            start,end=offsets[entry+index],offsets[entry+index+1]
            if start not in boundaries or end not in boundaries or end<=start:
                raise AssertionError('Source map splits a native instruction or reverses an operation')
            body_bytes+=end-start;body_instructions+=boundaries[end]-boundaries[start]
        ret_offset=offsets[entry+len(operations)]
        if ret_offset not in boundaries or decoded[boundaries[ret_offset]].mnemonic!='ret':
            raise AssertionError('Native accounting found no exact harness RET')
        ret_instructions+=1
        if len(operations)==1:
            shape=native_operation_shape(operations[0]);key=json.dumps(shape,sort_keys=True)
            start,end=offsets[entry],ret_offset
            size,count=end-start,boundaries[end]-boundaries[start]
            if key not in shapes:
                shapes[key]={'shape':shape,'functions':0,'native_bytes_min':size,'native_bytes_max':size,
                    'native_instructions_min':count,'native_instructions_max':count}
            row=shapes[key];row['functions']+=1
            for field,value in [('native_bytes',size),('native_instructions',count)]:
                row[field+'_min']=min(row[field+'_min'],value);row[field+'_max']=max(row[field+'_max'],value)
    if body_instructions+ret_instructions!=len(decoded) or body_bytes+ret_instructions!=len(batch['native']):
        raise AssertionError('Native accounting did not partition guest bodies and one-byte leaf RETs')
    return {'native_sha256':digest(batch['native']),'source_sha256':digest(batch['source']),
        'static_native_bytes_including_ret':len(batch['native']),
        'static_native_instructions_including_ret':len(decoded),
        'harness_ret_instructions':ret_instructions,'harness_ret_bytes':ret_instructions,
        'guest_operations_excluding_ret':guest_operations,'guest_operation_source_bytes':guest_operations*4,
        'static_body_native_bytes':body_bytes,'static_body_native_instructions':body_instructions,
        'body_native_instructions_per_guest_operation':body_instructions/guest_operations,
        'body_native_bytes_per_guest_operation':body_bytes/guest_operations,
        'body_native_to_guest_byte_expansion':body_bytes/(guest_operations*4),
        'static_opcode_histogram':dict(sorted(Counter(native_mnemonic(i.mnemonic) for i in decoded).items())),
        'single_operation_shapes':[shapes[key] for key in sorted(shapes)],
        'limits':'Static counts fully decode final emitted bytes, include both branch paths and count loop bodies once. Shape/body counts exclude the one-byte harness RET. These counts are not dynamic instruction counts, CPU cycles or application performance.'}


def emulate_native_trace(native,start,end,initial,instruction_budget=100000):
    code_base,state_base,stack_base=0x10000000,0x20000000,0x30000000
    code_size=(len(native)+4095)&~4095;stop=code_base+code_size+4096
    machine=Uc(UC_ARCH_X86,UC_MODE_64);machine.ctl_set_cpu_model(intel.UC_CPU_X86_HASWELL)
    machine.mem_map(code_base,code_size);machine.mem_write(code_base,native)
    machine.mem_map(stop,4096);machine.mem_write(stop,b'\x90')
    machine.mem_map(state_base,4096);machine.mem_write(state_base,bytes(initial))
    machine.mem_map(stack_base,4096);machine.mem_write(stack_base+2048,struct.pack('<Q',stop))
    machine.reg_write(intel.UC_X86_REG_RDI,state_base);machine.reg_write(intel.UC_X86_REG_RSP,stack_base+2048)
    machine.reg_write(intel.UC_X86_REG_MXCSR,0x1f80)
    counts=Counter();previous=None;backward_edges=0
    def trace(_,pc,size,__):
        nonlocal previous,backward_edges
        if not code_base+start<=pc<code_base+end or pc+size>code_base+end:
            raise AssertionError('Generated x86 trace escaped its exact mini-function boundary')
        offset=pc-code_base;counts[offset]+=1
        if previous is not None and offset<previous: backward_edges+=1
        previous=offset
    machine.hook_add(UC_HOOK_CODE,trace)
    machine.emu_start(code_base+start,stop,timeout=1_000_000,count=instruction_budget)
    if machine.reg_read(intel.UC_X86_REG_RIP)!=stop:
        raise AssertionError('Generated x86 trace did not return within its finite instruction/time budget')
    if counts[end-1]!=1 or native[end-1]!=0xc3:
        raise AssertionError('Generated x86 trace must execute exactly one harness RET')
    observed=State.from_buffer_copy(machine.mem_read(state_base,ctypes.sizeof(State)))
    return observed,{'dynamic_native_instructions_including_ret':sum(counts.values()),
        'dynamic_body_native_instructions':sum(counts.values())-1,'harness_ret_instructions':1,
        'unique_native_instruction_addresses':len(counts),'backward_edges_taken':backward_edges}


def native_trace_representatives(batch):
    focus=batch['cohort']
    if focus=='doubling_products':
        selections=[{'name':'pmull','lane':8,'upper':False},{'name':'pmull','lane':8,'upper':True},
            {'name':'pmul','bytes':16},{'name':'sqrdmulh','lane':4,'bytes':16,'index':None},
            {'name':'sqrdmulh','lane':2,'bytes':16,'index':None},
            {'name':'sqdmull','lane':4,'upper':True,'index':None},
            {'name':'sqdmlal','lane':4,'bytes':8,'index':3},{'name':'sqdmlsl','lane':2,'bytes':16,'upper':False},
            {'name':'sqrdmulh','lane':2,'bytes':8,'index':7}]
    elif focus=='indexed_products':
        selections=[{'name':'mul','lane':4,'bytes':16,'index':3},
            {'name':'mla','lane':2,'bytes':8,'index':7},
            {'name':'mls','lane':4,'bytes':16,'index':2},
            {'name':'smull','lane':4,'upper':True,'index':3},
            {'name':'umull','lane':2,'upper':True,'index':5},
            {'name':'smlal','lane':4,'upper':False,'index':1},
            {'name':'umlsl','lane':4,'upper':True,'index':3}]
    elif focus=='register_shifts':
        selections=[{'name':'sqshl','lane':8,'scalar':True,'immediate':False},
            {'name':'sshl','lane':1,'bytes':16,'immediate':False},
            {'name':'sqrshl','lane':8,'bytes':16,'immediate':False},
            {'name':'uqshl','lane':1,'bytes':16,'immediate':True,'amount':1},
            {'name':'sqshl','lane':1,'bytes':16,'immediate':True,'amount':1},
            {'name':'sqshlu','lane':1,'bytes':16,'immediate':True,'amount':0},
            {'name':'sqshlu','lane':8,'bytes':16,'immediate':True,'amount':0},
            {'name':'sqshl','lane':4,'bytes':16,'immediate':True,'amount':31}]
    elif focus=='narrowing_shifts':
        selections=[{'name':'sqshrn','lane':8,'scalar':True,'amount':32},
            {'name':'sqrshrn','lane':4,'upper':True,'amount':1},
            {'name':'uqshrn','lane':2,'scalar':False,'upper':False,'amount':8},
            {'name':'uqrshrn','lane':8,'upper':True,'amount':1},
            {'name':'sqshrun','lane':4,'scalar':True,'amount':16},
            {'name':'sqrshrun','lane':2,'upper':True,'amount':1}]
    elif focus=='dot_round_products':
        selections=[{'name':'sdot','bytes':16,'index':None},
            {'name':'udot','bytes':8,'index':3},
            {'name':'sqrdmlah','lane':2,'bytes':16,'index':None},
            {'name':'sqrdmlsh','lane':4,'scalar':True,'index':3},
            {'name':'sqrdmlah','lane':2,'bytes':8,'index':7}]
    else: return []
    representatives=[]
    for selection in selections:
        for index,function in enumerate(batch['functions']):
            if len(function['operations'])==1 and all(function['operations'][0].get(k)==v for k,v in selection.items()):
                representatives.append(index);break
        else: raise AssertionError(f'Missing bounded dynamic representative: {selection}')
    return representatives


def count_representative_native_paths(batch):
    rows=[]
    with executable(batch['native']) as address:
        for index in native_trace_representatives(batch):
            function=batch['functions'][index];operations=function['operations'];entry=batch['entries'][index]
            start=batch['instruction_offsets'][entry];end=batch['instruction_offsets'][entry+1]+1
            if batch['cohort'] == 'narrowing_shifts':
                patterns = (0, 9)
            elif batch['cohort'] == 'dot_round_products':
                patterns = (6, 7, 9)
            elif batch['cohort'] in ('doubling_products', 'indexed_products'):
                patterns = (0, 7)
            elif operations[0]['immediate']:
                patterns = (0, 6)
            else:
                counts = register_shift_counts(operations[0]['lane'] * 8)
                patterns = (counts.index(-64), counts.index(1))
            native=ctypes.CFUNCTYPE(None,ctypes.POINTER(State))(address+start)
            for pattern in patterns:
                initial=State();seed_extended_state(initial,index*16+pattern);initial.nzcv=0xf0000000
                if batch['cohort']=='doubling_products': seed_doubling_products(initial,operations,pattern,0)
                elif batch['cohort']=='indexed_products': seed_indexed_products(initial,operations,pattern,0)
                elif batch['cohort']=='narrowing_shifts': seed_narrowing_shifts(initial,operations,pattern,0)
                elif batch['cohort']=='dot_round_products': seed_dot_round_products(initial,operations,pattern,0)
                else: register_shift_seed(initial,operations,pattern,0)
                mathematical=REGISTER_COHORTS[batch['cohort']][1](operations,initial)
                actual=State.from_buffer_copy(initial);native(ctypes.byref(actual))
                emulated,counts=emulate_native_trace(batch['native'],start,end,initial)
                if mathematical!=state_dict(actual) or state_dict(actual)!=state_dict(emulated):
                    raise AssertionError(json.dumps({'dynamic_operations':operations,'initial':state_dict(initial),
                        'math':mathematical,'actual_native':state_dict(actual),'x86_emulated':state_dict(emulated)}))
                rows.append({'shape':native_operation_shape(operations[0]),'word':f"0x{operations[0]['word']:08x}",
                    'pattern':pattern,'native_start':start,'native_end':end,
                    'native_function_sha256':digest(batch['native'][start:end]),'initial_state_sha256':digest(bytes(initial)),
                    'output_state_sha256':digest(bytes(actual)),**counts})
    return {'reference':f'Unicorn {unicorn_version} x86-64 Haswell instruction-hook trace; same final emitted bytes also executed on the actual host CPU',
        'complete_state_math_actual_native_emulator_comparisons':len(rows),'instruction_budget_per_trace':100000,
        'timeout_microseconds_per_trace':1000000,'cases':rows,
        'limits':'Dynamic counts are bounded emulator instruction-path counts, including repeated loop bodies and taken branches. They are not CPU hardware counter readings, CPU cycles or application performance; the harness RET is reported separately.'}


def retain_native_binary_evidence(batch,accounting,dynamic):
    return retain_native_evidence(
        f"simd-{batch['cohort']}", batch['source'], batch['native'], batch['manifest'],
        {'static': accounting, 'dynamic': dynamic}, Path(__file__).read_bytes(), root=ROOT)



NUMERICAL_FOCUS = 'scalar_numerical'
NUMERICAL_FOUNDATION = ROOT / '.stela/research/numerical-fp/receipt.json'
NUMERICAL_RETURN_EXIT = 4
NUMERICAL_HELPER_EXIT = 9
NUMERICAL_EXCEPTION_FLAGS = 0x9f
NUMERICAL_EXCEPTION_ENABLE_SHIFT = 8
NUMERICAL_TRAP_ENABLE_MASK = NUMERICAL_EXCEPTION_FLAGS << NUMERICAL_EXCEPTION_ENABLE_SHIFT
NUMERICAL_NEP = 1 << 2
NUMERICAL_AH = 1 << 1
NUMERICAL_FZ16 = 1 << 19
NUMERICAL_FZ = 1 << 24
NUMERICAL_ROUND_NEGATIVE = 2 << 22
NUMERICAL_INVALID_ENABLE = 1 << NUMERICAL_EXCEPTION_ENABLE_SHIFT
NUMERICAL_MXCSR_ALL_MASKS = 0x1f80
NUMERICAL_MXCSR_ALL_STATUS = 0x3f
NUMERICAL_MXCSR_ROUND_SHIFT = 13
NUMERICAL_CACHE_LOOP_ITERATIONS = 3
NUMERICAL_ZERO_CARRY_FLAGS = 0x60000000
NUMERICAL_INPUT_HEADER = struct.calcsize('<Q')
NUMERICAL_INPUT_STRIDE = NUMERICAL_INPUT_HEADER + ctypes.sizeof(State) + 8
NUMERICAL_OUTPUT_STRIDE = struct.calcsize('<64Q4I')
NUMERICAL_GUARD_BYTES = 256
NUMERICAL_GUARD = bytes(range(256))
NUMERICAL_ADD_X7_ONE = 0x910004e7
NUMERICAL_ADD_X8_TWO = 0x91000908
NUMERICAL_SUBS_X10_ONE = 0xf100054a
NUMERICAL_CBNZ_X10_BACK_TWO = 0xb5ffffca
# SysV (state, block, MXCSR, result): install the requested caller environment,
# invoke the real block, capture its exit and MXCSR, then restore our caller.
NUMERICAL_MXCSR_WRAPPER = bytes.fromhex(
    '4883ec18 0fae1c24 89542404 48894c2408 0fae542404 0fae5914 '
    'ffd6 488b4c2408 488901 48895108 0fae5910 0fae1424 4883c418 c3')


class NumericalNativeExit(ctypes.Structure):
    _fields_ = [('next_pc', ctypes.c_uint64), ('kind', ctypes.c_uint64),
                ('mxcsr_after', ctypes.c_uint32), ('mxcsr_before', ctypes.c_uint32)]


def numerical_json(path, expected_sha256=None):
    path = Path(path)
    data = path.read_bytes()
    if expected_sha256 is not None and digest(data) != expected_sha256:
        raise AssertionError(f'Numerical evidence identity changed: {path}')
    return json.loads(data), digest(data)


def numerical_capture(path, expected_sha256):
    receipt, identity = numerical_json(path, expected_sha256)
    required = {'inputs.bin', 'results.bin', 'cases.json', 'guest.S', 'guest.elf', 'original.py'}
    if not required <= receipt['files'].keys():
        raise AssertionError('Numerical capture omits original source, states or output')
    for name, info in receipt['files'].items():
        if Path(name).name != name:
            raise AssertionError('Original capture filename is not one path component')
        data = (Path(path).parent / name).read_bytes()
        if digest(data) != info['sha256'] or len(data) != info['bytes']:
            raise AssertionError(f'Original capture changed: {name}')
    return receipt, identity


def numerical_expected_state(initial, result):
    if len(result) != NUMERICAL_OUTPUT_STRIDE:
        raise AssertionError('Truncated numerical original state')
    values = struct.unpack('<64Q4I', result)
    if values[-1] != 0x1234:
        raise AssertionError('Numerical original sentinel missing')
    expected = State.from_buffer_copy(initial)
    for register in range(32):
        expected.v[register][:] = values[register * 2:register * 2 + 2]
    expected.nzcv, expected.fpcr, expected.fpsr = values[64:67]
    return expected


def load_numerical_oracle(path):
    """Read historical producers as immutable data, without requiring their
    archived harness hashes to equal the current harness implementation.
    """
    foundation, foundation_hash = numerical_json(path)
    if foundation.get('kind') != 'numerical_fp_core_foundation_checkpoint' or foundation.get('passed') is not True:
        raise AssertionError('A passing numerical foundation receipt is required')
    records, functions, producers, executed_images = [], {}, {}, []
    pairs = (('original', 'core_comparison'), ('fresh_original', 'fresh_comparison'))
    for original_name, comparison_name in pairs:
        reference = foundation['evidence'][original_name]
        capture_path = ROOT / reference['path']
        producer, producer_hash = numerical_capture(capture_path, reference['sha256'])
        comparison_ref = foundation['evidence'][comparison_name]
        comparison, comparison_hash = numerical_json(ROOT / comparison_ref['path'], comparison_ref['sha256'])
        if comparison.get('passed') is not True or comparison['original_receipt_sha256'] != producer_hash:
            raise AssertionError('Numerical core comparison does not bind its original capture')
        for name, info in comparison['files'].items():
            data = (ROOT / comparison_ref['path']).parent.joinpath(name).read_bytes()
            if digest(data) != info['sha256'] or len(data) != info['bytes']:
                raise AssertionError(f'Numerical core evidence changed: {name}')
        directory = capture_path.parent
        executed_images.append((directory / 'guest.elf').read_bytes())
        cases = json.loads((directory / 'cases.json').read_bytes())
        inputs, results = (directory / 'inputs.bin').read_bytes(), (directory / 'results.bin').read_bytes()
        if len(inputs) != len(cases) * NUMERICAL_INPUT_STRIDE or len(results) != len(cases) * NUMERICAL_OUTPUT_STRIDE:
            raise AssertionError('Numerical corpus record count or state layout changed')
        producers[original_name] = {'path': str(capture_path.relative_to(ROOT)), 'sha256': producer_hash,
            'cases': len(cases), 'cpu': producer['cpu'], 'qemu_version': producer['qemu_version'],
            'historical_shared_sources_sha256': producer['shared_sources_sha256'],
            'core_comparison_sha256': comparison_hash, 'files': producer['files']}
        for index, case in enumerate(cases):
            record = inputs[index * NUMERICAL_INPUT_STRIDE:(index + 1) * NUMERICAL_INPUT_STRIDE]
            function = struct.unpack_from('<Q', record)[0]
            initial = State.from_buffer_copy(record[NUMERICAL_INPUT_HEADER:NUMERICAL_INPUT_HEADER + ctypes.sizeof(State)])
            if function != case['function'] or digest(bytes(initial)) != case['initial_state_sha256']:
                raise AssertionError('Original numerical metadata does not bind its state')
            # X30 belongs to the original QEMU transport. This sole derived input
            # mutation enables an actual guest RET in both native and Unicorn.
            initial.x[30] = STOP
            result = results[index * NUMERICAL_OUTPUT_STRIDE:(index + 1) * NUMERICAL_OUTPUT_STRIDE]
            expected = numerical_expected_state(initial, result)
            operation = {key: case[key] for key in ('name', 'lane', 'bytes', 'scalar', 'd', 'n', 'm', 'word')}
            if functions.setdefault(function, operation) != operation:
                raise AssertionError('Original numerical function changed between producers')
            unsupported = bool(initial.fpcr & NUMERICAL_TRAP_ENABLE_MASK)
            if not unsupported and expected.fpcr != initial.fpcr:
                raise AssertionError('Original FPCR readback differs outside classified trap controls')
            records.append({'producer': original_name, 'case': case['case'], 'parent_case': case.get('parent_case', case['case']),
                'label': case['label'], 'function': function, 'operation': operation,
                'initial': bytes(initial), 'expected': bytes(expected), 'unsupported': unsupported})
    if set(functions) != set(range(84)) or len(records) != foundation['original_core_result_status_comparisons']:
        raise AssertionError('Numerical foundation function/corpus counts changed')
    original_words = b''.join(struct.pack('<II', functions[index]['word'], RET) for index in range(84))
    if any(image.find(original_words) < 0 or image.count(original_words) != 1 for image in executed_images):
        raise AssertionError('Executed original images do not contain the exact unmodified FP/RET words')
    return {'records': records, 'functions': [functions[index] for index in range(84)],
            'foundation_sha256': foundation_hash, 'producers': producers,
            'input_derivation': 'Only X30 becomes the declared STOP address. Requested trap enables remain intact and test explicit refusal; their QEMU RAZ/WI outcomes receive no successful native equality credit.'}


def numerical_native_accounting(batch):
    decoded = decode_native_stream(batch['native'])
    operation = batch['functions'][0]['operations'][0]
    split = batch['instruction_offsets'][1]
    if split not in {instruction.address for instruction in decoded}:
        raise AssertionError('Numerical source map splits a native instruction')
    return {'shape': operation, 'native_bytes': len(batch['native']), 'native_instructions': len(decoded),
            'fp_body_bytes': split, 'fp_body_instructions': sum(instruction.address < split for instruction in decoded),
            'guest_ret_native_bytes': len(batch['native']) - split,
            'static_opcode_histogram': dict(sorted(Counter(native_mnemonic(i.mnemonic) for i in decoded).items())),
            'limits': 'Static counts include every generated branch path once, including helper side exits; no dynamic instruction, timing or application-performance claim.'}


def execute_scalar_numerical_batches(batches):
    oracle = load_numerical_oracle(batches[0]['oracle_path'])
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
    source = b''.join(batch['source'] for batch in batches)
    machine.mem_map(BASE, (len(source) + 4095) & ~4095)
    machine.mem_write(BASE, source)
    machine.mem_map(STOP, 4096)
    counts, corpus = Counter(), hashlib.sha256()
    examples, mxcsr_examples = {}, []
    with ExitStack() as mappings:
        addresses = [mappings.enter_context(executable(batch['native'])) for batch in batches]
        wrapper_address = mappings.enter_context(executable(NUMERICAL_MXCSR_WRAPPER))
        wrapper = ctypes.CFUNCTYPE(None, ctypes.POINTER(State), ctypes.c_void_p, ctypes.c_uint32,
                                 ctypes.POINTER(NumericalNativeExit))(wrapper_address)
        guard = ctypes.create_string_buffer(NUMERICAL_GUARD_BYTES * 2 + ctypes.sizeof(State))
        state_address = ctypes.addressof(guard) + NUMERICAL_GUARD_BYTES
        native_state = ctypes.cast(state_address, ctypes.POINTER(State))

        def invoke(record, mxcsr):
            ctypes.memmove(guard, NUMERICAL_GUARD + record['initial'] + NUMERICAL_GUARD, len(guard))
            observed = NumericalNativeExit()
            wrapper(native_state, addresses[record['function']], mxcsr, ctypes.byref(observed))
            if observed.mxcsr_before != mxcsr or observed.mxcsr_after != mxcsr:
                raise AssertionError(f'Native numerical path changed caller MXCSR: {record["operation"]}')
            if guard.raw[:NUMERICAL_GUARD_BYTES] != NUMERICAL_GUARD or guard.raw[-NUMERICAL_GUARD_BYTES:] != NUMERICAL_GUARD:
                raise AssertionError('Native numerical instruction changed surrounding RAM canaries')
            actual = ctypes.string_at(state_address, ctypes.sizeof(State))
            instruction_pc = BASE + record['function'] * 8
            if observed.kind == NUMERICAL_RETURN_EXIT:
                if record['unsupported'] or observed.next_pc != STOP or actual != record['expected']:
                    raise AssertionError(json.dumps({'operation': record['operation'], 'case': record['case'],
                        'exit': [observed.next_pc, observed.kind], 'actual': state_dict(State.from_buffer_copy(actual)),
                        'expected': state_dict(State.from_buffer_copy(record['expected']))}))
                return 'inline'
            if observed.kind != NUMERICAL_HELPER_EXIT or observed.next_pc != instruction_pc or actual != record['initial']:
                raise AssertionError(f'Numerical helper exit is imprecise or changed state: {record["operation"]}')
            return 'unsupported' if record['unsupported'] else 'helper'

        for record in oracle['records']:
            path = invoke(record, NUMERICAL_MXCSR_ALL_MASKS)
            counts[path] += 1
            corpus.update(record['initial']);corpus.update(struct.pack('<I', record['operation']['word']))
            shape = (record['operation']['name'], record['operation']['lane'], path)
            examples.setdefault(shape, record)
            initial = State.from_buffer_copy(record['initial'])
            if not record['unsupported'] and initial.fpcr & 7 == 0:
                initialize_arm(machine, initial)
                machine.emu_start(BASE + record['function'] * 8, STOP, count=3)
                original = capture_arm(machine, initial)
                if machine.reg_read(arm.UC_ARM64_REG_PC) != STOP or bytes(original) != record['expected']:
                    raise AssertionError(json.dumps({'ordinary_original_case': record['case'], 'operation': record['operation'],
                        'original': state_dict(original), 'expected': state_dict(State.from_buffer_copy(record['expected']))}))
                counts['unicorn_complete_state'] += 1
        for shape, record in sorted(examples.items()):
            for masks in (0, NUMERICAL_MXCSR_ALL_MASKS):
                for status in (0, NUMERICAL_MXCSR_ALL_STATUS):
                    for rounding in range(4):
                        requested = masks | status | (rounding << NUMERICAL_MXCSR_ROUND_SHIFT)
                        if invoke(record, requested) != shape[2]:
                            raise AssertionError('Caller MXCSR changed native numerical path choice')
                        counts['mxcsr_checks'] += 1
            mxcsr_examples.append({'name': shape[0], 'lane': shape[1], 'path': shape[2],
                                   'producer': record['producer'], 'case': record['case']})
    return {'raw_native_state_and_exit_comparisons': len(oracle['records']),
            'raw_inline_complete_state_comparisons': counts['inline'],
            'raw_helper_unchanged_state_comparisons': counts['helper'],
            'raw_unsupported_unchanged_state_comparisons': counts['unsupported'],
            'unicorn_original_complete_state_comparisons': counts['unicorn_complete_state'],
            'caller_mxcsr_preservation_comparisons': counts['mxcsr_checks'],
            'caller_mxcsr_examples': mxcsr_examples, 'state_corpus_sha256': corpus.hexdigest(),
            'state_bytes': ctypes.sizeof(State), 'ram_canary_bytes_per_case': NUMERICAL_GUARD_BYTES * 2,
            'limits': 'Raw helper exits verify unchanged full state and exact instruction PC only; Python never completes them. Actual Rust runtime completion is a separately reported cohort. QEMU GPR/SP transport is supplemented by complete-state Unicorn MAX checks only when AFP controls are zero.'}


def numerical_runtime_cases(records):
    selected = {}
    # One fresh case per operation/format/control, plus NEP aliases and typed
    # declines. Avoid repeating the full original corpus through subprocesses.
    for record in records:
        initial = State.from_buffer_copy(record['initial'])
        op = record['operation']
        if not record['unsupported'] and initial.fpsr == 0:
            selected.setdefault(('control', op['name'], op['lane'], initial.fpcr), record)
            if numerical_runtime_semantic_case(record, initial):
                selected.setdefault(('semantic', op['name'], op['lane'], record['label'], initial.fpcr), record)
        if not record['unsupported'] and initial.fpcr == NUMERICAL_NEP:
            selected.setdefault(('alias', record['function']), record)
        if record['unsupported']:
            selected.setdefault(('trap_control', initial.fpcr), record)
            if initial.fpcr == NUMERICAL_TRAP_ENABLE_MASK:
                selected.setdefault(('trap_form', op['name'], op['lane']), record)
    return list({(record['producer'], record['case']): record for record in selected.values()}.values())


def numerical_runtime_semantic_case(record, initial):
    """Exercise actual runtime arithmetic/status, beyond the first zero case
    retained for each control. All values come from the pinned original corpus.
    """
    label, control = record['label'], initial.fpcr
    ordinary = {'one_opposite_one', 'maximum_half', 'minimum_normal_half',
                'qnan_snan', 'denormal_zero_divisor', 'maximum_maximum', 'normal_boundary_midpoint'}
    if control == 0:
        return label in ordinary
    if control == NUMERICAL_AH:
        return label in {'qnan_snan', 'denormal_zero_divisor', 'normal_boundary_midpoint'}
    flush = NUMERICAL_FZ16 if record['operation']['lane'] == 2 else NUMERICAL_FZ
    if control == flush:
        return label in {'minimum_normal_half', 'denormal_zero_divisor'}
    return control == NUMERICAL_ROUND_NEGATIVE and label == 'maximum_maximum'


def numerical_report_state(value):
    state = State()
    if len(value['x']) != 31 or len(value['v']) != 32 or any(len(vector) != 2 for vector in value['v']):
        raise AssertionError('Runtime numerical state has an incomplete register bank')
    state.x[:] = value['x']
    for index, vector in enumerate(value['v']):
        state.v[index][:] = vector
    for name in ('sp', 'nzcv', 'reserved', 'fpcr', 'fpsr'):
        setattr(state, name, value[name])
    return state


def numerical_runtime_cohort(cli, directory, oracle, compiler):
    source = b''.join(struct.pack('<II', operation['word'], RET) for operation in oracle['functions'])
    source_path, state_path = directory / 'runtime.arm64', directory / 'runtime-state.json'
    source_path.write_bytes(source)
    ram_address, ram = 0x240000000000, NUMERICAL_GUARD * 16
    memory_path = directory / 'runtime-memory.json'
    memory_path.write_text(json.dumps({'regions': [{'guest_address': ram_address, 'virtual_bytes': len(ram),
        'initial_bytes': list(ram), 'readable': True, 'writable': True}]}))
    counts, transcripts = Counter(), []
    cache = directory / 'runtime-cache'
    original = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    original.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
    original.mem_map(BASE, 8192)
    original.mem_map(STOP, 4096)

    def invoke(code, base, entry, initial, budget=8, cache_dir=cache):
        code_path = source_path if code == source else directory / 'runtime-mixed.arm64'
        if code_path != source_path:
            code_path.write_bytes(code)
        state_path.write_text(json.dumps(state_dict(initial)))
        report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(code_path),
            '--guest-base', hex(base), '--entry', hex(entry), '--stop-pc', hex(STOP),
            '--cpu-target', 'baseline', '--state', str(state_path), '--block-budget', str(budget),
            '--cache-dir', str(cache_dir), '--memory', str(memory_path),
            '--read-memory', f'{hex(ram_address)}:{len(ram)}'], timeout=30))
        if (report['kind'] != 'native_block_run' or report['source_sha256'] != digest(code)
                or report['compiler_source_sha256'] != compiler or report['target_cpu'] != 'x86_64-baseline'):
            raise AssertionError('Runtime numerical report is not bound to this source/compiler/target')
        memory = report['memory']
        if memory['memory_before'] != memory['memory_after'] or memory['memory_reads'][0]['hex'] != ram.hex():
            raise AssertionError('Numerical runtime changed owned guest RAM')
        outcome = report['outcome']
        for name in ('compiled_blocks', 'disk_cache_hits', 'memory_cache_hits', 'floating_point_helpers'):
            if not isinstance(outcome[name], int) or outcome[name] < 0:
                raise AssertionError(f'Runtime numerical accounting missing {name}')
            counts[name] += outcome[name]
        transcripts.append({'entry': entry, 'budget': budget, 'initial_state_sha256': digest(bytes(initial)),
            'source_sha256': digest(code), 'synthetic_source_hex': code.hex() if code != source else None, 'report': report})
        counts['invocations'] += 1
        return report, numerical_report_state(report['state'])

    for record in numerical_runtime_cases(oracle['records']):
        initial = State.from_buffer_copy(record['initial'])
        entry = BASE + record['function'] * 8
        report, actual = invoke(source, BASE, entry, initial)
        reason = report['outcome']['reason']
        if record['unsupported']:
            expected = {'kind': 'floating_point_unsupported', 'instruction_pc': entry,
                        'fpcr': initial.fpcr, 'enabled_exceptions': (initial.fpcr >> NUMERICAL_EXCEPTION_ENABLE_SHIFT) & NUMERICAL_EXCEPTION_FLAGS}
            if reason != expected or report['pc'] != entry or bytes(actual) != record['initial']:
                raise AssertionError(json.dumps({'unsupported_case': record['case'], 'expected_reason': expected, 'report': report}))
            counts['typed_unsupported_state_checks'] += 1
        else:
            if (reason['kind'] != 'stop_address' or report['pc'] != STOP
                    or bytes(actual) != record['expected'] or report['outcome']['last_exit'] != [STOP, NUMERICAL_RETURN_EXIT]):
                raise AssertionError(json.dumps({'runtime_case': record['case'], 'producer': record['producer'],
                    'expected': state_dict(State.from_buffer_copy(record['expected'])), 'report': report}))
            counts['completed_state_checks'] += 1

    # Each shape has a genuine helper-only zero/zero case. Budget one must stop
    # after completing that operation, and resume at the real guest RET.
    resume_cases = {}
    for record in oracle['records']:
        initial = State.from_buffer_copy(record['initial'])
        if record['label'] == 'zero_pp' and initial.fpcr == 0 and initial.fpsr == 0:
            op = record['operation']
            resume_cases.setdefault((op['name'], op['lane']), record)
    if len(resume_cases) != 12:
        raise AssertionError('Numerical budget corpus omits an arithmetic form')
    for index, record in enumerate(resume_cases.values()):
        entry = BASE + record['function'] * 8
        initial = State.from_buffer_copy(record['initial'])
        resume_cache = directory / f'resume-cache-{index}'
        first, intermediate = invoke(source, BASE, entry, initial, budget=1, cache_dir=resume_cache)
        if (first['outcome']['reason']['kind'] != 'budget_exhausted' or first['pc'] != entry + 4
                or bytes(intermediate) != record['expected'] or first['outcome']['floating_point_helpers'] != 1):
            raise AssertionError('Numerical helper budget boundary lost or repeated an instruction')
        final, actual = invoke(source, BASE, first['pc'], intermediate, budget=1, cache_dir=resume_cache)
        if (final['outcome']['reason']['kind'] != 'stop_address' or final['pc'] != STOP
                or bytes(actual) != record['expected'] or final['outcome']['floating_point_helpers'] != 0):
            raise AssertionError('Numerical budget resume did not execute exactly the guest RET')
        warm, actual = invoke(source, BASE, entry, initial, cache_dir=resume_cache)
        if bytes(actual) != record['expected'] or warm['outcome']['disk_cache_hits'] < 2:
            raise AssertionError('Numerical warm runtime did not reuse both cached blocks')
        counts['budget_resume_checks'] += 1
        counts['disk_cache_resume_checks'] += 1

        # Interior helper PCs must retain already committed GPR work and resume
        # at the following instruction. ADD preserves NZCV and FP state.
        mixed = struct.pack('<4I', NUMERICAL_ADD_X7_ONE, record['operation']['word'], NUMERICAL_ADD_X8_TWO, RET)
        mixed_base = BASE + 0x1000 + index * 0x100
        expected = State.from_buffer_copy(record['expected'])
        expected.x[7] = (expected.x[7] + 1) & MASK
        expected.x[8] = (expected.x[8] + 2) & MASK
        completed, actual = invoke(mixed, mixed_base, mixed_base, initial)
        if (completed['pc'] != STOP or completed['outcome']['reason']['kind'] != 'stop_address'
                or bytes(actual) != bytes(expected) or completed['outcome']['floating_point_helpers'] != 1):
            raise AssertionError('Interior numerical helper lost prefix or suffix effects')
        original.mem_write(mixed_base, mixed)
        original.ctl_remove_cache(mixed_base, mixed_base + len(mixed))
        initialize_arm(original, initial)
        original.emu_start(mixed_base, STOP, count=8)
        if original.reg_read(arm.UC_ARM64_REG_PC) != STOP or bytes(capture_arm(original, initial)) != bytes(expected):
            raise AssertionError('Original interior fixture differs from complete runtime state')
        counts['synthetic_original_complete_state_checks'] += 1
        declined_initial = State.from_buffer_copy(initial)
        declined_initial.fpcr |= NUMERICAL_INVALID_ENABLE
        declined_expected = State.from_buffer_copy(declined_initial)
        declined_expected.x[7] = (declined_expected.x[7] + 1) & MASK
        declined, actual = invoke(mixed, mixed_base, mixed_base, declined_initial)
        declined_reason = {'kind': 'floating_point_unsupported', 'instruction_pc': mixed_base + 4,
                           'fpcr': declined_initial.fpcr, 'enabled_exceptions': 1}
        if (declined['pc'] != mixed_base + 4 or bytes(actual) != bytes(declined_expected)
                or declined['outcome']['reason'] != declined_reason):
            raise AssertionError('Interior numerical refusal changed state at the unsupported instruction')
        counts['interior_helper_state_checks'] += 1
        counts['interior_decline_state_checks'] += 1
        loop = struct.pack('<4I', record['operation']['word'], NUMERICAL_SUBS_X10_ONE,
                           NUMERICAL_CBNZ_X10_BACK_TWO, RET)
        loop_initial = State.from_buffer_copy(initial)
        loop_initial.x[10] = NUMERICAL_CACHE_LOOP_ITERATIONS
        loop_expected = State.from_buffer_copy(record['expected'])
        loop_expected.x[10], loop_expected.nzcv = 0, NUMERICAL_ZERO_CARRY_FLAGS
        loop_report, actual = invoke(loop, mixed_base, mixed_base, loop_initial, budget=16)
        if (loop_report['pc'] != STOP or bytes(actual) != bytes(loop_expected)
                or loop_report['outcome']['floating_point_helpers'] != NUMERICAL_CACHE_LOOP_ITERATIONS
                or loop_report['outcome']['memory_cache_hits'] < 2 * (NUMERICAL_CACHE_LOOP_ITERATIONS - 1)):
            raise AssertionError('Numerical loop did not preserve repeated helper/cache effects')
        original.mem_write(mixed_base, loop)
        original.ctl_remove_cache(mixed_base, mixed_base + len(loop))
        initialize_arm(original, loop_initial)
        original.emu_start(mixed_base, STOP, count=16)
        if original.reg_read(arm.UC_ARM64_REG_PC) != STOP or bytes(capture_arm(original, loop_initial)) != bytes(loop_expected):
            raise AssertionError('Original loop fixture differs from complete runtime state')
        counts['memory_cache_loop_checks'] += 1
        counts['synthetic_original_complete_state_checks'] += 1
    if counts['disk_cache_hits'] == 0:
        raise AssertionError('Numerical runtime evidence never exercised persistent cached code')
    snapshot = write_evidence(ROOT / '.stela/simd-scalar_numerical-runtime-records.json', transcripts)
    return {**dict(counts), 'ram_bytes_per_invocation': len(ram),
            'transcript': {'path': str(snapshot.relative_to(ROOT)), 'sha256': digest(snapshot.read_bytes())},
            'limits': 'Actual Rust BlockRuntime completes helpers and executes guest RET. Subprocesses exercise disk reuse; bounded three-iteration guest loops exercise live memory-cache reuse. Synthetic ADD/SUBS/CBNZ fixtures have separate complete-state original Unicorn checks. Original QEMU transports GPR/SP, while ordinary-control original Unicorn checks close that frame subset.'}


def run_scalar_numerical_cohort(cli, oracle_path):
    oracle = load_numerical_oracle(oracle_path)
    started = time.monotonic()
    cli_hash, harness_hash = digest(cli.read_bytes()), digest(Path(__file__).read_bytes())
    shared_paths = ('dev/differential.py', 'dev/evidence.py', 'dev/memory-faults.py', 'dev/native-memory-faults.c',
                    'dev/test_simd_differential.py', 'crates/stela-runtime/src/floating.rs',
                    'crates/stela-runtime/src/blocks.rs', 'crates/stela-runtime/src/lib.rs',
                    'crates/stela-runtime/src/execution.rs')
    shared_hashes = {name: digest((ROOT / name).read_bytes()) for name in shared_paths}
    batches, artifacts, compiler, checked = [], [], None, []
    cpu_info = json.loads(subprocess.check_output([str(cli), 'cpu-info']))
    with tempfile.TemporaryDirectory(prefix='stela-scalar-numerical-') as temporary:
        directory = Path(temporary)
        for index, operation in enumerate(oracle['functions']):
            batch = compile_batch(cli, directory, [{'operations': [operation]}], index,
                block=True, guest_base=BASE + index * 8)
            batch.update(cohort=NUMERICAL_FOCUS, oracle_path=str(oracle_path))
            if compiler is not None and batch['compiler'] != compiler:
                raise AssertionError('Numerical compiler changed between block preparations')
            compiler = batch['compiler']
            accounting = numerical_native_accounting(batch)
            retained = retain_native_evidence('simd-scalar_numerical', batch['source'], batch['native'],
                batch['manifest'], accounting, Path(__file__).read_bytes())
            batches.append(batch)
            artifacts.append({'function': index, 'compilation': batch['receipt'], 'accounting': accounting, 'files': retained})
        optional = {opcode['mnemonic'] for opcode in cpu_info['simd_opcodes'] if opcode['minimum_target'] != 'x86_64-baseline'}
        if any(optional & artifact['accounting']['static_opcode_histogram'].keys() for artifact in artifacts):
            raise AssertionError('Baseline numerical output contains an optional host opcode')
        if cpu_info['detected_target'] != 'x86_64-baseline':
            for index in (7, 56, 63):  # FADD S, FMUL D, FDIV H, original register roles.
                probe = compile_batch(cli, directory, [{'operations': [oracle['functions'][index]]}], 1000 + index,
                    block=True, cpu_target='native', target_id=cpu_info['detected_target'], guest_base=BASE + index * 8)
                if probe['compiler'] != compiler or probe['native'] != batches[index]['native']:
                    raise AssertionError('Checked host numerical recipe differs from the baseline policy')
                checked.append({'function': index, 'target_cpu': cpu_info['detected_target'],
                                'native_sha256': digest(probe['native']), 'baseline_bytes_identical': True})
        raw = bounded_cases(batches)
        runtime = numerical_runtime_cohort(cli, directory, oracle, compiler)
    if digest(cli.read_bytes()) != cli_hash or digest(Path(__file__).read_bytes()) != harness_hash:
        raise AssertionError('Numerical executable or harness changed during verification')
    if any(digest((ROOT / name).read_bytes()) != identity for name, identity in shared_hashes.items()):
        raise AssertionError('Numerical shared runner changed during verification')
    typed_checks = runtime['typed_unsupported_state_checks'] + runtime['interior_decline_state_checks']
    completed_checks = runtime['invocations'] - typed_checks
    report = {'kind': 'simd_scalar_numerical_arm_vs_native_x86', 'passed': True,
        'abi': batches[0]['manifest']['abi'], 'state_comparisons': completed_checks,
        'runtime_complete_state_comparisons': completed_checks,
        'runtime_typed_unsupported_state_checks': typed_checks,
        'runtime_budget_resume_checks': runtime['budget_resume_checks'],
        'runtime_memory_cache_loop_checks': runtime['memory_cache_loop_checks'],
        'runtime_disk_cache_resume_checks': runtime['disk_cache_resume_checks'],
        'raw_native_state_and_exit_comparisons': raw['raw_native_state_and_exit_comparisons'],
        'native_mxcsr_preservation_comparisons': raw['caller_mxcsr_preservation_comparisons'],
        'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_hash,
        'harness_source_sha256': harness_hash, 'shared_sources_sha256': shared_hashes,
        'foundation_receipt_sha256': oracle['foundation_sha256'], 'original_producers': oracle['producers'],
        'input_derivation': oracle['input_derivation'], 'raw_native': raw, 'rust_runtime': runtime,
        'native_artifacts': artifacts, 'checked_host_emission_identity': checked,
        'caller_mxcsr_wrapper_sha256': digest(NUMERICAL_MXCSR_WRAPPER),
        'verification_wall_seconds': time.monotonic() - started,
        'limits': 'Numerical scalar block-ABI verification only. Historical QEMU/core provenance remains distinct from current native/runtime provenance. Requested trap controls decline; no trap delivery, Apple hardware, complete application, OS or performance claim.'}
    write_evidence(ROOT / '.stela/simd-scalar_numerical-differential-report.json', report)
    print(json.dumps(report, indent=2))


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
            decoded=decode_native_stream(batch['native'])
            accounting=native_binary_accounting(batch,decoded)
            retained=retain_native_binary_evidence(batch,accounting,result['dynamic_x86_trace'])
            mnemonics=Counter(native_mnemonic(i.mnemonic) for i in decoded)
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
            elif focus=='indexed_products':
                if '+sse4.1' in target_id: expected.update(('pmulld','pmuldq','pmovsxwd','pmovzxwd'))
            elif focus=='products':
                if '+sse4.1' in target_id: expected.update(('pmulld','pmuldq'))
                if '+sse4.2' in target_id: expected.add('pcmpgtq')
            elif focus=='doubling_products':
                if '+ssse3' in target_id: expected.add('pmulhrsw')
                if '+sse4.1' in target_id: expected.update(('pmuldq','pmulld'))
                if '+pclmulqdq' in target_id: expected.add('pclmulqdq')
            elif focus=='narrowing_shifts':
                if '+sse4.1' in target_id: expected.add('packusdw')
                if '+sse4.2' in target_id: expected.add('pcmpgtq')
            elif focus=='dot_round_products':
                if '+sse4.1' in target_id: expected.add('pmuldq')
            elif focus=='floating_bits' and '+sse4.2' in target_id: expected.add('pcmpgtq')
            elif focus=='halving':
                if '+ssse3' in target_id: expected.add('pmaddubsw')
                if '+sse4.1' in target_id: expected.update(('pmovsxdq','pmovzxdq'))
            assert set(used)==expected,(target_id,used,expected)
            profiles[selection]={**result,'compilation':batch['receipt'],'optional_opcodes_used':used,
                'native_binary_accounting':accounting,'retained_native_evidence':retained,
                'packed_shifts_used':sorted({o['mnemonic'] for o in info['simd_immediate_shifts']} & mnemonics.keys())}
    assert digest(cli.read_bytes())==cli_hash and digest(Path(__file__).read_bytes())==harness_hash
    baseline=profiles['baseline']
    report={'kind':f'simd_{focus}_arm_vs_native_x86','passed':True,
        'three_way_register_state_comparisons':baseline['three_way_register_state_comparisons'],
        'state_corpus_sha256':baseline['state_corpus_sha256'],'programs':len(functions),
        'compiler_source_sha256':batch['compiler'],'compiler_executable_sha256':cli_hash,
        'harness_source_sha256':harness_hash,'shared_runner_sha256':digest((ROOT/'dev/differential.py').read_bytes()),
        'shared_sources_sha256':{name:digest((ROOT/name).read_bytes())
            for name in ('dev/differential.py','dev/evidence.py')},
        'corpus_sha256':digest(batch['source']),'compilation':baseline['compilation'],'cpu_profiles':profiles,
        'original_cpu_model':('QEMU10 max with AFP/FP16 plus classified Unicorn MAX baseline' if focus=='floating_bits' else 'MAX (FP16 enabled)' if focus=='immediates' else 'MAX (DotProd and RDM enabled)' if focus=='dot_round_products' else 'default'),
        'total_profile_comparisons':sum(p['three_way_register_state_comparisons'] for p in profiles.values()),
        'verification_wall_seconds':time.monotonic()-started,
        'limits':f'Focused {focus} SIMD semantics with FP/AdvSIMD enabled; no FP arithmetic, traps, disabled-feature behavior or application-performance claim. Leaf RET is harness-owned.'}
    if focus in ('narrowing_shifts','dot_round_products'):
        report['architectural_state_bytes']=ctypes.sizeof(State)
        report['original_oracle_limits']=(
            'Original A64 words execute unmodified under Unicorn with FP/AdvSIMD enabled. '
            'The selected CPU model enables DotProd/RDM where needed. All 784 architectural '
            'state bytes, including NZCV, FPCR, FPSR and every vector lane, compare against '
            'independent unbounded-integer math and actual emitted x86 execution. '
            'This is emulator conformance evidence; unavailable features, disabled FP access, '
            'FP traps and hardware-specific exception delivery remain outside this cohort.')
    write_evidence(ROOT/f'.stela/simd-{focus}-differential-report.json',report)
    print(json.dumps(report,indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--focus', choices=[*REGISTER_COHORTS, NUMERICAL_FOCUS], help='Only the focused SIMD implementation cohort')
    parser.add_argument('--numerical-oracle', type=Path, default=NUMERICAL_FOUNDATION,
                        help='Pinned numerical foundation receipt for scalar_numerical')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    if arguments.focus == NUMERICAL_FOCUS:
        run_scalar_numerical_cohort(cli, arguments.numerical_oracle)
        return
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
