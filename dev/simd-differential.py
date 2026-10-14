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
    consumed = manifest['source_bytes'] if block else manifest['guest_instructions'] * 4
    if (not isinstance(consumed, int) or not 0 < consumed <= len(source) or consumed % 4
            or (not block and consumed != len(source))):
        raise AssertionError('SIMD manifest has an invalid consumed source prefix')
    compiled_source = source[:consumed]
    if (manifest['schema_version'] != 1 or manifest['abi'] != (BLOCK_ABI if block else LEAF_ABI)
            or manifest['guest_base'] != guest_base or manifest['source_sha256'] != digest(compiled_source)
            or manifest['native_sha256'] != digest(native) or manifest['native_bytes'] != len(native)
            or manifest['verified'] is not False):
        raise AssertionError('SIMD manifest does not bind original/native bytes and ABI')
    mapping = manifest['source_map']
    if ([row[0] for row in mapping] != list(range(guest_base, guest_base + consumed, 4))
            or any(not 0 <= row[1] < len(native) for row in mapping)
            or any(a[1] >= b[1] for a, b in zip(mapping, mapping[1:]))):
        raise AssertionError('SIMD source map omits or merges original instructions')
    return [row[1] for row in mapping]


def compile_batch(cli, directory, functions, index, block=False, cpu_target="baseline", target_id="x86_64-baseline", guest_base=BASE):
    if block and len(functions) != 1:
        raise ValueError('A block compilation batch must have exactly one entry')
    words, entries = [], []
    for function in functions:
        entries.append(len(words))
        words.extend(operation['word'] for operation in function['operations'])
        words.append(numerical_return_word(function['operations'][0]) if len(function['operations']) == 1 else RET)
    source = struct.pack('<' + 'I' * len(words), *words)
    disassembly = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(source, BASE))
    if len(disassembly) != len(words) or any(i.mnemonic not in {'ldr', 'str', 'ldur', 'stur', 'ldp', 'stp', 'movi', 'ret', 'and', 'bic', 'orr', 'orn', 'eor', 'bsl', 'bit', 'bif', 'add', 'sub', 'abs', 'neg', 'mov', 'cmeq', 'cmgt', 'cmge', 'cmhi', 'cmhs', 'cmlt', 'cmle', 'cmtst', 'dup', 'ins', 'smov', 'umov', 'ext', 'rev16', 'rev32', 'rev64', 'zip1', 'zip2', 'uzp1', 'uzp2', 'trn1', 'trn2', 'tbl', 'tbx', 'shl', 'sshr', 'ushr', 'srshr', 'urshr', 'ssra', 'usra', 'srsra', 'ursra', 'sli', 'sri', 'shrn', 'shrn2', 'rshrn', 'rshrn2', 'sshll', 'sshll2', 'ushll', 'ushll2', 'sxtl', 'sxtl2', 'uxtl', 'uxtl2', 'smin', 'smax', 'umin', 'umax', 'sminp', 'smaxp', 'uminp', 'umaxp', 'sminv', 'smaxv', 'uminv', 'umaxv', 'addv', 'addp', 'saddlv', 'uaddlv', 'cnt', 'clz', 'cls', 'rbit', 'mvn', 'not', 'sqadd', 'uqadd', 'sqsub', 'uqsub', 'sqabs', 'sqneg', 'suqadd', 'usqadd', 'sqxtn', 'sqxtn2', 'uqxtn', 'uqxtn2', 'sqxtun', 'sqxtun2', 'mul', 'mla', 'mls', 'smull', 'smull2', 'umull', 'umull2', 'smlal', 'smlal2', 'umlal', 'umlal2', 'smlsl', 'smlsl2', 'umlsl', 'umlsl2', 'saddl', 'saddl2', 'uaddl', 'uaddl2', 'ssubl', 'ssubl2', 'usubl', 'usubl2', 'saddw', 'saddw2', 'uaddw', 'uaddw2', 'ssubw', 'ssubw2', 'usubw', 'usubw2', 'sabd', 'uabd', 'saba', 'uaba', 'sabdl', 'sabdl2', 'uabdl', 'uabdl2', 'sabal', 'sabal2', 'uabal', 'uabal2', 'shadd', 'uhadd', 'srhadd', 'urhadd', 'shsub', 'uhsub', 'addhn', 'addhn2', 'raddhn', 'raddhn2', 'subhn', 'subhn2', 'rsubhn', 'rsubhn2', 'saddlp', 'uaddlp', 'sadalp', 'uadalp', 'xtn', 'xtn2', 'shll', 'shll2', 'mvni', 'fmov', 'pmul', 'pmull', 'pmull2', 'sqdmulh', 'sqrdmulh', 'sqdmull', 'sqdmull2', 'sqdmlal', 'sqdmlal2', 'sqdmlsl', 'sqdmlsl2', 'sshl', 'ushl', 'srshl', 'urshl', 'sqshl', 'uqshl', 'sqrshl', 'uqrshl', 'sqshlu', 'fcsel', 'fabs', 'fneg', 'sqshrn', 'sqshrn2', 'sqrshrn', 'sqrshrn2', 'uqshrn', 'uqshrn2', 'uqrshrn', 'uqrshrn2', 'sqshrun', 'sqshrun2', 'sqrshrun', 'sqrshrun2', 'sdot', 'udot', 'sqrdmlah', 'sqrdmlsh', 'fadd', 'fsub', 'fmul', 'fdiv', 'mrs', 'msr', 'fmadd', 'fmsub', 'fnmadd', 'fnmsub', 'fmla', 'fmls', 'fcvt', 'fcvtl', 'fcvtl2', 'fcvtn', 'fcvtn2', 'fcvtxn', 'fcvtxn2', 'fcvtns', 'fcvtnu', 'fcvtps', 'fcvtpu', 'fcvtms', 'fcvtmu', 'fcvtzs', 'fcvtzu', 'fcvtas', 'fcvtau', 'scvtf', 'ucvtf', 'fjcvtzs', 'fcmp', 'fcmpe', 'fccmp', 'fccmpe', 'facge', 'facgt', 'fcmeq', 'fcmge', 'fcmgt', 'fcmle', 'fcmlt', 'fmax', 'fmin', 'fmaxnm', 'fminnm', 'fmaxp', 'fminp', 'fmaxnmp', 'fminnmp', 'fmaxv', 'fminv', 'fmaxnmv', 'fminnmv', 'frintn', 'frintp', 'frintm', 'frintz', 'frinta', 'frintx', 'frinti', 'frint32z', 'frint32x', 'frint64z', 'frint64x', 'fsqrt', 'frecpe', 'frsqrte', 'frecpx', 'urecpe', 'ursqrte', 'frecps', 'frsqrts', 'fnmul', 'fabd', 'faddp', 'fmulx'} for i in disassembly):
        raise AssertionError('Independent decoder declined SIMD fixture')
    path = directory / f'program-{index}.arm64'
    path.write_bytes(source)
    output = directory / f'native-{index}'
    manifest = json.loads(subprocess.check_output([str(cli), 'compile-block' if block else 'compile-leaf', str(path), '--guest-base', hex(guest_base), '--output-dir', str(output), '--cpu-target', cpu_target], timeout=60))
    native = (output / 'native.bin').read_bytes()
    offsets = validate_manifest(manifest, source, native, block, target_id, guest_base)
    consumed = manifest['source_bytes'] if block else len(source)
    compiled_source = source[:consumed]
    if not block:
        for entry, function in zip(entries, functions):
            if native[offsets[entry + len(function['operations'])]] != 0xc3:
                raise AssertionError('Independent mini-function has no exact host RET boundary')
    return {'functions': functions, 'source': source, 'compiled_source': compiled_source, 'native': native, 'entries': entries,
            'offsets': [offsets[entry] for entry in entries], 'block': block,
            'compiler': manifest['compiler_source_sha256'],'manifest':manifest,'instruction_offsets':offsets,
            'receipt': {'functions': len(functions), 'source_bytes': consumed, 'source_sha256': digest(compiled_source),
                        'input_source_bytes': len(source), 'input_source_sha256': digest(source),
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
            result = execute_numerical_batches(batches)
        elif batches[0].get('cohort') == 'fp_registers':
            result = execute_fp_register_batches(batches)
        elif batches[0].get('cohort') in FULL_FRAME_NUMERICAL_COHORTS:
            family = FULL_FRAME_NUMERICAL_COHORTS[batches[0]['cohort']]
            result = execute_numerical_batches(batches, family['loader'](batches[0]['oracle_path']))
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



FP_REGISTER_FOCUS = 'fp_registers'
FP_REGISTER_REVIEW = ROOT / '.stela/research/fp-registers/review.json'
FP_REGISTER_MASKS = {'fpcr': 0x07c89f07, 'fpsr': 0x0800009f}
FP_REGISTER_WORDS = {'mrs_fpcr': 0xd53b4400, 'msr_fpcr': 0xd51b4400,
                     'mrs_fpsr': 0xd53b4420, 'msr_fpsr': 0xd51b4420}
FP_REGISTER_WORD_MASK = 0xffffffe0
FP_REGISTER_QEMU_MASKS = {'fpcr': 0x07ff2007, 'fpsr': 0xf800009f}
FP_REGISTER_SEED = {'fpcr': 0x07c80007, 'fpsr': 0x0800009f}
FP_REGISTER_ORIGINAL_FLAGS = 0xa0000000
FP_REGISTER_ORIGINAL_SP = 0x48010000
FP_REGISTER_RECORD_BYTES = 1024
FP_REGISTER_SVC = 0xd4002461
FP_REGISTER_EC_SVC = 0x15
FP_REGISTER_EC_ACCESS = 7
FP_REGISTER_POLICY_FIELDS = {'trap_enables': ('fpcr', 0x9f00),
                             'ebf': ('fpcr', 1 << 13),
                             'len_stride': ('fpcr', 0x00370000),
                             'aarch32_nzcv': ('fpsr', 0xf0000000)}


def fp_register_operation(name, rt):
    if name not in FP_REGISTER_WORDS or not 0 <= rt < 32:
        raise ValueError('Invalid FP register operand')
    return {'kind': FP_REGISTER_FOCUS, 'name': name, 'rt': rt,
            'word': FP_REGISTER_WORDS[name] | rt}


def fp_register_functions():
    return [{'operations': [fp_register_operation(name, rt)]}
            for name in FP_REGISTER_WORDS for rt in range(32)]


def fp_register_expected(operation, initial, masks=FP_REGISTER_MASKS):
    result = State.from_buffer_copy(initial)
    name, rt = operation['name'], operation['rt']
    register = name.split('_')[1]
    if name.startswith('mrs'):
        if rt != 31:
            result.x[rt] = getattr(result, register) & masks[register]
    else:
        setattr(result, register, (0 if rt == 31 else result.x[rt]) & masks[register])
    return result


def fp_register_original_state(case, record=None):
    state = State()
    state.x[:] = case['initial_x']
    state.sp, state.nzcv = FP_REGISTER_ORIGINAL_SP, FP_REGISTER_ORIGINAL_FLAGS
    state.fpcr, state.fpsr = FP_REGISTER_SEED['fpcr'], FP_REGISTER_SEED['fpsr']
    for register in range(32):
        state.v[register][:] = [int.from_bytes(bytes([register + 1]) * 8, 'little')] * 2
    if record is not None:
        if len(record) != FP_REGISTER_RECORD_BYTES:
            raise AssertionError('Truncated original FP register snapshot')
        state.x[:] = struct.unpack_from('<31Q', record)
        sp, spsr, fpcr, fpsr = struct.unpack_from('<4Q', record, 248)
        state.sp, state.nzcv, state.fpcr, state.fpsr = sp, spsr & 0xf0000000, fpcr, fpsr
        vectors = struct.unpack_from('<64Q', record, 320)
        for register in range(32):
            state.v[register][:] = vectors[register * 2:register * 2 + 2]
    return state


def fp_register_elf_word(elf, address):
    if elf[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', elf, 18)[0] != 183:
        raise AssertionError('FP register original is not ELF64 little-endian AArch64')
    offset = struct.unpack_from('<Q', elf, 32)[0]
    size, count = struct.unpack_from('<HH', elf, 54)
    for index in range(count):
        segment = struct.unpack_from('<IIQQQQQQ', elf, offset + index * size)
        if segment[0] == 1 and segment[3] <= address <= segment[3] + segment[5] - 4:
            return struct.unpack_from('<I', elf, segment[2] + address - segment[3])[0]
    raise AssertionError('Original FP register subject PC is outside ELF file bytes')


def load_fp_register_oracle(path=FP_REGISTER_REVIEW):
    review, review_hash = numerical_json(path)
    selected = review['selected_software_profile']
    if any(int(selected[f'{name}_mask'], 16) != mask for name, mask in FP_REGISTER_MASKS.items()):
        raise AssertionError('FP register policy differs from declared independent masks')
    reference = review['original_el0_oracle']['receipt']
    receipt_path = ROOT / reference['path']
    receipt, receipt_hash = numerical_json(receipt_path, reference['sha256'])
    if receipt.get('passed') is not True or receipt['cases'] != 314:
        raise AssertionError('Passing complete original FP register capture required')
    for name, identity in receipt['files'].items():
        if Path(name).name != name:
            raise AssertionError('Original FP register file is not one path component')
        data = (receipt_path.parent / name).read_bytes()
        if digest(data) != identity['sha256'] or len(data) != identity['bytes']:
            raise AssertionError(f'Original FP register file changed: {name}')
    validation_ref = review['original_el0_oracle']['byte_and_exception_pc_validation']
    validation, validation_hash = numerical_json(ROOT / validation_ref['path'], validation_ref['sha256'])
    if validation.get('passed') is not True or validation['oracle_receipt']['sha256'] != receipt_hash:
        raise AssertionError('Original FP register byte/exception validation is unbound')
    directory = receipt_path.parent
    cases = json.loads((directory / 'cases.json').read_bytes())
    results, elf = (directory / 'results.bin').read_bytes(), (directory / 'guest.elf').read_bytes()
    if len(cases) != 314 or len(results) != (len(cases) + 1) * FP_REGISTER_RECORD_BYTES or len(validation['proofs']) != len(cases):
        raise AssertionError('Original FP register case/snapshot/proof counts differ')
    records, classifications, access_traps, undefined = [], [], [], []
    functions = {(function['operations'][0]['name'], function['operations'][0]['rt']): index
                 for index, function in enumerate(fp_register_functions())}
    for index, (case, proof, observation) in enumerate(zip(cases, validation['proofs'], receipt['observations'])):
        record = results[(index + 1) * FP_REGISTER_RECORD_BYTES:(index + 2) * FP_REGISTER_RECORD_BYTES]
        initial, original = fp_register_original_state(case), fp_register_original_state(case, record)
        esr, elr, current_el, cpacr, marker = struct.unpack_from('<5Q', record, 280)
        pc = int(proof['subject_pc'], 16)
        expected_ec = 0 if case['name'].endswith('fpmr') else FP_REGISTER_EC_ACCESS if case['fpen'] != 3 else FP_REGISTER_EC_SVC
        if (proof['case'] != index or observation['case'] != index or esr >> 26 != expected_ec
                or proof['exception_class'] != expected_ec or int(proof['verified_elr'], 16) != elr
                or elr != pc + (8 if expected_ec == FP_REGISTER_EC_SVC else 0)
                or fp_register_elf_word(elf, pc) != case['word']
                or fp_register_elf_word(elf, pc + 4) != FP_REGISTER_SVC
                or current_el != 4 or cpacr != case['fpen'] << 20 or marker != 0x1234):
            raise AssertionError(f'Original FP register instruction/exception evidence changed: {index}')
        if expected_ec != FP_REGISTER_EC_SVC:
            if bytes(original) != bytes(initial):
                raise AssertionError('Original disabled/undefined FP access changed state')
            (undefined if expected_ec == 0 else access_traps).append({'case': index, 'word': case['word'],
                'fpen': case['fpen'], 'subject_pc': pc, 'exception_pc': elr, 'esr': esr})
            continue
        operation = fp_register_operation(case['name'], case['rt'])
        if operation['word'] != case['word'] or bytes(original) != bytes(fp_register_expected(operation, initial, FP_REGISTER_QEMU_MASKS)):
            raise AssertionError(f'Original FP register full state disagrees with its declared observed policy: {index}')
        expected = fp_register_expected(operation, initial)
        fields = []
        if bytes(expected) != bytes(original):
            if (list(expected.x) != list(original.x)
                    or (expected.fpcr ^ original.fpcr) & ~(FP_REGISTER_MASKS['fpcr'] ^ FP_REGISTER_QEMU_MASKS['fpcr'])
                    or (expected.fpsr ^ original.fpsr) & ~(FP_REGISTER_MASKS['fpsr'] ^ FP_REGISTER_QEMU_MASKS['fpsr'])):
                raise AssertionError('Original FP register differs outside declared policy fields')
            for field, (register, mask) in FP_REGISTER_POLICY_FIELDS.items():
                if (getattr(expected, register) ^ getattr(original, register)) & mask:
                    fields.append(field)
            if not fields:
                raise AssertionError('Unclassified original FP register policy mismatch')
            classifications.append({'case': index, 'fields': fields, 'requested': case['value'],
                'original_fpcr': original.fpcr, 'native_policy_fpcr': expected.fpcr,
                'original_fpsr': original.fpsr, 'native_policy_fpsr': expected.fpsr})
        records.append({'function': functions[(case['name'], case['rt'])], 'initial': bytes(initial),
            'expected': bytes(expected), 'original': bytes(original), 'case': index, 'fields': fields})
    if len(records) != 274 or len(access_traps) != 36 or len(undefined) != 4:
        raise AssertionError('Original FP register success/trap classification changed')
    return {'records': records, 'classifications': classifications, 'disabled_fp_access_traps': access_traps,
            'undefined_fpmr_traps': undefined, 'review_sha256': review_hash,
            'receipt': {'path': str(receipt_path.relative_to(ROOT)), 'sha256': receipt_hash,
                        'files': receipt['files'], 'historical_harness_sha256': receipt['harness_sha256'],
                        'cpu': receipt['cpu'], 'qemu_version': receipt['qemu_version']},
            'validation_sha256': validation_hash}


def fp_register_policy_cases():
    records = []
    variants = ((0, 0, 0), (MASK, 0xffffffff, 0xffffffff),
                (0xfedcba9800000000, ~FP_REGISTER_MASKS['fpcr'] & 0xffffffff,
                 ~FP_REGISTER_MASKS['fpsr'] & 0xffffffff),
                (0x1234567807c89f07, 0x9f00, 0x0800009f))
    for index, function in enumerate(fp_register_functions()):
        operation = function['operations'][0]
        for variant, (value, fpcr, fpsr) in enumerate(variants):
            initial = State.from_buffer_copy(states()[0])
            seed_extended_state(initial, index * len(variants) + variant)
            initial.fpcr, initial.fpsr, initial.nzcv = fpcr, fpsr, ((index + variant) % 16) << 28
            if operation['rt'] != 31:
                initial.x[operation['rt']] = value
            records.append({'function': index, 'initial': bytes(initial),
                'expected': bytes(fp_register_expected(operation, initial)), 'variant': variant})
    for register in ('fpcr', 'fpsr'):
        operation = fp_register_operation('msr_' + register, 0)
        index = list(FP_REGISTER_WORDS).index(operation['name']) * 32
        for bit in range(64):
            initial = State.from_buffer_copy(states()[0])
            seed_extended_state(initial, bit)
            initial.fpcr, initial.fpsr, initial.x[0] = 0xffffffff, 0xffffffff, 1 << bit
            records.append({'function': index, 'initial': bytes(initial),
                'expected': bytes(fp_register_expected(operation, initial)), 'bit': bit})
    return records


def execute_fp_register_batches(batches):
    batch = batches[0]
    oracle = load_fp_register_oracle()
    records = oracle['records'] + fp_register_policy_cases()
    counts, corpus = Counter(), hashlib.sha256()
    with executable(batch['native']) as address, executable(NUMERICAL_MXCSR_WRAPPER) as wrapper_address:
        wrapper = ctypes.CFUNCTYPE(None, ctypes.POINTER(State), ctypes.c_void_p, ctypes.c_uint32,
                                 ctypes.POINTER(NumericalNativeExit))(wrapper_address)
        guard = ctypes.create_string_buffer(NUMERICAL_GUARD_BYTES * 2 + ctypes.sizeof(State))
        state_address = ctypes.addressof(guard) + NUMERICAL_GUARD_BYTES
        native_state = ctypes.cast(state_address, ctypes.POINTER(State))

        def invoke(record, mxcsr):
            ctypes.memmove(guard, NUMERICAL_GUARD + record['initial'] + NUMERICAL_GUARD, len(guard))
            observed = NumericalNativeExit()
            wrapper(native_state, address + batch['offsets'][record['function']], mxcsr, ctypes.byref(observed))
            actual = ctypes.string_at(state_address, ctypes.sizeof(State))
            if (actual != record['expected'] or observed.mxcsr_before != mxcsr or observed.mxcsr_after != mxcsr
                    or guard.raw[:NUMERICAL_GUARD_BYTES] != NUMERICAL_GUARD
                    or guard.raw[-NUMERICAL_GUARD_BYTES:] != NUMERICAL_GUARD):
                failure = {'kind': 'fp_register_native_failure', 'record': {key: value.hex() if isinstance(value, bytes) else value
                    for key, value in record.items()}, 'actual': actual.hex(), 'requested_mxcsr': mxcsr,
                    'observed_mxcsr': [observed.mxcsr_before, observed.mxcsr_after]}
                write_evidence(ROOT / '.stela/simd-fp_registers-failure.json', failure)
                raise AssertionError('FP register native state/MXCSR/canary mismatch; immutable failure retained')

        for record in records:
            invoke(record, NUMERICAL_MXCSR_ALL_MASKS)
            corpus.update(record['initial']); corpus.update(struct.pack('<I', record['function']))
            counts['complete_state'] += 1
            if 'original' in record:
                counts['classified_policy' if record['fields'] else 'direct_original'] += 1
        examples = {record['function']: record for record in records}
        for record in examples.values():
            for masks in (0, NUMERICAL_MXCSR_ALL_MASKS):
                for status in (0, NUMERICAL_MXCSR_ALL_STATUS):
                    for rounding in range(4):
                        invoke(record, masks | status | (rounding << NUMERICAL_MXCSR_ROUND_SHIFT))
                        counts['mxcsr_checks'] += 1
    return {'complete_state_comparisons': counts['complete_state'],
            'direct_original_complete_state_comparisons': counts['direct_original'],
            'classified_original_policy_comparisons': counts['classified_policy'],
            'caller_mxcsr_preservation_comparisons': counts['mxcsr_checks'],
            'state_corpus_sha256': corpus.hexdigest(), 'state_bytes': ctypes.sizeof(State),
            'ram_canary_bytes_per_case': NUMERICAL_GUARD_BYTES * 2}


NUMERICAL_FOCUS = 'scalar_numerical'
NUMERICAL_FOUNDATION = ROOT / '.stela/research/numerical-fp/receipt.json'
NUMERICAL_RETURN_EXIT = 4
NUMERICAL_HELPER_EXIT = 9
NUMERICAL_EXCEPTION_FLAGS = 0x9f
NUMERICAL_EXCEPTION_ENABLE_SHIFT = 8
NUMERICAL_TRAP_ENABLE_MASK = NUMERICAL_EXCEPTION_FLAGS << NUMERICAL_EXCEPTION_ENABLE_SHIFT
NUMERICAL_NEP = 1 << 2
NUMERICAL_AH = 1 << 1
NUMERICAL_FIZ = 1
NUMERICAL_DN = 1 << 25
NUMERICAL_FZ16 = 1 << 19
NUMERICAL_FZ = 1 << 24
NUMERICAL_ROUND_NEGATIVE = 2 << 22
NUMERICAL_INVALID_ENABLE = 1 << NUMERICAL_EXCEPTION_ENABLE_SHIFT
NUMERICAL_MXCSR_ALL_MASKS = 0x1f80
NUMERICAL_MXCSR_ALL_STATUS = 0x3f
NUMERICAL_MXCSR_ROUND_SHIFT = 13
NUMERICAL_CACHE_LOOP_ITERATIONS = 3
NUMERICAL_ZERO_CARRY_FLAGS = 0x60000000
NUMERICAL_MANY_HALF_OPERATIONS = 8
NUMERICAL_HELPER_NATIVE_BYTES = 16
NUMERICAL_RETURN_NATIVE_BYTES = 13
NUMERICAL_MOV_X30_X11 = 0xaa0b03fe
NUMERICAL_BRANCH_IMMEDIATE_BASE = 0x14000000
NUMERICAL_BRANCH_IMMEDIATE_MASK = (1 << 26) - 1
NUMERICAL_UNSUPPORTED_WORD = 0xffffffff
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
    compiled = batch['compiled_source']
    mapped_ret = struct.unpack_from('<I', compiled, len(compiled) - 4)[0] == numerical_return_word(operation)
    split = batch['instruction_offsets'][-1] if mapped_ret else len(batch['native'])
    if split not in {instruction.address for instruction in decoded} | {len(batch['native'])}:
        raise AssertionError('Numerical source map splits a native instruction')
    return {'shape': operation, 'native_bytes': len(batch['native']), 'native_instructions': len(decoded),
            'input_source_bytes': len(batch['source']), 'input_source_sha256': digest(batch['source']),
            'compiled_source_bytes': len(compiled), 'compiled_source_sha256': digest(compiled),
            'fp_body_bytes': split, 'fp_body_instructions': sum(instruction.address < split for instruction in decoded),
            'guest_ret_native_bytes': len(batch['native']) - split,
            'static_opcode_histogram': dict(sorted(Counter(native_mnemonic(i.mnemonic) for i in decoded).items())),
            'limits': 'Static counts include every generated branch path once, including helper side exits; no dynamic instruction, timing or application-performance claim.'}


def execute_numerical_batches(batches, oracle=None):
    oracle = load_numerical_oracle(batches[0]['oracle_path']) if oracle is None else oracle
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
    source = b''.join(batch['source'] for batch in batches)
    machine.mem_map(BASE, (len(source) + 4095) & ~4095)
    machine.mem_write(BASE, source)
    machine.mem_map(STOP, 4096)
    counts, corpus = Counter(), hashlib.sha256()
    examples, mxcsr_examples, unicorn_divergences, helper_cases = {}, [], [], []
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
            if path == 'helper' and FULL_FRAME_NUMERICAL_COHORTS.get(batches[0].get('cohort'), {}).get('actual_helpers'):
                helper_cases.append(record['case'])
            if path == 'inline' and record.get('equality_basis') == 'standard_profile_model':
                counts['inline_profile_model'] += 1
            elif path == 'inline' and record.get('control_policy_success'):
                counts['inline_policy'] += 1
            corpus.update(record['initial']);corpus.update(struct.pack('<I', record['operation']['word']))
            shape = (record['operation']['name'], record['operation']['lane'], path, record['operation']['bytes'])
            examples.setdefault(shape, record)
            initial = State.from_buffer_copy(record['initial'])
            if not record['unsupported'] and not record.get('control_policy_success') and initial.fpcr & 7 == 0:
                initialize_arm(machine, initial)
                machine.emu_start(BASE + record['function'] * 8, STOP, count=3)
                original = capture_arm(machine, initial)
                if machine.reg_read(arm.UC_ARM64_REG_PC) != STOP:
                    raise AssertionError('Supplementary numerical original did not execute the guest RET')
                if bytes(original) != record['expected']:
                    expected = State.from_buffer_copy(record['expected'])
                    classification = conversion_unicorn_difference(record['operation'], initial, original, expected)
                    if classification is None:
                        raise AssertionError(json.dumps({'ordinary_original_case': record['case'], 'operation': record['operation'],
                            'original': state_dict(original), 'expected': state_dict(expected)}))
                    counts['unicorn_exact_control_divergences'] += 1
                    if len(unicorn_divergences) < 8:
                        unicorn_divergences.append({'case': record['case'], 'operation': record['operation'],
                            'classification': classification,
                            'initial_state_hex': record['initial'].hex(), 'unicorn_state_hex': bytes(original).hex(),
                            'primary_qemu_state_hex': record['expected'].hex()})
                else:
                    counts['unicorn_complete_state'] += 1
        for shape, record in sorted(examples.items()):
            for masks in (0, NUMERICAL_MXCSR_ALL_MASKS):
                for status in (0, NUMERICAL_MXCSR_ALL_STATUS):
                    for rounding in range(4):
                        requested = masks | status | (rounding << NUMERICAL_MXCSR_ROUND_SHIFT)
                        if invoke(record, requested) != shape[2]:
                            raise AssertionError('Caller MXCSR changed native numerical path choice')
                        counts['mxcsr_checks'] += 1
            mxcsr_examples.append({'name': shape[0], 'lane': shape[1], 'path': shape[2], 'bytes': shape[3],
                                   'producer': record['producer'], 'case': record['case']})
    return {'raw_native_state_and_exit_comparisons': len(oracle['records']),
            'raw_helper_case_ids': helper_cases,
            'raw_inline_complete_state_comparisons': counts['inline'],
            'raw_inline_original_complete_state_comparisons': counts['inline'] - counts['inline_policy'] - counts['inline_profile_model'],
            'raw_inline_profile_model_comparisons': counts['inline_profile_model'],
            'raw_inline_control_policy_comparisons': counts['inline_policy'],
            'raw_helper_unchanged_state_comparisons': counts['helper'],
            'raw_unsupported_unchanged_state_comparisons': counts['unsupported'],
            'unicorn_original_complete_state_comparisons': counts['unicorn_complete_state'],
            'unicorn_exact_control_divergences': counts['unicorn_exact_control_divergences'],
            'unicorn_exact_divergence_examples': unicorn_divergences,
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


def numerical_half_chain_sources(operation):
    source = struct.pack('<' + 'I' * (NUMERICAL_MANY_HALF_OPERATIONS + 1),
                         *([operation['word']] * NUMERICAL_MANY_HALF_OPERATIONS), RET)
    # The first guest RET enters a declared trampoline which replaces LR with
    # STOP and revisits the same nine entries exactly once in this runtime.
    branch_displacement = -(len(source) + 4) // 4
    branch = NUMERICAL_BRANCH_IMMEDIATE_BASE | (branch_displacement & NUMERICAL_BRANCH_IMMEDIATE_MASK)
    repeated = source + struct.pack('<II', NUMERICAL_MOV_X30_X11, branch)
    return source, repeated


def numerical_half_cache_artifacts(cache, source, base, compiler, evidence_root=ROOT):
    manifests = sorted(cache.rglob('manifest.json'))
    if len(manifests) != NUMERICAL_MANY_HALF_OPERATIONS + 1:
        raise AssertionError('Half chain did not prepare exactly eight helpers and RET')
    entries, artifacts = set(), []
    for path in manifests:
        manifest = json.loads(path.read_bytes())
        identity = manifest['identity']
        pc = identity['guest_base']
        position = pc - base
        prefix = source[position:position + 4]
        if (position < 0 or position % 4 or position >= len(source) or pc in entries
                or identity['source_sha256'] != digest(prefix) or identity['compiler_source_sha256'] != compiler
                or identity['abi'] != BLOCK_ABI or identity['target_cpu'] != 'x86_64-baseline'
                or manifest['source_map'] != [[pc, 0]] or manifest['verified'] is not False):
            raise AssertionError('Half chain cache contains an incorrect source prefix or identity')
        entries.add(pc)
        native = (path.parent / 'native.bin').read_bytes()
        expected_bytes = NUMERICAL_RETURN_NATIVE_BYTES if position == len(source) - 4 else NUMERICAL_HELPER_NATIVE_BYTES
        if len(native) != expected_bytes or manifest['native_bytes'] != len(native) or manifest['native_sha256'] != digest(native):
            raise AssertionError('Half chain retained dead suffix bytes or changed its native body')
        accounting = {'guest_pc': pc, 'compiled_source_bytes': len(prefix), 'native_bytes': len(native),
                      'native_instructions': len(decode_native_stream(native))}
        retained = retain_native_evidence('simd-scalar_numerical-half-chain', prefix, native,
                                          manifest, accounting, Path(__file__).read_bytes(), root=evidence_root)
        artifacts.append({**accounting, 'files': retained})
    if entries != set(range(base, base + len(source), 4)):
        raise AssertionError('Half chain cache omitted a source instruction')
    return artifacts


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

    half_record = next(record for record in oracle['records']
        if record['operation']['name'] == 'fadd' and record['operation']['lane'] == 2
        and record['label'] == 'one_one' and State.from_buffer_copy(record['initial']).fpcr == 0
        and State.from_buffer_copy(record['initial']).fpsr == 0)
    half_initial = State.from_buffer_copy(half_record['initial'])
    half_expected = State.from_buffer_copy(half_record['expected'])
    half_source, repeated_source = numerical_half_chain_sources(half_record['operation'])
    half_base = BASE + 0x1c00
    half_cache = directory / 'many-half-cache'
    cold, actual = invoke(half_source, half_base, half_base, half_initial,
                          budget=NUMERICAL_MANY_HALF_OPERATIONS + 1, cache_dir=half_cache)
    if (cold['pc'] != STOP or bytes(actual) != bytes(half_expected)
            or cold['outcome']['compiled_blocks'] != NUMERICAL_MANY_HALF_OPERATIONS + 1
            or cold['outcome']['floating_point_helpers'] != NUMERICAL_MANY_HALF_OPERATIONS):
        raise AssertionError('Many-H cold runtime changed full state or prepared a dead suffix')
    half_artifacts = numerical_half_cache_artifacts(half_cache, half_source, half_base, compiler)
    half_bytes = sum(artifact['native_bytes'] for artifact in half_artifacts)
    if half_bytes != NUMERICAL_MANY_HALF_OPERATIONS * NUMERICAL_HELPER_NATIVE_BYTES + NUMERICAL_RETURN_NATIVE_BYTES:
        raise AssertionError('Many-H cached native aggregate is not exactly141bytes')
    warm, actual = invoke(half_source, half_base, half_base, half_initial,
                          budget=NUMERICAL_MANY_HALF_OPERATIONS + 1, cache_dir=half_cache)
    if (warm['pc'] != STOP or bytes(actual) != bytes(half_expected) or warm['outcome']['compiled_blocks'] != 0
            or warm['outcome']['disk_cache_hits'] != NUMERICAL_MANY_HALF_OPERATIONS + 1):
        raise AssertionError('Many-H fresh runtime did not reuse all nine disk artifacts')
    budget_cache = directory / 'many-half-budget-cache'
    partial, intermediate = invoke(half_source, half_base, half_base, half_initial,
        budget=NUMERICAL_CACHE_LOOP_ITERATIONS, cache_dir=budget_cache)
    resume_pc = half_base + NUMERICAL_CACHE_LOOP_ITERATIONS * 4
    if (partial['outcome']['reason']['kind'] != 'budget_exhausted' or partial['pc'] != resume_pc
            or bytes(intermediate) != bytes(half_expected)
            or partial['outcome']['floating_point_helpers'] != NUMERICAL_CACHE_LOOP_ITERATIONS):
        raise AssertionError('Many-H budget boundary skipped or repeated a helper')
    resumed, actual = invoke(half_source, half_base, resume_pc, intermediate,
        budget=NUMERICAL_MANY_HALF_OPERATIONS - NUMERICAL_CACHE_LOOP_ITERATIONS + 1, cache_dir=budget_cache)
    if (resumed['pc'] != STOP or bytes(actual) != bytes(half_expected)
            or resumed['outcome']['floating_point_helpers'] != NUMERICAL_MANY_HALF_OPERATIONS - NUMERICAL_CACHE_LOOP_ITERATIONS):
        raise AssertionError('Many-H budget resume failed to complete the suffix and RET')
    repeated_initial = State.from_buffer_copy(half_initial)
    repeated_initial.x[11], repeated_initial.x[30] = STOP, half_base + len(half_source)
    repeated_expected = State.from_buffer_copy(half_expected)
    repeated_expected.x[11] = STOP
    repeated, actual = invoke(repeated_source, half_base, half_base, repeated_initial,
        budget=2 * (NUMERICAL_MANY_HALF_OPERATIONS + 1) + 1, cache_dir=directory / 'many-half-live-cache')
    if (repeated['pc'] != STOP or bytes(actual) != bytes(repeated_expected)
            or repeated['outcome']['floating_point_helpers'] != 2 * NUMERICAL_MANY_HALF_OPERATIONS
            or repeated['outcome']['memory_cache_hits'] != NUMERICAL_MANY_HALF_OPERATIONS + 1):
        raise AssertionError('Many-H live runtime did not reuse exactly nine loaded entries')
    for code, initial, expected in ((half_source, half_initial, half_expected),
                                    (repeated_source, repeated_initial, repeated_expected)):
        original.mem_write(half_base, code)
        original.ctl_remove_cache(half_base, half_base + len(code))
        initialize_arm(original, initial)
        original.emu_start(half_base, STOP, count=32)
        if original.reg_read(arm.UC_ARM64_REG_PC) != STOP or bytes(capture_arm(original, initial)) != bytes(expected):
            raise AssertionError('Many-H original instruction chain differs from native runtime state')
        counts['synthetic_original_complete_state_checks'] += 1
    unsupported_source = half_source[:-4] + struct.pack('<I', NUMERICAL_UNSUPPORTED_WORD)
    unsupported, actual = invoke(unsupported_source, half_base, half_base, half_initial,
        budget=NUMERICAL_MANY_HALF_OPERATIONS + 1, cache_dir=directory / 'many-half-unsupported-cache')
    if (unsupported['pc'] != half_base + NUMERICAL_MANY_HALF_OPERATIONS * 4
            or unsupported['outcome']['reason']['kind'] != 'unsupported' or bytes(actual) != bytes(half_expected)
            or unsupported['outcome']['compiled_blocks'] != NUMERICAL_MANY_HALF_OPERATIONS
            or unsupported['outcome']['floating_point_helpers'] != NUMERICAL_MANY_HALF_OPERATIONS):
        raise AssertionError('Many-H unsupported suffix failed to preserve the completed prefix')
    counts['unsupported_suffix_state_checks'] += 1
    counts['many_half_complete_state_checks'] += 5
    counts['many_half_cache_artifacts'] = len(half_artifacts)
    counts['many_half_cached_native_bytes'] = half_bytes
    counts['many_half_disk_cache_hits'] = warm['outcome']['disk_cache_hits']
    counts['many_half_memory_cache_hits'] = repeated['outcome']['memory_cache_hits']
    counts['many_half_budget_resume_checks'] += 1
    if counts['disk_cache_hits'] == 0:
        raise AssertionError('Numerical runtime evidence never exercised persistent cached code')
    snapshot = write_evidence(ROOT / '.stela/simd-scalar_numerical-runtime-records.json', transcripts)
    return {**dict(counts), 'ram_bytes_per_invocation': len(ram),
            'many_half_native_artifacts': half_artifacts,
            'transcript': {'path': str(snapshot.relative_to(ROOT)), 'sha256': digest(snapshot.read_bytes())},
            'limits': 'Actual Rust BlockRuntime completes helpers and executes guest RET. Subprocesses exercise disk reuse; bounded three-iteration guest loops exercise live memory-cache reuse. Synthetic ADD/SUBS/CBNZ fixtures have separate complete-state original Unicorn checks. Original QEMU transports GPR/SP, while ordinary-control original Unicorn checks close that frame subset.'}


def run_scalar_numerical_cohort(cli, oracle_path):
    oracle = load_numerical_oracle(oracle_path)
    started = time.monotonic()
    cli_hash, harness_hash = digest(cli.read_bytes()), digest(Path(__file__).read_bytes())
    shared_paths = ('dev/differential.py', 'dev/evidence.py', 'dev/memory-faults.py', 'dev/native-memory-faults.c',
                    'dev/test_simd_differential.py', 'crates/stela-runtime/src/floating.rs',
                    'crates/stela-runtime/src/floating/comparison.rs', 'crates/stela-runtime/src/floating/minmax.rs', 'crates/stela-runtime/src/floating/rounding.rs', 'crates/stela-runtime/src/floating/sqrt.rs', 'crates/stela-runtime/src/floating/estimate.rs', 'crates/stela-runtime/src/floating/refinement.rs', 'crates/stela-runtime/src/floating/arithmetic.rs',
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
            retained = retain_native_evidence('simd-scalar_numerical', batch['compiled_source'], batch['native'],
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
    completed_checks = runtime['invocations'] - typed_checks - runtime['unsupported_suffix_state_checks']
    report = {'kind': 'simd_scalar_numerical_arm_vs_native_x86', 'passed': True,
        'abi': batches[0]['manifest']['abi'], 'state_comparisons': completed_checks,
        'runtime_complete_state_comparisons': completed_checks,
        'runtime_typed_unsupported_state_checks': typed_checks,
        'runtime_budget_resume_checks': runtime['budget_resume_checks'],
        'runtime_memory_cache_loop_checks': runtime['memory_cache_loop_checks'],
        'runtime_disk_cache_resume_checks': runtime['disk_cache_resume_checks'],
        'runtime_many_half_complete_state_comparisons': runtime['many_half_complete_state_checks'],
        'runtime_many_half_cache_artifacts': runtime['many_half_cache_artifacts'],
        'runtime_many_half_cached_native_bytes': runtime['many_half_cached_native_bytes'],
        'runtime_unsupported_suffix_state_checks': runtime['unsupported_suffix_state_checks'],
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


VECTOR_NUMERICAL_FOCUS = 'vector_numerical'
VECTOR_NUMERICAL_ORACLE = ROOT / '.stela/research/vector-numerical/oracle/receipt.json'
VECTOR_NUMERICAL_SHAPES = ((2, 8), (2, 16), (4, 8), (4, 16), (8, 16))
VECTOR_NUMERICAL_BASES = {'fadd': (0x0e401400, 0x0e20d400),
                        'fsub': (0x0ec01400, 0x0ea0d400),
                        'fmul': (0x2e401c00, 0x2e20dc00),
                        'fdiv': (0x2e403c00, 0x2e20fc00)}
VECTOR_NUMERICAL_ROLES = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1),
                         (31, 31, 31), (31, 29, 31), (31, 30, 29))
VECTOR_NUMERICAL_CONTROLS = (0, 1, 2, 4, 7, 1 << 19, 1 << 24, 3 << 22)
VECTOR_NUMERICAL_CASES = 21220
VECTOR_NUMERICAL_CANARY = 0x51ad1234
VECTOR_NUMERICAL_ROUND_ZERO = 3 << 22
VECTOR_NUMERICAL_STATUS_OFFSET = 248
VECTOR_NUMERICAL_EXCEPTION_OFFSET = 280
VECTOR_NUMERICAL_VECTORS_OFFSET = 320
VECTOR_NUMERICAL_READBACK_OFFSET = 832
VECTOR_NUMERICAL_ORIGINAL_MARKER = 0x1234
VECTOR_NUMERICAL_CPACR_FPEN = 3 << 20


def vector_numerical_operation(name, lane, width, d, n, m):
    if name not in VECTOR_NUMERICAL_BASES or (lane, width) not in VECTOR_NUMERICAL_SHAPES or any(not 0 <= register < 32 for register in (d, n, m)):
        raise ValueError('Invalid vector numerical shape or operand')
    half, standard = VECTOR_NUMERICAL_BASES[name]
    word = (half if lane == 2 else standard | (int(lane == 8) << 22))
    word |= int(width == 16) << 30 | m << 16 | n << 5 | d
    return {'name': name, 'lane': lane, 'bytes': width, 'scalar': False,
            'd': d, 'n': n, 'm': m, 'word': word}


def vector_numerical_functions():
    return [vector_numerical_operation(name, lane, width, *roles)
            for name in VECTOR_NUMERICAL_BASES for lane, width in VECTOR_NUMERICAL_SHAPES
            for roles in VECTOR_NUMERICAL_ROLES]


def vector_numerical_state(operation, index, pairs, control=0, sticky=False):
    initial = State()
    rng = random.Random(0x564543544f52 + index)
    initial.x[:] = [rng.getrandbits(64) for _ in range(31)]
    initial.sp = 0x48010000 + (index % 16) * 16
    seed_extended_state(initial, index * 31 + 11)
    initial.reserved, initial.nzcv = VECTOR_NUMERICAL_CANARY, (index % 16) << 28
    initial.fpcr, initial.fpsr = control, FP_REGISTER_MASKS['fpsr'] if sticky else 0
    lane, width = operation['lane'], operation['bytes']
    bits = lane * 8
    if len(pairs) != width // lane or any(not 0 <= value < 1 << bits for pair in pairs for value in pair):
        raise ValueError('Vector numerical input has an invalid lane count/value')
    # Inactive lanes are signaling NaNs. They must not contribute status or
    # make a Q0 instruction appear exceptional.
    fraction = {2: 10, 4: 23, 8: 52}[lane]
    signaling = ((1 << (bits - fraction - 1)) - 1) << fraction | 1
    poison = sum(signaling << (element * bits) for element in range(16 // lane))
    for register, side in ((operation['n'], 0), (operation['m'], 1)):
        value = poison & ~((1 << (width * 8)) - 1)
        value |= sum(pair[side] << (element * bits) for element, pair in enumerate(pairs))
        initial.v[register][:] = [value & MASK, value >> 64]
    return initial


def vector_numerical_corpus(foundation):
    """Pack the retained scalar directed pairs into active lanes. No native
    result or host floating-point arithmetic participates in input generation.
    """
    functions = vector_numerical_functions()
    directed, controls = {}, set()
    for record in foundation['records']:
        operation = record['operation']
        initial = State.from_buffer_copy(record['initial'])
        if (operation['d'], operation['n'], operation['m']) != (0, 1, 2) or record['unsupported'] or initial.fpsr:
            continue
        if record['label'] == 'zero_pp':
            controls.add(initial.fpcr)
        if initial.fpcr or record['label'].startswith(('alias_', 'bounded_', 'trap_')):
            continue
        mask = (1 << (operation['lane'] * 8)) - 1
        pair = (initial.v[1][0] & mask, initial.v[2][0] & mask)
        directed.setdefault((operation['name'], operation['lane']), {}).setdefault(record['label'], pair)
    if len(controls) != 30 or any(len(pairs) != 64 for pairs in directed.values()) or len(directed) != 12:
        raise AssertionError('Vector numerical corpus needs the complete retained scalar directed foundation')
    records = []

    def append(index, label, pairs, control=0, sticky=False):
        operation = functions[index]
        initial = vector_numerical_state(operation, len(records), pairs, control, sticky)
        records.append({'function': index, 'function_index': index, 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})

    rng = random.Random(0x564543465052414e)
    for index in range(0, len(functions), len(VECTOR_NUMERICAL_ROLES)):
        operation = functions[index]
        count, bits = operation['bytes'] // operation['lane'], operation['lane'] * 8
        pairs = directed[(operation['name'], operation['lane'])]
        values = list(pairs.values())
        for control in sorted(controls):
            for first in range(0, len(values), count):
                append(index, f'directed_pack_{first}', values[first:first + count], control)
            append(index, 'sticky_pack', values[:count], control, True)
        patterns = (('one_positive_halfulp', 'negative_one_positive_halfulp'),
                    ('qnan_snan', 'reverse_qnan_qnan'),
                    ('normal_boundary_midpoint', 'minimum_normal_half'))
        for role in range(1, len(VECTOR_NUMERICAL_ROLES)):
            for control in VECTOR_NUMERICAL_CONTROLS:
                for pattern, labels in enumerate(patterns):
                    active = [pairs[labels[element % len(labels)]] for element in range(count)]
                    for sticky in (False, True):
                        append(index + role, f'alias_pattern_{pattern}', active, control, sticky)
        one = pairs['one_one'][0]
        half = pairs['minimum_normal_half'][1]
        for control in VECTOR_NUMERICAL_CONTROLS:
            for label in ('snan_left', 'minimum_normal_half', 'maximum_maximum'):
                for position in range(count):
                    active = [(one, half)] * count
                    active[position] = pairs[label]
                    append(index, f'active_{label}_{position}', active, control)
        for iteration in range(16):
            active = [(rng.getrandbits(bits), rng.getrandbits(bits)) for _ in range(count)]
            append(index, 'bounded_random', active, sorted(controls)[iteration])
        for control in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
            append(index, 'trap_enable_readback_only', [(one, half)] * count, control)
    if len(records) != VECTOR_NUMERICAL_CASES:
        raise AssertionError('Vector numerical corpus exceeded its approved bounded scope')
    return functions, records


def prepare_vector_numerical_oracle(directory, numerical_path=NUMERICAL_FOUNDATION):
    foundation = load_numerical_oracle(numerical_path)
    functions, records = vector_numerical_corpus(foundation)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    inputs = b''.join(struct.pack('<Q', record['function']) + record['initial'] + bytes(8) for record in records)
    functions = [{**operation, 'source_hex': struct.pack('<II', operation['word'], RET).hex()} for operation in functions]
    metadata = [{key: value for key, value in record.items() if key != 'initial'} | {'case': index}
                for index, record in enumerate(records)]
    files = {'functions.json': (json.dumps(functions, indent=2) + '\n').encode(),
             'cases.json': (json.dumps(metadata, indent=2) + '\n').encode(), 'inputs.bin': inputs}
    for name, data in files.items():
        path = directory / name
        if path.exists():
            if path.read_bytes() != data:
                raise AssertionError('Frozen vector oracle inputs changed')
        else:
            with path.open('xb') as stream:
                stream.write(data)
    plan = {'kind': 'vector_numerical_original_input_plan', 'cases': len(records), 'functions': len(functions),
            'scalar_foundation_sha256': foundation['foundation_sha256'],
            'harness_sha256': digest(Path(__file__).read_bytes()),
            'files': {name: {'sha256': digest(data), 'bytes': len(data)} for name, data in files.items()}}
    path = write_evidence(directory / 'input-plan.json', plan)
    return {'path': str(path.relative_to(ROOT)), 'sha256': digest(path.read_bytes()), **plan}


def full_frame_numerical_original_state(initial, snapshot):
    if len(snapshot) != FP_REGISTER_RECORD_BYTES:
        raise AssertionError('Truncated numerical original full-frame snapshot')
    state = State.from_buffer_copy(initial)
    state.x[:] = struct.unpack_from('<31Q', snapshot)
    state.sp, spsr, state.fpcr, state.fpsr = struct.unpack_from('<4Q', snapshot, VECTOR_NUMERICAL_STATUS_OFFSET)
    state.nzcv = spsr & 0xf0000000
    vectors = struct.unpack_from('<64Q', snapshot, VECTOR_NUMERICAL_VECTORS_OFFSET)
    for register in range(32):
        state.v[register][:] = vectors[register * 2:register * 2 + 2]
    return state


def load_vector_numerical_oracle(path=VECTOR_NUMERICAL_ORACLE):
    return load_full_frame_numerical_oracle(path, vector_numerical_functions(), VECTOR_NUMERICAL_CASES, VECTOR_NUMERICAL_FOCUS)


def load_full_frame_numerical_oracle(path, expected_functions, expected_cases, focus):
    pointer, pointer_hash = numerical_json(path)
    receipt, receipt_hash = numerical_json(ROOT / pointer['receipt']['path'], pointer['receipt']['sha256'])
    if (receipt.get('passed_transport_and_architectural_frame_checks') is not True
            or receipt['cases'] != expected_cases or pointer['directory'] != receipt['directory']):
        raise AssertionError('Complete passing numerical original full-frame capture required')
    directory = ROOT / receipt['directory']
    family = FULL_FRAME_NUMERICAL_COHORTS[focus]
    for name, identity in receipt['files'].items():
        if Path(name).name != name:
            raise AssertionError('Full-frame original file is not one path component')
        data = (directory / name).read_bytes()
        if digest(data) != identity['sha256'] or len(data) != identity['bytes']:
            raise AssertionError(f'Full-frame original evidence changed: {name}')
    functions = json.loads((directory / 'functions.json').read_bytes())
    cases = json.loads((directory / 'cases.json').read_bytes())
    inputs, results, elf = ((directory / name).read_bytes() for name in ('inputs.bin', 'results.bin', 'guest.elf'))
    if len(functions) != len(expected_functions) or len(cases) != expected_cases:
        raise AssertionError('Full-frame original function/corpus count changed')
    for actual, expected in zip(functions, expected_functions):
        if any(actual[key] != value for key, value in expected.items()) or actual['source_hex'] != struct.pack('<II', expected['word'], numerical_return_word(expected)).hex():
            raise AssertionError('Full-frame original operation differs from independent encoding facts')
    if len(inputs) != len(cases) * NUMERICAL_INPUT_STRIDE or len(results) != (len(cases) + 1) * FP_REGISTER_RECORD_BYTES:
        raise AssertionError('Full-frame original state framing changed')
    records, readbacks = [], Counter()
    for index, case in enumerate(cases):
        raw = inputs[index * NUMERICAL_INPUT_STRIDE:(index + 1) * NUMERICAL_INPUT_STRIDE]
        function = struct.unpack_from('<Q', raw)[0]
        initial = State.from_buffer_copy(raw[NUMERICAL_INPUT_HEADER:NUMERICAL_INPUT_HEADER + ctypes.sizeof(State)])
        if case['case'] != index or case['function_index'] != function or digest(bytes(initial)) != case['initial_state_sha256']:
            raise AssertionError('Full-frame original metadata does not bind input state')
        operation = expected_functions[function]
        snapshot = results[(index + 1) * FP_REGISTER_RECORD_BYTES:(index + 2) * FP_REGISTER_RECORD_BYTES]
        original = full_frame_numerical_original_state(initial, snapshot)
        esr, elr, current_el, cpacr, marker = struct.unpack_from('<5Q', snapshot, VECTOR_NUMERICAL_EXCEPTION_OFFSET)
        actual_fpcr, actual_fpsr = struct.unpack_from('<2Q', snapshot, VECTOR_NUMERICAL_READBACK_OFFSET)
        if (esr >> 26 != FP_REGISTER_EC_SVC or current_el != 4 or cpacr != VECTOR_NUMERICAL_CPACR_FPEN or marker != VECTOR_NUMERICAL_ORIGINAL_MARKER
                or fp_register_elf_word(elf, elr - 8) != operation['word']
                or fp_register_elf_word(elf, elr - 4) != FP_REGISTER_SVC
                or original.fpcr != actual_fpcr or actual_fpsr != initial.fpsr
                or actual_fpcr != initial.fpcr & ~NUMERICAL_TRAP_ENABLE_MASK):
            raise AssertionError(f'Full-frame original instruction/EL0/control evidence changed: {index}')
        untouched = State.from_buffer_copy(original)
        if family.get('original_effects'):
            family['original_effects'](initial, original, operation)
            untouched.v[operation['d']][:] = initial.v[operation['d']]
        elif focus in (ROUND_INTEGRAL_FOCUS, SQRT_NUMERICAL_FOCUS):
            validate_numerical_unary_original_effects(initial, original, operation)
            untouched.v[operation['d']][:] = initial.v[operation['d']]
        elif focus == COMPARISON_MINMAX_FOCUS:
            validate_comparison_minmax_original_effects(initial, original, operation)
            if operation['output_kind'] == 'flags':
                untouched.nzcv = initial.nzcv
            else:
                untouched.v[operation['d']][:] = initial.v[operation['d']]
        elif focus == CONVERSION_NUMERICAL_FOCUS:
            validate_conversion_original_effects(initial, original, operation)
            if operation['destination_bank'] == 'general':
                if operation['d'] != 31:
                    untouched.x[operation['d']] = initial.x[operation['d']]
            else:
                untouched.v[operation['d']][:] = initial.v[operation['d']]
            if operation['writes_nzcv']:
                untouched.nzcv = initial.nzcv
        else:
            untouched.v[operation['d']][:] = initial.v[operation['d']]
        untouched.fpcr, untouched.fpsr = initial.fpcr, initial.fpsr
        if bytes(untouched) != bytes(initial) or original.fpsr & ~NUMERICAL_EXCEPTION_FLAGS != initial.fpsr & ~NUMERICAL_EXCEPTION_FLAGS:
            raise AssertionError('Original vector numerical operation changed unrelated state or QC')
        if (focus not in (CONVERSION_NUMERICAL_FOCUS, COMPARISON_MINMAX_FOCUS) and not operation['scalar']
                and operation['bytes'] == 8 and original.v[operation['d']][1] != 0):
            raise AssertionError('Original Q0 numerical instruction did not clear upper 64 bits')
        if operation['scalar'] and 'a' in operation:
            active = (1 << (operation['lane'] * 8)) - 1
            result = original.v[operation['d']][0] | original.v[operation['d']][1] << 64
            addend = initial.v[operation['a']][0] | initial.v[operation['a']][1] << 64
            merge = addend if initial.fpcr & NUMERICAL_NEP else 0
            if result & ~active != merge & ~active:
                raise AssertionError('Original scalar fused upper state did not follow addend NEP merge')
        readbacks[(initial.fpcr, actual_fpcr)] += 1
        # Only LR changes to let the native/runtime and Unicorn paths execute
        # the actual RET. The original subject instruction left every GPR intact.
        profile_expected = family['profile_expectation'](operation, initial, original, receipt) if family.get('profile_expectation') else None
        enabled = bool(initial.fpcr & NUMERICAL_TRAP_ENABLE_MASK)
        policy_success = enabled and bool(family.get('accepts_enabled_control') and family['accepts_enabled_control'](operation, initial))
        return_register = operation.get('return_register', 30)
        initial.x[return_register] = original.x[return_register] = STOP
        primary_expected = bytes(original)
        if profile_expected is not None:
            profile_expected.x[return_register] = STOP
            expected = bytes(profile_expected)
            basis = 'standard_profile_model'
        else:
            expected_state = State.from_buffer_copy(original)
            if policy_success:
                expected_state.fpcr = initial.fpcr
            expected = bytes(expected_state)
            basis = 'requested_control_policy' if policy_success else 'direct_original'
        records.append({'function': function, 'initial': bytes(initial), 'expected': expected,
            'primary_expected': primary_expected, 'profile_expected': bytes(profile_expected) if profile_expected is not None else None,
            'equality_basis': basis, 'control_policy_success': policy_success,
            'operation': operation, 'case': index, 'label': case['label'], 'producer': 'vector_el0' if focus == VECTOR_NUMERICAL_FOCUS else focus + '_el0',
            'unsupported': enabled and not policy_success})
    return {'records': records, 'functions': expected_functions, 'receipt_sha256': receipt_hash,
            'pointer_sha256': pointer_hash,
            'producer': receipt, 'control_readbacks': [{'requested': requested, 'actual': actual, 'cases': count}
                for (requested, actual), count in sorted(readbacks.items())],
            'input_derivation': ('Only the per-function unused return register becomes STOP for actual guest RET. Conversion input and output GPRs remain unchanged by transport derivation. ' if focus == CONVERSION_NUMERICAL_FOCUS else 'Only X30 becomes STOP for actual guest RET. All other imported bytes remain unchanged. ') + 'Original requested trap enables are retained. QEMU RAZ/WI readbacks, accepted requested-control policy and standard-versus-enhanced profile expectations are classified separately from direct original equality.'}


def vector_numerical_runtime_cases(records):
    selected = {}
    for record in records:
        operation, initial = record['operation'], State.from_buffer_copy(record['initial'])
        shape = (operation['name'], operation['lane'], operation['bytes'])
        if record['unsupported']:
            selected.setdefault(('trap', *shape, initial.fpcr), record)
        elif initial.fpsr == 0:
            if initial.fpcr in VECTOR_NUMERICAL_CONTROLS:
                selected.setdefault(('control', *shape, initial.fpcr), record)
            if initial.fpcr == NUMERICAL_NEP:
                selected.setdefault(('alias', record['function']), record)
            flush = NUMERICAL_FZ16 if operation['lane'] == 2 else NUMERICAL_FZ
            if initial.fpcr in (0, NUMERICAL_AH, flush) and record['label'] in (
                    'active_snan_left_0', 'active_minimum_normal_half_0', 'active_maximum_maximum_0'):
                selected.setdefault(('semantic', *shape, initial.fpcr, record['label']), record)
    return list({record['case']: record for record in selected.values()}.values())


FUSED_NUMERICAL_FOCUS = 'fused_numerical'
FUSED_NUMERICAL_ORACLE = ROOT / '.stela/research/fused-numerical/oracle/receipt.json'
FUSED_SCALAR_BASES = {'fmadd': 0x1f000000, 'fmsub': 0x1f008000,
                      'fnmadd': 0x1f200000, 'fnmsub': 0x1f208000}
FUSED_VECTOR_BASES = {'fmla': (0x0e400c00, 0x0e20cc00),
                     'fmls': (0x0ec00c00, 0x0ea0cc00)}
FUSED_INDEXED_BASES = {'fmla': 0x0f001000, 'fmls': 0x0f005000}
FUSED_NATIVE_PREFIXES = ('vfmadd', 'vfmsub', 'vfnmadd', 'vfnmsub')
FUSED_NATIVE_OPERATIONS = {'fmadd': 'vfmadd', 'fmla': 'vfmadd',
                           'fmsub': 'vfnmadd', 'fmls': 'vfnmadd',
                           'fnmadd': 'vfnmsub', 'fnmsub': 'vfmsub'}
FUSED_SCALAR_ROLES = ((0, 1, 2, 3), (1, 1, 2, 3), (2, 1, 2, 3),
                      (3, 1, 2, 3), (0, 1, 1, 3), (0, 1, 2, 1),
                      (0, 1, 2, 2), (31, 31, 31, 31), (31, 30, 29, 28))
FUSED_ACCUMULATE_ROLES = ((0, 1, 2), (1, 1, 2), (2, 1, 2),
                          (0, 1, 1), (31, 31, 31), (31, 30, 29))
FUSED_ROUNDING_CONTROLS = tuple(mode << 22 for mode in range(4))
FUSED_EXTRA_CONTROLS = (NUMERICAL_AH, NUMERICAL_FIZ, NUMERICAL_NEP,
                        NUMERICAL_AH | NUMERICAL_FIZ | NUMERICAL_NEP,
                        NUMERICAL_FZ16, NUMERICAL_FZ, NUMERICAL_DN,
                        NUMERICAL_AH | NUMERICAL_FZ, NUMERICAL_AH | NUMERICAL_DN)


def fused_numerical_operation(name, lane, width, scalar, d, n, m, a=None, index=None):
    if lane not in (2, 4, 8) or any(not 0 <= register < 32 for register in (d, n, m)):
        raise ValueError('Invalid fused format or register')
    if name in FUSED_SCALAR_BASES:
        if not scalar or width != lane or index is not None or a is None or not 0 <= a < 32:
            raise ValueError('Invalid scalar fused operand')
        word = FUSED_SCALAR_BASES[name] | {2: 3, 4: 0, 8: 1}[lane] << 22 | a << 10
    elif name in FUSED_VECTOR_BASES:
        if a is not None and a != d:
            raise ValueError('FMLA/FMLS addend must be destination')
        a = d
        if scalar:
            if width != lane or index is None:
                raise ValueError('Scalar FMLA/FMLS requires an indexed operand')
        elif (lane, width) not in VECTOR_NUMERICAL_SHAPES:
            raise ValueError('Invalid fused vector arrangement')
        if index is None:
            half, standard = FUSED_VECTOR_BASES[name]
            word = half if lane == 2 else standard | int(lane == 8) << 22
            word |= int(width == 16) << 30
        else:
            if not 0 <= index < 16 // lane or lane == 2 and m >= 16:
                raise ValueError('Invalid fused indexed register or lane')
            word = FUSED_INDEXED_BASES[name] | int(scalar) << 28
            word |= int(scalar or width == 16) << 30
            if lane == 2:
                word |= ((index >> 2) & 1) << 11 | (index & 3) << 20
            elif lane == 4:
                word |= 1 << 23 | ((index >> 1) & 1) << 11 | (index & 1) << 21
            else:
                word |= 3 << 22 | index << 11
    else:
        raise ValueError('Invalid fused mnemonic')
    word |= m << 16 | n << 5 | d
    return {'name': name, 'lane': lane, 'bytes': width, 'scalar': scalar,
            'd': d, 'n': n, 'm': m, 'a': a, 'index': index, 'word': word}


def fused_numerical_functions():
    functions = [fused_numerical_operation(name, lane, lane, True, *roles)
                 for name in FUSED_SCALAR_BASES for lane in (2, 4, 8)
                 for roles in FUSED_SCALAR_ROLES]
    for name in FUSED_VECTOR_BASES:
        for lane, width in VECTOR_NUMERICAL_SHAPES:
            functions.extend(fused_numerical_operation(name, lane, width, False, *roles)
                             for roles in FUSED_ACCUMULATE_ROLES)
        for scalar, lane, width in ([(True, lane, lane) for lane in (2, 4, 8)]
                                    + [(False, lane, width) for lane, width in VECTOR_NUMERICAL_SHAPES]):
            for index in range(16 // lane):
                for d, n, m in FUSED_ACCUMULATE_ROLES:
                    # FP16 indexed Rm has four bits; Vd/Vn still reach V31.
                    if lane == 2:
                        m &= 15
                    functions.append(fused_numerical_operation(name, lane, width, scalar, d, n, m, index=index))
    if len({operation['word'] for operation in functions}) != len(functions):
        raise AssertionError('Fused exact subject words must be unique')
    return functions


def fused_numerical_triples(lane):
    bits, fraction = lane * 8, {2: 10, 4: 23, 8: 52}[lane]
    exponent_bits = bits - fraction - 1
    bias = (1 << (exponent_bits - 1)) - 1
    sign = 1 << (bits - 1)
    one, half, two = bias << fraction, (bias - 1) << fraction, (bias + 1) << fraction
    infinity = ((1 << exponent_bits) - 1) << fraction
    maximum, minimum = infinity - 1, 1 << fraction
    quiet, signaling = infinity | 1 << (fraction - 1) | 0x15, infinity | 0x2b
    cases = [('one_one_one', one, one, one), ('exact_product', one, two, one),
             ('single_round_residual', one | sign, one + 1, one - 2),
             ('single_round_positive', (one + 2) | sign, one + 1, one + 1),
             ('product_overflow_cancel', maximum | sign, maximum, two),
             ('product_underflow_accumulate', minimum, minimum, half),
             ('normal_boundary', minimum - 1, minimum, half),
             ('minimum_subnormal', 1, minimum, 1),
             ('maximum_finite', maximum, maximum, one),
             ('rounding_tie', one, (bias - fraction - 1) << fraction, one),
             ('tiny_residual', 1 | sign, 1, one + 1),
             ('inf_zero_qnan_addend', quiet, infinity, 0),
             ('inf_zero_finite_addend', one, infinity, 0),
             ('opposed_infinities', infinity | sign, infinity, one),
             ('same_infinities', infinity, infinity, one),
             ('snan_addend', signaling, one, one),
             ('snan_left', one, signaling, one), ('snan_right', one, one, signaling),
             ('qnan_addend_snan_left', quiet, signaling, one),
             ('qnan_addend_snan_right', quiet, one, signaling),
             ('qnan_left_snan_right', one, quiet, signaling),
             ('qnan_priority', quiet, quiet | sign | 0x100, quiet | 0x200),
             ('snan_priority', signaling, signaling | sign | 0x100, signaling | 0x200),
             ('negative_qnan', quiet | sign, one, one),
             ('denormal_addend', minimum - 1, one, half),
             ('denormal_left', one, minimum - 1, half),
             ('denormal_right', one, half, minimum - 1)]
    cases.extend((f'zero_signs_{signs}', sign if signs & 1 else 0,
                  sign if signs & 2 else 0, sign if signs & 4 else 0) for signs in range(8))
    return cases


def fused_numerical_state(operation, index, triples, control=0, sticky=False):
    initial = State()
    rng = random.Random(0x46555345444650 + index)
    initial.x[:] = [rng.getrandbits(64) for _ in range(31)]
    initial.sp = 0x48010000 + index % 16 * 16
    seed_extended_state(initial, index * 31 + 17)
    initial.reserved, initial.nzcv = VECTOR_NUMERICAL_CANARY, index % 16 << 28
    initial.fpcr, initial.fpsr = control, FP_REGISTER_MASKS['fpsr'] if sticky else 0
    lane, width = operation['lane'], operation['bytes']
    bits, mask = lane * 8, (1 << (lane * 8)) - 1
    count = 1 if operation['scalar'] else width // lane
    if len(triples) != count or any(not 0 <= value <= mask for triple in triples for value in triple):
        raise ValueError('Invalid fused input lane count/value')
    signaling = next(triple[1] for triple in fused_numerical_triples(lane) if triple[0] == 'snan_addend')
    poison = sum(signaling << (element * bits) for element in range(16 // lane))
    # Deliberate aliases are resolved by these ordered writes. The frozen input
    # frame, rather than the requested triple, is the original/native oracle input.
    for register, side in ((operation['a'], 0), (operation['n'], 1), (operation['m'], 2)):
        value = poison
        if side == 2 and operation['index'] is not None:
            element = operation['index']
            value = (value & ~(mask << (element * bits))) | triples[0][side] << (element * bits)
        else:
            for element, triple in enumerate(triples):
                value = (value & ~(mask << (element * bits))) | triple[side] << (element * bits)
        initial.v[register][:] = [value & MASK, value >> 64]
    return initial


def fused_numerical_corpus():
    functions, records = fused_numerical_functions(), []
    primary = set()

    def append(function, label, triples, control=0, sticky=False):
        initial = fused_numerical_state(functions[function], len(records), triples, control, sticky)
        records.append({'function': function, 'function_index': function, 'case': len(records),
            'label': label, 'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})

    for function, operation in enumerate(functions):
        shape = tuple(operation[key] for key in ('name', 'lane', 'bytes', 'scalar')) + (operation['index'] is not None,)
        count = 1 if operation['scalar'] else operation['bytes'] // operation['lane']
        triples = fused_numerical_triples(operation['lane'])
        directed = {label: (a, n, m) for label, a, n, m in triples}
        if shape not in primary:
            primary.add(shape)
            for control in FUSED_ROUNDING_CONTROLS:
                for label, a, n, m in triples:
                    append(function, label, [(a, n, m)] * count, control)
            for control in FUSED_EXTRA_CONTROLS:
                for label, a, n, m in triples:
                    if label.startswith(('snan_', 'qnan_', 'denormal_', 'single_round_', 'product_', 'zero_signs_')):
                        append(function, label, [(a, n, m)] * count, control)
                a, n, m = directed['snan_addend']
                append(function, 'sticky_snan_addend', [(a, n, m)] * count, control, True)
            if not operation['scalar']:
                for control in (0, NUMERICAL_AH, NUMERICAL_FZ16 if operation['lane'] == 2 else NUMERICAL_FZ):
                    for position in range(count):
                        for label in ('single_round_residual', 'product_underflow_accumulate', 'snan_addend'):
                            active = [directed['one_one_one']] * count
                            active[position] = directed[label]
                            append(function, f'active_{label}_{position}', active, control)
            for enable in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                a, n, m = directed['one_one_one']
                append(function, 'trap_enable_readback_only', [(a, n, m)] * count, enable)
        # Every alias and indexed selector sees exact arithmetic, single-round
        # cancellation and signaling input under both scalar merge policies.
        for control in (0, NUMERICAL_NEP):
            for label in ('one_one_one', 'single_round_residual', 'snan_addend'):
                a, n, m = directed[label]
                append(function, 'roles_' + label, [(a, n, m)] * count, control)
    if len(records) > 20000:
        raise AssertionError('Fused corpus exceeded approved bounded scope')
    return functions, records


def prepare_full_frame_numerical_oracle(directory, functions, records, focus):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    files = {'functions.json': (json.dumps([{**operation, 'source_hex': struct.pack('<II', operation['word'], numerical_return_word(operation)).hex()}
                                            for operation in functions], indent=2) + '\n').encode(),
             'cases.json': (json.dumps([{key: value for key, value in record.items() if key != 'initial'}
                                       for record in records], indent=2) + '\n').encode(),
             'inputs.bin': b''.join(struct.pack('<Q', record['function']) + record['initial'] + bytes(8) for record in records)}
    for name, data in files.items():
        path = directory / name
        if path.exists() and path.read_bytes() != data:
            raise AssertionError('Frozen original numerical inputs changed')
        if not path.exists():
            with path.open('xb') as stream:
                stream.write(data)
    plan = {'kind': focus + '_original_input_plan', 'cases': len(records), 'functions': len(functions),
            'harness_sha256': digest(Path(__file__).read_bytes()),
            'files': {name: {'sha256': digest(data), 'bytes': len(data)} for name, data in files.items()}}
    path = write_evidence(directory / 'input-plan.json', plan)
    return {'path': str(path.relative_to(ROOT)), 'sha256': digest(path.read_bytes()), **plan}


def prepare_fused_numerical_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *fused_numerical_corpus(), FUSED_NUMERICAL_FOCUS)


def load_fused_numerical_oracle(path=FUSED_NUMERICAL_ORACLE):
    functions, records = fused_numerical_corpus()
    return load_full_frame_numerical_oracle(path, functions, len(records), FUSED_NUMERICAL_FOCUS)


CONVERSION_NUMERICAL_FOCUS = 'conversion_numerical'
CONVERSION_NUMERICAL_ORACLE = ROOT / '.stela/research/conversion-numerical/oracle-expanded/receipt.json'
CONVERSION_ROLES = ((0, 1), (1, 1), (31, 31), (30, 30))
CONVERSION_PRECISION_BASES = {(2, 4): 0x1ee24000, (2, 8): 0x1ee2c000,
    (4, 2): 0x1e23c000, (4, 8): 0x1e22c000, (8, 2): 0x1e63c000, (8, 4): 0x1e624000}
CONVERSION_GENERAL_BASES = {'fcvtns': 0x1e200000, 'fcvtps': 0x1e280000,
    'fcvtms': 0x1e300000, 'fcvtzs': 0x1e380000, 'fcvtas': 0x1e240000,
    'scvtf': 0x1e220000}
CONVERSION_VECTOR_BASES = {'fcvtns': 0x0e21a800, 'fcvtps': 0x0ea1a800,
    'fcvtms': 0x0e21b800, 'fcvtzs': 0x0ea1b800, 'fcvtas': 0x0e21c800,
    'scvtf': 0x0e21d800}
CONVERSION_ROUNDING = {'fcvtn': 'fpcr', 'fcvtl': 'fpcr', 'fcvt': 'fpcr',
    'fcvtxn': 'to_odd', 'fcvtns': 'nearest_ties_even', 'fcvtps': 'toward_positive',
    'fcvtms': 'toward_negative', 'fcvtzs': 'toward_zero', 'fcvtas': 'nearest_ties_away',
    'scvtf': 'fpcr', 'fjcvtzs': 'toward_zero_modulo_2pow32'}
CONVERSION_AHP = 1 << 26
CONVERSION_EXTRA_CONTROLS = (NUMERICAL_NEP, NUMERICAL_AH, NUMERICAL_FIZ,
    NUMERICAL_FZ, NUMERICAL_FZ16, NUMERICAL_DN, CONVERSION_AHP,
    NUMERICAL_AH | NUMERICAL_FZ, NUMERICAL_AH | NUMERICAL_DN,
    CONVERSION_AHP | NUMERICAL_DN, NUMERICAL_AH | NUMERICAL_FIZ | NUMERICAL_NEP)
CONVERSION_RET_BASE = 0xd65f0000
CONVERSION_REGISTER_SHIFT = 5


def numerical_return_word(operation):
    register = operation.get('return_register', 30)
    if not 0 <= register < 31:
        raise ValueError('Numerical return register must be a general register')
    return CONVERSION_RET_BASE | register << CONVERSION_REGISTER_SHIFT


def conversion_numerical_operation(name, source_lane, destination_lane, shape, d, n,
                                   integer_bits=0, fracbits=0, unsigned=False, part=0):
    if source_lane not in (2, 4, 8) or destination_lane not in (2, 4, 8):
        raise ValueError('Conversion requires H/S/D or integer16/32/64 lanes')
    if any(not 0 <= register < 32 for register in (d, n)) or part not in (0, 1):
        raise ValueError('Invalid conversion register or half selector')
    source_bank = destination_bank = 'simd'
    source_part, destination_part = 0, 0
    source_bytes = destination_bytes = source_lane
    signed_name = 'scvtf' if name == 'ucvtf' else name[:-1] + 's' if name.endswith('u') else name
    precision = name in ('fcvt', 'fcvtl', 'fcvtn', 'fcvtxn')
    int_to_fp = name in ('scvtf', 'ucvtf')
    if precision:
        if integer_bits or fracbits or unsigned:
            raise ValueError('Precision conversion has no integer or fixed operand')
        if name == 'fcvt':
            if shape != 'scalar' or part or (source_lane, destination_lane) not in CONVERSION_PRECISION_BASES:
                raise ValueError('Invalid scalar precision conversion')
            word = CONVERSION_PRECISION_BASES[source_lane, destination_lane]
            form = f"FCVT_{ {2:'H',4:'S',8:'D'}[destination_lane]}{ {2:'H',4:'S',8:'D'}[source_lane]}_floatdp1"
        elif name == 'fcvtl':
            if shape != 'vector' or (source_lane, destination_lane) not in ((2, 4), (4, 8)):
                raise ValueError('Invalid widening precision conversion')
            word = 0x0e217800 | int(source_lane == 4) << 22 | part << 30
            source_part, source_bytes, destination_bytes = part, 8, 16
            form = 'FCVTL_asimdmisc_L'
        else:
            if (source_lane, destination_lane) not in ((4, 2), (8, 4)) or (name == 'fcvtxn' and source_lane != 8):
                raise ValueError('Invalid narrowing precision conversion')
            if shape == 'scalar':
                if name != 'fcvtxn' or part:
                    raise ValueError('Only FCVTXN has a scalar narrowing form')
                word, form = 0x7e616800, 'FCVTXN_asisdmisc_N'
            elif shape == 'vector':
                word = (0x2e616800 if name == 'fcvtxn' else 0x0e216800 | int(source_lane == 8) << 22) | part << 30
                source_bytes, destination_bytes, destination_part = 16, 8, part
                form = name.upper() + '_asimdmisc_N'
            else:
                raise ValueError('Invalid narrowing shape')
    elif name == 'fjcvtzs':
        if (source_lane, destination_lane, shape, integer_bits, fracbits, unsigned, part) != (8, 4, 'general', 32, 0, False, 0):
            raise ValueError('FJCVTZS converts D to W')
        word, form, destination_bank = 0x1e7e0000, 'FJCVTZS_32D_float2int', 'general'
    elif signed_name in CONVERSION_GENERAL_BASES:
        if unsigned != (name == 'ucvtf' or name.endswith('u')) or part:
            raise ValueError('Conversion mnemonic and signedness disagree')
        if shape == 'general':
            if integer_bits not in (32, 64) or not 0 <= fracbits <= integer_bits:
                raise ValueError('Invalid general integer or fraction width')
            integer_lane = source_lane if int_to_fp else destination_lane
            if integer_lane * 8 != integer_bits:
                raise ValueError('Integer lane width differs from general register width')
            fp_lane = destination_lane if int_to_fp else source_lane
            word = CONVERSION_GENERAL_BASES[signed_name] | int(unsigned) << 16
            if fracbits:
                if signed_name not in ('scvtf', 'fcvtzs'):
                    raise ValueError('Fixed conversions require SCVTF/UCVTF/FCVTZS/FCVTZU')
                word &= ~(1 << 21)
                word |= (64 - fracbits) << 10
            word |= int(integer_bits == 64) << 31 | {2: 3, 4: 0, 8: 1}[fp_lane] << 22
            source_bank, destination_bank = ('general', 'simd') if int_to_fp else ('simd', 'general')
            source_bytes, destination_bytes = source_lane, destination_lane
            widths = ({2: 'H', 4: 'S', 8: 'D'}[fp_lane] + str(integer_bits) if int_to_fp
                      else str(integer_bits) + {2: 'H', 4: 'S', 8: 'D'}[fp_lane])
            form = f"{name.upper()}_{widths}_float2{'fix' if fracbits else 'int'}"
        else:
            if integer_bits or source_lane != destination_lane or shape not in ('scalar', 'vector64', 'vector128'):
                raise ValueError('SIMD integer conversion requires equal lane widths')
            if shape == 'vector64' and source_lane == 8 or not 0 <= fracbits <= source_lane * 8:
                raise ValueError('Unallocated SIMD arrangement or fixed scale')
            if fracbits:
                if signed_name not in ('scvtf', 'fcvtzs'):
                    raise ValueError('Unallocated fixed conversion mnemonic')
                word = (0x0f00e400 if int_to_fp else 0x0f00fc00) | int(unsigned) << 29
                word |= (2 * source_lane * 8 - fracbits) << 16
                suffix = 'asisdshf_C' if shape == 'scalar' else 'asimdshf_C'
            else:
                word = CONVERSION_VECTOR_BASES[signed_name] | int(unsigned) << 29
                word |= 0x00580000 if source_lane == 2 else int(source_lane == 8) << 22
                suffix = ('asisdmisc' if shape == 'scalar' else 'asimdmisc') + ('fp16_R' if source_lane == 2 else '_R')
            word |= 0x50000000 if shape == 'scalar' else int(shape == 'vector128') << 30
            source_bytes = destination_bytes = source_lane if shape == 'scalar' else 8 if shape == 'vector64' else 16
            form = name.upper() + '_' + suffix
    else:
        raise ValueError('Unknown conversion mnemonic')
    scalar = shape in ('scalar', 'general')
    if scalar:
        destination_bytes = destination_lane
    merge = ('replace_destination' if destination_bank == 'general' else 'original_destination_if_nep' if scalar
             else 'preserve_low64' if destination_part else 'zero_upper64' if destination_bytes == 8 else 'replace_all128')
    used = {register for bank, register in ((source_bank, n), (destination_bank, d)) if bank == 'general' and register != 31}
    return_register = next(register for register in (30, 29, 28) if register not in used)
    return {'name': name, 'canonical_id': form, 'source_lane': source_lane, 'destination_lane': destination_lane,
        'source_bank': source_bank, 'destination_bank': destination_bank, 'source_bytes': source_bytes,
        'source_part': source_part, 'destination_part': destination_part, 'merge': merge,
        'integer_bits': integer_bits or (source_lane * 8 if not precision else 0), 'unsigned': unsigned,
        'fracbits': fracbits, 'rounding': CONVERSION_ROUNDING[signed_name if not precision else name],
        'lane': destination_lane, 'bytes': destination_bytes, 'scalar': scalar,
        'd': d, 'n': n, 'word': word | n << 5 | d, 'return_register': return_register,
        'writes_nzcv': name == 'fjcvtzs'}


def conversion_numerical_functions():
    specifications = [('fcvt', source, destination, 'scalar', 0, 0, False, 0)
                      for source, destination in CONVERSION_PRECISION_BASES]
    for name, pairs in (('fcvtl', ((2, 4), (4, 8))), ('fcvtn', ((4, 2), (8, 4))), ('fcvtxn', ((8, 4),))):
        specifications.extend((name, source, destination, 'vector', 0, 0, False, part)
                              for source, destination in pairs for part in (0, 1))
    specifications.append(('fcvtxn', 8, 4, 'scalar', 0, 0, False, 0))
    specifications.append(('fjcvtzs', 8, 4, 'general', 32, 0, False, 0))
    for signed_name in CONVERSION_GENERAL_BASES:
        for unsigned in (False, True):
            name = 'ucvtf' if signed_name == 'scvtf' and unsigned else signed_name[:-1] + 'u' if unsigned else signed_name
            int_to_fp = signed_name == 'scvtf'
            for integer_bits in (32, 64):
                for fp_lane in (2, 4, 8):
                    source, destination = (integer_bits // 8, fp_lane) if int_to_fp else (fp_lane, integer_bits // 8)
                    scales = (0, 1, integer_bits // 2, integer_bits) if signed_name in ('scvtf', 'fcvtzs') else (0,)
                    specifications.extend((name, source, destination, 'general', integer_bits, scale, unsigned, 0) for scale in scales)
            for lane, shape in ([(lane, 'scalar') for lane in (2, 4, 8)] +
                                [(lane, 'vector64') for lane in (2, 4)] + [(lane, 'vector128') for lane in (2, 4, 8)]):
                scales = (0, 1, lane * 4, lane * 8) if signed_name in ('scvtf', 'fcvtzs') else (0,)
                specifications.extend((name, lane, lane, shape, 0, scale, unsigned, 0) for scale in scales)
    functions = [conversion_numerical_operation(name, source, destination, shape, d, n, width, scale, unsigned, part)
                 for name, source, destination, shape, width, scale, unsigned, part in specifications for d, n in CONVERSION_ROLES]
    if len({operation['word'] for operation in functions}) != len(functions) or len({operation['canonical_id'] for operation in functions}) != 163:
        raise AssertionError('Conversion inventory has duplicate words or omits classic forms')
    return functions


def conversion_numerical_shape(operation):
    return tuple(operation[key] for key in ('canonical_id', 'source_lane', 'destination_lane', 'source_bank',
        'destination_bank', 'source_bytes', 'bytes', 'scalar', 'source_part', 'destination_part', 'fracbits'))


def conversion_exact_positive_bits(lane, significand, exponent):
    """Encode an exactly representable positive dyadic input using integers only."""
    fraction, bias = {2: (10, 15), 4: (23, 127), 8: (52, 1023)}[lane]
    leading = significand.bit_length() - 1
    biased = leading + exponent + bias
    maximum_exponent = bias * 2 + 1
    if biased >= maximum_exponent:
        return None
    shift = leading - fraction if biased > 0 else 1 - bias - exponent - fraction
    if shift > 0 and significand & ((1 << shift) - 1):
        return None
    encoded = significand >> shift if shift > 0 else significand << -shift
    if biased <= 0:
        return encoded if 0 < encoded < 1 << fraction else None
    return biased << fraction | encoded & ((1 << fraction) - 1)


def conversion_numerical_values(operation):
    bits, lane = operation['source_lane'] * 8, operation['source_lane']
    if operation['name'] in ('scvtf', 'ucvtf'):
        sign, mask = 1 << (bits - 1), (1 << bits) - 1
        precision = {2: 11, 4: 24, 8: 53}[operation['destination_lane']]
        values = [('exact', 2), ('zero', 0), ('one', 1), ('minus_one', mask), ('input_min', sign),
            ('input_max', mask if operation['unsigned'] else sign - 1), ('signed_max', sign - 1),
            ('signed_min_plus_one', sign + 1), ('unsigned_max_minus_one', mask - 1)]
        if precision < bits:
            values.extend((label, (1 << precision) + increment) for label, increment in
                          (('inexact', 1), ('tie_even', 1), ('tie_odd', 3), ('above_tie', 5)))
        else:
            values.append(('inexact', sign - 1))
        return values
    fraction = {2: 10, 4: 23, 8: 52}[lane]
    bias = {2: 15, 4: 127, 8: 1023}[lane]
    sign, one = 1 << (bits - 1), bias << fraction
    infinity = ((1 << (bits - fraction - 1)) - 1) << fraction
    values = [('exact', one + (1 << fraction)), ('zero', 0), ('negative_zero', sign),
        ('one', one), ('minus_one', one | sign), ('half', (bias - 1) << fraction),
        ('negative_half', ((bias - 1) << fraction) | sign), ('tie_even', one | (1 << (fraction - 1))),
        ('tie_odd', one + (1 << fraction) + (1 << (fraction - 1))), ('above_tie', one | (1 << (fraction - 1)) | 1),
        ('below_tie', (one | (1 << (fraction - 1))) - 1), ('inexact', one + 1),
        ('minimum_normal', 1 << fraction), ('maximum_subnormal', (1 << fraction) - 1),
        ('minimum_subnormal', 1), ('negative_subnormal', sign | 1), ('maximum_finite', infinity - 1),
        ('positive_infinity', infinity), ('negative_infinity', infinity | sign),
        ('qnan', infinity | 1 << (fraction - 1) | 0x15), ('negative_qnan', infinity | sign | 1 << (fraction - 1) | 0x15),
        ('snan', infinity | 0x2b), ('negative_snan', infinity | sign | 0x2b)]
    exponents = ({2: 10, 4: 23, 8: 52}[operation['destination_lane']] + 1,) if operation['name'] in ('fcvt', 'fcvtn', 'fcvtxn') else (
        operation['integer_bits'] - int(not operation['unsigned']) - operation['fracbits'],)
    for exponent in exponents:
        biased = exponent + bias
        if 0 < biased < infinity >> fraction:
            boundary = biased << fraction
            values.extend((f'range_{side}_{offset:+}', ((boundary + offset) | (sign if side == 'negative' else 0)))
                          for side in ('positive', 'negative') for offset in (-1, 0, 1))
    if operation['name'] in ('fcvt', 'fcvtl', 'fcvtn', 'fcvtxn'):
        for exponent in (-25, -24, -14, 15, 16, 17, -150, -149, -126, 127, 128):
            if 0 < exponent + bias < infinity >> fraction:
                boundary = (exponent + bias) << fraction
                values.extend((f'precision_boundary_{exponent}_{offset:+}', boundary + offset) for offset in (-1, 0, 1))
    dyadics = []
    if operation['name'] in ('fcvt', 'fcvtn', 'fcvtxn'):
        target_fraction, target_bias = {2: (10, 15), 4: (23, 127), 8: (52, 1023)}[operation['destination_lane']]
        dyadics.extend((('target_max_finite', (1 << (target_fraction + 1)) - 1, target_bias - target_fraction),
                       ('target_overflow_tie', (1 << (target_fraction + 2)) - 1, target_bias - target_fraction - 1),
                       ('target_zero_tie', 1, 1 - target_bias - target_fraction - 1),
                       ('target_normal_tie', (1 << (target_fraction + 1)) - 1, 1 - target_bias - target_fraction - 1)))
        if operation['destination_lane'] == 2:
            dyadics.extend((('alternative_half_max', 131008, 0), ('alternative_half_overflow_tie', 131040, 0)))
    elif operation['name'] not in ('scvtf', 'ucvtf', 'fcvtl'):
        integer_bits = 32 if operation['writes_nzcv'] else operation['integer_bits']
        limit = integer_bits - int(not operation['unsigned'])
        scale = operation['fracbits']
        dyadics.extend((('integer_max', (1 << limit) - 1, -scale),
                       ('integer_limit_below_tie', (1 << (limit + 1)) - 1, -scale - 1),
                       ('integer_limit_above_tie', (1 << (limit + 1)) + 1, -scale - 1)))
    for label, significand, exponent in dyadics:
        raw = conversion_exact_positive_bits(lane, significand, exponent)
        if raw is not None:
            values.extend(((label, raw), ('negative_' + label, raw | sign)))
    return values


def conversion_numerical_state(operation, index, values, control=0, sticky=False):
    initial = State()
    rng = random.Random(0x434f4e56455254 + index)
    initial.x[:] = [rng.getrandbits(64) for _ in range(31)]
    initial.sp = 0x48010000 + index % 16 * 16
    seed_extended_state(initial, index * 31 + 19)
    initial.reserved, initial.nzcv = VECTOR_NUMERICAL_CANARY, index % 16 << 28
    initial.fpcr, initial.fpsr = control, FP_REGISTER_MASKS['fpsr'] if sticky else 0
    lane, bits = operation['source_lane'], operation['source_lane'] * 8
    count = 1 if operation['scalar'] else operation['source_bytes'] // lane
    if len(values) != count or any(not 0 <= value < 1 << bits for value in values):
        raise ValueError('Invalid conversion input lanes')
    if operation['source_bank'] == 'general':
        if operation['n'] != 31:
            initial.x[operation['n']] = values[0] | (rng.getrandbits(32) << 32 if bits == 32 else 0)
    else:
        poison = ((1 << bits) - 1) if operation['name'] in ('scvtf', 'ucvtf') else next(
            value for label, value in conversion_numerical_values(operation) if label == 'snan')
        packed = sum(poison << (position * bits) for position in range(16 // lane))
        start = operation['source_part'] * (8 // lane)
        for position, value in enumerate(values, start):
            mask = ((1 << bits) - 1) << (position * bits)
            packed = (packed & ~mask) | value << (position * bits)
        initial.v[operation['n']][:] = [packed & MASK, packed >> 64]
    return initial


def conversion_numerical_corpus():
    functions, records, primary, declines = conversion_numerical_functions(), [], set(), set()
    def append(function, label, values, control=0, sticky=False):
        initial = conversion_numerical_state(functions[function], len(records), values, control, sticky)
        records.append({'function': function, 'function_index': function, 'case': len(records), 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})
    for function, operation in enumerate(functions):
        shape = conversion_numerical_shape(operation)
        count = 1 if operation['scalar'] else operation['source_bytes'] // operation['source_lane']
        values = dict(conversion_numerical_values(operation))
        if shape not in primary:
            primary.add(shape)
            for label, value in values.items():
                append(function, label, [value] * count)
            for control in FUSED_ROUNDING_CONTROLS[1:]:
                for label in ('half', 'negative_half', 'tie_even', 'tie_odd', 'inexact'):
                    if label in values:
                        append(function, label, [values[label]] * count, control)
            for label, value in values.items():
                if label.startswith(('target_', 'negative_target_')):
                    for control in FUSED_ROUNDING_CONTROLS[1:]:
                        append(function, label, [value] * count, control)
                if label.startswith(('alternative_half_', 'negative_alternative_half_')):
                    for control in FUSED_ROUNDING_CONTROLS:
                        append(function, label, [value] * count, control | CONVERSION_AHP)
            for control in CONVERSION_EXTRA_CONTROLS:
                for label in (('input_max', 'input_min', 'inexact') if operation['name'] in ('scvtf', 'ucvtf') else
                              ('snan', 'minimum_subnormal', 'inexact')):
                    append(function, label, [values[label]] * count, control)
            for control in (0, NUMERICAL_NEP):
                label = 'input_max' if operation['name'] in ('scvtf', 'ucvtf') else 'snan'
                append(function, 'sticky_' + label, [values[label]] * count, control, True)
            if count > 1:
                for position in range(count):
                    active = [values['exact']] * count
                    label = 'input_max' if operation['name'] in ('scvtf', 'ucvtf') else 'snan'
                    active[position] = values[label]
                    append(function, f'active_{label}_{position}', active)
            form = operation['canonical_id']
            if form not in declines:
                declines.add(form)
                for enable in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                    append(function, 'trap_enable_readback_only', [values['exact']] * count, enable)
        for control in (0, NUMERICAL_NEP):
            for label in ('exact', 'inexact'):
                append(function, 'roles_' + label, [values[label]] * count, control)
    if len(records) > 35000:
        raise AssertionError('Conversion corpus exceeded the approved bounded scope')
    return functions, records


def prepare_conversion_numerical_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *conversion_numerical_corpus(), CONVERSION_NUMERICAL_FOCUS)


def load_conversion_numerical_oracle(path=CONVERSION_NUMERICAL_ORACLE):
    functions, records = conversion_numerical_corpus()
    return load_full_frame_numerical_oracle(path, functions, len(records), CONVERSION_NUMERICAL_FOCUS)


def conversion_unicorn_flushed_javascript_difference(operation, initial, observed, expected):
    if (operation['name'] != 'fjcvtzs' or not initial.fpcr & NUMERICAL_FZ
            or initial.fpcr & NUMERICAL_AH or observed.nzcv != 0x40000000 or expected.nzcv != 0):
        return False
    source = initial.v[operation['n']][0]
    fraction_mask, exponent_mask = (1 << 52) - 1, 0x7ff << 52
    if source & exponent_mask or not source & fraction_mask:
        return False
    copied = State.from_buffer_copy(observed)
    copied.nzcv = expected.nzcv
    return bytes(copied) == bytes(expected)


def conversion_unicorn_difference(operation, initial, observed, expected):
    if conversion_unicorn_flushed_javascript_difference(operation, initial, observed, expected):
        return 'Unicorn FJCVTZS sets Z for a flushed subnormal; pinned source and full-frame QEMU clear Z'
    if (operation['name'] != 'fcvtzs' or not operation.get('fracbits')
            or operation.get('source_lane') != 2 or operation.get('destination_lane') != 2
            or operation.get('destination_bank') != 'simd' or not operation['scalar']
            or initial.fpcr & NUMERICAL_NEP):
        return None
    destination = operation['d']
    result = expected.v[destination][0]
    if not result & (1 << 15) or result >> 16 or observed.v[destination][0] != result | 0xffff0000:
        return None
    copied = State.from_buffer_copy(observed)
    copied.v[destination][0] = result
    if bytes(copied) != bytes(expected):
        return None
    return 'Unicorn signed scalar FP16 fixed FCVTZS sign-extends through bit31; pinned source and full-frame QEMU clear inactive bits'


def validate_conversion_original_effects(initial, original, operation):
    destination, lane = operation['d'], operation['destination_lane']
    if operation['destination_bank'] == 'general':
        if destination != 31 and lane == 4 and original.x[destination] >> 32:
            raise AssertionError('Original W conversion did not zero-extend')
        if operation['writes_nzcv'] and original.nzcv not in (0, 0x40000000):
            raise AssertionError('FJCVTZS wrote NZCV bits other than Z')
        return
    original_bytes = struct.pack('<2Q', *original.v[destination])
    initial_bytes = struct.pack('<2Q', *initial.v[destination])
    if operation['scalar']:
        upper = initial_bytes[lane:] if initial.fpcr & NUMERICAL_NEP else bytes(16 - lane)
        if original_bytes[lane:] != upper:
            raise AssertionError('Original scalar conversion did not merge old Vd or clear upper bits')
    elif operation['destination_part']:
        if original_bytes[:8] != initial_bytes[:8]:
            raise AssertionError('Original narrowing2 conversion changed preserved low64')
    elif operation['bytes'] == 8 and original_bytes[8:] != bytes(8):
        raise AssertionError('Original vector64 conversion did not clear upper64')


def conversion_numerical_runtime_cases(records):
    selected = {}
    for record in records:
        operation, label = record['operation'], record['label']
        initial = State.from_buffer_copy(record['initial'])
        form, shape = operation['canonical_id'], conversion_numerical_shape(operation)
        direction = ('precision' if operation['name'] in ('fcvt', 'fcvtl', 'fcvtn', 'fcvtxn') else
                     'from_integer' if operation['name'] in ('scvtf', 'ucvtf') else
                     'javascript' if operation['writes_nzcv'] else 'to_integer')
        if record['unsupported']:
            if initial.fpcr == NUMERICAL_TRAP_ENABLE_MASK:
                selected.setdefault(('decline_form', form), record)
            else:
                selected.setdefault(('decline_control', initial.fpcr), record)
        elif initial.fpsr == 0:
            if label == 'exact' and initial.fpcr == 0:
                selected.setdefault(('shape', shape), record)
            if label == 'inexact' and initial.fpcr == 0:
                selected.setdefault(('corner', form), record)
            if label in ('snan', 'input_max') and initial.fpcr == 0:
                selected.setdefault(('status', direction, operation['source_lane'], operation['destination_lane']), record)
            if label == 'inexact' and initial.fpcr in (NUMERICAL_NEP, NUMERICAL_AH, CONVERSION_AHP):
                selected.setdefault(('control', direction, operation['source_lane'], operation['destination_lane'], initial.fpcr), record)
            if operation['return_register'] != 30 and label == 'roles_inexact' and initial.fpcr == 0:
                selected.setdefault(('lr_operand', form), record)
    return list({record['case']: record for record in selected.values()}.values())


def conversion_numerical_helpers(records):
    selected = {}
    for record in records:
        operation = record['operation']
        if operation['d'] != 0 or operation['n'] != 1 or State.from_buffer_copy(record['initial']).fpcr != 0:
            continue
        if operation['name'] in ('scvtf', 'ucvtf') or record['label'] != 'snan':
            continue
        key = (operation['source_bank'], operation['destination_bank'], operation['source_lane'],
               operation['destination_lane'], operation['scalar'], operation['source_part'], operation['destination_part'])
        selected.setdefault(key, record)
    return list(selected.values())

COMPARISON_MINMAX_FOCUS = 'comparison_minmax_numerical'
COMPARISON_MINMAX_ORACLE = ROOT / '.stela/research/comparison-minmax/oracle/receipt.json'
COMPARISON_REGISTER_BASES = {'facge': (0x2e402c00, 0x2e20ec00), 'facgt': (0x2ec02c00, 0x2ea0ec00),
    'fcmeq': (0x0e402400, 0x0e20e400), 'fcmge': (0x2e402400, 0x2e20e400), 'fcmgt': (0x2ec02400, 0x2ea0e400)}
COMPARISON_ZERO_BASES = {'fcmeq': 0x0ea0d800, 'fcmge': 0x2ea0c800,
    'fcmgt': 0x0ea0c800, 'fcmle': 0x2ea0d800, 'fcmlt': 0x0ea0e800}
MINMAX_NAMES = ('fmax', 'fmin', 'fmaxnm', 'fminnm')
COMPARISON_MINMAX_BINARY_ROLES = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31), (31, 30, 29), (0, 1, 1))
COMPARISON_MINMAX_UNARY_ROLES = ((0, 1), (1, 1), (31, 31), (31, 30))
COMPARISON_FLAG_ROLES = ((1, 2), (31, 31), (30, 29))
COMPARISON_MINMAX_CONTROLS = (NUMERICAL_AH, NUMERICAL_FIZ, NUMERICAL_NEP, NUMERICAL_FZ,
    NUMERICAL_FZ16, NUMERICAL_DN, CONVERSION_AHP, NUMERICAL_AH | NUMERICAL_DN,
    NUMERICAL_AH | NUMERICAL_FZ, NUMERICAL_AH | NUMERICAL_FIZ)
COMPARISON_MINMAX_ZERO_CONTROLS = (0, *COMPARISON_MINMAX_CONTROLS[:-1])


def numerical_condition_holds(condition, nzcv):
    if not 0 <= condition < 16:
        raise ValueError('Invalid condition field')
    n, z, c, v = (bool(nzcv & (1 << bit)) for bit in (31, 30, 29, 28))
    base = (z, c, n, v, c and not z, n == v, n == v and not z, True)[condition >> 1]
    return not base if condition & 1 and condition != 15 else base


def comparison_minmax_operation(name, lane, width, scalar, d=0, n=1, m=2,
                                family='predicate', zero=False, condition=None, immediate=0):
    if lane not in (2, 4, 8) or any(not 0 <= register < 32 for register in (d, n, m)):
        raise ValueError('Invalid FP comparison/minmax format or register')
    letter = {2: 'H', 4: 'S', 8: 'D'}[lane]
    ftype = {2: 3, 4: 0, 8: 1}[lane]
    merge, output_kind = 'none', 'vector'
    if family == 'flag_compare':
        if not scalar or width != lane or name not in ('fcmp', 'fcmpe', 'fccmp', 'fccmpe'):
            raise ValueError('Invalid flag comparison shape')
        output_kind = 'flags'
        if name.startswith('fccmp'):
            if zero or condition is None or not 0 <= condition < 16 or not 0 <= immediate < 16:
                raise ValueError('Invalid conditional comparison fields')
            word = 0x1e200400 | int(name == 'fccmpe') << 4 | condition << 12 | immediate
            canonical = f'{name.upper()}_{letter}_floatccmp'
        else:
            if condition is not None or immediate:
                raise ValueError('Unconditional comparison has no condition/immediate')
            word = 0x1e202000 | int(name == 'fcmpe') << 4 | int(zero) << 3
            canonical = f"{name.upper()}_{letter}{'Z' if zero else ''}_floatcmp"
        word |= ftype << 22 | m << 16 | n << 5
        source_lanes = 1
    elif family == 'predicate':
        if condition is not None or immediate:
            raise ValueError('Predicate has no conditional flag fields')
        if not scalar and (lane, width) not in VECTOR_NUMERICAL_SHAPES or scalar and width != lane:
            raise ValueError('Unallocated predicate arrangement')
        if zero:
            if name not in COMPARISON_ZERO_BASES:
                raise ValueError('Unallocated zero predicate')
            word = COMPARISON_ZERO_BASES[name] | (0x00580000 if lane == 2 else int(lane == 8) << 22)
            suffix = ('asisdmisc' if scalar else 'asimdmisc') + ('fp16_FZ' if lane == 2 else '_FZ')
        else:
            if name not in COMPARISON_REGISTER_BASES:
                raise ValueError('Unallocated register predicate')
            half, standard = COMPARISON_REGISTER_BASES[name]
            word = half if lane == 2 else standard | int(lane == 8) << 22
            word |= m << 16
            suffix = ('asisdsame' if scalar else 'asimdsame') + ('fp16_only' if lane == 2 else '_only')
            merge = 'right_if_nep' if scalar else 'none'
        word |= 0x50000000 if scalar else int(width == 16) << 30
        word |= n << 5 | d
        canonical, source_lanes = name.upper() + '_' + suffix, 1 if scalar else width // lane
    elif family in ('minmax_binary', 'minmax_pair', 'minmax_reduce'):
        base = next((candidate for candidate in MINMAX_NAMES if name == candidate or name == candidate + 'p' or name == candidate + 'v'), None)
        if base is None or zero or condition is not None or immediate:
            raise ValueError('Invalid minmax mnemonic or flag fields')
        minimum, number = base.startswith('fmin'), base.endswith('nm')
        if family == 'minmax_binary':
            if name != base or scalar and width != lane or not scalar and (lane, width) not in VECTOR_NUMERICAL_SHAPES:
                raise ValueError('Unallocated binary minmax shape')
            if scalar:
                word = (0x1e206800 if number else 0x1e204800) | int(minimum) << 12 | ftype << 22
                canonical, merge = f'{name.upper()}_{letter}_floatdp2', 'left_if_nep'
            else:
                word = (0x0e400400 if number else 0x0e403400) if lane == 2 else (0x0e20c400 if number else 0x0e20f400) | int(lane == 8) << 22
                word |= int(minimum) << 23 | int(width == 16) << 30
                canonical = name.upper() + ('_asimdsamefp16_only' if lane == 2 else '_asimdsame_only')
            word |= m << 16
            source_lanes = 1 if scalar else width // lane
        elif family == 'minmax_pair':
            if name != base + 'p':
                raise ValueError('Invalid pairwise minmax mnemonic')
            if scalar:
                if width != lane:
                    raise ValueError('Scalar pair reads exactly two source lanes')
                word = (0x5e30c800 if number else 0x5e30f800) if lane == 2 else (0x7e30c800 if number else 0x7e30f800) | int(lane == 8) << 22
                word |= int(minimum) << 23
                canonical, source_lanes = name.upper() + ('_asisdpair_only_H' if lane == 2 else '_asisdpair_only_SD'), 2
            else:
                if (lane, width) not in VECTOR_NUMERICAL_SHAPES:
                    raise ValueError('Invalid vector pairwise arrangement')
                word = (0x2e400400 if number else 0x2e403400) if lane == 2 else (0x2e20c400 if number else 0x2e20f400) | int(lane == 8) << 22
                word |= int(minimum) << 23 | int(width == 16) << 30 | m << 16
                canonical, source_lanes = name.upper() + ('_asimdsamefp16_only' if lane == 2 else '_asimdsame_only'), width // lane
        else:
            if name != base + 'v' or not scalar or (lane, width) not in ((2, 8), (2, 16), (4, 16)):
                raise ValueError('Invalid across-vector minmax arrangement')
            word = ((0x0e30c800 if number else 0x0e30f800) | int(width == 16) << 30) if lane == 2 else (0x6e30c800 if number else 0x6e30f800)
            word |= int(minimum) << 23
            canonical, source_lanes = name.upper() + ('_asimdall_only_H' if lane == 2 else '_asimdall_only_SD'), width // lane
        word |= n << 5 | d
    else:
        raise ValueError('Unknown comparison/minmax family')
    return {'name': name, 'canonical_id': canonical, 'cohort_family': 'comparison' if family in ('flag_compare', 'predicate') else 'minmax',
        'family': family, 'lane': lane, 'bytes': lane if scalar else width, 'source_bytes': source_lanes * lane,
        'scalar': scalar, 'source_lane_count': source_lanes, 'output_kind': output_kind, 'merge': merge,
        'd': d, 'n': n, 'm': m, 'zero_form': zero, 'condition': condition, 'immediate_nzcv': immediate,
        'word': word, 'return_register': 30}


def comparison_minmax_functions():
    functions = []
    for name in ('fcmp', 'fcmpe'):
        for lane in (2, 4, 8):
            for n, m in COMPARISON_FLAG_ROLES:
                functions.append(comparison_minmax_operation(name, lane, lane, True, n=n, m=m, family='flag_compare'))
            for n, m in ([(1, m) for m in range(32)] + [(n, m) for n in (31, 30) for m in (0, 31)]):
                functions.append(comparison_minmax_operation(name, lane, lane, True, n=n, m=m, family='flag_compare', zero=True))
    for name in ('fccmp', 'fccmpe'):
        for lane in (2, 4, 8):
            for condition in range(16):
                for immediate in range(16):
                    functions.append(comparison_minmax_operation(name, lane, lane, True, family='flag_compare', condition=condition, immediate=immediate))
            for n, m in COMPARISON_FLAG_ROLES[1:]:
                functions.append(comparison_minmax_operation(name, lane, lane, True, n=n, m=m, family='flag_compare', condition=0))
    arrangements = [(lane, lane, True) for lane in (2, 4, 8)] + [(lane, width, False) for lane, width in VECTOR_NUMERICAL_SHAPES]
    for zero, names in ((False, COMPARISON_REGISTER_BASES), (True, COMPARISON_ZERO_BASES)):
        for name in names:
            for lane, width, scalar in arrangements:
                roles = [(d, n, 0) for d, n in COMPARISON_MINMAX_UNARY_ROLES] if zero else COMPARISON_MINMAX_BINARY_ROLES
                functions.extend(comparison_minmax_operation(name, lane, width, scalar, d, n, m, zero=zero) for d, n, m in roles)
    for base in MINMAX_NAMES:
        for lane, width, scalar in arrangements:
            functions.extend(comparison_minmax_operation(base, lane, width, scalar, d, n, m, 'minmax_binary') for d, n, m in COMPARISON_MINMAX_BINARY_ROLES)
            roles = [(d, n, 0) for d, n in COMPARISON_MINMAX_UNARY_ROLES] if scalar else COMPARISON_MINMAX_BINARY_ROLES
            functions.extend(comparison_minmax_operation(base + 'p', lane, width, scalar, d, n, m, 'minmax_pair') for d, n, m in roles)
        for lane, width in ((2, 8), (2, 16), (4, 16)):
            functions.extend(comparison_minmax_operation(base + 'v', lane, width, True, d, n, 0, 'minmax_reduce') for d, n in COMPARISON_MINMAX_UNARY_ROLES)
    if len(functions) != 2590 or len({op['word'] for op in functions}) != len(functions) or len({op['canonical_id'] for op in functions}) != 102:
        raise AssertionError('Comparison/minmax complete form inventory changed')
    return functions


def comparison_minmax_shape(operation):
    return tuple(operation[key] for key in ('name', 'family', 'lane', 'bytes', 'source_bytes', 'scalar', 'zero_form'))


def comparison_minmax_values(lane):
    fraction, bias = {2: (10, 15), 4: (23, 127), 8: (52, 1023)}[lane]
    sign, one = 1 << (lane * 8 - 1), bias << fraction
    infinity = ((1 << (lane * 8 - fraction - 1)) - 1) << fraction
    return [0, sign, one, one | sign, infinity, infinity | sign,
        infinity | 1 << (fraction - 1) | 0x15, infinity | sign | 1 << (fraction - 1) | 0x29,
        infinity | 0x2b, infinity | sign | 0x35], [1, sign | 1, (1 << fraction) - 1, sign | ((1 << fraction) - 1)]


def comparison_minmax_layouts(operation):
    values, denormals = comparison_minmax_values(operation['lane'])
    count = operation['source_lane_count']
    if count == 2:
        return [(list(pair), list(reversed(pair))) for pair in [(left, right) for left in values for right in values][:64]]
    layouts = []
    for position in range(count):
        for special in values[6:]:
            source = [values[2]] * count
            source[position] = special
            layouts.append((source, list(reversed(source))))
    # Distinct payloads and zeros straddle every tree level. Pair-vector layouts
    # retain separate sources so neither the operand order nor output halves fold.
    fraction = {2: 10, 4: 23, 8: 52}[operation['lane']]
    two, three = values[2] + (1 << fraction), values[2] + (1 << fraction) + (1 << (fraction - 1))
    patterns = [values, list(reversed(values)), [values[8], values[2], two, three],
        [values[8], three, values[2], two],
        [values[0], values[1]], [values[1], values[0]], denormals, list(reversed(denormals))]
    for index in range(64 - len(layouts)):
        pattern = patterns[index % len(patterns)]
        source = [pattern[(position + index // len(patterns)) % len(pattern)] for position in range(count)]
        right = [pattern[(count - position + index + 1) % len(pattern)] for position in range(count)]
        layouts.append((source, right))
    return layouts


def comparison_minmax_state(operation, index, left, right=None, control=0, flags=None, sticky=False):
    initial = State()
    rng = random.Random(0x434f4d504d494e + index)
    initial.x[:] = [rng.getrandbits(64) for _ in range(31)]
    initial.sp = 0x48010000 + index % 16 * 16
    seed_extended_state(initial, index * 31 + 23)
    initial.reserved, initial.nzcv = VECTOR_NUMERICAL_CANARY, (index % 16 << 28) if flags is None else flags
    initial.fpcr, initial.fpsr = control, FP_REGISTER_MASKS['fpsr'] if sticky else 0
    count, bits = operation['source_lane_count'], operation['lane'] * 8
    if len(left) != count or right is not None and len(right) != count:
        raise ValueError('Incorrect comparison/minmax source lane count')
    poison = comparison_minmax_values(operation['lane'])[0][8]
    for register, lanes in ((operation['n'], left), (operation['m'], right)):
        if lanes is None:
            continue
        packed = sum(poison << (position * bits) for position in range(16 // operation['lane']))
        for position, value in enumerate(lanes):
            if not 0 <= value < 1 << bits:
                raise ValueError('Invalid comparison/minmax input lane')
            mask = ((1 << bits) - 1) << (position * bits)
            packed = packed & ~mask | value << (position * bits)
        initial.v[register][:] = [packed & MASK, packed >> 64]
    return initial


def comparison_minmax_corpus():
    functions, records, primary, ah_primary, enable_forms = comparison_minmax_functions(), [], set(), set(), set()
    def append(function, label, left, right=None, control=0, flags=None, sticky=False):
        initial = comparison_minmax_state(functions[function], len(records), left, right, control, flags, sticky)
        records.append({'function': function, 'function_index': function, 'case': len(records), 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})
    for function, op in enumerate(functions):
        values, denormals = comparison_minmax_values(op['lane'])
        count, shape = op['source_lane_count'], comparison_minmax_shape(op)
        pair = lambda left, right: ([left] * count, [right] * count)
        controls = COMPARISON_MINMAX_CONTROLS
        direct_pairs = [(values[8], values[6]), (values[6], values[8]), (values[6], denormals[0]),
            (denormals[0], values[6]), (values[2], denormals[0]), (denormals[0], values[2]),
            (values[0], values[1]), (values[1], values[0]), (values[6], values[7]), (values[9], values[6])]
        if op['condition'] is not None:
            passing = next(flags << 28 for flags in range(16) if numerical_condition_holds(op['condition'], flags << 28))
            failing = next((flags << 28 for flags in range(16) if not numerical_condition_holds(op['condition'], flags << 28)), None)
            if op['n'] == 1 and op['m'] == 2:
                append(function, 'condition_taken', *pair(values[2], values[2]), flags=passing)
                if failing is not None:
                    append(function, 'condition_failed_snan', *pair(values[8], denormals[0]), flags=failing)
                if op['immediate_nzcv'] == 0:
                    for flags in range(16):
                        append(function, 'all_incoming_nzcv', *pair(values[8], denormals[0]), flags=flags << 28)
                    for enable in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                        append(function, 'enabled_condition_taken', *pair(values[8], denormals[0]), control=enable, flags=passing)
                        if failing is not None:
                            append(function, 'enabled_condition_failed', *pair(values[8], denormals[0]), control=enable, flags=failing)
                    if op['condition'] == 0:
                        for control in controls:
                            for left, right in (direct_pairs + [(values[6], values[2]), (values[2], values[6]), (denormals[1], values[0]), (values[0], denormals[1])]):
                                append(function, 'conditional_semantic', *pair(left, right), control=control, flags=passing)
            else:
                for control in (0, NUMERICAL_TRAP_ENABLE_MASK):
                    append(function, 'conditional_roles_taken', *pair(values[8], denormals[0]), control=control, flags=passing)
                    append(function, 'conditional_roles_failed', *pair(values[8], denormals[0]), control=control, flags=failing)
            continue
        if op['canonical_id'] not in enable_forms:
            enable_forms.add(op['canonical_id'])
            for enable in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                append(function, 'enabled_unconditional', [values[8]] * count,
                    None if op['zero_form'] or op['scalar'] and op['family'] == 'minmax_pair' or op['family'] == 'minmax_reduce' else [denormals[0]] * count, enable)
        if shape not in primary:
            primary.add(shape)
            if op['zero_form']:
                unary = values + denormals
                for control in COMPARISON_MINMAX_ZERO_CONTROLS:
                    for index, value in enumerate(unary if op['family'] == 'flag_compare' else unary[:12]):
                        append(function, f'zero_value_{index}', [value] * count, control=control)
            elif op['family'] in ('minmax_pair', 'minmax_reduce'):
                layouts = comparison_minmax_layouts(op)
                for index, (left, right) in enumerate(layouts):
                    append(function, f'layout_{index}', left, right if not op['scalar'] else None)
                for control in controls:
                    for index, (left, right) in enumerate([*layouts[:4], *layouts[-2:]]):
                        append(function, f'control_layout_{index}', left, right if not op['scalar'] else None, control, sticky=control == NUMERICAL_NEP and index == 3)
            else:
                for left_index, left in enumerate(values):
                    for right_index, right in enumerate(values):
                        append(function, f'matrix_{left_index}_{right_index}', *pair(left, right))
                if op['family'] != 'flag_compare' and (op['name'], op['lane']) not in ah_primary:
                    ah_primary.add((op['name'], op['lane']))
                    for left_index, left in enumerate(values):
                        for right_index, right in enumerate(values):
                            append(function, f'ah_matrix_{left_index}_{right_index}', *pair(left, right), control=NUMERICAL_AH)
                special_pairs = direct_pairs + ([(values[6], values[2]), (values[2], values[6])] if op['family'] == 'flag_compare' else [])
                for control in controls:
                    for index, (left, right) in enumerate(special_pairs):
                        append(function, f'control_pair_{index}', *pair(left, right), control)
                denormal_pairs = [(left, right) for left in denormals for right in (values[0], values[2], values[6], values[8])]
                for index, (left, right) in enumerate(denormal_pairs[:12 if op['family'] == 'flag_compare' else 16]):
                    append(function, f'denormal_pair_{index}', *pair(left, right))
        else:
            for control in (0, NUMERICAL_NEP):
                append(function, 'roles_snan' if control else 'roles_exact', [values[8] if control else values[2]] * count,
                    None if op['zero_form'] or op['scalar'] and op['family'] == 'minmax_pair' or op['family'] == 'minmax_reduce' else [values[2]] * count, control, sticky=control == NUMERICAL_NEP)
    if len(records) != 39724:
        raise AssertionError(f'Comparison/minmax planned corpus framing changed: {len(records)}')
    return functions, records


def prepare_comparison_minmax_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *comparison_minmax_corpus(), COMPARISON_MINMAX_FOCUS)


def load_comparison_minmax_oracle(path=COMPARISON_MINMAX_ORACLE):
    functions, records = comparison_minmax_corpus()
    return load_full_frame_numerical_oracle(path, functions, len(records), COMPARISON_MINMAX_FOCUS)


def validate_comparison_minmax_original_effects(initial, original, operation):
    if operation['output_kind'] == 'flags':
        if operation['condition'] is not None and not numerical_condition_holds(operation['condition'], initial.nzcv):
            if original.nzcv != operation['immediate_nzcv'] << 28 or original.fpsr != initial.fpsr:
                raise AssertionError('Failed conditional comparison evaluated arithmetic or lost fallback NZCV')
        return
    lane, destination = operation['lane'], operation['d']
    if operation['scalar']:
        merge_register = operation['m'] if operation['merge'] == 'right_if_nep' else operation['n']
        merge = struct.pack('<2Q', *initial.v[merge_register]) if operation['merge'] != 'none' and initial.fpcr & NUMERICAL_NEP else bytes(16)
        if struct.pack('<2Q', *original.v[destination])[lane:] != merge[lane:]:
            raise AssertionError('Comparison/minmax scalar inactive destination bits violated merge contract')
    elif operation['bytes'] == 8 and original.v[destination][1] != 0:
        raise AssertionError('Comparison/minmax vector64 did not clear upper64')

def fused_numerical_shape(operation):
    return tuple(operation[key] for key in ('name', 'lane', 'bytes', 'scalar')) + (operation['index'] is not None,)


def fused_numerical_form(operation):
    if operation['name'] in FUSED_SCALAR_BASES:
        return operation['name'], operation['lane']
    return (operation['name'], operation['scalar'], operation['index'] is not None,
            'h' if operation['lane'] == 2 else 'sd')


def fused_numerical_runtime_cases(records):
    selected = {}
    for record in records:
        operation = record['operation']
        initial = State.from_buffer_copy(record['initial'])
        control, label = initial.fpcr, record['label']
        form, shape = fused_numerical_form(operation), fused_numerical_shape(operation)
        if record['unsupported']:
            if control == NUMERICAL_TRAP_ENABLE_MASK:
                selected.setdefault(('trap_form', form), record)
            else:
                selected.setdefault(('trap_format', operation['lane'], control), record)
        elif initial.fpsr == 0:
            if label == 'one_one_one' and control == 0:
                selected.setdefault(('shape', shape), record)
            if label == 'single_round_residual' and control in (*FUSED_ROUNDING_CONTROLS, NUMERICAL_AH, NUMERICAL_NEP):
                selected.setdefault(('fused_control', form, control), record)
            if label in ('snan_addend', 'product_overflow_cancel') and control == 0:
                selected.setdefault(('semantic', form, label), record)
            if label == 'product_underflow_accumulate' and control == 0 and operation['name'] == 'fmadd':
                selected.setdefault(('underflow_format', operation['lane']), record)
            if not operation['scalar'] and control == 0 and label.startswith('active_snan_addend_'):
                selected[('mixed_status', shape)] = record
            if (operation['name'] == 'fmla' and operation['index'] not in (None, 0)
                    and (operation['scalar'] or operation['bytes'] == 16)
                    and control == 0 and label == 'roles_one_one_one'):
                selected.setdefault(('index', shape, operation['index']), record)
            if operation['name'] == 'fmadd' and operation['lane'] == 4 and label == 'roles_single_round_residual' and control == NUMERICAL_NEP:
                selected.setdefault(('alias', record['function']), record)
    return list({record['case']: record for record in selected.values()}.values())


def fused_numerical_helpers(records):
    selected = {}
    for record in records:
        operation = record['operation']
        if record['label'] == 'snan_addend' and State.from_buffer_copy(record['initial']).fpcr == 0:
            # One scalar, vector, scalar-indexed and vector-indexed representative
            # per format covers each numerical boundary without duplicating aliases.
            kind = ('scalar' if operation['name'] in FUSED_SCALAR_BASES
                    else ('scalar_indexed' if operation['scalar'] else
                          'vector_indexed' if operation['index'] is not None else 'vector'))
            selected.setdefault((kind, operation['lane']), record)
    return list(selected.values())


def comparison_minmax_runtime_cases(records):
    selected = {}
    for record in records:
        op, label = record['operation'], record['label']
        initial = State.from_buffer_copy(record['initial'])
        form, shape = op['canonical_id'], comparison_minmax_shape(op)
        if record['unsupported']:
            if initial.fpcr == NUMERICAL_TRAP_ENABLE_MASK:
                selected.setdefault(('refusal_form', form), record)
            selected.setdefault(('refusal_mask', op['cohort_family'], initial.fpcr), record)
        elif record.get('control_policy_success'):
            selected.setdefault(('failed_enabled_condition', op['condition'], initial.fpcr), record)
            selected.setdefault(('failed_enabled_form', form), record)
        elif op['condition'] is not None:
            if op['immediate_nzcv'] == 0 and label in ('condition_taken', 'condition_failed_snan'):
                selected.setdefault(('conditional_path', form, op['condition'], label), record)
            if op['condition'] == 0 and label == 'condition_failed_snan':
                selected.setdefault(('fallback', form, op['immediate_nzcv']), record)
        else:
            if initial.fpcr == 0 and initial.fpsr == 0:
                selected.setdefault(('shape', shape), record)
            if label in ('matrix_8_6', 'matrix_6_8', 'ah_matrix_8_6', 'ah_matrix_6_8'):
                selected.setdefault(('nan_priority', form, label), record)
            if op['merge'] != 'none' and initial.fpcr == NUMERICAL_NEP:
                selected.setdefault(('merge', form), record)
            if op['family'] == 'minmax_reduce' and label in ('layout_18', 'layout_19', 'layout_34', 'layout_35'):
                selected.setdefault(('tree', shape, label), record)
            if initial.fpsr:
                selected.setdefault(('sticky', form), record)
    return list({record['case']: record for record in selected.values()}.values())


def comparison_minmax_helpers(records, case_ids=None):
    selected = {}
    for record in records:
        op = record['operation']
        initial = State.from_buffer_copy(record['initial'])
        if (case_ids is not None and record['case'] not in case_ids or initial.fpcr or initial.fpsr
                or op['condition'] is not None or op['d'] != 0 or op['n'] != 1):
            continue
        selected.setdefault((op['family'], op['lane'], op['scalar'], op['bytes'], op['source_bytes'], op['zero_form']), record)
    return list(selected.values())


def vector_numerical_helpers(records):
    return [record for record in records if record['label'] == 'active_snan_left_0'
            and State.from_buffer_copy(record['initial']).fpcr == 0]


ROUND_INTEGRAL_FOCUS = 'round_integral_numerical'
ROUND_INTEGRAL_ORACLE = ROOT / '.stela/research/round-integral/oracle/receipt.json'
ROUND_INTEGRAL_SCALAR_BASES = {'frintn': 0x1e244000, 'frintp': 0x1e24c000,
    'frintm': 0x1e254000, 'frintz': 0x1e25c000, 'frinta': 0x1e264000,
    'frintx': 0x1e274000, 'frinti': 0x1e27c000, 'frint32z': 0x1e284000,
    'frint32x': 0x1e28c000, 'frint64z': 0x1e294000, 'frint64x': 0x1e29c000}
ROUND_INTEGRAL_VECTOR_BASES = {'frintn': 0x0e218800, 'frintp': 0x0ea18800,
    'frintm': 0x0e219800, 'frintz': 0x0ea19800, 'frinta': 0x2e218800,
    'frintx': 0x2e219800, 'frinti': 0x2ea19800, 'frint32z': 0x0e21e800,
    'frint32x': 0x2e21e800, 'frint64z': 0x0e21f800, 'frint64x': 0x2e21f800}
NUMERICAL_UNARY_ROLES = ((0, 1), (1, 1), (31, 31), (31, 30))
NUMERICAL_UNARY_CONTROLS = (NUMERICAL_AH, NUMERICAL_FIZ, NUMERICAL_FZ, NUMERICAL_FZ16,
    NUMERICAL_DN, CONVERSION_AHP, NUMERICAL_NEP, NUMERICAL_AH | NUMERICAL_FIZ,
    NUMERICAL_AH | NUMERICAL_FZ, NUMERICAL_AH | NUMERICAL_DN,
    NUMERICAL_FIZ | NUMERICAL_FZ, NUMERICAL_AH | NUMERICAL_FIZ | NUMERICAL_FZ)
ROUND_INTEGRAL_CASES = 27281
NUMERICAL_ROUND_SHIFT = 22
ROUND_INTEGRAL_HALF_VECTOR_OFFSET = 0x00580000


def round_integral_operation(name, lane, width, scalar, d=0, n=1):
    bounded = int(name[5:7]) if name.startswith(('frint32', 'frint64')) else None
    if (name not in ROUND_INTEGRAL_SCALAR_BASES or lane not in (2, 4, 8)
            or bounded and lane == 2 or any(not 0 <= register < 32 for register in (d, n))
            or scalar and width != lane or not scalar and (lane, width) not in VECTOR_NUMERICAL_SHAPES):
        raise ValueError('Unallocated integral rounding operation')
    if scalar:
        word = ROUND_INTEGRAL_SCALAR_BASES[name] | {2: 3, 4: 0, 8: 1}[lane] << 22
        canonical = name.upper() + "_" + {2: "H", 4: "S", 8: "D"}[lane] + "_floatdp1"
    else:
        word = ROUND_INTEGRAL_VECTOR_BASES[name] | (ROUND_INTEGRAL_HALF_VECTOR_OFFSET if lane == 2 else int(lane == 8) << 22)
        word |= int(width == 16) << 30
        canonical = f'{name.upper()}_asimdmisc{"fp16" if lane == 2 else ""}_R'
    return {'name': name, 'lane': lane, 'bytes': width, 'scalar': scalar, 'd': d, 'n': n,
        'word': word | n << 5 | d, 'canonical_id': canonical, 'bounded_bits': bounded,
        'source_lane_count': 1 if scalar else width // lane, 'output_kind': 'vector',
        'merge': 'old_destination_if_nep' if scalar else 'none', 'cohort_family': 'round_integral'}


def round_integral_functions():
    functions = []
    for name in ROUND_INTEGRAL_SCALAR_BASES:
        bounded = name.startswith(('frint32', 'frint64'))
        shapes = [(lane, lane, True) for lane in ((4, 8) if bounded else (2, 4, 8))]
        shapes += [(lane, width, False) for lane, width in VECTOR_NUMERICAL_SHAPES if not bounded or lane != 2]
        for lane, width, scalar in shapes:
            functions.extend(round_integral_operation(name, lane, width, scalar, d, n) for d, n in NUMERICAL_UNARY_ROLES)
    return functions


def numerical_unary_shape(operation):
    return tuple(operation[key] for key in ('name', 'lane', 'bytes', 'scalar'))


def numerical_unary_values(lane):
    fraction, bias = {2: (10, 15), 4: (23, 127), 8: (52, 1023)}[lane]
    sign, infinity = 1 << (lane * 8 - 1), (bias * 2 + 1) << fraction
    positive = [('zero', 0)]
    dyadics = (('quarter', 1, -2), ('half', 1, -1), ('threequarter', 3, -2),
        ('one', 1, 0), ('onehalf', 3, -1), ('two', 2, 0), ('twohalf', 5, -1),
        ('threehalf', 7, -1), ('fourhalf', 9, -1))
    positive += [(label, conversion_exact_positive_bits(lane, number, exponent)) for label, number, exponent in dyadics]
    for label, number in (('half', 1), ('onehalf', 3), ('twohalf', 5)):
        bits = conversion_exact_positive_bits(lane, number, -1)
        positive.extend(((label + '_below', bits - 1), (label + '_above', bits + 1)))
    last_fraction = conversion_exact_positive_bits(lane, (1 << (fraction + 1)) - 1, -1)
    integral = conversion_exact_positive_bits(lane, 1, fraction)
    positive += [('last_fraction', last_fraction), ('integral_threshold', integral), ('integral_next', integral + 1),
        ('minsubnormal', 1), ('maxsubnormal', (1 << fraction) - 1), ('minnormal', 1 << fraction),
        ('maxfinite', infinity - 1), ('infinity', infinity), ('qnan', infinity | 1 << (fraction - 1) | 3),
        ('snan', infinity | 5), ('qnan_payload', infinity | 1 << (fraction - 1) | 7)]
    return [(label + suffix, bits | signed) for label, bits in positive for suffix, signed in (('_positive', 0), ('_negative', sign))]


def round_integral_bound_values(operation):
    if not operation['bounded_bits']:
        return []
    lane, bound = operation['lane'], operation['bounded_bits'] - 1
    sign = 1 << (lane * 8 - 1)
    limit = conversion_exact_positive_bits(lane, 1, bound)
    values = [(label + suffix, bits | signed) for label, bits in
        (('bound_below', limit - 1), ('bound_exact', limit), ('bound_above', limit + 1))
        for suffix, signed in (('_positive', 0), ('_negative', sign))]
    for label, number, exponent in (('bound_maximum', (1 << bound) - 1, 0),
            ('bound_half_below', (1 << (bound + 1)) - 1, -1),
            ('bound_half_above', (1 << (bound + 1)) + 1, -1)):
        bits = conversion_exact_positive_bits(lane, number, exponent)
        if bits is not None:
            values.extend((label + suffix, bits | signed) for suffix, signed in (('_positive', 0), ('_negative', sign)))
    return values


def numerical_unary_state(operation, index, values, control=0, sticky=0):
    initial = State()
    rng = random.Random(0x524f554e44494e54 + index)
    initial.x[:] = [rng.getrandbits(64) for _ in range(31)]
    initial.sp, initial.nzcv = 0x48010000 + index % 16 * 16, (index % 16) << 28
    seed_extended_state(initial, index * 31 + 29)
    initial.reserved, initial.fpcr, initial.fpsr = VECTOR_NUMERICAL_CANARY, control, sticky
    lane, count = operation['lane'], operation['source_lane_count']
    if len(values) != count:
        raise ValueError('Incorrect integral rounding source lane count')
    bits = lane * 8
    poison = dict(numerical_unary_values(lane))['snan_negative']
    packed = sum(poison << (position * bits) for position in range(16 // lane))
    for position, value in enumerate(values):
        if not 0 <= value < 1 << bits:
            raise ValueError('Invalid integral rounding source lane')
        mask = ((1 << bits) - 1) << (position * bits)
        packed = packed & ~mask | value << (position * bits)
    initial.v[operation['n']][:] = [packed & MASK, packed >> 64]
    return initial


def round_integral_corpus():
    functions, records, enable_forms = round_integral_functions(), [], set()
    def append(function, label, values, control=0, sticky=0):
        initial = numerical_unary_state(functions[function], len(records), values, control, sticky)
        records.append({'function': function, 'function_index': function, 'case': len(records), 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})
    for function in range(0, len(functions), len(NUMERICAL_UNARY_ROLES)):
        op = functions[function]
        values, count = numerical_unary_values(op['lane']), op['source_lane_count']
        catalog = dict(values)
        bounds = round_integral_bound_values(op)
        for label, value in values + bounds:
            append(function, 'value_' + label, [value] * count)
        ties = [(label, value) for label, value in values if label.split('_')[0] in ('half', 'onehalf', 'twohalf')]
        # Fourteen signed values: exact ties and immediate neighbors of half/onehalf.
        ties = [(label, value) for label, value in ties if not label.startswith(('twohalf_below', 'twohalf_above'))]
        for control in (mode << NUMERICAL_ROUND_SHIFT for mode in range(4)):
            for label, value in ties + bounds:
                append(function, 'round_' + label, [value] * count, control)
        controlled = [(label, catalog[label]) for stem in ('qnan', 'snan', 'minsubnormal', 'maxsubnormal', 'half')
            for label in (stem + '_positive', stem + '_negative')]
        for control in NUMERICAL_UNARY_CONTROLS:
            for label, value in controlled:
                append(function, 'control_' + label, [value] * count, control)
        for ah in (NUMERICAL_AH, NUMERICAL_AH | NUMERICAL_FZ, NUMERICAL_AH | NUMERICAL_FIZ):
            for mode in range(4):
                for stem in ('half', 'onehalf', 'minsubnormal'):
                    for suffix in ('_positive', '_negative'):
                        label = stem + suffix
                        append(function, 'ah_round_' + label, [catalog[label]] * count, ah | mode << NUMERICAL_ROUND_SHIFT)
        if op['canonical_id'] not in enable_forms:
            enable_forms.add(op['canonical_id'])
            for control in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                append(function, 'trap_enable_readback_only', [catalog['half_positive']] * count, control)
        for role in range(1, len(NUMERICAL_UNARY_ROLES)):
            for label, control in (('snan_positive', 0), ('half_negative', NUMERICAL_NEP),
                    ('minsubnormal_negative', NUMERICAL_AH | NUMERICAL_FIZ), ('qnan_negative', NUMERICAL_DN)):
                append(function + role, 'alias_' + label, [catalog[label]] * count, control)
        if not op['scalar']:
            patterns = ('snan_positive', 'qnan_negative', 'minsubnormal_negative', 'infinity_positive')
            for control in (0, NUMERICAL_AH, NUMERICAL_FZ16 if op['lane'] == 2 else NUMERICAL_FZ):
                for pattern, label in enumerate(patterns):
                    for position in range(count):
                        active = [catalog['half_positive']] * count
                        active[position] = catalog[label]
                        append(function, f'mixed_{pattern}_{position}', active, control)
        for sticky in (1 << 4, 1, 1 << 27, FP_REGISTER_MASKS['fpsr']):
            append(function, 'sticky_status', [catalog['half_negative']] * count, sticky=sticky)
    if len(records) != ROUND_INTEGRAL_CASES:
        raise AssertionError(f'Integral rounding corpus exceeded approved scope: {len(records)}')
    return functions, records


def prepare_round_integral_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *round_integral_corpus(), ROUND_INTEGRAL_FOCUS)


def load_round_integral_oracle(path=ROUND_INTEGRAL_ORACLE):
    return load_full_frame_numerical_oracle(path, round_integral_functions(), ROUND_INTEGRAL_CASES, ROUND_INTEGRAL_FOCUS)


def validate_numerical_unary_original_effects(initial, original, operation):
    if operation['scalar']:
        lane, destination = operation['lane'], operation['d']
        merge = struct.pack('<2Q', *initial.v[destination]) if initial.fpcr & NUMERICAL_NEP else bytes(16)
        if struct.pack('<2Q', *original.v[destination])[lane:] != merge[lane:]:
            raise AssertionError('Unary numerical scalar inactive bits violated old-Vd NEP merge')
    elif operation['bytes'] == 8 and original.v[operation['d']][1] != 0:
        raise AssertionError('Unary numerical vector64 did not clear upper64')


def round_integral_runtime_cases(records):
    selected = {}
    for record in records:
        op, label = record['operation'], record['label']
        initial = State.from_buffer_copy(record['initial'])
        form, shape = op['canonical_id'], numerical_unary_shape(op)
        if record['unsupported']:
            selected.setdefault(('enable', form if initial.fpcr == NUMERICAL_TRAP_ENABLE_MASK else initial.fpcr), record)
        elif label == 'value_half_negative':
            selected.setdefault(('shape', shape), record)
        elif label == 'round_half_negative':
            selected.setdefault(('rounding', form, initial.fpcr), record)
        elif label == 'round_bound_half_below_negative':
            selected.setdefault(('post_round_range', op['name'], initial.fpcr), record)
        elif label == 'ah_round_half_negative' and op['name'] in ('frinti', 'frintx', 'frint32x', 'frint64x'):
            selected.setdefault(('ah_rounding', op['name'], initial.fpcr), record)
        elif label in ('value_bound_exact_positive', 'value_bound_exact_negative'):
            selected.setdefault(('sentinel_range', op['name'], label), record)
        elif label == 'control_snan_positive':
            selected.setdefault(('control', op['name'], initial.fpcr), record)
        elif label == 'control_minsubnormal_negative' and initial.fpcr in (NUMERICAL_AH, NUMERICAL_AH | NUMERICAL_FIZ, NUMERICAL_FZ16, NUMERICAL_FZ):
            selected.setdefault(('denormal', op['lane'], op['name'], initial.fpcr), record)
        elif label == 'control_half_negative' and initial.fpcr == NUMERICAL_NEP and op['scalar']:
            selected.setdefault(('merge', form), record)
        elif label == 'sticky_status':
            selected.setdefault(('sticky', op['name']), record)
        elif label.startswith('alias_'):
            selected.setdefault(('alias', op['name'], op['d'], op['n']), record)
        elif label == 'mixed_3_0' and op['bounded_bits'] and initial.fpcr == 0:
            selected.setdefault(('mixed_invalid_inexact', shape), record)
    return list({record['case']: record for record in selected.values()}.values())


def round_integral_helpers(records, case_ids=None):
    selected = {}
    for record in records:
        op, initial = record['operation'], State.from_buffer_copy(record['initial'])
        if (case_ids is not None and record['case'] not in case_ids or initial.fpcr or initial.fpsr
                or op['d'] != 0 or op['n'] != 1):
            continue
        selected.setdefault((op['bounded_bits'], op['lane'], op['scalar'], op['bytes']), record)
    return list(selected.values())


SQRT_NUMERICAL_FOCUS = 'sqrt_numerical'
SQRT_NUMERICAL_ORACLE = ROOT / '.stela/research/sqrt/oracle/receipt.json'
SQRT_SCALAR_BASE = 0x1e21c000
SQRT_VECTOR_BASE = 0x2ea1f800
SQRT_HALF_VECTOR_BASE = 0x2ef9f800
SQRT_NUMERICAL_CASES = 11123
SQRT_RANDOM_SEED = 0x5351525443415345


def sqrt_numerical_operation(lane, width, scalar, d=0, n=1):
    if (lane not in (2, 4, 8) or any(not 0 <= register < 32 for register in (d, n))
            or scalar and width != lane or not scalar and (lane, width) not in VECTOR_NUMERICAL_SHAPES):
        raise ValueError('Unallocated square-root arrangement')
    if scalar:
        word = SQRT_SCALAR_BASE | {2: 3, 4: 0, 8: 1}[lane] << 22
        canonical = 'FSQRT_' + {2: 'H', 4: 'S', 8: 'D'}[lane] + '_floatdp1'
    else:
        word = (SQRT_HALF_VECTOR_BASE if lane == 2 else SQRT_VECTOR_BASE | int(lane == 8) << 22) | int(width == 16) << 30
        canonical = 'FSQRT_asimdmisc' + ('fp16' if lane == 2 else '') + '_R'
    return {'name': 'fsqrt', 'lane': lane, 'bytes': width, 'scalar': scalar, 'd': d, 'n': n,
        'word': word | n << 5 | d, 'canonical_id': canonical,
        'source_lane_count': 1 if scalar else width // lane, 'output_kind': 'vector',
        'merge': 'old_destination_if_nep' if scalar else 'none', 'cohort_family': 'sqrt'}


def sqrt_numerical_functions():
    shapes = [(lane, lane, True) for lane in (2, 4, 8)]
    shapes += [(lane, width, False) for lane, width in VECTOR_NUMERICAL_SHAPES]
    return [sqrt_numerical_operation(lane, width, scalar, d, n)
            for lane, width, scalar in shapes for d, n in NUMERICAL_UNARY_ROLES]


def sqrt_numerical_values(lane):
    values = numerical_unary_values(lane)
    sign = 1 << (lane * 8 - 1)
    four = conversion_exact_positive_bits(lane, 4, 0)
    positive = [('square_' + str(number), conversion_exact_positive_bits(lane, number, 0))
                for number in (9, 16, 25, 49, 64)]
    positive += [('four_below', four - 1), ('four', four), ('four_above', four + 1),
                 ('three', conversion_exact_positive_bits(lane, 3, 0))]
    return values + [(label + suffix, bits | signed) for label, bits in positive
                     for suffix, signed in (('_positive', 0), ('_negative', sign))]


def sqrt_numerical_midpoints(lane):
    """Neighboring representable inputs around exact squared root midpoints."""
    fraction = {2: 10, 4: 23, 8: 52}[lane]
    values = []
    for index, root in enumerate((1 << fraction, (1 << fraction) + 1,
                                 3 << (fraction - 1), (1 << (fraction + 1)) - 2)):
        numerator, exponent = (root * 2 + 1) ** 2, -2 * fraction - 2
        shift = numerator.bit_length() - 1 - fraction
        floor = conversion_exact_positive_bits(lane, numerator >> shift, exponent + shift)
        if floor is None or numerator & ((1 << shift) - 1) == 0:
            raise AssertionError('Squared root midpoint must lie between representable inputs')
        values.extend(((f'midpoint_{index}_below', floor), (f'midpoint_{index}_above', floor + 1)))
    return values


def sqrt_numerical_corpus():
    functions, records, enable_forms = sqrt_numerical_functions(), [], set()
    def append(function, label, values, control=0, sticky=0):
        initial = numerical_unary_state(functions[function], len(records), values, control, sticky)
        records.append({'function': function, 'function_index': function, 'case': len(records), 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})
    rng = random.Random(SQRT_RANDOM_SEED)
    for function in range(0, len(functions), len(NUMERICAL_UNARY_ROLES)):
        op = functions[function]
        values, count = sqrt_numerical_values(op['lane']), op['source_lane_count']
        catalog = dict(values)
        for mode in range(4):
            for label, value in values + sqrt_numerical_midpoints(op['lane']):
                append(function, 'value_' + label, [value] * count, mode << NUMERICAL_ROUND_SHIFT)
        controlled = [(label, catalog[label]) for stem in ('qnan', 'snan', 'minsubnormal', 'maxsubnormal',
                      'minnormal', 'zero', 'infinity', 'two') for label in (stem + '_positive', stem + '_negative')]
        for control in NUMERICAL_UNARY_CONTROLS:
            for mode in range(4):
                for label, value in controlled:
                    append(function, 'control_' + label, [value] * count, control | mode << NUMERICAL_ROUND_SHIFT)
        for role in range(1, len(NUMERICAL_UNARY_ROLES)):
            for control in (0, NUMERICAL_NEP, NUMERICAL_AH, NUMERICAL_FZ16):
                for label in ('one_positive', 'two_positive', 'snan_negative', 'minsubnormal_negative'):
                    append(function + role, 'alias_' + label, [catalog[label]] * count, control)
        if not op['scalar']:
            for control in (0, NUMERICAL_AH, NUMERICAL_FIZ, NUMERICAL_FZ, NUMERICAL_FZ16, NUMERICAL_AH | NUMERICAL_FZ):
                for pattern, label in enumerate(('qnan_negative', 'snan_positive', 'two_negative',
                                                'minsubnormal_negative', 'minsubnormal_positive', 'infinity_positive')):
                    for position in range(count):
                        active = [catalog['two_positive'] if element % 2 == 0 else catalog['square_9_positive'] for element in range(count)]
                        active[position] = catalog[label]
                        append(function, f'mixed_{pattern}_{position}', active, control)
        for sticky in (1 << 4, 1, 1 << 27, FP_REGISTER_MASKS['fpsr']):
            for control in (0, NUMERICAL_AH):
                for label in ('one_positive', 'two_positive', 'two_negative', 'minsubnormal_positive'):
                    append(function, 'sticky_' + label, [catalog[label]] * count, control, sticky)
        if op['canonical_id'] not in enable_forms:
            enable_forms.add(op['canonical_id'])
            for control in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                append(function, 'trap_enable_readback_only', [catalog['two_positive']] * count, control)
        random_values = [rng.getrandbits(op['lane'] * 8) for _ in range(32)]
        for mode in range(4):
            for index, value in enumerate(random_values):
                append(function, f'bounded_random_{index}', [value] * count, mode << NUMERICAL_ROUND_SHIFT)
    if len(records) != SQRT_NUMERICAL_CASES:
        raise AssertionError(f'Square-root corpus exceeded approved scope: {len(records)}')
    return functions, records


def prepare_sqrt_numerical_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *sqrt_numerical_corpus(), SQRT_NUMERICAL_FOCUS)


def load_sqrt_numerical_oracle(path=SQRT_NUMERICAL_ORACLE):
    return load_full_frame_numerical_oracle(path, sqrt_numerical_functions(), SQRT_NUMERICAL_CASES, SQRT_NUMERICAL_FOCUS)


def sqrt_numerical_runtime_cases(records):
    selected = {}
    directed = ('zero_negative', 'one_positive', 'two_negative', 'infinity_positive',
                'infinity_negative', 'four_below_positive', 'maxfinite_positive', 'snan_negative')
    for record in records:
        op, label = record['operation'], record['label']
        initial = State.from_buffer_copy(record['initial'])
        form, shape = op['canonical_id'], numerical_unary_shape(op)
        if record['unsupported']:
            selected.setdefault(('enable', form if initial.fpcr == NUMERICAL_TRAP_ENABLE_MASK else initial.fpcr), record)
        elif label == 'value_two_positive':
            selected.setdefault(('rounding', shape, initial.fpcr), record)
        elif label in tuple('value_' + name for name in directed) and initial.fpcr == 0:
            selected.setdefault(('directed', shape, label), record)
        elif label in ('value_midpoint_0_below', 'value_midpoint_0_above') and initial.fpcr == 0:
            selected.setdefault(('near_midpoint', shape, label), record)
        elif label in ('control_minsubnormal_negative', 'control_qnan_positive') and initial.fpcr in NUMERICAL_UNARY_CONTROLS:
            selected.setdefault(('control', op['lane'], initial.fpcr, label), record)
        elif label == 'control_minsubnormal_positive' and initial.fpcr in (NUMERICAL_AH, NUMERICAL_AH | NUMERICAL_FZ,
                NUMERICAL_FIZ, NUMERICAL_FZ, NUMERICAL_FZ16):
            selected.setdefault(('positive_denormal', op['lane'], initial.fpcr), record)
        elif label == 'control_snan_positive' and initial.fpcr in (NUMERICAL_DN, NUMERICAL_AH | NUMERICAL_DN):
            selected.setdefault(('signaling_dn', op['lane'], initial.fpcr), record)
        elif label == 'control_two_positive' and initial.fpcr == NUMERICAL_NEP and op['scalar']:
            selected.setdefault(('merge', form), record)
        elif label.startswith('alias_') and initial.fpcr == NUMERICAL_NEP:
            selected.setdefault(('alias', op['lane'], op['d'], op['n']), record)
        elif label == 'sticky_two_positive':
            selected.setdefault(('sticky', form), record)
        elif label in ('mixed_2_0', 'mixed_4_0') and initial.fpcr == NUMERICAL_AH:
            selected.setdefault(('mixed', shape, label), record)
    return list({record['case']: record for record in selected.values()}.values())


def sqrt_numerical_helpers(records, case_ids=None):
    selected = {}
    for record in records:
        op, initial = record['operation'], State.from_buffer_copy(record['initial'])
        if (case_ids is not None and record['case'] not in case_ids or initial.fpcr or initial.fpsr
                or op['d'] != 0 or op['n'] != 1):
            continue
        selected.setdefault((op['lane'], op['scalar'], op['bytes']), record)
    return list(selected.values())


ESTIMATE_NUMERICAL_FOCUS = 'estimate_numerical'
REFINEMENT_NUMERICAL_FOCUS = 'refinement_numerical'
ESTIMATE_NUMERICAL_ORACLE = ROOT / '.stela/research/estimates/oracle/receipt.json'
REFINEMENT_NUMERICAL_ORACLE = ROOT / '.stela/research/refinements/oracle/receipt.json'
ESTIMATE_BASES = {'frecpe': (0x5ea1d800, 0x5ef9d800, 0x0ea1d800, 0x0ef9d800),
    'frsqrte': (0x7ea1d800, 0x7ef9d800, 0x2ea1d800, 0x2ef9d800),
    'frecpx': (0x5ea1f800, 0x5ef9f800, None, None),
    'urecpe': (None, None, 0x0ea1c800, None), 'ursqrte': (None, None, 0x2ea1c800, None)}
REFINEMENT_BASES = {'frecps': (0x0e20fc00, 0x0e403c00), 'frsqrts': (0x0ea0fc00, 0x0ec03c00)}
ESTIMATE_NUMERICAL_CASES = 36734
REFINEMENT_NUMERICAL_CASES = 12720
ESTIMATE_RPRES_SHIFT = 4
ESTIMATE_RPRES_MASK = 15
ESTIMATE_SINGLE_BITS = 32
ESTIMATE_SINGLE_FRACTION_BITS = 23
ESTIMATE_SINGLE_EXPONENT_MASK = 255
ESTIMATE_SINGLE_SIGN = 1 << (ESTIMATE_SINGLE_BITS - 1)
ESTIMATE_SINGLE_MASK = (1 << ESTIMATE_SINGLE_BITS) - 1
ESTIMATE_SINGLE_FRACTION_MASK = (1 << ESTIMATE_SINGLE_FRACTION_BITS) - 1
ESTIMATE_SINGLE_QUIET = 1 << (ESTIMATE_SINGLE_FRACTION_BITS - 1)
ESTIMATE_SINGLE_INFINITY = ESTIMATE_SINGLE_EXPONENT_MASK << ESTIMATE_SINGLE_FRACTION_BITS
ESTIMATE_SINGLE_NEGATIVE_DEFAULT_NAN = ESTIMATE_SINGLE_SIGN | ESTIMATE_SINGLE_INFINITY | ESTIMATE_SINGLE_QUIET
ESTIMATE_SINGLE_RECIP_EXPONENT_BASE = 2 * 127 - 1
ESTIMATE_SINGLE_RSQRT_EXPONENT_BASE = 3 * 127 - 1
ESTIMATE_TABLE_FRACTION_BITS = {False: 8, True: 11}
ESTIMATE_RESULT_FRACTION_BITS = {False: 8, True: 12}
ESTIMATE_RECIP_NUMERATOR_BITS = {False: 19, True: 26}
ESTIMATE_RSQRT_NUMERATOR_BITS = {False: 28, True: 39}
ESTIMATE_RANDOM_SEED = 0x455354494d415445
REFINEMENT_RANDOM_SEED = 0x524546494e454d45
ESTIMATE_UNSIGNED_VALUES = (0, 1, 0x3fffffff, 0x40000000, 0x7fffffff, 0x80000000, 0xff800000, 0xffffffff)


def estimate_operation(name, lane, width, scalar, d=0, n=1):
    unsigned = name.startswith('u')
    if (name not in ESTIMATE_BASES or lane not in (2, 4, 8)
            or any(not 0 <= register < 32 for register in (d, n))
            or scalar and width != lane or not scalar and (lane, width) not in VECTOR_NUMERICAL_SHAPES
            or unsigned and (scalar or lane != 4) or name == 'frecpx' and not scalar):
        raise ValueError('Unallocated estimate arrangement')
    base = ESTIMATE_BASES[name][(0 if scalar else 2) + int(lane == 2)]
    if base is None:
        raise ValueError('Unallocated estimate format')
    word = base | (int(lane == 8) << 22) | (int(not scalar and width == 16) << 30) | n << 5 | d
    canonical = name.upper() + ('_asisdmisc' if scalar else '_asimdmisc') + ('fp16_R' if lane == 2 else '_R')
    return {'name': name, 'word': word, 'lane': lane, 'bytes': width, 'scalar': scalar, 'd': d, 'n': n,
        'is_unsigned': unsigned, 'canonical_id': canonical, 'source_lane_count': 1 if scalar else width // lane,
        'output_kind': 'vector', 'merge': 'old_destination_if_nep' if scalar else 'none', 'cohort_family': 'estimate'}


def refinement_operation(name, lane, width, scalar, d=0, n=1, m=2):
    if (name not in REFINEMENT_BASES or lane not in (2, 4, 8)
            or any(not 0 <= register < 32 for register in (d, n, m))
            or scalar and width != lane or not scalar and (lane, width) not in VECTOR_NUMERICAL_SHAPES):
        raise ValueError('Unallocated refinement arrangement')
    word = REFINEMENT_BASES[name][int(lane == 2)] | int(lane == 8) << 22
    word |= 0x50000000 if scalar else int(width == 16) << 30
    word |= m << 16 | n << 5 | d
    canonical = name.upper() + ('_asisdsame' if scalar else '_asimdsame') + ('fp16_only' if lane == 2 else '_only')
    return {'name': name, 'word': word, 'lane': lane, 'bytes': width, 'scalar': scalar, 'd': d, 'n': n, 'm': m,
        'canonical_id': canonical, 'source_lane_count': 1 if scalar else width // lane,
        'output_kind': 'vector', 'merge': 'left_if_nep' if scalar else 'none', 'cohort_family': 'refinement'}


def estimate_functions():
    functions = []
    for name in ESTIMATE_BASES:
        shapes = [(lane, lane, True) for lane in (2, 4, 8)] if not name.startswith('u') else []
        if name != 'frecpx':
            shapes += [(lane, width, False) for lane, width in VECTOR_NUMERICAL_SHAPES if not name.startswith('u') or lane == 4]
        functions.extend(estimate_operation(name, lane, width, scalar, d, n) for lane, width, scalar in shapes for d, n in NUMERICAL_UNARY_ROLES)
    return functions


def refinement_functions():
    shapes = [(lane, lane, True) for lane in (2, 4, 8)] + [(lane, width, False) for lane, width in VECTOR_NUMERICAL_SHAPES]
    return [refinement_operation(name, lane, width, scalar, d, n, m) for name in REFINEMENT_BASES
            for lane, width, scalar in shapes for d, n, m in COMPARISON_MINMAX_BINARY_ROLES]


def estimate_table_input(operation, key, poison):
    if operation['is_unsigned']:
        return key << 23 | ((1 << 23) - 1 if poison else 0)
    fraction, bias = {2: (10, 15), 4: (23, 127), 8: (52, 1023)}[operation['lane']]
    reciprocal = operation['name'] == 'frecpe'
    shift = fraction - (8 if reciprocal or key >= 256 else 7)
    base = 256 if reciprocal or key >= 256 else 128
    exponent = bias if reciprocal or key < 256 else bias + 1
    return exponent << fraction | (key - base) << shift | ((1 << shift) - 1 if poison else 0)


def numerical_suppressed_enables(operation, initial):
    return operation.get('is_unsigned', False) or bool(initial.fpcr & NUMERICAL_AH)


def comparison_minmax_enabled_control(operation, initial):
    return operation['condition'] is not None and not numerical_condition_holds(operation['condition'], initial.nzcv)


def estimate_single_profile_state(operation, initial, enhanced):
    """Closed integer rules for the AH Single profile split; no host FP."""
    if operation['lane'] != 4 or operation['name'] not in ('frecpe', 'frsqrte') or not initial.fpcr & NUMERICAL_AH:
        raise ValueError('Only AH Single estimates have this profile split')
    expected = State.from_buffer_copy(initial)
    packed = 0
    input_precision = ESTIMATE_TABLE_FRACTION_BITS[enhanced]
    precision = ESTIMATE_RESULT_FRACTION_BITS[enhanced]
    for position in range(operation['source_lane_count']):
        source = initial.v[operation['n']][position // 2] >> (position % 2 * ESTIMATE_SINGLE_BITS) & ESTIMATE_SINGLE_MASK
        sign, exponent, fraction = source & ESTIMATE_SINGLE_SIGN, source >> ESTIMATE_SINGLE_FRACTION_BITS & ESTIMATE_SINGLE_EXPONENT_MASK, source & ESTIMATE_SINGLE_FRACTION_MASK
        if exponent == ESTIMATE_SINGLE_EXPONENT_MASK and fraction:
            result = ESTIMATE_SINGLE_NEGATIVE_DEFAULT_NAN if initial.fpcr & NUMERICAL_DN else source | ESTIMATE_SINGLE_QUIET
        elif exponent == 0:
            result = sign | ESTIMATE_SINGLE_INFINITY  # AH forces FIZ, including every subnormal.
        elif operation['name'] == 'frecpe':
            if exponent == ESTIMATE_SINGLE_EXPONENT_MASK or exponent >= ESTIMATE_SINGLE_RECIP_EXPONENT_BASE:
                result = sign  # AH forces output FZ and suppresses UFC.
            else:
                scaled = (1 << input_precision) + (fraction >> (ESTIMATE_SINGLE_FRACTION_BITS - input_precision))
                estimate = (((1 << ESTIMATE_RECIP_NUMERATOR_BITS[enhanced]) // (2 * scaled + 1)) + 1) // 2
                result = sign | (ESTIMATE_SINGLE_RECIP_EXPONENT_BASE - exponent) << ESTIMATE_SINGLE_FRACTION_BITS | (estimate & ((1 << precision) - 1)) << (ESTIMATE_SINGLE_FRACTION_BITS - precision)
        elif sign:
            result = ESTIMATE_SINGLE_NEGATIVE_DEFAULT_NAN
        elif exponent == ESTIMATE_SINGLE_EXPONENT_MASK:
            result = 0
        else:
            if exponent & 1:
                scaled = (1 << (input_precision - 1)) + (fraction >> (ESTIMATE_SINGLE_FRACTION_BITS - input_precision + 1))
                transformed = 2 * scaled + 1
            else:
                scaled = (1 << input_precision) + (fraction >> (ESTIMATE_SINGLE_FRACTION_BITS - input_precision))
                transformed = 2 * ((scaled & ~1) + 1)
            estimate = (math.isqrt(((1 << ESTIMATE_RSQRT_NUMERATOR_BITS[enhanced]) - 1) // transformed) + 1) // 2
            result = ((ESTIMATE_SINGLE_RSQRT_EXPONENT_BASE - exponent) // 2) << ESTIMATE_SINGLE_FRACTION_BITS | (estimate & ((1 << precision) - 1)) << (ESTIMATE_SINGLE_FRACTION_BITS - precision)
        packed |= result << (position * ESTIMATE_SINGLE_BITS)
    if operation['scalar'] and initial.fpcr & NUMERICAL_NEP:
        old = initial.v[operation['d']][0] | initial.v[operation['d']][1] << 64
        packed |= old & ~ESTIMATE_SINGLE_MASK
    expected.v[operation['d']][:] = [packed & MASK, packed >> 64]
    return expected


def estimate_profile_expectation(operation, initial, original, producer):
    if operation['lane'] != 4 or operation['name'] not in ('frecpe', 'frsqrte') or not initial.fpcr & NUMERICAL_AH:
        return None
    rpres = int(producer['cpu_registers']['ID_AA64ISAR2_EL1'], 16) >> ESTIMATE_RPRES_SHIFT & ESTIMATE_RPRES_MASK
    if rpres != 1:
        raise AssertionError('Estimate original capture no longer has calibrated RPRES1 profile')
    enhanced = estimate_single_profile_state(operation, initial, True)
    enhanced.fpcr = original.fpcr
    if bytes(enhanced) != bytes(original):
        raise AssertionError('Raw enhanced original estimate disagrees with independent full-state integer model')
    return estimate_single_profile_state(operation, initial, False)


def validate_refinement_original_effects(initial, original, operation):
    if operation['scalar']:
        lane = operation['lane']
        merge = struct.pack('<2Q', *initial.v[operation['n']]) if initial.fpcr & NUMERICAL_NEP else bytes(16)
        if struct.pack('<2Q', *original.v[operation['d']])[lane:] != merge[lane:]:
            raise AssertionError('Scalar refinement did not merge original Vn')
    elif operation['bytes'] == 8 and original.v[operation['d']][1]:
        raise AssertionError('Vector64 refinement did not clear upper64')
    if initial.fpcr & NUMERICAL_AH and original.fpsr != initial.fpsr:
        raise AssertionError('AH refinement generated unsuppressed status')


def validate_estimate_original_effects(initial, original, operation):
    validate_numerical_unary_original_effects(initial, original, operation)
    if numerical_suppressed_enables(operation, initial) and original.fpsr != initial.fpsr:
        raise AssertionError('Unsigned or AH estimate generated unsuppressed status')


def estimate_corpus():
    functions, records, enable_forms = estimate_functions(), [], set()
    rng = random.Random(ESTIMATE_RANDOM_SEED)
    def append(function, label, values, control=0, sticky=0):
        initial = numerical_unary_state(functions[function], len(records), values, control, sticky)
        records.append({'function': function, 'function_index': function, 'case': len(records), 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})
    for function in range(0, len(functions), len(NUMERICAL_UNARY_ROLES)):
        op = functions[function]
        count, lane, unsigned = op['source_lane_count'], op['lane'], op['is_unsigned']
        fraction, bias = {2: (10, 15), 4: (23, 127), 8: (52, 1023)}[lane]
        values = [(f'unsigned_{i}', value) for i, value in enumerate(ESTIMATE_UNSIGNED_VALUES)] if unsigned else numerical_unary_values(lane)
        catalog = dict(values)
        if op['name'] != 'frecpx':
            start = 256 if op['name'] in ('frecpe', 'urecpe') else 128
            for key in range(start, 512):
                for poison in (False, True):
                    append(function, f'table_{key}_{int(poison)}', [estimate_table_input(op, key, poison)] * count)
        else:
            for exponent in range((bias + 1) * 2):
                for tail in (0, 1):
                    for sign in (0, 1 << (lane * 8 - 1)):
                        append(function, f'exponent_{exponent}_{tail}_{int(bool(sign))}', [sign | exponent << fraction | tail])
        if not unsigned:
            for mode in range(4):
                for label, value in values:
                    append(function, 'value_' + label, [value] * count, mode << NUMERICAL_ROUND_SHIFT)
            controlled = [(label, catalog[label]) for stem in ('qnan', 'snan', 'minsubnormal', 'maxsubnormal',
                          'minnormal', 'zero', 'infinity', 'one') for label in (stem + '_positive', stem + '_negative')]
            for control in NUMERICAL_UNARY_CONTROLS:
                for label, value in controlled:
                    append(function, 'control_' + label, [value] * count, control)
            for mode in range(4):
                for label in ('one_positive', 'one_negative', 'minsubnormal_positive', 'minsubnormal_negative',
                              'snan_positive', 'snan_negative', 'maxfinite_positive', 'maxfinite_negative'):
                    append(function, 'ah_round_' + label, [catalog[label]] * count, NUMERICAL_AH | mode << NUMERICAL_ROUND_SHIFT)
            if op['name'] == 'frecpe':
                flush = NUMERICAL_FZ16 if lane == 2 else NUMERICAL_FZ
                for boundary, exponent in (('overflow', {2: -16, 4: -128, 8: -1024}[lane]),
                                           ('flush', {2: 14, 4: 126, 8: 1022}[lane])):
                    threshold = conversion_exact_positive_bits(lane, 1, exponent)
                    for offset in (-1, 0, 1):
                        for sign in (0, 1 << (lane * 8 - 1)):
                            for control in (0, flush, NUMERICAL_AH, NUMERICAL_AH | flush):
                                for mode in range(4):
                                    append(function, f'threshold_{boundary}_{offset}_{int(bool(sign))}',
                                           [(threshold + offset) | sign] * count, control | mode << NUMERICAL_ROUND_SHIFT)
            if op['name'] == 'frsqrte':
                for position in range(fraction):
                    for sign in (0, 1 << (lane * 8 - 1)):
                        for control in (0, NUMERICAL_AH, NUMERICAL_FZ16 if lane == 2 else NUMERICAL_FZ):
                            append(function, f'leading_{position}_{int(bool(sign))}', [(1 << position) | sign] * count, control)
        else:
            for control in NUMERICAL_UNARY_CONTROLS:
                for label, value in values:
                    append(function, 'control_' + label, [value] * count, control)
        selected_values = values[:4] if unsigned else [(label, catalog[label]) for label in
                          ('one_positive', 'snan_negative', 'minsubnormal_negative', 'zero_negative')]
        if op['canonical_id'] not in enable_forms:
            enable_forms.add(op['canonical_id'])
            for enable in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                for ah in (0, NUMERICAL_AH):
                    append(function, 'enabled_suppression', [selected_values[1][1]] * count, enable | ah)
        for role in range(1, len(NUMERICAL_UNARY_ROLES)):
            for control in (0, NUMERICAL_NEP, NUMERICAL_AH):
                for label, value in selected_values:
                    append(function + role, 'alias_' + label, [value] * count, control)
        if not op['scalar']:
            patterns = values[:4] if unsigned else [(label, catalog[label]) for label in
                       ('qnan_negative', 'snan_positive', 'minsubnormal_negative', 'infinity_positive')]
            for control in (0, NUMERICAL_AH, NUMERICAL_FZ16 if lane == 2 else NUMERICAL_FZ):
                for pattern, (_, value) in enumerate(patterns):
                    for position in range(count):
                        active = [values[1][1] if unsigned else catalog['one_positive']] * count
                        active[position] = value
                        append(function, f'mixed_{pattern}_{position}', active, control)
        for sticky in (1, 1 << 4, 1 << 27, FP_REGISTER_MASKS['fpsr']):
            for control in (0, NUMERICAL_AH):
                for label, value in selected_values:
                    append(function, 'sticky_' + label, [value] * count, control, sticky)
        for iteration in range(16):
            value = rng.getrandbits(lane * 8)
            for control in (0, NUMERICAL_AH):
                append(function, f'bounded_random_{iteration}', [value] * count, control)
    if len(records) != ESTIMATE_NUMERICAL_CASES:
        raise AssertionError(f'Estimate corpus exceeded approved scope: {len(records)}')
    return functions, records


def refinement_pairs(lane):
    v = dict(numerical_unary_values(lane))
    def positive(label):
        return v[label + '_positive']
    pairs = []
    for zero in (v['zero_positive'], v['zero_negative']):
        for infinity in (v['infinity_positive'], v['infinity_negative']):
            pairs.extend(((zero, infinity), (infinity, zero)))
    for one in (v['one_positive'], v['one_negative']):
        for infinity in (v['infinity_positive'], v['infinity_negative']):
            pairs.extend(((one, infinity), (infinity, one)))
    for left, right in (('one_positive', 'one_positive'), ('two_positive', 'one_positive'), ('one_positive', 'two_positive'),
            ('one_positive', 'onehalf_positive'), ('one_negative', 'one_positive'), ('one_positive', 'one_negative'),
            ('two_negative', 'one_negative'), ('half_positive', 'half_positive'), ('onehalf_positive', 'two_positive'),
            ('quarter_positive', 'fourhalf_positive'), ('fourhalf_positive', 'twohalf_positive'), ('two_positive', 'two_positive')):
        pairs.append((v[left], v[right]))
    one, two = positive('one'), positive('two')
    three = conversion_exact_positive_bits(lane, 3, 0)
    pairs.extend(((three, one), (one, three), (one+1, one-1), (one-1, one+1), (two+1, one), (three+1, one)))
    overflow = {2: 0x5c00, 4: 0x5f800000, 8: 0x5ff0000000000000}[lane]
    pairs.extend(((one+1, two-2), (one+2, three-3), (overflow, overflow),
                  (positive('minsubnormal'), positive('maxfinite')), (positive('minnormal'), positive('maxfinite')),
                  (positive('maxfinite'), positive('maxfinite'))))
    for label in ('qnan_positive', 'qnan_negative', 'snan_positive', 'snan_negative'):
        pairs.extend(((v[label], one), (one, v[label])))
    if len(pairs) != 48:
        raise AssertionError('Refinement directed foundation changed')
    return pairs


def refinement_corpus():
    functions, records, enable_forms = refinement_functions(), [], set()
    rng = random.Random(REFINEMENT_RANDOM_SEED)
    def append(function, label, pairs, control=0, sticky=0):
        initial = vector_numerical_state(functions[function], len(records), pairs, control)
        initial.fpsr = sticky
        records.append({'function': function, 'function_index': function, 'case': len(records), 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})
    for function in range(0, len(functions), len(COMPARISON_MINMAX_BINARY_ROLES)):
        op = functions[function]
        count, lane = op['source_lane_count'], op['lane']
        pairs, v = refinement_pairs(lane), dict(numerical_unary_values(lane))
        for control in (0, NUMERICAL_AH):
            for mode in range(4):
                for index, pair in enumerate(pairs):
                    append(function, f'directed_{index}', [pair] * count, control | mode << NUMERICAL_ROUND_SHIFT)
        matrix = [v[label] for label in ('qnan_positive', 'qnan_negative', 'snan_positive', 'snan_negative', 'one_positive', 'one_negative')]
        for control in (0, NUMERICAL_AH, NUMERICAL_DN, NUMERICAL_AH | NUMERICAL_DN):
            for left, x in enumerate(matrix):
                for right, y in enumerate(matrix):
                    append(function, f'nan_{left}_{right}', [(x, y)] * count, control)
        boundaries = [pairs[0], (v['minsubnormal_positive'], v['infinity_positive']),
            (v['minsubnormal_negative'], v['infinity_positive']), (v['infinity_positive'], v['minsubnormal_positive']),
            pairs[30], pairs[34 if op['name'] == 'frecps' else 35], pairs[36], (v['qnan_positive'], v['snan_negative'])]
        for control in NUMERICAL_UNARY_CONTROLS:
            for index, pair in enumerate(boundaries):
                append(function, f'control_{index}', [pair] * count, control)
        for role in range(1, len(COMPARISON_MINMAX_BINARY_ROLES)):
            for control in (0, NUMERICAL_NEP, NUMERICAL_AH):
                for index in (0, 30, 36, 40):
                    append(function + role, f'alias_{index}', [pairs[index]] * count, control)
        if not op['scalar']:
            flush = NUMERICAL_FZ16 if lane == 2 else NUMERICAL_FZ
            for control in (0, NUMERICAL_AH, flush, NUMERICAL_AH | flush):
                for pattern, pair in enumerate((pairs[39], pairs[44], boundaries[1], pairs[34 if op['name'] == 'frecps' else 35])):
                    for position in range(count):
                        active = [pairs[16]] * count
                        active[position] = pair
                        append(function, f'mixed_{pattern}_{position}', active, control)
        if op['canonical_id'] not in enable_forms:
            enable_forms.add(op['canonical_id'])
            for enable in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                for ah in (0, NUMERICAL_AH):
                    append(function, 'enabled_suppression', [pairs[44]] * count, enable | ah)
        for sticky in (1, 1 << 4, 1 << 27, FP_REGISTER_MASKS['fpsr']):
            for control in (0, NUMERICAL_AH):
                for index in (0, 30, 36, 44):
                    append(function, f'sticky_{index}', [pairs[index]] * count, control, sticky)
        for iteration in range(16):
            pair = (rng.getrandbits(lane * 8), rng.getrandbits(lane * 8))
            for control in (0, NUMERICAL_AH):
                append(function, f'bounded_random_{iteration}', [pair] * count, control)
    if len(records) != REFINEMENT_NUMERICAL_CASES:
        raise AssertionError(f'Refinement corpus exceeded approved scope: {len(records)}')
    return functions, records


def prepare_estimate_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *estimate_corpus(), ESTIMATE_NUMERICAL_FOCUS)


def prepare_refinement_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *refinement_corpus(), REFINEMENT_NUMERICAL_FOCUS)


def load_estimate_oracle(path=ESTIMATE_NUMERICAL_ORACLE):
    return load_full_frame_numerical_oracle(path, estimate_functions(), ESTIMATE_NUMERICAL_CASES, ESTIMATE_NUMERICAL_FOCUS)


def load_refinement_oracle(path=REFINEMENT_NUMERICAL_ORACLE):
    return load_full_frame_numerical_oracle(path, refinement_functions(), REFINEMENT_NUMERICAL_CASES, REFINEMENT_NUMERICAL_FOCUS)


def estimate_refinement_helpers(records, case_ids=None):
    selected = {}
    for record in records:
        op, initial = record['operation'], State.from_buffer_copy(record['initial'])
        if (case_ids is not None and record['case'] not in case_ids or initial.fpcr or initial.fpsr
                or op['d'] != 0 or op['n'] != 1):
            continue
        selected.setdefault(numerical_unary_shape(op), record)
    return list(selected.values())


def estimate_runtime_cases(records):
    selected = {}
    for record in records:
        op, label = record['operation'], record['label']
        initial = State.from_buffer_copy(record['initial'])
        form, shape = op['canonical_id'], numerical_unary_shape(op)
        if label == 'enabled_suppression':
            key = ('enable', form if initial.fpcr & NUMERICAL_TRAP_ENABLE_MASK == NUMERICAL_TRAP_ENABLE_MASK else op['name'], initial.fpcr)
            selected.setdefault(key, record)
        elif initial.fpcr == 0 and initial.fpsr == 0 and label in ('table_256_0', 'exponent_0_0_0'):
            selected.setdefault(('shape', shape), record)
        elif label == 'control_snan_negative' and initial.fpcr in (0, NUMERICAL_AH, NUMERICAL_DN, NUMERICAL_AH | NUMERICAL_DN):
            selected.setdefault(('nan', form, initial.fpcr), record)
        elif label in ('control_minsubnormal_negative', 'control_one_positive') and initial.fpcr in (NUMERICAL_NEP, NUMERICAL_FZ16, NUMERICAL_FZ, NUMERICAL_FIZ):
            selected.setdefault(('control', op['name'], initial.fpcr, label), record)
        elif label.startswith('threshold_') and initial.fpcr in (0, NUMERICAL_AH):
            selected.setdefault(('threshold', op['lane'], label, initial.fpcr), record)
        elif label == 'ah_round_one_positive':
            selected.setdefault(('ah_mode', op['name'], initial.fpcr), record)
        elif label.startswith('alias_'):
            selected.setdefault(('alias', op['name'], op['d'], op['n']), record)
        elif label.startswith('sticky_'):
            selected.setdefault(('sticky', form), record)
    return list({record['case']: record for record in selected.values()}.values())


def refinement_runtime_cases(records):
    selected = {}
    for record in records:
        op, label = record['operation'], record['label']
        initial = State.from_buffer_copy(record['initial'])
        form, shape = op['canonical_id'], numerical_unary_shape(op)
        if label == 'enabled_suppression':
            selected.setdefault(('enable', form if initial.fpcr & NUMERICAL_TRAP_ENABLE_MASK == NUMERICAL_TRAP_ENABLE_MASK else 'all', initial.fpcr), record)
        elif label in ('directed_17', 'directed_28', 'directed_36') or label in ('directed_34', 'directed_35') and op['lane'] == 2 and not initial.fpcr & NUMERICAL_AH:
            selected.setdefault(('directed', op['name'], op['lane'], label, initial.fpcr), record)
        elif label in ('nan_0_3', 'nan_2_1'):
            selected.setdefault(('nan', op['name'], op['lane'], label, initial.fpcr), record)
        elif (label in ('control_1', 'control_2') or label == 'control_7' and initial.fpcr == NUMERICAL_NEP) and initial.fpcr in (NUMERICAL_NEP, NUMERICAL_FZ16, NUMERICAL_FZ, NUMERICAL_FIZ):
            selected.setdefault(('control', op['name'], op['lane'], label, initial.fpcr), record)
        elif label.startswith('alias_') and initial.fpcr == NUMERICAL_NEP:
            selected.setdefault(('alias', op['name'], op['d'], op['n'], op['m']), record)
        elif label.startswith('sticky_'):
            selected.setdefault(('sticky', op['name'], op['lane']), record)
        elif label == 'mixed_3_0' and op['lane'] == 2 and initial.fpcr in (NUMERICAL_FZ16, NUMERICAL_AH | NUMERICAL_FZ16):
            selected.setdefault(('half_output_flush', shape, initial.fpcr), record)
        elif label == 'mixed_0_0' and initial.fpcr == 0:
            selected.setdefault(('shape', shape), record)
    return list({record['case']: record for record in selected.values()}.values())


BINARY_REMAINING_FOCUS = 'binary_remaining_numerical'
BINARY_REMAINING_ORACLE = ROOT / '.stela/research/fp-binary-remaining/oracle/receipt.json'
BINARY_REMAINING_REGISTER_BASES = {'fabd': (0x2ec01400, 0x2ea0d400),
    'faddp': (0x2e401400, 0x2e20d400), 'fmulx': (0x0e401c00, 0x0e20dc00)}
BINARY_REMAINING_INDEXED_BASES = {'fmul': 0x0f009000, 'fmulx': 0x2f009000}
BINARY_REMAINING_NEGATED_BASE = 0x1e208800
BINARY_REMAINING_PAIR_BASES = {2: 0x5e30d800, 4: 0x7e30d800, 8: 0x7e70d800}
BINARY_REMAINING_CONTROLS = (NUMERICAL_AH, NUMERICAL_FIZ, NUMERICAL_NEP, NUMERICAL_FZ,
    NUMERICAL_FZ16, NUMERICAL_DN, CONVERSION_AHP, NUMERICAL_AH | NUMERICAL_FIZ,
    NUMERICAL_AH | NUMERICAL_FZ, NUMERICAL_AH | NUMERICAL_FZ16,
    NUMERICAL_AH | NUMERICAL_DN, NUMERICAL_AH | NUMERICAL_NEP)
BINARY_REMAINING_CASES = 33518
BINARY_REMAINING_RANDOM_SEED = 0x42494e4152594650


def binary_remaining_operation(name, lane, width, scalar, d=0, n=1, m=2, index=None):
    if (lane not in (2, 4, 8) or any(not 0 <= register < 32 for register in (d, n))
            or scalar and width != lane or not scalar and (lane, width) not in VECTOR_NUMERICAL_SHAPES):
        raise ValueError('Unallocated remaining binary arrangement')
    pair = name == 'faddp'
    if pair and scalar:
        if index is not None or m is not None:
            raise ValueError('Scalar pair has exactly one source register')
        word = BINARY_REMAINING_PAIR_BASES[lane]
        canonical = 'FADDP_asisdpair_only_' + ('H' if lane == 2 else 'SD')
    elif name == 'fnmul':
        if not scalar or index is not None:
            raise ValueError('FNMUL is scalar and non-indexed')
        word = BINARY_REMAINING_NEGATED_BASE | {2: 3, 4: 0, 8: 1}[lane] << 22
        canonical = 'FNMUL_' + {2: 'H', 4: 'S', 8: 'D'}[lane] + '_floatdp2'
    elif index is not None:
        if (name not in BINARY_REMAINING_INDEXED_BASES or not 0 <= index < 16 // lane
                or m is None or lane == 2 and m >= 16):
            raise ValueError('Unallocated indexed source')
        word = BINARY_REMAINING_INDEXED_BASES[name] | int(scalar) << 28 | int(scalar or width == 16) << 30
        if lane == 2:
            word |= ((index >> 2) & 1) << 11 | (index & 3) << 20
        elif lane == 4:
            word |= 1 << 23 | ((index >> 1) & 1) << 11 | (index & 1) << 21
        else:
            word |= 3 << 22 | index << 11
        canonical = name.upper() + ('_asisdelem_' if scalar else '_asimdelem_') + ('RH_H' if lane == 2 else 'R_SD')
    elif name in BINARY_REMAINING_REGISTER_BASES:
        if name == 'faddp' and scalar:
            raise ValueError('Scalar pair requires its one-source form')
        half, standard = BINARY_REMAINING_REGISTER_BASES[name]
        word = (half if lane == 2 else standard | int(lane == 8) << 22)
        word |= int(scalar) << 28 | int(scalar or width == 16) << 30
        canonical = name.upper() + ('_asisdsame' if scalar else '_asimdsame') + ('fp16_only' if lane == 2 else '_only')
    else:
        raise ValueError('Unknown remaining binary mnemonic')
    if m is not None:
        if not 0 <= m < 32:
            raise ValueError('Invalid right source register')
        word |= m << 16
    elif not (pair and scalar):
        raise ValueError('Binary instruction requires a right source')
    return {'name': name, 'lane': lane, 'bytes': width, 'scalar': scalar, 'd': d, 'n': n, 'm': m,
        'index': index, 'word': word | n << 5 | d, 'canonical_id': canonical,
        'source_lane_count': 2 if pair and scalar else 1 if scalar else width // lane,
        'output_kind': 'vector', 'input_kind': 'scalar_pair' if pair and scalar else 'vector_pair' if pair else 'indexed' if index is not None else 'register',
        'merge': 'left_if_nep' if scalar and not pair else 'none', 'cohort_family': 'binary_remaining'}


def binary_remaining_functions():
    functions = []
    for name in ('fnmul', 'fabd', 'faddp', 'fmulx', 'fmul'):
        indexed_modes = (False, True) if name == 'fmulx' else (True,) if name == 'fmul' else (False,)
        shapes = [(lane, lane, True) for lane in (2, 4, 8)]
        if name != 'fnmul':
            shapes += [(lane, width, False) for lane, width in VECTOR_NUMERICAL_SHAPES]
        for indexed in indexed_modes:
            for lane, width, scalar in shapes:
                for index in (range(16 // lane) if indexed else (None,)):
                    roles = [(d, n, None) for d, n in NUMERICAL_UNARY_ROLES] if name == 'faddp' and scalar else COMPARISON_MINMAX_BINARY_ROLES
                    for d, n, m in roles:
                        if indexed and lane == 2:
                            m &= 15
                        functions.append(binary_remaining_operation(name, lane, width, scalar, d, n, m, index))
    if len(functions) != len({op['word'] for op in functions}):
        raise AssertionError('Remaining binary subject words must be unique')
    return functions


def binary_remaining_pairs(lane):
    v = dict(numerical_unary_values(lane))
    one, two, half = (v[name + '_positive'] for name in ('one', 'two', 'half'))
    sign, fraction = 1 << (lane * 8 - 1), {2: 10, 4: 23, 8: 52}[lane]
    pairs = [('one_one', one, one), ('one_two', one, two), ('opposed_one', one, one | sign),
        ('product_residual', one + 1, one - 1), ('product_round', one + 1, one + 1),
        ('sum_tie_even', one, ({2: 15, 4: 127, 8: 1023}[lane] - fraction - 1) << fraction),
        ('sum_tie_odd', one + 1, ({2: 15, 4: 127, 8: 1023}[lane] - fraction - 1) << fraction),
        ('negative_round', one | sign, one + 1), ('normal_boundary', v['minnormal_positive'], half),
        ('overflow', v['maxfinite_positive'], two), ('maximum', v['maxfinite_positive'], v['maxfinite_positive']),
        ('tiny', v['minsubnormal_positive'], half)]
    for left, right in (('zero', 'zero'), ('zero', 'infinity'), ('infinity', 'zero'), ('infinity', 'infinity')):
        for ls, rs in (('positive', 'positive'), ('positive', 'negative'), ('negative', 'positive'), ('negative', 'negative')):
            pairs.append((left + '_' + ls + '_' + right + '_' + rs, v[left + '_' + ls], v[right + '_' + rs]))
    for label in ('minsubnormal_positive', 'minsubnormal_negative', 'maxsubnormal_positive', 'minnormal_positive',
                  'qnan_positive', 'qnan_negative', 'snan_positive', 'snan_negative'):
        pairs.extend(((label + '_left', v[label], one), (label + '_right', one, v[label])))
    pairs.extend((('denormal_infinity', v['minsubnormal_positive'], v['infinity_negative']),
        ('infinity_denormal', v['infinity_negative'], v['minsubnormal_positive']),
        ('nan_denormal', v['qnan_negative'], v['minsubnormal_positive']),
        ('denormal_nan', v['minsubnormal_positive'], v['qnan_negative'])))
    if len(pairs) != 48:
        raise AssertionError('Remaining binary directed catalog changed')
    return pairs


def binary_remaining_state(op, case, pairs, control=0, sticky=0):
    if len(pairs) != (1 if op['input_kind'] == 'scalar_pair' else op['bytes'] // op['lane']):
        raise ValueError('Incorrect remaining binary active pair count')
    # The common binary state generator owns full-state canaries and poison.
    shape = dict(op, bytes=op['lane'] if op['scalar'] else op['bytes'], m=op['n'] if op['m'] is None else op['m'])
    initial = vector_numerical_state(shape, case, [(left, right) for left, right in pairs], control)
    initial.fpsr = sticky
    lane, bits = op['lane'], op['lane'] * 8
    poison = dict(numerical_unary_values(lane))['snan_positive']
    def store(register, values):
        packed = sum(poison << (position * bits) for position in range(16 // lane))
        for position, value in values:
            if not 0 <= value < 1 << bits:
                raise ValueError('Invalid remaining binary input bits')
            mask = ((1 << bits) - 1) << (position * bits)
            packed = packed & ~mask | value << (position * bits)
        initial.v[register][:] = [packed & MASK, packed >> 64]
    if op['input_kind'] == 'scalar_pair':
        store(op['n'], enumerate(pairs[0]))
    elif op['input_kind'] == 'vector_pair':
        half = len(pairs) // 2
        for register, active in ((op['n'], pairs[:half]), (op['m'], pairs[half:])):
            store(register, enumerate(value for pair in active for value in pair))
    elif op['index'] is not None:
        store(op['n'], enumerate(left for left, _ in pairs))
        store(op['m'], [(op['index'], pairs[0][1])])
    return initial


def binary_remaining_shape(op):
    return op['name'], op['lane'], op['bytes'], op['scalar'], op['input_kind']


def binary_remaining_corpus():
    functions, records, primary, enabled = binary_remaining_functions(), [], set(), set()
    rng = random.Random(BINARY_REMAINING_RANDOM_SEED)
    def append(function, label, pairs, control=0, sticky=0):
        initial = binary_remaining_state(functions[function], len(records), pairs, control, sticky)
        records.append({'function': function, 'function_index': function, 'case': len(records), 'label': label,
            'initial_state_sha256': digest(bytes(initial)), 'initial': bytes(initial)})
    for function, op in enumerate(functions):
        shape = binary_remaining_shape(op)
        count = 1 if op['input_kind'] == 'scalar_pair' else op['bytes'] // op['lane']
        pairs = binary_remaining_pairs(op['lane'])
        catalog = {label: (left, right) for label, left, right in pairs}
        v = dict(numerical_unary_values(op['lane']))
        if shape not in primary:
            primary.add(shape)
            for mode in range(4):
                for label, left, right in pairs:
                    append(function, 'directed_' + label, [(left, right)] * count, mode << NUMERICAL_ROUND_SHIFT)
            for mode in range(4):
                for label in ('product_round', 'negative_round', 'sum_tie_even', 'sum_tie_odd', 'opposed_one', 'tiny', 'overflow', 'normal_boundary'):
                    append(function, 'ah_round_' + label, [catalog[label]] * count, NUMERICAL_AH | mode << NUMERICAL_ROUND_SHIFT)
            matrix = [v['qnan_positive'], v['qnan_negative'], v['qnan_positive'] + 7, v['qnan_negative'] + 7, v['snan_positive'], v['snan_negative']]
            for control in (0, NUMERICAL_AH, NUMERICAL_DN, NUMERICAL_AH | NUMERICAL_DN):
                for left, x in enumerate(matrix):
                    for right, y in enumerate(matrix):
                        append(function, f'nan_matrix_{left}_{right}', [(x, y)] * count, control)
            for control in BINARY_REMAINING_CONTROLS:
                for label in ('product_round', 'negative_round', 'tiny', 'normal_boundary', 'denormal_infinity',
                              'infinity_denormal', 'nan_denormal', 'denormal_nan'):
                    append(function, 'control_' + label, [catalog[label]] * count, control)
            for sticky in (1, 1 << 4, 1 << 27, FP_REGISTER_MASKS['fpsr']):
                for control in (0, NUMERICAL_AH):
                    for label in ('one_one', 'product_round', 'snan_negative_left', 'tiny'):
                        append(function, 'sticky_' + label, [catalog[label]] * count, control, sticky)
            for mode in range(4):
                for iteration in range(8):
                    active = [(rng.getrandbits(op['lane'] * 8), rng.getrandbits(op['lane'] * 8)) for _ in range(count)]
                    append(function, f'bounded_random_{iteration}', active, mode << NUMERICAL_ROUND_SHIFT)
            if not op['scalar']:
                for control in (0, NUMERICAL_AH, NUMERICAL_FZ16, NUMERICAL_AH | NUMERICAL_FZ):
                    for label in ('one_two', 'snan_negative_left', 'tiny', 'denormal_infinity', 'negative_round', 'overflow'):
                        for position in range(count):
                            active = [catalog['one_one']] * count
                            active[position] = catalog[label]
                            append(function, f'mixed_{label}_{position}', active, control)
            for control in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                append(function, 'trap_enable_readback_only', [catalog['snan_negative_left']] * count, control)
        if op['canonical_id'] not in enabled:
            enabled.add(op['canonical_id'])
            for control in (*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), NUMERICAL_TRAP_ENABLE_MASK):
                append(function, 'trap_ah_enable_readback_only', [catalog['one_one']] * count, control | NUMERICAL_AH)
        if op['index'] not in (None, 0):
            for control in (0, NUMERICAL_AH, NUMERICAL_NEP):
                for label in ('one_two', 'product_round', 'snan_negative_right', 'denormal_infinity'):
                    append(function, 'indexed_' + label, [catalog[label]] * count, control)
        elif (op['d'], op['n'], op['m']) != ((0, 1, None) if op['input_kind'] == 'scalar_pair' else (0, 1, 2)):
            for control in (0, NUMERICAL_AH, NUMERICAL_NEP, NUMERICAL_FZ16):
                for label in ('one_two', 'product_round', 'snan_negative_right', 'tiny'):
                    append(function, 'alias_' + label, [catalog[label]] * count, control)
    if len(records) != BINARY_REMAINING_CASES:
        raise AssertionError('Remaining binary corpus exceeded approved bounded scope')
    return functions, records


def binary_remaining_runtime_cases(records):
    selected = {}
    for record in records:
        op, label = record['operation'], record['label']
        initial = State.from_buffer_copy(record['initial'])
        shape = binary_remaining_shape(op)
        if initial.fpcr & NUMERICAL_TRAP_ENABLE_MASK:
            enabled = initial.fpcr & NUMERICAL_TRAP_ENABLE_MASK
            selected.setdefault(('enable', op['canonical_id'] if enabled == NUMERICAL_TRAP_ENABLE_MASK else enabled, bool(initial.fpcr & NUMERICAL_AH)), record)
        elif label == 'directed_one_one' and initial.fpcr == 0:
            selected.setdefault(('shape', shape), record)
        elif label == 'directed_product_round':
            selected.setdefault(('round', op['name'], op['lane'], initial.fpcr), record)
        elif label in ('directed_zero_positive_infinity_positive', 'directed_snan_negative_left',
                       'directed_denormal_infinity', 'directed_sum_tie_odd') and initial.fpcr == 0:
            selected.setdefault(('semantic', op['name'], op['lane'], label), record)
        elif label == 'indexed_one_two' and initial.fpcr == 0:
            selected.setdefault(('index', shape, op['index']), record)
        elif label == 'control_denormal_nan':
            selected.setdefault(('control', op['lane'], initial.fpcr), record)
        elif label == 'alias_one_two' and initial.fpcr == NUMERICAL_NEP:
            selected.setdefault(('alias', op['name'], op['d'], op['n'], op['m']), record)
        elif label == 'sticky_product_round' and initial.fpcr == 0:
            selected.setdefault(('sticky', op['name']), record)
        elif label == 'mixed_one_two_0' and op['name'] == 'faddp' and initial.fpcr == 0:
            selected.setdefault(('pair_order', shape), record)
    return list({record['case']: record for record in selected.values()}.values())


def binary_remaining_helpers(records, case_ids=None):
    selected = {}
    for record in records:
        op, initial = record['operation'], State.from_buffer_copy(record['initial'])
        if (case_ids is not None and record['case'] not in case_ids or initial.fpcr or initial.fpsr
                or op['d'] != 0 or op['n'] != 1 or op['m'] not in (None, 2) or op['index'] not in (None, 0)):
            continue
        selected.setdefault(binary_remaining_shape(op), record)
    return list(selected.values())


def validate_binary_remaining_original_effects(initial, original, operation):
    if operation['scalar']:
        source = initial.v[operation['n']] if operation['merge'] != 'none' and initial.fpcr & NUMERICAL_NEP else (0, 0)
        merge = struct.pack('<2Q', *source)
        if struct.pack('<2Q', *original.v[operation['d']])[operation['lane']:] != merge[operation['lane']:]:
            raise AssertionError('Remaining binary scalar inactive bits violated merge/clear contract')


def prepare_binary_remaining_oracle(directory):
    return prepare_full_frame_numerical_oracle(directory, *binary_remaining_corpus(), BINARY_REMAINING_FOCUS)


def load_binary_remaining_oracle(path=BINARY_REMAINING_ORACLE):
    return load_full_frame_numerical_oracle(path, binary_remaining_functions(), BINARY_REMAINING_CASES, BINARY_REMAINING_FOCUS)


FULL_FRAME_NUMERICAL_COHORTS = {
    BINARY_REMAINING_FOCUS: {'loader': load_binary_remaining_oracle, 'runtime_cases': binary_remaining_runtime_cases,
        'helpers': binary_remaining_helpers, 'forms': 23, 'actual_helpers': True,
        'original_effects': validate_binary_remaining_original_effects, 'status_merge_source': 'n',
        'limits': 'Enabled nonstreaming H/S/D scalar FNMUL, scalar/vector FABD/FMULX/FADDP and indexed FMUL/FMULX only. All retained enables precisely refuse, including AH1; QEMU RAZ/WI observations receive no successful equality credit. Full original states and supplementary oracle limitations remain explicit. No trap delivery, disabled-feature, Apple hardware, application, OS or performance claim.'},
    VECTOR_NUMERICAL_FOCUS: {'loader': load_vector_numerical_oracle, 'runtime_cases': vector_numerical_runtime_cases,
        'helpers': vector_numerical_helpers, 'forms': 8,
        'limits': 'Enabled nonstreaming H/S/D vector arithmetic only. Full-frame original captures and retained-enable refusals remain separate; no enabled FP trap delivery, Apple hardware, application, OS or performance claim.'},
    FUSED_NUMERICAL_FOCUS: {'loader': load_fused_numerical_oracle, 'runtime_cases': fused_numerical_runtime_cases,
        'native_fma_operations': FUSED_NATIVE_OPERATIONS,
        'helpers': fused_numerical_helpers, 'forms': 24,
        'limits': 'Enabled nonstreaming scalar/vector/indexed H/S/D fused arithmetic only. Full-frame original observations compare under compatible controls; trap-delivery, disabled-feature, Apple hardware, complete application, OS and performance claims remain outside this cohort.'},
    CONVERSION_NUMERICAL_FOCUS: {'loader': load_conversion_numerical_oracle, 'runtime_cases': conversion_numerical_runtime_cases,
        'helpers': conversion_numerical_helpers, 'forms': 163,
        'limits': 'Enabled nonstreaming classic precision/integer/fixed-point conversion and JSCVT profile only. Full-frame original captures and retained-enable refusals remain separate; no enabled FP trap delivery, Apple hardware, application, OS or performance claim.'},
    COMPARISON_MINMAX_FOCUS: {'loader': load_comparison_minmax_oracle, 'runtime_cases': comparison_minmax_runtime_cases,
        'accepts_enabled_control': comparison_minmax_enabled_control, 'actual_helpers': True,
        'helpers': comparison_minmax_helpers, 'forms': 102,
        'limits': 'Enabled nonstreaming scalar/AdvSIMD comparison and minmax only. Direct full-frame original equality excludes failed-FCCMP retained-enable control-policy successes. No enabled trap delivery, disabled FP access, Apple hardware, process, OS or performance claim.'},
    ROUND_INTEGRAL_FOCUS: {'loader': load_round_integral_oracle, 'runtime_cases': round_integral_runtime_cases,
        'actual_helpers': True,
        'helpers': round_integral_helpers, 'forms': 47,
        'limits': 'Enabled nonstreaming scalar/AdvSIMD H/S/D integral rounding, including bounded 32/64-bit rounding, only. Full-frame original captures and retained-enable refusals remain separate; no enabled FP trap delivery, disabled FP access, Apple hardware, application, OS or performance claim.'},
    SQRT_NUMERICAL_FOCUS: {'loader': load_sqrt_numerical_oracle, 'runtime_cases': sqrt_numerical_runtime_cases,
        'actual_helpers': True,
        'helpers': sqrt_numerical_helpers, 'forms': 5,
        'limits': 'Enabled nonstreaming scalar/AdvSIMD H/S/D square root only. Full-frame original captures and retained-enable refusals remain separate; no enabled FP trap delivery, disabled FP access, Apple hardware, application, OS or performance claim.'},
    ESTIMATE_NUMERICAL_FOCUS: {'loader': load_estimate_oracle, 'runtime_cases': estimate_runtime_cases,
        'helpers': estimate_refinement_helpers, 'forms': 12, 'actual_helpers': True,
        'original_effects': validate_estimate_original_effects, 'accepts_enabled_control': numerical_suppressed_enables,
        'profile_expectation': estimate_profile_expectation, 'status_merge_source': 'd',
        'limits': 'Enabled nonstreaming standard RPRES-absent H/S/D estimates/exponent and unsigned 32-bit estimates only. All AH1 Single FRECPE/FRSQRTE states are separately counted standard-profile model comparisons against preserved, independently validated enhanced QEMU observations, including coincident results. Accepted AH1/unsigned retained enables use separate requested-FPCR control-policy comparisons; AH0 floating enables precisely refuse. No enabled trap delivery, RPRES-enabled guest CPU, Apple hardware, process/OS or performance claim.'},
    REFINEMENT_NUMERICAL_FOCUS: {'loader': load_refinement_oracle, 'runtime_cases': refinement_runtime_cases,
        'native_fma_operations': {'frecps': 'vfnmadd', 'frsqrts': 'vfnmadd'},
        'helpers': estimate_refinement_helpers, 'forms': 8, 'actual_helpers': True,
        'original_effects': validate_refinement_original_effects, 'accepts_enabled_control': numerical_suppressed_enables,
        'status_merge_source': 'n',
        'limits': 'Enabled nonstreaming H/S/D fused reciprocal and reciprocal-square-root refinements only. AH1 suppresses fresh status and accepts retained enables with separately counted requested-FPCR control-policy comparisons; AH0 enables precisely refuse. Original full frames and source/profile/control expectations remain distinct. No enabled trap delivery, Apple hardware, process/OS or performance claim.'},
}


def vector_numerical_runtime_cohort(cli, directory, oracle, compiler):
    return full_frame_numerical_runtime_cohort(cli, directory, oracle, compiler)


def full_frame_numerical_runtime_cohort(cli, directory, oracle, compiler,
                                      focus=VECTOR_NUMERICAL_FOCUS, cpu_target='baseline',
                                      target_id='x86_64-baseline'):
    fused = focus == FUSED_NUMERICAL_FOCUS
    conversion = focus == CONVERSION_NUMERICAL_FOCUS
    comparison_minmax = focus == COMPARISON_MINMAX_FOCUS
    family = FULL_FRAME_NUMERICAL_COHORTS[focus]
    unary = focus in (ROUND_INTEGRAL_FOCUS, SQRT_NUMERICAL_FOCUS)
    merge_source = family.get('status_merge_source')
    modern = conversion or comparison_minmax or unary or bool(merge_source)
    reuse_reference = comparison_minmax or unary or bool(merge_source)
    source = b''.join(struct.pack('<II', operation['word'], numerical_return_word(operation)) for operation in oracle['functions'])
    source_path, state_path = directory / 'vector-runtime.arm64', directory / 'vector-runtime-state.json'
    ram_address, ram = 0x240000000000, NUMERICAL_GUARD * 16
    memory_path = directory / 'vector-runtime-memory.json'
    memory_path.write_text(json.dumps({'regions': [{'guest_address': ram_address, 'virtual_bytes': len(ram),
        'initial_bytes': list(ram), 'readable': True, 'writable': True}]}))
    counts, transcripts = Counter(), []
    cache = directory / 'vector-runtime-cache'
    original = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    original.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
    original.mem_map(BASE, 8192)
    original.mem_map(STOP, 4096)

    def invoke(code, initial, entry, budget=16, cache_dir=cache):
        source_path.write_bytes(code)
        state_path.write_text(json.dumps(state_dict(initial)))
        report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path),
            '--guest-base', hex(BASE), '--entry', hex(entry), '--stop-pc', hex(STOP), '--cpu-target', cpu_target,
            '--state', str(state_path), '--block-budget', str(budget), '--cache-dir', str(cache_dir),
            '--memory', str(memory_path), '--read-memory', f'{hex(ram_address)}:{len(ram)}'], timeout=30))
        if (report['kind'] != 'native_block_run' or report['source_sha256'] != digest(code)
                or report['compiler_source_sha256'] != compiler or report['target_cpu'] != target_id):
            raise AssertionError('Numerical runtime source/compiler/target differs')
        memory = report['memory']
        if memory['memory_before'] != memory['memory_after'] or memory['memory_reads'][0]['hex'] != ram.hex():
            raise AssertionError('Vector runtime modified owned RAM')
        for name in ('compiled_blocks', 'disk_cache_hits', 'memory_cache_hits', 'floating_point_helpers'):
            value = report['outcome'][name]
            if not isinstance(value, int) or value < 0:
                raise AssertionError(f'Vector runtime omitted {name}')
            counts[name] += value
        transcripts.append({'source_hex': code.hex() if code != source else None,
            'source_sha256': digest(code), 'initial_state_hex': bytes(initial).hex(), 'entry': entry,
            'budget': budget, 'report': report})
        counts['invocations'] += 1
        return report, numerical_report_state(report['state'])

    def require(report, actual, expected, pc=STOP, reason='stop_address'):
        if report['pc'] != pc or report['outcome']['reason']['kind'] != reason or bytes(actual) != bytes(expected):
            write_evidence(ROOT / f'.stela/simd-{focus}-runtime-failure.json',
                {'kind': 'vector_numerical_runtime_failure', 'transcripts': transcripts,
                 'expected_state_hex': bytes(expected).hex(), 'expected_pc': pc, 'expected_reason': reason})
            raise AssertionError('Vector runtime complete-state mismatch; immutable failure retained')
        if reason == 'stop_address' and report['outcome']['last_exit'] != [STOP, NUMERICAL_RETURN_EXIT]:
            raise AssertionError('Vector runtime did not execute guest RET')
        counts['typed_unsupported_state_checks' if reason == 'floating_point_unsupported' else 'complete_state_comparisons'] += 1

    def check_original(code, initial, expected):
        original.mem_write(BASE, code)
        original.ctl_remove_cache(BASE, BASE + len(code))
        initialize_arm(original, initial)
        original.emu_start(BASE, STOP, count=64)
        if original.reg_read(arm.UC_ARM64_REG_PC) != STOP or bytes(capture_arm(original, initial)) != bytes(expected):
            raise AssertionError('Joined original vector complete state differs')
        counts['original_joined_complete_state_comparisons'] += 1

    selector = family['runtime_cases']
    selected = selector(oracle['records'])
    for record in selected:
        initial = State.from_buffer_copy(record['initial'])
        entry = BASE + record['function'] * 8
        report, actual = invoke(source, initial, entry)
        if record['unsupported']:
            require(report, actual, initial, entry, 'floating_point_unsupported')
            if report['outcome']['reason'] != {'kind': 'floating_point_unsupported', 'instruction_pc': entry,
                    'fpcr': initial.fpcr, 'enabled_exceptions': (initial.fpcr >> NUMERICAL_EXCEPTION_ENABLE_SHIFT) & NUMERICAL_EXCEPTION_FLAGS}:
                raise AssertionError('Vector requested trap enables were lost or refusal was imprecise')
        else:
            require(report, actual, State.from_buffer_copy(record['expected']))
            if record.get('equality_basis') == 'standard_profile_model':
                counts['profile_model_success_checks'] += 1
            elif record.get('control_policy_success'):
                counts['control_policy_success_checks'] += 1

    helpers = (family['helpers'](oracle['records'], oracle.get('raw_helper_case_ids')) if family.get('actual_helpers')
               else family['helpers'](oracle['records']))
    if not family.get('actual_helpers') and (not helpers or (not conversion and len(helpers) != (12 if fused else len(VECTOR_NUMERICAL_BASES) * len(VECTOR_NUMERICAL_SHAPES)))):
        raise AssertionError('Numerical helper boundary fixture omits an arrangement')
    for record in helpers:
        initial, expected = State.from_buffer_copy(record['initial']), State.from_buffer_copy(record['expected'])
        entry = BASE + record['function'] * 8
        first, actual = invoke(source, initial, entry, budget=1)
        require(first, actual, expected, entry + 4, 'budget_exhausted')
        if first['outcome']['floating_point_helpers'] != 1:
            raise AssertionError('Vector budget fixture did not complete exactly one helper')
        final, actual = invoke(source, actual, entry + 4, budget=1)
        require(final, actual, expected)
        counts['budget_helper_resume_checks'] += 1
        warm, actual = invoke(source, initial, entry)
        require(warm, actual, expected)
        if warm['outcome']['compiled_blocks'] != 0 or warm['outcome']['disk_cache_hits'] < 2:
            raise AssertionError('Vector helper/RET did not reuse persistent cache')
        counts['disk_cache_checks'] += 1
        operation = record['operation']
        loop = struct.pack('<4I', operation['word'], NUMERICAL_SUBS_X10_ONE, NUMERICAL_CBNZ_X10_BACK_TWO, RET)
        loop_initial, loop_expected = State.from_buffer_copy(initial), State.from_buffer_copy(expected)
        loop_initial.x[10] = NUMERICAL_CACHE_LOOP_ITERATIONS
        loop_expected.x[10], loop_expected.nzcv = 0, NUMERICAL_ZERO_CARRY_FLAGS
        repeated, actual = invoke(loop, loop_initial, BASE, budget=16)
        require(repeated, actual, loop_expected)
        if repeated['outcome']['floating_point_helpers'] != NUMERICAL_CACHE_LOOP_ITERATIONS or repeated['outcome']['memory_cache_hits'] < 2:
            raise AssertionError('Vector loop did not repeat helper and live cache effects')
        check_original(loop, loop_initial, loop_expected)
        counts['memory_cache_loop_checks'] += 1

        for control in ((NUMERICAL_NEP, 0) if modern else (NUMERICAL_NEP, VECTOR_NUMERICAL_ROUND_ZERO)):
            reference = record if reuse_reference else next(candidate for candidate in oracle['records'] if candidate['function'] == record['function']
                and candidate['label'] == record['label'] and State.from_buffer_copy(candidate['initial']).fpcr == control)
            chain_initial = State.from_buffer_copy(reference['initial'])
            control_register, status_register, clear_register = (20, 21, 22) if modern else (0, 3, 4)
            chain_initial.x[control_register] = control
            chain_initial.fpcr, chain_initial.fpsr = 0, FP_REGISTER_MASKS['fpsr']
            chain_expected = State.from_buffer_copy(reference['expected'])
            if modern:
                chain_expected.x[control_register] = control
                if reuse_reference:
                    chain_expected.fpcr = control
                    if (unary or merge_source) and operation['scalar'] and operation['merge'] != 'none' and control & NUMERICAL_NEP:
                        bits = operation['lane'] * 8
                        active_mask = (1 << bits) - 1
                        merge_register = operation[merge_source] if merge_source else operation['d']
                        merged = chain_initial.v[merge_register][0] | chain_initial.v[merge_register][1] << 64
                        result = chain_expected.v[operation['d']][0] & active_mask | merged & ~active_mask
                        chain_expected.v[operation['d']][:] = [result & MASK, result >> 64]
                    elif operation['output_kind'] == 'vector' and operation['scalar'] and operation['merge'] != 'none' and control & NUMERICAL_NEP:
                        bits = operation['lane'] * 8
                        active_mask = (1 << bits) - 1
                        merge_register = operation['m'] if operation['merge'] == 'right_if_nep' else operation['n']
                        merged = chain_initial.v[merge_register][0] | chain_initial.v[merge_register][1] << 64
                        result = chain_expected.v[operation['d']][0] & active_mask | merged & ~active_mask
                        chain_expected.v[operation['d']][:] = [result & MASK, result >> 64]
            else:
                chain_expected.x[:] = chain_initial.x
            chain_expected.x[status_register], chain_expected.x[clear_register], chain_expected.fpsr = chain_expected.fpsr, 0, 0
            chain = struct.pack('<7I', fp_register_operation('msr_fpcr', control_register)['word'],
                fp_register_operation('msr_fpsr', 31)['word'], operation['word'],
                fp_register_operation('mrs_fpsr', status_register)['word'], fp_register_operation('msr_fpsr', 31)['word'],
                fp_register_operation('mrs_fpsr', clear_register)['word'], numerical_return_word(operation))
            joined, actual = invoke(chain, chain_initial, BASE)
            require(joined, actual, chain_expected)
            if control & 7 == 0:
                check_original(chain, chain_initial, chain_expected)
            counts['control_status_chain_checks'] += 1
    if fused:
        record = next(record for record in oracle['records'] if record['operation']['name'] == 'fmadd'
                      and record['operation']['lane'] == 4 and record['label'] == 'single_round_residual'
                      and State.from_buffer_copy(record['initial']).fpcr == 0)
        operation = record['operation']
        chain = struct.pack('<4I', NUMERICAL_ADD_X7_ONE, operation['word'], NUMERICAL_ADD_X8_TWO, RET)
        initial = State.from_buffer_copy(record['initial'])
        expected = State.from_buffer_copy(record['expected'])
        expected.x[7], expected.x[8] = (expected.x[7] + 1) & MASK, (expected.x[8] + 2) & MASK
        report, actual = invoke(chain, initial, BASE)
        require(report, actual, expected)
        check_original(chain, initial, expected)
        counts['interior_fused_prefix_suffix_checks'] += 1
        initial.fpcr = NUMERICAL_INVALID_ENABLE
        expected = State.from_buffer_copy(initial)
        expected.x[7] = (expected.x[7] + 1) & MASK
        report, actual = invoke(chain, initial, BASE)
        require(report, actual, expected, BASE + 4, 'floating_point_unsupported')
        if report['outcome']['reason'] != {'kind': 'floating_point_unsupported', 'instruction_pc': BASE + 4,
                'fpcr': NUMERICAL_INVALID_ENABLE, 'enabled_exceptions': 1}:
            raise AssertionError('Interior fused refusal did not preserve exact pending instruction and enable')
        counts['interior_fused_precise_refusal_checks'] += 1
    transcript_name = f'{focus}-{target_id}' if fused or modern else focus
    for name in ('budget_helper_resume_checks', 'disk_cache_checks', 'memory_cache_loop_checks', 'control_status_chain_checks', 'control_policy_success_checks', 'profile_model_success_checks'):
        counts.setdefault(name, 0)
    snapshot = write_evidence(ROOT / f'.stela/simd-{transcript_name}-runtime-records.json', transcripts)
    return {**dict(counts), 'ram_bytes_per_invocation': len(ram),
            'transcript': {'path': str(snapshot.relative_to(ROOT)), 'sha256': digest(snapshot.read_bytes())}}


def run_fused_numerical_cohort(cli, oracle_path):
    return run_full_frame_numerical_cohort(cli, oracle_path, FUSED_NUMERICAL_FOCUS)


def run_conversion_numerical_cohort(cli, oracle_path):
    return run_full_frame_numerical_cohort(cli, oracle_path, CONVERSION_NUMERICAL_FOCUS)


def numerical_fma_expectation(operation, target_id, operations):
    if not operations or 'fma' not in target_id.split('+')[1:] or operation['lane'] == 2:
        return {}
    suffix = ('s' if operation['scalar'] else 'p') + ('s' if operation['lane'] == 4 else 'd')
    return {operations[operation['name']] + '132' + suffix: 1}


def run_full_frame_numerical_cohort(cli, oracle_path, focus):
    fused = focus == FUSED_NUMERICAL_FOCUS
    family = FULL_FRAME_NUMERICAL_COHORTS[focus]
    oracle = family['loader'](oracle_path)
    started = time.monotonic()
    cli_hash, harness_hash = digest(cli.read_bytes()), digest(Path(__file__).read_bytes())
    shared_paths = ('dev/differential.py', 'dev/evidence.py', 'dev/test_simd_differential.py',
                    'crates/stela-runtime/src/floating.rs', 'crates/stela-runtime/src/floating/comparison.rs',
                    'crates/stela-runtime/src/floating/minmax.rs', 'crates/stela-runtime/src/floating/rounding.rs', 'crates/stela-runtime/src/floating/sqrt.rs', 'crates/stela-runtime/src/floating/estimate.rs', 'crates/stela-runtime/src/floating/refinement.rs', 'crates/stela-runtime/src/floating/arithmetic.rs', 'crates/stela-runtime/src/blocks.rs',
                    'crates/stela-runtime/src/lib.rs', 'crates/stela-runtime/src/execution.rs')
    shared_hashes = {name: digest((ROOT / name).read_bytes()) for name in shared_paths}
    cpu_info = json.loads(subprocess.check_output([str(cli), 'cpu-info']))
    targets = [('baseline', 'x86_64-baseline')]
    if cpu_info['detected_target'] != 'x86_64-baseline':
        targets.append(('native', cpu_info['detected_target']))
    profiles, compiler = [], None
    with tempfile.TemporaryDirectory(prefix=f'stela-{focus}-') as temporary:
        for cpu_target, target_id in targets:
            directory = Path(temporary) / target_id
            directory.mkdir()
            batches, artifacts = [], []
            for index, operation in enumerate(oracle['functions']):
                batch = compile_batch(cli, directory, [{'operations': [operation]}], index,
                    block=True, cpu_target=cpu_target, target_id=target_id, guest_base=BASE + index * 8)
                batch.update(cohort=focus, oracle_path=str(oracle_path))
                if compiler is not None and batch['compiler'] != compiler:
                    raise AssertionError('Fused compiler changed during preparation')
                compiler = batch['compiler']
                accounting = numerical_native_accounting(batch)
                if fused and operation['lane'] == 2 and (len(batch['compiled_source']) != 4 or len(batch['native']) != NUMERICAL_HELPER_NATIVE_BYTES):
                    raise AssertionError('Fused half instruction is not a terminal helper')
                if fused and operation['lane'] != 2 and len(batch['compiled_source']) != 8:
                    raise AssertionError('Fused S/D instruction does not retain conditional fast path and guest RET')
                retained = retain_native_evidence(f'simd-{focus}', batch['compiled_source'], batch['native'],
                    batch['manifest'], accounting, Path(__file__).read_bytes())
                batches.append(batch)
                artifacts.append({'function': index, 'compilation': batch['receipt'], 'accounting': accounting, 'files': retained})
            optional = {opcode['mnemonic'] for opcode in cpu_info['simd_opcodes'] if opcode['minimum_target'] != 'x86_64-baseline'}
            if cpu_target == 'baseline' and any(optional & artifact['accounting']['static_opcode_histogram'].keys() for artifact in artifacts):
                raise AssertionError('Baseline fused code contains optional host opcodes')
            for artifact in artifacts:
                operation = artifact['accounting']['shape']
                histogram = artifact['accounting']['static_opcode_histogram']
                fused_mnemonics = {mnemonic: count for mnemonic, count in histogram.items()
                                   if mnemonic.startswith(FUSED_NATIVE_PREFIXES)}
                expected = numerical_fma_expectation(operation, target_id, family.get('native_fma_operations'))
                if fused_mnemonics != expected:
                    raise AssertionError(f'FMA3 opcode/feature guard failed: {target_id} {operation} {fused_mnemonics}')
            raw = bounded_cases(batches)
            raw['limits'] = 'Original QEMU captures every architectural register before transport clobbers. Raw helper exits verify exact PC and unchanged full state; actual Rust runtime completion is separate. Requested enables remain intact in native inputs. QEMU RAZ/WI observations receive no direct-original equality credit; accepted control-policy and standard-profile model successes are counted separately.'
            if family.get('actual_helpers'):
                oracle['raw_helper_case_ids'] = set(raw['raw_helper_case_ids'])
            runtime = full_frame_numerical_runtime_cohort(cli, directory, oracle, compiler,
                focus, cpu_target, target_id)
            profiles.append({'target_cpu': target_id, 'raw_native': raw, 'rust_runtime': runtime,
                             ('fma3_instruction_checks' if fused else 'feature_emission_checks'): len(artifacts), 'native_artifacts': artifacts})
    if (digest(cli.read_bytes()) != cli_hash or digest(Path(__file__).read_bytes()) != harness_hash
            or any(digest((ROOT / name).read_bytes()) != value for name, value in shared_hashes.items())):
        raise AssertionError('Fused executable, harness or shared source changed during verification')
    def sums(section, key):
        return sum(profile[section][key] for profile in profiles)

    report = {'kind': f'simd_{focus}_arm_vs_native_x86', 'passed': True, 'abi': BLOCK_ABI,
        'state_comparisons': sums('rust_runtime', 'complete_state_comparisons'),
        'runtime_complete_state_comparisons': sums('rust_runtime', 'complete_state_comparisons'),
        'runtime_typed_unsupported_state_checks': sums('rust_runtime', 'typed_unsupported_state_checks'),
        'runtime_budget_resume_checks': sums('rust_runtime', 'budget_helper_resume_checks'),
        'runtime_disk_cache_checks': sums('rust_runtime', 'disk_cache_checks'),
        'runtime_memory_cache_loop_checks': sums('rust_runtime', 'memory_cache_loop_checks'),
        'runtime_control_status_chain_checks': sums('rust_runtime', 'control_status_chain_checks'),
        'raw_native_state_and_exit_comparisons': sums('raw_native', 'raw_native_state_and_exit_comparisons'),
        'raw_original_complete_state_comparisons': sums('raw_native', 'raw_inline_original_complete_state_comparisons'),
        'raw_inline_complete_state_comparisons': sums('raw_native', 'raw_inline_complete_state_comparisons'),
        'raw_helper_unchanged_state_comparisons': sums('raw_native', 'raw_helper_unchanged_state_comparisons'),
        'raw_unsupported_unchanged_state_comparisons': sums('raw_native', 'raw_unsupported_unchanged_state_comparisons'),
        'original_full_frame_captures': len(oracle['records']), 'canonical_forms': family['forms'],
        'original_reference_classifications': dict(Counter('precise_refusal' if record['unsupported'] else record.get('equality_basis', 'direct_original') for record in oracle['records'])),
        'native_mxcsr_preservation_comparisons': sums('raw_native', 'caller_mxcsr_preservation_comparisons'),
        'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_hash,
        'harness_source_sha256': harness_hash, 'shared_sources_sha256': shared_hashes,
        'original_oracle_receipt_sha256': oracle['receipt_sha256'], 'original_producer': oracle['producer'],
        'control_readbacks': oracle['control_readbacks'], 'input_derivation': oracle['input_derivation'],
        'profiles': profiles, 'caller_mxcsr_wrapper_sha256': digest(NUMERICAL_MXCSR_WRAPPER),
        'verification_wall_seconds': time.monotonic() - started,
        'limits': family['limits']}
    if family.get('accepts_enabled_control'):
        report['runtime_control_policy_success_checks'] = sums('rust_runtime', 'control_policy_success_checks')
        report['raw_inline_control_policy_comparisons'] = sums('raw_native', 'raw_inline_control_policy_comparisons')
        report['runtime_profile_model_success_checks'] = sums('rust_runtime', 'profile_model_success_checks')
        report['raw_inline_profile_model_comparisons'] = sums('raw_native', 'raw_inline_profile_model_comparisons')
    write_evidence(ROOT / f'.stela/simd-{focus}-differential-report.json', report)
    print(json.dumps(report, indent=2))


def run_vector_numerical_cohort(cli, oracle_path):
    oracle = load_vector_numerical_oracle(oracle_path)
    started = time.monotonic()
    cli_hash, harness_hash = digest(cli.read_bytes()), digest(Path(__file__).read_bytes())
    shared_paths = ('dev/differential.py', 'dev/evidence.py', 'dev/test_simd_differential.py',
                    'crates/stela-runtime/src/floating.rs', 'crates/stela-runtime/src/floating/comparison.rs',
                    'crates/stela-runtime/src/floating/minmax.rs', 'crates/stela-runtime/src/floating/rounding.rs', 'crates/stela-runtime/src/floating/sqrt.rs', 'crates/stela-runtime/src/floating/estimate.rs', 'crates/stela-runtime/src/floating/refinement.rs', 'crates/stela-runtime/src/floating/arithmetic.rs', 'crates/stela-runtime/src/blocks.rs',
                    'crates/stela-runtime/src/lib.rs', 'crates/stela-runtime/src/execution.rs')
    shared_hashes = {name: digest((ROOT / name).read_bytes()) for name in shared_paths}
    batches, artifacts, checked, compiler = [], [], [], None
    cpu_info = json.loads(subprocess.check_output([str(cli), 'cpu-info']))
    with tempfile.TemporaryDirectory(prefix='stela-vector-numerical-') as temporary:
        directory = Path(temporary)
        for index, operation in enumerate(oracle['functions']):
            batch = compile_batch(cli, directory, [{'operations': [operation]}], index,
                block=True, guest_base=BASE + index * 8)
            batch.update(cohort=VECTOR_NUMERICAL_FOCUS, oracle_path=str(oracle_path))
            if compiler is not None and batch['compiler'] != compiler:
                raise AssertionError('Vector compiler changed during preparation')
            compiler = batch['compiler']
            accounting = numerical_native_accounting(batch)
            retained = retain_native_evidence('simd-vector_numerical', batch['compiled_source'], batch['native'],
                batch['manifest'], accounting, Path(__file__).read_bytes())
            batches.append(batch)
            artifacts.append({'function': index, 'compilation': batch['receipt'], 'accounting': accounting, 'files': retained})
        optional = {opcode['mnemonic'] for opcode in cpu_info['simd_opcodes'] if opcode['minimum_target'] != 'x86_64-baseline'}
        if any(optional & artifact['accounting']['static_opcode_histogram'].keys() for artifact in artifacts):
            raise AssertionError('Baseline vector numerical code contains optional host opcodes')
        if cpu_info['detected_target'] != 'x86_64-baseline':
            for index in (0, 14, 28):
                probe = compile_batch(cli, directory, [{'operations': [oracle['functions'][index]]}], 1000 + index,
                    block=True, cpu_target='native', target_id=cpu_info['detected_target'], guest_base=BASE + index * 8)
                if probe['compiler'] != compiler or probe['native'] != batches[index]['native']:
                    raise AssertionError('Checked vector numerical recipe differs from baseline')
                checked.append({'function': index, 'target_cpu': cpu_info['detected_target'],
                                'native_sha256': digest(probe['native']), 'baseline_bytes_identical': True})
        raw = bounded_cases(batches)
        raw['limits'] = 'QEMU original captures all GPR/SP/V/NZCV/FPCR/FPSR before transport clobbers. Reserved GuestState bytes are metadata canaries. Raw helper exits verify unchanged state and exact instruction PC; actual Rust runtime separately completes helpers. Requested controls remain unchanged; QEMU trap-enable RAZ/WI is excluded from successful native equality.'
        runtime = vector_numerical_runtime_cohort(cli, directory, oracle, compiler)
    if (digest(cli.read_bytes()) != cli_hash or digest(Path(__file__).read_bytes()) != harness_hash
            or any(digest((ROOT / name).read_bytes()) != value for name, value in shared_hashes.items())):
        raise AssertionError('Vector executable, harness or shared source changed during verification')
    report = {'kind': 'simd_vector_numerical_arm_vs_native_x86', 'passed': True, 'abi': BLOCK_ABI,
        'state_comparisons': runtime['complete_state_comparisons'],
        'runtime_complete_state_comparisons': runtime['complete_state_comparisons'],
        'runtime_typed_unsupported_state_checks': runtime['typed_unsupported_state_checks'],
        'runtime_budget_resume_checks': runtime['budget_helper_resume_checks'],
        'runtime_disk_cache_checks': runtime['disk_cache_checks'],
        'runtime_memory_cache_loop_checks': runtime['memory_cache_loop_checks'],
        'runtime_control_status_chain_checks': runtime['control_status_chain_checks'],
        'raw_native_state_and_exit_comparisons': raw['raw_native_state_and_exit_comparisons'],
        'raw_original_complete_state_comparisons': raw['raw_inline_complete_state_comparisons'],
        'raw_inline_complete_state_comparisons': raw['raw_inline_complete_state_comparisons'],
        'raw_helper_unchanged_state_comparisons': raw['raw_helper_unchanged_state_comparisons'],
        'raw_unsupported_unchanged_state_comparisons': raw['raw_unsupported_unchanged_state_comparisons'],
        'original_full_frame_captures': len(oracle['records']),
        'native_mxcsr_preservation_comparisons': raw['caller_mxcsr_preservation_comparisons'],
        'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_hash,
        'harness_source_sha256': harness_hash, 'shared_sources_sha256': shared_hashes,
        'original_oracle_receipt_sha256': oracle['receipt_sha256'], 'original_producer': oracle['producer'],
        'control_readbacks': oracle['control_readbacks'], 'input_derivation': oracle['input_derivation'],
        'raw_native': raw, 'rust_runtime': runtime, 'native_artifacts': artifacts,
        'checked_host_emission_identity': checked, 'caller_mxcsr_wrapper_sha256': digest(NUMERICAL_MXCSR_WRAPPER),
        'verification_wall_seconds': time.monotonic() - started,
        'limits': 'Enabled nonstreaming AdvSIMD H/S/D binary arithmetic only. Full-frame unchanged original instruction captures receive direct equality credit only under actual compatible controls. No numerical trap delivery, disabled-feature, Apple hardware, complete application, OS or performance claim.'}
    write_evidence(ROOT / '.stela/simd-vector_numerical-differential-report.json', report)
    print(json.dumps(report, indent=2))


def fp_register_runtime_cases(oracle):
    controls = (0, 1 << 22, 2 << 22, 3 << 22, NUMERICAL_NEP)
    helper_labels = {'fadd': 'one_opposite_one', 'fsub': 'one_one',
                     'fmul': 'minimum_normal_half', 'fdiv': 'denormal_zero_divisor'}
    selected = {}
    for record in oracle['records']:
        operation = record['operation']
        initial = State.from_buffer_copy(record['initial'])
        if ((operation['d'], operation['n'], operation['m']) != (0, 1, 2)
                or initial.fpcr not in controls or initial.fpsr != 0
                or record['label'] not in (helper_labels[operation['name']], 'one_positive_halfulp')):
            continue
        key = (operation['name'], operation['lane'], initial.fpcr, record['label'])
        selected.setdefault(key, record)
    if len(selected) != 4 * 3 * len(controls) * 2:
        raise AssertionError('FP register runtime selection omits a format, control or arithmetic boundary')
    return list(selected.values()), helper_labels


def fp_register_chain(record):
    words = [fp_register_operation('msr_fpcr', 0)['word'], fp_register_operation('msr_fpsr', 31)['word'],
             record['operation']['word'], fp_register_operation('mrs_fpsr', 3)['word'],
             fp_register_operation('msr_fpsr', 31)['word'], fp_register_operation('mrs_fpsr', 4)['word'],
             record['operation']['word'], fp_register_operation('mrs_fpsr', 5)['word'],
             fp_register_operation('msr_fpsr', 31)['word'], fp_register_operation('mrs_fpsr', 6)['word'], RET]
    initial = State.from_buffer_copy(record['initial'])
    control = initial.fpcr
    initial.x[0] = 0xfeedface00000000 | control
    initial.fpcr = control ^ (3 << 22)
    initial.fpsr = FP_REGISTER_MASKS['fpsr']
    intermediate = State.from_buffer_copy(record['expected'])
    intermediate.x[:] = initial.x
    intermediate.fpcr = control
    expected = State.from_buffer_copy(intermediate)
    expected.x[3] = expected.x[5] = expected.fpsr & FP_REGISTER_MASKS['fpsr']
    expected.x[4] = expected.x[6] = expected.fpsr = 0
    return struct.pack('<' + 'I' * len(words), *words), initial, intermediate, expected


def fp_register_runtime_cohort(cli, directory, numerical, compiler):
    records, helper_labels = fp_register_runtime_cases(numerical)
    counts, transcripts = Counter(), []
    cache = directory / 'fp-register-runtime-cache'
    source_path, state_path = directory / 'fp-register-chain.arm64', directory / 'fp-register-state.json'
    ram_address, ram = 0x240000000000, NUMERICAL_GUARD * 16
    memory_path = directory / 'fp-register-memory.json'
    memory_path.write_text(json.dumps({'regions': [{'guest_address': ram_address, 'virtual_bytes': len(ram),
        'initial_bytes': list(ram), 'readable': True, 'writable': True}]}))
    original = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    original.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
    base = BASE + 0x4000
    original.mem_map(base, 4096)
    original.mem_map(STOP, 4096)

    def invoke(code, initial, entry=base, budget=16, cache_dir=cache):
        source_path.write_bytes(code)
        state_path.write_text(json.dumps(state_dict(initial)))
        report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path),
            '--guest-base', hex(base), '--entry', hex(entry), '--stop-pc', hex(STOP),
            '--cpu-target', 'baseline', '--state', str(state_path), '--block-budget', str(budget),
            '--cache-dir', str(cache_dir), '--memory', str(memory_path),
            '--read-memory', f'{hex(ram_address)}:{len(ram)}'], timeout=30))
        if (report['kind'] != 'native_block_run' or report['source_sha256'] != digest(code)
                or report['compiler_source_sha256'] != compiler or report['target_cpu'] != 'x86_64-baseline'):
            raise AssertionError('FP register runtime report source/compiler/target differs')
        memory = report['memory']
        if memory['memory_before'] != memory['memory_after'] or memory['memory_reads'][0]['hex'] != ram.hex():
            raise AssertionError('FP register runtime changed owned guest RAM')
        for name in ('compiled_blocks', 'disk_cache_hits', 'memory_cache_hits', 'floating_point_helpers'):
            value = report['outcome'][name]
            if not isinstance(value, int) or value < 0:
                raise AssertionError(f'FP register runtime omitted {name}')
            counts[name] += value
        transcripts.append({'source_hex': code.hex(), 'initial_state_hex': bytes(initial).hex(),
                            'entry': entry, 'budget': budget, 'report': report})
        counts['invocations'] += 1
        return report, numerical_report_state(report['state'])

    def require(report, actual, expected, pc=STOP, reason='stop_address'):
        if report['pc'] != pc or report['outcome']['reason']['kind'] != reason or bytes(actual) != bytes(expected):
            write_evidence(ROOT / '.stela/simd-fp_registers-runtime-failure.json',
                {'kind': 'fp_register_runtime_failure', 'transcripts': transcripts,
                 'expected_state_hex': bytes(expected).hex(), 'expected_pc': pc, 'expected_reason': reason})
            raise AssertionError('FP register runtime complete-state mismatch; immutable failure retained')
        if reason == 'stop_address' and report['outcome']['last_exit'] != [STOP, NUMERICAL_RETURN_EXIT]:
            raise AssertionError('FP register runtime did not execute actual guest RET')
        counts['complete_state_comparisons'] += 1

    def check_original(code, initial, expected):
        original.mem_write(base, code)
        original.ctl_remove_cache(base, base + len(code))
        initialize_arm(original, initial)
        original.emu_start(base, STOP, count=128)
        if original.reg_read(arm.UC_ARM64_REG_PC) != STOP or bytes(capture_arm(original, initial)) != bytes(expected):
            raise AssertionError('FP register joined original complete state differs')
        counts['original_joined_complete_state_comparisons'] += 1

    for record in records:
        code, initial, intermediate, expected = fp_register_chain(record)
        report, actual = invoke(code, initial)
        require(report, actual, expected)
        counts['status_clear_repeat_checks'] += 1
        if State.from_buffer_copy(record['initial']).fpcr & 7 == 0:
            check_original(code, initial, expected)
        if record['label'] != helper_labels[record['operation']['name']]:
            continue
        if State.from_buffer_copy(record['initial']).fpcr != 0:
            continue
        first, actual = invoke(code, initial, budget=1, cache_dir=directory / f"fp-resume-{record['function']}")
        require(first, actual, intermediate, base + 12, 'budget_exhausted')
        if first['outcome']['floating_point_helpers'] != 1:
            raise AssertionError('FP register budget fixture did not cross the actual arithmetic helper')
        final, actual = invoke(code, intermediate, entry=base + 12)
        require(final, actual, expected)
        counts['budget_helper_resume_checks'] += 1
        warm, actual = invoke(code, initial)
        require(warm, actual, expected)
        if warm['outcome']['compiled_blocks'] != 0 or warm['outcome']['disk_cache_hits'] < 2:
            raise AssertionError('FP register joined chain did not reuse its persistent cache')
        counts['disk_cache_checks'] += 1
        loop_words = list(struct.unpack('<' + 'I' * (len(code) // 4), code))[:-1]
        loop_words += [NUMERICAL_SUBS_X10_ONE,
                       0xb5000000 | ((-(len(loop_words) + 1) & ((1 << 19) - 1)) << 5) | 10, RET]
        loop = struct.pack('<' + 'I' * len(loop_words), *loop_words)
        loop_initial = State.from_buffer_copy(initial)
        loop_initial.x[10] = NUMERICAL_CACHE_LOOP_ITERATIONS
        loop_expected = State.from_buffer_copy(expected)
        loop_expected.x[10], loop_expected.nzcv = 0, NUMERICAL_ZERO_CARRY_FLAGS
        repeated, actual = invoke(loop, loop_initial, budget=32)
        require(repeated, actual, loop_expected)
        if repeated['outcome']['memory_cache_hits'] < NUMERICAL_CACHE_LOOP_ITERATIONS - 1:
            raise AssertionError('FP register joined loop did not exercise live cache reuse')
        check_original(loop, loop_initial, loop_expected)
        counts['memory_cache_loop_checks'] += 1
        for bit in (8, 9, 10, 11, 12, 15):
            trap_initial = State.from_buffer_copy(initial)
            trap_initial.x[0] |= 1 << bit
            trap_expected = State.from_buffer_copy(trap_initial)
            trap_expected.fpcr = trap_initial.x[0] & FP_REGISTER_MASKS['fpcr']
            trap_expected.fpsr = 0
            declined, actual = invoke(code, trap_initial)
            require(declined, actual, trap_expected, base + 8, 'floating_point_unsupported')
            if declined['outcome']['reason'] != {'kind': 'floating_point_unsupported',
                    'instruction_pc': base + 8, 'fpcr': trap_expected.fpcr,
                    'enabled_exceptions': 1 << (bit - NUMERICAL_EXCEPTION_ENABLE_SHIFT)}:
                raise AssertionError('MSR FPCR lost requested enable or imprecise arithmetic refusal')
            counts['typed_unsupported_state_checks'] += 1
    snapshot = write_evidence(ROOT / '.stela/simd-fp_registers-runtime-records.json', transcripts)
    return {**dict(counts), 'ram_bytes_per_invocation': len(ram),
            'transcript': {'path': str(snapshot.relative_to(ROOT)), 'sha256': digest(snapshot.read_bytes())}}


def run_fp_register_cohort(cli, numerical_path):
    started = time.monotonic()
    oracle, numerical = load_fp_register_oracle(), load_numerical_oracle(numerical_path)
    cli_hash, harness_hash = digest(cli.read_bytes()), digest(Path(__file__).read_bytes())
    shared_paths = ('dev/differential.py', 'dev/evidence.py', 'dev/test_simd_differential.py',
                    'crates/stela-runtime/src/floating.rs', 'crates/stela-runtime/src/floating/comparison.rs',
                    'crates/stela-runtime/src/floating/minmax.rs', 'crates/stela-runtime/src/floating/rounding.rs', 'crates/stela-runtime/src/floating/sqrt.rs', 'crates/stela-runtime/src/floating/estimate.rs', 'crates/stela-runtime/src/floating/refinement.rs', 'crates/stela-runtime/src/floating/arithmetic.rs', 'crates/stela-runtime/src/blocks.rs',
                    'crates/stela-runtime/src/lib.rs', 'crates/stela-runtime/src/execution.rs')
    shared_hashes = {name: digest((ROOT / name).read_bytes()) for name in shared_paths}
    with tempfile.TemporaryDirectory(prefix='stela-fp-registers-') as temporary:
        directory = Path(temporary)
        batch = compile_batch(cli, directory, fp_register_functions(), 0)
        batch['cohort'] = FP_REGISTER_FOCUS
        compiler = batch['compiler']
        accounting = native_binary_accounting(batch)
        artifacts = retain_native_evidence('simd-fp_registers', batch['source'], batch['native'],
            batch['manifest'], accounting, Path(__file__).read_bytes())
        raw = bounded_cases([batch])
        runtime = fp_register_runtime_cohort(cli, directory, numerical, compiler)
    if (digest(cli.read_bytes()) != cli_hash or digest(Path(__file__).read_bytes()) != harness_hash
            or any(digest((ROOT / name).read_bytes()) != value for name, value in shared_hashes.items())):
        raise AssertionError('FP register executable, harness or shared source changed during verification')
    report = {'kind': 'simd_fp_registers_arm_vs_native_x86', 'passed': True, 'abi': LEAF_ABI,
        'state_comparisons': raw['complete_state_comparisons'],
        'compatible_original_native_full_state_comparisons': raw['direct_original_complete_state_comparisons'],
        'native_policy_state_comparisons': raw['complete_state_comparisons'] - raw['direct_original_complete_state_comparisons'],
        'policy_difference_classifications': len(oracle['classifications']),
        'runtime_state_comparisons': runtime['complete_state_comparisons'] - runtime['typed_unsupported_state_checks'],
        'runtime_complete_state_comparisons': runtime['complete_state_comparisons'] - runtime['typed_unsupported_state_checks'],
        'runtime_typed_unsupported_state_checks': runtime['typed_unsupported_state_checks'],
        'runtime_budget_resume_checks': runtime['budget_helper_resume_checks'],
        'runtime_disk_cache_checks': runtime['disk_cache_checks'],
        'runtime_memory_cache_loop_checks': runtime['memory_cache_loop_checks'],
        'native_mxcsr_preservation_comparisons': raw['caller_mxcsr_preservation_comparisons'],
        'native_caller_mxcsr_checks': raw['caller_mxcsr_preservation_comparisons'],
        'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_hash,
        'harness_source_sha256': harness_hash, 'shared_sources_sha256': shared_hashes,
        'original_oracle': {key: value for key, value in oracle.items() if key != 'records'},
        'numerical_foundation_receipt_sha256': numerical['foundation_sha256'],
        'policy_masks': FP_REGISTER_MASKS, 'operand_combinations': len(batch['functions']),
        'raw_native': raw, 'rust_runtime': runtime, 'native_accounting': accounting,
        'native_artifacts': artifacts, 'caller_mxcsr_wrapper_sha256': digest(NUMERICAL_MXCSR_WRAPPER),
        'verification_wall_seconds': time.monotonic() - started,
        'limits': 'Enabled AArch64 nonstreaming FP/FP16/AFP software policy only. Original EL0 inputs remain unchanged; exact QEMU RAZ/WI and AArch32/EBF differences receive separate policy credit. Disabled FP and absent FPMR traps are original-only evidence. Requested numerical enables precisely decline arithmetic; no exception delivery, generic MRS/MSR form completion, Apple hardware or application claim.'}
    write_evidence(ROOT / '.stela/simd-fp_registers-differential-report.json', report)
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
    parser.add_argument('--focus', choices=[*REGISTER_COHORTS, NUMERICAL_FOCUS, FP_REGISTER_FOCUS, VECTOR_NUMERICAL_FOCUS, FUSED_NUMERICAL_FOCUS, CONVERSION_NUMERICAL_FOCUS, COMPARISON_MINMAX_FOCUS, ROUND_INTEGRAL_FOCUS, SQRT_NUMERICAL_FOCUS, ESTIMATE_NUMERICAL_FOCUS, REFINEMENT_NUMERICAL_FOCUS, BINARY_REMAINING_FOCUS], help='Only the focused SIMD implementation cohort')
    parser.add_argument('--numerical-oracle', type=Path, default=NUMERICAL_FOUNDATION,
                        help='Pinned numerical foundation receipt for scalar_numerical')
    parser.add_argument('--vector-oracle', type=Path, default=VECTOR_NUMERICAL_ORACLE,
                        help='Pinned full-frame original vector numerical receipt')
    parser.add_argument('--fused-oracle', type=Path, default=FUSED_NUMERICAL_ORACLE,
                        help='Pinned full-frame original fused numerical receipt')
    parser.add_argument('--conversion-oracle', type=Path, default=CONVERSION_NUMERICAL_ORACLE,
                        help='Pinned full-frame original precision/integer conversion receipt')
    parser.add_argument('--comparison-minmax-oracle', type=Path, default=COMPARISON_MINMAX_ORACLE,
                        help='Pinned full-frame original comparison/minmax receipt')
    parser.add_argument('--round-integral-oracle', type=Path, default=ROUND_INTEGRAL_ORACLE,
                        help='Pinned full-frame original integral rounding receipt')
    parser.add_argument('--sqrt-oracle', type=Path, default=SQRT_NUMERICAL_ORACLE,
                        help='Pinned full-frame original square-root receipt')
    parser.add_argument('--binary-remaining-oracle', type=Path, default=BINARY_REMAINING_ORACLE)
    parser.add_argument('--estimate-oracle', type=Path, default=ESTIMATE_NUMERICAL_ORACLE)
    parser.add_argument('--refinement-oracle', type=Path, default=REFINEMENT_NUMERICAL_ORACLE)
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    if arguments.focus == NUMERICAL_FOCUS:
        run_scalar_numerical_cohort(cli, arguments.numerical_oracle)
        return
    if arguments.focus == FP_REGISTER_FOCUS:
        run_fp_register_cohort(cli, arguments.numerical_oracle)
        return
    if arguments.focus == BINARY_REMAINING_FOCUS:
        run_full_frame_numerical_cohort(cli, arguments.binary_remaining_oracle, arguments.focus)
        return
    if arguments.focus in (ESTIMATE_NUMERICAL_FOCUS, REFINEMENT_NUMERICAL_FOCUS):
        oracle_path = arguments.estimate_oracle if arguments.focus == ESTIMATE_NUMERICAL_FOCUS else arguments.refinement_oracle
        run_full_frame_numerical_cohort(cli, oracle_path, arguments.focus)
        return
    if arguments.focus == SQRT_NUMERICAL_FOCUS:
        run_full_frame_numerical_cohort(cli, arguments.sqrt_oracle, SQRT_NUMERICAL_FOCUS)
        return
    if arguments.focus == ROUND_INTEGRAL_FOCUS:
        run_full_frame_numerical_cohort(cli, arguments.round_integral_oracle, ROUND_INTEGRAL_FOCUS)
        return
    if arguments.focus == COMPARISON_MINMAX_FOCUS:
        run_full_frame_numerical_cohort(cli, arguments.comparison_minmax_oracle, COMPARISON_MINMAX_FOCUS)
        return
    if arguments.focus == CONVERSION_NUMERICAL_FOCUS:
        run_conversion_numerical_cohort(cli, arguments.conversion_oracle)
        return
    if arguments.focus == FUSED_NUMERICAL_FOCUS:
        run_fused_numerical_cohort(cli, arguments.fused_oracle)
        return
    if arguments.focus == VECTOR_NUMERICAL_FOCUS:
        run_vector_numerical_cohort(cli, arguments.vector_oracle)
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
