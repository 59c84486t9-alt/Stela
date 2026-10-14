#!/usr/bin/env python3
"""Original-only full-state EL0 observer for SIMD register and RAM fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from differential import ROOT
INPUT_ADDRESS = 0x41000000
OUTPUT_ADDRESS = 0x49000000
MARKER_ADDRESS = 0x40070000
SCRATCH_ADDRESS = 0x40072000
TEXT_ADDRESS = 0x40080000
MEMORY_TEMPLATE_ADDRESS = 0x40060000
QEMU_RAM_END = 0x60000000
MEMORY_RAM_ADDRESS = 0x140074000
MEMORY_RAM_BYTES = 8192
MEMORY_QEMU_RAM_SIZE = '5G'
MEMORY_QEMU_RAM_END = 0x180000000
INPUT_STRIDE = 800
STATE_BYTES = 784
RECORD_BYTES = 1024
HEADER_BYTES = 1024
FP_ACCESS_ENABLED = 3 << 20
PSTATE_EL0T_MASKED = 0x3c0
PSTATE_EL1H_MASKED = 0x3c5
NZCV_MASK = 0xf0000000
QEMU_FPCR_MASK = 0x07ff2007
QEMU_FPSR_MASK = 0xf800009f
FPCR_TRAP_MASK = 0x9f00
CPU_MODEL = 'max'
FPSR_QC = 1 << 27
FPCR_NEP = 1 << 2
SVC_IMMEDIATE = 0x123
SVC_WORD = 0xd4000001 | (SVC_IMMEDIATE << 5)
RET_WORD = 0xd65f03c0
COMPLETED_MARKER = 0x1234
CPU_REGISTERS = ('CurrentEL', 'MIDR_EL1', 'ID_AA64PFR0_EL1', 'ID_AA64ISAR1_EL1',
                 'ID_AA64PFR1_EL1', 'ID_AA64ZFR0_EL1', 'ID_AA64MMFR1_EL1', 'ID_AA64ISAR2_EL1', 'ID_AA64ISAR0_EL1')
MEMORY_L1_ADDRESS = 0x40010000
MEMORY_L2_ADDRESS = 0x40011000
MEMORY_L3_ADDRESS = 0x40012000
MEMORY_PAGE_BYTES = 4096
MEMORY_TABLE_ENTRIES = 512
MEMORY_CODE_END = TEXT_ADDRESS + 0x100000
MEMORY_ACCESS_FLAG = 1 << 10
MEMORY_EL0_RW = 1 << 6
MEMORY_READ_ONLY = 1 << 7
MEMORY_INNER_SHAREABLE = 3 << 8
MEMORY_VALID_TABLE_PAGE = 3
MEMORY_VALID_BLOCK = 1
MEMORY_NORMAL_ATTRIBUTES = MEMORY_ACCESS_FLAG | MEMORY_EL0_RW | MEMORY_INNER_SHAREABLE
# Same bounded Normal-memory profile as the retained fault calibration, extended
# to 39-bit VA so the private high RAM has an identity mapping. TTBR1 is disabled.
MEMORY_TCR = 25 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (5 << 32)
MEMORY_SCTLR = 0x30d00801  # RES1, MMU on; caches/alignment/tags/PAUTH off.
MEMORY_CONTROLS = {'SCTLR_EL1': MEMORY_SCTLR, 'TCR_EL1': MEMORY_TCR,
                   'MAIR_EL1': 0xff, 'TTBR0_EL1': MEMORY_L1_ADDRESS}
MEMORY_CONTROL_HEADER_OFFSET = len(CPU_REGISTERS) * 8
ELF_EXECINSTR = 1 << 2
ATOMIC_FEATURE_HEADER_OFFSET = MEMORY_CONTROL_HEADER_OFFSET + len(MEMORY_CONTROLS) * 8
ATOMIC_FOCUS = 'atomic_memory'
ATOMIC_PAIR_FOCUS = 'atomic_pair_memory'
ORDERED_UNSCALED_FOCUS = 'ordered_unscaled_memory'
LIMITED_ORDERED_FOCUS = 'limited_ordered_memory'
LIMITED_CONTROL_HEADER_OFFSET = ATOMIC_FEATURE_HEADER_OFFSET + 8
LIMITED_CONTROLS = ('LORID_EL1', 'LORC_EL1', 'LORSA_EL1', 'LOREA_EL1', 'LORN_EL1')
ATOMIC_FEATURE_FOCUSES = (ATOMIC_FOCUS, ATOMIC_PAIR_FOCUS, ORDERED_UNSCALED_FOCUS, LIMITED_ORDERED_FOCUS)
TAG_ARITHMETIC_FOCUS = 'tag_arithmetic'
TAG_ATA0 = 1 << 42
TAG_TCF0_MASK = 3 << 38
TAG_UNDEFINED_ESR = 1 << 25  # EC=Unknown, IL=32; no additional syndrome bits.
TAG_SCTLR = (MEMORY_SCTLR & ~1) | TAG_ATA0
TAG_CONTROLS = {'SCTLR_EL1': TAG_SCTLR, 'GCR_EL1': 0}
TAG_CONTROL_HEADER_OFFSET = len(CPU_REGISTERS) * 8
LAYOUT = {'x': 0, 'sp': 248, 'spsr': 256, 'fpcr': 264, 'fpsr': 272,
          'esr': 280, 'elr': 288, 'current_el': 296, 'cpacr': 304,
          'marker': 312, 'v': 320, 'pre_fpcr': 832, 'pre_fpsr': 840}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def write_new(path, data):
    if path.exists():
        if path.read_bytes() != data:
            raise AssertionError(f'Immutable evidence file changed: {path}')
    else:
        with path.open('xb') as file:
            file.write(data)


def integer(value):
    return int(value, 0) if isinstance(value, str) else value


def operation(function):
    if 'operations' in function:
        assert len(function['operations']) == 1
        return function['operations'][0]
    return function


def load_corpus(directory):
    names = ('functions.json', 'cases.json', 'inputs.bin', 'input-plan.json')
    files = {name: (directory / name).read_bytes() for name in names}
    functions = json.loads(files['functions.json'])
    cases = json.loads(files['cases.json'])
    inputs = files['inputs.bin']
    plan = json.loads(files['input-plan.json'])
    for name, identity in plan['files'].items():
        assert sha(files[name]) == identity['sha256'], name
        assert len(files[name]) == identity['bytes'], name
    assert plan['cases'] == len(cases) and plan['functions'] == len(functions)
    assert 0 < len(cases) <= 50000
    assert len(inputs) == len(cases) * INPUT_STRIDE
    assert len(functions) > 0
    words = []
    for function in functions:
        word = integer(operation(function)['word'])
        assert 0 <= word < 1 << 32
        canonical_source = struct.pack('<II', word, 0xd65f0000 | operation(function).get('return_register', 30) << 5)
        if 'source_hex' in function:
            assert bytes.fromhex(function['source_hex']) == canonical_source
        words.append(word)
    assert len(set(words)) == len(words), 'Each exact subject word must have one function'
    for index, case in enumerate(cases):
        offset = index * INPUT_STRIDE
        function_index = struct.unpack_from('<Q', inputs, offset)[0]
        assert function_index < len(functions), index
        for field in ('function', 'function_index'):
            if field in case:
                assert case[field] == function_index, (index, field)
        if 'initial_state_sha256' in case:
            assert case['initial_state_sha256'] == sha(inputs[offset + 8:offset + 8 + STATE_BYTES]), index
        assert inputs[offset + 8 + STATE_BYTES:offset + INPUT_STRIDE] == bytes(8), index
    memory = memory_plan(directory)
    if memory is not None:
        for name in ('memory-plan.json', 'memory.bin'):
            files[name] = (directory / name).read_bytes()
        if OUTPUT_ADDRESS + len(cases) * memory['record_bytes'] > QEMU_RAM_END:
            raise AssertionError('Memory original results exceed QEMU RAM')
        if INPUT_ADDRESS + len(inputs) > OUTPUT_ADDRESS - HEADER_BYTES:
            raise AssertionError('Memory original inputs overlap output')
    return files, functions, cases, inputs, words


def mov(register, value):
    lines = [f'movz {register},#{value & 65535}']
    lines.extend(f'movk {register},#{value >> shift & 65535},lsl#{shift}'
                 for shift in (16, 32, 48) if value >> shift & 65535)
    return lines


def memory_plan(directory):
    """Optional bounded two-page private RAM extension; defaults stay unchanged."""
    path = Path(directory) / 'memory-plan.json'
    if not path.exists():
        return None
    plan = json.loads(path.read_bytes())
    if set(plan) != {'ram_address', 'ram_bytes', 'initial_ram_sha256'}:
        raise AssertionError('Memory observer plan fields differ')
    address, length = plan['ram_address'], plan['ram_bytes']
    # This high region avoids native executable PAGEZERO while retaining exact
    # original/native pointer equality. QEMU backs it with lazily allocated RAM.
    if (address != MEMORY_RAM_ADDRESS or length != MEMORY_RAM_BYTES
            or address + length > MEMORY_QEMU_RAM_END):
        raise AssertionError('Memory observer requires the bounded two-page RAM region')
    data = (Path(directory) / 'memory.bin').read_bytes()
    if len(data) != length or sha(data) != plan['initial_ram_sha256']:
        raise AssertionError('Memory observer RAM template identity changed')
    return {**plan, 'record_bytes': RECORD_BYTES + length}


def copy_memory(source, destination, length, label):
    lines = mov('x0', source) + mov('x1', destination) + mov('x2', length // 16)
    return lines + [label + ':', 'ldp x3,x4,[x0],#16', 'stp x3,x4,[x1],#16',
                    'subs x2,x2,#1', 'b.ne ' + label]


def memory_setup():
    """Bounded identity tables for original success RAM; register mode is untouched."""
    lines = mov('x0', MEMORY_L1_ADDRESS) + mov('x1', 3 * MEMORY_PAGE_BYTES // 8)
    lines += ['zero_memory_tables:', 'str xzr,[x0],#8', 'subs x1,x1,#1', 'b.ne zero_memory_tables']
    # Eight 1GiB blocks cover the high RAM; split only the low code/data block.
    lines += mov('x0', MEMORY_L1_ADDRESS) + mov('x1', MEMORY_NORMAL_ATTRIBUTES | MEMORY_VALID_BLOCK)
    lines += mov('x2', 8) + mov('x3', 1 << 30)
    lines += ['memory_l1_blocks:', 'str x1,[x0],#8', 'add x1,x1,x3', 'subs x2,x2,#1', 'b.ne memory_l1_blocks']
    lines += mov('x0', MEMORY_L1_ADDRESS) + mov('x1', MEMORY_L2_ADDRESS | MEMORY_VALID_TABLE_PAGE) + ['str x1,[x0,#8]']
    lines += mov('x0', MEMORY_L2_ADDRESS) + mov('x1', 0x40000000 | MEMORY_NORMAL_ATTRIBUTES | MEMORY_VALID_BLOCK)
    lines += mov('x2', MEMORY_TABLE_ENTRIES)
    lines += ['memory_l2_blocks:', 'str x1,[x0],#8', 'add x1,x1,#0x200,lsl#12', 'subs x2,x2,#1', 'b.ne memory_l2_blocks']
    lines += mov('x0', MEMORY_L2_ADDRESS) + mov('x1', MEMORY_L3_ADDRESS | MEMORY_VALID_TABLE_PAGE) + ['str x1,[x0]']
    lines += mov('x0', MEMORY_L3_ADDRESS) + mov('x1', 0x40000000 | MEMORY_NORMAL_ATTRIBUTES | MEMORY_VALID_TABLE_PAGE)
    lines += mov('x2', MEMORY_TABLE_ENTRIES)
    lines += ['memory_l3_pages:', 'str x1,[x0],#8', 'add x1,x1,#1,lsl#12', 'subs x2,x2,#1', 'b.ne memory_l3_pages']
    # EL1 cannot execute user-writable pages. Protect the whole bounded code
    # interval while leaving the tables, input, output and RAM template writable.
    code_offset = ((TEXT_ADDRESS >> 12) & (MEMORY_TABLE_ENTRIES - 1)) * 8
    lines += mov('x0', MEMORY_L3_ADDRESS + code_offset)
    lines += mov('x1', TEXT_ADDRESS | MEMORY_NORMAL_ATTRIBUTES | MEMORY_VALID_TABLE_PAGE | MEMORY_READ_ONLY)
    lines += mov('x2', (MEMORY_CODE_END - TEXT_ADDRESS) // MEMORY_PAGE_BYTES)
    lines += ['memory_code_pages:', 'str x1,[x0],#8', 'add x1,x1,#1,lsl#12', 'subs x2,x2,#1', 'b.ne memory_code_pages']
    for register in ('MAIR_EL1', 'TTBR0_EL1', 'TCR_EL1'):
        lines += mov('x0', MEMORY_CONTROLS[register]) + [f'msr {register},x0']
    lines += mov('x0', OUTPUT_ADDRESS) + ['mov sp,x0', 'dsb sy', 'isb', 'tlbi vmalle1', 'dsb sy', 'isb']
    lines += mov('x0', MEMORY_SCTLR) + ['msr SCTLR_EL1,x0', 'isb']
    return lines


def validate_memory_controls(results):
    actual = dict(zip(MEMORY_CONTROLS, struct.unpack_from('<4Q', results, MEMORY_CONTROL_HEADER_OFFSET)))
    if actual != MEMORY_CONTROLS:
        raise AssertionError('Memory observer actual MMU controls differ: ' + str(actual))
    return {name: hex(value) for name, value in actual.items()}



def validate_atomic_features(results, focus=ATOMIC_FOCUS):
    registers = dict(zip(CPU_REGISTERS, struct.unpack_from('<9Q', results)))
    mmfr2 = struct.unpack_from('<Q', results, ATOMIC_FEATURE_HEADER_OFFSET)[0]
    fields = {'LSE_Atomic': registers['ID_AA64ISAR0_EL1'] >> 20 & 15,
              'LRCPC': registers['ID_AA64ISAR1_EL1'] >> 20 & 15, 'LSE2_AT': mmfr2 >> 32 & 15}
    if not (fields['LSE_Atomic'] in (2, 3) and fields['LRCPC'] in (1, 2, 3) and fields['LSE2_AT'] == 1):
        raise AssertionError('Original atomic feature profile unavailable: ' + str(fields))
    if focus == ORDERED_UNSCALED_FOCUS and fields['LRCPC'] < 2:
        raise AssertionError('Original ordered-unscaled requires actual FEAT_LRCPC2')
    if focus not in ATOMIC_FEATURE_FOCUSES:
        raise AssertionError('Unknown atomic original feature focus: ' + str(focus))
    limited = {}
    if focus == LIMITED_ORDERED_FOCUS:
        lo = registers['ID_AA64MMFR1_EL1'] >> 16 & 15
        values = dict(zip(LIMITED_CONTROLS, struct.unpack_from('<5Q', results, LIMITED_CONTROL_HEADER_OFFSET)))
        if lo != 1 or any(values.values()):
            raise AssertionError('Original limited ordering requires FEAT_LOR and no implemented/enabled regions: ' + str((lo, values)))
        limited = {'LO': lo, 'controls': {name: hex(value) for name, value in values.items()}}
    validate_memory_controls(results)
    if MEMORY_SCTLR & ((1 << 1) | (1 << 6)):
        raise AssertionError('Atomic original requires A=0,nAA=0')
    return {'fields': fields, 'ID_AA64MMFR2_EL1': hex(mmfr2),
            **({'limited_ordering': limited} if limited else {}),
            'profile': 'EL0_Normal_WB_LSE2_A0_nAA0_SCA16',
            'limits': 'Feature and MMU controls are actual readbacks. The original implementation SCA granule is not inferred from feature ID alone. SA0 remains0; native SP policy faults are separate.'}


def validate_tag_features(results):
    registers = dict(zip(CPU_REGISTERS, struct.unpack_from('<9Q', results)))
    controls = dict(zip(TAG_CONTROLS, struct.unpack_from('<2Q', results, TAG_CONTROL_HEADER_OFFSET)))
    mte = registers['ID_AA64PFR1_EL1'] >> 8 & 15
    if mte not in (2, 3) or controls != TAG_CONTROLS or registers['CurrentEL'] != 4:
        raise AssertionError('Original tag arithmetic feature/control profile unavailable: ' + str((mte, controls)))
    if not controls['SCTLR_EL1'] & TAG_ATA0 or controls['SCTLR_EL1'] & TAG_TCF0_MASK:
        raise AssertionError('Original tag arithmetic requires ATA0=1 and TCF0=0')
    return {'MTE': mte, 'controls': {name: hex(value) for name, value in controls.items()},
            'profile': 'EL0_MTE2_ATA0_1_TCF0_0_GCR_Exclude0_register_only',
            'limits': 'Actual QEMU feature/control readbacks only; no allocation-tag memory access, tag checking, IRG randomness or Apple hardware credit.'}


def validate_memory_text(sections):
    for section in sections:
        if section[2] & ELF_EXECINSTR and section[5]:
            if not TEXT_ADDRESS <= section[3] < section[3] + section[5] <= MEMORY_CODE_END:
                raise AssertionError('Memory original executable section exceeds read-only code mapping')


def assembly(words, count, memory=None, focus=None):
    architecture = '.arch armv8.7-a+fp16+sve' + ('+memtag' if focus == TAG_ARITHMETIC_FOCUS else '')
    lines = [architecture, '.text', '.global _start', '_start:',
             'adrp x0,vectors', 'add x0,x0,:lo12:vectors', 'msr vbar_el1,x0', 'isb']
    lines += mov('x0', FP_ACCESS_ENABLED) + ['msr cpacr_el1,x0', 'isb']
    if memory is not None:
        lines += memory_setup()
    if focus == TAG_ARITHMETIC_FOCUS:
        if memory is not None:
            raise AssertionError('Tag arithmetic original is a separate register-only profile')
        for register, value in TAG_CONTROLS.items():
            lines += mov('x0', value) + [f'msr {register},x0']
        lines += ['isb']
    lines += mov('x1', OUTPUT_ADDRESS - HEADER_BYTES)
    for index, register in enumerate(CPU_REGISTERS):
        lines += [f'mrs x0,{register}', f'str x0,[x1,#{index * 8}]']
    if memory is not None:
        for index, register in enumerate(MEMORY_CONTROLS):
            lines += [f'mrs x0,{register}', f'str x0,[x1,#{MEMORY_CONTROL_HEADER_OFFSET + index * 8}]']
    if focus in ATOMIC_FEATURE_FOCUSES:
        if memory is None:
            raise AssertionError('Atomic original requires Normal-memory controls')
        lines += ['mrs x0,ID_AA64MMFR2_EL1', f'str x0,[x1,#{ATOMIC_FEATURE_HEADER_OFFSET}]']
    if focus == LIMITED_ORDERED_FOCUS:
        for index, register in enumerate(LIMITED_CONTROLS):
            lines += [f'mrs x0,{register}', f'str x0,[x1,#{LIMITED_CONTROL_HEADER_OFFSET + index * 8}]']
    if focus == TAG_ARITHMETIC_FOCUS:
        for index, register in enumerate(TAG_CONTROLS):
            lines += [f'mrs x0,{register}', f'str x0,[x1,#{TAG_CONTROL_HEADER_OFFSET + index * 8}]']
    lines += mov('x0', SCRATCH_ADDRESS)
    for offset, value in ((0, INPUT_ADDRESS), (8, OUTPUT_ADDRESS), (16, count)):
        lines += mov('x1', value) + [f'str x1,[x0,#{offset}]']
    lines += ['again:']
    if memory is not None:
        lines += copy_memory(MEMORY_TEMPLATE_ADDRESS, memory['ram_address'], memory['ram_bytes'], 'restore_ram')
    lines += mov('x0', SCRATCH_ADDRESS)
    lines += ['ldr x19,[x0]', 'ldr x20,[x0,#8]', 'mov sp,x20',
              'ldr w0,[x19,#784]', 'msr fpcr,x0', 'mrs x0,fpcr', 'str x0,[sp,#832]',
              'ldr w0,[x19,#788]', 'msr fpsr,x0', 'mrs x0,fpsr', 'str x0,[sp,#840]',
              'ldr x0,[x19,#256]', 'msr sp_el0,x0',
              'ldr w0,[x19,#264]', f'and x0,x0,#{NZCV_MASK:#x}',
              f'orr x0,x0,#{PSTATE_EL0T_MASKED:#x}', 'msr spsr_el1,x0',
              'adrp x0,functions', 'add x0,x0,:lo12:functions',
              'ldr x1,[x19]', 'ldr x0,[x0,x1,lsl#3]', 'msr elr_el1,x0']
    lines += [f'ldr q{register},[x19,#{272 + register * 16}]' for register in range(32)]
    lines += ['mov x30,x19']
    lines += [f'ldp x{register},x{register + 1},[x30,#{8 + register * 8}]'
              for register in range(0, 30, 2)]
    lines += ['ldr x30,[x30,#248]', 'eret']
    for index, word in enumerate(words):
        lines += [f'subject_{index}:', f'.inst 0x{word:08x}', f'svc #{SVC_IMMEDIATE}']
    lines += ['.balign 2048', 'vectors:']
    for _ in range(16):
        lines += ['b exception_entry', '.space 124']
    lines += ['exception_entry:']
    lines += [f'stp x{register},x{register + 1},[sp,#{register * 8}]'
              for register in range(0, 30, 2)]
    lines += ['str x30,[sp,#240]']
    for register, offset in (('sp_el0', 248), ('spsr_el1', 256), ('fpcr', 264),
                             ('fpsr', 272), ('esr_el1', 280), ('elr_el1', 288),
                             ('CurrentEL', 296), ('cpacr_el1', 304)):
        lines += [f'mrs x0,{register}', f'str x0,[sp,#{offset}]']
    lines += [f'str q{register},[sp,#{320 + register * 16}]' for register in range(32)]
    lines += mov('x0', COMPLETED_MARKER) + ['str x0,[sp,#312]']
    if memory is not None:
        lines += mov('x0', memory['ram_address']) + ['add x1,sp,#1024'] + mov('x2', memory['ram_bytes'] // 16)
        lines += ['snapshot_ram:', 'ldp x3,x4,[x0],#16', 'stp x3,x4,[x1],#16', 'subs x2,x2,#1', 'b.ne snapshot_ram']
    lines += mov('x0', SCRATCH_ADDRESS)
    lines += ['ldp x1,x2,[x0]', f'add x1,x1,#{INPUT_STRIDE}']
    lines += (mov('x3', memory['record_bytes']) + ['add x2,x2,x3'] if memory is not None else [f'add x2,x2,#{RECORD_BYTES}'])
    lines += ['stp x1,x2,[x0]',
              'ldr x1,[x0,#16]', 'subs x1,x1,#1', 'str x1,[x0,#16]', 'b.eq finished',
              'adr x0,again', 'msr elr_el1,x0']
    lines += mov('x0', PSTATE_EL1H_MASKED) + ['msr spsr_el1,x0', 'eret', 'finished:']
    lines += mov('x0', MARKER_ADDRESS) + mov('x1', COMPLETED_MARKER)
    lines += ['str x1,[x0]', 'completed: b completed',
              '.section .rodata', '.balign 8', 'functions:']
    lines += [f'.quad subject_{index}' for index in range(len(words))]
    return '\n'.join(lines) + '\n'


def tools_and_bindings():
    qemu_override = os.environ.get('STELA_QEMU')
    qemu = Path(qemu_override) if qemu_override else ROOT / '.tools/qemu/bin/qemu-system-aarch64'
    if qemu_override and not qemu.is_file():
        raise ValueError('STELA_QEMU must name an existing QEMU executable')
    if not qemu.is_file():
        qemu = Path(shutil.which('qemu-system-aarch64') or '')
    clang = Path(shutil.which('clang') or '')
    if os.uname().sysname == 'Darwin':
        clang = Path(subprocess.check_output(['/usr/bin/xcrun', '--find', 'clang'], text=True).strip())
    candidates = sorted((ROOT / '.tools/rust/rustup/toolchains').glob('*/lib/rustlib/*/bin/rust-lld'))
    lld = Path(shutil.which('ld.lld')) if shutil.which('ld.lld') else candidates[0]
    assert all(path.is_file() for path in (qemu, clang, lld))
    qemu_executables = sorted((ROOT / '.tools/qemu/Cellar/qemu').glob('*/bin/qemu-system-aarch64'))
    tools = {str(path): {'sha256': sha(path.read_bytes()), 'resolved_path': str(path.resolve())}
             for path in (qemu, qemu.resolve(), clang, clang.resolve(), lld, lld.resolve(), *qemu_executables)}
    return qemu, clang, lld, {'tools': tools,
        'qemu_version': subprocess.check_output([str(qemu), '--version'], text=True).splitlines()[0],
        'clang_version': subprocess.check_output([str(clang), '--version'], text=True).splitlines()[0],
        'producer_sha256': sha(Path(__file__).read_bytes())}


def elf_subjects(path, words, functions, memory=None):
    """Read ELF64 symbols/sections directly; inspect the actual linked instruction bytes."""
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    section_offset, section_stride, section_count = header[6], header[11], header[12]
    assert section_stride == 64
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, section_offset + index * section_stride)
                for index in range(section_count)]
    if memory is not None:
        validate_memory_text(sections)
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        string_data = data[strings[4]:strings[4] + strings[5]]
        assert section[9] == 24
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, _, _, section_index, value, size = struct.unpack_from('<IBBHQQ', data, offset)
            end = string_data.find(b'\0', name)
            symbols[string_data[name:end].decode()] = (section_index, value, size)
    subjects = []
    for index, word in enumerate(words):
        section_index, pc, _ = symbols[f'subject_{index}']
        section = sections[section_index]
        offset = section[4] + pc - section[3]
        actual = data[offset:offset + 8]
        assert actual == struct.pack('<II', word, SVC_WORD), (index, actual.hex())
        canonical = bytes.fromhex(functions[index]['source_hex'])
        subjects.append({'function_index': index, 'instruction_pc': pc, 'svc_pc': pc + 4,
                         'expected_elr': pc + 8, 'executed_source_hex': actual.hex(),
                         'executed_source_sha256': sha(actual), 'canonical_source_hex': canonical.hex(),
                         'canonical_source_sha256': sha(canonical), 'elf_offset': offset})
    assert symbols['_start'][1] == TEXT_ADDRESS
    assert symbols['vectors'][1] % 2048 == 0
    return subjects


def prepare(directory, focus, source_bindings):
    directory = Path(directory).resolve()
    directory.relative_to(ROOT)
    if not focus or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in focus):
        raise ValueError("Invalid original observer focus")
    for name, identity in source_bindings.items():
        if sha((ROOT / name).read_bytes()) != identity:
            raise AssertionError("Frozen original source binding changed: " + name)
    files, functions, cases, inputs, words = load_corpus(directory)
    memory = memory_plan(directory)
    if focus in (ATOMIC_PAIR_FOCUS, ORDERED_UNSCALED_FOCUS, LIMITED_ORDERED_FOCUS):
        if memory is None or any(operation(function)['kind'] != focus for function in functions):
            raise AssertionError('New memory original requires its exact family corpus and RAM plan')
        for function in functions:
            memory_destinations(operation(function))
    if focus == TAG_ARITHMETIC_FOCUS:
        if memory is not None:
            raise AssertionError('Tag arithmetic original must not include a RAM plan')
        for function in functions:
            tag_destinations(operation(function))
    source = assembly(words, len(cases), memory, focus if focus in (*ATOMIC_FEATURE_FOCUSES, TAG_ARITHMETIC_FOCUS) else None).encode()
    qemu, clang, lld, bindings = tools_and_bindings()
    bindings['focus'] = focus
    if memory is not None:
        bindings['memory_plan'] = memory
    if focus == TAG_ARITHMETIC_FOCUS:
        bindings['tag_arithmetic_controls'] = TAG_CONTROLS
        bindings['tag_arithmetic_control_header_offset'] = TAG_CONTROL_HEADER_OFFSET
    bindings['source_receipts'] = source_bindings
    bindings['observer_dependencies'] = {'dev/differential.py': sha((ROOT / 'dev/differential.py').read_bytes())}
    bindings['inputs'] = {name: {'sha256': sha(data), 'bytes': len(data)} for name, data in files.items()}
    key = sha(source + json_bytes(bindings))
    destination = directory / key
    destination.mkdir(exist_ok=True)
    for name, data in files.items():
        write_new(destination / name, data)
    write_new(destination / 'guest.S', source)
    write_new(destination / 'original.py', Path(__file__).read_bytes())
    write_new(destination / 'bindings.json', json_bytes(bindings))
    if not (destination / 'guest.elf').exists():
        command = [str(clang), '--target=aarch64-unknown-none-elf', '-c', str(destination / 'guest.S'), '-o', str(destination / 'guest.o')]
        write_new(destination / 'assemble-command.json', json_bytes(command))
        subprocess.run(command, check=True)
        env = os.environ.copy()
        if lld.name == 'rust-lld' and os.uname().sysname == 'Darwin':
            env['DYLD_LIBRARY_PATH'] = str(lld.resolve().parents[3])
        command = [str(lld), *(['-flavor', 'gnu'] if lld.name == 'rust-lld' else []),
                   '-m', 'aarch64elf', '-Ttext', hex(TEXT_ADDRESS), '-e', '_start',
                   str(destination / 'guest.o'), '-o', str(destination / 'guest.elf')]
        write_new(destination / 'link-command.json', json_bytes(command))
        subprocess.run(command, check=True, env=env)
    subjects = elf_subjects(destination / 'guest.elf', words, functions, memory)
    write_new(destination / 'subjects.json', json_bytes(subjects))
    return destination, qemu, bindings, functions, cases, inputs, subjects


def execute(destination, qemu, count, focus=None):
    memory = memory_plan(destination)
    machine = 'virt,secure=off,virtualization=off' + (',mte=on' if focus == TAG_ARITHMETIC_FOCUS else '')
    command = [str(qemu), '-machine', machine, '-cpu', CPU_MODEL,
               '-accel', 'tcg', '-m', MEMORY_QEMU_RAM_SIZE if memory is not None else '512M',
               '-display', 'none', '-serial', 'none',
               '-monitor', 'none', '-nic', 'none', '-kernel', str(destination / 'guest.elf'),
               '-device', f'loader,file={destination / "inputs.bin"},addr={INPUT_ADDRESS:#x},force-raw=on']
    if memory is not None:
        command += ['-device', f'loader,file={destination / "memory.bin"},addr={MEMORY_TEMPLATE_ADDRESS:#x},force-raw=on']
    size = HEADER_BYTES + count * (memory['record_bytes'] if memory is not None else RECORD_BYTES)
    execute_transport(destination, command, size)


def execute_transport(destination, command, output_size, timeout=60):
    """Run a bounded observer with the shared marker/QMP/raw-memory transport."""
    with tempfile.TemporaryDirectory(prefix='stela-simd-original-el0-') as temporary:
        endpoint = Path(temporary) / 'qmp'
        command = [*command, '-qmp', f'unix:{endpoint},server=on,wait=off', '-S']
        write_new(destination / 'qemu-command.json', json_bytes(command))
        with (destination / 'stderr.log').open('xb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            stream = connection = None
            request = None
            marker = None
            try:
                deadline = time.monotonic() + 15
                while not endpoint.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError('QEMU failed before QMP connection')
                    time.sleep(0.02)
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(10)
                connection.connect(str(endpoint))
                stream = connection.makefile('rwb')
                json.loads(stream.readline())

                def request(name, arguments=None):
                    data = {'execute': name}
                    if arguments is not None:
                        data['arguments'] = arguments
                    stream.write(json.dumps(data).encode() + b'\n')
                    stream.flush()
                    while True:
                        reply = json.loads(stream.readline())
                        if 'error' in reply:
                            raise AssertionError(reply)
                        if 'return' in reply:
                            return reply['return']

                request('qmp_capabilities')
                request('cont')
                deadline = time.monotonic() + timeout
                while True:
                    marker = request('human-monitor-command', {'command-line': f'xp /1gx {MARKER_ADDRESS:#x}'})
                    if marker.strip().endswith(f'{COMPLETED_MARKER:#018x}'):
                        break
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(f'Original oracle timeout/failure: {marker}')
                    time.sleep(0.02)
                request('stop')
                request('human-monitor-command', {'command-line': f'pmemsave {OUTPUT_ADDRESS - HEADER_BYTES:#x} {output_size} "{destination / "results.bin"}"'})
                request('quit')
                process.wait(timeout=5)
            except Exception as error:
                failure = {'error': repr(error), 'last_marker': marker,
                           'output_size': output_size, 'partial_dump_error': None}
                if request is not None and process.poll() is None:
                    try:
                        request('stop')
                        request('human-monitor-command', {'command-line':
                            f'pmemsave {OUTPUT_ADDRESS - HEADER_BYTES:#x} {output_size} "{destination / "results.partial.bin"}"'})
                    except Exception as dump_error:
                        failure['partial_dump_error'] = repr(dump_error)
                write_new(destination / 'failure.json', json_bytes(failure))
                raise
            finally:
                if stream is not None:
                    stream.close()
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)


def memory_destinations(op):
    """Declared ordinary destinations; retain legacy structured inference."""
    if op['kind'] == 'structure_memory':
        if not 1 <= op['total_bytes'] <= 64:
            raise AssertionError('Invalid structured memory footprint')
        gprs = [op['rn']] if op['mode'] != 'offset' and op['rn'] != 31 else []
        vectors = [(op['rt'] + slot) % 32 for slot in range(op['runs'] * op['structures'])] if op['loading'] else []
        return set(gprs), set(vectors), op['mode'] != 'offset' and op['rn'] == 31
    if op['kind'] == ATOMIC_PAIR_FOCUS:
        from simd_fixtures import atomic_pair_memory
        expected = atomic_pair_memory.operation(op['element_bytes'], op['order'], op['rs'], op['rt'], op['rn'])
        if {key: value for key, value in op.items() if key != 'source_hex'} != expected:
            raise AssertionError('Original CASP metadata differs from actual pure family')
    elif op['kind'] == ORDERED_UNSCALED_FOCUS:
        from simd_fixtures import ordered_unscaled_memory
        expected = ordered_unscaled_memory.operation(op['canonical_id'], op['rt'], op['rn'], op['offset'])
        if {key: value for key, value in op.items() if key != 'source_hex'} != expected:
            raise AssertionError('Original ordered-unscaled metadata differs from actual pure family')
    elif op['kind'] == LIMITED_ORDERED_FOCUS:
        from simd_fixtures import limited_ordered_memory
        expected = limited_ordered_memory.operation('ldlar' if op['loading'] else 'stllr',
            op['element_bytes'], op['rt'], op['rn'], op['sbo'], op['rt2'])
        if {key: value for key, value in op.items() if key != 'source_hex'} != expected:
            raise AssertionError('Original limited-order metadata differs from actual pure family')
    elif op['kind'] not in ('ordinary_memory', ATOMIC_FOCUS) or not 0 <= op['total_bytes'] <= (8 if op['kind'] == ATOMIC_FOCUS else 32):
        raise AssertionError('Invalid memory observer family/footprint')
    destinations = []
    for name, bound in (('written_gprs', 31), ('written_vectors', 32)):
        values = op.get(name)
        if (not isinstance(values, list) or any(type(value) is not int or not 0 <= value < bound for value in values)
                or len(values) != len(set(values))):
            raise AssertionError('Invalid declared memory destinations: ' + name)
        destinations.append(set(values))
    return *destinations, False


def tag_destinations(op):
    from simd_fixtures import tag_arithmetic
    expected = tag_arithmetic.operation(op['name'], op['d'], op['n'], op['m'],
                                        op['address_offset'], op['tag_offset'], op['soft_bits'])
    if {key: value for key, value in op.items() if key != 'source_hex'} != expected:
        raise AssertionError('Original tag arithmetic metadata differs from actual pure family')
    gprs = {op['d']} if op['d'] != 31 else set()
    sp = op['name'] in ('addg', 'subg') and op['d'] == 31
    nzcv = op['name'] == 'subps'
    if (op['kind'] != TAG_ARITHMETIC_FOCUS or op['written_gprs'] != sorted(gprs)
            or any(type(register) is not int for register in op['written_gprs'])
            or op['written_vectors'] != [] or type(op['writes_sp']) is not bool or type(op['writes_nzcv']) is not bool
            or op['writes_sp'] != sp or op['writes_nzcv'] != nzcv):
        raise AssertionError('Original tag arithmetic destination/flag declaration differs')
    return gprs, set(), sp, nzcv


def validate_results(destination, functions, cases, inputs, subjects, focus=None):
    results = (destination / 'results.bin').read_bytes()
    memory = memory_plan(destination)
    stride = memory['record_bytes'] if memory is not None else RECORD_BYTES
    assert len(results) == HEADER_BYTES + len(cases) * stride
    memory_controls = validate_memory_controls(results) if memory is not None else None
    tag_features = validate_tag_features(results) if focus == TAG_ARITHMETIC_FOCUS else None
    controls, trap_observations, status_deltas = {}, [], {}
    tag_undefined_cases = []
    for index in range(len(cases)):
        input_offset = index * INPUT_STRIDE
        function_index = struct.unpack_from('<Q', inputs, input_offset)[0]
        initial = inputs[input_offset + 8:input_offset + 8 + STATE_BYTES]
        record = results[HEADER_BYTES + index * stride:HEADER_BYTES + (index + 1) * stride]
        requested_fpcr, requested_fpsr = struct.unpack_from('<II', initial, 776)
        pre_fpcr, pre_fpsr = struct.unpack_from('<QQ', record, LAYOUT['pre_fpcr'])
        observed = {name: struct.unpack_from('<Q', record, offset)[0]
                    for name, offset in LAYOUT.items() if name not in ('x', 'v')}
        assert pre_fpcr == requested_fpcr & QEMU_FPCR_MASK, (index, 'pre_fpcr')
        assert pre_fpsr == requested_fpsr & QEMU_FPSR_MASK, (index, 'pre_fpsr')
        op = operation(functions[function_index])
        writes_nzcv = False
        if focus == TAG_ARITHMETIC_FOCUS:
            written_gprs, written_vectors, written_sp, writes_nzcv = tag_destinations(op)
        else:
            written_gprs, written_vectors, written_sp = memory_destinations(op) if memory is not None else (set(), set(), False)
        for register in range(31):
            if register not in written_gprs:
                assert record[register * 8:register * 8 + 8] == initial[register * 8:register * 8 + 8], (index, 'unchanged_gpr', register)
        if not written_sp:
            assert observed['sp'] == struct.unpack_from('<Q', initial, 248)[0], (index, 'sp')
        initial_nzcv = struct.unpack_from('<I', initial, 256)[0]
        if writes_nzcv:
            assert observed['spsr'] & ~NZCV_MASK == PSTATE_EL0T_MASKED, (index, 'non_nzcv_spsr_unchanged')
        else:
            assert observed['spsr'] == (initial_nzcv & NZCV_MASK) | PSTATE_EL0T_MASKED, (index, 'spsr_unchanged')
        assert observed['fpcr'] == pre_fpcr, (index, 'fpcr_unchanged')
        assert observed['fpsr'] & pre_fpsr == pre_fpsr, (index, 'sticky_fpsr')
        assert observed['fpsr'] & FPSR_QC == pre_fpsr & FPSR_QC, (index, 'qc_unchanged')
        assert observed['fpsr'] & ~QEMU_FPSR_MASK == 0, (index, 'reserved_fpsr')
        tag_undefined = (focus == TAG_ARITHMETIC_FOCUS and op['name'] in ('addg', 'subg')
                         and op['soft_bits'] != 0 and observed['esr'] == TAG_UNDEFINED_ESR)
        if tag_undefined:
            assert observed['elr'] == subjects[function_index]['instruction_pc'], (index, 'tag_undefined_elr')
            assert record[:248] == initial[:248], (index, 'tag_undefined_all_gprs')
            assert observed['sp'] == struct.unpack_from('<Q', initial, 248)[0], (index, 'tag_undefined_sp')
            assert observed['spsr'] == (initial_nzcv & NZCV_MASK) | PSTATE_EL0T_MASKED, (index, 'tag_undefined_nzcv')
            assert record[320:832] == initial[264:776], (index, 'tag_undefined_all_vectors')
            assert observed['fpcr'] == pre_fpcr and observed['fpsr'] == pre_fpsr, (index, 'tag_undefined_fp_controls')
            unchanged = bytearray(initial)
            struct.pack_into('<II', unchanged, 776, pre_fpcr, pre_fpsr)
            tag_undefined_cases.append({'case_index': index, 'function_index': function_index,
                'word': integer(op['word']), 'esr': observed['esr'], 'elr': observed['elr'],
                'state_sha256': sha(unchanged)})
        else:
            assert observed['esr'] >> 26 == 0x15 and observed['esr'] & 65535 == SVC_IMMEDIATE, (index, 'genuine_svc')
            assert observed['elr'] == subjects[function_index]['expected_elr'], (index, 'elr')
        assert observed['current_el'] == 4 and observed['cpacr'] == FP_ACCESS_ENABLED, (index, 'access')
        assert observed['marker'] == COMPLETED_MARKER, (index, 'marker')
        op = operation(functions[function_index])
        word = integer(op['word'])
        destination_register = op.get('d')
        if memory is not None or focus == TAG_ARITHMETIC_FOCUS:
            assert observed['fpsr'] == pre_fpsr, (index, 'movement_fpsr')
            for register in set(range(32)) - written_vectors:
                assert record[320 + register * 16:336 + register * 16] == initial[264 + register * 16:280 + register * 16], (index, 'non_destination_v', register)
            controls.setdefault(str(requested_fpcr), set()).add(pre_fpcr)
            continue
        for register in range(32):
            if op['output_kind'] != 'vector' or register != destination_register:
                assert record[320 + register * 16:336 + register * 16] == initial[264 + register * 16:280 + register * 16], (index, 'non_destination_v', register)
        if op['output_kind'] == 'vector':
            destination_offset = LAYOUT['v'] + destination_register * 16
            if op['scalar']:
                lane_bytes = op['lane']
                merge_register = op['n'] if op['merge'] == 'left_if_nep' else op['d']
                merge_offset = 264 + merge_register * 16
                expected_upper = (initial[merge_offset + lane_bytes:merge_offset + 16]
                                  if pre_fpcr & FPCR_NEP and op['merge'] != 'none' else bytes(16 - lane_bytes))
                assert record[destination_offset + lane_bytes:destination_offset + 16] == expected_upper, (index, 'declared_scalar_merge_or_clear')
            elif op['bytes'] == 8:
                assert record[destination_offset + 8:destination_offset + 16] == bytes(8), (index, 'vector64_upper_zero')
        controls.setdefault(str(requested_fpcr), set()).add(pre_fpcr)
        delta = observed['fpsr'] & ~pre_fpsr
        status_deltas[str(delta)] = status_deltas.get(str(delta), 0) + 1
        if requested_fpcr & FPCR_TRAP_MASK:
            trap_observations.append({'case': index, 'function_index': function_index,
                                      'requested_fpcr': requested_fpcr, 'pre_fpcr': pre_fpcr,
                                      'post_fpcr': observed['fpcr'], 'classification': 'requested_trap_enables_raz_wi'})
    return {**({'atomic_features': validate_atomic_features(results, focus)} if focus in ATOMIC_FEATURE_FOCUSES else {}),
            **({'tag_arithmetic_features': tag_features} if tag_features is not None else {}),
            **({'tag_soft_fixed_undefined_cases': tag_undefined_cases,
                'tag_soft_fixed_original_choice': 'ADDG/SUBG nonzero should-be-zero op3 may be UNDEFINED under pinned Arm C2-362/K1-16812. Exact original ESR/subject ELR and unchanged full frames are retained; execute-as-zero native policy receives no original equality credit. The exact linked next SVC bytes remain validated even when UNDEFINED prevents reaching them.'}
               if focus == TAG_ARITHMETIC_FOCUS else {}),
            **({'memory_controls': memory_controls} if memory is not None else {}),
            'cpu_registers': dict(zip(CPU_REGISTERS, map(hex, struct.unpack_from('<9Q', results)))),
            'fpcr_requested_readbacks': {key: sorted(value) for key, value in controls.items()},
            'trap_enable_readback_cases': trap_observations, 'observed_new_fpsr_masks': status_deltas}


def capture(prepared, directory, focus):
    directory = Path(directory).resolve()
    destination, qemu, bindings, functions, cases, inputs, subjects = prepared
    if destination.parent != directory or bindings['focus'] != focus:
        raise AssertionError('Original observer preparation/capture configuration differs')
    receipt_path = destination / 'receipt.json'
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_bytes())
        for name, info in receipt['files'].items():
            assert sha((destination / name).read_bytes()) == info['sha256'], name
    else:
        if not (destination / 'results.bin').exists():
            execute(destination, qemu, len(cases), focus)
        observations = validate_results(destination, functions, cases, inputs, subjects, focus)
        files = {path.name: {'sha256': sha(path.read_bytes()), 'bytes': path.stat().st_size}
                 for path in sorted(destination.iterdir()) if path.is_file() and path.name != 'receipt.json'}
        receipt = {'kind': focus + '_original_el0_full_frame_qemu',
                   'passed_transport_and_architectural_frame_checks': True,
                   'cases': len(cases), 'functions': len(functions), 'cpu': CPU_MODEL,
                   'directory': str(destination.relative_to(ROOT)), **bindings, **observations,
                   'input_stride': INPUT_STRIDE, 'state_bytes': STATE_BYTES,
                   'results_header_bytes': HEADER_BYTES, 'results_stride': bindings.get('memory_plan', {}).get('record_bytes', RECORD_BYTES),
                   'snapshot_layout': LAYOUT, 'files': files,
                   'checks': ['Each exact original SIMD instruction runs at EL0t with all 31 GPRs, SP_EL0, 32 full vectors, NZCV, FPCR and FPSR restored from the retained input.',
                              'A genuine SVC follows the subject; the EL1 handler snapshots all GPRs before transport clobbers and all vectors before transport resumes.',
                              ('Only declared GPR/SP results and SUBPS NZCV may change; all vectors, FP controls/status and remaining GPR/SP/PSTATE bits preserve.' if focus == TAG_ARITHMETIC_FOCUS else
                               'Only the actual pure family declared load/compare GPR destinations may change; SP, NZCV, vectors and FP controls/status preserve.' if focus in (ATOMIC_PAIR_FOCUS, ORDERED_UNSCALED_FOCUS, LIMITED_ORDERED_FOCUS) else
                               'All GPRs/SP, NZCV and non-destination vectors are unchanged. Scalars merge the declared original destination/left source under NEP or clear inactive bits; vector64 upper clears. QC and sticky flags preserve.'),
                              ('Actual preinstruction FPCR/FPSR readbacks and exact linked subject/next-SVC bytes identify every tag case. Successful executions have genuine SVC ESR/ELR; classified nonzero soft-field UNDEFINED cases have exact exception ESR/subject ELR and unchanged full frames.' if focus == TAG_ARITHMETIC_FOCUS else
                               'Actual preinstruction FPCR/FPSR readbacks, genuine SVC ESR, exact linked subject/SVC bytes and ELR identify every execution.')],
                   'limits': ['Original QEMU emulator observations only; no native execution, mathematical result-model validation, Apple hardware proof, or performance credit.',
                              'Canonical function identity is original SIMD word plus RET through the unused per-function return register. This EL0 fixture executes the unchanged SIMD word followed by SVC; the original RET is not executed.',
                              'QEMU trap enables are RAZ/WI. Exact requested and actual controls are retained; no FP trap-delivery credit is claimed.',
                              ('State.reserved is retained input metadata, not an architectural register. The bounded memory extension retains every8192 RAM byte after every subject; result-model equality belongs to the shared memory runner.' if 'memory_plan' in bindings else 'State.reserved is retained input metadata, not an architectural register; general guest RAM effects are not applicable to these register-only subjects.'),
                              'EL2/EL3/security, streaming modes and access-disabled execution are outside this fixture.']}
        write_new(receipt_path, json_bytes(receipt))
    publish_pointer(directory, receipt_path, focus, receipt)
    return receipt_path


def publish_pointer(directory, receipt_path, focus, receipt):
    pointer = {'kind': focus + '_original_oracle_capture_pointer',
               'directory': str(receipt_path.parent.relative_to(ROOT)),
               'receipt': {'path': str(receipt_path.relative_to(ROOT)),
                           'sha256': sha(receipt_path.read_bytes()), 'bytes': receipt_path.stat().st_size},
               'files': receipt['files']}
    pointer_path = directory / 'receipt.json'
    if pointer_path.exists():
        history = directory / 'pointer-history'
        history.mkdir(exist_ok=True)
        previous = pointer_path.read_bytes()
        write_new(history / f'{sha(previous)}.json', previous)
    next_pointer = directory / 'receipt.next.json'
    next_pointer.write_bytes(json_bytes(pointer))
    os.replace(next_pointer, pointer_path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--focus', required=True)
    parser.add_argument('--source-bindings', type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', action='store_true')
    group.add_argument('--capture', action='store_true')
    arguments = parser.parse_args()
    source_bindings = json.loads(arguments.source_bindings.read_bytes())
    if arguments.focus in ('atomic_memory_smp', 'atomic_pair_memory_smp'):
        import simd_atomic_original as smp
        if arguments.focus == 'atomic_pair_memory_smp':
            prepared = smp.prepare(arguments.directory, smp.pair_default_pairs(), source_bindings, focus=arguments.focus)
        else:
            prepared = smp.prepare(arguments.directory, smp.default_pairs(), source_bindings)
        if arguments.capture:
            path = smp.capture(prepared, arguments.directory)
            publish_pointer(arguments.directory.resolve(), path, arguments.focus, json.loads(path.read_bytes()))
            print(json.dumps({'receipt': str(path), 'sha256': sha(path.read_bytes())}))
        else:
            print(json.dumps({'prepared': str(prepared[0]), 'pairs': len(prepared[3]),
                              'trials': sum(pair['trials'] for pair in prepared[3]),
                              'guest_elf_sha256': sha((prepared[0] / 'guest.elf').read_bytes())}))
        raise SystemExit(0)
    prepared = prepare(arguments.directory, arguments.focus, source_bindings)
    if arguments.capture:
        path = capture(prepared, arguments.directory, arguments.focus)
        print(json.dumps({'receipt': str(path), 'sha256': sha(path.read_bytes())}))
    else:
        destination = prepared[0]
        print(json.dumps({'prepared': str(destination), 'functions': len(prepared[3]),
                          'cases': len(prepared[4]), 'guest_elf_sha256': sha((destination / 'guest.elf').read_bytes())}))
