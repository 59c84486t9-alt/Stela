#!/usr/bin/env python3
"""Genuine EL0 scalable-state snapshots with immutable QEMU transport evidence.

The Apple-like profile has SME and streaming SVE, with ordinary SVE and FA64
absent. FFR is allocated in the wire format but cannot be accessed by this
architectural observer; it never receives architectural validity credit.
"""

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
import shlex
from pathlib import Path
import struct
import subprocess

import scalable_frame as frame
import simd_original as shared

ROOT = shared.ROOT
UPGRADED_QEMU = ROOT / '.stela/research/cssc-implementation/oracle-upgrade/bin/qemu-system-aarch64'
CPU_PROFILE = 'max,sve=off,sme=on,sme_fa64=off'
SVE_ACCESS = 3 << 16
SMCR_FA64 = 1 << 31
ID_MMFR2_AT_SHIFT = 32
ID_ZFR0_B16B16_SHIFT = 24
ID_SMFR0_SMEVER_SHIFT = 56
LSE2_AT_FIELD = 1
MACHO_MAGIC_64 = 0xfeedfacf
MACHO_EXECUTE = 2
MACHO_UUID_COMMAND = 0x1b


@dataclass(frozen=True)
class CaptureProfile:
    id: str
    version: int
    cpu: str
    sve: bool
    capture_mmfr2: bool
    bf16_vector: bool = False

    @property
    def cpacr(self):
        return FP_ACCESS | SME_ACCESS | (SVE_ACCESS if self.sve else 0)

    @property
    def registers(self):
        return GLOBAL_REGISTERS + (('ID_AA64MMFR2_EL1',) if self.capture_mmfr2 else ())


SME_ONLY_V1 = CaptureProfile('apple-streaming-sme-v1', 1, CPU_PROFILE, False, False)
SME_ONLY_V2 = CaptureProfile('apple-streaming-sme-v2', 2, CPU_PROFILE, False, True)
SVE_STREAMING_BF16_V2 = CaptureProfile('sve-streaming-bf16-fa64-off-v2', 2,
    'max,sve=on,sme=on,sme_fa64=off', True, True, True)
PROFILES = {profile.id: profile for profile in (SME_ONLY_V1, SME_ONLY_V2, SVE_STREAMING_BF16_V2)}

FP_ACCESS = 3 << 20
SME_ACCESS = 3 << 24
SMCR_ZT0_ENABLE = 1 << 30
SCTLR_TPIDR2_ENABLE = 1 << 60
SCTLR_BASE = shared.MEMORY_SCTLR
PRIMARY_SP = 248
PRIMARY_NZCV = 256
PRIMARY_FPCR = 776
PRIMARY_FPSR = 780
HEADER_VALID = 44
HEADER_PROVENANCE = 48
STATUS_COMPLETE = 0
STATUS_OBSERVER_FAILURE = 1
PHASE_SETUP = 0
PHASE_SUBJECT = 1
PHASE_CAPTURE = 2
SCRATCH_INPUT = 0
SCRATCH_OUTPUT = 8
SCRATCH_REMAINING = 16
SCRATCH_PHASE = 24
SCRATCH_RAM_INPUT = 32
RAM_INPUT_ADDRESS = 0x45000000
MAX_CAPTURE_CASES = 128
RAW_PRE_NAMES = ('fpcr', 'fpsr', 'svcr', 'rdsvl', 'tpidr2_el0', 'fpmr', 'cpacr', 'smcr')
RAW_PRE_FORMAT = struct.Struct('<' + 'Q' * len(RAW_PRE_NAMES))
GLOBAL_HEADER_BYTES = 1024
ID_PFR0_SVE_SHIFT = 32
ID_PFR1_SME_SHIFT = 24
ID_SMFR0_FA64_SHIFT = 63
ID_PFR2_FPMR_SHIFT = 32
FEATURE_NIBBLE_MASK = 15
SME2_MINIMUM_FIELD = 2
CURRENT_EL1 = 4
SMCR_LENGTH_MASK = 15
SUBJECT_AND_SVC_BYTES = 8
GLOBAL_REGISTERS = ('CurrentEL', 'ID_AA64PFR0_EL1', 'ID_AA64PFR1_EL1',
                    'ID_AA64ZFR0_EL1', 'ID_AA64SMFR0_EL1', 'ID_AA64PFR2_EL1',
                    'CPACR_EL1', 'SMCR_EL1', 'SCTLR_EL1', 'TCR_EL1', 'MAIR_EL1', 'TTBR0_EL1')
CONTROL_REGISTERS = {
    'svcr': 'SVCR', 'tpidr2_el0': 'TPIDR2_EL0',
    'esr': 'ESR_EL1', 'elr': 'ELR_EL1', 'far': 'FAR_EL1',
    'spsr': 'SPSR_EL1', 'current_el': 'CurrentEL', 'cpacr': 'CPACR_EL1',
    'smcr': 'SMCR_EL1', 'sctlr': 'SCTLR_EL1',
    'pfr0': 'ID_AA64PFR0_EL1', 'pfr1': 'ID_AA64PFR1_EL1',
    'zfr0': 'ID_AA64ZFR0_EL1', 'smfr0': 'ID_AA64SMFR0_EL1',
}
SVC_ESR = (0x15 << 26) | (1 << 25) | shared.SVC_IMMEDIATE
LIMITS = [
    'QEMU TCG original execution, not Apple hardware or complete process/OS acceptance.',
    'SME-only streaming SVE with FA64 disabled; no ordinary nonstreaming SVE support claim.',
    'FFR cannot be seeded or captured architecturally in this profile and has no validity credit.',
    'ZA/ZT0 bytes are not architectural observations when SVCR.ZA is clear.',
    'Z/P upper state is not architecturally observable when SVCR.SM is clear.',
    'Original FP control/status readbacks are retained separately from requested input bits.',
    'Bounded Normal-memory identity mappings; exact synchronous exceptions may be captured, with no trap-resumption or OS-delivery claim.',
    'Native translated execution, model equality and performance are separate consumers.',
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def control_offset(name):
    return frame.HEADER_PREFIX.size + frame.CONTROL_NAMES.index(name) * struct.calcsize('<Q')


def pointer(register, base, offset):
    return shared.mov(register, base + offset)


def relative_pointer(register, base, offset):
    return shared.mov(register, offset) + [f'add {register},{base},{register}']


def store_control(name, value_register='x0'):
    return [f'str {value_register},[sp,#{control_offset(name)}]']


def row_transfer(bank, loading, base_register, length):
    opcode = 'ldr' if loading else 'str'
    count = frame.VECTOR_COUNT if bank == 'z' else frame.PREDICATE_COUNT
    return [f'{opcode} {bank}{index},[{base_register},#{index},mul vl]'
            for index in range(count)]


def za_transfer(loading, length, label):
    opcode = 'ldr' if loading else 'str'
    return ['mov w12,#0', label + ':', f'{opcode} za[w12,0],[x0]',
            f'add x0,x0,#{length}', 'add w12,w12,#1', f'cmp w12,#{length}',
            f'b.lo {label}']


def setup_assembly(length, count, profile=SME_ONLY_V1):
    lines = ['.arch armv9.4-a+sme2', '.text', '.global _start', '_start:']
    lines += pointer('x0', shared.OUTPUT_ADDRESS, 0) + ['mov sp,x0']
    lines += ['adrp x0,vectors', 'add x0,x0,:lo12:vectors', 'msr vbar_el1,x0', 'isb']
    lines += shared.mov('x0', profile.cpacr) + ['msr cpacr_el1,x0', 'isb']
    lines += shared.mov('x0', SMCR_ZT0_ENABLE | (length // frame.FIXED_VECTOR_BYTES - 1))
    lines += ['msr smcr_el1,x0', 'isb']
    if profile.sve:
        lines += shared.mov('x0', length // frame.FIXED_VECTOR_BYTES - 1)
        lines += ['msr zcr_el1,x0', 'isb']
    lines += shared.memory_setup()
    lines += shared.mov('x0', SCTLR_BASE | SCTLR_TPIDR2_ENABLE)
    lines += ['msr sctlr_el1,x0', 'isb']
    lines += pointer('x1', shared.OUTPUT_ADDRESS - GLOBAL_HEADER_BYTES, 0)
    for index, register in enumerate(profile.registers):
        lines += [f'mrs x0,{register}', f'str x0,[x1,#{index * 8}]']
    lines += pointer('x0', shared.SCRATCH_ADDRESS, 0)
    for offset, value in ((SCRATCH_INPUT, shared.INPUT_ADDRESS),
                          (SCRATCH_OUTPUT, shared.OUTPUT_ADDRESS),
                          (SCRATCH_REMAINING, count), (SCRATCH_PHASE, PHASE_SETUP),
                          (SCRATCH_RAM_INPUT, RAM_INPUT_ADDRESS)):
        lines += shared.mov('x1', value) + [f'str x1,[x0,#{offset}]']
    return lines


def seed_assembly(layout, capture_fpmr):
    length = layout['length']
    lines = ['again:'] + pointer('x0', shared.SCRATCH_ADDRESS, 0)
    lines += ['ldr x19,[x0]', 'ldr x20,[x0,#8]', 'mov sp,x20',
              'str xzr,[x0,#24]']
    # Copy the input framing and diagnostic banks. The final validity mask
    # distinguishes observed banks from inaccessible input storage.
    lines += ['mov x0,x19', 'mov x1,x20'] + shared.mov('x2', layout['frame_bytes'] // 16)
    lines += ['copy_input:', 'ldp x3,x4,[x0],#16', 'stp x3,x4,[x1],#16',
              'subs x2,x2,#1', 'b.ne copy_input']
    if layout['ram_bytes']:
        lines += pointer('x0', shared.SCRATCH_ADDRESS, SCRATCH_RAM_INPUT) + ['ldr x0,[x0]']
        lines += pointer('x1', frame.RAM_ADDRESS, 0) + shared.mov('x2', layout['ram_bytes'] // 16)
        lines += ['restore_ram:', 'ldp x3,x4,[x0],#16', 'stp x3,x4,[x1],#16',
                  'subs x2,x2,#1', 'b.ne restore_ram']
    lines += [f'ldr x0,[x19,#{control_offset("svcr")}]', 'msr svcr,x0']
    lines += store_control('requested_svcr')
    lines += [f'ldr x0,[x19,#{control_offset("tpidr2_el0")}]', 'msr tpidr2_el0,x0']
    if capture_fpmr:
        lines += [f'ldr x0,[x19,#{control_offset("fpmr")}]', 'msr S3_3_C4_C4_2,x0']
    lines += ['mrs x0,svcr', 'tbz x0,#1,seed_no_za']
    lines += relative_pointer('x0', 'x19', layout['za'])
    lines += za_transfer(True, length, 'seed_za')
    lines += relative_pointer('x0', 'x19', layout['zt0']) + ['ldr zt0,[x0]', 'seed_no_za:']
    lines += ['mrs x0,svcr', 'tbz x0,#0,seed_nonstreaming']
    lines += relative_pointer('x0', 'x19', layout['z']) + row_transfer('z', True, 'x0', length)
    lines += relative_pointer('x0', 'x19', layout['p']) + row_transfer('p', True, 'x0', length)
    lines += ['b seed_vectors_done', 'seed_nonstreaming:']
    lines += relative_pointer('x0', 'x19', layout['primary'] + frame.PRIMARY_VECTOR_OFFSET)
    lines += [f'ldr q{index},[x0,#{index * frame.FIXED_VECTOR_BYTES}]'
              for index in range(frame.VECTOR_COUNT)]
    lines += ['seed_vectors_done:']
    for name, offset in (('fpcr', PRIMARY_FPCR), ('fpsr', PRIMARY_FPSR)):
        lines += [f'ldr w0,[x19,#{layout["primary"] + offset}]', f'msr {name},x0']
        lines += store_control('requested_' + name)
    lines += relative_pointer('x1', 'sp', layout['frame_bytes'])
    for index, name in enumerate(RAW_PRE_NAMES):
        if name == 'fpmr':
            lines += ['mrs x0,S3_3_C4_C4_2' if capture_fpmr else 'mov x0,xzr']
        elif name == 'rdsvl':
            lines += ['rdsvl x0,#1']
        else:
            lines += [f'mrs x0,{CONTROL_REGISTERS.get(name, name)}']
        lines += [f'str x0,[x1,#{index * 8}]']
    primary = layout['primary']
    lines += [f'ldr x0,[x19,#{primary + PRIMARY_SP}]', 'msr sp_el0,x0',
              f'ldr w0,[x19,#{primary + PRIMARY_NZCV}]', f'and x0,x0,#{shared.NZCV_MASK:#x}',
              f'orr x0,x0,#{shared.PSTATE_EL0T_MASKED:#x}', 'msr spsr_el1,x0',
              'adrp x0,functions', 'add x0,x0,:lo12:functions',
              'ldr x1,[x19,#32]', 'ldr x0,[x0,x1,lsl#3]', 'msr elr_el1,x0']
    lines += pointer('x0', shared.SCRATCH_ADDRESS, SCRATCH_PHASE)
    lines += [f'mov x1,#{PHASE_SUBJECT}', 'str x1,[x0]', 'mov x30,x19']
    lines += [f'ldp x{index},x{index + 1},[x30,#{primary + index * 8}]'
              for index in range(0, 30, 2)]
    lines += [f'ldr x30,[x30,#{primary + 30 * 8}]', 'eret']
    return lines


def capture_assembly(layout, capture_fpmr, profile=SME_ONLY_V1):
    primary, length = layout['primary'], layout['length']
    lines = ['exception_entry:']
    lines += [f'stp x{index},x{index + 1},[sp,#{primary + index * 8}]'
              for index in range(0, 30, 2)]
    lines += [f'str x30,[sp,#{primary + 30 * 8}]']
    lines += pointer('x0', shared.SCRATCH_ADDRESS, SCRATCH_PHASE)
    lines += ['ldr x1,[x0]', f'cmp x1,#{PHASE_SUBJECT}', 'b.ne observer_failure',
              f'mov x1,#{PHASE_CAPTURE}', 'str x1,[x0]',
              'mrs x0,sp_el0', f'str x0,[sp,#{primary + PRIMARY_SP}]',
              'mrs x0,spsr_el1', f'and x0,x0,#{shared.NZCV_MASK:#x}',
              f'str w0,[sp,#{primary + PRIMARY_NZCV}]']
    for name, offset in (('fpcr', PRIMARY_FPCR), ('fpsr', PRIMARY_FPSR)):
        lines += [f'mrs x0,{name}', f'str w0,[sp,#{primary + offset}]']
    registers = dict(CONTROL_REGISTERS)
    if profile.sve:
        registers['zcr'] = 'ZCR_EL1'
    for name, register in registers.items():
        lines += [f'mrs x0,{register}'] + store_control(name)
    lines += ['rdsvl x0,#1'] + store_control('rdsvl')
    lines += ['adr x0,exception_entry'] + store_control('observation_pc')
    lines += [f'mov x0,#{STATUS_COMPLETE}'] + store_control('status')
    lines += [f'mov x0,#{shared.COMPLETED_MARKER}'] + store_control('marker')
    for name in ('zcr', 'choice_bits', 'reserved_control'):
        if name == 'zcr' and profile.sve:
            continue
        lines += store_control(name, 'xzr')
    if capture_fpmr:
        lines += ['mrs x0,S3_3_C4_C4_2'] + store_control('fpmr')
    else:
        lines += store_control('fpmr', 'xzr')
    valid = frame.Component.PRIMARY | frame.Component.SVCR | frame.Component.TPIDR2
    if capture_fpmr:
        valid |= frame.Component.FPMR
    lines += [f'mov x21,#{int(valid)}', 'mrs x0,svcr', 'tbz x0,#0,capture_nonstreaming']
    lines += relative_pointer('x0', 'sp', layout['z']) + row_transfer('z', False, 'x0', length)
    lines += relative_pointer('x0', 'sp', layout['p']) + row_transfer('p', False, 'x0', length)
    lines += [f'orr x21,x21,#{int(frame.Component.Z | frame.Component.P)}', 'b capture_vectors_done',
              'capture_nonstreaming:']
    lines += relative_pointer('x0', 'sp', primary + frame.PRIMARY_VECTOR_OFFSET)
    lines += [f'str q{index},[x0,#{index * frame.FIXED_VECTOR_BYTES}]'
              for index in range(frame.VECTOR_COUNT)]
    lines += ['capture_vectors_done:', 'mrs x0,svcr', 'tbz x0,#1,capture_no_za']
    lines += relative_pointer('x0', 'sp', layout['za']) + za_transfer(False, length, 'capture_za')
    lines += relative_pointer('x0', 'sp', layout['zt0']) + ['str zt0,[x0]']
    lines += [f'orr x21,x21,#{int(frame.Component.ZA | frame.Component.ZT0)}', 'capture_no_za:',
              f'str w21,[sp,#{HEADER_VALID}]',
              f'mov w0,#{int(frame.Provenance.ARCHITECTURAL)}', f'str w0,[sp,#{HEADER_PROVENANCE}]',
              'smstop sm']
    if layout['ram_bytes']:
        lines += pointer('x0', frame.RAM_ADDRESS, 0)
        lines += relative_pointer('x1', 'sp', layout['frame_bytes'] + RAW_PRE_FORMAT.size)
        lines += shared.mov('x2', layout['ram_bytes'] // 16)
        lines += ['snapshot_ram:', 'ldp x3,x4,[x0],#16', 'stp x3,x4,[x1],#16',
                  'subs x2,x2,#1', 'b.ne snapshot_ram']
        lines += pointer('x0', shared.SCRATCH_ADDRESS, SCRATCH_RAM_INPUT)
        lines += ['ldr x1,[x0]'] + shared.mov('x2', layout['ram_bytes'])
        lines += ['add x1,x1,x2', 'str x1,[x0]']
    # The primary V bank is populated offline from the captured full Z bank.
    # Scalar copies here avoid corrupting result flags or touching invalid Z/P.
    lines += pointer('x0', shared.SCRATCH_ADDRESS, 0)
    lines += ['ldp x1,x2,[x0]'] + shared.mov('x3', layout['frame_bytes'])
    lines += ['add x1,x1,x3'] + shared.mov('x3', layout['raw_bytes'])
    lines += ['add x2,x2,x3', 'stp x1,x2,[x0]', 'ldr x1,[x0,#16]',
              'subs x1,x1,#1', 'str x1,[x0,#16]', 'b.eq finished',
              'adr x0,again', 'msr elr_el1,x0']
    lines += shared.mov('x0', shared.PSTATE_EL1H_MASKED)
    lines += ['msr spsr_el1,x0', 'eret', 'observer_failure:',
              'mrs x0,esr_el1'] + store_control('esr')
    lines += ['mrs x0,elr_el1'] + store_control('elr')
    lines += [f'mov x0,#{STATUS_OBSERVER_FAILURE}'] + store_control('status')
    lines += ['finished:'] + pointer('x0', shared.MARKER_ADDRESS, 0)
    lines += shared.mov('x1', shared.COMPLETED_MARKER) + ['str x1,[x0]', 'completed: b completed']
    return lines


def assembly(words, count, length, capture_fpmr=False, ram_bytes=0, profile=SME_ONLY_V1):
    frame.require_sme_length(length)
    layout = {**frame.offsets(length), 'length': length}
    layout['frame_bytes'] = layout['record_bytes']
    layout['ram_bytes'] = ram_bytes
    layout['raw_bytes'] = layout['frame_bytes'] + RAW_PRE_FORMAT.size + ram_bytes
    lines = setup_assembly(length, count, profile) + seed_assembly(layout, capture_fpmr)
    for index, word in enumerate(words):
        lines += [f'subject_{index}:', f'.inst 0x{word:08x}', f'svc #{shared.SVC_IMMEDIATE}']
    lines += ['.balign 2048', 'vectors:']
    for _ in range(16):
        lines += ['b exception_entry', '.space 124']
    lines += capture_assembly(layout, capture_fpmr, profile)
    lines += ['.section .rodata', '.balign 8', 'functions:']
    lines += [f'.quad subject_{index}' for index in range(len(words))]
    return '\n'.join(lines) + '\n', layout


def validate_inputs(functions, snapshots):
    if not functions or not snapshots:
        raise ValueError('Original capture requires subjects and input snapshots')
    if len(snapshots) > MAX_CAPTURE_CASES:
        raise ValueError('Chunk original captures into at most 128 cases')
    words = []
    for function in functions:
        word = function['word']
        if type(word) is not int or not 0 <= word < 1 << 32:
            raise ValueError('Subject word must fit u32')
        words.append(word)
    if len(set(words)) != len(words):
        raise ValueError('Each exact subject word requires one function')
    length = frame.require_sme_length(snapshots[0].svl_bytes)
    for index, snapshot in enumerate(snapshots):
        if snapshot.svl_bytes != length or not 0 <= snapshot.function_index < len(functions):
            raise ValueError('One capture requires one length and valid function indices')
        if snapshot.case_index != index:
            raise ValueError('Capture case indices must be contiguous from zero')
        if snapshot.control('svcr') & ~frame.SVCR_MASK:
            raise ValueError('Input SVCR contains unsupported bits')
        if snapshot.control('svcr') & frame.SVCR_SM:
            required = frame.Component.PRIMARY | frame.Component.Z | frame.Component.P
            if snapshot.valid & required != required:
                raise ValueError('Streaming input requires initialized Z/P banks')
        if snapshot.control('svcr') & frame.SVCR_ZA:
            required = frame.Component.ZA | frame.Component.ZT0
            if snapshot.valid & required != required:
                raise ValueError('ZA-enabled input requires initialized ZA/ZT0')
    return words, length


def macho_identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    if len(data) < 32:
        raise AssertionError('Executed QEMU Mach-O header is truncated')
    magic, cpu_type, cpu_subtype, file_type, count, commands_bytes, flags, reserved = struct.unpack_from('<8I', data)
    if magic != MACHO_MAGIC_64 or file_type != MACHO_EXECUTE or reserved:
        raise AssertionError('Executed QEMU is not a supported thin Mach-O executable')
    commands_end = 32 + commands_bytes
    if commands_end > len(data):
        raise AssertionError('Executed QEMU Mach-O commands are truncated')
    offset, uuid = 32, None
    for _ in range(count):
        command, size = struct.unpack_from('<2I', data, offset)
        if size < 8 or offset + size > commands_end:
            raise AssertionError('Executed QEMU Mach-O command size differs')
        if command == MACHO_UUID_COMMAND:
            if size != 24 or uuid is not None:
                raise AssertionError('Executed QEMU Mach-O UUID command differs')
            uuid = data[offset + 8:offset + size].hex()
        offset += size
    if offset != commands_end:
        raise AssertionError('Executed QEMU Mach-O command count differs')
    return {'path': str(path), 'sha256': digest(data), 'bytes': len(data),
            'kind': 'thin-little-endian-mach-o-64-execute', 'cpu_type': cpu_type,
            'cpu_subtype': cpu_subtype, 'uuid': uuid, 'flags': flags}


def tool_bindings(qemu):
    _, clang, lld, bindings = shared.tools_and_bindings()
    executable = Path(qemu or UPGRADED_QEMU).resolve()
    if not executable.is_file():
        raise FileNotFoundError('A bound QEMU SME2 oracle is required: ' + str(executable))
    version = subprocess.check_output([str(executable), '--version'], text=True).splitlines()[0]
    bindings['selected_qemu'] = {'path': str(executable), 'sha256': digest(executable.read_bytes()),
                                 'version': version}
    if executable == UPGRADED_QEMU.resolve():
        receipt_path = UPGRADED_QEMU.parent.parent / 'build-receipt.json'
        build = json.loads(receipt_path.read_bytes())
        binary = Path(build['binary'])
        actual_hash = digest(binary.read_bytes())
        if actual_hash != build['binary_sha256']:
            raise AssertionError('Upgraded QEMU binary differs from its build receipt')
        bindings['selected_qemu']['binary'] = {'path': str(binary), 'sha256': actual_hash}
        bindings['selected_qemu']['build_receipt_sha256'] = digest(receipt_path.read_bytes())
    selected = bindings['selected_qemu']
    if 'binary' not in selected:
        raise AssertionError('Selected QEMU wrapper lacks a bound executed binary')
    wrapper_lines = executable.read_text().splitlines()
    exec_lines = [line for line in wrapper_lines if line.startswith('exec ')]
    if len(exec_lines) != 1:
        raise AssertionError('QEMU wrapper must contain one explicit exec command')
    tokens = shlex.split(exec_lines[0])
    if len(tokens) != 3 or tokens[2] != '$@':
        raise AssertionError('QEMU wrapper exec command differs from the bound plan')
    executed = Path(tokens[1]).resolve()
    if executed != Path(selected['binary']['path']).resolve():
        raise AssertionError('QEMU wrapper executes a different binary than its receipt')
    selected['executed_binary'] = macho_identity(executed)
    if selected['executed_binary']['sha256'] != selected['binary']['sha256']:
        raise AssertionError('Executed QEMU Mach-O differs from the build receipt')
    bindings['scalable_producer_sha256'] = digest(Path(__file__).read_bytes())
    bindings['frame_source_sha256'] = digest(Path(frame.__file__).read_bytes())
    return executable, clang, lld, bindings


def canonical_results(raw, snapshots, subjects, layout, capture_fpmr, profile_spec=SME_ONLY_V1):
    expected_bytes = GLOBAL_HEADER_BYTES + len(snapshots) * layout['raw_bytes']
    if len(raw) != expected_bytes:
        raise AssertionError('Original scalable raw byte count differs')
    profile = dict(zip(profile_spec.registers, struct.unpack_from('<' + 'Q' * len(profile_spec.registers), raw)))
    if (profile['CurrentEL'] != CURRENT_EL1 or bool(profile['ID_AA64PFR0_EL1'] >> ID_PFR0_SVE_SHIFT & FEATURE_NIBBLE_MASK) != profile_spec.sve
            or profile['ID_AA64PFR1_EL1'] >> ID_PFR1_SME_SHIFT & FEATURE_NIBBLE_MASK < SME2_MINIMUM_FIELD
            or profile['ID_AA64SMFR0_EL1'] >> ID_SMFR0_FA64_SHIFT & 1
            or profile['CPACR_EL1'] != profile_spec.cpacr
            or profile['SMCR_EL1'] & (SMCR_ZT0_ENABLE | SMCR_LENGTH_MASK) != SMCR_ZT0_ENABLE | (layout['length'] // frame.FIXED_VECTOR_BYTES - 1)):
        raise AssertionError('Actual original CPU/access/SME profile differs: ' + str(profile))
    if profile['SMCR_EL1'] & SMCR_FA64:
        raise AssertionError('Original streaming profile requires FA64 disabled')
    if profile_spec.capture_mmfr2:
        at = profile['ID_AA64MMFR2_EL1'] >> ID_MMFR2_AT_SHIFT & FEATURE_NIBBLE_MASK
        if at != LSE2_AT_FIELD:
            raise AssertionError('Original Normal-memory profile requires actual FEAT_LSE2 AT=1')
    if profile_spec.bf16_vector:
        b16b16 = profile['ID_AA64ZFR0_EL1'] >> ID_ZFR0_B16B16_SHIFT & FEATURE_NIBBLE_MASK
        smever = profile['ID_AA64SMFR0_EL1'] >> ID_SMFR0_SMEVER_SHIFT & FEATURE_NIBBLE_MASK
        if b16b16 != 1 or smever not in (1, 2):
            raise AssertionError('Original BF vector profile requires ZFR0.B16B16=1 and SME2')
        if any(not snapshot.control('svcr') & frame.SVCR_SM for snapshot in snapshots):
            raise AssertionError('BF vector originals require streaming mode for every subject')
    for name in ('TCR_EL1', 'MAIR_EL1', 'TTBR0_EL1'):
        if profile[name] != shared.MEMORY_CONTROLS[name]:
            raise AssertionError('Actual original MMU control differs: ' + name)
    if profile['SCTLR_EL1'] != SCTLR_BASE | SCTLR_TPIDR2_ENABLE:
        raise AssertionError('Actual original SCTLR profile differs')
    if capture_fpmr and profile['ID_AA64PFR2_EL1'] >> ID_PFR2_FPMR_SHIFT & FEATURE_NIBBLE_MASK == 0:
        raise AssertionError('FPMR capture requested without an observed FPMR feature')
    outputs, rows, ram_outputs = [], [], []
    for index, initial in enumerate(snapshots):
        start = GLOBAL_HEADER_BYTES + index * layout['raw_bytes']
        record = bytearray(raw[start:start + layout['frame_bytes']])
        controls = dict(zip(frame.CONTROL_NAMES, frame.CONTROL_FORMAT.unpack_from(record, frame.HEADER_PREFIX.size)))
        before = dict(zip(RAW_PRE_NAMES, RAW_PRE_FORMAT.unpack_from(raw, start + layout['frame_bytes'])))
        if controls['status'] != STATUS_COMPLETE or controls['marker'] != shared.COMPLETED_MARKER:
            raise AssertionError('Original observer failed: ' + str((index, controls)))
        subject = subjects[initial.function_index]
        completed = controls['esr'] == SVC_ESR
        if controls['elr'] != subject['instruction_pc'] + (SUBJECT_AND_SVC_BYTES if completed else 0):
            raise AssertionError('Original exception is not bound to exact subject/SVC: ' + str((index, controls)))
        if before['svcr'] != initial.control('svcr') or before['rdsvl'] != layout['length']:
            raise AssertionError('Original input mode/vector length differs')
        if controls['rdsvl'] != layout['length']:
            raise AssertionError('Subject changed unsupported vector length')
        valid = struct.unpack_from('<I', record, HEADER_VALID)[0]
        if valid & int(frame.Component.Z):
            for register in range(frame.VECTOR_COUNT):
                source = layout['z'] + register * layout['length']
                target = layout['primary'] + frame.PRIMARY_VECTOR_OFFSET + register * frame.FIXED_VECTOR_BYTES
                record[target:target + frame.FIXED_VECTOR_BYTES] = record[source:source + frame.FIXED_VECTOR_BYTES]
        # Explicitly clear unavailable diagnostic bytes in the canonical record;
        # the immutable raw capture retains the original copied input bytes.
        record[layout['ffr']:layout['za']] = bytes(layout['length'] // frame.BITS_PER_BYTE)
        output = frame.Snapshot.from_bytes(bytes(record))
        outputs.append(output)
        if layout['ram_bytes']:
            ram_start = start + layout['frame_bytes'] + RAW_PRE_FORMAT.size
            ram_outputs.append(raw[ram_start:ram_start + layout['ram_bytes']])
        rows.append({'case_index': index, 'function_index': initial.function_index,
                     'source_word': int.from_bytes(bytes.fromhex(subject['executed_source_hex'])[:4], 'little'), 'instruction_pc': subject['instruction_pc'],
                     'completed_subject': completed, 'esr': hex(controls['esr']), 'elr': hex(controls['elr']),
                     'initial_readbacks': {name: hex(value) for name, value in before.items()},
                     'valid_components': int(output.valid), 'input_sha256': initial.digest(),
                     'raw_sha256': digest(raw[start:start + layout['raw_bytes']]),
                     'snapshot_sha256': output.digest()})
    return outputs, profile, rows, ram_outputs


def capture(directory, functions, input_frames, *, qemu=None, capture_fpmr=False,
            ram_inputs=None, timeout=60, profile=SME_ONLY_V2):
    """Execute exact original subject words and return a bound capture receipt.

    Functions contain an integer ``word`` and optional descriptive metadata.
    Inputs are Snapshot instances or canonical serialized snapshots. All cases
    share one declared SME vector length. The original subject may trap; only
    SVC after the exact subject counts as successful execution.
    """
    if isinstance(profile, str):
        profile = PROFILES[profile]
    if profile not in PROFILES.values():
        raise ValueError('Unknown original capture profile')
    snapshots = [frame.Snapshot.from_bytes(item) if isinstance(item, bytes) else item
                 for item in input_frames]
    functions = [dict(item) for item in functions]
    for function in functions:
        canonical = struct.pack('<II', function['word'], shared.RET_WORD).hex()
        if function.get('source_hex', canonical) != canonical:
            raise ValueError('Canonical subject source bytes differ')
        function['source_hex'] = canonical
    words, length = validate_inputs(functions, snapshots)
    ram_bytes = 0
    if ram_inputs is not None:
        if (len(ram_inputs) != len(snapshots) or any(type(item) is not bytes or len(item) != frame.RAM_BYTES
                                                  for item in ram_inputs)):
            raise ValueError('Original RAM requires one exact 8192-byte input per case')
        ram_bytes = frame.RAM_BYTES
    source, layout = assembly(words, len(snapshots), length, capture_fpmr, ram_bytes, profile)
    if (shared.INPUT_ADDRESS + len(snapshots) * layout['frame_bytes'] > (RAM_INPUT_ADDRESS if ram_bytes else shared.OUTPUT_ADDRESS - GLOBAL_HEADER_BYTES)
            or shared.OUTPUT_ADDRESS + len(snapshots) * layout['raw_bytes'] > shared.QEMU_RAM_END):
        raise ValueError('Scalable original corpus exceeds bounded QEMU memory')
    destination = Path(directory).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    executable, clang, lld, bindings = tool_bindings(qemu)
    files = {'guest.S': source.encode(), 'inputs.bin': b''.join(item.to_bytes() for item in snapshots),
             'functions.json': shared.json_bytes(functions), 'bindings.json': shared.json_bytes(bindings),
             'producer.py': Path(__file__).read_bytes(), 'frame.py': Path(frame.__file__).read_bytes()}
    if ram_inputs is not None:
        files['initial-ram.bin'] = b''.join(ram_inputs)
    for name, data in files.items():
        shared.write_new(destination / name, data)
    commands = [
        [str(clang), '--target=aarch64-unknown-none-elf', '-c', str(destination / 'guest.S'), '-o', str(destination / 'guest.o')],
        [str(lld), *(['-flavor', 'gnu'] if lld.name == 'rust-lld' else []), '-m', 'aarch64elf',
         '-Ttext', hex(shared.TEXT_ADDRESS), '-e', '_start', str(destination / 'guest.o'), '-o', str(destination / 'guest.elf')],
    ]
    environment = os.environ.copy()
    if lld.name == 'rust-lld' and os.uname().sysname == 'Darwin':
        environment['DYLD_LIBRARY_PATH'] = str(lld.resolve().parents[3])
    for index, command in enumerate(commands):
        shared.write_new(destination / f'build-command-{index}.json', shared.json_bytes(command))
        subprocess.run(command, check=True, env=environment)
    subjects = shared.elf_subjects(destination / 'guest.elf', words, functions)
    shared.write_new(destination / 'subjects.json', shared.json_bytes(subjects))
    command = [str(executable), '-machine', 'virt,secure=off,virtualization=off', '-cpu', profile.cpu,
               '-accel', 'tcg', '-m', shared.MEMORY_QEMU_RAM_SIZE if ram_bytes else '512M', '-display', 'none', '-serial', 'none', '-monitor', 'none',
               '-nic', 'none', '-kernel', str(destination / 'guest.elf'), '-device',
               f'loader,file={destination / "inputs.bin"},addr={shared.INPUT_ADDRESS:#x},force-raw=on']
    if ram_bytes:
        command += ['-device', f'loader,file={destination / "initial-ram.bin"},addr={RAM_INPUT_ADDRESS:#x},force-raw=on']
    raw_bytes = GLOBAL_HEADER_BYTES + len(snapshots) * layout['raw_bytes']
    shared.execute_transport(destination, command, raw_bytes, timeout=timeout)
    raw = (destination / 'results.bin').read_bytes()
    outputs, actual_profile, rows, ram_outputs = canonical_results(raw, snapshots, subjects, layout, capture_fpmr, profile)
    shared.write_new(destination / 'frames.bin', b''.join(item.to_bytes() for item in outputs))
    if ram_outputs:
        shared.write_new(destination / 'ram-results.bin', b''.join(ram_outputs))
        for row, before, after in zip(rows, ram_inputs, ram_outputs):
            row['initial_ram_sha256'] = digest(before)
            row['observed_ram_sha256'] = digest(after)
    shared.write_new(destination / 'cases.json', shared.json_bytes(rows))
    executed_before = bindings['selected_qemu']['executed_binary']
    if macho_identity(executed_before['path']) != executed_before:
        raise AssertionError('Executed QEMU Mach-O changed during capture')
    if digest(executable.read_bytes()) != bindings['selected_qemu']['sha256']:
        raise AssertionError('Selected QEMU wrapper changed during capture')
    if digest(Path(__file__).read_bytes()) != bindings['scalable_producer_sha256']:
        raise AssertionError('Original scalable producer changed during execution')
    if digest(Path(frame.__file__).read_bytes()) != bindings['frame_source_sha256']:
        raise AssertionError('Scalable frame contract changed during execution')
    receipt = {'kind': f'original-el0-scalable-state-v{profile.version}', 'profile_id': profile.id, 'passed': True, 'cases': len(rows),
               'completed_subjects': sum(row['completed_subject'] for row in rows),
               'requested_svl_bytes': length, 'capture_fpmr': capture_fpmr,
               'ram_bytes_per_case': ram_bytes, 'ram_address': frame.RAM_ADDRESS if ram_bytes else None,
               'cpu_profile': profile.cpu, 'actual_profile': {name: hex(value) for name, value in actual_profile.items()},
               'raw_layout': layout, 'raw_pre_readback_fields': list(RAW_PRE_NAMES),
               'cases_file': 'cases.json', 'bindings': bindings,
               'limits': ([limit for limit in LIMITS if not limit.startswith('SME-only')] +
                   ['Explicit SVE-enabled supplemental oracle profile; SM remains enabled and FA64 disabled. No Apple hardware membership claim.'])
                   if profile.sve else LIMITS,
               'files': {path.name: {'sha256': digest(path.read_bytes()), 'bytes': path.stat().st_size}
                         for path in sorted(destination.iterdir()) if path.is_file()}}
    shared.write_new(destination / 'receipt.json', shared.json_bytes(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path, help='Directory containing functions.json and canonical inputs.bin')
    parser.add_argument('output', type=Path, help='New immutable original-capture directory')
    parser.add_argument('--qemu', type=Path)
    parser.add_argument('--profile', choices=PROFILES, default=SME_ONLY_V2.id)
    parser.add_argument('--capture-fpmr', action='store_true')
    parser.add_argument('--ram-inputs', type=Path, help='Contiguous 8192-byte RAM inputs, one per case')
    arguments = parser.parse_args()
    functions = json.loads((arguments.corpus / 'functions.json').read_bytes())
    data = (arguments.corpus / 'inputs.bin').read_bytes()
    if len(data) < frame.HEADER_BYTES:
        raise ValueError('Truncated scalable corpus')
    record_bytes = frame.HEADER_PREFIX.unpack_from(data)[3]
    if not record_bytes or len(data) % record_bytes:
        raise ValueError('Scalable corpus framing differs')
    inputs = [data[start:start + record_bytes] for start in range(0, len(data), record_bytes)]
    ram_inputs = None
    if arguments.ram_inputs is not None:
        ram = arguments.ram_inputs.read_bytes()
        ram_inputs = [ram[start:start + frame.RAM_BYTES]
                      for start in range(0, len(ram), frame.RAM_BYTES)]
    receipt = capture(arguments.output, functions, inputs, qemu=arguments.qemu,
                      capture_fpmr=arguments.capture_fpmr, ram_inputs=ram_inputs, profile=arguments.profile)
    print(json.dumps({'cases': receipt['cases'], 'completed_subjects': receipt['completed_subjects'],
                      'receipt': str(arguments.output / 'receipt.json')}, indent=2))


if __name__ == '__main__':
    main()
