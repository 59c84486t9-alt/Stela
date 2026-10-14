"""Bounded two-PE original atomic/ordered observer; shared CLI owns invocation.

This module collects original QEMU frames and RAM, not an Arm outcome model.
The single-PE observer and its default assembly remain independent.
"""
from collections import Counter
import json
import os
from pathlib import Path
import struct
import subprocess

from differential import ROOT, State
import simd_original as original
from simd_fixtures import atomic_memory

PE_COUNT = 2
MAX_PAIRS = 8
MAX_TRIALS = 512
MAX_PROGRAM_WORDS = 16
PAIR_INPUT_BYTES = PE_COUNT * original.INPUT_STRIDE
PAIR_RECORD_BYTES = PE_COUNT * original.RECORD_BYTES + original.MEMORY_RAM_BYTES
PE_HEADER_BYTES = original.HEADER_BYTES // PE_COUNT
MPIDR_OFFSET = original.ATOMIC_FEATURE_HEADER_OFFSET + 8
PSCI_RESULT_OFFSET = MPIDR_OFFSET + 8
SETUP_ERROR_OFFSET = PSCI_RESULT_OFFSET + 8
FINAL_GENERATION_OFFSET = SETUP_ERROR_OFFSET + 8
VBAR_OFFSET = FINAL_GENERATION_OFFSET + 8
CPACR_OFFSET = VBAR_OFFSET + 8
SETUP_SP_OFFSET = CPACR_OFFSET + 8
CONTROL_ADDRESS = 0x40073000
CONTROL_LINE_BYTES = 64
CONTROL_NAMES = ('ready', 'generation', 'armed', 'go', 'done0', 'done1',
                 'input', 'output', 'pair', 'error')
CONTROL = {name: CONTROL_ADDRESS + index * CONTROL_LINE_BYTES
           for index, name in enumerate(CONTROL_NAMES)}
CONTROL_BYTES = len(CONTROL_NAMES) * CONTROL_LINE_BYTES
SETUP_STACKS = (0x40078000, 0x4007a000)
PSCI_CPU_ON_64 = 0xc4000003
SECONDARY_AFFINITY = 1
MPIDR_AFFINITY_MASK = 0xff00ffffff
SETUP_BAD_EL = 1
SETUP_CPU_ON_FAILED = 2
FOCUS = 'atomic_memory_smp'
PAIR_FOCUS = 'atomic_pair_memory_smp'
DEPENDENCIES = ('dev/simd_atomic_original.py', 'dev/simd_original.py',
                'dev/differential.py', 'dev/simd_fixtures/atomic_memory.py',
                'dev/a64_checklist.py')


def default_pairs(trials=256):
    """The seven reviewed ordering pairs plus the exact unaligned X64 witness."""
    if type(trials) is not int or not 1 <= trials <= MAX_TRIALS:
        raise ValueError('Original SMP default trial count exceeds fixed bounds')
    cases = atomic_memory.concurrency_cases()
    selected = [case for case in cases if case['kind'] == 4]
    witness = [case for case in cases if case['id'] == 'cross8_ldar_swap_8_offset1']
    if len(selected) != 7 or len(witness) != 1:
        raise AssertionError('Original SMP default reviewed pair inventory changed')
    return [{**case, 'trials': trials,
             'initial': [bytes(atomic_memory.relocate_state(initial, original.MEMORY_RAM_ADDRESS))
                         for initial in case['initial']]}
            for case in [*selected, *witness]]


def pair_default_pairs(trials=256):
    """Reviewed CASP pair histories; full outcome validation belongs to the runner."""
    from simd_fixtures import atomic_pair_memory
    if type(trials) is not int or not 1 <= trials <= MAX_TRIALS:
        raise ValueError('Original CASP SMP trial count exceeds fixed bounds')
    cases = atomic_pair_memory.original_concurrency_cases()
    if len(cases) != MAX_PAIRS:
        raise AssertionError('Original CASP SMP reviewed pair inventory changed')
    return [{**case, 'trials': trials,
             'initial': [bytes(atomic_memory.relocate_state(initial, original.MEMORY_RAM_ADDRESS))
                         for initial in case['initial']]}
            for case in cases]


def _state_bytes(value):
    result = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if len(result) != original.STATE_BYTES:
        raise ValueError('SMP observer requires complete 784-byte initial States')
    return result


def input_files(pairs, focus=FOCUS):
    """Seal exact absolute-address inputs; no guest pointer rewriting occurs."""
    if focus not in (FOCUS, PAIR_FOCUS):
        raise ValueError('Original SMP focus is not a reviewed atomic family')
    pair_family = None
    if focus == PAIR_FOCUS:
        from simd_fixtures import atomic_pair_memory as pair_family
    if not 1 <= len(pairs) <= MAX_PAIRS:
        raise ValueError('Original SMP observer requires one to eight program pairs')
    plan, programs, inputs, memory = [], [], bytearray(), bytearray()
    identifiers = set()
    for pair_index, pair in enumerate(pairs):
        identifier = pair['id']
        if (not isinstance(identifier, str) or not identifier or identifier in identifiers
                or pair.get('threads', PE_COUNT) != PE_COUNT or pair.get('alias', False)):
            raise ValueError('Original SMP pair identity/thread/alias policy differs')
        identifiers.add(identifier)
        trials = pair.get('trials', pair.get('iterations'))
        if type(trials) is not int or not 1 <= trials <= MAX_TRIALS:
            raise ValueError('Original SMP trials exceed the bounded pair limit')
        pair_programs = pair['programs']
        states = [_state_bytes(value) for value in pair['initial']]
        ram = bytes(pair['memory'])
        if len(states) != PE_COUNT or len(pair_programs) != PE_COUNT or len(ram) != original.MEMORY_RAM_BYTES:
            raise ValueError('Original SMP pair needs two programs/States and 8192 RAM bytes')
        if focus == PAIR_FOCUS and (any(len(program) != 1 for program in pair_programs)
                or not any(op['kind'] == pair_family.FOCUS for program in pair_programs for op in program)):
            raise ValueError('Original CASP SMP requires single-operation pair histories containing CASP')
        for pe, program in enumerate(pair_programs):
            if not 1 <= len(program) <= MAX_PROGRAM_WORDS:
                raise ValueError('Original SMP program length exceeds fixed bounds')
            for op in program:
                kinds = (atomic_memory.FOCUS, 'atomic_litmus_transfer')
                if focus == PAIR_FOCUS:
                    kinds += (pair_family.FOCUS,)
                if op['kind'] not in kinds:
                    raise ValueError('Original SMP accepts only reviewed atomic/ordered litmus words')
                if type(op['word']) is not int or not 0 <= op['word'] < 1 << 32:
                    raise ValueError('Original SMP subject word is not u32')
                if op.get('written_vectors', []) or any(type(reg) is not int or not 0 <= reg < 31
                                                        for reg in op.get('written_gprs', [])):
                    raise ValueError('Original SMP destination declarations differ')
                if op['kind'] == 'atomic_litmus_transfer':
                    if op != atomic_memory.ordinary_transfer(op['loading'], op['rt'], op['rn']):
                        raise ValueError('Original SMP ordinary-transfer word/metadata differs')
                if op.get('operation') != 'dmb':
                    state = State.from_buffer_copy(states[pe])
                    address = state.sp if op['rn'] == 31 else state.x[op['rn']]
                    is_pair = pair_family is not None and op['kind'] == pair_family.FOCUS
                    width = op['total_bytes'] if is_pair else op['element_bytes']
                    if not original.MEMORY_RAM_ADDRESS <= address <= original.MEMORY_RAM_ADDRESS + len(ram) - width:
                        raise ValueError('Original SMP inputs must contain absolute owned-RAM bases')
                    if address % atomic_memory.SCA_BYTES + width > atomic_memory.SCA_BYTES:
                        raise ValueError('Original SMP success input crosses the declared SCA granule')
                    if is_pair and op['rn'] == 31 and address % atomic_memory.SCA_BYTES:
                        raise ValueError('Original CASP SMP success input requires aligned SP')
            programs.append({'operations': program})
        for _ in range(trials):
            for pe, state in enumerate(states):
                inputs += struct.pack('<Q', pair_index * PE_COUNT + pe) + state + bytes(8)
        memory += ram
        plan.append({'id': identifier, 'trials': trials, 'programs': pair_programs,
                     'initial_state_hex': [state.hex() for state in states],
                     'initial_ram_sha256': original.sha(ram),
                     'allowed_outcomes': pair.get('allowed_outcomes')})
    total = sum(pair['trials'] for pair in plan)
    if (original.MEMORY_TEMPLATE_ADDRESS + len(memory) > original.MARKER_ADDRESS
            or original.INPUT_ADDRESS + len(inputs) > original.OUTPUT_ADDRESS - original.HEADER_BYTES
            or original.OUTPUT_ADDRESS + total * PAIR_RECORD_BYTES > original.QEMU_RAM_END
            or not original.MARKER_ADDRESS + 8 <= CONTROL_ADDRESS
            or CONTROL_ADDRESS + CONTROL_BYTES > min(SETUP_STACKS)
            or max(SETUP_STACKS) >= original.TEXT_ADDRESS):
        raise ValueError('Original SMP input/template/control/output ranges overlap or exceed RAM')
    source = b''.join(b''.join(struct.pack('<I', op['word']) for op in function['operations'])
                      + struct.pack('<I', original.RET_WORD) for function in programs)
    validator = pair_family if focus == PAIR_FOCUS else atomic_memory
    inspection = validator.validate_source_words(source, programs, ('ldr', 'str'))
    files = {'pair-plan.json': original.json_bytes(plan), 'inputs.bin': bytes(inputs),
             'memory.bin': bytes(memory), 'canonical-source.arm64': source}
    envelope = {'pairs': len(plan), 'trials': total, 'input_stride': PAIR_INPUT_BYTES,
                'record_stride': PAIR_RECORD_BYTES, 'header_bytes': original.HEADER_BYTES,
                'pe_header_bytes': PE_HEADER_BYTES, 'ram_address': original.MEMORY_RAM_ADDRESS,
                'ram_bytes': original.MEMORY_RAM_BYTES, 'source_inspection': inspection,
                'files': {name: {'sha256': original.sha(data), 'bytes': len(data)}
                          for name, data in files.items()}}
    files['input-plan.json'] = original.json_bytes(envelope)
    return files, plan, programs


def _address(register, name):
    return original.mov(register, CONTROL[name])


def _read_control(register, name, scratch='x9'):
    return _address(scratch, name) + [f'ldar {register},[{scratch}]']


def _write_control(register, name, scratch='x9'):
    return _address(scratch, name) + [f'stlr {register},[{scratch}]']


def _header(pe):
    address = original.OUTPUT_ADDRESS - original.HEADER_BYTES + pe * PE_HEADER_BYTES
    lines = original.mov('x1', address)
    for index, register in enumerate(original.CPU_REGISTERS):
        lines += [f'mrs x0,{register}', f'str x0,[x1,#{index * 8}]']
    for index, register in enumerate(original.MEMORY_CONTROLS):
        lines += [f'mrs x0,{register}',
                  f'str x0,[x1,#{original.MEMORY_CONTROL_HEADER_OFFSET + index * 8}]']
    lines += ['mrs x0,ID_AA64MMFR2_EL1', f'str x0,[x1,#{original.ATOMIC_FEATURE_HEADER_OFFSET}]',
              'mrs x0,MPIDR_EL1', f'str x0,[x1,#{MPIDR_OFFSET}]',
              'mrs x0,VBAR_EL1', f'str x0,[x1,#{VBAR_OFFSET}]',
              'mrs x0,CPACR_EL1', f'str x0,[x1,#{CPACR_OFFSET}]',
              'mov x0,sp', f'str x0,[x1,#{SETUP_SP_OFFSET}]']
    return lines


def _restore(pe):
    lines = [f'restore_pe{pe}:'] + _read_control('x19', 'input') + _read_control('x20', 'output')
    if pe:
        lines += [f'add x19,x19,#{original.INPUT_STRIDE}', f'add x20,x20,#{original.RECORD_BYTES}']
    lines += ['mov sp,x20', 'ldr w0,[x19,#784]', 'msr fpcr,x0', 'mrs x0,fpcr', 'str x0,[sp,#832]',
              'ldr w0,[x19,#788]', 'msr fpsr,x0', 'mrs x0,fpsr', 'str x0,[sp,#840]',
              'ldr x0,[x19,#256]', 'msr sp_el0,x0', 'ldr w0,[x19,#264]',
              f'and x0,x0,#{original.NZCV_MASK:#x}', f'orr x0,x0,#{original.PSTATE_EL0T_MASKED:#x}',
              'msr spsr_el1,x0', 'adrp x0,functions', 'add x0,x0,:lo12:functions',
              'ldr x1,[x19]', 'ldr x0,[x0,x1,lsl#3]', 'msr elr_el1,x0']
    lines += [f'ldr q{register},[x19,#{272 + register * 16}]' for register in range(32)]
    lines += ['mov x30,x19']
    lines += [f'ldp x{register},x{register + 1},[x30,#{8 + register * 8}]'
              for register in range(0, 30, 2)]
    return lines + ['ldr x30,[x30,#248]', 'eret']


def _snapshot(pe):
    lines = [f'exception_pe{pe}:']
    lines += [f'stp x{register},x{register + 1},[sp,#{register * 8}]'
              for register in range(0, 30, 2)]
    lines += ['str x30,[sp,#240]']
    for register, offset in (('sp_el0', 248), ('spsr_el1', 256), ('fpcr', 264), ('fpsr', 272),
                             ('esr_el1', 280), ('elr_el1', 288), ('CurrentEL', 296), ('cpacr_el1', 304)):
        lines += [f'mrs x0,{register}', f'str x0,[sp,#{offset}]']
    lines += [f'str q{register},[sp,#{320 + register * 16}]' for register in range(32)]
    lines += original.mov('x0', original.COMPLETED_MARKER) + ['str x0,[sp,#312]']
    lines += _read_control('x1', 'generation') + _write_control('x1', f'done{pe}')
    return lines + [f'b {"finish_trial" if pe == 0 else "secondary_wait"}']


def assembly(plan):
    """Each ERET-to-SVC subject contains only its exact reviewed source words."""
    if not 1 <= len(plan) <= MAX_PAIRS:
        raise ValueError('Original SMP assembly pair count differs')
    lines = ['.arch armv8.7-a+fp16+sve', '.text', '.global _start', '_start:',
             'mrs x0,CurrentEL', 'cmp x0,#4', 'b.ne primary_bad_el',
             'adrp x0,vectors', 'add x0,x0,:lo12:vectors', 'msr vbar_el1,x0', 'isb']
    lines += original.mov('x0', original.FP_ACCESS_ENABLED) + ['msr cpacr_el1,x0', 'isb']
    lines += original.memory_setup()
    lines += original.mov('x0', SETUP_STACKS[0]) + ['mov sp,x0']
    lines += original.mov('x0', CONTROL_ADDRESS) + original.mov('x1', CONTROL_BYTES // 8)
    lines += ['clear_controls:', 'str xzr,[x0],#8', 'subs x1,x1,#1', 'b.ne clear_controls']
    lines += _header(0)
    for name, value in (('input', original.INPUT_ADDRESS), ('output', original.OUTPUT_ADDRESS)):
        lines += original.mov('x0', value) + _write_control('x0', name)
    lines += original.mov('x0', PSCI_CPU_ON_64) + original.mov('x1', SECONDARY_AFFINITY)
    lines += ['adrp x2,secondary_entry', 'add x2,x2,:lo12:secondary_entry', 'mov x3,xzr', 'hvc #0']
    lines += original.mov('x2', original.OUTPUT_ADDRESS - original.HEADER_BYTES + PSCI_RESULT_OFFSET)
    lines += ['str x0,[x2]', 'cbnz x0,primary_cpu_on_failed', 'wait_secondary_ready:']
    lines += _read_control('x0', 'ready') + ['cbz x0,wait_secondary_ready']
    lines += _read_control('x0', 'error') + ['cbnz x0,setup_failed', 'b pair_0']

    # Unroll at most eight pair selectors; each RAM reset reuses copy_memory.
    for pair_index, pair in enumerate(plan):
        remaining = original.SCRATCH_ADDRESS + pair_index * 8
        lines += [f'pair_{pair_index}:'] + original.mov('x0', remaining)
        lines += original.mov('x1', pair['trials']) + ['str x1,[x0]', f'trial_pair_{pair_index}:']
        lines += original.copy_memory(original.MEMORY_TEMPLATE_ADDRESS + pair_index * original.MEMORY_RAM_BYTES,
                                      original.MEMORY_RAM_ADDRESS, original.MEMORY_RAM_BYTES,
                                      f'restore_ram_pair_{pair_index}')
        lines += original.mov('x0', pair_index) + _write_control('x0', 'pair')
        lines += _read_control('x1', 'generation') + ['add x1,x1,#1'] + _write_control('x1', 'generation')
        lines += [f'wait_armed_pair_{pair_index}:'] + _read_control('x0', 'armed')
        lines += ['cmp x0,x1', f'b.ne wait_armed_pair_{pair_index}']
        lines += _write_control('x1', 'go') + ['b restore_pe0']
        # The shared handler resumes the current pair through a table.
        lines += [f'advance_pair_{pair_index}:'] + original.mov('x0', remaining)
        lines += ['ldr x1,[x0]', 'subs x1,x1,#1', 'str x1,[x0]', f'b.ne trial_pair_{pair_index}',
                  f'b {"finished" if pair_index + 1 == len(plan) else "pair_" + str(pair_index + 1)}']

    lines += ['finish_trial:'] + _read_control('x1', 'generation')
    lines += ['wait_trial_done:'] + _read_control('x0', 'done1') + ['cmp x0,x1', 'b.ne wait_trial_done']
    lines += ['dmb ish'] + original.mov('x0', original.MEMORY_RAM_ADDRESS)
    lines += [f'add x1,sp,#{PE_COUNT * original.RECORD_BYTES}'] + original.mov('x2', original.MEMORY_RAM_BYTES // 16)
    lines += ['snapshot_ram:', 'ldp x3,x4,[x0],#16', 'stp x3,x4,[x1],#16', 'subs x2,x2,#1', 'b.ne snapshot_ram']
    lines += _read_control('x1', 'input') + [f'add x1,x1,#{PAIR_INPUT_BYTES}'] + _write_control('x1', 'input')
    lines += _read_control('x1', 'output') + original.mov('x2', PAIR_RECORD_BYTES)
    lines += ['add x1,x1,x2'] + _write_control('x1', 'output')
    lines += _read_control('x1', 'pair')
    lines += ['adrp x0,advances', 'add x0,x0,:lo12:advances', 'ldr x0,[x0,x1,lsl#3]', 'br x0']

    lines += ['secondary_entry:', 'mrs x0,CurrentEL', 'cmp x0,#4', 'b.ne secondary_bad_el',
              'adrp x0,vectors_pe1', 'add x0,x0,:lo12:vectors_pe1', 'msr vbar_el1,x0', 'isb']
    lines += original.mov('x0', original.FP_ACCESS_ENABLED) + ['msr cpacr_el1,x0', 'isb']
    lines += original.mov('x0', SETUP_STACKS[1]) + ['mov sp,x0']
    for register in ('MAIR_EL1', 'TTBR0_EL1', 'TCR_EL1'):
        lines += original.mov('x0', original.MEMORY_CONTROLS[register]) + [f'msr {register},x0']
    lines += ['dsb sy', 'isb', 'tlbi vmalle1', 'dsb sy', 'isb']
    lines += original.mov('x0', original.MEMORY_CONTROLS['SCTLR_EL1']) + ['msr SCTLR_EL1,x0', 'isb']
    lines += _header(1) + ['mov x0,#1'] + _write_control('x0', 'ready')
    lines += ['secondary_wait:'] + _read_control('x1', 'generation') + _read_control('x0', 'done1')
    lines += ['cmp x0,x1', 'b.eq secondary_wait'] + _write_control('x1', 'armed')
    lines += ['secondary_wait_go:'] + _read_control('x0', 'go')
    lines += ['cmp x0,x1', 'b.ne secondary_wait_go', 'b restore_pe1']

    lines += _restore(0) + _restore(1)
    for pair_index, pair in enumerate(plan):
        for pe, program in enumerate(pair['programs']):
            index = pair_index * PE_COUNT + pe
            lines += [f'program_{index}:']
            for word_index, op in enumerate(program):
                if word_index == len(program) - 1:
                    lines += [f'subject_{index}:']
                lines += [f'.inst 0x{op["word"]:08x}']
            lines += [f'svc #{original.SVC_IMMEDIATE}']
    for pe in range(PE_COUNT):
        lines += ['.balign 2048', 'vectors:' if pe == 0 else 'vectors_pe1:']
        for _ in range(16):
            lines += [f'b exception_pe{pe}', '.space 124']
    lines += _snapshot(0) + _snapshot(1)
    lines += ['primary_bad_el:'] + original.mov('x0', SETUP_BAD_EL) + _write_control('x0', 'error') + ['b setup_failed']
    lines += ['primary_cpu_on_failed:'] + original.mov('x0', SETUP_CPU_ON_FAILED) + _write_control('x0', 'error') + ['b setup_failed']
    lines += ['secondary_bad_el:'] + original.mov('x0', SETUP_BAD_EL) + _write_control('x0', 'error')
    lines += ['mov x0,#1'] + _write_control('x0', 'ready') + ['secondary_failed: b secondary_failed']
    lines += ['setup_failed:'] + _read_control('x0', 'error')
    lines += original.mov('x1', original.OUTPUT_ADDRESS - original.HEADER_BYTES + SETUP_ERROR_OFFSET) + ['str x0,[x1]', 'b publish_marker']
    lines += ['finished:'] + _read_control('x0', 'generation')
    lines += original.mov('x1', original.OUTPUT_ADDRESS - original.HEADER_BYTES + FINAL_GENERATION_OFFSET) + ['str x0,[x1]']
    lines += ['publish_marker:', 'dsb sy'] + original.mov('x0', original.MARKER_ADDRESS) + original.mov('x1', original.COMPLETED_MARKER)
    lines += ['str x1,[x0]', 'completed: b completed', '.section .rodata', '.balign 8', 'functions:']
    lines += [f'.quad program_{index}' for index in range(len(plan) * PE_COUNT)]
    lines += ['advances:'] + [f'.quad advance_pair_{index}' for index in range(len(plan))]
    return '\n'.join(lines) + '\n'


def linked_subjects(path, plan):
    """Reuse the single-word ELF inspector, then verify the complete sequence."""
    programs = [program for pair in plan for program in pair['programs']]
    tails = [program[-1]['word'] for program in programs]
    functions = [{'source_hex': struct.pack('<II', word, original.RET_WORD).hex()} for word in tails]
    memory = {'ram_address': original.MEMORY_RAM_ADDRESS, 'ram_bytes': original.MEMORY_RAM_BYTES}
    inspected = original.elf_subjects(path, tails, functions, memory)
    data = path.read_bytes()
    result = []
    for index, (program, tail) in enumerate(zip(programs, inspected)):
        prefix_bytes = (len(program) - 1) * 4
        pc, offset = tail['instruction_pc'] - prefix_bytes, tail['elf_offset'] - prefix_bytes
        executed = b''.join(struct.pack('<I', op['word']) for op in program) + struct.pack('<I', original.SVC_WORD)
        canonical = executed[:-4] + struct.pack('<I', original.RET_WORD)
        if data[offset:offset + len(executed)] != executed:
            raise AssertionError('Actual linked SMP sequence differs from sealed original words')
        result.append({'program_index': index, 'pair_index': index // PE_COUNT, 'pe': index % PE_COUNT,
                       'instruction_pc': pc, 'svc_pc': tail['svc_pc'], 'expected_elr': tail['expected_elr'],
                       'elf_offset': offset, 'executed_source_hex': executed.hex(),
                       'executed_source_sha256': original.sha(executed), 'canonical_source_hex': canonical.hex(),
                       'canonical_source_sha256': original.sha(canonical), 'tail_inspection': tail})
    return result


def _check_bindings(source_bindings):
    for name, identity in source_bindings.items():
        if original.sha((ROOT / name).read_bytes()) != identity:
            raise AssertionError('Frozen original SMP source changed: ' + name)


def prepare(directory, pairs, source_bindings, focus=FOCUS):
    """Prepare sealed inputs/assembly/ELF; caller grants tool execution explicitly."""
    directory = Path(directory).resolve()
    directory.relative_to(ROOT)
    _check_bindings(source_bindings)
    files, plan, _ = input_files(pairs, focus)
    source = assembly(plan).encode()
    qemu, clang, lld, bindings = original.tools_and_bindings()
    dependencies = DEPENDENCIES + (('dev/simd_fixtures/atomic_pair_memory.py',) if focus == PAIR_FOCUS else ())
    bindings.update({'focus': focus, 'shared_original_producer_sha256': bindings['producer_sha256'],
                     'producer_sha256': original.sha(Path(__file__).read_bytes()),
                     'source_receipts': source_bindings,
                     'observer_dependencies': {name: original.sha((ROOT / name).read_bytes()) for name in dependencies},
                     'inputs': {name: {'sha256': original.sha(data), 'bytes': len(data)} for name, data in files.items()},
                     'input_stride': PAIR_INPUT_BYTES, 'record_stride': PAIR_RECORD_BYTES,
                     'control_address': CONTROL_ADDRESS, 'control_layout': CONTROL,
                     'limits': 'Two PEs; raw original frames only. Root owns formal allowed outcomes; finite TCG absence/frequencies are not model proof.'})
    destination = directory / original.sha(source + original.json_bytes(bindings))
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        original.write_new(destination / name, data)
    original.write_new(destination / 'guest.S', source)
    original.write_new(destination / 'original_smp.py', Path(__file__).read_bytes())
    original.write_new(destination / 'bindings.json', original.json_bytes(bindings))
    if not (destination / 'guest.elf').exists():
        command = [str(clang), '--target=aarch64-unknown-none-elf', '-c', str(destination / 'guest.S'), '-o', str(destination / 'guest.o')]
        original.write_new(destination / 'assemble-command.json', original.json_bytes(command))
        subprocess.run(command, check=True)
        env = os.environ.copy()
        if lld.name == 'rust-lld' and os.uname().sysname == 'Darwin':
            env['DYLD_LIBRARY_PATH'] = str(lld.resolve().parents[3])
        command = [str(lld), *(['-flavor', 'gnu'] if lld.name == 'rust-lld' else []),
                   '-m', 'aarch64elf', '-Ttext', hex(original.TEXT_ADDRESS), '-e', '_start',
                   str(destination / 'guest.o'), '-o', str(destination / 'guest.elf')]
        original.write_new(destination / 'link-command.json', original.json_bytes(command))
        subprocess.run(command, check=True, env=env)
    subjects = linked_subjects(destination / 'guest.elf', plan)
    original.write_new(destination / 'subjects.json', original.json_bytes(subjects))
    names = ('guest.S', 'guest.o', 'guest.elf', 'subjects.json', 'original_smp.py', 'bindings.json')
    artifact_plan = {name: {'sha256': original.sha((destination / name).read_bytes()),
                            'bytes': (destination / name).stat().st_size} for name in names}
    original.write_new(destination / 'prepared-artifacts.json', original.json_bytes(artifact_plan))
    _check_bindings(source_bindings)
    return destination, qemu, bindings, plan, subjects


def execute(destination, qemu, trials):
    command = [str(qemu), '-machine', 'virt,secure=off,virtualization=off', '-cpu', original.CPU_MODEL,
               '-smp', str(PE_COUNT), '-accel', 'tcg,thread=multi', '-m', original.MEMORY_QEMU_RAM_SIZE,
               '-display', 'none', '-serial', 'none', '-monitor', 'none', '-nic', 'none',
               '-kernel', str(destination / 'guest.elf'),
               '-device', f'loader,file={destination / "inputs.bin"},addr={original.INPUT_ADDRESS:#x},force-raw=on',
               '-device', f'loader,file={destination / "memory.bin"},addr={original.MEMORY_TEMPLATE_ADDRESS:#x},force-raw=on']
    original.execute_transport(destination, command, original.HEADER_BYTES + trials * PAIR_RECORD_BYTES)


def frame_state(frame, initial, program, subject):
    observed = {name: struct.unpack_from('<Q', frame, offset)[0]
                for name, offset in original.LAYOUT.items() if name not in ('x', 'v')}
    fpcr, fpsr = struct.unpack_from('<II', initial, 776)
    if (observed['pre_fpcr'] != fpcr & original.QEMU_FPCR_MASK
            or observed['pre_fpsr'] != fpsr & original.QEMU_FPSR_MASK
            or observed['fpcr'] != observed['pre_fpcr'] or observed['fpsr'] != observed['pre_fpsr']
            or observed['spsr'] != ((struct.unpack_from('<I', initial, 256)[0] & original.NZCV_MASK) | original.PSTATE_EL0T_MASKED)
            or observed['esr'] >> 26 != 0x15 or observed['esr'] & 65535 != original.SVC_IMMEDIATE
            or observed['elr'] != subject['expected_elr'] or observed['current_el'] != 4
            or observed['cpacr'] != original.FP_ACCESS_ENABLED or observed['marker'] != original.COMPLETED_MARKER):
        raise AssertionError('Original SMP frame controls/SVC/source completion differ')
    final = bytearray(initial)
    final[:256] = frame[:256]
    struct.pack_into('<I', final, 256, observed['spsr'] & original.NZCV_MASK)
    final[264:776] = frame[original.LAYOUT['v']:original.LAYOUT['v'] + 512]
    struct.pack_into('<II', final, 776, observed['fpcr'], observed['fpsr'])
    expected = bytearray(initial)
    written = {reg for op in program for reg in op.get('written_gprs', [])}
    for register in written:
        expected[register * 8:register * 8 + 8] = final[register * 8:register * 8 + 8]
    # QEMU masks requested FP fields; retain those actual readbacks explicitly.
    struct.pack_into('<II', expected, 776, observed['pre_fpcr'], observed['pre_fpsr'])
    if final != expected:
        raise AssertionError('Original SMP changed an undeclared register/vector/SP/status field')
    return bytes(final)


def validate_results(destination, plan, subjects):
    results = (destination / 'results.bin').read_bytes()
    trials = sum(pair['trials'] for pair in plan)
    if len(results) != original.HEADER_BYTES + trials * PAIR_RECORD_BYTES:
        raise AssertionError('Original SMP result byte count differs')
    headers = []
    for pe in range(PE_COUNT):
        header = results[pe * PE_HEADER_BYTES:(pe + 1) * PE_HEADER_BYTES]
        memory_controls = original.validate_memory_controls(header)
        features = original.validate_atomic_features(header)
        current_el = struct.unpack_from('<Q', header)[0]
        mpidr = struct.unpack_from('<Q', header, MPIDR_OFFSET)[0]
        vbar, cpacr, setup_sp = struct.unpack_from('<3Q', header, VBAR_OFFSET)
        if (current_el != 4 or mpidr & MPIDR_AFFINITY_MASK != pe
                or vbar % 2048 or not original.TEXT_ADDRESS <= vbar < original.MEMORY_CODE_END
                or cpacr != original.FP_ACCESS_ENABLED or setup_sp != SETUP_STACKS[pe]):
            raise AssertionError('Original SMP PE affinity/EL/VBAR/FP/stack readback differs')
        headers.append({'pe': pe, 'MPIDR_EL1': hex(mpidr), 'VBAR_EL1': hex(vbar),
                        'CPACR_EL1': hex(cpacr), 'setup_SP_EL1': hex(setup_sp),
                        'memory_controls': memory_controls, **features})
    if headers[0]['VBAR_EL1'] == headers[1]['VBAR_EL1']:
        raise AssertionError('Original SMP PEs require separate vector tables')
    psci_result, setup_error, generation = struct.unpack_from('<3Q', results, PSCI_RESULT_OFFSET)
    if psci_result != 0 or setup_error != 0 or generation != trials:
        raise AssertionError('Original SMP CPU_ON/setup/completion generation differs')
    inputs = (destination / 'inputs.bin').read_bytes()
    if len(inputs) != trials * PAIR_INPUT_BYTES:
        raise AssertionError('Original SMP retained input length differs')
    rows, index, histograms = [], 0, {}
    for pair_index, pair in enumerate(plan):
        histogram = Counter()
        for trial in range(pair['trials']):
            record = results[original.HEADER_BYTES + index * PAIR_RECORD_BYTES:
                             original.HEADER_BYTES + (index + 1) * PAIR_RECORD_BYTES]
            final_states = []
            for pe, program in enumerate(pair['programs']):
                input_offset = index * PAIR_INPUT_BYTES + pe * original.INPUT_STRIDE
                selector = struct.unpack_from('<Q', inputs, input_offset)[0]
                initial = inputs[input_offset + 8:input_offset + 8 + original.STATE_BYTES]
                if selector != pair_index * PE_COUNT + pe or initial.hex() != pair['initial_state_hex'][pe]:
                    raise AssertionError('Original SMP retained inputs differ from sealed pair plan')
                frame = record[pe * original.RECORD_BYTES:(pe + 1) * original.RECORD_BYTES]
                final_states.append(frame_state(frame, initial, program, subjects[selector]))
            ram = record[PE_COUNT * original.RECORD_BYTES:]
            observed = []
            for program, final in zip(pair['programs'], final_states):
                written = sorted({reg for op in program for reg in op.get('written_gprs', [])})
                observed.append({str(reg): struct.unpack_from('<Q', final, reg * 8)[0] for reg in written})
            histogram[json.dumps(observed, sort_keys=True)] += 1
            rows.append({'pair': pair['id'], 'trial': trial, 'record_index': index,
                         'initial_state_hex': pair['initial_state_hex'],
                         'final_state_hex': [state.hex() for state in final_states],
                         'final_ram_sha256': original.sha(ram), 'raw_record_sha256': original.sha(record),
                         'written_gprs': observed})
            index += 1
        histograms[pair['id']] = dict(histogram)
    return {'pe_headers': headers, 'psci_cpu_on_result': psci_result, 'completed_generations': generation,
            'records': rows, 'outcome_histograms': histograms}


def capture(prepared, directory):
    destination, qemu, bindings, plan, subjects = prepared
    if destination.parent != Path(directory).resolve() or bindings['focus'] not in (FOCUS, PAIR_FOCUS):
        raise AssertionError('Original SMP preparation/capture configuration differs')
    _check_bindings(bindings['source_receipts'])
    _check_bindings(bindings['observer_dependencies'])
    prepared_artifacts = json.loads((destination / 'prepared-artifacts.json').read_bytes())
    for name, identity in {**bindings['inputs'], **prepared_artifacts}.items():
        data = (destination / name).read_bytes()
        if original.sha(data) != identity['sha256'] or len(data) != identity['bytes']:
            raise AssertionError('Original SMP sealed input changed: ' + name)
    path = destination / 'receipt.json'
    if path.exists():
        receipt = json.loads(path.read_bytes())
        for name, identity in receipt['files'].items():
            if original.sha((destination / name).read_bytes()) != identity['sha256']:
                raise AssertionError('Original SMP retained evidence changed: ' + name)
        _check_bindings(bindings['source_receipts'])
        _check_bindings(bindings['observer_dependencies'])
        return path
    if not (destination / 'results.bin').exists():
        execute(destination, qemu, sum(pair['trials'] for pair in plan))
    try:
        observations = validate_results(destination, plan, subjects)
    except Exception as error:
        original.write_new(destination / 'validation-failure.json', original.json_bytes({
            'error': str(error), 'results_sha256': original.sha((destination / 'results.bin').read_bytes()),
            'limits': 'Raw original bytes retained; no transport/frame or allowed-outcome credit.'}))
        raise
    _check_bindings(bindings['source_receipts'])
    _check_bindings(bindings['observer_dependencies'])
    original.write_new(destination / 'observations.json', original.json_bytes(observations))
    files = {p.name: {'sha256': original.sha(p.read_bytes()), 'bytes': p.stat().st_size}
             for p in sorted(destination.iterdir()) if p.is_file() and p.name != 'receipt.json'}
    receipt = {'kind': ('atomic_pair_original_two_pe_full_frame_qemu' if bindings['focus'] == PAIR_FOCUS
                        else 'atomic_ordered_original_two_pe_full_frame_qemu'),
               'passed_transport_and_architectural_frame_checks': True,
               'directory': str(destination.relative_to(ROOT)),
               'pairs': len(plan), 'trials': sum(pair['trials'] for pair in plan),
               'pes': PE_COUNT, 'input_stride': PAIR_INPUT_BYTES, 'results_stride': PAIR_RECORD_BYTES,
               'results_header_bytes': original.HEADER_BYTES, 'pe_header_bytes': PE_HEADER_BYTES,
               'snapshot_layout': original.LAYOUT, **bindings,
               'pe_headers': observations['pe_headers'], 'outcome_histograms': observations['outcome_histograms'],
               'files': files,
               'limits': ['Root owns authoritative allowed-outcome membership checks; no formal outcome verdict is made by this observer.',
                          'Finite two-PE TCG outcomes/frequencies do not prove the complete Arm memory model or Apple hardware.',
                          'Control LDAR/STLR, RAM reset, State restoration and snapshots occur outside complete tested EL0 source sequences.',
                          'Both full1024-byte original frames and every8192 RAM byte are retained per trial; State.reserved is input metadata.',
                          'The canonical RET is replaced only by the existing genuine SVC observation boundary; exact complete subject bytes are bound.']}
    original.write_new(path, original.json_bytes(receipt))
    return path
