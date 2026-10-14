#!/usr/bin/env python3
"""Original-only full-state EL0 observer for register-only SIMD fixtures."""
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
    return files, functions, cases, inputs, words


def mov(register, value):
    lines = [f'movz {register},#{value & 65535}']
    lines.extend(f'movk {register},#{value >> shift & 65535},lsl#{shift}'
                 for shift in (16, 32, 48) if value >> shift & 65535)
    return lines


def assembly(words, count):
    lines = ['.arch armv8.7-a+fp16+sve', '.text', '.global _start', '_start:',
             'adrp x0,vectors', 'add x0,x0,:lo12:vectors', 'msr vbar_el1,x0', 'isb']
    lines += mov('x0', FP_ACCESS_ENABLED) + ['msr cpacr_el1,x0', 'isb']
    lines += mov('x1', OUTPUT_ADDRESS - HEADER_BYTES)
    for index, register in enumerate(CPU_REGISTERS):
        lines += [f'mrs x0,{register}', f'str x0,[x1,#{index * 8}]']
    lines += mov('x0', SCRATCH_ADDRESS)
    for offset, value in ((0, INPUT_ADDRESS), (8, OUTPUT_ADDRESS), (16, count)):
        lines += mov('x1', value) + [f'str x1,[x0,#{offset}]']
    lines += ['again:'] + mov('x0', SCRATCH_ADDRESS)
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
    lines += mov('x0', SCRATCH_ADDRESS)
    lines += ['ldp x1,x2,[x0]', f'add x1,x1,#{INPUT_STRIDE}',
              f'add x2,x2,#{RECORD_BYTES}', 'stp x1,x2,[x0]',
              'ldr x1,[x0,#16]', 'subs x1,x1,#1', 'str x1,[x0,#16]', 'b.eq finished',
              'adr x0,again', 'msr elr_el1,x0']
    lines += mov('x0', PSTATE_EL1H_MASKED) + ['msr spsr_el1,x0', 'eret', 'finished:']
    lines += mov('x0', MARKER_ADDRESS) + mov('x1', COMPLETED_MARKER)
    lines += ['str x1,[x0]', 'completed: b completed',
              '.section .rodata', '.balign 8', 'functions:']
    lines += [f'.quad subject_{index}' for index in range(len(words))]
    return '\n'.join(lines) + '\n'


def tools_and_bindings():
    qemu = ROOT / '.tools/qemu/bin/qemu-system-aarch64'
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


def elf_subjects(path, words, functions):
    """Read ELF64 symbols/sections directly; inspect the actual linked instruction bytes."""
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    section_offset, section_stride, section_count = header[6], header[11], header[12]
    assert section_stride == 64
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, section_offset + index * section_stride)
                for index in range(section_count)]
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
    source = assembly(words, len(cases)).encode()
    qemu, clang, lld, bindings = tools_and_bindings()
    bindings['focus'] = focus
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
    subjects = elf_subjects(destination / 'guest.elf', words, functions)
    write_new(destination / 'subjects.json', json_bytes(subjects))
    return destination, qemu, bindings, functions, cases, inputs, subjects


def execute(destination, qemu, count):
    with tempfile.TemporaryDirectory(prefix='stela-simd-original-el0-') as temporary:
        endpoint = Path(temporary) / 'qmp'
        command = [str(qemu), '-machine', 'virt,secure=off,virtualization=off', '-cpu', CPU_MODEL,
                   '-accel', 'tcg', '-m', '512M', '-display', 'none', '-serial', 'none',
                   '-monitor', 'none', '-nic', 'none', '-kernel', str(destination / 'guest.elf'),
                   '-device', f'loader,file={destination / "inputs.bin"},addr={INPUT_ADDRESS:#x},force-raw=on',
                   '-qmp', f'unix:{endpoint},server=on,wait=off', '-S']
        write_new(destination / 'qemu-command.json', json_bytes(command))
        with (destination / 'stderr.log').open('xb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=log)
            stream = connection = None
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
                deadline = time.monotonic() + 60
                while True:
                    marker = request('human-monitor-command', {'command-line': f'xp /1gx {MARKER_ADDRESS:#x}'})
                    if marker.strip().endswith(f'{COMPLETED_MARKER:#018x}'):
                        break
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(f'Original oracle timeout/failure: {marker}')
                    time.sleep(0.02)
                request('stop')
                size = HEADER_BYTES + count * RECORD_BYTES
                request('human-monitor-command', {'command-line': f'pmemsave {OUTPUT_ADDRESS - HEADER_BYTES:#x} {size} "{destination / "results.bin"}"'})
                request('quit')
                process.wait(timeout=5)
            finally:
                if stream is not None:
                    stream.close()
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)


def validate_results(destination, functions, cases, inputs, subjects):
    results = (destination / 'results.bin').read_bytes()
    assert len(results) == HEADER_BYTES + len(cases) * RECORD_BYTES
    controls, trap_observations, status_deltas = {}, [], {}
    for index in range(len(cases)):
        input_offset = index * INPUT_STRIDE
        function_index = struct.unpack_from('<Q', inputs, input_offset)[0]
        initial = inputs[input_offset + 8:input_offset + 8 + STATE_BYTES]
        record = results[HEADER_BYTES + index * RECORD_BYTES:HEADER_BYTES + (index + 1) * RECORD_BYTES]
        requested_fpcr, requested_fpsr = struct.unpack_from('<II', initial, 776)
        pre_fpcr, pre_fpsr = struct.unpack_from('<QQ', record, LAYOUT['pre_fpcr'])
        observed = {name: struct.unpack_from('<Q', record, offset)[0]
                    for name, offset in LAYOUT.items() if name not in ('x', 'v')}
        assert pre_fpcr == requested_fpcr & QEMU_FPCR_MASK, (index, 'pre_fpcr')
        assert pre_fpsr == requested_fpsr & QEMU_FPSR_MASK, (index, 'pre_fpsr')
        op = operation(functions[function_index])
        assert record[:248] == initial[:248], (index, 'all_gprs_unchanged')
        assert observed['sp'] == struct.unpack_from('<Q', initial, 248)[0], (index, 'sp')
        initial_nzcv = struct.unpack_from('<I', initial, 256)[0]
        assert observed['spsr'] == (initial_nzcv & NZCV_MASK) | PSTATE_EL0T_MASKED, (index, 'spsr_unchanged')
        assert observed['fpcr'] == pre_fpcr, (index, 'fpcr_unchanged')
        assert observed['fpsr'] & pre_fpsr == pre_fpsr, (index, 'sticky_fpsr')
        assert observed['fpsr'] & FPSR_QC == pre_fpsr & FPSR_QC, (index, 'qc_unchanged')
        assert observed['fpsr'] & ~QEMU_FPSR_MASK == 0, (index, 'reserved_fpsr')
        assert observed['esr'] >> 26 == 0x15 and observed['esr'] & 65535 == SVC_IMMEDIATE, (index, 'genuine_svc')
        assert observed['elr'] == subjects[function_index]['expected_elr'], (index, 'elr')
        assert observed['current_el'] == 4 and observed['cpacr'] == FP_ACCESS_ENABLED, (index, 'access')
        assert observed['marker'] == COMPLETED_MARKER, (index, 'marker')
        op = operation(functions[function_index])
        word = integer(op['word'])
        destination_register = op['d']
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
    return {'cpu_registers': dict(zip(CPU_REGISTERS, map(hex, struct.unpack_from('<9Q', results)))),
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
            execute(destination, qemu, len(cases))
        observations = validate_results(destination, functions, cases, inputs, subjects)
        files = {path.name: {'sha256': sha(path.read_bytes()), 'bytes': path.stat().st_size}
                 for path in sorted(destination.iterdir()) if path.is_file() and path.name != 'receipt.json'}
        receipt = {'kind': focus + '_original_el0_full_frame_qemu',
                   'passed_transport_and_architectural_frame_checks': True,
                   'cases': len(cases), 'functions': len(functions), 'cpu': CPU_MODEL,
                   'directory': str(destination.relative_to(ROOT)), **bindings, **observations,
                   'input_stride': INPUT_STRIDE, 'state_bytes': STATE_BYTES,
                   'results_header_bytes': HEADER_BYTES, 'results_stride': RECORD_BYTES,
                   'snapshot_layout': LAYOUT, 'files': files,
                   'checks': ['Each exact original SIMD instruction runs at EL0t with all 31 GPRs, SP_EL0, 32 full vectors, NZCV, FPCR and FPSR restored from the retained input.',
                              'A genuine SVC follows the subject; the EL1 handler snapshots all GPRs before transport clobbers and all vectors before transport resumes.',
                              'All GPRs/SP, NZCV and non-destination vectors are unchanged. Scalars merge the declared original destination/left source under NEP or clear inactive bits; vector64 upper clears. QC and sticky flags preserve.',
                              'Actual preinstruction FPCR/FPSR readbacks, genuine SVC ESR, exact linked subject/SVC bytes and ELR identify every execution.'],
                   'limits': ['Original QEMU emulator observations only; no native execution, mathematical result-model validation, Apple hardware proof, or performance credit.',
                              'Canonical function identity is original SIMD word plus RET through the unused per-function return register. This EL0 fixture executes the unchanged SIMD word followed by SVC; the original RET is not executed.',
                              'QEMU trap enables are RAZ/WI. Exact requested and actual controls are retained; no FP trap-delivery credit is claimed.',
                              'State.reserved is retained input metadata, not an architectural register; general guest RAM effects are not applicable to these register-only subjects.',
                              'EL2/EL3/security, streaming modes and access-disabled execution are outside this fixture.']}
        write_new(receipt_path, json_bytes(receipt))
    pointer = {'kind': focus + '_original_oracle_capture_pointer',
               'directory': str(destination.relative_to(ROOT)),
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
    return receipt_path


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
    prepared = prepare(arguments.directory, arguments.focus, source_bindings)
    if arguments.capture:
        path = capture(prepared, arguments.directory, arguments.focus)
        print(json.dumps({'receipt': str(path), 'sha256': sha(path.read_bytes())}))
    else:
        destination = prepared[0]
        print(json.dumps({'prepared': str(destination), 'functions': len(prepared[3]),
                          'cases': len(prepared[4]), 'guest_elf_sha256': sha((destination / 'guest.elf').read_bytes())}))
