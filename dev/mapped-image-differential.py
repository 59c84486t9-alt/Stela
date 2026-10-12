#!/usr/bin/env python3
"""Linked own Mach-O data/BSS entry versus original ARM and native dispatch.

Uses an unchanged Apple-linker executable with LC_MAIN, dyld and libSystem
requirements retained. Its chained-fixup payload has no imports or chains. This
is an explicitly supplied entry ABI, not macOS process launch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm

from differential import ROOT, ARM_REGISTERS, MASK, State, states
from evidence import write_evidence

STOP = 0xffff0000
SEED = 0x9e3779b97f4a7c15
PAGE = 16384
STACK_BASE = 0x70000000000
STACK_BYTES = 65536
STACK_TOP = STACK_BASE + STACK_BYTES
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 2
LC_UNIXTHREAD = 5
LC_MAIN = 0x80000028
FIXTURE = ROOT / 'tests/fixtures/mapped-image-arm64.S'


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(state):
    return {'x': list(state.x), 'sp': state.sp, 'nzcv': state.nzcv, 'reserved': state.reserved}


def commands(data):
    require(len(data) >= 32 and data[:4] == bytes.fromhex('cffaedfe'), 'expected thin 64-bit little-endian Mach-O')
    _, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    require(cpu == 0x100000c and subtype == 0 and kind == 2 and not reserved, 'unexpected linked fixture architecture/type')
    end = 32 + size
    require(end <= len(data), 'truncated load commands')
    offset, result = 32, []
    for _ in range(count):
        require(offset + 8 <= end, 'missing load-command header')
        command, length = struct.unpack_from('<II', data, offset)
        require(length >= 8 and length % 8 == 0 and offset + length <= end, 'bad load-command length')
        result.append((offset, command, bytes(data[offset:offset + length])))
        offset += length
    require(offset == end, 'load-command size mismatch')
    return result


def layout(data):
    segments, symbols, sections, entry = [], {}, {}, None
    table = None
    for offset, command, body in commands(data):
        if command == LC_SEGMENT_64:
            require(len(body) >= 72, 'truncated segment')
            _, _, name, address, size, fileoff, filesize, maximum, protection, count, flags = struct.unpack_from('<II16sQQQQIIII', body)
            name = name.rstrip(b'\0').decode('ascii')
            require(len(body) == 72 + 80 * count, 'segment section size mismatch')
            require(fileoff + filesize <= len(data) and filesize <= size, 'invalid segment file range')
            require(address % PAGE == 0 and size % PAGE == 0, 'fixture must use Apple 16-KiB segment pages')
            segment = {'name': name, 'address': address, 'bytes': size, 'file_offset': fileoff,
                       'file_bytes': filesize, 'protection': protection, 'maximum_protection': maximum}
            segments.append(segment)
            for index in range(count):
                section = struct.unpack_from('<16s16sQQIIIIIIII', body, 72 + index * 80)
                section_name = section[0].rstrip(b'\0').decode('ascii')
                require(section[6] == 0 and section[7] == 0, 'fixture has unresolved section relocations')
                sections[section_name] = {'address': section[2], 'bytes': section[3], 'file_offset': section[4], 'flags': section[8]}
        elif command == LC_SYMTAB:
            require(len(body) == 24, 'bad symbol table command')
            table = struct.unpack_from('<6I', body)[2:]
        elif command == LC_MAIN:
            require(entry is None and len(body) == 24, 'duplicate/invalid LC_MAIN')
            entry = struct.unpack_from('<IIQQ', body)[2]
        elif command == 0x80000034:
            require(len(body) == 16, 'invalid chained-fixup command')
            fileoff, length = struct.unpack_from('<II', body, 8)
            require(fileoff + length <= len(data) and length >= 28, 'truncated chained-fixup header')
            payload = data[fileoff:fileoff + length]
            version, starts, imports, strings, count, import_format, symbol_format = struct.unpack_from('<7I', payload)
            require(version == 0 and count == 0 and import_format == 1 and symbol_format == 0, 'fixture must have no chained imports')
            require(starts + 4 <= length, 'missing fixup segment table')
            segment_count = struct.unpack_from('<I', payload, starts)[0]
            require(starts + 4 + 4 * segment_count <= length, 'truncated fixup segment table')
            require(not any(struct.unpack_from(f'<{segment_count}I', payload, starts + 4)), 'fixture contains actual pointer-fixup chains')
        elif command == 0xb:
            require(len(body) == 80 and struct.unpack_from('<I', body, 28)[0] == 0, 'fixture has undefined symbols')
        else:
            require(command in (0x2a, LC_UNIXTHREAD, 0x80000033, 0xe, 0x32, 0xc, 0x26, 0x29), f'unexpected linked fixture command {command:#x}')
    require(table is not None, 'fixture symbols are required')
    symoff, count, stroff, strsize = table
    require(symoff + count * 16 <= len(data) and stroff + strsize <= len(data), 'symbol/string table out of bounds')
    strings = data[stroff:stroff + strsize]
    for index in range(count):
        string, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', data, symoff + 16 * index)
        require(string < len(strings) and b'\0' in strings[string:], 'invalid symbol name')
        name = strings[string:].split(b'\0', 1)[0].decode('ascii')
        require(kind & 0xe != 0, 'fixture has an undefined import')
        symbols[name] = value
    require({'_mapped_entry', '_mapped_seed', '_mapped_output'} <= symbols.keys(), 'missing fixture symbols')
    return {'segments': segments, 'sections': sections, 'symbols': symbols, 'entry_offset': entry}


def build_fixture(work):
    require(platform.system() == 'Darwin', 'fixture construction currently requires Apple clang/ld on macOS')
    clang = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    linker = subprocess.check_output(['xcrun', '--find', 'ld'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    object_path, image = work / 'fixture.o', work / 'mapped-image-arm64'
    commands_used = [
        [clang, '-target', 'arm64-apple-macos14', '-c', str(FIXTURE), '-o', str(object_path)],
        [linker, '-arch', 'arm64', '-platform_version', 'macos', '14.0', '14.0',
         '-e', '_mapped_entry', '-o', str(image), str(object_path), '-syslibroot', sdk,
         '-lSystem', '-segaddr', '__TEXT', '0x40000000000',
         '-segaddr', '__DATA', '0x40000004000', '-no_uuid', '-no_adhoc_codesign'],
    ]
    tool_outputs = []
    for command in commands_used:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        tool_outputs.append({'stdout': completed.stdout, 'stderr': completed.stderr})
    data = image.read_bytes()
    info = layout(data)
    mapped_segments = sorted((segment for segment in info['segments'] if segment['protection']), key=lambda segment: segment['address'])
    require(all(left['address'] + left['bytes'] <= right['address'] for left, right in zip(mapped_segments, mapped_segments[1:])), 'linked segment addresses overlap')
    require(next(segment for segment in mapped_segments if segment['name'] == '__TEXT')['address'] == 0x40000000000, 'linker ignored fixture text address')
    require(next(segment for segment in mapped_segments if segment['name'] == '__DATA')['address'] == 0x40000004000, 'linker ignored fixture data address')
    text = info['sections']['__text']
    code = data[text['file_offset']:text['file_offset'] + text['bytes']]
    instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, text['address']))
    require(len(code) == 68 and len(instructions) == 17, 'fixture text changed; review before native execution')
    require([item.mnemonic for item in instructions] == [
        'stp', 'mov', 'adr', 'adrp', 'add', 'ldr', 'add', 'bl', 'ldp', 'ret',
        'adrp', 'add', 'ldr', 'str', 'add', 'str', 'ret'], 'fixture contains unexpected instruction/control flow')
    require(info['symbols']['_mapped_entry'] == text['address'], 'entry differs from fixture text start')
    return image, info, {'commands': commands_used, 'tool_outputs': tool_outputs, 'source_sha256': digest(FIXTURE.read_bytes()),
                         'object_sha256': digest(object_path.read_bytes()), 'fixture_sha256': digest(data),
                         'linked_executable_unchanged': True, 'actual_fixup_chains': 0, 'undefined_imports': 0,
                         'text_sha256': digest(code), 'disassembly': [f'{item.address:#x}: {item.mnemonic} {item.op_str}' for item in instructions]}


def original(data, info, initial):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for segment in info['segments']:
        if not segment['protection']:
            continue
        machine.mem_map(segment['address'], segment['bytes'])
        start = segment['file_offset']
        machine.mem_write(segment['address'], data[start:start + segment['file_bytes']])
        machine.mem_protect(segment['address'], segment['bytes'], segment['protection'])
    require(initial.sp == STACK_TOP, 'reference requires the owned research stack top')
    machine.mem_map(STACK_BASE, STACK_BYTES, 3)
    for register, value in zip(ARM_REGISTERS, initial.x):
        machine.reg_write(register, value)
    machine.reg_write(arm.UC_ARM64_REG_SP, initial.sp)
    machine.reg_write(arm.UC_ARM64_REG_NZCV, initial.nzcv)
    section = info['sections']['__text']
    trace = []
    def guard(machine, address, size, _):
        require(size == 4 and section['address'] <= address < section['address'] + section['bytes'], 'original execution left reviewed fixture text')
        trace.append(address)
    machine.hook_add(UC_HOOK_CODE, guard)
    entry = info['symbols']['_mapped_entry']
    machine.emu_start(entry, STOP, count=128)
    pc = machine.reg_read(arm.UC_ARM64_REG_PC)
    require(pc == STOP and len(trace) == 17, 'original fixture failed to execute real call/returns to stop address')
    state = {'x': [machine.reg_read(register) for register in ARM_REGISTERS],
             'sp': machine.reg_read(arm.UC_ARM64_REG_SP),
             'nzcv': machine.reg_read(arm.UC_ARM64_REG_NZCV) & 0xf0000000,
             'reserved': initial.reserved}
    data_segment = next(segment for segment in info['segments'] if segment['name'] == '__DATA')
    memory = bytes(machine.mem_read(data_segment['address'], data_segment['bytes']))
    frame = bytes(machine.mem_read(STACK_TOP - 16, 16))
    return state, pc, memory, frame, trace


def fixture_oracle(data, info, initial):
    expected = snapshot(initial)
    symbols, section = info['symbols'], info['sections']['__text']
    result = (initial.x[0] + SEED) & MASK
    for register, value in {0: (result + 7) & MASK, 1: SEED, 4: 0,
                            8: section['address'] + 12, 9: symbols['_mapped_seed'],
                            10: symbols['_mapped_output'], 30: STOP}.items():
        expected['x'][register] = value
    segment = next(segment for segment in info['segments'] if segment['name'] == '__DATA')
    memory = bytearray(segment['bytes'])
    start = segment['file_offset']
    memory[:segment['file_bytes']] = data[start:start + segment['file_bytes']]
    output = symbols['_mapped_output'] - segment['address']
    require(output >= segment['file_bytes'] and output + 16 <= segment['bytes'], 'observed BSS output must lie in actual segment zero-fill tail')
    require(not any(memory[8:]), 'initial BSS/padding was not zero')
    struct.pack_into('<QQ', memory, output, result, (result + 7) & MASK)
    return expected, STOP, bytes(memory), struct.pack('<QQ', initial.x[29], STOP)


def invoke(cli, *arguments):
    result = subprocess.run([str(cli), *map(str, arguments)], capture_output=True, text=True)
    require(result.returncode == 0, f'CLI failed ({result.returncode}): {result.stderr.strip()}')
    return json.loads(result.stdout)


def validate_regions(report, info):
    require(report['host_execute'] is False, 'mapped guest pages unexpectedly permit host execution')
    regions = {region['guest_address']: region for region in report['memory_regions']}
    for segment in info['segments']:
        if not segment['protection']:
            require(segment['address'] not in regions, 'PAGEZERO guard must not allocate guest RAM')
            require({'segment': segment['name'], 'guest_address': segment['address'],
                     'virtual_bytes': segment['bytes']} in report['guard_segments_not_reserved'],
                    'unreserved guest guard limitation must remain explicit')
            continue
        require(segment['address'] in regions, 'missing owned image segment')
        region = regions[segment['address']]
        require(region['virtual_bytes'] == segment['bytes'] and region['mapped_bytes'] >= segment['bytes'], 'owned segment extent mismatch')
        require(region['initial_bytes'] == segment['file_bytes'], 'owned segment file initialization extent mismatch')
        require((region['readable'], region['writable'], region['executable']) ==
                tuple(bool(segment['protection'] & bit) for bit in (1, 2, 4)), 'mapped guest permissions differ from linked segment')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/mapped-image-differential.json')
    arguments = parser.parse_args()
    require(platform.machine() == 'x86_64', 'native execution requires an x86_64 host')
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    cli_hash = digest(arguments.cli.read_bytes())
    source_paths = [Path(__file__), FIXTURE, ROOT / 'dev/differential.py', ROOT / 'dev/evidence.py',
                    ROOT / 'src/main.rs', ROOT / 'crates/stela-runtime/Cargo.toml', ROOT / 'Cargo.lock']
    source_paths.extend(sorted((ROOT / 'src/macho').rglob('*.rs')))
    source_paths.extend(sorted((ROOT / 'crates/stela-runtime/src').rglob('*.rs')))
    source_hashes = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_paths}
    with tempfile.TemporaryDirectory(prefix='mapped-image-', dir=arguments.output.parent) as temporary:
        work = Path(temporary)
        image, info, provenance = build_fixture(work)
        data = image.read_bytes()
        memory_segment = next(segment for segment in info['segments'] if segment['name'] == '__DATA')
        require(memory_segment['bytes'] > memory_segment['file_bytes'], 'fixture requires real segment zero tail')
        preflight = invoke(arguments.cli, 'plan-executable', image, '--architecture', 'arm64')
        require(preflight['container_sha256'] == digest(data), 'preflight input hash differs from linked fixture')
        require(preflight['plan']['entry']['guest_address'] == info['symbols']['_mapped_entry'], 'planned LC_MAIN entry differs from linked entry symbol')
        require(preflight['plan']['dylinker'] == '/usr/lib/dyld' and
                any(item['name'] == '/usr/lib/libSystem.B.dylib' for item in preflight['plan']['dependencies']),
                'actual dynamic loader/library dependencies must remain recorded')
        require(preflight['plan']['execution_supported'] is False and preflight['plan']['unresolved_requirements'], 'entry fixture must not imply complete process loading')
        rows = []
        for index, initial in enumerate(states(all_flags=True)):
            initial.sp = STACK_TOP
            initial.reserved = 0xa5c39e71
            initial.x[30] = STOP
            expected, pc, memory, frame, trace = original(data, info, initial)
            require((expected, pc, memory, frame) == fixture_oracle(data, info, initial), 'original ARM differs from independent fixture oracle')
            state_path = work / 'state.json'
            state_path.write_text(json.dumps(snapshot(initial)) + '\n')
            native = invoke(arguments.cli, 'run-mapped-image', image, '--architecture', 'arm64',
                            '--state', state_path, '--stop-pc', hex(STOP), '--block-budget', '8',
                            '--cache-dir', work / 'cache', '--read-memory', f"{memory_segment['address']:#x}:{memory_segment['bytes']}",
                            '--read-memory', f'{STACK_TOP - 16:#x}:16')
            require(native['complete_binary_verified'] is False, 'invalid complete-binary claim')
            require(native['initial_state'] == snapshot(initial), 'actual mapped entry state differs from supplied ABI')
            validate_regions(native, info)
            require(native['state'] == expected and native['pc'] == pc, f'state/PC mismatch in case {index}')
            require(native['outcome']['reason'] == {'kind': 'stop_address'}, 'native fixture did not stop at supplied return')
            require(native['outcome']['blocks_executed'] == 3 and native['outcome']['last_exit'] == [STOP, 4], 'native call/return dispatch was not exercised')
            require(native['outcome']['compiled_blocks'] == (3 if index == 0 else 0), 'unexpected cold/warm translation count')
            require(native['outcome']['disk_cache_hits'] == (0 if index == 0 else 3), 'unexpected cold/warm disk-cache count')
            require(native['plan'] == preflight['plan'], 'load plan changed between preflight and execution')
            require(native['memory'] == [{'address': memory_segment['address'], 'bytes_hex': memory.hex()},
                                         {'address': STACK_TOP - 16, 'bytes_hex': frame.hex()}], 'complete mapped data/BSS or guest-stack frame snapshot differs')
            rows.append({'initial': snapshot(initial), 'original_state': expected, 'original_pc': pc,
                         'original_trace': trace, 'original_data_sha256': digest(memory), 'original_stack_frame_hex': frame.hex(), 'native': native})
        require(cli_hash == digest(arguments.cli.read_bytes()), 'CLI changed during mapped-image probes')
        require(source_hashes == {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_paths}, 'harness/runtime source changed during mapped-image probes')
        report = {'kind': 'own_mapped_macho_entry_differential', 'schema_version': 1, 'passed': True,
                  'complete_binary_verified': False, 'complete_binaries_verified': 0,
                  'compiler_source_sha256': rows[0]['native']['compiler_source_sha256'], 'cli_sha256': cli_hash,
                  'harness_source_sha256': digest(Path(__file__).read_bytes()), 'source_sha256': source_hashes, 'fixture': provenance,
                  'layout': info, 'preflight': preflight, 'full_state_comparisons': len(rows),
                  'mapped_data_bytes_per_comparison': memory_segment['bytes'], 'stack_frame_bytes_per_comparison': 16, 'comparisons': rows,
                  'tested_state': ['x0..x30', 'sp', 'nzcv', 'reserved', 'actual RET PC', 'complete __DATA mapping including BSS and zero-fill tail', 'owned guest-stack FP/LR frame and restored SP/X29/LR'],
                  'limits': 'Own unchanged Apple-linker fixture with explicitly supplied entry ABI and unresolved dyld/libSystem dependencies. No full macOS process loading, dyld, imports, fixups, signatures, PAC, syscalls or macOS boot. Original/reference execution is Unicorn; native execution uses Stela mapped-image dispatcher.'}
        archive = write_evidence(arguments.output, report)
    print(json.dumps({'passed': True, 'full_state_comparisons': len(rows), 'data_bytes_per_comparison': memory_segment['bytes'],
                      'complete_binaries_verified': 0, 'report': str(arguments.output), 'snapshot': str(archive)}, indent=2))


if __name__ == '__main__':
    main()
