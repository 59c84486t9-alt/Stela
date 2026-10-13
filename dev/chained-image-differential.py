#!/usr/bin/env python3
"""Genuine Apple-linker chained rebases and slid native image entry execution.

The linked executable is unchanged. Original Arm runs with independently decoded
rebases at two load bases. Native dispatch must reproduce all registers, complete
DATA_CONST/DATA mappings and the FP/LR stack frame. This is an entry research ABI;
dyld, dependency loading and complete macOS process execution remain unresolved.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm

from differential import capture_arm, initialize_arm, state_dict as complete_state
from differential import ROOT, ARM_REGISTERS, MASK, states
from evidence import write_evidence

mapped = importlib.import_module('mapped-image-differential')
require, digest, snapshot = mapped.require, mapped.digest, mapped.snapshot
STOP, PAGE = mapped.STOP, mapped.PAGE
STACK_BASE, STACK_BYTES, STACK_TOP = mapped.STACK_BASE, mapped.STACK_BYTES, mapped.STACK_TOP
SEED = 0x9e3779b97f4a7c15
LOAD_BASES = (0x40000000000, 0x50000000000)
FIXTURE = ROOT / 'tests/fixtures/chained-image-arm64.S'


def parse_image(data):
    segments, sections, symbols = [], {}, {}
    symbol_table, chained, entry_offset = None, None, None
    for offset, command, body in mapped.commands(data):
        if command == 0x19:
            require(len(body) >= 72, 'truncated segment')
            _, _, name, address, size, fileoff, filesize, maximum, protection, count, flags = struct.unpack_from('<II16sQQQQIIII', body)
            name = name.rstrip(b'\0').decode('ascii')
            require(len(body) == 72 + count * 80 and fileoff + filesize <= len(data) and filesize <= size, 'invalid segment extent')
            require(address % PAGE == 0 and size % PAGE == 0, 'expected 16-KiB segment pages')
            segments.append({'name': name, 'address': address, 'bytes': size, 'file_offset': fileoff,
                             'file_bytes': filesize, 'protection': protection, 'maximum_protection': maximum, 'flags': flags})
            for index in range(count):
                item = struct.unpack_from('<16s16sQQIIIIIIII', body, 72 + index * 80)
                require(item[6] == 0 and item[7] == 0, 'unexpected section relocations')
                sections[item[0].rstrip(b'\0').decode('ascii')] = {'address': item[2], 'bytes': item[3], 'file_offset': item[4], 'flags': item[8]}
        elif command == 2:
            require(len(body) == 24 and symbol_table is None, 'invalid symbol table')
            symbol_table = struct.unpack_from('<6I', body)[2:]
        elif command == 0x80000034:
            require(len(body) == 16 and chained is None, 'invalid chained-fixup command')
            fileoff, length = struct.unpack_from('<II', body, 8)
            require(fileoff + length <= len(data), 'fixup payload exceeds file')
            chained = {'offset': fileoff, 'bytes': length, 'command_offset': offset}
        elif command == 0xb:
            require(len(body) == 80 and struct.unpack_from('<I', body, 28)[0] == 0, 'undefined imports')
        elif command == 0x80000028:
            require(len(body) == 24 and entry_offset is None, 'invalid LC_MAIN')
            entry_offset = struct.unpack_from('<Q', body, 8)[0]
        else:
            require(command in (0x80000033, 0xe, 0x32, 0x2a, 0xc, 0x26, 0x29), f'unexpected command {command:#x}')
    require(symbol_table is not None and chained is not None and entry_offset is not None, 'missing linker metadata')
    symoff, count, stroff, strsize = symbol_table
    require(symoff + 16 * count <= len(data) and stroff + strsize <= len(data), 'symbol/string table out of bounds')
    strings = data[stroff:stroff + strsize]
    for index in range(count):
        string, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', data, symoff + 16 * index)
        require(kind & 0xe != 0, 'undefined imports')
        require(string < len(strings) and b'\0' in strings[string:], 'bad symbol string')
        symbols[strings[string:].split(b'\0', 1)[0].decode('ascii')] = value
    require({'_chained_entry', '_chained_callee', '_chained_pointers', '_chained_seed', '_chained_output'} <= symbols.keys(), 'missing fixture symbols')
    preferred = next(segment['address'] for segment in segments if segment['name'] == '__TEXT')
    require(preferred + entry_offset == symbols['_chained_entry'], 'LC_MAIN disagrees with entry symbol')
    return {'segments': segments, 'sections': sections, 'symbols': symbols, 'preferred_base': preferred,
            'entry_offset': entry_offset, 'chained_payload': chained}


def decode_rebases(data, info, load_base):
    """Independent SDK-layout decoder, intentionally bounded to ordinary 64-bit rebases.

    Layout source: Apple's SDK mach-o/fixup-chains.h structures and bit fields.
    This decoder never calls Stela's parser, linker fixup tools or runtime.
    """
    require(load_base % PAGE == 0 and 0 < load_base < (1 << 47), 'invalid research load base')
    payload_info = info['chained_payload']
    payload = data[payload_info['offset']:payload_info['offset'] + payload_info['bytes']]
    require(len(payload) >= 28, 'truncated fixup header')
    version, starts, imports, strings, count, import_format, symbol_format = struct.unpack_from('<7I', payload)
    require(version == 0 and count == 0 and import_format == 1 and symbol_format == 0, 'unsupported imports or fixup-header format')
    require(28 <= starts and starts + 4 <= len(payload), 'starts table out of bounds')
    require(imports <= len(payload) and strings <= len(payload), 'imports/symbols offset out of bounds')
    segment_count = struct.unpack_from('<I', payload, starts)[0]
    require(segment_count == len(info['segments']) and starts + 4 + 4 * segment_count <= len(payload), 'invalid fixup segment table')
    offsets = struct.unpack_from(f'<{segment_count}I', payload, starts + 4)
    table_end = starts + 4 + 4 * segment_count
    rows, seen, formats = [], set(), set()
    slide = load_base - info['preferred_base']
    for index, relative in enumerate(offsets):
        if not relative:
            continue
        node = starts + relative
        require(table_end <= node and node + 22 <= len(payload), 'segment starts node out of bounds')
        size, page_size, pointer_format, segment_offset, max_pointer, page_count = struct.unpack_from('<IHHQIH', payload, node)
        require(size >= 22 + page_count * 2 and node + size <= len(payload), 'truncated segment starts node')
        require(page_size in (4096, 16384) and max_pointer == 0, 'unsupported page/max-pointer profile')
        require(pointer_format in (2, 6), 'authenticated/arm64e or unknown pointer format unsupported')
        formats.add(pointer_format)
        segment = info['segments'][index]
        require(segment['address'] - info['preferred_base'] == segment_offset, 'segment offset disagrees with Mach-O')
        require(page_count * page_size <= segment['bytes'], 'page count exceeds segment')
        for page_index in range(page_count):
            start = struct.unpack_from('<H', payload, node + 22 + page_index * 2)[0]
            if start == 0xffff:
                continue
            require(not start & 0x8000, 'multiple chain starts unsupported')
            require(start % 4 == 0, 'unaligned chain start')
            within = start
            while True:
                require(within + 8 <= page_size, 'chain escapes page')
                relative_slot = page_index * page_size + within
                require(relative_slot + 8 <= segment['file_bytes'], 'chain slot exceeds file-backed bytes')
                file_offset = segment['file_offset'] + relative_slot
                require(file_offset not in seen, 'duplicate/cyclic chain slot')
                seen.add(file_offset)
                raw = struct.unpack_from('<Q', data, file_offset)[0]
                require(raw >> 63 == 0, 'bound pointer unsupported')
                require((raw >> 44) & 0x7f == 0, 'nonzero reserved pointer bits')
                target = raw & ((1 << 36) - 1)
                high8 = (raw >> 36) & 0xff
                require(high8 == 0, 'tagged pointer outside ordinary-RAM fixture profile')
                value = load_base + target if pointer_format == 6 else target + slide
                require(0 < value < (1 << 47), 'rebased target exceeds native user range')
                rows.append({'segment_index': index, 'file_offset': file_offset,
                             'guest_address': segment['address'] + slide + relative_slot,
                             'raw': raw, 'value': value, 'pointer_format': pointer_format})
                next_words = (raw >> 51) & 0xfff
                if not next_words:
                    break
                within += next_words * 4
    return {'preferred_base': info['preferred_base'], 'load_base': load_base,
            'pointer_formats': sorted(formats), 'rebases': rows}


def initialized_segments(data, info, fixups):
    slide = fixups['load_base'] - info['preferred_base']
    segments = {}
    for segment in info['segments']:
        if not segment['protection']:
            continue
        memory = bytearray(segment['bytes'])
        start = segment['file_offset']
        memory[:segment['file_bytes']] = data[start:start + segment['file_bytes']]
        segments[segment['address'] + slide] = memory
    for row in fixups['rebases']:
        segment = info['segments'][row['segment_index']]
        start = segment['address'] + slide
        struct.pack_into('<Q', segments[start], row['guest_address'] - start, row['value'])
    return segments


def fixture_oracle(data, info, initial, load_base):
    """Symbol-level oracle does not consume the independent decoder's results."""
    slide = load_base - info['preferred_base']
    symbols = {name: value + slide for name, value in info['symbols'].items()}
    expected = snapshot(initial)
    result = (initial.x[0] + SEED) & MASK
    for register, value in {0: (result + 7) & MASK, 1: SEED, 4: 0, 9: symbols['_chained_pointers'],
                            10: symbols['_chained_seed'], 11: symbols['_chained_output'],
                            12: symbols['_chained_callee'], 30: STOP}.items():
        expected['x'][register] = value
    const = next(segment for segment in info['segments'] if segment['name'] == '__DATA_CONST')
    memory = next(segment for segment in info['segments'] if segment['name'] == '__DATA')
    constant_bytes, data_bytes = bytearray(const['bytes']), bytearray(memory['bytes'])
    for segment, output in ((const, constant_bytes), (memory, data_bytes)):
        start = segment['file_offset']
        output[:segment['file_bytes']] = data[start:start + segment['file_bytes']]
    const_offset = symbols['_chained_pointers'] - const['address'] - slide
    struct.pack_into('<QQQ', constant_bytes, const_offset,
                     symbols['_chained_seed'], symbols['_chained_output'], symbols['_chained_callee'])
    output_offset = symbols['_chained_output'] - memory['address'] - slide
    require(output_offset >= memory['file_bytes'] and not any(data_bytes[8:]), 'expected zero-tail BSS output')
    struct.pack_into('<QQ', data_bytes, output_offset, result, (result + 7) & MASK)
    snapshots = [{'address': const['address'] + slide, 'bytes_hex': constant_bytes.hex()},
                 {'address': memory['address'] + slide, 'bytes_hex': data_bytes.hex()},
                 {'address': STACK_TOP - 16, 'bytes_hex': struct.pack('<QQ', initial.x[29], STOP).hex()}]
    return expected, STOP, snapshots


def original(data, info, initial, fixups):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    slide = fixups['load_base'] - info['preferred_base']
    memories = initialized_segments(data, info, fixups)
    for segment in info['segments']:
        if not segment['protection']:
            continue
        address = segment['address'] + slide
        machine.mem_map(address, segment['bytes'])
        machine.mem_write(address, bytes(memories[address]))
        protection = segment['protection'] & ~2 if segment['flags'] & 0x10 else segment['protection']
        machine.mem_protect(address, segment['bytes'], protection)
    require(initial.sp == STACK_TOP and initial.x[30] == STOP, 'invalid supplied entry research ABI')
    machine.mem_map(STACK_BASE, STACK_BYTES, 3)
    initialize_arm(machine, initial)
    text = info['sections']['__text']
    trace = []
    def guard(machine, address, size, _):
        require(size == 4 and text['address'] + slide <= address < text['address'] + slide + text['bytes'], 'original execution left reviewed text')
        trace.append(address)
    machine.hook_add(UC_HOOK_CODE, guard)
    machine.emu_start(info['symbols']['_chained_entry'] + slide, STOP, count=128)
    pc = machine.reg_read(arm.UC_ARM64_REG_PC)
    require(pc == STOP and len(trace) == 16, 'original call/returns did not reach supplied stop')
    state = complete_state(capture_arm(machine, initial))
    snapshots = []
    for name in ('__DATA_CONST', '__DATA'):
        segment = next(segment for segment in info['segments'] if segment['name'] == name)
        address = segment['address'] + slide
        snapshots.append({'address': address, 'bytes_hex': bytes(machine.mem_read(address, segment['bytes'])).hex()})
    snapshots.append({'address': STACK_TOP - 16, 'bytes_hex': bytes(machine.mem_read(STACK_TOP - 16, 16)).hex()})
    return state, pc, snapshots, trace


def build_fixture(work):
    require(platform.system() == 'Darwin', 'fixture construction requires Apple clang/ld')
    clang = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    linker = subprocess.check_output(['xcrun', '--find', 'ld'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    obj, image = work / 'fixture.o', work / 'chained-image-arm64'
    commands = [[clang, '-target', 'arm64-apple-macos14', '-c', str(FIXTURE), '-o', str(obj)],
                [linker, '-arch', 'arm64', '-platform_version', 'macos', '14.0', '14.0', '-e', '_chained_entry',
                 '-o', str(image), str(obj), '-syslibroot', sdk, '-lSystem', '-no_uuid', '-no_adhoc_codesign']]
    outputs = []
    for command in commands:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        outputs.append({'stdout': completed.stdout, 'stderr': completed.stderr})
    data = image.read_bytes()
    info = parse_image(data)
    fixups = decode_rebases(data, info, LOAD_BASES[0])
    require(fixups['pointer_formats'] == [6] and len(fixups['rebases']) == 3, 'linker fixture pointer format/count changed; review before native execution')
    targets = [info['symbols'][name] for name in ('_chained_seed', '_chained_output', '_chained_callee')]
    require([row['value'] for row in fixups['rebases']] == [value + LOAD_BASES[0] - info['preferred_base'] for value in targets], 'linked pointer targets disagree with symbol oracle')
    text = info['sections']['__text']
    code = data[text['file_offset']:text['file_offset'] + text['bytes']]
    instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, text['address']))
    require(len(code) == 64 and len(instructions) == 16 and [item.mnemonic for item in instructions] ==
            ['stp', 'mov', 'adrp', 'add', 'ldp', 'ldr', 'ldr', 'ldr', 'add', 'blr', 'ldp', 'ret',
             'str', 'add', 'str', 'ret'], 'fixture instructions changed; review before native execution')
    header = Path(sdk) / 'usr/include/mach-o/fixup-chains.h'
    return image, info, {'commands': commands, 'tool_outputs': outputs, 'linked_executable_unchanged': True,
                         'source_sha256': digest(FIXTURE.read_bytes()), 'object_sha256': digest(obj.read_bytes()),
                         'fixture_sha256': digest(data), 'text_sha256': digest(code), 'actual_rebases': 3, 'undefined_imports': 0,
                         'independent_decoder_layout_source': str(header), 'layout_header_sha256': digest(header.read_bytes()),
                         'disassembly': [f'{item.address:#x}: {item.mnemonic} {item.op_str}' for item in instructions]}


def negative_inputs(data, info):
    """Mutate metadata only; these inputs must never reach an execution command."""
    rows = []
    payload = info['chained_payload']['offset']
    starts = struct.unpack_from('<I', data, payload + 4)[0]
    segment_count = len(info['segments'])
    offsets = struct.unpack_from(f'<{segment_count}I', data, payload + starts + 4)
    node = payload + starts + next(offset for offset in offsets if offset)
    slot = decode_rebases(data, info, LOAD_BASES[0])['rebases'][0]['file_offset']
    for name, offset, format, value in [
            ('nonzero_import_count', payload + 16, '<I', 1),
            ('bound_pointer', slot, '<Q', struct.unpack_from('<Q', data, slot)[0] | (1 << 63)),
            ('out_of_bounds_starts_node', payload + starts + 4 + 2 * 4, '<I', 0xfffffffc),
            ('chain_crosses_page', slot, '<Q', (struct.unpack_from('<Q', data, slot)[0] & ~(0xfff << 51)) | (0xfff << 51)),
            ('multiple_chain_starts', node + 22, '<H', 0x8000),
            ('reserved_pointer_bits', slot, '<Q', struct.unpack_from('<Q', data, slot)[0] | (1 << 44)),
    ]:
        changed = bytearray(data)
        struct.pack_into(format, changed, offset, value)
        rows.append({'name': name, 'data': bytes(changed)})
    authenticated = bytearray(data)
    struct.pack_into('<H', authenticated, node + 6, 9)
    struct.pack_into('<Q', authenticated, slot, struct.unpack_from('<Q', data, slot)[0] | (1 << 63))
    rows.append({'name': 'actual_authenticated_pointer', 'data': bytes(authenticated)})
    return rows


def invoke(cli, *arguments):
    completed = subprocess.run([str(cli), *map(str, arguments)], capture_output=True, text=True)
    require(completed.returncode == 0, f'CLI failed ({completed.returncode}): {completed.stderr.strip()}')
    return json.loads(completed.stdout)


def validate_regions(native, info, load_base):
    slide = load_base - info['preferred_base']
    regions = {region['guest_address']: region for region in native['memory_regions']}
    require(native['host_execute'] is False, 'original guest bytes must never receive host execute permission')
    for segment in info['segments']:
        if not segment['protection']:
            require(segment['address'] not in regions, 'PAGEZERO must remain unreserved')
            continue
        address = segment['address'] + slide
        require(address in regions, 'missing slid image segment')
        region = regions[address]
        require(region['virtual_bytes'] == segment['bytes'] and region['initial_bytes'] == segment['file_bytes'], 'slid mapping extent differs')
        expected = (bool(segment['protection'] & 1), bool(segment['protection'] & 2) and not bool(segment['flags'] & 0x10), bool(segment['protection'] & 4))
        require((region['readable'], region['writable'], region['executable']) == expected, 'sealed segment protection mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/chained-image-differential.json')
    arguments = parser.parse_args()
    require(platform.machine() == 'x86_64', 'native differential requires x86_64')
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    cli_hash = digest(arguments.cli.read_bytes())
    paths = [Path(__file__), FIXTURE, ROOT / 'dev/mapped-image-differential.py', ROOT / 'dev/differential.py',
             ROOT / 'dev/evidence.py', ROOT / 'src/main.rs', ROOT / 'Cargo.toml', ROOT / 'Cargo.lock',
             ROOT / 'crates/stela-runtime/Cargo.toml']
    paths.extend(sorted((ROOT / 'src/macho').rglob('*.rs')))
    paths.extend(sorted((ROOT / 'crates/stela-runtime/src').rglob('*.rs')))
    hashes = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in paths}
    with tempfile.TemporaryDirectory(prefix='chained-image-', dir=arguments.output.parent) as temporary:
        work = Path(temporary)
        image, info, provenance = build_fixture(work)
        data = image.read_bytes()
        structural = invoke(arguments.cli, 'plan-executable', image, '--architecture', 'arm64')
        require(structural['container_sha256'] == digest(data), 'structural plan changed fixture identity')
        plan = structural['plan']
        require(plan['execution_supported'] is False and plan['unresolved_requirements'], 'full process compatibility cannot be claimed')
        require(plan['dylinker'] == '/usr/lib/dyld' and any(item['name'] == '/usr/lib/libSystem.B.dylib' for item in plan['dependencies']), 'dynamic loader/library requirements disappeared')
        rejected = []
        for negative in negative_inputs(data, info):
            with_exception = False
            try:
                decode_rebases(negative['data'], info, LOAD_BASES[0])
            except AssertionError:
                with_exception = True
            require(with_exception, 'independent decoder accepted malformed or unsupported fixture ' + negative['name'])
            path = work / (negative['name'] + '.macho')
            path.write_bytes(negative['data'])
            completed = subprocess.run([str(arguments.cli), 'plan-fixups', str(path), '--architecture', 'arm64',
                                        '--image-base', hex(LOAD_BASES[0])], capture_output=True, text=True)
            require(completed.returncode != 0 and completed.stderr, 'native preflight accepted malformed or unsupported fixup ' + negative['name'])
            rejected.append({'name': negative['name'], 'input_sha256': digest(negative['data']),
                             'returncode': completed.returncode, 'stderr': completed.stderr.strip(), 'execution_attempted': False})
        policy_rejections = []
        misaligned_state = snapshot(states(all_flags=True)[0])
        misaligned_state['sp'] = STACK_TOP + 1
        misaligned_state['x'][30] = STOP
        bad_state_path = work / 'misaligned-state.json'
        bad_state_path.write_text(json.dumps(misaligned_state) + '\n')
        no_read_const = bytearray(data)
        for offset, command, body in mapped.commands(data):
            if command == 0x19 and body[8:24].rstrip(b'\0') == b'__DATA_CONST':
                struct.pack_into('<I', no_read_const, offset + 60, 2)
                break
        else:
            raise AssertionError('missing fixture DATA_CONST segment')
        no_read_path = work / 'constant_without_read_permission.macho'
        no_read_path.write_bytes(no_read_const)
        for name, input_path, parameters, error_hint in [
                ('unaligned_image_base', image, ['--image-base', hex(LOAD_BASES[0] + 4)], '16 kib'),
                ('unaligned_initial_sp', image, ['--image-base', hex(LOAD_BASES[0]), '--state', bad_state_path], 'align'),
                ('read_only_const_without_declared_read', no_read_path, ['--image-base', hex(LOAD_BASES[0])], 'read permission')]:
            # Zero block budget prevents instruction execution even if the
            # expected early argument/profile validation were to regress.
            completed = subprocess.run([str(arguments.cli), 'run-mapped-image', str(input_path),
                                        '--architecture', 'arm64', '--block-budget', '0',
                                        *map(str, parameters)], capture_output=True, text=True)
            require(completed.returncode != 0 and error_hint in completed.stderr.lower(),
                    'missing explicit mapped-profile preflight rejection: ' + name)
            policy_rejections.append({'name': name, 'input_sha256': digest(input_path.read_bytes()),
                                      'returncode': completed.returncode, 'stderr': completed.stderr.strip(),
                                      'block_budget': 0, 'instructions_executed': 0})
        rows, preflights = [], []
        for load_base in LOAD_BASES:
            expected_fixups = decode_rebases(data, info, load_base)
            preflight = invoke(arguments.cli, 'plan-fixups', image, '--architecture', 'arm64', '--image-base', hex(load_base))
            require(preflight['container_sha256'] == digest(data), 'fixup preflight changed fixture input identity')
            require(preflight['fixups'] == expected_fixups and preflight['plan'] == plan, 'native fixup plan differs from independent decoder')
            require(preflight['complete_binary_verified'] is False, 'fixup preflight claimed full binary execution')
            preflights.append(preflight)
            for index, initial in enumerate(states(all_flags=True)):
                initial.sp, initial.x[30], initial.reserved = STACK_TOP, STOP, 0xa5c39e71
                expected, pc, memory, trace = original(data, info, initial, expected_fixups)
                require((expected, pc, memory) == fixture_oracle(data, info, initial, load_base), 'original ARM differs from symbol-level state/data oracle')
                state_path = work / 'state.json'
                state_path.write_text(json.dumps(snapshot(initial)) + '\n')
                parameters = ['run-mapped-image', image, '--architecture', 'arm64', '--image-base', hex(load_base),
                              '--state', state_path, '--stop-pc', hex(STOP), '--block-budget', '8', '--cache-dir', work / 'shared-cache']
                for region in memory:
                    parameters.extend(['--read-memory', f"{region['address']:#x}:{len(region['bytes_hex']) // 2}"])
                native = invoke(arguments.cli, *parameters)
                require(native['container_sha256'] == digest(data), 'execution changed fixture input identity')
                require(native['plan'] == plan and native['fixups'] == expected_fixups, 'execution changed original plan/fixup results')
                require(native['applied_rebases'] == 3, 'actual mapped rebase application count differs')
                require(native['image_base'] == load_base and native['mapped_entry'] == info['symbols']['_chained_entry'] + load_base - info['preferred_base'], 'wrong slid image entry')
                require(native['initial_state'] == snapshot(initial) and native['state'] == expected and native['pc'] == pc, 'slid native state differs from original ARM')
                require(native['memory'] == memory, 'slid DATA_CONST/DATA/stack memory differs from original and oracle')
                require(native['complete_binary_verified'] is False, 'entry probe claimed full process compatibility')
                require(native['outcome']['reason'] == {'kind': 'stop_address'} and native['outcome']['last_exit'] == [STOP, 4] and native['outcome']['blocks_executed'] == 3, 'real indirect call/return chain was not exercised')
                require(native['outcome']['compiled_blocks'] == (3 if index == 0 else 0) and native['outcome']['disk_cache_hits'] == (0 if index == 0 else 3), 'cache did not bind native blocks to actual slid guest addresses')
                validate_regions(native, info, load_base)
                rows.append({'load_base': load_base, 'initial': snapshot(initial), 'original_state': expected, 'original_pc': pc,
                             'original_trace': trace, 'original_memory_sha256': [digest(bytes.fromhex(region['bytes_hex'])) for region in memory], 'native': native})
        require(image.read_bytes() == data, 'execution changed original linked file bytes')
        require(cli_hash == digest(arguments.cli.read_bytes()), 'CLI changed during chained image execution')
        require(hashes == {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in paths}, 'harness/runtime sources changed during chained image execution')
        report = {'kind': 'own_chained_macho_slid_entry_differential', 'schema_version': 1, 'passed': True,
                  'complete_binary_verified': False, 'complete_binaries_verified': 0,
                  'compiler_source_sha256': rows[0]['native']['compiler_source_sha256'], 'cli_sha256': cli_hash,
                  'harness_source_sha256': digest(Path(__file__).read_bytes()), 'source_sha256': hashes,
                  'fixture': provenance, 'layout': info, 'load_bases': list(LOAD_BASES), 'preflights': preflights,
                  'declined_inputs_before_execution': rejected, 'profile_preflight_rejections': policy_rejections,
                  'full_state_comparisons': len(rows),
                  'mapped_data_bytes_per_comparison': sum(segment['bytes'] for segment in info['segments'] if segment['name'] in ('__DATA_CONST', '__DATA')), 'stack_frame_bytes_per_comparison': 16, 'comparisons': rows,
                  'tested_state': ['x0..x30', 'SP/NZCV/reserved', 'real BLR/RET guest PCs', 'three genuine format-6 rebased pointers',
                                   'complete DATA_CONST/DATA and BSS zero-tail snapshots', 'FP/LR guest-stack frame', 'two slid address identities and cold/warm cache reuse'],
                  'limits': 'Own unchanged linker fixture under explicitly supplied entry ABI. Ordinary format-6 rebases only; no imports/binds/authenticated pointers, dynamic dependency loading, initializer execution, process ABI, syscalls or macOS boot.'}
        archive = write_evidence(arguments.output, report)
    print(json.dumps({'passed': True, 'full_state_comparisons': len(rows), 'load_bases': [hex(base) for base in LOAD_BASES],
                      'actual_linked_rebases': provenance['actual_rebases'], 'declined_inputs': len(rejected),
                      'complete_binaries_verified': 0, 'report': str(arguments.output), 'snapshot': str(archive)}, indent=2))


if __name__ == '__main__':
    main()
