#!/usr/bin/env python3
"""Unchanged Apple-linked main/dylib imports versus original ARM and native dispatch.

Independent SDK-layout decoders resolve the dylib exports and genuine chained
binds. Original ARM and native x86 run the same code at two distinct placements;
no guest import is redirected to a host stub. Full macOS process launch remains
unverified: dependency discovery, initializer calls, PAC and system ABI are pending.
"""
import argparse
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
from differential import ROOT, ARM_REGISTERS, MASK, states
from evidence import write_evidence

chained = importlib.import_module('chained-image-differential')
require, digest, snapshot = chained.require, chained.digest, chained.snapshot
STOP, PAGE, SEED = chained.STOP, chained.PAGE, chained.SEED
STACK_BASE, STACK_BYTES = 0x80000000000, 65536
STACK_TOP = STACK_BASE + STACK_BYTES
PLACEMENTS = ((0x40000000000, 0x50000000000), (0x60000000000, 0x70000000000))
INSTALL_NAME = '@rpath/libstela-fixture.dylib'
MAIN_SOURCE = ROOT / 'tests/fixtures/bound-image-arm64.S'
LIBRARY_SOURCE = ROOT / 'tests/fixtures/bound-library-arm64.S'


def commands(data):
    require(len(data) >= 32, 'truncated image header')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    require((magic, cpu, subtype, reserved) == (0xfeedfacf, 0x100000c, 0, 0) and kind in (2, 6), 'unsupported fixture image header')
    end, position, rows = 32 + size, 32, []
    require(end <= len(data), 'truncated load commands')
    for _ in range(count):
        require(position + 8 <= end, 'truncated command header')
        command, length = struct.unpack_from('<II', data, position)
        require(length >= 8 and length % 8 == 0 and position + length <= end, 'invalid command extent')
        rows.append((position, command, data[position:position + length]))
        position += length
    require(position == end, 'command count/size mismatch')
    return rows


def command_string(body):
    offset = struct.unpack_from('<I', body, 8)[0]
    require(12 <= offset < len(body) and b'\0' in body[offset:], 'invalid command string')
    return body[offset:].split(b'\0', 1)[0].decode('utf-8')


def parse_image(data):
    info = {'kind': struct.unpack_from('<I', data, 12)[0], 'segments': [], 'sections': {}, 'symbols': {},
            'dependencies': [], 'install_name': None, 'entry_offset': None}
    symbol_table = None
    for offset, command, body in commands(data):
        if command == 0x19:
            require(len(body) >= 72, 'truncated segment')
            _, _, name, address, size, fileoff, filesize, maximum, protection, count, flags = struct.unpack_from('<II16sQQQQIIII', body)
            require(len(body) == 72 + count * 80 and fileoff + filesize <= len(data) and filesize <= size, 'invalid segment extent')
            require(address % PAGE == 0 and size % PAGE == 0, 'expected 16-KiB segment pages')
            info['segments'].append({'name': name.rstrip(b'\0').decode(), 'address': address, 'bytes': size,
                                     'file_offset': fileoff, 'file_bytes': filesize, 'maximum_protection': maximum,
                                     'protection': protection, 'flags': flags, 'command_offset': offset})
            for index in range(count):
                item = struct.unpack_from('<16s16sQQIIIIIIII', body, 72 + index * 80)
                require(item[6] == item[7] == 0, 'unexpected section relocations')
                info['sections'][item[0].rstrip(b'\0').decode()] = {'address': item[2], 'bytes': item[3], 'file_offset': item[4]}
        elif command == 2:
            require(len(body) == 24 and symbol_table is None, 'invalid symbol table')
            symbol_table = struct.unpack_from('<6I', body)[2:]
        elif command in (0x80000034, 0x80000033):
            require(len(body) == 16, 'invalid linkedit payload command')
            fileoff, length = struct.unpack_from('<II', body, 8)
            require(fileoff + length <= len(data), 'payload exceeds file')
            key = 'chained_payload' if command == 0x80000034 else 'exports_payload'
            require(key not in info, 'duplicate payload command')
            info[key] = {'offset': fileoff, 'bytes': length, 'command_offset': offset}
        elif command == 0xc:
            info['dependencies'].append(command_string(body))
        elif command == 0xd:
            require(info['install_name'] is None, 'duplicate install name')
            info['install_name'] = command_string(body)
        elif command == 0x80000028:
            require(info['entry_offset'] is None and len(body) == 24, 'invalid LC_MAIN')
            info['entry_offset'] = struct.unpack_from('<Q', body, 8)[0]
        else:
            require(command in (0xb, 0xe, 0x1b, 0x32, 0x2a, 0x26, 0x29), f'unexpected command {command:#x}')
    require(symbol_table is not None and 'chained_payload' in info and 'exports_payload' in info, 'missing image metadata')
    symoff, count, stroff, strsize = symbol_table
    require(symoff + count * 16 <= len(data) and stroff + strsize <= len(data), 'invalid symbol/string table')
    strings = data[stroff:stroff + strsize]
    for index in range(count):
        string, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', data, symoff + index * 16)
        require(string < len(strings) and b'\0' in strings[string:], 'invalid symbol name')
        info['symbols'][strings[string:].split(b'\0', 1)[0].decode()] = value
    info['preferred_base'] = next(segment['address'] for segment in info['segments'] if segment['name'] == '__TEXT')
    require(info['kind'] != 2 or info['preferred_base'] + info['entry_offset'] == info['symbols']['_bound_entry'], 'LC_MAIN disagrees with symbol')
    require(info['kind'] != 6 or info['install_name'] == INSTALL_NAME, 'unexpected dylib install name')
    return info


def uleb(data, offset, end):
    result, shift = 0, 0
    for _ in range(10):
        require(offset < end, 'truncated ULEB')
        byte = data[offset]
        offset += 1
        require(shift < 63 or byte & 0x7f <= 1, 'ULEB overflow')
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
    raise AssertionError('overlong ULEB')


def exports(data, info, terminal_locations=None):
    payload = info['exports_payload']
    trie = data[payload['offset']:payload['offset'] + payload['bytes']]
    symbols, visited = {}, 0
    def walk(position, prefix, active):
        nonlocal visited
        require(position not in active and position < len(trie), 'cyclic or out-of-bounds export trie')
        visited += 1
        require(visited <= 10000, 'excessive export trie traversal')
        active = active | {position}
        size, cursor = uleb(trie, position, len(trie))
        end = cursor + size
        require(end < len(trie), 'export terminal exceeds trie')
        if size:
            terminal_start = cursor
            flags, cursor = uleb(trie, cursor, end)
            require(flags & 0x18 == 0 and flags & 3 == 0, 'unsupported reexport/resolver/absolute/thread-local export')
            value, cursor = uleb(trie, cursor, end)
            require(cursor == end and prefix and prefix not in symbols, 'invalid/duplicate export terminal')
            symbols[prefix] = {'flags': flags, 'value': value}
            if terminal_locations is not None:
                terminal_locations[prefix] = {'offset': payload['offset'] + terminal_start, 'bytes': size}
        cursor = end
        count = trie[cursor]
        cursor += 1
        for _ in range(count):
            terminator = trie.find(b'\0', cursor)
            require(terminator > cursor, 'missing/empty export edge')
            edge = trie[cursor:terminator].decode('utf-8')
            child, cursor = uleb(trie, terminator + 1, len(trie))
            walk(child, prefix + edge, active)
    walk(0, '', set())
    return symbols


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def decode_fixups(data, info, load_base):
    require(load_base % PAGE == 0 and 0 < load_base < (1 << 47), 'invalid load base')
    meta = info['chained_payload']
    payload = data[meta['offset']:meta['offset'] + meta['bytes']]
    require(len(payload) >= 28, 'truncated fixup header')
    version, starts, imports_offset, symbols_offset, import_count, import_format, symbols_format = struct.unpack_from('<7I', payload)
    require(version == 0 and import_format == 1 and symbols_format == 0, 'unsupported fixup-header format')
    require(28 <= starts < imports_offset <= symbols_offset <= len(payload) and imports_offset + 4 * import_count <= symbols_offset, 'invalid fixup metadata extents')
    imports = []
    for index in range(import_count):
        word = struct.unpack_from('<I', payload, imports_offset + index * 4)[0]
        name_offset = symbols_offset + (word >> 9)
        require(name_offset < len(payload) and b'\0' in payload[name_offset:], 'invalid import name')
        name = payload[name_offset:].split(b'\0', 1)[0].decode('utf-8')
        imports.append({'library_ordinal': signed(word & 0xff, 8), 'weak': bool(word & 0x100), 'name': name, 'addend': 0})
    segment_count = struct.unpack_from('<I', payload, starts)[0]
    table_end = starts + 4 + segment_count * 4
    require(segment_count == len(info['segments']) and table_end <= imports_offset, 'invalid segment-start table')
    offsets = struct.unpack_from(f'<{segment_count}I', payload, starts + 4)
    rebases, binds, formats, slots = [], [], set(), set()
    for segment_index, relative in enumerate(offsets):
        if not relative:
            continue
        node = starts + relative
        require(table_end <= node and node + 22 <= imports_offset, 'segment-start node out of bounds')
        size, page_size, pointer_format, segment_offset, maximum, pages = struct.unpack_from('<IHHQIH', payload, node)
        require(size >= 22 + pages * 2 and node + size <= imports_offset and page_size in (4096, 16384) and maximum == 0, 'invalid segment-start node')
        require(pointer_format in (2, 6), 'fixture decoder supports ordinary format2/6 only')
        formats.add(pointer_format)
        segment = info['segments'][segment_index]
        require(segment_offset == segment['address'] - info['preferred_base'] and pages * page_size <= segment['bytes'], 'segment offset/page count mismatch')
        for page in range(pages):
            within = struct.unpack_from('<H', payload, node + 22 + page * 2)[0]
            if within == 0xffff:
                continue
            require(within & 0x8000 == 0 and within % 4 == 0, 'unsupported multistart or unaligned start')
            while True:
                require(within + 8 <= page_size, 'chain escapes page')
                relative_slot = page * page_size + within
                require(relative_slot + 8 <= segment['file_bytes'], 'chain escapes file-backed segment')
                file_offset = segment['file_offset'] + relative_slot
                require(file_offset not in slots, 'duplicate chain slot')
                slots.add(file_offset)
                raw = struct.unpack_from('<Q', data, file_offset)[0]
                row = {'segment_index': segment_index, 'file_offset': file_offset,
                       'guest_address': load_base + segment_offset + relative_slot, 'raw': raw, 'pointer_format': pointer_format}
                if raw >> 63:
                    import_index = raw & 0xffffff
                    require(import_index < len(imports) and (raw >> 32) & 0x7ffff == 0, 'invalid bind ordinal/reserved bits')
                    inline = signed((raw >> 24) & 0xff, 8)
                    binds.append({**row, 'import_index': import_index, 'inline_addend': inline, 'addend': inline + imports[import_index]['addend']})
                else:
                    require((raw >> 44) & 0x7f == 0 and (raw >> 36) & 0xff == 0, 'unsupported reserved/tagged rebase')
                    target = raw & ((1 << 36) - 1)
                    value = load_base + target if pointer_format == 6 else target + load_base - info['preferred_base']
                    rebases.append({**row, 'value': value})
                next_words = (raw >> 51) & 0xfff
                if not next_words:
                    break
                within += next_words * 4
    return {'preferred_base': info['preferred_base'], 'load_base': load_base, 'pointer_formats': sorted(formats),
            'rebases': rebases, 'imports': imports, 'binds': binds}


def resolve_bindings(main, library, decoded, library_exports, library_base):
    rows = []
    for bind in decoded['binds']:
        imported = decoded['imports'][bind['import_index']]
        ordinal = imported['library_ordinal']
        require(ordinal > 0 and ordinal <= len(main['dependencies']), 'unsupported nonpositive or missing library ordinal')
        require(not imported['weak'] and main['dependencies'][ordinal - 1] == library['install_name'], 'missing/weak/mismatched declared provider')
        require(imported['name'] in library_exports, 'missing export')
        exported = library_exports[imported['name']]
        address = library_base + exported['value']
        rows.append({**{key: bind[key] for key in ('segment_index', 'file_offset', 'guest_address', 'raw', 'pointer_format', 'import_index')},
                     'library_ordinal': ordinal, 'name': imported['name'], 'provider_image': 1,
                     'address': address, 'addend': bind['addend'], 'value': address + bind['addend']})
    return rows


def reference_memories(data, info, fixups, bindings=()):
    memories = chained.initialized_segments(data, info, fixups)
    slide = fixups['load_base'] - info['preferred_base']
    for row in bindings:
        segment = info['segments'][row['segment_index']]
        base = segment['address'] + slide
        struct.pack_into('<Q', memories[base], row['guest_address'] - base, row['value'])
    return memories


def oracle_memory(data, info, load_base):
    memories = {}
    for segment in info['segments']:
        if segment['name'] not in ('__DATA_CONST', '__DATA'):
            continue
        output = bytearray(segment['bytes'])
        start = segment['file_offset']
        output[:segment['file_bytes']] = data[start:start + segment['file_bytes']]
        memories[segment['name']] = (load_base + segment['address'] - info['preferred_base'], output)
    return memories


def fixture_oracle(inputs, infos, initial, bases):
    main, library = infos
    main_symbols = {name: bases[0] + value - main['preferred_base'] for name, value in main['symbols'].items()}
    lib_symbols = {name: bases[1] + value - library['preferred_base'] for name, value in library['symbols'].items()}
    result = (initial.x[0] + SEED) & MASK
    final = (result + 11) & MASK
    expected = snapshot(initial)
    for register, value in {0: final, 1: SEED, 4: 0, 9: lib_symbols['_library_pointers'],
                            10: lib_symbols['_library_output'], 12: lib_symbols['_bound_function'],
                            13: lib_symbols['_bound_seed'], 14: main_symbols['_bound_output'], 30: STOP}.items():
        expected['x'][register] = value
    main_memory, lib_memory = [oracle_memory(data, info, base) for data, info, base in zip(inputs, infos, bases)]
    base, output = main_memory['__DATA_CONST']
    struct.pack_into('<QQ', output, main_symbols['_bound_imports'] - base, lib_symbols['_bound_function'], lib_symbols['_bound_seed'])
    base, output = main_memory['__DATA']
    require(not any(output[8:]), 'main BSS must begin zero')
    struct.pack_into('<Q', output, main_symbols['_bound_output'] - base, final)
    base, output = lib_memory['__DATA_CONST']
    struct.pack_into('<Q', output, lib_symbols['_library_pointers'] - base, lib_symbols['_library_output'])
    base, output = lib_memory['__DATA']
    require(not any(output[8:]), 'library BSS must begin zero')
    struct.pack_into('<QQ', output, lib_symbols['_library_output'] - base, result, final)
    memory = [{'address': address, 'bytes_hex': output.hex()} for group in (main_memory, lib_memory)
              for address, output in (group['__DATA_CONST'], group['__DATA'])]
    memory.append({'address': STACK_TOP - 16, 'bytes_hex': struct.pack('<QQ', initial.x[29], STOP).hex()})
    return expected, STOP, memory


def original(inputs, infos, initial, bases, decoded, bindings):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for index, (data, info, base, fixups) in enumerate(zip(inputs, infos, bases, decoded)):
        memories = reference_memories(data, info, fixups, bindings if index == 0 else ())
        for segment in info['segments']:
            if not segment['protection']:
                continue
            address = base + segment['address'] - info['preferred_base']
            machine.mem_map(address, segment['bytes'])
            machine.mem_write(address, bytes(memories[address]))
            protection = segment['protection'] & ~2 if segment['flags'] & 0x10 else segment['protection']
            machine.mem_protect(address, segment['bytes'], protection)
    require(initial.sp == STACK_TOP and initial.x[30] == STOP, 'invalid supplied entry ABI')
    machine.mem_map(STACK_BASE, STACK_BYTES, 3)
    for register, value in zip(ARM_REGISTERS, initial.x):
        machine.reg_write(register, value)
    machine.reg_write(arm.UC_ARM64_REG_SP, initial.sp)
    machine.reg_write(arm.UC_ARM64_REG_NZCV, initial.nzcv)
    ranges = [(base + info['sections']['__text']['address'] - info['preferred_base'], info['sections']['__text']['bytes']) for info, base in zip(infos, bases)]
    trace = []
    def guard(machine, address, size, _):
        require(size == 4 and any(start <= address < start + size_bytes for start, size_bytes in ranges), 'original left reviewed image text')
        trace.append(address)
    machine.hook_add(UC_HOOK_CODE, guard)
    machine.emu_start(bases[0] + infos[0]['entry_offset'], STOP, count=128)
    pc = machine.reg_read(arm.UC_ARM64_REG_PC)
    require(pc == STOP and len(trace) == 21, 'cross-image BLR/RET did not reach stop')
    state = {'x': [machine.reg_read(register) for register in ARM_REGISTERS], 'sp': machine.reg_read(arm.UC_ARM64_REG_SP),
             'nzcv': machine.reg_read(arm.UC_ARM64_REG_NZCV) & 0xf0000000, 'reserved': initial.reserved}
    memory = []
    for info, base in zip(infos, bases):
        for name in ('__DATA_CONST', '__DATA'):
            segment = next(segment for segment in info['segments'] if segment['name'] == name)
            address = base + segment['address'] - info['preferred_base']
            memory.append({'address': address, 'bytes_hex': bytes(machine.mem_read(address, segment['bytes'])).hex()})
    memory.append({'address': STACK_TOP - 16, 'bytes_hex': bytes(machine.mem_read(STACK_TOP - 16, 16)).hex()})
    return state, pc, memory, trace


def build_fixtures(work):
    require(platform.system() == 'Darwin', 'genuine fixture construction requires Apple clang/ld')
    clang = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    linker = subprocess.check_output(['xcrun', '--find', 'ld'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    main_object, lib_object = work / 'main.o', work / 'library.o'
    main_path, lib_path = work / 'bound-main', work / 'libstela-fixture.dylib'
    exported = work / 'exports.txt'
    exported.write_text('_bound_function\n_bound_seed\n')
    common = ['-arch', 'arm64', '-platform_version', 'macos', '14.0', '14.0']
    commands_used = [
        [clang, '-target', 'arm64-apple-macos14', '-c', str(MAIN_SOURCE), '-o', str(main_object)],
        [clang, '-target', 'arm64-apple-macos14', '-c', str(LIBRARY_SOURCE), '-o', str(lib_object)],
        [linker, '-dylib', *common, '-install_name', INSTALL_NAME, '-exported_symbols_list', str(exported),
         '-o', str(lib_path), str(lib_object), '-syslibroot', sdk, '-lSystem', '-no_adhoc_codesign'],
        [linker, *common, '-e', '_bound_entry', '-o', str(main_path), str(main_object), str(lib_path),
         '-syslibroot', sdk, '-lSystem', '-no_uuid', '-no_adhoc_codesign'],
    ]
    tool_outputs = []
    for command in commands_used:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        tool_outputs.append({'stdout': completed.stdout, 'stderr': completed.stderr})
    paths = (main_path, lib_path)
    data = [path.read_bytes() for path in paths]
    infos = [parse_image(blob) for blob in data]
    library_exports = exports(data[1], infos[1])
    require(set(library_exports) == {'_bound_function', '_bound_seed'}, 'library exported symbol set changed')
    for name, exported_symbol in library_exports.items():
        require(exported_symbol['flags'] == 0 and exported_symbol['value'] == infos[1]['symbols'][name] - infos[1]['preferred_base'], 'exports trie disagrees with symbol oracle')
    decoded = [decode_fixups(blob, info, base) for blob, info, base in zip(data, infos, PLACEMENTS[0])]
    require([len(item['binds']) for item in decoded] == [2, 0] and [len(item['rebases']) for item in decoded] == [0, 1], 'genuine fixup counts changed')
    require(all(item['pointer_formats'] == [6] for item in decoded), 'genuine pointer format changed')
    require({item['name'] for item in decoded[0]['imports']} == {'_bound_function', '_bound_seed'} and
            all(item['library_ordinal'] == 1 and not item['weak'] for item in decoded[0]['imports']), 'genuine import profile changed')
    disassembly = []
    for blob, info, names in zip(data, infos, [
            ['stp', 'mov', 'adrp', 'add', 'ldp', 'ldr', 'add', 'blr', 'adrp', 'add', 'str', 'ldp', 'ret'],
            ['adrp', 'add', 'ldr', 'ldr', 'str', 'add', 'str', 'ret']]):
        section = info['sections']['__text']
        code = blob[section['file_offset']:section['file_offset'] + section['bytes']]
        instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, section['address']))
        require(len(code) == 4 * len(names) and [item.mnemonic for item in instructions] == names, 'review fixture instruction changes before native execution')
        disassembly.append([f'{item.address:#x}: {item.mnemonic} {item.op_str}' for item in instructions])
    return paths, infos, {'commands': commands_used, 'tool_outputs': tool_outputs, 'linked_files_unchanged': True,
                          'source_sha256': [digest(path.read_bytes()) for path in (MAIN_SOURCE, LIBRARY_SOURCE)],
                          'object_sha256': [digest(path.read_bytes()) for path in (main_object, lib_object)],
                          'image_sha256': [digest(blob) for blob in data], 'disassembly': disassembly,
                          'library_uuid_retained': True, 'exported_symbols': sorted(library_exports)}


def declined_inputs(inputs, infos):
    """Valid-but-unsupported and missing-provider cases; never execute their code."""
    main, library = inputs
    decoded = decode_fixups(main, infos[0], PLACEMENTS[0][0])
    meta = infos[0]['chained_payload']['offset']
    imports = meta + struct.unpack_from('<I', main, meta + 8)[0]
    function_index = next(index for index, item in enumerate(decoded['imports']) if item['name'] == '_bound_function')
    function_import = imports + 4 * function_index
    rows = [{'name': 'missing_declared_provider', 'main': main, 'library': None}]
    for name, ordinal in [('flat_lookup_ordinal', 0xfe), ('wrong_positive_library_ordinal', 2)]:
        changed = bytearray(main)
        word = struct.unpack_from('<I', changed, function_import)[0]
        struct.pack_into('<I', changed, function_import, (word & ~0xff) | ordinal)
        rows.append({'name': name, 'main': bytes(changed), 'library': library})
    changed = bytearray(library)
    for offset, command, body in commands(library):
        if command == 0xd:
            start = offset + struct.unpack_from('<I', body, 8)[0]
            changed[start + len(INSTALL_NAME) - 1] = ord('X')
            break
    rows.append({'name': 'mismatched_provider_install_name', 'main': main, 'library': bytes(changed)})
    changed = bytearray(library)
    trie = infos[1]['exports_payload']
    position = library.find(b'function\0', trie['offset'], trie['offset'] + trie['bytes'])
    require(position >= 0, 'function export edge changed')
    changed[position + len('function') - 1] = ord('X')
    rows.append({'name': 'missing_trie_export_with_original_symtab', 'main': main, 'library': bytes(changed)})
    terminals = {}
    exports(library, infos[1], terminals)
    function_terminal = terminals['_bound_function']
    require(function_terminal['bytes'] == 3, 'function terminal changed; review reexport fixture')
    changed = bytearray(library)
    offset = function_terminal['offset']
    changed[offset:offset + 3] = bytes((8, 1, 0))  # Valid reexport: ordinal1, same symbol name.
    rows.append({'name': 'unsupported_regular_symbol_reexport', 'main': main, 'library': bytes(changed)})
    changed = bytearray(main)
    starts = meta + struct.unpack_from('<I', main, meta + 4)[0]
    offsets = struct.unpack_from(f"<{len(infos[0]['segments'])}I", main, starts + 4)
    node = starts + next(offset for offset in offsets if offset)
    struct.pack_into('<H', changed, node + 6, 9)
    slot = decoded['binds'][0]['file_offset']
    raw = decoded['binds'][0]['raw'] | (1 << 63) | (1 << 62)
    struct.pack_into('<Q', changed, slot, raw)
    rows.append({'name': 'unsupported_authenticated_bind', 'main': bytes(changed), 'library': library})
    return rows


def validate_regions(native, infos, bases):
    require(native['host_execute'] is False, 'guest bytes must remain nonexecutable on host')
    regions = {region['guest_address']: region for region in native['memory_regions']}
    for index, (info, base) in enumerate(zip(infos, bases)):
        for segment in info['segments']:
            if not segment['protection']:
                continue
            address = base + segment['address'] - info['preferred_base']
            region = regions[address]
            expected = (bool(segment['protection'] & 1), bool(segment['protection'] & 2) and not bool(segment['flags'] & 0x10), bool(segment['protection'] & 4))
            require((region['readable'], region['writable'], region['executable']) == expected and region['virtual_bytes'] == segment['bytes'], 'cross-image mapped permissions/extent mismatch')


def invoke(cli, *arguments):
    result = subprocess.run([str(cli), *map(str, arguments)], capture_output=True, text=True)
    require(result.returncode == 0, f'CLI failed ({result.returncode}): {result.stderr.strip()}')
    return json.loads(result.stdout)


def retain_fixtures(directory, inputs):
    """Keep the verified pair by content identity, without replacing older pairs."""
    require(len(inputs) == 2, 'retained fixture requires exactly main and dylib')
    hashes = [digest(data) for data in inputs]
    destination = directory.resolve() / digest(''.join(hashes).encode('ascii'))
    destination.mkdir(parents=True, exist_ok=True)
    result = {'directory': str(destination), 'image_sha256': hashes}
    for name, filename, data in zip(('main', 'library'), ('main', 'libstela-fixture.dylib'), inputs):
        path = destination / filename
        try:
            with path.open('xb') as stream:
                stream.write(data)
        except FileExistsError:
            pass
        require(path.read_bytes() == data, 'retained fixture identity mismatch: ' + str(path))
        result[name] = str(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/bound-image-differential.json')
    parser.add_argument('--retain-fixtures', type=Path,
                        help='retain the verified pair in a content-addressed subdirectory for release benchmarks')
    arguments = parser.parse_args()
    require(platform.machine() == 'x86_64', 'native differential requires x86_64')
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    cli_hash = digest(arguments.cli.read_bytes())
    source_paths = [Path(__file__), MAIN_SOURCE, LIBRARY_SOURCE, ROOT / 'dev/chained-image-differential.py',
                    ROOT / 'dev/mapped-image-differential.py', ROOT / 'dev/differential.py', ROOT / 'dev/evidence.py',
                    ROOT / 'src/main.rs', ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'crates/stela-runtime/Cargo.toml']
    source_paths.extend(sorted((ROOT / 'src/macho').rglob('*.rs')))
    source_paths.extend(sorted((ROOT / 'crates/stela-runtime/src').rglob('*.rs')))
    hashes = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_paths}
    with tempfile.TemporaryDirectory(prefix='bound-image-', dir=arguments.output.parent) as temporary:
        work = Path(temporary)
        paths, infos, provenance = build_fixtures(work)
        inputs = [path.read_bytes() for path in paths]
        library_exports = exports(inputs[1], infos[1])
        declines = []
        for declined in declined_inputs(inputs, infos):
            bad_main, bad_library = work / (declined['name'] + '-main'), work / (declined['name'] + '.dylib')
            bad_main.write_bytes(declined['main'])
            parameters = ['run-linked-images', bad_main, '--architecture', 'arm64', '--image-base', hex(PLACEMENTS[0][0]),
                          '--stack-base', hex(STACK_BASE), '--block-budget', '0', '--cache-dir', work / 'declined-cache']
            if declined['library'] is not None:
                bad_library.write_bytes(declined['library'])
                parameters.extend(['--library', f'{bad_library}@{PLACEMENTS[0][1]:#x}'])
            completed = subprocess.run([str(arguments.cli), *map(str, parameters)], capture_output=True, text=True)
            require(completed.returncode != 0 and completed.stderr, 'unsupported linked profile accepted: ' + declined['name'])
            declines.append({'name': declined['name'], 'main_sha256': digest(declined['main']),
                             'library_sha256': digest(declined['library']) if declined['library'] is not None else None,
                             'returncode': completed.returncode, 'stderr': completed.stderr.strip(), 'block_budget': 0})
        rows = []
        for bases in PLACEMENTS:
            decoded = [decode_fixups(data, info, base) for data, info, base in zip(inputs, infos, bases)]
            bindings = resolve_bindings(infos[0], infos[1], decoded[0], library_exports, bases[1])
            for index, initial in enumerate(states(all_flags=True)):
                initial.sp, initial.x[30], initial.reserved = STACK_TOP, STOP, 0xa5c39e71
                expected, pc, memory, trace = original(inputs, infos, initial, bases, decoded, bindings)
                require((expected, pc, memory) == fixture_oracle(inputs, infos, initial, bases), 'original ARM differs from independent symbol oracle')
                state_path = work / 'state.json'
                state_path.write_text(json.dumps(snapshot(initial)) + '\n')
                parameters = ['run-linked-images', paths[0], '--architecture', 'arm64', '--image-base', hex(bases[0]),
                              '--library', f'{paths[1]}@{bases[1]:#x}', '--stack-base', hex(STACK_BASE),
                              '--state', state_path, '--stop-pc', hex(STOP), '--block-budget', '8', '--cache-dir', work / 'shared-cache']
                for region in memory:
                    parameters.extend(['--read-memory', f"{region['address']:#x}:{len(region['bytes_hex']) // 2}"])
                native = invoke(arguments.cli, *parameters)
                require(native['complete_binary_verified'] is False, 'cross-image entry does not prove full process execution')
                require(native['mapped_entry'] == bases[0] + infos[0]['entry_offset'], 'wrong cross-image entry address')
                require(native['initial_state'] == snapshot(initial) and native['state'] == expected and native['pc'] == pc, 'native cross-image state differs')
                require(native['memory'] == memory, 'native cross-image DATA_CONST/DATA/stack differs')
                require(native['outcome']['reason'] == {'kind': 'stop_address'} and native['outcome']['last_exit'] == [STOP, 4]
                        and native['outcome']['blocks_executed'] == 3, 'cross-image BLR/RET was not exercised')
                require(native['outcome']['compiled_blocks'] == (3 if index == 0 else 0) and native['outcome']['disk_cache_hits'] == (0 if index == 0 else 3), 'cache reused blocks across incompatible guest placements')
                require(len(native['images']) == 2, 'unexpected mapped image set')
                for image_index, receipt in enumerate(native['images']):
                    require(receipt['index'] == image_index and receipt['container_sha256'] == digest(inputs[image_index]) and receipt['slice_offset'] == 0,
                            'image receipt/input identity mismatch')
                    require(receipt['load_base'] == bases[image_index] and receipt['fixups'] == decoded[image_index], 'image fixup receipt differs from independent decoder')
                    info, blob = infos[image_index], inputs[image_index]
                    require(receipt['plan']['file_type'] == info['kind'] and receipt['plan']['slice_sha256'] == digest(blob)
                            and receipt['plan']['slice_bytes'] == len(blob), 'image plan/type/slice identity mismatch')
                    require(receipt['plan']['execution_supported'] is False and receipt['plan']['unresolved_requirements'], 'image plan must retain unresolved process requirements')
                    require([item['name'] for item in receipt['plan']['dependencies']] == info['dependencies'], 'declared dependency order changed')
                    if image_index == 1:
                        require(receipt['plan']['entry'] is None and receipt['plan']['dylib_identity']['name'] == INSTALL_NAME, 'dylib identity or no-entry convention changed')
                    expected_exports = {name: {'flags': item['flags'], 'value': item['value'], 'address': bases[image_index] + item['value']}
                                        for name, item in exports(blob, info).items()}
                    actual_exports = {item['name']: {key: item[key] for key in ('flags', 'value', 'address')} for item in receipt['exports']}
                    require(actual_exports == expected_exports and len(actual_exports) == len(receipt['exports']), 'native exports trie receipt differs from independent decoder')
                    require(receipt['applied_rebases'] == len(decoded[image_index]['rebases']) and receipt['applied_binds'] == len(decoded[image_index]['binds']), 'image applied fixup counts differ')
                    require(receipt['bindings'] == (bindings if image_index == 0 else []), 'declared dylib symbol resolution differs from independent resolver')
                validate_regions(native, infos, bases)
                rows.append({'bases': list(bases), 'initial': snapshot(initial), 'original_state': expected, 'original_pc': pc,
                             'original_trace': trace, 'original_memory_sha256': [digest(bytes.fromhex(region['bytes_hex'])) for region in memory], 'native': native})
        require([path.read_bytes() for path in paths] == inputs, 'execution altered original linked files')
        require(cli_hash == digest(arguments.cli.read_bytes()), 'CLI changed during linked-image probes')
        require(hashes == {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_paths}, 'harness/runtime source changed during linked-image probes')
        report = {'kind': 'own_bound_macho_cross_image_differential', 'schema_version': 1, 'passed': True,
                  'complete_binary_verified': False, 'complete_binaries_verified': 0, 'full_state_comparisons': len(rows),
                  'compiler_source_sha256': rows[0]['native']['compiler_source_sha256'], 'cli_sha256': cli_hash,
                  'harness_source_sha256': digest(Path(__file__).read_bytes()), 'source_sha256': hashes,
                  'fixture': provenance, 'layouts': infos, 'placements': [list(bases) for bases in PLACEMENTS],
                  'library_exports': library_exports, 'declined_inputs_before_execution': declines, 'comparisons': rows, 'mapped_data_bytes_per_comparison': 131072,
                  'stack_frame_bytes_per_comparison': 16,
                  'tested_state': ['all 31 GPRs, SP, NZCV, reserved', 'cross-image BLR/RET PC', 'two genuine chained binds',
                                   'one genuine library BSS rebase', 'both images complete DATA_CONST/DATA/BSS', 'FP/LR stack frame', 'two placements and address-bound disk caches'],
                  'limits': 'Own unchanged Apple-linked main and companion dylib under supplied research entry ABI. Positive library ordinal and regular nonweak exports only. No full dependency discovery, initializers, reexports, flat/weak lookup, PAC, system calls or macOS process launch.'}
        report['retained_fixtures'] = retain_fixtures(arguments.retain_fixtures, inputs) if arguments.retain_fixtures else None
        archive = write_evidence(arguments.output, report)
    print(json.dumps({'passed': True, 'full_state_comparisons': len(rows), 'placements': [[hex(base) for base in bases] for bases in PLACEMENTS],
                      'bound_symbols': sorted(library_exports), 'declined_inputs': len(declines), 'complete_binaries_verified': 0,
                      'report': str(arguments.output), 'snapshot': str(archive),
                      'retained_fixtures': report['retained_fixtures']}, indent=2))


if __name__ == '__main__':
    main()
