#!/usr/bin/env python3
"""Genuine requester/load-chain rpaths and three-image native entry execution.

Apple-linked files remain unchanged. Their actual dependency graph is discovered
inside an explicit guest root; declared unused libSystem dependencies remain
unresolved. Native entry research explicitly opts in to that incomplete graph,
while all actual chained binds must resolve to discovered guest code/data.
"""
import argparse
import importlib
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm
from differential import capture_arm, initialize_arm, state_dict as complete_state
from differential import ROOT, ARM_REGISTERS, MASK, states
from evidence import write_evidence

bound = importlib.import_module('bound-image-differential')
require, digest, snapshot = bound.require, bound.digest, bound.snapshot
PAGE, SEED, STOP = bound.PAGE, bound.SEED, bound.STOP
STACK_BASE, STACK_BYTES = 0xa0000000000, 65536
STACK_TOP = STACK_BASE + STACK_BYTES
PLACEMENTS = ((0x40000000000, 0x50000000000, 0x60000000000),
              (0x70000000000, 0x80000000000, 0x90000000000))
STRIDE = 0x10000000000
GUEST_PATHS = ('/app/bin/main', '/app/Frameworks/libmiddle-fixture.dylib',
               '/app/Frameworks/private/libleaf-fixture.dylib')
IDS = (None, '@rpath/libmiddle-fixture.dylib', '@rpath/libleaf-fixture.dylib')
SOURCES = (ROOT / 'tests/fixtures/bound-image-arm64.S',
           ROOT / 'tests/fixtures/dependency-middle-arm64.S', ROOT / 'tests/fixtures/dependency-leaf-arm64.S')


def parse_image(data):
    info = {'kind': struct.unpack_from('<I', data, 12)[0], 'segments': [], 'sections': {}, 'symbols': {},
            'dependencies': [], 'rpaths': [], 'install_name': None, 'entry_offset': None}
    table = None
    for offset, command, body in bound.commands(data):
        if command == 0x19:
            require(len(body) >= 72, 'truncated segment')
            _, _, name, address, size, fileoff, filesize, maximum, protection, count, flags = struct.unpack_from('<II16sQQQQIIII', body)
            require(len(body) == 72 + count * 80 and fileoff + filesize <= len(data) and filesize <= size, 'invalid segment extent')
            require(address % PAGE == 0 and size % PAGE == 0, 'expected 16-KiB segment pages')
            info['segments'].append({'name': name.rstrip(b'\0').decode(), 'address': address, 'bytes': size,
                                     'file_offset': fileoff, 'file_bytes': filesize, 'maximum_protection': maximum,
                                     'protection': protection, 'flags': flags})
            for index in range(count):
                item = struct.unpack_from('<16s16sQQIIIIIIII', body, 72 + index * 80)
                require(item[6] == item[7] == 0, 'unexpected section relocations')
                info['sections'][item[0].rstrip(b'\0').decode()] = {'address': item[2], 'bytes': item[3], 'file_offset': item[4]}
        elif command == 2:
            require(len(body) == 24 and table is None, 'invalid symbol table')
            table = struct.unpack_from('<6I', body)[2:]
        elif command in (0x80000034, 0x80000033):
            fileoff, size = struct.unpack_from('<II', body, 8)
            require(fileoff + size <= len(data), 'payload exceeds file')
            info['chained_payload' if command == 0x80000034 else 'exports_payload'] = {'offset': fileoff, 'bytes': size}
        elif command == 0xc:
            info['dependencies'].append(bound.command_string(body))
        elif command == 0xd:
            require(info['install_name'] is None, 'duplicate install name')
            info['install_name'] = bound.command_string(body)
        elif command == 0x8000001c:
            info['rpaths'].append(bound.command_string(body))
        elif command == 0x80000028:
            require(info['entry_offset'] is None and len(body) == 24, 'invalid LC_MAIN')
            info['entry_offset'] = struct.unpack_from('<Q', body, 8)[0]
        else:
            require(command in (0xb, 0xe, 0x1b, 0x32, 0x2a, 0x26, 0x29), f'unexpected command {command:#x}')
    require(table is not None and 'chained_payload' in info and 'exports_payload' in info, 'missing image metadata')
    symoff, count, stroff, strsize = table
    require(symoff + count * 16 <= len(data) and stroff + strsize <= len(data), 'invalid symbol/string table')
    strings = data[stroff:stroff + strsize]
    for index in range(count):
        string, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', data, symoff + index * 16)
        require(string < len(strings) and b'\0' in strings[string:], 'invalid symbol name')
        info['symbols'][strings[string:].split(b'\0', 1)[0].decode()] = value
    info['preferred_base'] = next(segment['address'] for segment in info['segments'] if segment['name'] == '__TEXT')
    require(info['kind'] != 2 or info['preferred_base'] + info['entry_offset'] == info['symbols']['_bound_entry'], 'entry/symbol mismatch')
    return info


def resolve_all(infos, decoded, exported, bases):
    ids = {info['install_name']: index for index, info in enumerate(infos) if info['install_name']}
    all_bindings = []
    for info, fixups in zip(infos, decoded):
        rows = []
        for bind in fixups['binds']:
            imported = fixups['imports'][bind['import_index']]
            ordinal = imported['library_ordinal']
            require(ordinal > 0 and ordinal <= len(info['dependencies']) and not imported['weak'], 'unsupported import ordinal/weak profile')
            identity = info['dependencies'][ordinal - 1]
            require(identity in ids, 'missing declared guest provider')
            provider = ids[identity]
            require(imported['name'] in exported[provider], 'missing declared guest export')
            address = bases[provider] + exported[provider][imported['name']]['value']
            rows.append({**{key: bind[key] for key in ('segment_index', 'file_offset', 'guest_address', 'raw', 'pointer_format', 'import_index')},
                         'library_ordinal': ordinal, 'name': imported['name'], 'provider_image': provider,
                         'address': address, 'addend': bind['addend'], 'value': address + bind['addend']})
        all_bindings.append(rows)
    return all_bindings


def oracle(inputs, infos, initial, bases):
    symbols = [{name: base + value - info['preferred_base'] for name, value in info['symbols'].items()} for info, base in zip(infos, bases)]
    main, middle, leaf = symbols
    first = (initial.x[0] + SEED) & MASK
    second, final = (first + 11) & MASK, (first + 24) & MASK
    expected = snapshot(initial)
    for register, value in {0: final, 1: SEED, 4: 0, 9: leaf['_leaf_pointers'], 10: leaf['_leaf_output'],
                            12: middle['_bound_function'], 13: middle['_bound_seed'], 14: main['_bound_output'],
                            15: middle['_middle_pointers'], 16: leaf['_leaf_function'], 17: middle['_middle_output'], 30: STOP}.items():
        expected['x'][register] = value
    memories = [bound.oracle_memory(data, info, base) for data, info, base in zip(inputs, infos, bases)]
    address, memory = memories[0]['__DATA_CONST']
    struct.pack_into('<QQ', memory, main['_bound_imports'] - address, middle['_bound_function'], middle['_bound_seed'])
    address, memory = memories[0]['__DATA']
    require(not any(memory[8:]), 'expected zero main BSS')
    struct.pack_into('<Q', memory, main['_bound_output'] - address, final)
    address, memory = memories[1]['__DATA_CONST']
    struct.pack_into('<QQ', memory, middle['_middle_pointers'] - address, leaf['_leaf_function'], middle['_middle_output'])
    address, memory = memories[1]['__DATA']
    require(not any(memory[8:]), 'expected zero middle BSS')
    struct.pack_into('<QQ', memory, middle['_middle_output'] - address, second, final)
    address, memory = memories[2]['__DATA_CONST']
    struct.pack_into('<Q', memory, leaf['_leaf_pointers'] - address, leaf['_leaf_output'])
    address, memory = memories[2]['__DATA']
    require(not any(memory[8:]), 'expected zero leaf BSS')
    struct.pack_into('<QQ', memory, leaf['_leaf_output'] - address, first, second)
    snapshots = [{'address': address, 'bytes_hex': data.hex()} for image in memories
                 for address, data in (image['__DATA_CONST'], image['__DATA'])]
    frames = struct.pack('<QQQQ', STACK_TOP - 16, bases[0] + infos[0]['entry_offset'] + 32, initial.x[29], STOP)
    snapshots.append({'address': STACK_TOP - 32, 'bytes_hex': frames.hex()})
    return expected, STOP, snapshots


def original(inputs, infos, initial, bases, decoded, bindings):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for data, info, base, fixups, resolved in zip(inputs, infos, bases, decoded, bindings):
        memories = bound.reference_memories(data, info, fixups, resolved)
        for segment in info['segments']:
            if not segment['protection']:
                continue
            address = base + segment['address'] - info['preferred_base']
            machine.mem_map(address, segment['bytes'])
            machine.mem_write(address, bytes(memories[address]))
            protection = segment['protection'] & ~2 if segment['flags'] & 0x10 else segment['protection']
            machine.mem_protect(address, segment['bytes'], protection)
    machine.mem_map(STACK_BASE, STACK_BYTES, 3)
    initialize_arm(machine, initial)
    ranges = [(base + info['sections']['__text']['address'] - info['preferred_base'], info['sections']['__text']['bytes']) for info, base in zip(infos, bases)]
    trace = []
    def guard(machine, address, size, _):
        require(size == 4 and any(start <= address < start + length for start, length in ranges), 'original left reviewed image text')
        trace.append(address)
    machine.hook_add(UC_HOOK_CODE, guard)
    machine.emu_start(bases[0] + infos[0]['entry_offset'], STOP, count=128)
    pc = machine.reg_read(arm.UC_ARM64_REG_PC)
    require(pc == STOP and len(trace) == 32, 'nested cross-image calls/returns did not reach stop')
    state = complete_state(capture_arm(machine, initial))
    snapshots = []
    for info, base in zip(infos, bases):
        for name in ('__DATA_CONST', '__DATA'):
            segment = next(segment for segment in info['segments'] if segment['name'] == name)
            address = base + segment['address'] - info['preferred_base']
            snapshots.append({'address': address, 'bytes_hex': bytes(machine.mem_read(address, segment['bytes'])).hex()})
    snapshots.append({'address': STACK_TOP - 32, 'bytes_hex': bytes(machine.mem_read(STACK_TOP - 32, 32)).hex()})
    return state, pc, snapshots, trace


def build_fixtures(work):
    require(platform.system() == 'Darwin', 'genuine fixture construction requires Apple clang/ld')
    guest_root = work / 'guest'
    paths = [guest_root / path.lstrip('/') for path in GUEST_PATHS]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
    clang = subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip()
    linker = subprocess.check_output(['xcrun', '--find', 'ld'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    objects = [work / name for name in ('main.o', 'middle.o', 'leaf.o')]
    middle_exports, leaf_exports = work / 'middle-exports.txt', work / 'leaf-exports.txt'
    middle_exports.write_text('_bound_function\n_bound_seed\n')
    leaf_exports.write_text('_leaf_function\n')
    common = ['-arch', 'arm64', '-platform_version', 'macos', '14.0', '14.0']
    commands = [[clang, '-target', 'arm64-apple-macos14', '-c', str(source), '-o', str(obj)] for source, obj in zip(SOURCES, objects)]
    commands.extend([
        [linker, '-dylib', *common, '-install_name', IDS[2], '-exported_symbols_list', str(leaf_exports),
         '-o', str(paths[2]), str(objects[2]), '-syslibroot', sdk, '-lSystem', '-no_adhoc_codesign'],
        [linker, '-dylib', *common, '-install_name', IDS[1], '-exported_symbols_list', str(middle_exports),
         '-rpath', '@loader_path/private', '-o', str(paths[1]), str(objects[1]), str(paths[2]),
         '-syslibroot', sdk, '-lSystem', '-no_adhoc_codesign'],
        [linker, *common, '-e', '_bound_entry', '-rpath', '@executable_path/../Frameworks', '-o', str(paths[0]),
         str(objects[0]), str(paths[1]), '-syslibroot', sdk, '-lSystem', '-no_uuid', '-no_adhoc_codesign'],
    ])
    outputs = []
    no_system_probe = None
    for index, command in enumerate(commands):
        if index == 3:
            attempted = [linker, '-dylib', *common, '-install_name', IDS[2], '-exported_symbols_list', str(leaf_exports),
                         '-o', str(work / 'leaf-without-libSystem.dylib'), str(objects[2]), '-no_adhoc_codesign']
            trial = subprocess.run(attempted, capture_output=True, text=True)
            require(trial.returncode != 0 and 'libSystem.dylib' in trial.stderr, 'Apple linker no-libSystem behavior changed; review fixture dependencies')
            no_system_probe = {'command': attempted, 'returncode': trial.returncode, 'stdout': trial.stdout, 'stderr': trial.stderr}
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        outputs.append({'stdout': completed.stdout, 'stderr': completed.stderr})
    inputs = [path.read_bytes() for path in paths]
    infos = [parse_image(data) for data in inputs]
    require([info['install_name'] for info in infos] == list(IDS), 'genuine install names changed')
    require(infos[0]['rpaths'] == ['@executable_path/../Frameworks'] and infos[1]['rpaths'] == ['@loader_path/private'], 'genuine rpath profile changed')
    require([info['dependencies'] for info in infos] == [[IDS[1], '/usr/lib/libSystem.B.dylib'],
                                                         [IDS[2], '/usr/lib/libSystem.B.dylib'], ['/usr/lib/libSystem.B.dylib']], 'genuine dependency ordinals changed')
    exports = [bound.exports(data, info) for data, info in zip(inputs, infos)]
    require(set(exports[1]) == {'_bound_function', '_bound_seed'} and set(exports[2]) == {'_leaf_function'}, 'genuine exported symbol sets changed')
    decoded = [bound.decode_fixups(data, info, base) for data, info, base in zip(inputs, infos, PLACEMENTS[0])]
    require([len(item['binds']) for item in decoded] == [2, 1, 0] and [len(item['rebases']) for item in decoded] == [0, 1, 1], 'genuine fixup counts changed')
    expected = [['stp', 'mov', 'adrp', 'add', 'ldp', 'ldr', 'add', 'blr', 'adrp', 'add', 'str', 'ldp', 'ret'],
                ['stp', 'mov', 'adrp', 'add', 'ldp', 'blr', 'str', 'add', 'str', 'ldp', 'ret'],
                ['adrp', 'add', 'ldr', 'ldr', 'str', 'add', 'str', 'ret']]
    disassembly = []
    for data, info, names in zip(inputs, infos, expected):
        section = info['sections']['__text']
        code = data[section['file_offset']:section['file_offset'] + section['bytes']]
        instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, section['address']))
        require(len(code) == 4 * len(names) and [item.mnemonic for item in instructions] == names, 'review fixture code changes before native execution')
        disassembly.append([f'{item.address:#x}: {item.mnemonic} {item.op_str}' for item in instructions])
    # Same valid leaf is also available on the ancestor's rpath. The graph must
    # nevertheless choose the requester's @loader_path/private candidate first.
    decoy = guest_root / 'app/Frameworks/libleaf-fixture.dylib'
    decoy.write_bytes(inputs[2])
    return guest_root, paths, infos, {'commands': commands, 'tool_outputs': outputs, 'linked_files_unchanged': True,
                                     'image_sha256': [digest(data) for data in inputs],
                                     'source_sha256': [digest(path.read_bytes()) for path in SOURCES],
                                     'disassembly': disassembly, 'ancestor_rpath_decoy_guest_path': '/app/Frameworks/libleaf-fixture.dylib',
                                     'unused_system_dependency': '/usr/lib/libSystem.B.dylib', 'link_without_libSystem_probe': no_system_probe}


def build_traversal_fixture(work):
    """Genuine read-only diamond whose shared X depends on load-chain-rpathed Y."""
    root = work / 'traversal-guest'
    guests = {'main': '/branch/bin/main', 'A': '/branch/A/libA.dylib', 'B': '/branch/B/libB.dylib',
              'C': '/branch/shared/libC.dylib', 'X': '/branch/shared/libX.dylib',
              'YA': '/branch/A/y/libY.dylib', 'YB': '/branch/B/y/libY.dylib'}
    paths = {name: root / guest.lstrip('/') for name, guest in guests.items()}
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    linker = subprocess.check_output(['xcrun', '--find', 'ld'], text=True).strip()
    sdk = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
    common = ['-arch', 'arm64', '-platform_version', 'macos', '14.0', '14.0']
    commands = []
    for name, dependencies in [('YA', []), ('YB', []), ('X', ['YA']), ('C', ['X']), ('B', ['X'])]:
        identity = '@rpath/libY.dylib' if name in ('YA', 'YB') else guests[name]
        command = [linker, '-dylib', *common, '-install_name', identity,
                   '-exported_symbols_list', str(work / 'leaf-exports.txt'), '-o', str(paths[name]), str(work / 'leaf.o')]
        if name == 'B':
            command.extend(['-rpath', '@loader_path/y'])
        for dependency in dependencies:
            command.extend(['-needed_library', str(paths[dependency])])
        command.extend(['-syslibroot', sdk, '-lSystem', '-no_adhoc_codesign'])
        commands.append(command)
    commands.append([linker, '-dylib', *common, '-install_name', guests['A'], '-rpath', '@loader_path/y',
                     '-exported_symbols_list', str(work / 'middle-exports.txt'), '-o', str(paths['A']),
                     str(work / 'middle.o'), str(paths['C']), '-syslibroot', sdk, '-lSystem', '-no_adhoc_codesign'])
    commands.append([linker, *common, '-e', '_bound_entry', '-o', str(paths['main']), str(work / 'main.o'),
                     str(paths['A']), '-needed_library', str(paths['B']), '-syslibroot', sdk, '-lSystem',
                     '-no_uuid', '-no_adhoc_codesign'])
    outputs = []
    for command in commands:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        outputs.append({'stdout': result.stdout, 'stderr': result.stderr})
    infos = {name: parse_image(path.read_bytes()) for name, path in paths.items()}
    expected = {'main': [guests['A'], guests['B']], 'A': [guests['C']], 'B': [guests['X']],
                'C': [guests['X']], 'X': ['@rpath/libY.dylib'], 'YA': [], 'YB': []}
    for name, dependencies in expected.items():
        require(infos[name]['dependencies'] == dependencies + ['/usr/lib/libSystem.B.dylib'],
                'genuine traversal dependency order changed: ' + name)
    require(infos['A']['rpaths'] == infos['B']['rpaths'] == ['@loader_path/y'], 'genuine traversal rpaths changed')
    return root, paths, {'commands': commands, 'tool_outputs': outputs, 'guest_paths': guests,
                         'image_sha256': {name: digest(path.read_bytes()) for name, path in paths.items()},
                         'declared_dependencies': {name: info['dependencies'] for name, info in infos.items()},
                         'linked_files_unchanged': True}


def validate_graph(graph, paths, infos, bases):
    require(graph['complete_dependency_graph'] is False and graph['unresolved_dependencies'] == 3, 'unused declared system dependencies must remain explicit')
    require(len(graph['images']) == 3 and len(graph['edges']) == 5, 'unexpected discovered graph size')
    for index, image in enumerate(graph['images']):
        require(image['index'] == index and image['guest_path'] == GUEST_PATHS[index]
                and Path(image['host_path']).resolve() == paths[index].resolve() and image['load_base'] == bases[index], 'discovered image path/order/placement differs')
        require(image['container_sha256'] == digest(paths[index].read_bytes()), 'discovered input identity differs')
        require(image['plan']['rpaths'] == infos[index]['rpaths'], 'discovery changed actual LC_RPATH metadata')
    for requester, ordinal, name, provider in [(0, 1, IDS[1], 1), (1, 1, IDS[2], 2)]:
        edge = next(edge for edge in graph['edges'] if edge['requester'] == requester and edge['ordinal'] == ordinal)
        require(edge['name'] == name and edge['provider'] == provider and edge['candidates'][0]['guest_path'] == GUEST_PATHS[provider], 'requester rpath selection/ordinal differs')
    for edge in graph['edges']:
        if edge['name'] == '/usr/lib/libSystem.B.dylib':
            require(edge['provider'] is None, 'missing guest system library must not use a host fallback')


def invoke(cli, *arguments):
    result = subprocess.run([str(cli), *map(str, arguments)], capture_output=True, text=True)
    require(result.returncode == 0, f'CLI failed ({result.returncode}): {result.stderr.strip()}')
    return json.loads(result.stdout)


def guest_arguments(guest_root, bases):
    return ['--guest-root', guest_root, '--guest-path', GUEST_PATHS[0], '--architecture', 'arm64',
            '--image-base', hex(bases[0]), '--library-base', hex(bases[1]), '--library-stride', hex(STRIDE)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/dependency-image-differential.json')
    arguments = parser.parse_args()
    require(platform.machine() == 'x86_64', 'native differential requires x86_64')
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    cli_hash = digest(arguments.cli.read_bytes())
    source_paths = [Path(__file__), *SOURCES, ROOT / 'dev/bound-image-differential.py', ROOT / 'dev/chained-image-differential.py',
                    ROOT / 'dev/mapped-image-differential.py', ROOT / 'dev/differential.py', ROOT / 'dev/evidence.py',
                    ROOT / 'src/main.rs', ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', ROOT / 'crates/stela-runtime/Cargo.toml']
    source_paths.extend(sorted((ROOT / 'src/macho').rglob('*.rs')))
    source_paths.extend(sorted((ROOT / 'crates/stela-runtime/src').rglob('*.rs')))
    hashes = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_paths}
    with tempfile.TemporaryDirectory(prefix='dependency-image-', dir=arguments.output.parent) as temporary:
        work = Path(temporary)
        guest_root, paths, infos, provenance = build_fixtures(work)
        inputs = [path.read_bytes() for path in paths]
        traversal_root, traversal_paths, traversal_provenance = build_traversal_fixture(work)
        traversal = invoke(arguments.cli, 'discover-images', traversal_paths['main'], '--guest-root', traversal_root,
                           '--guest-path', '/branch/bin/main', '--architecture', 'arm64', '--image-base', hex(PLACEMENTS[0][0]),
                           '--library-base', hex(PLACEMENTS[0][1]), '--library-stride', hex(STRIDE))
        branch_images = traversal['graph']['images']
        x_index = next(image['index'] for image in branch_images if image['guest_path'] == '/branch/shared/libX.dylib')
        x_to_y = next(edge for edge in traversal['graph']['edges'] if edge['requester'] == x_index and edge['name'] == '@rpath/libY.dylib')
        require(x_to_y['provider'] is not None and branch_images[x_to_y['provider']]['guest_path'] == '/branch/A/y/libY.dylib',
                'shared X used breadth-first B ancestry instead of first depth-first C/A load chain')
        require(x_to_y['candidates'][0]['guest_path'] == '/branch/A/y/libY.dylib' and
                all(image['guest_path'] != '/branch/B/y/libY.dylib' for image in branch_images), 'wrong first-load runpath context for shared X')
        exported = [bound.exports(data, info) for data, info in zip(inputs, infos)]
        declines = []
        # Without the explicit incomplete-graph opt-in, even unused declared
        # system dependencies must prevent execution of this entry research ABI.
        completed = subprocess.run([str(arguments.cli), 'run-linked-images', str(paths[0]),
                                    *map(str, guest_arguments(guest_root, PLACEMENTS[0])),
                                    '--stack-base', hex(STACK_BASE), '--block-budget', '0'], capture_output=True, text=True)
        require(completed.returncode != 0 and completed.stderr, 'incomplete dependency graph was accepted without explicit opt-in')
        declines.append({'name': 'incomplete_graph_without_entry_opt_in', 'returncode': completed.returncode, 'stderr': completed.stderr.strip(), 'block_budget': 0})
        fallback_root = work / 'ancestor-fallback'
        shutil.copytree(guest_root, fallback_root)
        (fallback_root / GUEST_PATHS[2].lstrip('/')).unlink()
        fallback_main = fallback_root / GUEST_PATHS[0].lstrip('/')
        fallback = invoke(arguments.cli, 'discover-images', fallback_main, *guest_arguments(fallback_root, PLACEMENTS[0]))
        fallback_edge = next(edge for edge in fallback['graph']['edges'] if edge['requester'] == 1 and edge['ordinal'] == 1)
        require(fallback_edge['provider'] == 2 and fallback['graph']['images'][2]['guest_path'] == '/app/Frameworks/libleaf-fixture.dylib',
                'missing requester candidate did not fall back to ancestor runpath')
        require([candidate['guest_path'] for candidate in fallback_edge['candidates']][:2] ==
                [GUEST_PATHS[2], '/app/Frameworks/libleaf-fixture.dylib'], 'load-chain candidate order differs')
        missing_root = work / 'missing-used-provider'
        shutil.copytree(guest_root, missing_root)
        for name in ('app/Frameworks/private/libleaf-fixture.dylib', 'app/Frameworks/libleaf-fixture.dylib'):
            (missing_root / name).unlink()
        missing_main = missing_root / GUEST_PATHS[0].lstrip('/')
        missing = invoke(arguments.cli, 'discover-images', missing_main, *guest_arguments(missing_root, PLACEMENTS[0]))
        leaf_edge = next(edge for edge in missing['graph']['edges'] if edge['requester'] == 1 and edge['ordinal'] == 1)
        require(leaf_edge['provider'] is None, 'missing actual provider unexpectedly escaped the guest root')
        completed = subprocess.run([str(arguments.cli), 'run-linked-images', str(missing_main),
                                    *map(str, guest_arguments(missing_root, PLACEMENTS[0])), '--allow-unresolved-unused-dependencies',
                                    '--stack-base', hex(STACK_BASE), '--block-budget', '0'], capture_output=True, text=True)
        require(completed.returncode != 0 and completed.stderr, 'missing actual bind was accepted through unused-dependency opt-in')
        declines.append({'name': 'missing_used_leaf_no_host_fallback', 'discovery': missing, 'returncode': completed.returncode,
                         'stderr': completed.stderr.strip(), 'block_budget': 0})
        wrong_root = work / 'wrong-root'
        wrong_root.mkdir()
        completed = subprocess.run([str(arguments.cli), 'discover-images', str(paths[0]),
                                    *map(str, guest_arguments(wrong_root, PLACEMENTS[0]))], capture_output=True, text=True)
        require(completed.returncode != 0 and completed.stderr, 'main outside declared guest root was accepted')
        declines.append({'name': 'main_does_not_match_declared_guest_root', 'returncode': completed.returncode, 'stderr': completed.stderr.strip(), 'execution_command_used': False})
        rows, discoveries = [], []
        for bases in PLACEMENTS:
            discovered = invoke(arguments.cli, 'discover-images', paths[0], *guest_arguments(guest_root, bases))
            validate_graph(discovered['graph'], paths, infos, bases)
            require(discovered['complete_binary_verified'] is False, 'discovery must not imply binary execution')
            discoveries.append(discovered)
            decoded = [bound.decode_fixups(data, info, base) for data, info, base in zip(inputs, infos, bases)]
            bindings = resolve_all(infos, decoded, exported, bases)
            for index, initial in enumerate(states(all_flags=True)):
                initial.sp, initial.x[30], initial.reserved = STACK_TOP, STOP, 0xa5c39e71
                expected, pc, memory, trace = original(inputs, infos, initial, bases, decoded, bindings)
                require((expected, pc, memory) == oracle(inputs, infos, initial, bases), 'original ARM differs from independent three-image symbol oracle')
                state_path = work / 'state.json'
                state_path.write_text(json.dumps(snapshot(initial)) + '\n')
                parameters = ['run-linked-images', paths[0], *guest_arguments(guest_root, bases),
                              '--allow-unresolved-unused-dependencies', '--stack-base', hex(STACK_BASE), '--state', state_path,
                              '--stop-pc', hex(STOP), '--block-budget', '8', '--cache-dir', work / 'shared-cache']
                for region in memory:
                    parameters.extend(['--read-memory', f"{region['address']:#x}:{len(region['bytes_hex']) // 2}"])
                native = invoke(arguments.cli, *parameters)
                require(native['dependency_graph'] == discovered['graph'] and native['unresolved_unused_dependencies_allowed'] is True, 'execution changed explicit dependency graph/profile')
                require(native['complete_binary_verified'] is False and native['host_execute'] is False, 'invalid full compatibility or host execute claim')
                require(native['mapped_entry'] == bases[0] + infos[0]['entry_offset'] and native['initial_state'] == snapshot(initial), 'wrong actual guest entry/state')
                require(native['state'] == expected and native['pc'] == pc and native['memory'] == memory, 'native three-image state/data/stack differs')
                require(native['outcome']['reason'] == {'kind': 'stop_address'} and native['outcome']['last_exit'] == [STOP, 4]
                        and native['outcome']['blocks_executed'] == 5, 'nested guest calls/returns not fully exercised')
                require(native['outcome']['compiled_blocks'] == (5 if index == 0 else 0)
                        and native['outcome']['disk_cache_hits'] == (0 if index == 0 else 5), 'disk cache did not bind discovered guest placements')
                require(len(native['images']) == 3, 'unexpected native discovered image set')
                for image_index, receipt in enumerate(native['images']):
                    require(receipt['index'] == image_index and receipt['container_sha256'] == digest(inputs[image_index])
                            and receipt['load_base'] == bases[image_index] and receipt['fixups'] == decoded[image_index], 'discovered native image/fixup identity differs')
                    require(receipt['bindings'] == bindings[image_index] and receipt['applied_binds'] == len(decoded[image_index]['binds'])
                            and receipt['applied_rebases'] == len(decoded[image_index]['rebases']), 'discovered positive-ordinal bindings differ')
                bound.validate_regions(native, infos, bases)
                rows.append({'bases': list(bases), 'initial': snapshot(initial), 'original_state': expected, 'original_pc': pc,
                             'original_trace': trace, 'original_memory_sha256': [digest(bytes.fromhex(region['bytes_hex'])) for region in memory], 'native': native})
        require([path.read_bytes() for path in paths] == inputs, 'execution changed original linked files')
        require({name: digest(path.read_bytes()) for name, path in traversal_paths.items()} == traversal_provenance['image_sha256'], 'discovery changed original traversal files')
        require(cli_hash == digest(arguments.cli.read_bytes()), 'CLI changed during dependency probes')
        require(hashes == {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in source_paths}, 'harness/runtime source changed during dependency probes')
        report = {'kind': 'own_guest_dependency_graph_native_differential', 'schema_version': 1, 'passed': True,
                  'complete_binary_verified': False, 'complete_binaries_verified': 0, 'full_state_comparisons': len(rows),
                  'compiler_source_sha256': rows[0]['native']['compiler_source_sha256'], 'cli_sha256': cli_hash,
                  'harness_source_sha256': digest(Path(__file__).read_bytes()), 'source_sha256': hashes,
                  'fixture': provenance, 'layouts': infos, 'placements': [list(bases) for bases in PLACEMENTS], 'discoveries': discoveries,
                  'traversal_load_chain_discovery': traversal, 'traversal_fixture': traversal_provenance,
                  'ancestor_runpath_fallback_discovery': fallback, 'declined_inputs_before_execution': declines, 'comparisons': rows, 'mapped_data_bytes_per_comparison': 196608,
                  'stack_frame_bytes_per_comparison': 32,
                  'tested_state': ['all 31 GPRs, SP/NZCV/reserved', 'three-image nested BLR/RET guest PCs', 'three chained binds and two rebases',
                                   'complete three-image DATA_CONST/DATA/BSS', 'two nested FP/LR stack frames',
                                   'requester LC_RPATH before ancestor decoy', 'guest-root path containment', 'explicit unresolved unused dependencies'],
                  'limits': 'Own unchanged Apple-linked main/middle/leaf under explicitly supplied entry ABI. All actual binds resolved; three genuine libSystem dependencies remain absent and explicitly permitted only for entry research. No full process ABI, initializers, shared cache, PAC, syscalls or macOS boot.'}
        archive = write_evidence(arguments.output, report)
    print(json.dumps({'passed': True, 'full_state_comparisons': len(rows), 'discovered_images': 3, 'unresolved_unused_dependencies': 3,
                      'declined_inputs': len(declines), 'complete_binaries_verified': 0,
                      'report': str(arguments.output), 'snapshot': str(archive)}, indent=2))


if __name__ == '__main__':
    main()
