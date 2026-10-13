#!/usr/bin/env python3
"""Pinned original dyld entry prefix versus native shared BlockRuntime.

The complete original file-backed __TEXT is registered unchanged. Only the
reviewed five-instruction prefix executes; the next PACIBSP must decline.
This tests neither dyld initialization nor process launch or PAC behavior.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm

from differential import ROOT, State, states, state_dict, initialize_arm, capture_arm, seed_extended_state
from evidence import write_evidence

DEFAULT_DYLD = ROOT / '.stela/26A434/userspace-os/files/usr/lib/dyld'
CONTAINER_SHA256 = 'be8904b70f95adeb9d244308ca470f939bb89bd32a9b1b05e3f65ac92579e226'
SLICE_SHA256 = '5ef43084763a8fb5c272e78e90a0c14728d8434bc3fc584d65b7f0a2f6e32b1f'
SLICE_OFFSET, SLICE_BYTES = 1179648, 1475728
ENTRY, TARGET = 0x4bf0, 0x30460
PREFIX_WORDS = (0x910003e0, 0x927cec1f, 0xd280001d, 0xd280001e, 0x1400ae18)
PACIBSP = 0xd503237f
ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
MAX_INPUT = 16 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def classic_slice(container):
    """Independent FAT32/FAT64 selection; never select arm64e.x1 as classic."""
    require(32 <= len(container) <= MAX_INPUT, 'dyld input size outside research bound')
    if container[:4] == b'\xcf\xfa\xed\xfe':
        return 0, container
    require(container[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'), 'unsupported dyld container magic')
    count = struct.unpack_from('>I', container, 4)[0]
    stride = 32 if container[:4] == b'\xca\xfe\xba\xbf' else 20
    require(0 < count <= 64 and 8 + count * stride <= len(container), 'invalid fat table extent')
    matches, spans = [], []
    for index in range(count):
        offset = 8 + index * stride
        if stride == 32:
            cpu, subtype, start, size, alignment, reserved = struct.unpack_from('>IIQQII', container, offset)
            require(reserved == 0, 'nonzero FAT64 reserved field')
        else:
            cpu, subtype, start, size, alignment = struct.unpack_from('>IIIII', container, offset)
        require(size > 0 and start >= 8 + count * stride and start + size <= len(container), 'fat slice escapes container/table')
        require(alignment <= 31 and start % (1 << alignment) == 0, 'invalid fat slice alignment')
        require(all(start + size <= a or start >= b for a, b in spans), 'overlapping fat slices')
        spans.append((start, start + size))
        if cpu == 0x100000c and subtype & 0xffffff == 2:
            matches.append((start, container[start:start + size]))
    require(len(matches) == 1, 'expected one classic arm64e slice')
    return matches[0]


def parse_dyld(image):
    require(len(image) >= 32, 'truncated dyld header')
    magic, cpu, subtype, kind, count, command_bytes, _, reserved = struct.unpack_from('<8I', image)
    require(magic == 0xfeedfacf and cpu == 0x100000c and subtype & 0xffffff == 2 and kind == 7 and reserved == 0,
            'expected classic arm64e MH_DYLINKER')
    require(0 < count <= 4096 and 32 + command_bytes <= len(image), 'invalid load-command extent')
    end, position, texts, threads = 32 + command_bytes, 32, [], []
    for _ in range(count):
        require(position + 8 <= end, 'truncated load command')
        command, size = struct.unpack_from('<2I', image, position)
        require(size >= 8 and size % 8 == 0 and position + size <= end, 'invalid load-command bounds')
        if command == 0x19:
            require(size >= 72, 'truncated segment command')
            address, virtual, file_offset, file_bytes, maximum, initial, sections, _ = struct.unpack_from('<4Q4I', image, position + 24)
            require(size == 72 + sections * 80 and file_bytes <= virtual and file_offset + file_bytes <= len(image), 'invalid segment bounds')
            if image[position + 8:position + 24].rstrip(b'\0') == b'__TEXT':
                require(initial & 5 == 5 and maximum & 5 == 5, 'dyld text is not readable/executable')
                texts.append((address, file_offset, file_bytes))
        elif command == 5:
            require(size == 288 and struct.unpack_from('<2I', image, position + 8) == (6, 68), 'unsupported UNIXTHREAD layout')
            threads.append({'pc': struct.unpack_from('<Q', image, position + 272)[0],
                            'raw_command': image[position:position + size],
                            'raw_command_sha256': digest(image[position:position + size])})
        position += size
    require(position == end and len(texts) == len(threads) == 1, 'dyld text/thread identity is ambiguous')
    address, offset, size = texts[0]
    require(address + size <= (1 << 64) and threads[0]['pc'] == ENTRY, 'unexpected dyld entry/VM extent')
    text = image[offset:offset + size]
    require(address <= ENTRY and ENTRY + 20 <= address + size and address <= TARGET and TARGET + 4 <= address + size,
            'entry or PAC boundary outside original file-backed text')
    prefix = text[ENTRY - address:ENTRY - address + 20]
    require(struct.unpack('<5I', prefix) == PREFIX_WORDS, 'dyld prefix differs from reviewed original instructions')
    require(struct.unpack_from('<I', text, TARGET - address)[0] == PACIBSP, 'original PAC boundary differs')
    branch = PREFIX_WORDS[-1] & 0x3ffffff
    signed = branch - (1 << 26) if branch & (1 << 25) else branch
    require(ENTRY + 16 + signed * 4 == TARGET, 'original direct branch does not reach reviewed target')
    decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(prefix, ENTRY))
    require([i.mnemonic for i in decoded] == ['mov', 'and', 'mov', 'mov', 'b'], 'independent entry decode differs')
    return {'text': text, 'text_address': address, 'text_file_offset': offset,
            'thread_command_sha256': threads[0]['raw_command_sha256'],
            'thread_command': threads[0]['raw_command'], 'prefix': prefix}


def expected_state(initial):
    expected = State.from_buffer_copy(initial)
    expected.x[0] = initial.sp
    expected.sp = initial.sp & ~15
    expected.x[29] = expected.x[30] = 0
    return expected


def original_segment_regions(image, load_base):
    """Independently materialize logical LC_SEGMENT_64 bytes for ARM oracles."""
    require(image[:4] == b'\xcf\xfa\xed\xfe' and len(image) >= 32, 'original image is not thin Mach-O64')
    count, command_bytes = struct.unpack_from('<II', image, 16)
    require(count <= 4096 and 32 + command_bytes <= len(image), 'original load commands exceed file')
    cursor, segments = 32, []
    for _ in range(count):
        command, size = struct.unpack_from('<II', image, cursor)
        require(size >= 8 and size % 8 == 0 and cursor + size <= 32 + command_bytes, 'invalid original command extent')
        if command == 0x19:
            name = image[cursor + 8:cursor + 24].split(b'\0')[0].decode('ascii')
            address, virtual_bytes, offset, file_bytes, maximum, protection, sections, flags = struct.unpack_from('<4Q4I', image, cursor + 24)
            require(size == 72 + 80 * sections and file_bytes <= virtual_bytes and offset + file_bytes <= len(image)
                    and address + virtual_bytes <= 1 << 64 and protection & ~maximum == 0,
                    'invalid original segment bounds/protection')
            segments.append({'name': name, 'preferred': address, 'virtual_bytes': virtual_bytes,
                             'file_offset': offset, 'file_bytes': file_bytes, 'maximum_protection': maximum,
                             'initial_protection': protection, 'flags': flags})
        cursor += size
    require(cursor == 32 + command_bytes, 'original command count/extent mismatch')
    text = [segment for segment in segments if segment['name'] == '__TEXT']
    require(len(text) == 1, 'original image requires unique __TEXT')
    regions, total = [], 0
    for segment in segments:
        if not segment['virtual_bytes'] or not segment['initial_protection']:
            continue
        address = load_base + segment['preferred'] - text[0]['preferred']
        require(address >= 0 and address + segment['virtual_bytes'] <= 1 << 47, 'original region exceeds direct-RAM profile')
        total += segment['virtual_bytes']
        require(total <= 256 * 1024 * 1024, 'original image virtual extent exceeds oracle budget')
        data = image[segment['file_offset']:segment['file_offset'] + segment['file_bytes']]
        data += bytes(segment['virtual_bytes'] - segment['file_bytes'])
        regions.append({**segment, 'address': address, 'data': data})
    return regions


def original_kernel_args(stack_base, stack_bytes, main_header, executable, arguments):
    """Construct deterministic oracle input from the reviewed word-array ABI."""
    strings = [*arguments['argv'], *arguments['environment'], list(executable), *arguments['apple']]
    strings = [bytes(value) for value in strings]
    require(all(b'\0' not in value for value in strings), 'argument contains NUL')
    top = stack_base + stack_bytes
    string_start = top - sum(len(value) + 1 for value in strings)
    argc_address = (string_start - (len(strings) + 4) * 8) & ~15
    raw_sp = argc_address - 8
    require((raw_sp & ~15) - 0x6c0 >= stack_base, 'oracle stack lacks bootstrap scratch')
    payload, pointers, cursor = bytearray(top - raw_sp), [], string_start
    for value in strings:
        pointers.append(cursor)
        offset = cursor - raw_sp
        payload[offset:offset + len(value)] = value
        cursor += len(value) + 1
    argc, envc = len(arguments['argv']), len(arguments['environment'])
    words = [main_header, argc, *pointers[:argc], 0,
             *pointers[argc:argc + envc], 0, *pointers[argc + envc:], 0]
    require(len(words) * 8 <= string_start - raw_sp, 'oracle argument table overlaps strings')
    for index, word in enumerate(words):
        struct.pack_into('<Q', payload, index * 8, word)
    return raw_sp, bytes(payload)


def original_state(view, slide, initial):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    base = view['text_address'] + slide
    require(base % 4096 == 0, 'original text base is not page aligned')
    machine.mem_map(base, (len(view['text']) + 4095) & ~4095)
    machine.mem_write(base, view['text'])
    initialize_arm(machine, initial)
    observed = []
    machine.hook_add(UC_HOOK_CODE, lambda _, pc, size, unused: observed.append((pc, size)))
    machine.emu_start(ENTRY + slide, TARGET + slide, count=5)
    require(observed == [(ENTRY + slide + index * 4, 4) for index in range(5)], 'original execution escaped exact five-instruction prefix')
    require(machine.reg_read(arm.UC_ARM64_REG_PC) == TARGET + slide, 'original branch missed PAC boundary')
    return capture_arm(machine, initial)


def validate_native(result, expected, text_hash, slide, cold):
    require(result.get('kind') == 'native_block_run' and result.get('abi') == ABI and result.get('complete_binary_verified') is False,
            'native report identity/scope differs')
    require(result.get('source_sha256') == text_hash and result.get('guest_base') == slide and result.get('pc') == TARGET + slide,
            'native report source/placement/stop differs')
    require(result.get('state') == state_dict(expected), 'native prefix differs from complete independent state')
    outcome = result['outcome']
    require(outcome.get('reason', {}).get('kind') == 'unsupported' and str(PACIBSP) in outcome['reason'].get('detail', ''),
            'runtime did not reject exact original PACIBSP')
    require(outcome.get('blocks_executed') == 1 and outcome.get('last_exit') == [TARGET + slide, 1], 'native runtime escaped prefix boundary')
    require(outcome.get('compiled_blocks') == int(cold) and outcome.get('disk_cache_hits') == int(not cold)
            and outcome.get('memory_cache_hits') == 0, 'unexpected cold/disk cache path')


def cache_receipts(cache, view, compiler):
    receipts = []
    for manifest_path in sorted(cache.glob('*/manifest.json')):
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
        native = manifest_path.with_name('native.bin').read_bytes()
        identity = manifest['identity']
        require(identity['guest_base'] in (ENTRY, ENTRY + 0x4000) and identity['source_sha256'] == digest(view['prefix'])
                and identity['compiler_source_sha256'] == compiler and identity['abi'] == ABI and identity['target_cpu'] == 'x86_64-baseline'
                and manifest['verified'] is False, 'cache contains a different source block/ABI')
        mapping = manifest['source_map']
        require([row[0] for row in mapping] == [identity['guest_base'] + i * 4 for i in range(5)]
                and all(0 <= row[1] < len(native) for row in mapping)
                and all(a[1] < b[1] for a, b in zip(mapping, mapping[1:])), 'cache source map differs from original prefix')
        require(manifest['native_sha256'] == digest(native) and manifest['native_bytes'] == len(native)
                and json.loads(manifest_path.with_name('manifest.sha256.json').read_bytes()) == digest(raw), 'cache payload/metadata checksum differs')
        receipts.append({'key': manifest_path.parent.name, 'manifest': manifest, 'manifest_sha256': digest(raw)})
    require(len(receipts) == 2, 'unsupported PAC created a translation or a placement is missing')
    return receipts


def audit_arguments(report, path, arguments):
    """Walk installed pointers/bytes; do not regenerate the planner's layout."""
    plan = report['arguments']
    payload = bytes(plan['initial_bytes'])
    begin, end = plan['payload_address'], plan['stack_base'] + plan['stack_bytes']
    require(plan['raw_sp'] == begin and begin % 16 == 8 and plan['argc_address'] == begin + 8
            and plan['aligned_sp'] == begin & ~15 and plan['aligned_sp'] >= plan['stack_base'] + 256
            and begin + len(payload) == end and len(payload) <= 1024 * 1024, 'invalid argument stack/payload extent')
    occupied = set()

    def word(address):
        offset = address - begin
        require(0 <= offset <= len(payload) - 8, 'argument word escapes payload')
        occupied.update(range(offset, offset + 8))
        return struct.unpack_from('<Q', payload, offset)[0]

    def string(address, expected):
        offset = address - begin
        require(0 <= offset < len(payload), 'argument string escapes payload')
        finish = payload.find(b'\0', offset)
        require(finish >= offset and payload[offset:finish] == expected, 'argument string bytes/terminator differ')
        span = set(range(offset, finish + 1))
        require(not span & occupied, 'argument strings/tables overlap')
        occupied.update(span)
        return finish - offset

    require(word(begin) == report['main']['load_base'] and word(begin + 8) == len(arguments['argv'])
            and plan['argc'] == len(arguments['argv']), 'kernel arguments main header/argc differ')
    cursor, spans = begin + 16, []
    for kind, expected_strings, metadata in [('argv', arguments['argv'], 'argv_address'),
            ('environment', arguments['environment'], 'envp_address'),
            ('apple', [list(str(path).encode()), *arguments['apple']], 'apple_address')]:
        require(plan[metadata] == cursor, 'argument table address differs from walked layout')
        pointers = []
        for index, expected in enumerate(expected_strings):
            pointers.append((index, word(cursor), bytes(expected)))
            cursor += 8
        require(word(cursor) == 0, 'argument pointer array lacks NULL')
        cursor += 8
        # Mark all pointer words before checking string overlap.
        spans.extend((kind, index, address, expected) for index, address, expected in pointers)
    observed = []
    for kind, index, address, expected in spans:
        require(address >= cursor, 'argument string overlaps a later pointer table')
        observed.append({'kind': kind, 'index': index, 'address': address, 'bytes': string(address, expected)})
    require(observed == plan['strings'], 'argument string metadata differs from actual pointed bytes')
    require(all(byte == 0 for index, byte in enumerate(payload) if index not in occupied), 'unexplained nonzero argument padding')
    require(report['argument_payload_sha256'] == digest(payload) == report['argument_payload_after_sha256'],
            'installed argument readback changed')
    stack = report['stack']
    require((stack['base'], stack['bytes']) == (plan['stack_base'], plan['stack_bytes']), 'owned stack differs from argument range')
    for address, size, access in [(stack['base'] - stack['guard_bytes'], stack['guard_bytes'], False),
                                  (stack['base'], stack['bytes'], True),
                                  (stack['base'] + stack['bytes'], stack['guard_bytes'], False)]:
        matches = [row for row in report['mapped_regions'] if row['guest_address'] == address and row['virtual_bytes'] == size]
        require(len(matches) == 1 and matches[0]['readable'] == access and matches[0]['writable'] == access
                and matches[0]['executable'] is False, 'owned stack/guard permissions differ')


def audit_process_input(report, view, executable, arguments, compiler):
    image = executable.read_bytes()
    require(image[:4] == b'\xcf\xfa\xed\xfe', 'integrated verifier currently requires a thin acquired main executable')
    header = struct.unpack_from('<8I', image)
    require(report['kind'] == 'original_dyld_startup_prefix_probe' and report['schema_version'] == 1
            and report['complete_binary_verified'] is False and report['fixups_applied'] is False
            and report['native_executed'] is True and report['compiler_source_sha256'] == compiler,
            'integrated probe identity/scope differs')
    require(report['main']['container_sha256'] == digest(image) and report['main']['slice_offset'] == 0,
            'main input identity differs')
    main = report['main']['plan']
    require(main['slice_sha256'] == digest(image) and main['slice_bytes'] == len(image)
            and (main['cpu_type'], main['cpu_subtype'], main['file_type'], main['header_flags']) == header[1:4] + (header[6],),
            'main raw header/plan identity differs')
    dyld = report['dyld']
    require(dyld['container_sha256'] == CONTAINER_SHA256 and dyld['slice_offset'] == SLICE_OFFSET
            and dyld['plan']['image']['slice_sha256'] == SLICE_SHA256 and dyld['plan']['image']['file_type'] == 7,
            'dyld input/plan identity differs')
    raw = view['thread_command']
    thread = dyld['plan']['thread']
    require(thread['raw_command_hex'] == raw.hex() and thread['raw_command_sha256'] == digest(raw)
            and (thread['flavor'], thread['count']) == (6, 68)
            and thread['x'] == list(struct.unpack_from('<31Q', raw, 16))
            and (thread['sp'], thread['pc'], thread['cpsr'], thread['pad']) == struct.unpack_from('<QQII', raw, 264),
            'serialized UNIXTHREAD differs from original command')
    require(report['process_arguments'] == arguments, 'integrated arguments differ from explicit inputs')
    audit_arguments(report, executable, arguments)
    initial = State()
    initial.x[:] = thread['x']
    initial.sp, initial.nzcv = report['arguments']['raw_sp'], thread['cpsr']
    # The CLI initializes appended fields to zero; standalone cases test dirty state.
    for vector in initial.v:
        vector[:] = [0, 0]
    initial.fpcr = initial.fpsr = 0
    require(report['initial_state'] == state_dict(initial), 'initial process state differs from thread/stack plan')
    for key, path in [('probe_source_sha256', ROOT / 'src/dyld_entry.rs'),
                      ('process_source_sha256', ROOT / 'crates/stela-runtime/src/process.rs')]:
        require(report[key] == digest(path.read_bytes()), 'integrated probe source identity differs')
    return initial


def audit_integrated(report, view, executable, arguments, compiler):
    initial = audit_process_input(report, view, executable, arguments, compiler)
    dyld = report['dyld']
    expected = expected_state(initial)
    original = original_state(view, dyld['slide'], initial)
    require(bytes(original) == bytes(expected) and report['state'] == state_dict(expected), 'integrated original/math/native state differs')
    require(report['entry_pc'] == ENTRY + dyld['slide'] and report['stop_pc'] == TARGET + dyld['slide'] == report['pc']
            and report['original_prefix_words'] == list(PREFIX_WORDS), 'integrated original entry/boundary differs')
    require(report['outcome']['reason']['kind'] == 'stop_address' and report['outcome']['blocks_executed'] == 1
            and report['outcome']['last_exit'] == [report['stop_pc'], 1] and report['target_analysis']['supported'] is False
            and str(PACIBSP) in report['target_analysis']['detail'], 'integrated probe entered or admitted PAC')
    for key, path in [('probe_source_sha256', ROOT / 'src/dyld_entry.rs'),
                      ('process_source_sha256', ROOT / 'crates/stela-runtime/src/process.rs')]:
        require(report[key] == digest(path.read_bytes()), 'integrated probe source identity differs')
    return {'original': state_dict(original), 'expected': state_dict(expected), 'native': report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dyld', type=Path, default=DEFAULT_DYLD)
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/dyld-entry-differential-report.json')
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--executable', type=Path, action='append', default=[], help='Also verify installed argument-table probe for this thin main image')
    args = parser.parse_args()
    require(args.dyld.stat().st_size <= MAX_INPUT, 'dyld file exceeds research bound')
    container = args.dyld.read_bytes()
    require(digest(container) == CONTAINER_SHA256, 'dyld container does not match acquired26A434 input')
    offset, image = classic_slice(container)
    require((offset, len(image), digest(image)) == (SLICE_OFFSET, SLICE_BYTES, SLICE_SHA256), 'classic dyld slice differs')
    view = parse_dyld(image)
    require(view['text_address'] == 0, 'pinned dyld preferred text base changed')
    if not args.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    cli_hash = digest(cli.read_bytes())
    sources = [Path(__file__), ROOT / 'dev/differential.py', ROOT / 'src/dyld_entry.rs', ROOT / 'crates/stela-runtime/src/process.rs']
    source_hashes = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources}
    rows, integrated, compiler = [], [], None
    templates = states(all_flags=True)
    with tempfile.TemporaryDirectory(prefix='stela-dyld-entry-') as temporary:
        directory = Path(temporary)
        source, state_path, cache = directory / 'original-text.arm64', directory / 'state.json', directory / 'cache'
        source.write_bytes(view['text'])
        for slide in (0, 0x4000):
            for alignment in (0, 8):
                for flags in range(16):
                    initial = State.from_buffer_copy(templates[flags])
                    initial.nzcv = flags << 28
                    initial.sp = 0x220004000000 + alignment
                    seed_extended_state(initial, slide + alignment + flags * 256)
                    initial.fpcr |= 1 << 22
                    initial.fpsr |= 1
                    require(all(v[0] and v[1] for v in initial.v) and initial.fpcr and initial.fpsr,
                            'entry fixture must carry dirty vector and FP state')
                    expected = expected_state(initial)
                    original = original_state(view, slide, initial)
                    require(bytes(original) == bytes(expected), 'original prefix differs from independent semantics')
                    state_path.write_text(json.dumps(state_dict(initial)))
                    result = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source), '--guest-base', hex(slide),
                        '--entry', hex(ENTRY + slide), '--state', str(state_path), '--block-budget', '2', '--cache-dir', str(cache)], timeout=15))
                    require(compiler is None or compiler == result['compiler_source_sha256'], 'compiler changed during entry probe')
                    compiler = result['compiler_source_sha256']
                    validate_native(result, expected, digest(view['text']), slide, alignment == flags == 0)
                    rows.append({'slide': slide, 'raw_sp_alignment': alignment, 'nzcv': initial.nzcv,
                                 'initial': state_dict(initial), 'original': state_dict(original), 'expected': state_dict(expected), 'native': result})
            print(f'dyld entry slide{slide:#x}: {len(rows)} complete states', flush=True)
        cached = cache_receipts(cache, view, compiler)
        arguments = {'argv': [list(b'stela-entry-test'), [0xff, 0xfe]],
                     'environment': [list(b'STELA_ENTRY=1')], 'apple': [list(b'stela=original-dyld-prefix')]}
        argument_path = directory / 'arguments.json'
        argument_path.write_text(json.dumps(arguments))
        for index, executable in enumerate(args.executable):
            input_hash = digest(executable.read_bytes())
            for placement in (0, 0x4000):
                result = json.loads(subprocess.check_output([str(cli), 'probe-dyld-entry', str(args.dyld), '--executable', str(executable),
                    '--arguments', str(argument_path), '--image-base', hex(0x60000000000 + index * 0x1000000),
                    '--dyld-slide', hex(0x40000000000 + placement), '--stack-base', hex(0x80000000000 + index * 0x1000000),
                    '--cache-dir', str(directory / 'integrated-cache')], timeout=30))
                integrated.append(audit_integrated(result, view, executable, arguments, compiler))
                outcome = result['outcome']
                require(outcome['compiled_blocks'] == int(index == 0) and outcome['disk_cache_hits'] == int(index != 0),
                        'integrated AOT/new-loader cache path differs')
            require(input_hash == digest(executable.read_bytes()), 'integrated main source changed')
    require(digest(args.dyld.read_bytes()) == CONTAINER_SHA256 and digest(cli.read_bytes()) == cli_hash
            and all(digest((ROOT / path).read_bytes()) == value for path, value in source_hashes.items()), 'input/compiler/harness changed during proof')
    report = {'kind': 'original_dyld_entry_arm_vs_shared_native', 'passed': True, 'build': '26A434',
              'dyld_path': str(args.dyld), 'container_sha256': CONTAINER_SHA256, 'slice_sha256': SLICE_SHA256,
              'slice_offset': offset, 'slice_bytes': len(image), 'original_text_sha256': digest(view['text']),
              'original_text_bytes': len(view['text']), 'prefix_sha256': digest(view['prefix']),
              'thread_command_sha256': view['thread_command_sha256'], 'entry': ENTRY, 'pac_boundary': TARGET,
              'three_way_register_state_comparisons': len(rows), 'native_pac_declines': len(rows),
              'cold_compiles': 2, 'new_runtime_disk_hits': len(rows) - 2, 'guest_state_bytes': ctypes.sizeof(State),
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_hash,
              'harness_source_sha256': source_hashes[str(Path(__file__).relative_to(ROOT))],
              'shared_sources_sha256': source_hashes, 'cache_receipts': cached, 'cases': rows,
              'integrated_argument_probes': integrated,
              'limits': 'Unchanged original five-instruction entry prefix only, two16KiBplacements, aligned/rawSP8mod16 and all16NZCV. Standalone numeric SP values are not dereferenced. Full784Bstandalone state includes nonzero V/FP. Optional integrated cases audit installed argument arrays, guardedstack and raw image mappings at two additional placements, but execute the same register-only prefix with zero initialV/FP. Runtime rejects original PACIBSP before execution; integrated cases stop explicitly and analyze it separately. No PAC semantics, dyld initialization, original chained fixups, Mach services, process launch or complete binary verification.'}
    snapshot = write_evidence(args.output, report)
    print(json.dumps({'passed': True, 'comparisons': len(rows), 'report': str(args.output), 'snapshot': str(snapshot)}, indent=2))


if __name__ == '__main__':
    main()
