#!/usr/bin/env python3
"""Original dyld entry, data protection and self-rebase versus shared BlockRuntime.

Default mode retains the five-instruction entry/PAC-decline fixture. Explicit
cohorts cover the original lockdown callback or complete self-rebase path.
All register the unchanged original text; none establishes a complete process.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
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


def audit_raw_permissions(report, dyld_image, main_image):
    require(report.get('mapping_phase') == 'kernel_loaded_unfixed', 'dyld probe mapping phase differs')
    for image, base in [(dyld_image, report['dyld']['slide']), (main_image, report['main']['load_base'])]:
        for region in original_segment_regions(image, base):
            matches = [r for r in report['mapped_regions'] if r['guest_address'] == region['address'] and r['virtual_bytes'] == region['virtual_bytes']]
            prot = region['initial_protection']
            require(len(matches) == 1 and (matches[0]['readable'], matches[0]['writable'], matches[0]['executable']) ==
                    (bool(prot & 1), bool(prot & 2), bool(prot & 4)), 'raw image initial protections differ or SG_READ_ONLY sealed early')


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
    _, raw_dyld = classic_slice(DEFAULT_DYLD.read_bytes())
    audit_raw_permissions(report, raw_dyld, image)
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


VM_ENTRY, VM_THUNK, VM_STUB, VM_RETURN = 0x341c8, 0x30160, 0x6074, 0x609c
VM_META, VM_STOP = 0x90000000000, 0xdead0000
VM_PROFILE = 'darwin-arm64-va47-page16k-data-mprotect-v1'


def vm_callback_expected(initial, segment, base):
    expected = State.from_buffer_copy(initial)
    if segment['flags'] & 16:
        expected.x[0], expected.x[1], expected.x[2], expected.x[3] = 0, 0, 1, 1
        expected.x[8], expected.x[9], expected.x[16] = base, segment['preferred'], 74
        expected.nzcv &= ~(1 << 29)
    else:
        expected.x[8] = segment['flags'] & 255
    return expected


def original_vm_callback(view, initial, segment, base, metadata):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(base, (len(view['text']) + 4095) & ~4095)
    machine.mem_write(base, view['text'])
    machine.mem_protect(base, (len(view['text']) + 4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
    machine.mem_map(VM_META, 16384); machine.mem_write(VM_META, metadata); machine.mem_protect(VM_META, 16384, UC_PROT_READ)
    target = base + segment['preferred']
    data = segment['data']
    active = bool(segment['flags'] & 16)
    if active:
        require(segment['initial_protection'] == 3 and segment['maximum_protection'] == 3, 'reviewed data protection contract differs')
        machine.mem_map(target, segment['virtual_bytes'], UC_PROT_READ | UC_PROT_WRITE); machine.mem_write(target, data)
    machine.reg_write(arm.UC_ARM64_REG_PSTATE, initial.nzcv)  # EL0; kernel return is modeled below.
    initialize_arm(machine, initial)
    visited, calls = [], []
    machine.hook_add(UC_HOOK_CODE, lambda _,pc,size,unused: visited.append(pc))
    def svc(uc, number, unused):
        require(number == 2 and uc.reg_read(arm.UC_ARM64_REG_PC) == base + VM_STUB + 8, 'unexpected original exception boundary')
        args = [uc.reg_read(arm.UC_ARM64_REG_X0 + i) for i in range(3)]
        require(args == [target, segment['virtual_bytes'], 1] and uc.reg_read(arm.UC_ARM64_REG_X16) == 74, 'original mprotect arguments differ')
        uc.mem_protect(target, segment['virtual_bytes'], UC_PROT_READ)
        uc.reg_write(arm.UC_ARM64_REG_X0, 0); uc.reg_write(arm.UC_ARM64_REG_X1, 0)
        uc.reg_write(arm.UC_ARM64_REG_NZCV, uc.reg_read(arm.UC_ARM64_REG_NZCV) & ~(1 << 29))
        calls.append(args)
    machine.hook_add(UC_HOOK_INTR, svc)
    machine.emu_start(base + VM_ENTRY, VM_STOP, count=32)
    require(machine.reg_read(arm.UC_ARM64_REG_PC) == VM_STOP, 'original callback did not return')
    require(len(visited) == (17 if active else 3) and len(calls) == int(active), 'original callback path differs')
    require(bytes(machine.mem_read(VM_META, 16384)) == metadata, 'original metadata changed')
    if active:
        require(bytes(machine.mem_read(target, len(data))) == data, 'original target bytes changed')
        require(any(a == target and b + 1 == target + len(data) and rights == UC_PROT_READ for a,b,rights in machine.mem_regions()), 'original target protection differs')
    return capture_arm(machine, initial), visited, calls


def validate_vm_native(report, expected, source_hash, memory, active):
    require(report['kind'] == 'native_block_run' and report['abi'] == ABI and report['source_sha256'] == source_hash
            and report['data_vm_profile'] == VM_PROFILE and report['complete_binary_verified'] is False, 'VM probe identity/scope differs')
    require(report['state'] == state_dict(expected) and report['pc'] == VM_STOP, 'VM callback full state differs')
    outcome = report['outcome']
    require(outcome['reason'] == {'kind':'stop_address'} and outcome['blocks_executed'] == (6 if active else 2), 'VM callback dispatch differs')
    before = [{'address':r['guest_address'],'bytes':r['virtual_bytes'],'sha256':digest(bytes(r['initial_bytes']))} for r in sorted(memory,key=lambda r:r['guest_address'])]
    proof = report['memory']
    require(proof['memory_before'] == before and proof['memory_after'] == before, 'VM callback RAM hashes differ')
    require(proof['memory_reads'] == [{'address':VM_META,'bytes':16384,'hex':bytes(next(r for r in memory if r['guest_address']==VM_META)['initial_bytes']).hex()}], 'VM metadata readback differs')
    require(len(proof['memory_regions']) == len(memory) and {(r['guest_address'],r['virtual_bytes']) for r in proof['memory_regions']} ==
            {(r['guest_address'],r['virtual_bytes']) for r in memory}, 'VM region coverage incomplete')
    for region in proof['memory_regions']:
        require(region['readable'] is True and region['writable'] is False and region['executable'] is False, 'VM final owned protections differ')
    events = report['data_vm_events']
    require(len(events) == int(active), 'VM service count differs')
    if active:
        target = next(r for r in memory if r['guest_address'] != VM_META)
        event = events[0]
        require(event['request'] == {'number':74,'indirect':False,'arguments':[target['guest_address'],target['virtual_bytes'],1],
                'prototype':{'argument_count':3,'return_type':'int'}} and event['completion'] == {'kind':'success','values':[0,0]}
                and event['declined'] is None, 'VM service arguments/completion differ')


def data_vm_cohort(cli, directory, view, image):
    rows, seen, svc_count = [], set(), 0
    source, state_path, memory_path = directory/'vm-text.arm64', directory/'vm-state.json', directory/'vm-memory.json'
    source.write_bytes(view['text'])
    templates = states(all_flags=True)
    for base in (0x40000000000,0x40000004000):
        for segment in original_segment_regions(image, 0):
            active = bool(segment['flags'] & 16)
            for flags in range(16):
                initial = State.from_buffer_copy(templates[flags]);seed_extended_state(initial, base + flags + segment['preferred'])
                initial.nzcv = flags << 28; initial.x[0] = VM_META; initial.x[1] = VM_META + 0x80; initial.x[30] = VM_STOP
                metadata = bytearray(b'\xa5' * 16384)
                struct.pack_into('<Q',metadata,0x20,base)
                struct.pack_into('<QQ',metadata,0x90,segment['preferred'],segment['virtual_bytes'])
                metadata[0xa8] = segment['flags'] & 255
                expected = vm_callback_expected(initial,segment,base)
                original, visited, calls = original_vm_callback(view,initial,segment,base,bytes(metadata))
                require(bytes(original) == bytes(expected), 'original callback differs from independent full-state model')
                memory = [{'guest_address':VM_META,'virtual_bytes':16384,'initial_bytes':list(metadata),'readable':True,'writable':False}]
                if active:
                    memory.append({'guest_address':base+segment['preferred'],'virtual_bytes':segment['virtual_bytes'],
                        'initial_bytes':list(segment['data']),'readable':True,'writable':True})
                state_path.write_text(json.dumps(state_dict(initial)));memory_path.write_text(json.dumps({'regions':memory}))
                report = json.loads(subprocess.check_output([str(cli),'run-blocks',str(source),'--guest-base',hex(base),'--entry',hex(base+VM_ENTRY),
                    '--stop-pc',hex(VM_STOP),'--state',str(state_path),'--memory',str(memory_path),'--data-vm-services',
                    '--read-memory',f'{hex(VM_META)}:16384','--block-budget','8','--cache-dir',str(directory/'vm-cache')],timeout=30))
                validate_vm_native(report,expected,digest(view['text']),memory,active)
                roots = [base+p for p in ([VM_ENTRY,0x341d4,VM_THUNK,VM_STUB,VM_STUB+8,VM_RETURN] if active else [VM_ENTRY,0x341d0])]
                cold = sum(pc not in seen for pc in roots)
                require(report['outcome']['compiled_blocks'] == cold and report['outcome']['disk_cache_hits'] == len(roots)-cold, 'VM cold/disk reuse differs')
                seen.update(roots);svc_count += len(calls)
                rows.append({'base':base,'segment':segment['name'],'flags':flags,'original_instruction_pcs':visited,
                    'initial':state_dict(initial),'original':state_dict(original),'expected':state_dict(expected),'native':report})
    require(len(rows) == 224 and svc_count == 32 and len(seen) == 14, 'VM cohort coverage differs')
    return {'profile':VM_PROFILE,'full_state_ram_comparisons':len(rows),'original_mprotect_calls':svc_count,'cold_blocks':len(seen),
            'fresh_runtime_disk_hits':sum(r['native']['outcome']['disk_cache_hits'] for r in rows),'cases':rows,
            'limits':'Unchanged original callback/thunk/syscall wrapper execute through genuine SVC, with modeled reviewed kernel result and Unicorn protection change. Native invokes owned host mprotect. No original privileged kernel, ProcessConfig, full self-rebase, TLS/error wrapper or complete process claim.'}



SELF_REBASE_BEGIN, SELF_REBASE_END = 0x30524, 0x30568


def self_rebase_cohort(cli, directory, view, image):
    """Execute the unchanged startup rebase path, including its full fixup loop."""
    spec = importlib.util.spec_from_file_location('self_rebase_pauth', ROOT / 'dev/pauth-differential.py')
    pac = importlib.util.module_from_spec(spec); spec.loader.exec_module(pac)
    source, state_path, memory_path = directory/'rebase-text.bin', directory/'rebase-state.json', directory/'rebase-memory.json'
    source.write_bytes(view['text'])
    keys_path = directory/'rebase-keys.json'
    keys_path.write_text(json.dumps({key: {'low': v[0], 'high': v[1]} for key,v in pac.DOMAIN_KEYS.items()}))
    source_paths = ('dev/dyld-entry-differential.py','dev/pauth-differential.py','dev/differential.py','src/main.rs',
                    'crates/stela-runtime/src/blocks.rs','crates/stela-runtime/src/memory.rs','crates/stela-runtime/src/pauth.rs')
    source_hashes = {path:digest((ROOT/path).read_bytes()) for path in source_paths}
    cli_hash, rows, compiler = digest(cli.read_bytes()), [], None
    for base in (0x40000000000, 0x40000004000):
        regions = original_segment_regions(image, base)
        stack, stack_bytes = 0x90000000000, 65536
        regions.append({'name':'stack','address':stack,'virtual_bytes':stack_bytes,
                        'initial_protection':3,'data':bytes(stack_bytes)})
        for flags in (0, 15):
            initial = State.from_buffer_copy(states(all_flags=True)[flags])
            initial.nzcv, initial.sp = flags << 28, stack + stack_bytes - 0x680
            initial.x[19], initial.x[26] = 1234, 0
            machine = pac.arm_machine(keys=pac.DOMAIN_KEYS)
            memory = []
            for index, region in enumerate(regions):
                address, data = region['address'], region['data']
                machine.mem_map(address, len(data)); machine.mem_write(address, data)
                machine.mem_protect(address, len(data), region['initial_protection'])
                path = directory/f'rebase-region-{index}.bin'; path.write_bytes(data)
                memory.append({'guest_address':address,'virtual_bytes':len(data),
                    'initial_file':{'path':path.name,'bytes':len(data),'sha256':digest(data)},
                    'readable':True,'writable':bool(region['initial_protection'] & 2)})
            initialize_arm(machine, initial)
            visited = []
            machine.hook_add(UC_HOOK_CODE, lambda _,pc,size,unused: visited.append(pc))
            machine.emu_start(base + SELF_REBASE_BEGIN, base + SELF_REBASE_END, count=2000000)
            require(machine.reg_read(arm.UC_ARM64_REG_PC) == base + SELF_REBASE_END,
                    'original self-rebase did not reach the original continuation')
            expected = capture_arm(machine, initial)
            after = {r['address']:bytes(machine.mem_read(r['address'],r['virtual_bytes'])) for r in regions}
            slots, slot_digest = pac.original_fixup_slots(image, base), hashlib.sha256()
            for slot in slots:
                if 'authentication' in slot:
                    auth = slot['authentication']
                    modifier = (slot['guest_address'] & ((1 << 48) - 1)) if auth['address_diversity'] else 0
                    modifier |= auth['diversity'] << 48
                    value = pac.domain_sign(slot['target'], modifier, auth['key'])
                else: value = slot['value']
                region = regions[slot['segment_index']]
                actual = struct.unpack_from('<Q',after[region['address']],slot['guest_address']-region['address'])[0]
                require(actual == value and actual != slot['raw'], 'original fixup differs from independent slot/signing model')
                slot_digest.update(struct.pack('<QQQ',slot['guest_address'],slot['raw'],value))
            before_hashes = [{'address':r['address'],'bytes':r['virtual_bytes'],'sha256':digest(r['data'])} for r in regions]
            after_hashes = [{'address':r['address'],'bytes':r['virtual_bytes'],'sha256':digest(after[r['address']])} for r in regions]
            state_path.write_text(json.dumps(state_dict(initial))); memory_path.write_text(json.dumps({'regions':memory}))
            native = json.loads(subprocess.check_output([str(cli),'run-blocks',str(source),'--guest-base',hex(base),
                '--entry',hex(base+SELF_REBASE_BEGIN),'--stop-pc',hex(base+SELF_REBASE_END),'--block-budget','100000',
                '--state',str(state_path),'--memory',str(memory_path),'--software-pauth-keys',str(keys_path),
                '--cache-dir',str(directory/'rebase-cache')],timeout=60))
            require(native['source_sha256'] == digest(view['text']) and native['abi'] == pac.ABI
                    and native['software_pauth_profile'] == pac.FULL_PROFILE
                    and native['complete_binary_verified'] is False, 'native rebase source/ABI/scope differs')
            require(native['pc'] == base + SELF_REBASE_END and native['outcome']['reason'] == {'kind':'stop_address'}
                    and native['state'] == state_dict(expected), 'native self-rebase state/continuation differs')
            require(native['memory']['memory_before'] == before_hashes and native['memory']['memory_after'] == after_hashes,
                    'native self-rebase full mapped RAM differs')
            events = native['outcome']['pointer_authentication_events']
            require(events and all(event['authenticated'] is not False for event in events), 'self-rebase authentication failed')
            require(compiler in (None, native['compiler_source_sha256']), 'rebase compiler changed')
            compiler = native['compiler_source_sha256']
            counts = {k:v for k,v in native['outcome'].items() if k != 'pointer_authentication_events'}
            require(counts['compiled_blocks'] > 0 if flags == 0 else counts['compiled_blocks'] == 0,
                    'self-rebase cold/disk cache reuse differs')
            rows.append({'base':base,'incoming_nzcv':initial.nzcv,'initial_state':state_dict(initial),
                'final_state':state_dict(expected),'original_instruction_count':len(visited),
                'original_unique_instructions':len(set(visited)), 'native_dispatch':counts,
                'pointer_authentication_events':len(events),'memory_before':before_hashes,'memory_after':after_hashes,
                'independent_fixup_slots':len(slots),'authenticated_slots':sum('authentication' in slot for slot in slots),
                'slot_raw_and_result_sha256':slot_digest.hexdigest()})
            print(f'self-rebase {base:#x}, NZCV {flags:x}: {len(visited):,} original instructions; all 2,568 fixups/state/RAM match',flush=True)
    require(digest(cli.read_bytes()) == cli_hash and all(digest((ROOT/path).read_bytes()) == value
            for path,value in source_hashes.items()), 'CLI or sources changed during self-rebase cohort')
    return {'kind':'original_dyld_self_rebase_arm_vs_shared_native','passed':True,
        'container_sha256':CONTAINER_SHA256,'slice_sha256':SLICE_SHA256,'original_text_sha256':digest(view['text']),
        'entry_offset':SELF_REBASE_BEGIN,'continuation_offset':SELF_REBASE_END,
        'compiler_source_sha256':compiler,'compiler_executable_sha256':cli_hash,
        'full_state_and_all_mapped_ram_comparisons':len(rows),'independent_fixup_slot_comparisons':sum(r['independent_fixup_slots'] for r in rows),
        'abi':pac.ABI,'software_pauth_profile':pac.FULL_PROFILE,'shared_sources_sha256':source_hashes,
        'cases':rows,
        'limits':'Unchanged complete self-rebase startup path entered at original basic block with explicit live inputs, original raw mappings and software PAuth1 keys. All chained writes execute in original code. This does not execute earlier time/kdebug startup, following libc/Mach/TLS initialization, full ProcessConfig, application launch, Apple hardware PAC or macOS boot.'}


def mach_ports_cohort(cli, directory, view, image):
    """Original wrappers and initialization prefix; host results replayed at SVC."""
    spec = importlib.util.spec_from_file_location('mach_ports_pauth', ROOT / 'dev/pauth-differential.py')
    pac = importlib.util.module_from_spec(spec); spec.loader.exec_module(pac)
    source, state_path, memory_path = directory/'mach-text.bin', directory/'mach-state.json', directory/'mach-memory.json'
    source.write_bytes(view['text'])
    keys_path = directory/'mach-keys.json'
    keys_path.write_text(json.dumps({key:{'low':v[0],'high':v[1]} for key,v in pac.DOMAIN_KEYS.items()}))
    source_paths = ('dev/dyld-entry-differential.py','dev/pauth-differential.py','dev/differential.py',
                    'src/main.rs','crates/stela-runtime/src/mach.rs','crates/stela-runtime/src/darwin.rs')
    hashes = {path:digest((ROOT/path).read_bytes()) for path in source_paths}
    cli_hash, rows, compiler = digest(cli.read_bytes()), [], None
    for base in (0x40000000000,0x40000004000):
        for flags in (0,15):
            for entry,stop,numbers in [(0x1634,VM_STOP,[26]),(0x1640,VM_STOP,[27]),
                                       (0x164c,VM_STOP,[28]),(0x1658,VM_STOP,[29]),
                                       (0x4c0c,base+0x4c38,[28,26])]:
                initial = State.from_buffer_copy(states(all_flags=True)[flags]); initial.nzcv=flags<<28
                initial.sp,initial.x[30] = 0x9000000f000,VM_STOP
                regions = original_segment_regions(image,base)
                regions.append({'address':0x90000000000,'virtual_bytes':65536,'initial_protection':3,'data':bytes(65536)})
                memory=[]
                for index,r in enumerate(regions):
                    path=directory/f'mach-region-{index}.bin';path.write_bytes(r['data'])
                    memory.append({'guest_address':r['address'],'virtual_bytes':r['virtual_bytes'],
                        'initial_file':{'path':path.name,'bytes':len(r['data']),'sha256':digest(r['data'])},
                        'readable':True,'writable':bool(r['initial_protection']&2)})
                state_path.write_text(json.dumps(state_dict(initial)));memory_path.write_text(json.dumps({'regions':memory}))
                native=json.loads(subprocess.check_output([str(cli),'run-blocks',str(source),'--guest-base',hex(base),
                    '--entry',hex(base+entry),'--stop-pc',hex(stop),'--state',str(state_path),'--memory',str(memory_path),
                    '--software-pauth-keys',str(keys_path),'--mach-port-services','--block-budget','32',
                    '--cache-dir',str(directory/'mach-cache')],timeout=15))
                require(native['outcome']['reason']=={'kind':'stop_address'} and native['pc']==stop,
                        'native Mach fixture missed original continuation/return')
                require(native['mach_port_profile']=='darwin-host-owned-mach-ports-v1' and native['data_vm_profile'] is None,
                        'Mach service profile changed or implicitly enabled data VM')
                events=native['mach_port_events']
                require([e['request']['number'] for e in events]==numbers and all(e['result']>0 and e['declined'] is None for e in events),
                        'original Mach requests did not obtain actual host-backed guest rights')
                require(len(native['mach_port_rights'])==len(numbers), 'Mach owned rights count differs')
                machine=pac.arm_machine(keys=pac.DOMAIN_KEYS)
                for r in regions:
                    machine.mem_map(r['address'],r['virtual_bytes']);machine.mem_write(r['address'],r['data'])
                    machine.mem_protect(r['address'],r['virtual_bytes'],r['initial_protection'])
                initialize_arm(machine,initial)
                replay=iter(events);observed=[]
                def svc(uc,number,unused):
                    event=next(replay); observed.append(event)
                    require(number==2 and uc.reg_read(arm.UC_ARM64_REG_PC)==event['trap']['exception_return_pc'],
                            'original SVC return PC differs')
                    require((uc.reg_read(arm.UC_ARM64_REG_X16)&0xffffffff)==(-event['request']['number'])&0xffffffff,
                            'original Mach selector differs')
                    # Pinned XNU arm_set_mach_syscall_ret assigns signed int to X0;
                    # X1/NZCV and other saved registers are preserved.
                    uc.reg_write(arm.UC_ARM64_REG_X0,event['result']&((1<<64)-1))
                machine.hook_add(UC_HOOK_INTR,svc)
                machine.emu_start(base+entry,stop,count=128)
                require(machine.reg_read(arm.UC_ARM64_REG_PC)==stop and len(observed)==len(events), 'original Mach path differs')
                expected=state_dict(capture_arm(machine,initial))
                after=[{'address':r['address'],'bytes':r['virtual_bytes'],
                        'sha256':digest(bytes(machine.mem_read(r['address'],r['virtual_bytes'])))} for r in regions]
                require(native['state']==expected and native['memory']['memory_after']==after,
                        'native original-wrapper/prefix CPU state or full RAM differs')
                require(compiler in (None,native['compiler_source_sha256']), 'Mach cohort compiler changed')
                compiler=native['compiler_source_sha256']
                rows.append({'base':base,'entry_offset':entry,'incoming_nzcv':initial.nzcv,'state':expected,
                             'events':events,'rights':native['mach_port_rights'],'memory_after':after})
    require(digest(cli.read_bytes())==cli_hash and all(digest((ROOT/p).read_bytes())==h for p,h in hashes.items()),
            'Mach cohort sources or executable changed')
    return {'kind':'original_dyld_mach_ports_arm_vs_shared_native','passed':True,
        'full_state_and_mapped_ram_comparisons':len(rows),'cases':rows,'compiler_source_sha256':compiler,
        'compiler_executable_sha256':cli_hash,'shared_sources_sha256':hashes,
        'container_sha256':CONTAINER_SHA256,'slice_sha256':SLICE_SHA256,
        'limits':'Original Mach wrappers and initialization prefix execute unchanged. Actual host-backed guest port results are replayed at original ARM SVC using public XNU return rules; the ARM kernel itself is not executed. Full IPC, Mach messages, commpage initialization, TLS and process startup remain unsupported.'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dyld', type=Path, default=DEFAULT_DYLD)
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/dyld-entry-differential-report.json')
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--mach-ports', action='store_true', help='run only original Mach port wrappers and initialization prefix')
    parser.add_argument('--self-rebase', action='store_true', help='run only the focused original full self-rebase cohort')
    parser.add_argument('--data-vm', action='store_true', help='verify original segment lockdown callback and owned mprotect service')
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
    require(not (args.self_rebase and args.mach_ports), 'select one focused dyld cohort')
    if args.self_rebase or args.mach_ports:
        with tempfile.TemporaryDirectory(prefix='stela-self-rebase-') as temporary:
            report = (mach_ports_cohort if args.mach_ports else self_rebase_cohort)(cli,Path(temporary),view,image)
        output = ROOT / ('.stela/dyld-mach-ports-differential-report.json' if args.mach_ports else '.stela/dyld-self-rebase-differential-report.json')
        snapshot = write_evidence(output,report)
        print(json.dumps({'passed':True,'report':str(output),'snapshot':str(snapshot)}))
        return
    sources = [Path(__file__), ROOT / 'dev/differential.py', ROOT / 'src/dyld_entry.rs', ROOT / 'crates/stela-runtime/src/process.rs',
               ROOT / 'src/macho/mapped_image.rs', ROOT / 'crates/stela-runtime/src/memory.rs', ROOT / 'crates/stela-runtime/src/darwin.rs',
               ROOT / 'crates/stela-runtime/src/blocks.rs', ROOT / 'src/main.rs']
    source_hashes = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources}
    rows, integrated, compiler = [], [], None
    vm = None
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
        if args.data_vm:
            vm = data_vm_cohort(cli,directory,view,image)
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
              'integrated_argument_probes': integrated,'data_vm':vm,
              'limits': 'Unchanged original five-instruction entry prefix only, two16KiBplacements, aligned/rawSP8mod16 and all16NZCV. Standalone numeric SP values are not dereferenced. Full784Bstandalone state includes nonzero V/FP. Optional integrated cases audit installed argument arrays, guardedstack and raw image mappings at two additional placements, but execute the same register-only prefix with zero initialV/FP. Runtime rejects original PACIBSP before execution; integrated cases stop explicitly and analyze it separately. No PAC semantics, dyld initialization, original chained fixups, Mach services, process launch or complete binary verification.'}
    snapshot = write_evidence(args.output, report)
    print(json.dumps({'passed': True, 'comparisons': len(rows), 'report': str(args.output), 'snapshot': str(snapshot)}, indent=2))


if __name__ == '__main__':
    main()
