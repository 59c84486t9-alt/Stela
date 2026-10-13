#!/usr/bin/env python3
"""Original enabled ARM PAuth versus explicit software-profile shared runtime.

The independent model uses Arm's QARMA5 nibble operations. Emulator-derived
canonical vectors and ASL-derived full64 outputs are separate evidence classes.
"""
import argparse
import ctypes
import hashlib
import json
import importlib
from pathlib import Path
import random
import struct
import subprocess
import tempfile

import unicorn
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm
from differential import State, initialize_arm, capture_arm, seed_extended_state, state_dict
from evidence import write_evidence

ROOT = Path(__file__).resolve().parents[1]
MASK = (1 << 64) - 1
LOW = (1 << 47) - 1
PAC_MASK = MASK ^ LOW ^ (1 << 55)
BASE = 0x100000
STOP = BASE + 0x800
KEY = (0x1122334455667788, 0x99aabbccddeeff00)
TCR = 17 | (17 << 16) | (1 << 37) | (1 << 38) | (1 << 51) | (1 << 52)
WORDS = {'pacibsp': 0xd503237f, 'autibsp': 0xd50323ff, 'retab': 0xd65f0fff}
SUB = (11, 6, 8, 15, 12, 0, 9, 14, 3, 7, 4, 5, 13, 2, 1, 10)
INV_SUB = tuple(SUB.index(i) for i in range(16))
CELL = (13, 6, 11, 0, 7, 12, 1, 10, 8, 3, 14, 5, 2, 9, 4, 15)
INV_CELL = tuple(CELL.index(i) for i in range(16))
TWEAK = (4, 5, 6, 7, 11, 2, 3, 8, 12, 13, 14, 15, 0, 1, 10, 9)
ROTATED = frozenset((2, 4, 7, 11, 12, 14, 15))
RC = (0, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89, 0x452821e638d01377)
ALPHA = 0xc0ac29b7c97c50dd


def nibbles(value):
    return [(value >> (4 * i)) & 15 for i in range(16)]


def packed(cells):
    return sum(cell << (4 * i) for i, cell in enumerate(cells))


def substitute(value, inverse=False):
    table = INV_SUB if inverse else SUB
    return packed([table[cell] for cell in nibbles(value)])


def shuffle(value, inverse=False):
    cells = nibbles(value)
    return packed([cells[index] for index in (INV_CELL if inverse else CELL)])


def tweak_rotation(cell):
    return (cell >> 1) | (((cell ^ (cell >> 1)) & 1) << 3)


INV_ROTATION = tuple(next(i for i in range(16) if tweak_rotation(i) == j) for j in range(16))


def tweak(value, inverse=False):
    cells = nibbles(value)
    if inverse:
        result = [0] * 16
        for out, source in enumerate(TWEAK):
            result[source] = INV_ROTATION[cells[out]] if out in ROTATED else cells[out]
    else:
        result = [tweak_rotation(cells[source]) if out in ROTATED else cells[source]
                  for out, source in enumerate(TWEAK)]
    return packed(result)


def mix(value):
    cells = nibbles(value)
    result = [0] * 16
    def rol(x, count):
        return ((x << count) | (x >> (4 - count))) & 15
    for column in range(4):
        a, b, c, d = (cells[column + 4 * row] for row in range(4))
        result[column] = rol(d, 1) ^ rol(c, 2) ^ rol(b, 1)
        result[column + 4] = rol(d, 2) ^ rol(c, 1) ^ rol(a, 1)
        result[column + 8] = rol(d, 1) ^ rol(b, 1) ^ rol(a, 2)
        result[column + 12] = rol(c, 1) ^ rol(b, 2) ^ rol(a, 1)
    return packed(result)


def qarma5(data, modifier, low, high):
    """Full64 ASL-derived result; high=key0, low=key1, five forward/reverse rounds."""
    mod_high = ((high << 63) | ((high >> 1) ^ (high >> 63))) & MASK
    running = modifier
    working = data ^ high
    for i, constant in enumerate(RC):
        working ^= low ^ running ^ constant
        if i:
            working = mix(shuffle(working))
        working = substitute(working)
        running = tweak(running)
    working ^= mod_high ^ running
    working = mix(shuffle(substitute(mix(shuffle(working)))))
    working ^= low
    working = substitute(shuffle(working, True), True)
    working = shuffle(mix(working), True)
    working ^= high ^ running
    for i in range(5):
        working = substitute(working, True)
        if i < 4:
            working = shuffle(mix(working), True)
        running = tweak(running, True)
        working ^= RC[4 - i] ^ low ^ running ^ ALPHA
    return working ^ mod_high


def strip_ib(pointer):
    return (pointer & LOW) | ((MASK ^ LOW) if pointer & (1 << 55) else 0)


def sign_ib(pointer, modifier, key=KEY):
    extension = MASK if pointer >> 63 else 0
    canonical = (pointer & LOW) | (extension & (MASK ^ LOW))
    signature = qarma5(canonical, modifier, *key)
    extension_field = pointer >> 47
    if extension_field not in (0, (1 << 17) - 1):
        signature ^= 1 << 62  # June2026 ASL, differs from older Unicorn's bit63.
    return (pointer & LOW) | (signature & PAC_MASK) | (extension & (1 << 55))


def authenticate_ib(pointer, modifier, key=KEY):
    original = strip_ib(pointer)
    valid = ((qarma5(original, modifier, *key) ^ pointer) & PAC_MASK) == 0
    poisoned = (original & ~(3 << 61)) | (2 << 61)
    return (original if valid else poisoned), valid


def arm_machine(key=KEY, enabled=True):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
    machine.mem_map(BASE, 4096)
    controls = [((3, 6, 1, 1, 0), 1 | (1 << 10) | (1 << 16) | (1 << 17)),
                ((3, 4, 1, 1, 0), (1 << 31) | (1 << 40) | (1 << 41)),
                ((3, 0, 1, 0, 0), 0xc50838 | (((1 << 31) | (1 << 30) | (1 << 27) | (1 << 13)) if enabled else 0)),
                ((3, 0, 2, 0, 2), TCR)]
    for register, value in controls:
        machine.cpr_write(*register, value)
        assert machine.cpr_read(*register) & value == value
    for half, value in enumerate(key):
        machine.cpr_write(3, 0, 2, 1, 2 + half, value)
        assert machine.cpr_read(3, 0, 2, 1, 2 + half) == value
    # Explicit EL0t, no PAuth2/FPAC model, masks do not affect pointer operations.
    machine.reg_write(arm.UC_ARM64_REG_PSTATE, 0x3c0)
    isar = machine.cpr_read(3, 0, 0, 6, 1)
    assert (isar >> 4) & 15 == 1 and (isar >> 8) & 15 == 0
    return machine


def initial_state(pointer, modifier, seed):
    rng = random.Random(seed)
    state = State()
    state.x[:] = [rng.getrandbits(64) for _ in range(31)]
    state.x[30] = pointer
    state.sp, state.nzcv, state.reserved = modifier, (seed & 15) << 28, 0x5a5aa5a5
    seed_extended_state(state, seed.to_bytes(8, 'little'))
    state.fpcr |= 1 << 22
    state.fpsr |= 1
    return state


def math_state(operation, initial, key=KEY):
    state = State.from_buffer_copy(initial)
    state.x[7] = 42
    authenticated = None
    pc = BASE + 8
    if operation == 'pacibsp':
        state.x[30] = sign_ib(initial.x[30], initial.sp, key)
    else:
        pointer, authenticated = authenticate_ib(initial.x[30], initial.sp, key)
        if operation == 'autibsp':
            state.x[30] = pointer
        else:
            pc = pointer
    return state, pc, authenticated


def original(operation, initial, key=KEY):
    machine = arm_machine(key)
    machine.mem_write(BASE, struct.pack('<2I', 0xd2800547, WORDS[operation]))
    initialize_arm(machine, initial)
    observed = []
    machine.hook_add(UC_HOOK_CODE, lambda _, pc, size, unused: observed.append([pc, size]))
    error = None
    try:
        machine.emu_start(BASE, BASE + 8, count=2)
    except UcError as exc:
        error = {'code': exc.errno, 'message': str(exc)}
    assert observed == [[BASE, 4], [BASE + 4, 4]], observed
    return capture_arm(machine, initial), machine.reg_read(arm.UC_ARM64_REG_PC), error

PROFILE = 'stela-classic-arm64e-qarma5-va47-itbi0-ib-v1'
ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-v1'
OPERATIONS = {'pacibsp': 'sign_ib_sp', 'autibsp': 'authenticate_ib_sp', 'retab': 'return_ib_sp'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(pointer):
    return pointer >> 47 in (0, (1 << 17) - 1)


def cases():
    for key in [KEY, (0, 0), (MASK, MASK), (1, 2)]:
        for pointer in [0, STOP, LOW, 0xffff800000001400]:
            for modifier in [0, 0x2000, MASK, 0x0123456789abcdef]:
                signed = sign_ib(pointer, modifier, key)
                for flag in range(16):
                    yield {'name': 'canonical-sign', 'operation': 'pacibsp', 'pointer': pointer, 'modifier': modifier, 'key': key, 'flag': flag}
                    yield {'name': 'canonical-auth', 'operation': 'autibsp', 'pointer': signed, 'modifier': modifier, 'key': key, 'flag': flag}
        for modifier in [0, 0x2000, MASK, 0x0123456789abcdef]:
            signed = sign_ib(STOP, modifier, key)
            for flag in range(16):
                yield {'name': 'canonical-return', 'operation': 'retab', 'pointer': signed, 'modifier': modifier, 'key': key, 'flag': flag}
    signed = sign_ib(STOP, 0x2000)
    mutations = [('wrong-modifier', signed, 0x2010, KEY),
                 ('wrong-key-low', signed, 0x2000, (KEY[0] ^ 1, KEY[1])),
                 ('wrong-key-high', signed, 0x2000, (KEY[0], KEY[1] ^ 1))]
    mutations += [(f'pac-bit-{bit}', signed ^ (1 << bit), 0x2000, KEY) for bit in [*range(47, 55), *range(56, 64)]]
    mutations += [(f'target-bit-{bit}', signed ^ (1 << bit), 0x2000, KEY) for bit in [0, 2, 12, 32, 46]]
    for name, pointer, modifier, key in mutations:
        assert authenticate_ib(pointer, modifier, key)[1] is False
        for flag in range(16):
            for operation in ['autibsp', 'retab']:
                yield {'name': name, 'operation': operation, 'pointer': pointer, 'modifier': modifier, 'key': key, 'flag': flag}
    for pointer in [1 << 47, 1 << 55, 1 << 63, 0x1234000000001400]:
        signed = sign_ib(pointer, 0x2000)
        for flag in range(16):
            yield {'name': 'invalid-extension-sign', 'operation': 'pacibsp', 'pointer': pointer, 'modifier': 0x2000, 'key': KEY, 'flag': flag}
            yield {'name': 'invalid-extension-auth', 'operation': 'autibsp', 'pointer': signed, 'modifier': 0x2000, 'key': KEY, 'flag': flag}


def validate_native(report, operation, expected, pc, authenticated, source_sha, cold):
    assert report['kind'] == 'native_block_run' and report['abi'] == ABI
    assert report['software_pauth_profile'] == PROFILE and report['complete_binary_verified'] is False
    assert report['source_sha256'] == source_sha and report['guest_base'] == BASE
    assert report['state'] == state_dict(expected) and report['pc'] == pc
    outcome = report['outcome']
    descriptor = {'operation': OPERATIONS[operation], 'instruction_pc': BASE + 4, 'next_pc': BASE + 8}
    assert outcome['pointer_authentication_events'] == [{'instruction': descriptor, 'next_pc': pc, 'authenticated': authenticated}]
    if operation == 'retab' and authenticated is False:
        assert outcome['reason'] == {'kind': 'pointer_authentication_poisoned_return', 'instruction': descriptor, 'poisoned_target': pc}
    else:
        assert outcome['reason'] == {'kind': 'stop_address'}
    assert outcome['blocks_executed'] == 1 and outcome['last_exit'] == [BASE + 4, 6]
    assert outcome['compiled_blocks'] == int(cold) and outcome['disk_cache_hits'] == int(not cold)
    assert outcome['memory_cache_hits'] == 0


def validate_original(operation, initial, expected, expected_pc, observed, observed_pc):
    if operation == 'pacibsp' and not canonical(initial.x[30]):
        legacy = State.from_buffer_copy(expected)
        legacy.x[30] ^= (1 << 62) | (1 << 63)
        assert bytes(observed) == bytes(legacy) and observed_pc == expected_pc
        return 'invalid_extension_legacy_unicorn_observation'
    assert bytes(observed) == bytes(expected) and observed_pc == expected_pc
    return 'original_math_native_equal'


def cache_receipts(cache, source_hashes):
    result = []
    for path in sorted(cache.glob('*/manifest.json')):
        raw = path.read_bytes()
        manifest = json.loads(raw)
        native = path.with_name('native.bin').read_bytes()
        identity = manifest['identity']
        assert identity['abi'] == ABI and identity['guest_base'] == BASE
        assert identity['source_sha256'] in source_hashes and manifest['verified'] is False
        assert manifest['native_sha256'] == digest(native) and manifest['native_bytes'] == len(native)
        assert json.loads(path.with_name('manifest.sha256.json').read_bytes()) == digest(raw)
        assert [row[0] for row in manifest['source_map']] == [BASE, BASE + 4]
        assert manifest['source_map'][0][1] < manifest['source_map'][1][1] < len(native)
        for key in [KEY, (KEY[0] ^ 1, KEY[1]), (KEY[0], KEY[1] ^ 1)]:
            assert all(struct.pack('<Q', limb) not in native for limb in key)
        result.append({'key': path.parent.name, 'manifest': manifest, 'manifest_sha256': digest(raw)})
    assert len(result) == 3
    return result


def audit_integrated(report, view, executable, arguments, compiler):
    dyld_suite = importlib.import_module('dyld-entry-differential')
    initial = dyld_suite.audit_process_input(report, view, executable, arguments, compiler)
    assert report['abi'] == ABI and report['software_pauth_profile'] == PROFILE
    assert report['pauth_instruction_executed'] is True
    dyld = report['dyld']
    expected = dyld_suite.expected_state(initial)
    expected.x[30] = sign_ib(0, expected.sp)
    assert expected.x[30] != 0  # This observed startup PAC must really sign null LR.
    slide = dyld['slide']
    machine = arm_machine(KEY)
    machine.mem_map(view['text_address'] + slide, (len(view['text']) + 4095) & ~4095)
    machine.mem_write(view['text_address'] + slide, view['text'])
    initialize_arm(machine, initial)
    pcs = []
    machine.hook_add(UC_HOOK_CODE, lambda _, pc, size, unused: pcs.append([pc, size]))
    stop = dyld_suite.TARGET + slide + 4
    machine.emu_start(dyld_suite.ENTRY + slide, stop, count=6)
    assert pcs == [[dyld_suite.ENTRY + slide + i * 4, 4] for i in range(5)] + [[stop - 4, 4]]
    observed = capture_arm(machine, initial)
    assert bytes(observed) == bytes(expected) and report['state'] == state_dict(expected)
    assert machine.reg_read(arm.UC_ARM64_REG_PC) == stop == report['pc'] == report['stop_pc']
    assert report['entry_pc'] == dyld_suite.ENTRY + slide and report['target_pc'] == stop - 4
    assert report['original_prefix_words'] == list(dyld_suite.PREFIX_WORDS)
    descriptor = {'operation': 'sign_ib_sp', 'instruction_pc': stop - 4, 'next_pc': stop}
    outcome = report['outcome']
    assert outcome['reason'] == {'kind': 'stop_address'} and outcome['blocks_executed'] == 2
    assert outcome['last_exit'] == [stop - 4, 6]
    assert outcome['pointer_authentication_events'] == [{'instruction': descriptor, 'next_pc': stop, 'authenticated': None}]
    assert report['target_analysis_profile'] == 'ordinary' and report['target_analysis']['supported'] is False
    assert str(WORDS['pacibsp']) in report['target_analysis']['detail']
    assert report['selected_profile_target_analysis']['supported'] is True
    for field, path in [('probe_source_sha256', ROOT / 'src/dyld_entry.rs'),
                        ('process_source_sha256', ROOT / 'crates/stela-runtime/src/process.rs'),
                        ('pauth_source_sha256', ROOT / 'crates/stela-runtime/src/pauth.rs')]:
        assert report[field] == digest(path.read_bytes())
    return {'original': state_dict(observed), 'independent_math': state_dict(expected), 'native': report}


CLOCK_BASE = 0xfffffc000
CLOCK_BYTES = 16 * 1024
CLOCK_PROFILE = 'stela-continuous-ns-arm-commpage-clock-v1'
CLOCK_ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-clock-v1'
BOOTSTRAP_PCS = tuple([0x4bf0 + i * 4 for i in range(5)] + list(range(0x30460, 0x304a4, 4))
                     + list(range(0x8054c, 0x80584, 4)) + list(range(0x805d4, 0x805f4, 4)))


def clock_page(sleep_ticks):
    assert 0 <= sleep_ticks <= MASK
    page = bytearray(CLOCK_BYTES)
    struct.pack_into('<Q', page, 0x88, (-sleep_ticks) & MASK)
    page[0x90:0x92] = b'\x01\x01'
    struct.pack_into('<Q', page, 0x98, sleep_ticks)
    struct.pack_into('<Q', page, 0xa8, 0)
    return bytes(page)


def bootstrap_math(initial, stack_before, stack_base, slide, counter):
    """Independent exact observed path, no general ARM decoder/interpreter."""
    state = State.from_buffer_copy(initial)
    state.x[0] = initial.sp
    state.sp &= ~15
    state.x[29] = 0
    state.x[30] = sign_ib(0, state.sp)
    stack = bytearray(stack_before)
    writes = []
    def store(address, *values):
        data = struct.pack('<' + 'Q' * len(values), *values)
        offset = address - stack_base
        assert 0 <= offset and offset + len(data) <= len(stack)
        stack[offset:offset + len(data)] = data
        writes.append({'address': address, 'bytes': len(data), 'value_hex': data.hex()})
    state.sp -= 0x60
    for index, first in enumerate([28, 26, 24, 22, 20]):
        store(state.sp + 16 * index, state.x[first], state.x[first - 1])
    store(state.sp + 0x50, state.x[29], state.x[30])
    state.x[29] = state.sp + 0x50
    state.sp -= 0x620
    for destination, source in [(26, 3), (23, 2), (21, 1), (22, 0), (19, 3)]:
        state.x[destination] = state.x[source]
    store(state.sp + 0x38, state.x[0])
    assert state.x[3] == 0
    state.x[30] = sign_ib(slide + 0x304a4, state.sp)
    state.sp -= 0x40
    store(state.sp + 0x20, state.x[20], state.x[19])
    store(state.sp + 0x30, state.x[29], state.x[30])
    state.x[29] = state.sp + 0x30
    state.x[19] = 0xfffffc098
    # CONT_HWCLOCK=1/USER_TIMEBASE=1 select both comparisons and the ISB/MRS path.
    state.nzcv = 0x80000000  # CMP W8(1),#2 => negative, nonzero, borrow, no overflow.
    state.x[8], state.x[9], state.x[0] = counter, 0, counter
    def pair(address):
        offset = address - stack_base
        return struct.unpack_from('<2Q', stack, offset)
    state.x[29], state.x[30] = pair(state.sp + 0x30)
    state.x[20], state.x[19] = pair(state.sp + 0x20)
    state.sp += 0x40
    target, valid = authenticate_ib(state.x[30], state.sp)
    assert valid and target == slide + 0x304a4
    assert len(writes) == 9 and sum(item['bytes'] for item in writes) == 136
    return state, bytes(stack), writes


def original_bootstrap(view, main_bytes, main_base, slide, stack_base, stack_bytes, initial, payload, sleep_ticks):
    """Execute all44 unchanged original instructions including real CNTVCT MRS."""
    dyld_suite = importlib.import_module('dyld-entry-differential')
    container = dyld_suite.DEFAULT_DYLD.read_bytes()
    assert digest(container) == dyld_suite.CONTAINER_SHA256
    offset, image = dyld_suite.classic_slice(container)
    assert offset == dyld_suite.SLICE_OFFSET and digest(image) == dyld_suite.SLICE_SHA256
    machine = arm_machine(KEY)
    # Remove the unused single-instruction test page; every accessible byte below
    # is an explicit original image, owned stack/guard, or selected clock view.
    machine.mem_unmap(BASE, 4096)
    machine.cpr_write(3, 0, 14, 1, 0, machine.cpr_read(3, 0, 14, 1, 0) | 2)
    assert machine.cpr_read(3, 0, 14, 1, 0) & 2
    regions = []
    for name, data, base in [('dyld', image, slide), ('main', main_bytes, main_base)]:
        for region in dyld_suite.original_segment_regions(data, base):
            assert region['address'] % 4096 == 0 and region['virtual_bytes'] % 4096 == 0
            protection = region['initial_protection'] & (~2 if region['flags'] & 16 else MASK)
            machine.mem_map(region['address'], region['virtual_bytes'])
            machine.mem_write(region['address'], region['data'])
            machine.mem_protect(region['address'], region['virtual_bytes'], protection)
            regions.append({**region, 'image': name, 'protection': protection})
    stack_before = bytearray(stack_bytes)
    start = initial.sp - stack_base
    assert 0 <= start and start + len(payload) == stack_bytes
    stack_before[start:] = payload
    machine.mem_map(stack_base, stack_bytes, 3)
    machine.mem_write(stack_base, bytes(stack_before))
    for address in [stack_base - 4096, stack_base + stack_bytes]:
        machine.mem_map(address, 4096, 0)
    page = clock_page(sleep_ticks)
    machine.mem_map(CLOCK_BASE, CLOCK_BYTES)
    machine.mem_write(CLOCK_BASE, page)
    machine.mem_protect(CLOCK_BASE, CLOCK_BYTES, 1)
    initialize_arm(machine, initial)
    steps, accesses = [], []
    captured = []
    def code(_, pc, size, unused):
        if steps:
            steps[-1]['after'] = state_dict(capture_arm(machine, initial))
        assert size == 4 and len(steps) < len(BOOTSTRAP_PCS)
        assert pc == slide + BOOTSTRAP_PCS[len(steps)]
        preferred = pc - slide
        assert bytes(machine.mem_read(pc, 4)) == image[preferred:preferred + 4]
        if preferred == 0x805dc:
            captured.append(machine.reg_read(arm.UC_ARM64_REG_X8))
        steps.append({'pc': pc, 'word': struct.unpack_from('<I', image, preferred)[0],
                      'before': state_dict(capture_arm(machine, initial))})
    def memory(_, kind, address, size, value, unused):
        write = kind == unicorn.UC_MEM_WRITE
        protected = 2 if write else 1
        owned = stack_base <= address and address + size <= stack_base + stack_bytes
        owned |= not write and CLOCK_BASE <= address and address + size <= CLOCK_BASE + CLOCK_BYTES
        owned |= any(region['address'] <= address and address + size <= region['address'] + region['virtual_bytes']
                     and region['protection'] & protected for region in regions)
        assert owned, ('unowned original access', hex(address), size)
        accesses.append({'pc': machine.reg_read(arm.UC_ARM64_REG_PC), 'kind': 'write' if write else 'read',
                         'address': address, 'bytes': size})
    machine.hook_add(UC_HOOK_CODE, code)
    machine.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, memory)
    stop = slide + 0x304a4
    machine.emu_start(slide + dyld_suite.ENTRY, stop, count=128)
    final = capture_arm(machine, initial)
    steps[-1]['after'] = state_dict(final)
    assert len(steps) == 44 and len(captured) == 1 and machine.reg_read(arm.UC_ARM64_REG_PC) == stop
    counter = captured[0]
    assert counter >= sleep_ticks
    expected, expected_stack, writes = bootstrap_math(initial, bytes(stack_before), stack_base, slide, counter)
    after = bytes(machine.mem_read(stack_base, stack_bytes))
    assert bytes(final) == bytes(expected) and after == expected_stack
    observed_writes = {address for event in accesses if event['kind'] == 'write'
                       for address in range(event['address'], event['address'] + event['bytes'])}
    expected_writes = {address for event in writes for address in range(event['address'], event['address'] + event['bytes'])}
    assert observed_writes == expected_writes and len(expected_writes) == 136
    images = []
    for region in regions:
        actual = bytes(machine.mem_read(region['address'], region['virtual_bytes']))
        assert actual == region['data']
        images.append({'image': region['image'], 'segment': region['name'], 'address': region['address'],
                       'bytes': region['virtual_bytes'], 'initial_sha256': digest(region['data']), 'final_sha256': digest(actual)})
    assert bytes(machine.mem_read(CLOCK_BASE, CLOCK_BYTES)) == page
    return {'counter': counter, 'sleep_ticks': sleep_ticks, 'initial': state_dict(initial), 'state': state_dict(final),
            'stack_before_hex': bytes(stack_before).hex(), 'stack_after_hex': after.hex(), 'memory_effects': images,
            'clock_page_hex': page.hex(), 'steps': steps, 'accesses': accesses, 'writes': writes,
            'cntfrq_el0': machine.cpr_read(3, 3, 14, 0, 0), 'cntkctl_el1': machine.cpr_read(3, 0, 14, 1, 0),
            'pc': stop, 'limits': 'Original real MRS counter is opaque replay input; emulator62500000Hz and nativevirtual1GHz rate are not equated.'}


def audit_clock_probe(report, oracle, view, executable, arguments, compiler, replay, host_bounds=None):
    dyld_suite = importlib.import_module('dyld-entry-differential')
    initial = dyld_suite.audit_process_input(report, view, executable, arguments, compiler)
    assert state_dict(initial) == oracle['initial']
    assert report['bootstrap_clock'] is True and report['abi'] == CLOCK_ABI
    assert report['software_pauth_profile'] == PROFILE and report['pauth_instruction_executed'] is True
    slide = report['dyld']['slide']
    assert report['entry_pc'] == slide + dyld_suite.ENTRY and report['pc'] == report['stop_pc'] == slide + 0x304a4
    assert report['target_pc'] == slide + dyld_suite.TARGET and report['original_prefix_words'] == list(dyld_suite.PREFIX_WORDS)
    assert report['target_analysis_profile'] == 'ordinary' and report['target_analysis']['supported'] is False
    assert report['selected_profile_target_analysis']['supported'] is True
    clock = report['clock']
    assert clock['profile_id'] == CLOCK_PROFILE and clock['frequency'] == 1_000_000_000
    region = clock['region']
    assert (region['guest_address'], region['virtual_bytes'], region['readable'], region['writable'], region['executable']) == (CLOCK_BASE, CLOCK_BYTES, True, False, False)
    events = clock['events']
    assert len(events) == 2 and [event['sequence'] for event in events] == [0, 1]
    first, last = [event['snapshot'] for event in events]
    assert clock['snapshot'] == last
    assert last['counter'] >= first['counter'] >= first['sleep_ticks']
    assert last['sleep_ticks'] >= first['sleep_ticks'] and last['counter'] - last['sleep_ticks'] >= first['counter'] - first['sleep_ticks']
    if replay:
        assert clock['source_id'] == 'explicit-finite-replay-v1'
        assert first == last == {'counter': oracle['counter'], 'sleep_ticks': oracle['sleep_ticks']}
    else:
        assert clock['source_id'] == 'darwin-x86_64-absolute-plus-commpage-sleep-v1'
        assert host_bounds is not None and host_bounds[0] <= first['counter'] <= last['counter'] <= host_bounds[1]
    assert bytes.fromhex(clock['page_before_hex']) == clock_page(first['sleep_ticks'])
    assert bytes.fromhex(clock['page_after_hex']) == clock_page(last['sleep_ticks'])
    assert report['stack_before_hex'] == oracle['stack_before_hex']
    expected, stack, writes = bootstrap_math(initial, bytes.fromhex(oracle['stack_before_hex']), report['stack']['base'], slide, last['counter'])
    assert report['state'] == state_dict(expected)
    assert report['stack_after_hex'] == stack.hex() == oracle['stack_after_hex']
    if replay:
        assert report['state'] == oracle['state']
    expected_memory = [dict(region) for region in oracle['memory_effects']]
    expected_memory.append({'address': report['stack']['base'], 'bytes': len(stack),
                            'initial_sha256': digest(bytes.fromhex(oracle['stack_before_hex'])), 'final_sha256': digest(stack)})
    expected_by_address = {region['address']: region for region in expected_memory}
    effects = report['memory_effects']
    assert len(effects) == len(expected_by_address)
    assert {effect['address'] for effect in effects} == set(expected_by_address)
    owned_readable = {(region['guest_address'], region['virtual_bytes']) for region in report['mapped_regions'] if region['readable']}
    assert owned_readable == {(effect['address'], effect['bytes']) for effect in effects}
    for effect in effects:
        expected_region = expected_by_address[effect['address']]
        assert all(effect[field] == expected_region[field] for field in ('bytes', 'initial_sha256', 'final_sha256'))
    outcome = report['outcome']
    assert outcome['reason'] == {'kind': 'stop_address'} and outcome['blocks_executed'] == 11
    assert outcome['last_exit'] == [slide + 0x805f0, 6] and outcome['memory_cache_hits'] == 0
    def pa(operation, pc, next_pc, actual_pc, authenticated):
        return {'instruction': {'operation': operation, 'instruction_pc': slide + pc, 'next_pc': slide + next_pc},
                'next_pc': slide + actual_pc, 'authenticated': authenticated}
    assert outcome['pointer_authentication_events'] == [pa('sign_ib_sp', 0x30460, 0x30464, 0x30464, None),
        pa('sign_ib_sp', 0x8054c, 0x80550, 0x80550, None), pa('return_ib_sp', 0x805f0, 0x805f4, 0x304a4, True)]
    assert outcome['clock_events'] == [
        {'instruction': {'operation': {'kind': 'instruction_synchronization'}, 'instruction_pc': slide + 0x805d4, 'next_pc': slide + 0x805d8}, 'next_pc': slide + 0x805d8, 'counter': None},
        {'instruction': {'operation': {'kind': 'read_virtual_counter', 'destination': 8}, 'instruction_pc': slide + 0x805d8, 'next_pc': slide + 0x805dc}, 'next_pc': slide + 0x805dc, 'counter': last['counter']}]
    for field, path in [('pauth_source_sha256', ROOT / 'crates/stela-runtime/src/pauth.rs'),
                        ('clock_source_sha256', ROOT / 'crates/stela-runtime/src/clock.rs')]:
        if field in report:
            assert report[field] == digest(path.read_bytes())
    return {'native': report, 'independent_math': state_dict(expected), 'whole_stack_bytes_compared': len(stack),
            'distinct_original_store_bytes': sum(event['bytes'] for event in writes),
            'replay_three_way_equal': replay, 'host_counter_bounds': host_bounds}


def clock_cache_receipts(cache, image):
    roots = (0x4bf0, 0x30460, 0x30464, 0x304a0, 0x8054c, 0x80550, 0x80570, 0x8057c, 0x805d4, 0x805d8, 0x805dc)
    expected = {slide + pc for slide in (0x40000000000, 0x40000004000) for pc in roots}
    rows = []
    for path in sorted(cache.glob('*/manifest.json')):
        raw = path.read_bytes()
        manifest = json.loads(raw)
        identity, mapping = manifest['identity'], manifest['source_map']
        entry = identity['guest_base']
        assert entry in expected and identity['abi'] == CLOCK_ABI and manifest['verified'] is False
        # Prefer exact membership rather than address ordering where the two
        # placements' helper addresses interleave.
        candidates = [base for base in (0x40000000000, 0x40000004000) if entry - base in roots]
        assert len(candidates) == 1
        slide = candidates[0]
        preferred = entry - slide
        assert [pc for pc, _ in mapping] == list(range(entry, entry + 4 * len(mapping), 4))
        assert identity['source_sha256'] == digest(image[preferred:preferred + 4 * len(mapping)])
        native = path.with_name('native.bin').read_bytes()
        assert manifest['native_sha256'] == digest(native) and manifest['native_bytes'] == len(native)
        assert all(a[1] < b[1] for a, b in zip(mapping, mapping[1:])) and mapping[-1][1] < len(native)
        assert json.loads(path.with_name('manifest.sha256.json').read_bytes()) == digest(raw)
        assert all(struct.pack('<Q', limb) not in native for limb in KEY)
        rows.append({'key': path.parent.name, 'manifest': manifest, 'manifest_sha256': digest(raw)})
    assert {row['manifest']['identity']['guest_base'] for row in rows} == expected and len(rows) == 22
    return rows


def host_continuous_time():
    """Independent public host API bound, not the provider's private source."""
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    class Timebase(ctypes.Structure):
        _fields_ = [('numer', ctypes.c_uint32), ('denom', ctypes.c_uint32)]
    info = Timebase()
    library.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
    library.mach_timebase_info.restype = ctypes.c_int
    assert library.mach_timebase_info(ctypes.byref(info)) == 0 and (info.numer, info.denom) == (1, 1)
    library.mach_continuous_time.argtypes = []
    library.mach_continuous_time.restype = ctypes.c_uint64
    return library.mach_continuous_time()


def clock_instruction_math(initial, destination, counter):
    state = State.from_buffer_copy(initial)
    state.x[7] = 42
    if destination != 31:
        state.x[destination] = counter
    return state


def clock_instruction_original(initial, destination):
    machine = arm_machine()
    machine.cpr_write(3, 0, 14, 1, 0, machine.cpr_read(3, 0, 14, 1, 0) | 2)
    source = struct.pack('<3I', 0xd2800547, 0xd5033fdf, 0xd53be040 | destination)
    machine.mem_write(BASE, source)
    initialize_arm(machine, initial)
    pcs = []
    machine.hook_add(UC_HOOK_CODE, lambda _, pc, size, unused: pcs.append([pc, size]))
    machine.emu_start(BASE, BASE + 12, count=3)
    assert pcs == [[BASE + i * 4, 4] for i in range(3)]
    observed = capture_arm(machine, initial)
    if destination == 31:
        # MRS XZR discards its architectural result. This separately sampled
        # opaque replay value is not mislabeled as that unobservable read.
        counter = machine.cpr_read(3, 3, 14, 0, 2)
        observation = 'post_instruction_counter_sample; discarded_read_value_unobservable'
    else:
        counter = observed.x[destination]
        observation = 'actual_mrs_destination_value'
    assert counter > 0
    expected = clock_instruction_math(initial, destination, counter)
    assert bytes(observed) == bytes(expected) and machine.reg_read(arm.UC_ARM64_REG_PC) == BASE + 12
    return observed, counter, observation, source, machine.cpr_read(3, 3, 14, 0, 0)


def validate_clock_instruction(report, initial, destination, counter, source, compiled, disk):
    expected = clock_instruction_math(initial, destination, counter)
    assert report['kind'] == 'native_block_run' and report['complete_binary_verified'] is False
    assert report['abi'] == CLOCK_ABI and report['software_pauth_profile'] == PROFILE
    assert report['source_sha256'] == digest(source) and report['guest_base'] == BASE and report['pc'] == BASE + 12
    assert report['state'] == state_dict(expected)
    outcome = report['outcome']
    assert outcome['reason'] == {'kind': 'stop_address'} and outcome['blocks_executed'] == 2
    assert outcome['last_exit'] == [BASE + 8, 7]
    assert outcome['compiled_blocks'] == compiled and outcome['disk_cache_hits'] == disk and outcome['memory_cache_hits'] == 0
    assert 'pointer_authentication_events' not in outcome
    assert outcome['clock_events'] == [
        {'instruction': {'operation': {'kind': 'instruction_synchronization'}, 'instruction_pc': BASE + 4, 'next_pc': BASE + 8}, 'next_pc': BASE + 8, 'counter': None},
        {'instruction': {'operation': {'kind': 'read_virtual_counter', 'destination': destination}, 'instruction_pc': BASE + 8, 'next_pc': BASE + 12}, 'next_pc': BASE + 12, 'counter': counter}]
    snapshot = {'counter': counter, 'sleep_ticks': 0}
    clock = report['clock']
    assert clock['snapshot'] == snapshot and clock['events'] == [{'sequence': i, 'snapshot': snapshot} for i in (0, 1)]
    assert clock['profile_id'] == CLOCK_PROFILE and clock['frequency'] == 1_000_000_000 and clock['source_id'] == 'explicit-finite-replay-v1'
    assert (clock['region']['guest_address'], clock['region']['virtual_bytes'], clock['region']['readable'],
            clock['region']['writable'], clock['region']['executable']) == (CLOCK_BASE, CLOCK_BYTES, True, False, False)
    return expected


def raw_clock_cohort(cli, folder, key_path, state_path):
    source_path, snapshot_path = folder / 'clock-register.arm64', folder / 'clock-register.json'
    cache = folder / 'clock-register-cache'
    rows = []
    for destination in range(32):
        for flags in range(16):
            initial = initial_state(MASK ^ destination, 0x220004000008, destination * 16 + flags)
            observed, counter, observation, source, frequency = clock_instruction_original(initial, destination)
            source_path.write_bytes(source)
            state_path.write_text(json.dumps(state_dict(initial)))
            snapshot_path.write_text(json.dumps({'counter': counter, 'sleep_ticks': 0}))
            report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path), '--state', str(state_path),
                '--guest-base', hex(BASE), '--stop-pc', hex(BASE + 12), '--block-budget', '2',
                '--software-pauth-ib-key', str(key_path), '--clock-snapshot', str(snapshot_path), '--cache-dir', str(cache)], timeout=15))
            compiled = (2 if destination == 0 else 1) if flags == 0 else 0
            expected = validate_clock_instruction(report, initial, destination, counter, source, compiled, 2 - compiled)
            assert bytes(observed) == bytes(expected)
            rows.append({'destination': destination, 'nzcv': initial.nzcv, 'initial': state_dict(initial),
                         'original': state_dict(observed), 'native': report, 'counter': counter,
                         'counter_observation': observation, 'original_cntfrq_el0': frequency})
    assert len(rows) == 512
    expected_sources = {(BASE, digest(struct.pack('<2I', 0xd2800547, 0xd5033fdf)))}
    expected_sources |= {(BASE + 8, digest(struct.pack('<I', 0xd53be040 | rt))) for rt in range(32)}
    manifests = []
    for path in sorted(cache.glob('*/manifest.json')):
        raw = path.read_bytes()
        manifest = json.loads(raw)
        identity, mapping = manifest['identity'], manifest['source_map']
        assert (identity['guest_base'], identity['source_sha256']) in expected_sources
        assert identity['abi'] == CLOCK_ABI and manifest['verified'] is False
        expected_pcs = [BASE, BASE + 4] if identity['guest_base'] == BASE else [BASE + 8]
        assert [pc for pc, _ in mapping] == expected_pcs
        native = path.with_name('native.bin').read_bytes()
        assert manifest['native_sha256'] == digest(native) and manifest['native_bytes'] == len(native)
        assert mapping[-1][1] < len(native) and all(a[1] < b[1] for a, b in zip(mapping, mapping[1:]))
        assert json.loads(path.with_name('manifest.sha256.json').read_bytes()) == digest(raw)
        assert all(struct.pack('<Q', limb) not in native for limb in KEY)
        manifests.append({'key': path.parent.name, 'manifest': manifest, 'manifest_sha256': digest(raw)})
    assert len(manifests) == 33 and {(row['manifest']['identity']['guest_base'], row['manifest']['identity']['source_sha256']) for row in manifests} == expected_sources
    return rows, manifests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--executable', type=Path, action='append', default=[])
    parser.add_argument('--bootstrap-clock', action='store_true', help='also verify the complete original mach_continuous_time startup call')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/pauth-differential-report.json')
    args = parser.parse_args()
    if args.bootstrap_clock and len(args.executable) != 2:
        parser.error('--bootstrap-clock requires two explicit --executable inputs for cold/disk coverage')
    if not args.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    sources = [Path(__file__), ROOT / 'dev/differential.py', ROOT / 'crates/stela-runtime/src/pauth.rs',
               ROOT / 'crates/stela-runtime/src/blocks.rs', ROOT / 'src/main.rs',
               ROOT / 'dev/dyld-entry-differential.py', ROOT / 'src/dyld_entry.rs',
               ROOT / 'crates/stela-runtime/src/process.rs', ROOT / 'crates/stela-runtime/src/clock.rs',
               ROOT / 'crates/stela-runtime/src/memory.rs']
    pins = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources}
    cli_hash = digest(cli.read_bytes())
    records = []
    integrated = []
    clock_integrated = []
    clock_manifests = []
    clock_register_cases, clock_register_manifests = [], []
    seen = set()
    equal = divergent = poisoned_returns = failed_auth = 0
    with tempfile.TemporaryDirectory(prefix='stela-pauth-') as temporary:
        folder = Path(temporary)
        cache = folder / 'cache'
        key_path, state_path = folder / 'key.json', folder / 'state.json'
        source_paths = {}
        source_hashes = set()
        for operation, word in WORDS.items():
            source = struct.pack('<2I', 0xd2800547, word)
            source_paths[operation] = folder / (operation + '.arm64')
            source_paths[operation].write_bytes(source)
            source_hashes.add(digest(source))
        for index, case in enumerate(cases()):
            operation, key = case['operation'], case['key']
            initial = initial_state(case['pointer'], case['modifier'], index * 16 + case['flag'])
            expected, pc, authenticated = math_state(operation, initial, key)
            observed, original_pc, error = original(operation, initial, key)
            classification = validate_original(operation, initial, expected, pc, observed, original_pc)
            assert error is None or (operation == 'retab' and authenticated is False and error['code'] in (8, 21))
            equal += classification == 'original_math_native_equal'
            divergent += classification != 'original_math_native_equal'
            failed_auth += operation == 'autibsp' and authenticated is False
            poisoned_returns += operation == 'retab' and authenticated is False
            state_path.write_text(json.dumps(state_dict(initial)))
            key_path.write_text(json.dumps({'low': key[0], 'high': key[1]}))
            command = [str(cli), 'run-blocks', str(source_paths[operation]), '--state', str(state_path),
                       '--guest-base', hex(BASE), '--stop-pc', hex(pc), '--block-budget', '1',
                       '--software-pauth-ib-key', str(key_path), '--cache-dir', str(cache)]
            report = json.loads(subprocess.check_output(command, timeout=15))
            cold = operation not in seen
            validate_native(report, operation, expected, pc, authenticated, digest(source_paths[operation].read_bytes()), cold)
            assert report['pauth_source_sha256'] == pins['crates/stela-runtime/src/pauth.rs']
            seen.add(operation)
            records.append({'case': case, 'classification': classification, 'initial': state_dict(initial),
                            'original': state_dict(observed), 'original_pc': original_pc, 'original_error': error,
                            'independent_math': state_dict(expected), 'native': report})
            if (index + 1) % 512 == 0:
                print(f'{index + 1} full-state PAuth cases', flush=True)
        # Default profile must decline rather than loading helper-profile cache entries.
        ordinary = []
        for operation in WORDS:
            initial = initial_state(STOP, 0x2000, 0)
            state_path.write_text(json.dumps(state_dict(initial)))
            report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_paths[operation]),
                '--state', str(state_path), '--guest-base', hex(BASE), '--block-budget', '1', '--cache-dir', str(cache)], timeout=15))
            assert report['outcome']['reason']['kind'] == 'unsupported'
            assert report['outcome']['blocks_executed'] == 0 and report['outcome']['disk_cache_hits'] == 0
            assert report['state'] == state_dict(initial) and report['pc'] == BASE
            assert report['software_pauth_profile'] is None and 'pointer_authentication_events' not in report['outcome']
            ordinary.append(report)
        manifests = cache_receipts(cache, source_hashes)
        if args.executable:
            dyld_suite = importlib.import_module('dyld-entry-differential')
            container = dyld_suite.DEFAULT_DYLD.read_bytes()
            assert digest(container) == dyld_suite.CONTAINER_SHA256
            offset, image = dyld_suite.classic_slice(container)
            assert offset == dyld_suite.SLICE_OFFSET and digest(image) == dyld_suite.SLICE_SHA256
            view = dyld_suite.parse_dyld(image)
            arguments = {'argv': [list(b'stela-pauth-test'), [0xff, 0xfe]],
                         'environment': [list(b'STELA_PAUTH=1')], 'apple': [list(b'stela=original-dyld-pac')]}
            argument_path = folder / 'arguments.json'
            argument_path.write_text(json.dumps(arguments))
            key_path.write_text(json.dumps({'low': KEY[0], 'high': KEY[1]}))
            for index, executable in enumerate(args.executable):
                input_hash = digest(executable.read_bytes())
                for placement in (0, 0x4000):
                    report = json.loads(subprocess.check_output([str(cli), 'probe-dyld-entry', str(dyld_suite.DEFAULT_DYLD),
                        '--executable', str(executable), '--arguments', str(argument_path),
                        '--image-base', hex(0x60000000000 + index * 0x1000000),
                        '--dyld-slide', hex(0x40000000000 + placement), '--stack-base', hex(0x80000000000 + index * 0x1000000),
                        '--software-pauth-ib-key', str(key_path), '--cache-dir', str(folder / 'integrated-cache')], timeout=30))
                    integrated.append(audit_integrated(report, view, executable, arguments, records[0]['native']['compiler_source_sha256']))
                    assert report['outcome']['compiled_blocks'] == 2 * int(index == 0)
                    assert report['outcome']['disk_cache_hits'] == 2 * int(index != 0)
                    if args.bootstrap_clock:
                        slide = 0x40000000000 + placement
                        main_base = 0x60000000000 + index * 0x1000000
                        stack_base = 0x80000000000 + index * 0x1000000
                        raw_sp, payload = dyld_suite.original_kernel_args(stack_base, 65536, main_base, str(executable).encode(), arguments)
                        initial = State.from_buffer_copy(bytes(ctypes.sizeof(State)))
                        initial.x[:] = struct.unpack_from('<31Q', view['thread_command'], 16)
                        initial.sp = raw_sp
                        initial.nzcv = struct.unpack_from('<I', view['thread_command'], 280)[0]
                        oracle = original_bootstrap(view, executable.read_bytes(), main_base, slide, stack_base, 65536,
                                                    initial, payload, 0 if placement == 0 else 123456789)
                        snapshot_path = folder / 'clock.json'
                        snapshot_path.write_text(json.dumps({'counter': oracle['counter'], 'sleep_ticks': oracle['sleep_ticks']}))
                        command = [str(cli), 'probe-dyld-entry', str(dyld_suite.DEFAULT_DYLD), '--executable', str(executable),
                            '--arguments', str(argument_path), '--image-base', hex(main_base), '--dyld-slide', hex(slide),
                            '--stack-base', hex(stack_base), '--software-pauth-ib-key', str(key_path), '--bootstrap-clock',
                            '--cache-dir', str(folder / 'clock-cache')]
                        replay = json.loads(subprocess.check_output([*command, '--clock-snapshot', str(snapshot_path)], timeout=30))
                        checked_replay = audit_clock_probe(replay, oracle, view, executable, arguments,
                            records[0]['native']['compiler_source_sha256'], True)
                        assert replay['outcome']['compiled_blocks'] == 11 * int(index == 0)
                        assert replay['outcome']['disk_cache_hits'] == 11 * int(index != 0)
                        before = host_continuous_time()
                        host = json.loads(subprocess.check_output(command, timeout=30))
                        after = host_continuous_time()
                        checked_host = audit_clock_probe(host, oracle, view, executable, arguments,
                            records[0]['native']['compiler_source_sha256'], False, [before, after])
                        assert host['outcome']['compiled_blocks'] == 0 and host['outcome']['disk_cache_hits'] == 11
                        clock_integrated.append({'original': oracle, 'replay': checked_replay, 'native_host_clock': checked_host})
                assert digest(executable.read_bytes()) == input_hash
            assert digest(dyld_suite.DEFAULT_DYLD.read_bytes()) == dyld_suite.CONTAINER_SHA256
            if args.bootstrap_clock:
                clock_manifests = clock_cache_receipts(folder / 'clock-cache', image)
                clock_register_cases, clock_register_manifests = raw_clock_cohort(cli, folder, key_path, state_path)
    assert len(records) == 3200 and equal == 3136 and divergent == 64
    assert poisoned_returns == 384 and failed_auth == 448
    assert digest(cli.read_bytes()) == cli_hash and all(digest((ROOT / path).read_bytes()) == checksum for path, checksum in pins.items())
    result = {'kind': 'original_arm_pauth_vs_explicit_software_native', 'passed': True,
              'profile': PROFILE, 'compiler_executable_sha256': cli_hash, 'compiler_source_sha256': records[0]['native']['compiler_source_sha256'],
              'sources_sha256': pins, 'guest_state_bytes': ctypes.sizeof(State), 'three_way_register_state_comparisons': equal,
              'native_math_state_comparisons': len(records), 'legacy_unicorn_invalid_extension_observations': divergent,
              'poisoned_return_checks': poisoned_returns, 'failed_aut_poison_checks': failed_auth,
              'cold_compiles': 3, 'new_runtime_disk_hits': len(records) - 3, 'ordinary_profile_declines': ordinary,
              'oracle': {'unicorn_version': unicorn.__version__, 'cpu_model': 'max', 'tcr_el1': TCR, 'current_el': 0,
                         'instruction_tbi': False, 'data_tbi': True, 'virtual_address_bits': 47, 'pauth2': False, 'fpac': False},
              'public_fixed_test_keys': True, 'cache_receipts': manifests, 'cases': records,
              'integrated_original_dyld_pac_probes': integrated,
              'integrated_original_dyld_clock_probes': clock_integrated, 'clock_cache_receipts': clock_manifests,
              'original_clock_replay_full_state_ram_comparisons': len(clock_integrated),
              'native_host_clock_bounded_state_ram_comparisons': len(clock_integrated),
              'clock_register_full_state_comparisons': len(clock_register_cases),
              'clock_register_cases': clock_register_cases, 'clock_register_cache_receipts': clock_register_manifests,
              'limits': ['Explicit software QARMA5 classic PAuth1 IB/SP profile, not Apple hardware bit identity or complete arm64e support.',
                         'Native executes original scalar prefix then explicit PAC runtime boundary; cryptography is a software helper, not inline native PAC.',
                         'Authentication failures poison pointers; RETAB typed stop records pending instruction-fetch exception delivery.',
                         'Noncanonical signing: June2026 ASL corrupts bit62, older Unicorn2.1.4 corrupts bit63;64 exact classified observations are not counted as three-way equality.',
                         'Generic IA/DA/DB/PACGA/XPAC remain oracle-only, outside the three production instruction forms.',
                         'MRS Rt31 discardedvalue is unobservable; the unchangedinstruction executes and fullstate preservation is checked, while native event replays a separatelyrecorded postinstruction counter sample. Other31Rt replay actualMRSdestination results.',
                         'Optional clock bootstrap executes44 originalinstructions, twoPACsigns+RETAB, actualISB/CNTVCT, allnine stores and restoredframe. Counterreplay provesopaque input effects; original62500000Hz and nativevirtual1GHz rates are not equated. Nativehost samples are separatelybounded by publicmach_continuous_time.',
                         'PAC-only vectors do not access guest RAM; complete clock probes compare every stack byte and all readable image/clock views. Full784B state is checked throughout; no full OS process, Apple hardware or performance claim.']}
    snapshot = write_evidence(args.output, result)
    print(json.dumps({'passed': True, 'three_way': equal, 'native_math': len(records), 'divergences': divergent,
                      'report': str(args.output), 'snapshot': str(snapshot)}, indent=2))


if __name__ == '__main__':
    main()
