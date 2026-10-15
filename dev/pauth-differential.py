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
import os
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



DOMAIN_KEYS = {'ia': (0x0123456789abcdef, 0xfedcba9876543210), 'ib': KEY,
               'da': (0x0f1e2d3c4b5a6978, 0x8877665544332211),
               'db': (0xcafebabedeadbeef, 0x1020304050607080)}
FULL_PROFILE = 'stela-classic-arm64e-qarma5-va47-itbi0-dtbi1-all-keys-v1'
DATA_PAC_MASK = ((1 << 55) - 1) ^ LOW
HIGH8 = 0xff << 56


def domain_strip(pointer, data):
    extension = MASK if pointer & (1 << 55) else 0
    mask = ((1 << 56) - 1) ^ LOW if data else MASK ^ LOW
    return (pointer & ~mask) | (extension & mask)


def domain_sign(pointer, modifier, key, keys=DOMAIN_KEYS):
    data = key[0] == 'd'
    top = 55 if data else 63
    extension = MASK if pointer & (1 << top) else 0
    extmask = ((1 << (top + 1)) - 1) ^ LOW
    canonical = (pointer & ~extmask) | (extension & extmask)
    signature = qarma5(canonical, modifier, *keys[key])
    if pointer & extmask not in (0, extmask):
        signature ^= 1 << (54 if data else 62)
    pacmask = DATA_PAC_MASK if data else PAC_MASK
    # Bit55 chooses the address range, even when it was not a valid extension.
    return (pointer & LOW) | (pointer & HIGH8 if data else 0) | (extension & (1 << 55)) | (signature & pacmask)


def domain_authenticate(pointer, modifier, key, keys=DOMAIN_KEYS):
    data = key[0] == 'd'
    original_pointer = domain_strip(pointer, data)
    pacmask = DATA_PAC_MASK if data else PAC_MASK
    valid = ((qarma5(original_pointer, modifier, *keys[key]) ^ pointer) & pacmask) == 0
    shift = 53 if data else 61
    error = 1 if key[1] == 'a' else 2
    poison = (original_pointer & ~(3 << shift)) | (error << shift)
    return (original_pointer if valid else poison), valid


def domain_invalid_extension(pointer, key):
    top = 55 if key[0] == 'd' else 63
    mask = ((1 << (top + 1)) - 1) ^ LOW
    return pointer & mask not in (0, mask)


def classify_domain_original(expected, observed, pc, original_pc, operation, key, destination, pointer):
    assert pc == original_pc, (hex(pc), hex(original_pc))
    if bytes(expected) == bytes(observed):
        return 'original_math_native_equal'
    assert operation == 'sign' and destination != 31 and domain_invalid_extension(pointer, key)
    corrected = State.from_buffer_copy(observed)
    corrected.x[destination] ^= (1 << 54) if key[0] == 'd' else ((1 << 62) | (1 << 63))
    assert bytes(corrected) == bytes(expected), 'unclassified original PAuth state mismatch'
    return 'invalid_extension_legacy_unicorn_observation'

def arm_machine(key=KEY, enabled=True, keys=None):
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
    if keys is not None:
        for domain, (crm, op2) in zip(('ia', 'ib', 'da', 'db'), ((1, 0), (1, 2), (2, 0), (2, 2))):
            for half, value in enumerate(keys[domain]):
                machine.cpr_write(3, 0, 2, crm, op2 + half, value)
                assert machine.cpr_read(3, 0, 2, crm, op2 + half) == value
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
            protection = region['initial_protection']
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


def basic_forms():
    forms = []
    for auth in (False, True):
        for zero in (False, True):
            for index, key in enumerate(DOMAIN_KEYS):
                name = ('aut' if auth else 'pac') + key + ('z' if zero else '')
                word = 0xdac10000 | (int(auth) << 12) | (int(zero) << 13) | (index << 10) | ((31 if zero else 1) << 5)
                forms.append({'name': name, 'word': word, 'operation': 'authenticate' if auth else 'sign',
                              'key': key, 'destination': 0, 'modifier': 'zero' if zero else 1, 'variable': True})
    for word, name, operation, key, destination, modifier in [
        (0xd503211f, 'pacia1716', 'sign', 'ia', 17, 16), (0xd503215f, 'pacib1716', 'sign', 'ib', 17, 16),
        (0xd503219f, 'autia1716', 'authenticate', 'ia', 17, 16), (0xd50321df, 'autib1716', 'authenticate', 'ib', 17, 16),
        (0xd503233f, 'paciasp', 'sign', 'ia', 30, 'sp'), (0xd503237f, 'pacibsp', 'sign', 'ib', 30, 'sp'),
        (0xd50323bf, 'autiasp', 'authenticate', 'ia', 30, 'sp'), (0xd50323ff, 'autibsp', 'authenticate', 'ib', 30, 'sp'),
        (0xd503231f, 'paciaz', 'sign', 'ia', 30, 'zero'), (0xd503235f, 'pacibz', 'sign', 'ib', 30, 'zero'),
        (0xd503239f, 'autiaz', 'authenticate', 'ia', 30, 'zero'), (0xd50323df, 'autibz', 'authenticate', 'ib', 30, 'zero'),
        (0xdac143e0, 'xpaci', 'strip', 'ia', 0, 'zero'), (0xdac147e0, 'xpacd', 'strip', 'da', 0, 'zero'),
        (0xd50320ff, 'xpaclri', 'strip', 'ia', 30, 'zero'),
        (0xd65f0bff, 'retaa', 'return', 'ia', 30, 'sp'), (0xd65f0fff, 'retab', 'return', 'ib', 30, 'sp')]:
        forms.append({'name': name, 'word': word, 'operation': operation, 'key': key,
                      'destination': destination, 'modifier': modifier, 'variable': name in ('xpaci', 'xpacd')})
    assert len(forms) == 33 and len({f['word'] for f in forms}) == 33
    return forms


def generic_cases():
    for form in basic_forms():
        for variant in range(4):
            for flag in range(16):
                yield dict(form, variant=variant, flag=flag, role='canonical_form')
        if form['variable']:
            for destination in range(32):
                changed = dict(form, destination=destination, word=(form['word'] & ~31) | destination)
                yield dict(changed, variant=1, flag=destination % 16, role='all_destinations')
                if isinstance(form['modifier'], int):
                    changed['modifier'] = destination if destination < 31 else 'sp'
                    changed['word'] = (changed['word'] & ~(31 << 5)) | (destination << 5)
                    yield dict(changed, variant=1, flag=destination % 16, role='aliased_modifier')


def generic_input(case, seed):
    state = initial_state(STOP, 0x2000, seed)
    state.nzcv = case['flag'] << 28
    destination, modifier, operation, key = (case[n] for n in ('destination', 'modifier', 'operation', 'key'))
    if isinstance(modifier, int):
        state.x[modifier] = 0x2000
    raw = [0, STOP, 0x8000000000001400 if key[0] == 'd' else 0xffff800000001400, 1 << 47][case['variant']]
    actual_modifier = 0 if modifier == 'zero' else state.sp if modifier == 'sp' else state.x[modifier]
    if operation in ('authenticate', 'return'):
        raw = domain_sign(STOP if operation == 'return' else (0x8000000000001400 if key[0] == 'd' else STOP), actual_modifier, key)
        if case['variant'] == 1:
            raw ^= 1 << 47
        elif case['variant'] == 2:
            raw ^= 1 << 56  # Wrong tag for data, PAC bit for code; collisions remain explicit.
        elif case['variant'] == 3:
            raw = domain_sign(STOP, actual_modifier, list(DOMAIN_KEYS)[(list(DOMAIN_KEYS).index(key) + 1) % 4])
    if destination != 31:
        state.x[destination] = raw
    return state


def generic_math(case, initial):
    state = State.from_buffer_copy(initial)
    destination, modifier, operation, key = (case[n] for n in ('destination', 'modifier', 'operation', 'key'))
    pointer = 0 if destination == 31 else initial.x[destination]
    modifier = 0 if modifier == 'zero' else initial.sp if modifier == 'sp' else initial.x[modifier]
    authenticated = None
    pc = BASE + 4
    if operation == 'sign':
        value = domain_sign(pointer, modifier, key)
    elif operation in ('authenticate', 'return'):
        value, authenticated = domain_authenticate(pointer, modifier, key)
    else:
        value = domain_strip(pointer, key[0] == 'd')
    if operation == 'return':
        pc = value
    elif destination != 31:
        state.x[destination] = value
    return state, pc, authenticated, pointer


def original_generic(case, initial):
    machine = arm_machine(keys=DOMAIN_KEYS)
    machine.mem_write(BASE, struct.pack('<I', case['word']))
    initialize_arm(machine, initial)
    visited = []
    machine.hook_add(UC_HOOK_CODE, lambda _, pc, size, unused: visited.append([pc, size]))
    error = None
    try:
        machine.emu_start(BASE, BASE + 4, count=1)
    except UcError as exc:
        error = {'code': exc.errno, 'message': str(exc)}
    assert visited == [[BASE, 4]]
    return capture_arm(machine, initial), machine.reg_read(arm.UC_ARM64_REG_PC), error


def generic_descriptor(case):
    operation, key, destination, modifier = (case[n] for n in ('operation', 'key', 'destination', 'modifier'))
    if case['name'] in WORDS:
        value = OPERATIONS[case['name']]
    elif operation == 'return':
        value = 'return_ia_sp'
    elif operation == 'strip':
        value = {'strip': {'data': key[0] == 'd', 'destination': destination}}
    else:
        mod = 'stack_pointer' if modifier == 'sp' else 'zero' if modifier == 'zero' else {'register': modifier}
        value = {operation: {'key': key, 'destination': destination, 'modifier': mod}}
    return {'operation': value, 'instruction_pc': BASE, 'next_pc': BASE + 4}


def validate_generic_native(report, case, initial, expected, pc, authenticated, checksum):
    assert report['kind'] == 'native_block_run' and report['abi'] == ABI
    assert report['software_pauth_profile'] == FULL_PROFILE and not report['complete_binary_verified']
    assert report['source_sha256'] == checksum and report['state'] == state_dict(expected) and report['pc'] == pc
    outcome = report['outcome']
    descriptor = generic_descriptor(case)
    assert outcome['blocks_executed'] == 1 and outcome['last_exit'] == [BASE, 6]
    assert outcome['pointer_authentication_events'] == [{'instruction': descriptor, 'next_pc': pc, 'authenticated': authenticated}]
    if case['operation'] == 'return' and authenticated is False:
        assert outcome['reason'] == {'kind': 'pointer_authentication_poisoned_return', 'instruction': descriptor, 'poisoned_target': pc}
    else:
        assert outcome['reason']['kind'] == 'stop_address'
    assert bytes(initial)[248:] == bytes(expected)[248:]


def generic_cohort(cli, folder, state_path, keys_path):
    records, seen = [], set()
    cache = folder / 'generic-cache'
    for index, case in enumerate(generic_cases()):
        initial = generic_input(case, 0x100000 + index)
        expected, pc, authenticated, pointer = generic_math(case, initial)
        observed, original_pc, error = original_generic(case, initial)
        classification = classify_domain_original(expected, observed, pc, original_pc, case['operation'], case['key'], case['destination'], pointer)
        assert error is None or (case['operation'] == 'return' and authenticated is False and error['code'] in (8, 21))
        source = struct.pack('<I', case['word'])
        source_path = folder / ('generic-' + hex(case['word']) + '.arm64')
        source_path.write_bytes(source)
        state_path.write_text(json.dumps(state_dict(initial)))
        report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path), '--state', str(state_path),
            '--guest-base', hex(BASE), '--stop-pc', hex(pc), '--block-budget', '1', '--software-pauth-keys', str(keys_path),
            '--cache-dir', str(cache)], timeout=15))
        validate_generic_native(report, case, initial, expected, pc, authenticated, digest(source))
        cold = case['word'] not in seen
        assert report['outcome']['compiled_blocks'] == int(cold)
        assert report['outcome']['disk_cache_hits'] == int(not cold)
        seen.add(case['word'])
        records.append({'case': case, 'initial': state_dict(initial), 'classification': classification,
                        'original': state_dict(observed), 'original_pc': original_pc, 'original_error': error,
                        'independent_math': state_dict(expected), 'native': report})
        if (index + 1) % 512 == 0:
            print(f'{index + 1} generic full-key PAuth cases', flush=True)
    negatives = []
    ib_path = folder / 'only-ib.json'
    ib_path.write_text(json.dumps({'low': KEY[0], 'high': KEY[1]}))
    for form in basic_forms():
        source_path = folder / ('negative-' + form['name'] + '.arm64')
        source_path.write_bytes(struct.pack('<I', form['word']))
        initial = generic_input(dict(form, variant=0, flag=15), 0x300000)
        state_path.write_text(json.dumps(state_dict(initial)))
        command = [str(cli), 'run-blocks', str(source_path), '--state', str(state_path), '--guest-base', hex(BASE),
                   '--block-budget', '1', '--cache-dir', str(cache)]
        ordinary = json.loads(subprocess.check_output(command, timeout=15))
        assert ordinary['outcome']['reason']['kind'] == 'unsupported' and ordinary['outcome']['blocks_executed'] == 0
        assert ordinary['state'] == state_dict(initial) and ordinary['pc'] == BASE
        assert ordinary['outcome']['disk_cache_hits'] == 0
        negatives.append({'form': form['name'], 'ordinary': ordinary})
        if form['key'] != 'ib' and form['operation'] != 'strip':
            missing = json.loads(subprocess.check_output([*command, '--software-pauth-ib-key', str(ib_path)], timeout=15))
            assert missing['outcome']['reason'] == {'kind': 'pointer_authentication_key_unavailable',
                'instruction': generic_descriptor(form), 'key': form['key']}
            assert missing['state'] == state_dict(initial) and missing['pc'] == BASE
            assert not missing['outcome'].get('pointer_authentication_events')
            negatives[-1]['missing_key'] = missing
    artifacts = []
    for path in sorted(cache.rglob('manifest.json')):
        raw = path.read_bytes(); manifest = json.loads(raw); native = path.with_name('native.bin').read_bytes()
        assert manifest['identity']['abi'] == ABI and manifest['identity']['guest_base'] == BASE
        assert manifest['source_map'] == [[BASE, 0]] and not manifest['verified']
        assert manifest['native_sha256'] == digest(native) and manifest['native_bytes'] == len(native)
        assert json.loads(path.with_name('manifest.sha256.json').read_bytes()) == digest(raw)
        for words in DOMAIN_KEYS.values():
            assert all(struct.pack('<Q', word) not in native for word in words)
        artifacts.append({'manifest': manifest, 'manifest_sha256': digest(raw)})
    assert len(artifacts) == len(seen)
    return {'negative_profile_checks': negatives, 'cache_receipts': artifacts, 'cases': records, 'canonical_forms': 33, 'native_math_state_comparisons': len(records),
            'original_equal': sum(r['classification'] == 'original_math_native_equal' for r in records),
            'invalid_extension_observations': sum(r['classification'] != 'original_math_native_equal' for r in records),
            'cold_compiles': len(seen), 'disk_hits': len(records) - len(seen)}


SIGNER_BEGIN, SIGNER_END = 0x898c0, 0x89920
METADATA_BASE = 0x90000000000


def branch_cases():
    """Eight architectural forms, all NZCV, every source and modifier role."""
    for link in (False, True):
        for key in ('ia', 'ib'):
            for zero in (False, True):
                operands = [(0, 1), (30, 1), (0, 30), (30, 30), (31, 31)]
                operands += [(r, 31 if zero else r) for r in range(32)]
                if not zero:
                    operands += [(0, r) for r in range(32)]
                for target, rm in sorted(set(operands)):
                    modifier = 'zero' if zero else 'sp' if rm == 31 else rm
                    word = 0xd61f0800 | (int(not zero) << 24) | (int(link) << 21) | (int(key == 'ib') << 10) | (target << 5) | (31 if zero else rm)
                    for flag in range(16):
                        yield {'word': word, 'key': key, 'link': link, 'target': target, 'modifier': modifier, 'flag': flag}


def branch_math(case, initial):
    expected = State.from_buffer_copy(initial)
    pointer = 0 if case['target'] == 31 else initial.x[case['target']]
    modifier = case['modifier']
    modifier = 0 if modifier == 'zero' else initial.sp if modifier == 'sp' else initial.x[modifier]
    target, authenticated = domain_authenticate(pointer, modifier, case['key'])
    if case['link']:
        expected.x[30] = BASE + 4
    return expected, target, authenticated


def branch_cohort(cli, folder, state_path, keys_path):
    rows, seen = [], set()
    for index, case in enumerate(branch_cases()):
        initial = initial_state(STOP, 0x2000, 0x500000 + index)
        initial.nzcv = case['flag'] << 28
        modifier = case['modifier']
        if isinstance(modifier, int):
            initial.x[modifier] = 0x2000
        value = 0 if modifier == 'zero' else initial.sp if modifier == 'sp' else initial.x[modifier]
        if case['target'] != 31:
            initial.x[case['target']] = domain_sign(STOP, value, case['key'])
            if case['flag'] & 1:
                initial.x[case['target']] ^= 1 << 47
        expected, pc, authenticated = branch_math(case, initial)
        original, original_pc, error = original_generic(case, initial)
        assert bytes(original) == bytes(expected) and original_pc == pc, (case, error)
        assert error is None or (authenticated is False and error['code'] in (8, 21))
        path = folder / 'branch.arm64'; path.write_bytes(struct.pack('<I', case['word']))
        state_path.write_text(json.dumps(state_dict(initial)))
        report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(path), '--guest-base', hex(BASE),
            '--stop-pc', hex(pc), '--block-budget', '1', '--state', str(state_path), '--software-pauth-keys', str(keys_path),
            '--cache-dir', str(folder / 'branch-cache')], timeout=15))
        mod = 'zero' if modifier == 'zero' else 'stack_pointer' if modifier == 'sp' else {'register': modifier}
        descriptor = {'operation': {'branch': {'key': case['key'], 'target': case['target'], 'modifier': mod, 'link': case['link']}},
                      'instruction_pc': BASE, 'next_pc': BASE + 4}
        assert report['state'] == state_dict(expected) and report['pc'] == pc
        assert report['source_sha256'] == digest(path.read_bytes()) and report['abi'] == ABI
        assert report['software_pauth_profile'] == FULL_PROFILE and report['complete_binary_verified'] is False
        outcome = report['outcome']
        assert outcome['blocks_executed'] == 1 and outcome['last_exit'] == [BASE, 6]
        assert outcome['pointer_authentication_events'] == [{'instruction': descriptor, 'next_pc': pc, 'authenticated': authenticated}]
        reason = {'kind': 'stop_address'} if authenticated else {'kind': 'pointer_authentication_poisoned_branch', 'instruction': descriptor, 'poisoned_target': pc}
        assert outcome['reason'] == reason
        cold = case['word'] not in seen
        assert outcome['compiled_blocks'] == int(cold) and outcome['disk_cache_hits'] == int(not cold)
        seen.add(case['word'])
        rows.append({'case': case, 'initial': state_dict(initial), 'original': state_dict(original), 'original_pc': pc,
                     'original_error': error, 'native': report})
    return {'canonical_forms': 8, 'original_model_native_full_state_comparisons': len(rows), 'cold_blocks': len(seen),
            'disk_hits': len(rows) - len(seen), 'poisoned_transfers': sum(not r['native']['outcome']['pointer_authentication_events'][0]['authenticated'] for r in rows),
            'cases': rows, 'limits': 'Classic PAuth1: failed calls update X30 before poisoned fetch. GCS/BTI/PSTATE.BTYPE disabled; architectural exception delivery is pending.'}


def signer_math(initial, diversity, key, address_diversity):
    state = State.from_buffer_copy(initial)
    if initial.x[1] == 0:
        state.x[0] = 0
        return state
    blended = (initial.x[2] & ((1 << 48) - 1)) | (diversity << 48)
    modifier = blended if address_diversity else diversity
    state.x[2], state.x[8], state.x[9], state.x[16] = blended, list(DOMAIN_KEYS).index(key), diversity, modifier
    state.x[0] = state.x[17] = domain_sign(initial.x[1], modifier, key)
    state.nzcv = [0x80000000, 0x60000000, 0x60000000, 0x20000000][list(DOMAIN_KEYS).index(key)]
    return state


def original_signer(source, initial, memory):
    machine = arm_machine(keys=DOMAIN_KEYS)
    machine.mem_write(BASE, source)
    machine.mem_map(METADATA_BASE, 4096)
    machine.mem_write(METADATA_BASE, memory)
    machine.mem_protect(METADATA_BASE, 4096, unicorn.UC_PROT_READ)
    initialize_arm(machine, initial)
    visited = []
    machine.hook_add(UC_HOOK_CODE, lambda _, pc, size, unused: visited.append(pc))
    machine.emu_start(BASE, STOP, count=32)
    assert machine.reg_read(arm.UC_ARM64_REG_PC) == STOP and visited[-1] in (BASE + 0x38, BASE + 0x5c)
    assert bytes(machine.mem_read(METADATA_BASE, 4096)) == memory
    return capture_arm(machine, initial), visited



def validate_signer_native(report, expected, source, memory, pointer):
    assert report['state'] == state_dict(expected) and report['pc'] == STOP and report['outcome']['reason']['kind'] == 'stop_address'
    assert report['software_pauth_profile'] == FULL_PROFILE and report['source_sha256'] == digest(source)
    assert report['abi'] == ABI and not report['complete_binary_verified']
    proof = report['memory']; receipt = [{'address': METADATA_BASE, 'bytes': 4096, 'sha256': digest(memory)}]
    assert proof['memory_before'] == receipt and proof['memory_after'] == receipt
    assert proof['memory_reads'] == [{'address': METADATA_BASE, 'bytes': 4096, 'hex': memory.hex()}]
    assert len(report['outcome'].get('pointer_authentication_events', [])) == int(pointer != 0)

def signer_cohort(cli, folder, state_path, keys_path, image):
    source = image[SIGNER_BEGIN:SIGNER_END]
    assert len(source) == 96
    source_path, memory_path = folder / 'original-sign-pointer.arm64', folder / 'memory.json'
    source_path.write_bytes(source)
    records = []
    for key in DOMAIN_KEYS:
        for diversity in (0, 1, 0x8000, 0xffff):
            for address_diversity in (False, True):
                for pointer in (0, STOP, LOW, 0xffff800000001400, 0x8000000000001400, 1 << 47):
                    initial = initial_state(STOP, 0x2000, 0x200000 + len(records))
                    initial.x[0], initial.x[1], initial.x[2], initial.x[30] = METADATA_BASE + 4092, pointer, 0x1000001400, STOP
                    memory = bytearray(b'\xa5' * 4096)
                    struct.pack_into('<I', memory, 4092, diversity | (list(DOMAIN_KEYS).index(key) << 25) | (int(address_diversity) << 27))
                    expected = signer_math(initial, diversity, key, address_diversity)
                    observed, visited = original_signer(source, initial, bytes(memory))
                    classification = 'original_math_native_equal' if bytes(expected) == bytes(observed) else 'invalid_extension_legacy_unicorn_observation'
                    if classification != 'original_math_native_equal':
                        assert pointer != 0 and domain_invalid_extension(pointer, key)
                        # Signer's MOV X0,X17 duplicates the exact legacy difference.
                        corrected = State.from_buffer_copy(observed)
                        delta = (1 << 54) if key[0] == 'd' else ((1 << 62) | (1 << 63))
                        corrected.x[0] ^= delta; corrected.x[17] ^= delta
                        assert bytes(corrected) == bytes(expected)
                    state_path.write_text(json.dumps(state_dict(initial)))
                    memory_path.write_text(json.dumps({'regions': [{'guest_address': METADATA_BASE, 'virtual_bytes': 4096,
                        'initial_bytes': list(memory), 'readable': True, 'writable': False}]}))
                    report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path), '--state', str(state_path),
                        '--guest-base', hex(BASE), '--stop-pc', hex(STOP), '--block-budget', '16', '--software-pauth-keys', str(keys_path),
                        '--memory', str(memory_path), '--read-memory', f'{hex(METADATA_BASE)}:4096', '--cache-dir', str(folder / 'signer-cache')], timeout=15))
                    validate_signer_native(report, expected, source, memory, pointer)
                    records.append({'key': key, 'diversity': diversity, 'address_diversity': address_diversity, 'pointer': pointer,
                        'classification': classification, 'initial': state_dict(initial), 'original': state_dict(observed),
                        'original_instruction_pcs': visited, 'independent_math': state_dict(expected), 'native': report})
    return {'original_slice_offset': SIGNER_BEGIN, 'original_bytes': len(source), 'source_sha256': digest(source),
            'native_math_full_state_ram_comparisons': len(records), 'cases': records,
            'limits': ['Unchanged complete original signPointer executes, not the entire chained-fixup loop. Null input returns without reading metadata or executing PAC.']}


def original_fixup_slots(image, load_base):
    segments, payload = [], None
    cursor = 32
    for _ in range(struct.unpack_from('<I', image, 16)[0]):
        command, size = struct.unpack_from('<II', image, cursor)
        assert size >= 8 and cursor + size <= len(image)
        if command == 0x19:
            name, vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<16s4Q', image, cursor + 8)
            segments.append((name.rstrip(b'\0').decode(), vmaddr, vmsize, fileoff, filesize))
        elif command == 0x80000034:
            offset, extent = struct.unpack_from('<II', image, cursor + 8)
            payload = image[offset:offset + extent]
            assert len(payload) == extent
        cursor += size
    assert payload is not None
    version, starts, imports, symbols, count, import_format, symbol_format = struct.unpack_from('<7I', payload)
    assert (version, count, symbol_format) == (0, 0, 0)
    segcount = struct.unpack_from('<I', payload, starts)[0]
    assert segcount == len(segments)
    records, seen = [], set()
    for segment_index in range(segcount):
        delta = struct.unpack_from('<I', payload, starts + 4 + 4 * segment_index)[0]
        if not delta:
            continue
        segment = starts + delta
        size, page_bytes, pointer_format, segment_offset, max_valid, page_count = struct.unpack_from('<IHHQIH', payload, segment)
        assert pointer_format == 12 and size >= 22 + page_count * 2 and segment + size <= len(payload)
        name, vmaddr, vmsize, fileoff, filesize = segments[segment_index]
        assert vmaddr == segment_offset
        for page in range(page_count):
            offset = struct.unpack_from('<H', payload, segment + 22 + 2 * page)[0]
            if offset == 0xffff:
                continue
            assert offset < page_bytes and not offset & 0x8000
            while True:
                within = page * page_bytes + offset
                position, slot = fileoff + within, load_base + segment_offset + within
                assert within + 8 <= filesize and offset + 8 <= page_bytes and slot not in seen
                seen.add(slot)
                raw = struct.unpack_from('<Q', image, position)[0]
                assert not raw & (1 << 62)
                record = {'segment_index': segment_index, 'file_offset': position, 'guest_address': slot, 'raw': raw, 'pointer_format': pointer_format}
                if raw >> 63:
                    authentication = {'key': list(DOMAIN_KEYS)[(raw >> 49) & 3], 'diversity': (raw >> 32) & 0xffff,
                                      'address_diversity': bool((raw >> 48) & 1)}
                    record.update(target=load_base + (raw & 0xffffffff), authentication=authentication)
                else:
                    assert (raw >> 43) & 0xff == 0
                    record['value'] = load_base + (raw & ((1 << 43) - 1))
                records.append(record)
                advance = (raw >> 51) & 0x7ff
                if not advance:
                    break
                offset += advance * 8
    assert len(records) == 2568 and sum('authentication' in r for r in records) == 1324
    return records


def fixup_plan_cohort(cli, folder, keys_path, image, dyld_path):
    records = []
    source = image[SIGNER_BEGIN:SIGNER_END]
    for load_base in (0x40000000000, 0x40000004000):
        slots = original_fixup_slots(image, load_base)
        report = json.loads(subprocess.check_output([str(cli), 'plan-fixups', str(dyld_path), '--image-base', hex(load_base),
            '--software-pauth-keys', str(keys_path)], timeout=30))
        decoded, signed = report['decoded_fixups'], report['fixups']
        plain = [r for r in slots if 'authentication' not in r]
        authenticated = [r for r in slots if 'authentication' in r]
        assert decoded['rebases'] == plain and decoded['authenticated_rebases'] == authenticated
        assert not decoded['binds'] and not decoded.get('authenticated_binds') and not decoded['imports']
        assert signed['rebases'] == plain and signed['pauth_profile'] == FULL_PROFILE and signed['address_space'] == 1
        expected_signed, original_equal = [], 0
        for fixup in authenticated:
            auth = fixup['authentication']; diversity = auth['diversity']; address_diversity = auth['address_diversity']; key = auth['key']
            modifier = ((fixup['guest_address'] & ((1 << 48) - 1)) | (diversity << 48)) if address_diversity else diversity
            value = domain_sign(fixup['target'], modifier, key)
            initial = initial_state(STOP, 0x2000, fixup['file_offset'])
            initial.x[0], initial.x[1], initial.x[2], initial.x[30] = METADATA_BASE, fixup['target'], fixup['guest_address'], STOP
            memory = bytearray(4096)
            struct.pack_into('<I', memory, 0, diversity | (list(DOMAIN_KEYS).index(key) << 25) | (int(address_diversity) << 27))
            observed, visited = original_signer(source, initial, bytes(memory))
            assert bytes(observed) == bytes(signer_math(initial, diversity, key, address_diversity)) and observed.x[0] == value
            original_equal += 1
            expected_signed.append({'fixup': fixup, 'modifier': modifier, 'value': value})
        assert signed['authenticated_rebases'] == expected_signed
        records.append({'load_base': load_base, 'original_raw_slots': slots, 'signed_expected': expected_signed,
                        'original_signer_equal': original_equal, 'native_plan': report})
    return {'placements': records, 'raw_slots_checked': 5136, 'original_signer_checks': 2648,
            'limits': ['Raw original descriptors and unchanged signPointer verify plans; no memory patching, binds, complete original fixup-loop or process claim.']}


GENERIC_CODE_WORD_MASK = 0xffe0fc00
GENERIC_CODE_OPCODE = 0x9ac03000
GENERIC_CODE_EXIT_BYTES = 16
GENERIC_CODE_EXIT_INSTRUCTIONS = 3
PAUTH_EXIT_KIND = 6
A64_INSTRUCTION_BYTES = 4
A64_SVC_MASK = 0xffe0001f
A64_SVC_OPCODE = 0xd4000001
A64_SVC_IMMEDIATE_SHIFT = 5
A64_SVC_IMMEDIATE_MASK = 0xffff
A64_SVC_EXCEPTION_CLASS = 0x15
A64_ESR_CLASS_SHIFT = 26
A64_ESR_INSTRUCTION_LENGTH = 1 << 25
A64_MODE_MASK = 31
ELF_AARCH64_MACHINE = 183
ELF_LOAD_SEGMENT = 1
ELF_PROGRAM_OFFSET = 32
ELF_PROGRAM_SIZE_OFFSET = 54
ELF_PROGRAM_COUNT_OFFSET = 56
ORIGINAL_INPUT_PREFIX_BYTES = 8
PAUTH_FEATURE_FIELDS = {
    'APA': ('ID_AA64ISAR1_EL1', 4), 'API': ('ID_AA64ISAR1_EL1', 8),
    'GPA': ('ID_AA64ISAR1_EL1', 24), 'GPI': ('ID_AA64ISAR1_EL1', 28),
    'APA3': ('ID_AA64ISAR2_EL1', 12), 'GPA3': ('ID_AA64ISAR2_EL1', 8),
}
PAUTH_FEATURE_MASK = 15


def generic_code_audit(corpus, native_run):
    """Audit raw original frames and actual public-runtime blocks, without a producer model."""
    import simd_original as observer
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import X86_OP_IMM, X86_OP_REG, X86_REG_RAX, X86_REG_EDX

    corpus, native_run = Path(corpus).resolve(), Path(native_run).resolve()
    cases = json.loads((corpus / 'cases.json').read_bytes())
    functions = json.loads((corpus / 'functions.json').read_bytes())
    subjects = json.loads((corpus / 'subjects.json').read_bytes())
    profile = json.loads((corpus / 'profile.json').read_bytes())
    build = json.loads((corpus / 'build-receipt.json').read_bytes())
    receipt = json.loads((corpus / 'validation-receipt.json').read_bytes())
    report = json.loads((native_run / 'report.json').read_bytes())
    assert receipt['passed'] and report['passed'] and profile['kind'] == 'pacga'
    inputs, originals, ram, elf = [(corpus / name).read_bytes()
                                    for name in ('inputs.bin', 'results.bin', 'memory.bin', 'guest.elf')]
    assert digest((corpus / 'build-receipt.json').read_bytes()) == receipt['build_receipt_sha256']
    assert digest(elf) == build['elf_sha256'] and digest(originals) == receipt['results_sha256']
    assert digest(Path(build['qemu_binary']).read_bytes()) == build['qemu_binary_sha256']
    assert elf[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', elf, 18)[0] == ELF_AARCH64_MACHINE
    phoff, phsize, phcount = struct.unpack_from('<Q', elf, ELF_PROGRAM_OFFSET)[0], struct.unpack_from('<H', elf, ELF_PROGRAM_SIZE_OFFSET)[0], struct.unpack_from('<H', elf, ELF_PROGRAM_COUNT_OFFSET)[0]
    segments = [struct.unpack_from('<II6Q', elf, phoff + i * phsize) for i in range(phcount)]
    for index, subject in enumerate(subjects):
        operation = functions[index]['operations'][0]
        word = operation['word']
        assert word & GENERIC_CODE_WORD_MASK == GENERIC_CODE_OPCODE
        pc = subject['instruction_pc']
        matching = [segment for segment in segments if segment[0] == ELF_LOAD_SEGMENT and segment[3] <= pc and pc + 8 <= segment[3] + segment[5]]
        assert len(matching) == 1
        segment = matching[0]
        offset = segment[2] + pc - segment[3]
        assert offset == subject['elf_offset']
        actual = elf[offset:offset + 8]
        assert actual.hex() == subject['executed_source_hex'] and digest(actual) == subject['executed_source_sha256']
        canonical = struct.pack('<2I', word, observer.RET_WORD)
        assert canonical.hex() == functions[index]['source_hex'] == subject['canonical_source_hex']
        assert digest(canonical) == subject['canonical_source_sha256']
        assert struct.unpack_from('<I', actual)[0] == word
        svc = struct.unpack_from('<I', actual, 4)[0]
        assert svc & A64_SVC_MASK == A64_SVC_OPCODE
    controls = dict(zip(observer.MEMORY_CONTROLS, struct.unpack_from('<4Q', originals, observer.MEMORY_CONTROL_HEADER_OFFSET)))
    assert controls == profile['controls'] == receipt['controls']
    key_names = [f'APD{side}Key{half}_EL1' for side in ('A', 'B') for half in ('Lo', 'Hi')]
    key_names += ['APGAKeyLo_EL1', 'APGAKeyHi_EL1']
    assert struct.unpack_from('<6Q', originals, profile['key_header_offset']) == tuple(profile['keys'][name] for name in key_names)
    ids = dict(zip(observer.CPU_REGISTERS, struct.unpack_from('<9Q', originals)))
    features = {name: (ids[register] >> shift) & PAUTH_FEATURE_MASK
                for name, (register, shift) in PAUTH_FEATURE_FIELDS.items()}
    assert features == profile['feature_requirement'] == receipt['features'] and features['GPA'] == 1
    stride = observer.RECORD_BYTES + len(ram)
    assert len(originals) == observer.HEADER_BYTES + len(cases) * stride
    assert len(inputs) == len(cases) * observer.INPUT_STRIDE
    states = []
    for index, case in enumerate(cases):
        assert struct.unpack_from('<Q', inputs, index * observer.INPUT_STRIDE)[0] == case['function_index']
        begin = index * observer.INPUT_STRIDE + ORIGINAL_INPUT_PREFIX_BYTES
        before = State.from_buffer_copy(inputs[begin:begin + ctypes.sizeof(State)])
        assert digest(bytes(before)) == case['initial_state_sha256']
        start = observer.HEADER_BYTES + index * stride
        frame = originals[start:start + observer.RECORD_BYTES]
        observed = State.from_buffer_copy(before)
        observed.x[:] = struct.unpack_from('<31Q', frame)
        observed.sp = struct.unpack_from('<Q', frame, observer.LAYOUT['sp'])[0]
        spsr = struct.unpack_from('<Q', frame, observer.LAYOUT['spsr'])[0]
        assert spsr & A64_MODE_MASK == 0
        observed.nzcv = spsr & observer.NZCV_MASK
        for register in range(32):
            observed.v[register][:] = struct.unpack_from('<2Q', frame, observer.LAYOUT['v'] + register * 16)
        observed.fpcr = struct.unpack_from('<Q', frame, observer.LAYOUT['fpcr'])[0]
        observed.fpsr = struct.unpack_from('<Q', frame, observer.LAYOUT['fpsr'])[0]
        assert (before.fpcr, before.fpsr) == struct.unpack_from('<2Q', frame, observer.LAYOUT['pre_fpcr'])
        subject = subjects[case['function_index']]
        esr, elr = struct.unpack_from('<2Q', frame, observer.LAYOUT['esr'])
        svc = struct.unpack_from('<I', elf, subject['elf_offset'] + 4)[0]
        assert esr == (A64_SVC_EXCEPTION_CLASS << A64_ESR_CLASS_SHIFT) | A64_ESR_INSTRUCTION_LENGTH | ((svc >> A64_SVC_IMMEDIATE_SHIFT) & A64_SVC_IMMEDIATE_MASK)
        assert elr == subject['instruction_pc'] + 8 == subject['expected_elr']
        assert receipt['cases'][index]['classification'] == 'direct_original'
        assert digest(bytes(observed)) == receipt['cases'][index]['state_sha256']
        assert originals[start + observer.RECORD_BYTES:start + stride] == ram
        states.append(bytes(observed))
    inventory = json.loads((native_run / 'emission-inventory.json').read_bytes())
    assert len(inventory) == len(functions)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    for index, row in inventory.items():
        index = int(index)
        manifest = row['manifest']
        identity = manifest['identity']
        code = bytes.fromhex(row['native_hex'])
        directory = Path(row['directory'])
        raw_manifest = (directory / 'manifest.json').read_bytes()
        assert digest(raw_manifest) == row['manifest_sha256'] == json.loads((directory / 'manifest.sha256.json').read_bytes())
        assert json.loads(raw_manifest) == manifest and (directory / 'native.bin').read_bytes() == code
        assert not manifest['verified'] and identity['abi'] == ABI and identity['target_cpu'] == 'x86_64-baseline'
        assert identity['compiler_source_sha256'] == report['compiler_sha256']
        assert identity['source_sha256'] == digest(struct.pack('<I', functions[index]['operations'][0]['word']))
        assert manifest['native_sha256'] == digest(code) and manifest['native_bytes'] == len(code) == GENERIC_CODE_EXIT_BYTES
        assert manifest['source_map'] == [[identity['guest_base'], 0]]
        assert row['checked_manifest']['native_sha256'] == digest(code)
        assert row['checked_manifest']['source_map'] == manifest['source_map']
        instructions = list(decoder.disasm(code, 0))
        assert len(instructions) == GENERIC_CODE_EXIT_INSTRUCTIONS and sum(i.size for i in instructions) == len(code)
        assert [i.mnemonic for i in instructions] == ['movabs', 'mov', 'ret']
        first, second, last = instructions
        assert first.operands[0].type == X86_OP_REG and first.operands[0].reg == X86_REG_RAX
        assert first.operands[1].type == X86_OP_IMM and first.operands[1].imm == identity['guest_base']
        assert second.operands[0].type == X86_OP_REG and second.operands[0].reg == X86_REG_EDX
        assert second.operands[1].type == X86_OP_IMM and second.operands[1].imm == PAUTH_EXIT_KIND and not last.operands
    expected_cache = {'cold': (len(functions), 0, len(cases) - len(functions)), 'hot': (0, 0, len(cases)),
                      'disk': (0, len(functions), len(cases) - len(functions)), 'aot': (0, len(functions), len(cases) - len(functions))}
    total = 0
    assert {phase['phase'] for phase in report['phases']} == set(expected_cache)
    for phase in report['phases']:
        native = (native_run / (phase['phase'] + '-states.bin')).read_bytes()
        assert native == b''.join(states) and digest(native) == phase['native_states_sha256']
        outcomes = json.loads((native_run / (phase['phase'] + '-outcomes.json')).read_bytes())
        assert len(outcomes) == len(cases)
        for index, row in enumerate(outcomes):
            operation = functions[cases[index]['function_index']]['operations'][0]
            body = inventory[str(cases[index]['function_index'])]['manifest']
            pc = body['identity']['guest_base']
            outcome = row['outcome']
            assert row['case'] == index and row['pc'] == pc + A64_INSTRUCTION_BYTES and row['state_sha256'] == digest(states[index])
            assert outcome['reason'] == {'kind': 'stop_address'} and outcome['last_exit'] == [pc, PAUTH_EXIT_KIND]
            assert outcome['blocks_executed'] == 1 and outcome['floating_point_helpers'] == 0
            assert outcome['pointer_authentication_events'] == [{'authenticated': None, 'instruction': {
                'instruction_pc': pc, 'next_pc': pc + A64_INSTRUCTION_BYTES, 'operation': {'generic_code': {
                    'destination': operation['d'], 'source': operation['n'], 'modifier': operation['m']}}}, 'next_pc': pc + A64_INSTRUCTION_BYTES}]
        counts = tuple(sum(row['outcome'][key] for row in outcomes) for key in ('compiled_blocks', 'disk_cache_hits', 'memory_cache_hits'))
        assert counts == expected_cache[phase['phase']]
        assert counts == tuple(phase[key] for key in ('compiled_blocks', 'disk_cache_hits', 'memory_cache_hits'))
        total += len(states)
    sources = [Path(__file__), ROOT / 'dev/differential.py', ROOT / 'dev/simd_original.py',
               ROOT / 'crates/stela-runtime/tests/pointer_authentication/corpus.rs']
    return {'kind': 'original_arm_generic_pac_vs_native_runtime', 'passed': True, 'abi': ABI,
            'compiler_source_sha256': report['compiler_sha256'], 'profile': report['profile'],
            'harness_source_sha256': digest(Path(__file__).read_bytes()),
            'sources_sha256': {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in sources},
            'canonical_forms': 1, 'raw_original_frames': len(cases), 'state_comparisons': total,
            'actual_emitted_bodies': len(inventory), 'baseline_checked_byte_bridges': len(inventory),
            'body_bytes_including_ret': GENERIC_CODE_EXIT_BYTES, 'body_instructions_including_ret': GENERIC_CODE_EXIT_INSTRUCTIONS,
            'phases': report['phases'], 'original_controls': controls, 'original_features': features,
            'external_input_sha256': {str(corpus / name): digest((corpus / name).read_bytes()) for name in
                                      ('cases.json', 'functions.json', 'inputs.bin', 'results.bin', 'guest.elf',
                                       'profile.json', 'build-receipt.json', 'validation-receipt.json')},
            'runtime_report_sha256': digest((native_run / 'report.json').read_bytes()),
            'limits': ['Original QEMU EL0 QARMA5 GA execution, not Apple hardware key identity.',
                       f'PACGA is memory-free; original {len(ram)}-byte RAM snapshots stay unchanged.',
                       'Full State includes raw X30, NZCV, FP/SIMD and requested control readbacks.',
                       'No complete process, application, exception delivery or performance claim.']}


def generic_code_cohort(args, parser):
    if args.generic_code_originals is None or args.generic_code_run is None:
        parser.error('--generic-code requires --generic-code-originals and a fresh/existing --generic-code-run')
    if args.generic_code_test_executable is not None:
        if args.generic_code_run.exists():
            parser.error('--generic-code-test-executable requires a fresh --generic-code-run')
        environment = os.environ.copy()
        environment['STELA_PAUTH_ORIGINALS'] = str(args.generic_code_originals.resolve())
        environment['STELA_PAUTH_NATIVE_OUTPUT'] = str(args.generic_code_run.resolve())
        subprocess.run([str(args.generic_code_test_executable.resolve()), '--ignored', '--exact',
                        'corpus::generic_code_original_corpus', '--nocapture'], env=environment, check=True)
    result = generic_code_audit(args.generic_code_originals, args.generic_code_run)
    output = args.output or ROOT / '.stela/pacga-differential-report.json'
    snapshot = write_evidence(output, result)
    print(json.dumps({'passed': True, 'state_comparisons': result['state_comparisons'],
                      'report': str(output), 'snapshot': str(snapshot)}, indent=2))



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--generic-code', action='store_true', help='verify the separate batched PACGA original/runtime cohort')
    parser.add_argument('--generic-code-originals', type=Path, help='independently captured full-State PACGA corpus')
    parser.add_argument('--generic-code-run', type=Path, help='native cohort output directory (fresh when executing)')
    parser.add_argument('--generic-code-test-executable', type=Path, help='built consolidated pointer_authentication test binary; omit to audit an existing run')
    parser.add_argument('--generic-pauth', action='store_true', help='also verify all33 basic PAC forms, original dyld signer and authenticated fixup plans')
    parser.add_argument('--executable', type=Path, action='append', default=[])
    parser.add_argument('--bootstrap-clock', action='store_true', help='also verify the complete original mach_continuous_time startup call')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.generic_code:
        generic_code_cohort(args, parser)
        return
    args.output = args.output or ROOT / '.stela/pauth-differential-report.json'
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
    if args.generic_pauth:
        sources += [ROOT / 'src/macho/chained_fixups.rs', ROOT / 'src/macho/load_plan.rs']
    pins = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources}
    cli_hash = digest(cli.read_bytes())
    records = []
    integrated = []
    clock_integrated = []
    clock_manifests = []
    clock_register_cases, clock_register_manifests = [], []
    generic, signer, fixups, branches = None, None, None, None
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
        if args.generic_pauth:
            keys_path = folder / 'keys.json'
            keys_path.write_text(json.dumps({key: {'low': values[0], 'high': values[1]} for key, values in DOMAIN_KEYS.items()}))
            generic = generic_cohort(cli, folder, state_path, keys_path)
            dyld_suite = importlib.import_module('dyld-entry-differential')
            container = dyld_suite.DEFAULT_DYLD.read_bytes()
            assert digest(container) == dyld_suite.CONTAINER_SHA256
            offset, image = dyld_suite.classic_slice(container)
            assert offset == dyld_suite.SLICE_OFFSET and digest(image) == dyld_suite.SLICE_SHA256
            signer = signer_cohort(cli, folder, state_path, keys_path, image)
            branches = branch_cohort(cli, folder, state_path, keys_path)
            fixups = fixup_plan_cohort(cli, folder, keys_path, image, dyld_suite.DEFAULT_DYLD)
            assert digest(dyld_suite.DEFAULT_DYLD.read_bytes()) == dyld_suite.CONTAINER_SHA256
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
              'generic_pauth': generic, 'original_sign_pointer': signer, 'authenticated_fixup_plan': fixups,
              'authenticated_branches': branches,
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
                         'Optional generic cohort covers33 basic IA/IB/DA/DB PAC/AUT/XPAC/RET forms and eight authenticated branch/call forms; PACGA is verified by the separate --generic-code cohort; unreviewed system controls remain unsupported. Data signing invalid-extension differences classify exact bit54 versus older Unicorn bit55 insertion behavior, not equality.',
                         'MRS Rt31 discardedvalue is unobservable; the unchangedinstruction executes and fullstate preservation is checked, while native event replays a separatelyrecorded postinstruction counter sample. Other31Rt replay actualMRSdestination results.',
                         'Optional clock bootstrap executes44 originalinstructions, twoPACsigns+RETAB, actualISB/CNTVCT, allnine stores and restoredframe. Counterreplay provesopaque input effects; original62500000Hz and nativevirtual1GHz rates are not equated. Nativehost samples are separatelybounded by publicmach_continuous_time.',
                         'PAC-only vectors do not access guest RAM; complete clock probes compare every stack byte and all readable image/clock views. Full784B state is checked throughout; no full OS process, Apple hardware or performance claim.']}
    snapshot = write_evidence(args.output, result)
    print(json.dumps({'passed': True, 'three_way': equal, 'native_math': len(records), 'divergences': divergent,
                      'report': str(args.output), 'snapshot': str(snapshot)}, indent=2))


if __name__ == '__main__':
    main()
