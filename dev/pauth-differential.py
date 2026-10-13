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
    image = executable.read_bytes()
    assert image[:4] == b'\xcf\xfa\xed\xfe'
    header = struct.unpack_from('<8I', image)
    assert report['kind'] == 'original_dyld_startup_prefix_probe' and report['schema_version'] == 1
    assert report['complete_binary_verified'] is False and report['fixups_applied'] is False and report['native_executed'] is True
    assert report['compiler_source_sha256'] == compiler and report['abi'] == ABI
    assert report['software_pauth_profile'] == PROFILE and report['pauth_instruction_executed'] is True
    assert report['main']['container_sha256'] == digest(image) and report['main']['slice_offset'] == 0
    main = report['main']['plan']
    assert main['slice_sha256'] == digest(image) and main['slice_bytes'] == len(image)
    assert (main['cpu_type'], main['cpu_subtype'], main['file_type'], main['header_flags']) == header[1:4] + (header[6],)
    dyld = report['dyld']
    assert dyld['container_sha256'] == dyld_suite.CONTAINER_SHA256 and dyld['slice_offset'] == dyld_suite.SLICE_OFFSET
    assert dyld['plan']['image']['slice_sha256'] == dyld_suite.SLICE_SHA256 and dyld['plan']['image']['file_type'] == 7
    raw = view['thread_command']
    thread = dyld['plan']['thread']
    assert thread['raw_command_hex'] == raw.hex() and thread['raw_command_sha256'] == digest(raw)
    assert (thread['flavor'], thread['count']) == (6, 68) and thread['x'] == list(struct.unpack_from('<31Q', raw, 16))
    assert (thread['sp'], thread['pc'], thread['cpsr'], thread['pad']) == struct.unpack_from('<QQII', raw, 264)
    assert report['process_arguments'] == arguments
    dyld_suite.audit_arguments(report, executable, arguments)
    initial = State()
    initial.x[:] = thread['x']
    initial.sp, initial.nzcv = report['arguments']['raw_sp'], thread['cpsr']
    for vector in initial.v:
        vector[:] = [0, 0]
    initial.fpcr = initial.fpsr = 0
    assert report['initial_state'] == state_dict(initial)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--executable', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/pauth-differential-report.json')
    args = parser.parse_args()
    if not args.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    sources = [Path(__file__), ROOT / 'dev/differential.py', ROOT / 'crates/stela-runtime/src/pauth.rs',
               ROOT / 'crates/stela-runtime/src/blocks.rs', ROOT / 'src/main.rs',
               ROOT / 'dev/dyld-entry-differential.py', ROOT / 'src/dyld_entry.rs',
               ROOT / 'crates/stela-runtime/src/process.rs']
    pins = {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sources}
    cli_hash = digest(cli.read_bytes())
    records = []
    integrated = []
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
                assert digest(executable.read_bytes()) == input_hash
            assert digest(dyld_suite.DEFAULT_DYLD.read_bytes()) == dyld_suite.CONTAINER_SHA256
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
              'limits': ['Explicit software QARMA5 classic PAuth1 IB/SP profile, not Apple hardware bit identity or complete arm64e support.',
                         'Native executes original scalar prefix then explicit PAC runtime boundary; cryptography is a software helper, not inline native PAC.',
                         'Authentication failures poison pointers; RETAB typed stop records pending instruction-fetch exception delivery.',
                         'Noncanonical signing: June2026 ASL corrupts bit62, older Unicorn2.1.4 corrupts bit63;64 exact classified observations are not counted as three-way equality.',
                         'Generic IA/DA/DB/PACGA/XPAC remain oracle-only, outside the three production instruction forms.',
                         'All784B state including dirty V/FP and scalar prefix verified; no guest memory access, OS process, Apple hardware or performance claim.']}
    snapshot = write_evidence(args.output, result)
    print(json.dumps({'passed': True, 'three_way': equal, 'native_math': len(records), 'divergences': divergent,
                      'report': str(args.output), 'snapshot': str(snapshot)}, indent=2))


if __name__ == '__main__':
    main()
