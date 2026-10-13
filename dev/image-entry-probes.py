#!/usr/bin/env python3
"""Check real true/false ARM64e entry blocks, not complete process loading.

Uses the prebuilt CLI only. The structural plan selects source bytes; original
Unicorn execution includes the real RET and is compared with native guest state.
Apple dependencies, signatures, fixups and process setup remain unresolved.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import time

from differential import ROOT, State, states
from evidence import write_evidence

STOP = 0xffff0000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def invoke(cli, *arguments):
    started = time.perf_counter_ns()
    result = subprocess.run([str(cli), *map(str, arguments)], check=True, capture_output=True, text=True)
    return json.loads(result.stdout), time.perf_counter_ns() - started


def original_helpers():
    path = ROOT / 'dev/block-differential.py'
    spec = importlib.util.spec_from_file_location('stela_block_reference', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_run(report, expected, expected_pc, context):
    require(report['complete_binary_verified'] is False, f'{context}: invalid full-binary claim')
    require(report['pc'] == expected_pc, f'{context}: wrong guest PC')
    require(report['state'] == expected, f'{context}: register/state mismatch')
    require(report['outcome']['reason'] == {'kind': 'stop_address'}, f'{context}: no return stop')
    require(report['outcome']['blocks_executed'] == 1, f'{context}: unexpected block count')
    require(report['outcome']['last_exit'] == [STOP, 4], f'{context}: no architectural RET exit')


def check_image(cli, path, exit_status, work, reference):
    preflight, _ = invoke(cli, 'plan-executable', path, '--architecture', 'arm64e')
    container = path.read_bytes()
    preflight_plan = preflight['plan']
    start = preflight['slice_offset']
    thin = container[start:start + preflight_plan['slice_bytes']]
    require(digest(container) == preflight['container_sha256'] and digest(thin) == preflight_plan['slice_sha256'], 'preflight input identity mismatch')
    offset = preflight_plan['entry']['file_offset']
    entry_pc = preflight_plan['entry']['guest_address']
    require(any(segment['initial_protection'] & 4
                and segment['guest']['address'] <= entry_pc
                and entry_pc + 8 <= segment['guest']['address'] + segment['file']['bytes']
                for segment in preflight_plan['segments']), 'entry pair is not fully file-backed executable code')
    known_source = struct.pack('<II', 0x52800000 | exit_status << 5, 0xd65f03c0)
    require(thin[offset:offset + 8] == known_source, 'entry changed: refusing native image probe before bounded MOV/RET check')
    cache = work / (path.name + '-image-cache')
    cold, cold_ns = invoke(cli, 'probe-image-entry', path, '--architecture', 'arm64e', '--stop-pc', hex(STOP), '--cache-dir', cache)
    warm, warm_ns = invoke(cli, 'probe-image-entry', path, '--architecture', 'arm64e', '--stop-pc', hex(STOP), '--cache-dir', cache)
    require(cold['outcome']['compiled_blocks'] == 1 and cold['outcome']['disk_cache_hits'] == 0, 'image cold translation did not compile once')
    require(warm['outcome']['compiled_blocks'] == 0 and warm['outcome']['disk_cache_hits'] == 1, 'image warm translation did not reuse disk cache')
    require(cold['plan'] == warm['plan'] == preflight_plan, 'preflight/cold/warm load plans differ')
    plan = cold['plan']
    require(plan['execution_supported'] is False and plan['unresolved_requirements'], 'pending loader work disappeared')
    require(plan['architecture'] == 'arm64e', 'expected the selected Apple ARM64e slice')
    require(digest(container) == cold['container_sha256'] == warm['container_sha256'], 'input changed after CLI read')
    start = cold['slice_offset']
    thin = container[start:start + plan['slice_bytes']]
    require(len(thin) == plan['slice_bytes'] and digest(thin) == plan['slice_sha256'], 'selected slice identity mismatch')
    entry = plan['entry']
    segment = next(segment for segment in plan['segments']
                   if segment['initial_protection'] & 4
                   and segment['guest']['address'] <= entry['guest_address']
                   < segment['guest']['address'] + segment['file']['bytes'])
    available = segment['file']['offset'] + segment['file']['bytes'] - entry['file_offset']
    window = thin[entry['file_offset']:entry['file_offset'] + min(1024, available // 4 * 4)]
    window_path = work / (path.name + '-entry-window.bin')
    window_path.write_bytes(window)
    compiled, _ = invoke(cli, 'compile-block', window_path, '--guest-base', hex(entry['guest_address']), '--output-dir', work / (path.name + '-aot'))
    require(compiled['compiler_source_sha256'] == cold['compiler_source_sha256'] == warm['compiler_source_sha256'], 'compiler changed between image/AOT probes')
    source = window[:compiled['source_bytes']]
    require(digest(source) == compiled['source_sha256'], 'consumed source identity mismatch')
    # Keep this harness explicitly bounded to these known constant-return entries.
    # It is unsafe to run an arbitrary process entry without its data/ABI mappings.
    require(source == known_source, 'entry changed: expected original MOV W0,#status; RET X30')
    source_path = work / (path.name + '-entry.bin')
    source_path.write_bytes(source)
    case = {'base': entry['guest_address'], 'source_bytes': len(source),
            'words': list(struct.unpack('<II', source))}
    # This command uses GuestState::default(), whereas State() deliberately
    # dirties SIMD/FP fields for the explicit-state preservation cases below.
    initial = State.from_buffer_copy(bytes(ctypes.sizeof(State)))
    initial.x[30] = STOP
    machine = reference.machine_for({case['base']: case}, initial)
    expected, pc = reference.original_block(machine, case, initial.reserved)
    require(pc == STOP and expected['x'][0] == exit_status, 'original entry did not return expected status')
    default_expected = expected
    validate_run(cold, expected, pc, path.name + ' image cold')
    validate_run(warm, expected, pc, path.name + ' image warm')
    comparisons = []
    raw_cache = work / (path.name + '-raw-cache')
    for index, initial in enumerate(states(all_flags=True)):
        initial.sp = 0x1234000056780000  # Aligned, never dereferenced by these entries.
        initial.reserved = 0xa5c39e71
        initial.x[30] = STOP
        state_path = work / (path.name + '-state.json')
        initial_json = reference.snapshot(initial)
        state_path.write_text(json.dumps(initial_json) + '\n')
        machine = reference.machine_for({case['base']: case}, initial)
        expected, pc = reference.original_block(machine, case, initial.reserved)
        native, elapsed_ns = invoke(cli, 'run-blocks', source_path, '--guest-base', hex(case['base']),
                                    '--state', state_path, '--stop-pc', hex(STOP), '--cache-dir', raw_cache)
        validate_run(native, expected, pc, f'{path.name} flags {index}')
        require(native['compiler_source_sha256'] == cold['compiler_source_sha256'], 'compiler changed during probes')
        comparisons.append({'initial': initial_json, 'original_state': expected, 'original_pc': pc,
                            'native': native, 'cli_elapsed_ns': elapsed_ns})
    host = subprocess.run(['/usr/bin/arch', '-x86_64', str(path)], capture_output=True)
    require(host.returncode == exit_status and not host.stdout and not host.stderr, 'host x86_64 executable behavior differs')
    require(digest(path.read_bytes()) == digest(container), 'input changed during native/reference probes')
    return {'path': str(path), 'container_sha256': digest(container), 'slice_sha256': digest(thin),
            'entry_guest_address': case['base'], 'entry_file_offset': entry['file_offset'],
            'entry_bytes': len(source), 'entry_hex': source.hex(), 'entry_sha256': digest(source),
            'aot_manifest': compiled, 'cold_image_probe': cold, 'warm_image_probe': warm,
            'cold_cli_elapsed_ns': cold_ns, 'warm_cli_elapsed_ns': warm_ns,
            'host_x86_64_exit_status': host.returncode, 'original_default_state': default_expected,
            'dirty_state_comparisons': comparisons, 'full_state_comparisons': len(comparisons) + 2,
            'complete_binary_verified': False, 'pending_loader_requirements': plan['unresolved_requirements']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/image-entry-probes.json')
    arguments = parser.parse_args()
    require(platform.system() == 'Darwin' and platform.machine() == 'x86_64', 'requires an x86_64 macOS host with universal true/false inputs')
    reference = original_helpers()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    source_paths = ['dev/image-entry-probes.py', 'dev/block-differential.py', 'dev/differential.py', 'dev/evidence.py',
                    'crates/stela-runtime/src/blocks.rs', 'crates/stela-runtime/src/lib.rs',
                    'crates/stela-runtime/src/execution.rs', 'src/macho/block_image.rs', 'src/macho/load_plan.rs']
    hashes = {name: digest((ROOT / name).read_bytes()) for name in source_paths}
    cli_hash = digest(arguments.cli.read_bytes())
    with tempfile.TemporaryDirectory(prefix='image-entry-', dir=arguments.output.parent) as temporary:
        rows = [check_image(arguments.cli, Path('/usr/bin') / name, status, Path(temporary), reference)
                for name, status in [('true', 0), ('false', 1)]]
    require(cli_hash == digest(arguments.cli.read_bytes()), 'CLI changed while probes were running')
    require(hashes == {name: digest((ROOT / name).read_bytes()) for name in source_paths}, 'harness/runtime source changed during probes')
    report = {'kind': 'apple_macho_entry_block_differential', 'schema_version': 1, 'passed': True,
              'complete_binary_verified': False, 'complete_binaries_verified': 0,
              'compiler_source_sha256': rows[0]['cold_image_probe']['compiler_source_sha256'],
              'cli_sha256': cli_hash, 'source_sha256': hashes, 'inputs': rows,
              'full_state_comparisons': sum(row['full_state_comparisons'] for row in rows),
              'tested_state': ['x0..x30', 'sp', 'nzcv', 'reserved', 'V0..V31', 'FPCR', 'FPSR', 'actual RET guest PC'],
              'limits': 'Only original two-instruction MOV W0,#status; RET X30 entry blocks. No complete process loading, dyld, imports, signing, PAC ABI, syscalls or macOS boot. CLI times include process startup and are not native execution benchmarks.'}
    archive = write_evidence(arguments.output, report)
    print(json.dumps({'passed': True, 'inputs': len(rows), 'full_state_comparisons': report['full_state_comparisons'],
                      'complete_binaries_verified': 0, 'report': str(arguments.output), 'snapshot': str(archive)}, indent=2))


if __name__ == '__main__':
    main()
