#!/usr/bin/env python3
"""Verify unchanged SMP2 SEV/SEVL originals through the shared System corpus runner.

This family adapter validates evidence and fresh results; it imports no original
producer and does not implement an independent execution runner or event model.
"""
import argparse
import hashlib
import json
from pathlib import Path

import block_system_corpus
from block_system_corpus import run_runtime_corpus, runtime_source_inventory, sha256

FAMILY = 'system_events_send_v1'
REPORT_KIND = 'system_events_runtime_corpus_v1'
TEST_NAME = 'system::execution::tests::event_corpus::original_sends_match_runtime'
SHARED_HELPER_SHA256 = '881a3660840de1e8e52c160ee5f7db28f961e66f220d2e90eba7072483004e8a'
ORIGINAL_SHA256 = '2293f2b9b1be319113d08e3bfecbdabe067bd659c6203377df46eaa8754d2774'
INDEPENDENT_SHA256 = '52be11ebebd207a5e5e951d56acacc7ba66a8b9ad350c5a85cc20045370b1e47'
RAW_AUDIT_SHA256 = 'a0c91e74298a6374d2cf868daa391a98150802be198bd82af64138cea806f556'
SOURCE_AUDIT_SHA256 = '3f21b012ac8bb62874a1b14677bb8b9d19c421f6b324ba27f24d508fd496b6e3'
HISTORICAL_PACKET_SHA256 = 'a72d33aedfd2498cdfa7b9ca6400b715bacac8763bfc9b2fd51759e4c246e9a6'
HISTORICAL_NATIVE_SHA256 = 'c47993ff4dc97e1e3fbc8d69c67f5ab0a216c08cc0eae079c07ddfab278479d7'
CASE_COUNT, PE_COUNT, SENDER_STEPS = 6, 2, 8
STATE_BYTES, INSTRUCTION_BYTES, X0_BYTES = 784, 4, 8
SEND_NATIVE_BYTES, NOP_NATIVE_BYTES = 16, 17
NOP, SEV, SEVL, WFE = 0xd503201f, 0xd503209f, 0xd50320bf, 0xd503205f
ADD_X0_X0_ONE = 0x91000400
WFE_TRAP_ESR, LOWER_A64_VECTOR = 0x07e00001, 0x400
SYSTEM_ABI = 'x86_64-sysv-guest-state-v2-block-exit-system-v1'
EL1_REGISTER_NAMES = ('ELR_EL1', 'SPSR_EL1', 'ESR_EL1', 'FAR_EL1', 'VBAR_EL1')
REGISTER_BYTES = 8


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(Path(path).read_text())


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def bound_file(repo, binding, frozen):
    path = Path(binding['path'])
    path = path.resolve() if path.is_absolute() else (repo / path).resolve()
    digest = sha256(path)
    require(digest == binding['sha256'], f'Evidence changed: {path}')
    if 'bytes' in binding:
        require(path.stat().st_size == binding['bytes'], f'Evidence size changed: {path}')
    require(path not in frozen or frozen[path] == digest, 'Conflicting evidence bindings')
    frozen[path] = digest
    return path


def frame_bytes(frame):
    data = bytes.fromhex(frame['state_hex'])
    require(len(data) == STATE_BYTES, 'Expected complete 784-byte State')
    require(digest_bytes(data) == frame['state_sha256'], 'State digest differs')
    require(set(frame['canonical_sp_banks']) == {'SP_EL0', 'SP_EL1'}, 'Both SP banks required')
    require(type(frame['pc']) is int and type(frame['pstate_low32']) is int, 'PC/PSTATE required')
    return data


def raw_register(frame, name):
    return int.from_bytes(bytes.fromhex(frame['raw_register_hex'][name]), 'little')


def el1_registers(frame):
    if 'raw_register_hex' in frame:
        require(all(len(bytes.fromhex(frame['raw_register_hex'][name])) == REGISTER_BYTES
                    for name in EL1_REGISTER_NAMES), 'Original EL1 register width differs')
        return {name: raw_register(frame, name) for name in EL1_REGISTER_NAMES}
    registers = frame['el1_registers']
    require(set(registers) == set(EL1_REGISTER_NAMES), 'All five native EL1 registers required')
    require(all(type(value) is int and 0 <= value < (1 << (REGISTER_BYTES * 8))
                for value in registers.values()), 'Native EL1 register value is not unsigned64')
    return registers


def trapped_wfe(step):
    require(bytes.fromhex(step['source_hex']) == WFE.to_bytes(INSTRUCTION_BYTES, 'little'), 'Observer source is not WFE')
    after = step['after']
    return (after['current_el'] == 1 and after['handler_instructions_executed'] == 0
            and after['pc'] == raw_register(after, 'VBAR_EL1') + LOWER_A64_VECTOR
            and raw_register(after, 'ESR_EL1') == WFE_TRAP_ESR
            and raw_register(after, 'ELR_EL1') == step['source_pc'])


def observed_event(probe):
    first = probe['first']
    require(digest_bytes(bytes.fromhex(first['source_hex'])) == first['source_sha256'], 'Observer source digest differs')
    if trapped_wfe(first):
        require('second' not in probe, 'Unexpected second observer after first trap')
        return False
    before, after = first['before'], first['after']
    require(after['current_el'] == 0 and after['pc'] == first['source_pc'] + INSTRUCTION_BYTES,
            'First WFE neither retired nor entered its exact trap')
    require(frame_bytes(before) == frame_bytes(after), 'Consuming WFE changed original State')
    require(before['pstate_low32'] == after['pstate_low32']
            and before['canonical_sp_banks'] == after['canonical_sp_banks'], 'Consuming WFE changed PSTATE/SP')
    require(trapped_wfe(probe['second']), 'Coalesced event was not exhausted by first WFE')
    return True


def load_originals(repo, original_path, independent_path):
    frozen = {}
    bound_file(repo, {'path': str(original_path), 'sha256': ORIGINAL_SHA256}, frozen)
    bound_file(repo, {'path': str(independent_path), 'sha256': INDEPENDENT_SHA256}, frozen)
    aggregate, independent = read_json(original_path), read_json(independent_path)
    require(aggregate['passed'] is True and len(aggregate['cases']) == CASE_COUNT, 'Wrong original aggregate')
    require(not independent['blocking_findings'], 'Independent review has blocking findings')
    guards = independent['guards_before_after']
    raw_paths = [Path(path) for path, digest in guards.items() if digest == RAW_AUDIT_SHA256]
    source_paths = [Path(path) for path, digest in guards.items() if digest == SOURCE_AUDIT_SHA256]
    require(len(raw_paths) == len(source_paths) == 1, 'Original independent source/raw audits missing')
    raw_path = bound_file(repo, {'path': str(raw_paths[0]), 'sha256': RAW_AUDIT_SHA256}, frozen)
    source_path = bound_file(repo, {'path': str(source_paths[0]), 'sha256': SOURCE_AUDIT_SHA256}, frozen)
    raw, source = read_json(raw_path), read_json(source_path)
    require(raw['aggregate_sha256'] == ORIGINAL_SHA256 and raw['raw_snapshot_bindings'] == 112, 'Raw proof differs')
    require(source['capture_receipt']['sha256'] == ORIGINAL_SHA256 and source['passed'], 'Source proof differs')
    bound_file(repo, source['june_helpers'], frozen)
    # These are retained historical references, never fresh runtime results.
    for digest in (HISTORICAL_PACKET_SHA256, HISTORICAL_NATIVE_SHA256):
        paths = [path for path, expected in guards.items() if expected == digest]
        require(len(paths) == 1, 'Historical source/native reference missing')
        bound_file(repo, {'path': paths[0], 'sha256': digest}, frozen)
    # Frozen capture assets include original sources, linked ELF, raw transcripts
    # and complete registers. Historical live tools need not remain installed.
    for binding in source['all_capture_files']:
        bound_file(repo, binding, frozen)
    raw_cases = {case['case']: case for case in raw['cases']}
    originals = {}
    for binding in aggregate['cases']:
        path = bound_file(repo, binding, frozen)
        case = read_json(path)
        key = path.parent.name
        require(key not in originals and key in raw_cases and case['passed'], 'Duplicate/unknown original case')
        require(case['subject_word'] in (NOP, SEV, SEVL), 'Unexpected subject instruction')
        require(case['input_ram_before_send_hex'] == case['input_ram_after_send_hex']
                and case['control_header_ram_before_send_hex'] == case['control_header_ram_after_send_hex'], 'Original RAM changed')
        require([probe['pe'] for probe in case['probes']] == list(range(PE_COUNT)), 'Original probe PE order differs')
        actual_events = [observed_event(probe) for probe in case['probes']]
        require(actual_events == raw_cases[key]['events_by_pe'], 'Raw event consumption proof differs')
        require(len(actual_events) == PE_COUNT and len(case['observations']) == case['repeats'], 'Original case extent differs')
        for step in case['observations']:
            expected_word = case['subject_word'].to_bytes(INSTRUCTION_BYTES, 'little')
            require(bytes.fromhex(step['source_hex']) == expected_word
                    and step['source_sha256'] == digest_bytes(expected_word), 'Original subject bytes differ')
            require(frame_bytes(step['before']) == frame_bytes(step['after']), 'Original send changed State')
            require(el1_registers(step['before']) == el1_registers(step['after']), 'Original send changed EL1 registers')
        originals[key] = (binding, case, actual_events)
    require(len(originals) == CASE_COUNT and sum(case['repeats'] for _, case, _ in originals.values()) == SENDER_STEPS,
            'Original six-case/eight-step cohort differs')
    return originals, frozen


def validate_body(body, expected_source, expected_pc):
    require(bytes.fromhex(body['original_source_hex']) == expected_source,
            'Original consumed source differs')
    native = bytes.fromhex(body['native_hex'])
    manifest = body['manifest']
    identity = manifest['identity']
    require(native and len(native) == manifest['native_bytes'], 'Native extent differs')
    require(digest_bytes(native) == body['native_sha256'] == manifest['native_sha256'], 'Native digest differs')
    require(identity['guest_base'] == expected_pc and identity['abi'] == SYSTEM_ABI, 'Native ABI/base differs')
    require(identity['source_sha256'] == digest_bytes(expected_source), 'Native source binding differs')
    require(isinstance(identity['target_cpu'], str) and identity['target_cpu'], 'Actual target identity missing')
    require(len(identity['compiler_source_sha256']) == 64, 'Compiler identity missing')
    maps = manifest['source_map']
    require([row[0] for row in maps] == list(range(expected_pc, expected_pc + len(expected_source), INSTRUCTION_BYTES)),
            'Native source-map PCs differ')
    offsets = [row[1] for row in maps]
    require(offsets and offsets[0] == 0 and offsets == sorted(set(offsets)) and offsets[-1] < len(native), 'Native source-map offsets differ')
    return identity['target_cpu'], identity['compiler_source_sha256']


def compare_frame(actual, original):
    require(frame_bytes(actual) == frame_bytes(original), 'Native complete State differs from original')
    require(all(actual[field] == original[field] for field in ('pc', 'pstate_low32', 'canonical_sp_banks')),
            'Native PC/PSTATE/SP differs')
    require(el1_registers(actual) == el1_registers(original), 'Native EL1 registers differ from original')


def validate_report(report, originals):
    require(report['kind'] == REPORT_KIND and report['passed'] is True, 'Wrong fresh family report')
    require(report['compiled_sources_sha256'], 'Compiled-source bindings missing')
    require(report['wfx_admission'] is False and report['exception_admission'] is False, 'Observer scope widened')
    require(len(report['cases']) == CASE_COUNT, 'Fresh case count differs')
    seen, identities, steps, state_comparisons, nop_steps = set(), set(), 0, 0, 0
    for result in report['cases']:
        key = Path(result['original']['path']).parent.name
        require(key in originals and key not in seen and result['passed'] is True, 'Duplicate/unknown fresh case')
        seen.add(key)
        binding, original, events = originals[key]
        require(result['original'] == binding, 'Original binding was rewritten')
        require(all(result[field] == original[field] for field in ('mnemonic', 'sender', 'repeats')), 'Case metadata differs')
        count = original['repeats']
        require(len(result['bodies']) == len(result['native_outcomes']) == len(result['step_pes']) == count,
                'Sender step count differs')
        first_pc, word = original['symbols']['sender_subject'], original['subject_word']
        for index, (body, outcome) in enumerate(zip(result['bodies'], result['native_outcomes'])):
            pc = first_pc + index * INSTRUCTION_BYTES
            require(body['pc'] == pc and body['word'] == word, 'Sender source PC/word differs')
            identities.add(validate_body(body, word.to_bytes(INSTRUCTION_BYTES, 'little'), pc))
            require(len(bytes.fromhex(body['native_hex'])) == (NOP_NATIVE_BYTES if word == NOP else SEND_NATIVE_BYTES),
                    'Actual baseline sender body extent differs')
            require(outcome['reason']['kind'] == 'stop_address' and outcome['blocks_executed'] == 1, 'Sender did not retire once')
            require(all(type(outcome[field]) is int and outcome[field] >= 0
                        for field in ('compiled_blocks', 'disk_cache_hits', 'memory_cache_hits')), 'Cache accounting missing')
            require(outcome['last_exit'] == [pc + INSTRUCTION_BYTES, 0] if word == NOP else outcome['last_exit'] == [pc, 11],
                    'Native exit tuple differs')
            step_pes = result['step_pes'][index]
            require(len(step_pes) == PE_COUNT, 'Per-step PE states missing')
            for pe, actual in enumerate(step_pes):
                expected = (original['observations'][index]['after'] if pe == original['sender']
                            else original['both_before_send'][str(pe)])
                compare_frame(actual, expected)
                require(type(actual['event']) is bool and actual['event'] == events[pe], 'Per-step event differs')
            state_comparisons += 1  # One sender observation; peer is checked additionally.
            steps += 1
            nop_steps += word == NOP
        require(len(result['pes']) == PE_COUNT and {pe['pe'] for pe in result['pes']} == {0, 1}, 'PE results differ')
        for pe in result['pes']:
            expected = original['both_after_send'][str(pe['pe'])]
            compare_frame(pe, expected)
            require(type(pe['event']) is bool and pe['event'] == events[pe['pe']], 'Native event differs from raw consume/trap proof')
            state_comparisons += 1
    require(steps == SENDER_STEPS and len(identities) == 1, 'Native extent or actual compiler/target identities differ')
    failures = report['failure_prefix_checks']
    require(len(failures) == 1, 'Expected exact one actual failed-service prefix check')
    for check in failures:
        source = bytes.fromhex(check['original_source_hex'])
        word, entry, terminal = check['word'], check['body']['pc'], check['terminal_pc']
        require(word in (SEV, SEVL) and source == ADD_X0_X0_ONE.to_bytes(INSTRUCTION_BYTES, 'little') + word.to_bytes(INSTRUCTION_BYTES, 'little')
                and terminal == entry + INSTRUCTION_BYTES, 'Failure source is not ADD prefix plus send')
        before, after = bytearray(frame_bytes(check['before'])), frame_bytes(check['after'])
        before[:X0_BYTES] = ((int.from_bytes(before[:X0_BYTES], 'little') + 1) % (1 << (X0_BYTES * 8))).to_bytes(X0_BYTES, 'little')
        require(bytes(before) == after and check['before']['pc'] == entry
                and check['after']['pc'] == terminal, 'Failed service lost committed prefix or source PC')
        require(check['before']['pstate_low32'] == check['after']['pstate_low32']
                and check['before']['canonical_sp_banks'] == check['after']['canonical_sp_banks'], 'Failure changed PSTATE/SP')
        require(el1_registers(check['before']) == el1_registers(check['after']), 'Failure changed EL1 registers')
        compare_frame(check['peer_after'], check['peer_before'])
        for initial, final in ((check['before'], check['after']), (check['peer_before'], check['peer_after'])):
            require(type(initial['event']) is bool and type(final['event']) is bool
                    and initial['event'] == final['event'], 'Failed send published events')
        require(check['body']['word'] == word, 'Failure body original word differs')
        require(validate_body(check['body'], source, entry) in identities, 'Failure native identity differs')
        outcome = check['native_outcome']
        require(outcome['reason']['kind'] == 'system_failure' and outcome['blocks_executed'] == 1
                and outcome['reason']['instruction']['word'] == word
                and outcome['reason']['instruction']['instruction_pc'] == terminal
                and outcome['last_exit'] == [terminal, 11], 'Failure outcome lost exact terminal identity')
        failure = outcome['reason']['failure']
        require(failure['kind'] == 'backend'
                and isinstance(failure['detail'], str) and failure['detail'], 'Explicit failed-service cause missing')
        require(check['actual_system_failure'] is True and check['passed'] is True, 'Failure execution missing')
    measurements = {'fresh_original_state_comparisons': state_comparisons,
                    'fresh_native_blocks_executed': steps, 'original_cases': CASE_COUNT,
                    'both_pe_checks': CASE_COUNT * PE_COUNT, 'send_steps': steps - nop_steps,
                    'nop_steps': nop_steps, 'failure_prefix_check_count': len(failures)}
    require(measurements == {'fresh_original_state_comparisons': 20, 'fresh_native_blocks_executed': 8,
                            'original_cases': 6, 'both_pe_checks': 12, 'send_steps': 6,
                            'nop_steps': 2, 'failure_prefix_check_count': 1}, 'Independent measurement census differs')
    require(all(report[field] == count for field, count in measurements.items()), 'Rust measurement fields differ')
    target, compiler = next(iter(identities))
    require(report['compiler_source_sha256'] == compiler and report['target'] == target == 'x86_64-baseline',
            'Actual baseline/compiler identity differs')
    return {'cases': CASE_COUNT, 'pe_states': CASE_COUNT * PE_COUNT, 'sender_steps': steps,
            'measurements': measurements,
            'failure_prefix_checks': len(failures), 'actual_target_compiler': list(next(iter(identities)))}


def source_body_transfer(args, root, repo, originals, frozen):
    """Validate source/body lineage without executing a native program."""
    names = ('lineage_native_report', 'lineage_source_bridge',
             'lineage_source_review', 'lineage_cli_transfer')
    require(all(getattr(args, name) for name in names), 'All four lineage inputs required')
    require(not args.no_build and args.runtime_test_executable is None
            and args.runtime_build_binding is None, 'Lineage mode cannot launch a runtime')
    shared = runtime_source_inventory(root, additional=(root / 'dev/block_system_corpus.py',
                                                       root / 'dev/block_system_events.py'))
    inputs = {name: {'path': str(getattr(args, name).resolve()),
                     'sha256': sha256(getattr(args, name))} for name in names}
    for item in inputs.values():
        frozen[Path(item['path'])] = item['sha256']
    historical = read_json(args.lineage_native_report)
    counts = validate_report(historical, originals)['measurements']
    bridge, review = read_json(args.lineage_source_bridge), read_json(args.lineage_source_review)
    require(review.get('passed') is True and bridge['new_execution'] is False,
            'Independent source-equivalence approval required')
    require(review['source_bridge']['sha256'] == sha256(args.lineage_source_bridge),
            'Review is bound to a different source bridge')
    require(review['source_manifest']['sha256'] == bridge['source_manifest_sha256']
            and review['current_compiler_source_sha256'] == bridge['new_current_compiler_source_sha256'],
            'Reviewed source/compiler identity differs')
    native_receipt_path = bound_file(repo, bridge['historical232_actual_native_receipt'], frozen)
    native_receipt = read_json(native_receipt_path)
    require(native_receipt['runtime_report_sha256'] == sha256(args.lineage_native_report),
            'Historical actual execution report differs')
    historical_runtime = {'path': native_receipt['runtime_executable_path'],
                          'sha256': native_receipt['runtime_executable_sha256']}
    bound_file(repo, historical_runtime, frozen)
    build_binding = bridge['historical232_build_binding']
    bound_file(repo, build_binding, frozen)
    require(build_binding['sha256'] == native_receipt['execution']['runtime_build_binding_sha256']
            and historical['compiler_source_sha256'] == native_receipt['compiler_source_sha256'],
            'Historical actual compiler/build identity differs')
    for item in bridge['byte_equal_leaves'] + bridge['changed_leaves']:
        require(sha256(root / item['path']) == item['current255_source_sha256'],
                'Current reviewed source changed')
    transfer = read_json(args.lineage_cli_transfer)
    require(transfer['passed'] is True and transfer['new_native_execution'] is False,
            'Expected actual CLI compilation-only transfer')
    compiler = transfer['compiler_source_sha256']
    require(compiler == bridge['new_current_compiler_source_sha256'], 'Compiler lineage differs')
    bound_file(repo, transfer['cli'], frozen)
    bodies = [body for case in historical['cases'] for body in case['bodies']]
    require(len(transfer['rows']) == len(bodies) == SENDER_STEPS, 'Eight CLI bodies required')
    for row, body in zip(transfer['rows'], bodies):
        command = row['argv']
        output = Path(command[command.index('--output-dir') + 1])
        source = Path(command[command.index('compile-block') + 1])
        for path in (output / 'manifest.json', output / 'native.bin', source):
            frozen[path] = sha256(path)
        require(source.read_bytes().hex() == body['original_source_hex'], 'Current source bytes differ')
        manifest, native = read_json(output / 'manifest.json'), (output / 'native.bin').read_bytes()
        require(row['exit_code'] == 0 and row['runtime_actual_body_equal'] is True,
                'Current CLI transfer failed')
        require(digest_bytes(native) == row['native_sha256'] == body['native_sha256']
                and native.hex() == body['native_hex'], 'Whole native bodies differ')
        require(sha256(output / 'manifest.json') == row['manifest_sha256']
                and manifest['source_map'] == row['source_map'] == body['source_map']
                and manifest['guest_base'] == row['pc'] == body['pc'], 'Current map/PC differs')
        require(manifest['compiler_source_sha256'] == compiler and manifest['abi'] == SYSTEM_ABI
                and manifest['target_cpu'] == 'x86_64-baseline'
                and manifest['source_sha256'] == body['manifest']['identity']['source_sha256'],
                'Current compiler/ABI/original identity differs')
    report = {'kind': 'system_events_source_body_lineage_v1', 'passed': True,
              'compiler_source_sha256': compiler, 'abi': SYSTEM_ABI,
              'harness_source_sha256': sha256(__file__), 'shared_sources_sha256': shared,
              'inputs': inputs, 'historical_compiler_source_sha256': historical['compiler_source_sha256'],
              'historical_runtime_executable': historical_runtime, 'historical_runtime_build_binding': build_binding,
              'transferred_original_state_comparisons': counts['fresh_original_state_comparisons'],
              'fresh_original_state_comparisons': 0, 'fresh_native_blocks_executed': 0,
              'current_cli_body_transfers': len(bodies), 'new_original_captures': 0,
              'original_cases': CASE_COUNT, 'both_pe_checks': CASE_COUNT * PE_COUNT,
              'send_steps': counts['send_steps'], 'nop_steps': counts['nop_steps'],
              'failure_prefix_check_count': counts['failure_prefix_check_count'],
              'wfx_admission': False, 'exception_admission': False,
              'limits': 'Historical State/event effects retain their actual compiler/runtime epoch; current evidence is reviewed source equivalence and whole CLI body/source-map/ABI equality, not fresh current native execution.'}
    require(all(sha256(path) == digest for path, digest in frozen.items()), 'Lineage input changed')
    require(runtime_source_inventory(root, additional=(root / 'dev/block_system_corpus.py',
                                                      root / 'dev/block_system_events.py')) == shared,
            'Current shared source changed during lineage validation')
    args.output_dir.mkdir(parents=True, exist_ok=False)
    output = args.output_dir / 'receipt.json'
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'passed': True, 'report': str(output), 'sha256': sha256(output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1], help='Runtime build/source root')
    parser.add_argument('--repo', type=Path, help='Historical evidence root; defaults to --root')
    parser.add_argument('--original-receipt', type=Path, required=True)
    parser.add_argument('--independent-audit', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--runtime-test-executable', type=Path)
    parser.add_argument('--runtime-build-binding', type=Path)
    for name in ('lineage-native-report', 'lineage-source-bridge',
                 'lineage-source-review', 'lineage-cli-transfer'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    root, repo = args.root.resolve(), (args.repo or args.root).resolve()
    helper = Path(block_system_corpus.__file__).resolve()
    require(sha256(helper) == SHARED_HELPER_SHA256, 'Shared corpus helper differs from reviewed base3')
    original, independent = args.original_receipt.resolve(), args.independent_audit.resolve()
    originals, frozen = load_originals(repo, original, independent)
    if any((args.lineage_native_report, args.lineage_source_bridge,
            args.lineage_source_review, args.lineage_cli_transfer)):
        source_body_transfer(args, root, repo, originals, frozen)
        return
    if args.runtime_test_executable is not None:
        args.runtime_test_executable.resolve().relative_to(repo)
    output = args.output_dir.resolve()
    report_path = output / 'runtime-report.json'
    inventory = lambda: runtime_source_inventory(root, additional=(Path(__file__).resolve(), helper))
    report, execution = run_runtime_corpus(
        root, family=FAMILY, test_name=TEST_NAME,
        environment={'STELA_SYSTEM_EVENTS_ORIGINAL': original, 'STELA_SYSTEM_EVENTS_REPORT': report_path,
                     'STELA_SYSTEM_EVENTS_REPO': repo},
        report_path=report_path, output_dir=output, source_inventory=inventory,
        frozen_inputs=frozen, no_build=args.no_build,
        runtime_test_executable=args.runtime_test_executable, runtime_build_binding=args.runtime_build_binding)
    comparisons = validate_report(report, originals)
    executable = Path(execution['command'][0]).resolve()
    receipt = {'kind': 'system_events_family_verification_v1', 'passed': True, 'family': FAMILY,
               'compiler_source_sha256': comparisons['actual_target_compiler'][1], 'abi': SYSTEM_ABI,
               'target': comparisons['actual_target_compiler'][0],
               'harness_source_sha256': sha256(__file__),
               'runtime_executable_path': str(executable.relative_to(repo)),
               'runtime_executable_sha256': execution['runtime_test_executable_sha256'],
               'shared_sources_sha256': execution['shared_sources_sha256'],
               'original_receipt_sha256': ORIGINAL_SHA256, 'independent_audit_sha256': INDEPENDENT_SHA256,
               'raw_original_inputs_sha256': {str(path): digest for path, digest in frozen.items()},
               'runtime_report_sha256': sha256(report_path), 'comparisons': comparisons,
               'execution': execution, 'wfx_admission': False, 'exception_admission': False,
               'limits': ['Six original SMP2 cases only; WFE is original observer, not native instruction admission.',
                          'No guest RAM access, timing or complete application claim.']}
    receipt.update(comparisons['measurements'])
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
