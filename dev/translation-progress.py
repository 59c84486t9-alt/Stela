#!/usr/bin/env python3
"""Report Apple-silicon translation evidence without inventing a completion denominator."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from evidence import write_evidence
import a64_checklist
import apple_isa

ROOT = Path(__file__).resolve().parents[1]
STATUSES = ('implemented', 'partial', 'unsupported')
RET = 0xd65f03c0
BLOCK_ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
SERVICE_ABI = BLOCK_ABI + '-apple-arm64e-software-pauth-clock-v1'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def repository_path(value):
    if not isinstance(value, str) or not value:
        raise ValueError('Evidence/source paths must be nonempty repository-relative paths')
    path = Path(value)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Evidence/source paths must stay inside the repository')
    return path


def digest(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Expected a lowercase SHA-256 identity')
    return value


def validate_registry(registry):
    if registry.get('schema_version') != 2 or registry.get('kind') != 'reviewed_apple_silicon_instruction_forms':
        raise ValueError('Unsupported Apple-silicon reviewed-form registry')
    target = registry.get('target_profile', {})
    if (target.get('vendor') != 'Apple' or target.get('guest_architectures') != ['arm64', 'arm64e']
            or target.get('host_architecture') != 'x86_64'):
        raise ValueError('Registry must target Apple arm64/arm64e to native x86_64')
    if target.get('required_isa_inventory_complete') is not False or target.get('required_isa_form_count') is not None:
        raise ValueError('An incomplete reviewed list cannot establish a required Apple ISA denominator')
    if not registry.get('registry_version') or not registry.get('instruction_sources') or not target.get('inventory_limits'):
        raise ValueError('Reviewed forms require versioned source facts and inventory limits')
    profile = registry.get('profile', {}).get('id')
    if not profile or not registry.get('profile', {}).get('outside_scope'):
        raise ValueError('Support needs an explicit bounded execution profile')
    evidence = registry.get('evidence_groups', {})
    rows = {}
    for row in registry.get('forms', []):
        identity = row.get('id')
        if not isinstance(identity, str) or not identity or identity in rows:
            raise ValueError('Reviewed form IDs must be unique and nonempty')
        if row.get('alias') is not False:
            raise ValueError('Aliases cannot inflate reviewed support counts')
        if not row.get('category') or not row.get('source_file') or not row.get('source_sha256'):
            raise ValueError('Reviewed forms need their instruction source facts')
        digest(row['source_sha256'])
        mask, value = int(row['encoding_mask'], 16), int(row['encoding_value'], 16)
        if not 0 <= mask <= 0xffffffff or not 0 <= value <= 0xffffffff or value & ~mask:
            raise ValueError('Invalid reviewed encoding mask/value')
        if row.get('status') not in STATUSES:
            raise ValueError('Unknown support status')
        if row.get('profile') != profile or not row.get('scope'):
            raise ValueError('Form support scope/profile missing')
        if row['status'] != 'unsupported':
            if not row.get('review') or not row.get('compiler_sources') or not row.get('smoke_samples'):
                raise ValueError('Support requires reviewed implementation and smoke samples')
            if not row.get('evidence_groups') or any(group not in evidence for group in row['evidence_groups']):
                raise ValueError('Support requires a native differential evidence group')
            for source in row['compiler_sources']:
                repository_path(source)
            for sample in row['smoke_samples']:
                validate_sample(row, sample)
            if row['status'] == 'partial' and not row.get('rejected_samples'):
                raise ValueError('Partial forms need a rejected scope-boundary sample')
        rows[identity] = row
    return rows


def validate_sample(form, sample):
    word = int(sample['word'], 16)
    if not 0 <= word <= 0xffffffff or word & int(form['encoding_mask'], 16) != int(form['encoding_value'], 16):
        raise ValueError(f'Smoke does not match canonical form: {form["id"]}')
    # Official byte-register forms distinguish an extended operand from LSL,
    # although the extended form's !=011 constraint cannot fit a fixed mask.
    reguse = form.get('docvars', {}).get('reguse') if form['id'].endswith('_ldst_regoff') else None
    if reguse == 'ext-reg' and ((word >> 13) & 7) not in (2, 6, 7):
        raise ValueError('Extended-register smoke has the wrong operand form')
    if reguse == 'shifted-reg' and ((word >> 13) & 7) != 3:
        raise ValueError('Shifted-register smoke has the wrong operand form')
    expected = sample.get('expected_mnemonics')
    if not isinstance(expected, list) or not expected:
        raise ValueError('Smoke needs an independent decoded mnemonic expectation')
    consumed = sample.get('consumed_source_bytes', 4)
    if type(consumed) is not int or consumed not in (4, 8):
        raise ValueError('Smoke must declare a valid instruction/RET boundary')
    return word


def summarize(rows):
    categories = {}
    overall = Counter({status: 0 for status in STATUSES})
    for row in rows.values():
        counts = categories.setdefault(row['category'], Counter({status: 0 for status in STATUSES}))
        counts[row['status']] += 1
        overall[row['status']] += 1
    def finish(counts):
        return {**dict(counts), 'reviewed_forms': sum(counts.values())}
    return {'categories': {key: finish(counts) for key, counts in sorted(categories.items())},
            'reviewed': finish(overall), 'required_isa_forms': None,
            'required_isa_completion_percentage': None, 'overall_completion_percentage': None,
            'complete_binaries': {'verified': 0, 'full_binary_harness_available': False,
                                  'required_total': None, 'completion_percentage': None,
                                  'evidence_requirement': 'Stela full Mach-O load and native execution with validated process behavior; leaf fixtures do not qualify.'}}


def compile_probe(cli, word, directory, expect_failure=None, run=subprocess.run, mode='leaf',
                  expected_source_bytes=4):
    if mode not in ('leaf', 'block', 'service'):
        raise ValueError('Unknown compiler probe mode')
    if type(expected_source_bytes) is not int or expected_source_bytes not in (4, 8):
        raise ValueError('Invalid declared compiler probe boundary')
    source = directory / 'source.arm64'
    source.write_bytes(struct.pack('<II', word, RET))
    output = directory / 'native'
    command = [str(cli), 'compile-' + ('block' if mode == 'service' else mode), str(source), '--output-dir', str(output)]
    if mode != 'leaf':
        command.extend(['--guest-base', '0x10000000'])
    if mode == 'service':
        command.extend(['--software-pauth', '--software-clock'])
    process = run(command,
                  capture_output=True, text=True, timeout=30)
    if expect_failure:
        if process.returncode == 0 or expect_failure not in process.stderr or output.exists():
            raise ValueError(f'Expected unsupported scope boundary {word:#x}: {process.stderr}')
        return {'word': f'0x{word:08x}', 'rejected': True, 'reason': expect_failure}
    if process.returncode != 0:
        raise ValueError(f'Reviewed supported form no longer emits {word:#x}: {process.stderr}')
    manifest = json.loads(process.stdout)
    source_data = source.read_bytes()
    if mode != 'leaf':
        if manifest.get('abi') != (SERVICE_ABI if mode == 'service' else BLOCK_ABI):
            raise ValueError('Compiler block probe ABI mismatch')
        consumed = manifest.get('source_bytes')
        if type(consumed) is not int or consumed != expected_source_bytes:
            raise ValueError('Compiler block probe differs from the declared consumed boundary')
        source_data = source_data[:consumed]
    if manifest.get('source_sha256') != hashlib.sha256(source_data).hexdigest():
        raise ValueError('Compiler probe source identity mismatch')
    native = output / 'native.bin'
    if manifest.get('native_sha256') != sha256(native) or native.stat().st_size == 0:
        raise ValueError('Compiler probe native output identity mismatch')
    fingerprint = manifest.get('compiler_source_sha256')
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError('Compiler probe fingerprint missing')
    return {'word': f'0x{word:08x}', 'emitted': True, 'compiler_source_sha256': fingerprint,
            'source_sha256': manifest['source_sha256'], 'native_sha256': manifest['native_sha256'],
            'native_bytes': native.stat().st_size,
            **({'abi': manifest['abi'], 'source_bytes': consumed, 'compiler_mode': mode} if mode != 'leaf' else {})}


def smoke_forms(cli, forms, overrides, directory, mode='leaf'):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    fingerprint = None
    results = []
    for identity, row in overrides.items():
        if row['status'] == 'unsupported':
            continue
        for index, sample in enumerate(row['smoke_samples']):
            word = validate_sample(forms[identity], sample)
            instruction = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if instruction is None or instruction.mnemonic not in sample['expected_mnemonics']:
                raise ValueError(f'Independent decoder differs for {identity}: {word:#x}')
            location = directory / f'{len(results)}-supported'
            location.mkdir()
            options = {'mode': mode} if mode != 'leaf' else {}
            if 'consumed_source_bytes' in sample:
                options['expected_source_bytes'] = sample['consumed_source_bytes']
            probe = compile_probe(cli, word, location, **options)
            if fingerprint is not None and fingerprint != probe['compiler_source_sha256']:
                raise ValueError('Compiler changed during ISA progress probes')
            fingerprint = probe['compiler_source_sha256']
            results.append({'id': identity, 'sample': index, 'assembly': f'{instruction.mnemonic} {instruction.op_str}', **probe})
        for index, sample in enumerate(row.get('rejected_samples', [])):
            location = directory / f'{len(results)}-rejected'
            location.mkdir()
            probe = compile_probe(cli, int(sample['word'], 16), location, sample['reason'],
                                  **({'mode': mode} if mode != 'leaf' else {}))
            results.append({'id': identity, 'scope_boundary_sample': index, **probe})
    if fingerprint is None:
        location = directory / 'compiler-identity'
        location.mkdir()
        fingerprint = compile_probe(cli, RET, location, **({'mode': mode} if mode != 'leaf' else {}))['compiler_source_sha256']
    return fingerprint, results


def validate_evidence(registry, overrides, compiler, root=ROOT, executable_hash=None):
    names = sorted({name for row in overrides.values() if row['status'] != 'unsupported'
                    for name in row['evidence_groups']})
    results = {}
    for name in names:
        group = registry['evidence_groups'][name]
        path = root / repository_path(group['report'])
        report_data = path.read_bytes()
        report = json.loads(report_data)
        if report.get('passed') is not True or report.get('kind') != group['kind']:
            raise ValueError(f'Native differential evidence missing or failed: {name}')
        if report.get('compiler_source_sha256') != compiler:
            raise ValueError(f'Stale native differential compiler evidence: {name}')
        comparison_keys = (('single_block_state_exit_comparisons',)
                           if group['kind'] == 'arm64_block_control_flow_differential'
                           else ('state_comparisons', 'state_and_memory_comparisons',
                                 'register_state_comparisons', 'three_way_register_state_comparisons'))
        comparison_field = group.get('comparison_field')
        if comparison_field is not None:
            comparison_keys = (comparison_field,)
        comparisons = next((report[key] for key in comparison_keys if key in report), None)
        if type(comparisons) is not int or comparisons <= 0:
            raise ValueError(f'Native differential evidence has no comparisons: {name}')
        harness = root / repository_path(group['harness'])
        harness_hash = sha256(harness)
        recorded = report.get('harness_source_sha256', report.get('sources_sha256', {}).get(group['harness']))
        if recorded != harness_hash:
            raise ValueError(f'Stale differential harness evidence: {name}')
        shared = {}
        if 'sources_sha256' in report:
            shared.update(report['sources_sha256'])
        if 'shared_runner_sha256' in report:
            shared['dev/differential.py'] = report['shared_runner_sha256']
        if 'shared_sources_sha256' in report:
            declared = report['shared_sources_sha256']
            if not isinstance(declared, dict):
                raise ValueError('Shared differential source identities must be a mapping')
            for source, digest in declared.items():
                source_path = Path(source)
                if source_path.is_absolute() or '..' in source_path.parts:
                    raise ValueError('Shared source must be a repository-relative path')
                if not (root / source_path).is_file():
                    source_path = Path('dev') / source_path
                if str(source_path) in shared and shared[str(source_path)] != digest:
                    raise ValueError('Conflicting shared differential source identities')
                shared[str(source_path)] = digest
        for source in group.get('required_shared_sources', []):
            if str(repository_path(source)) not in shared:
                raise ValueError(f'Differential report does not bind required shared source: {source}')
        if group.get('abi') is not None and report.get('abi') != group['abi']:
            raise ValueError(f'Differential ABI mismatch: {name}')
        for source, digest in shared.items():
            if sha256(root / source) != digest:
                raise ValueError(f'Stale shared differential source evidence: {source}')
        results[name] = {'report': group['report'], 'report_sha256': hashlib.sha256(report_data).hexdigest(),
                         'harness': group['harness'], 'harness_source_sha256': harness_hash,
                         'report_binds_harness_hash': True,
                         'shared_sources_sha256': shared,
                         'native_comparisons': comparisons, 'compiler_source_sha256': compiler,
                         'comparison_field': comparison_field}
        for key in group.get('required_positive_counts', []):
            if type(report.get(key)) is not int or report[key] <= 0:
                raise ValueError(f'Differential evidence missing positive count {key}')
            results[name][key] = report[key]
        for key, expected in group.get('required_measurements', {}).items():
            value = report
            # Slash-separated paths preserve literal dots in CPU profile names.
            parts = key[1:].split('/') if key.startswith('/') else key.split('.')
            for part in parts:
                value = value.get(part) if isinstance(value, dict) else None
            if type(value) is not int or value != expected:
                raise ValueError(f'Differential evidence missing required measurement {key}')
        if group.get('require_current_executable') and report.get('compiler_executable_sha256') != executable_hash:
            raise ValueError('Stale service runtime executable evidence')
        if group['kind'] == 'arm64_block_control_flow_differential':
            if executable_hash is not None and report.get('compiler_executable_sha256') != executable_hash:
                raise ValueError('Stale native block runtime executable evidence')
            for key in ('multiblock_state_exit_comparisons', 'rust_runtime_execution_comparisons'):
                if type(report.get(key)) is not int or report[key] <= 0:
                    raise ValueError(f'Block differential evidence missing {key}')
                results[name][key] = report[key]
    sources = sorted({path for row in overrides.values() if row['status'] != 'unsupported'
                      for path in row['compiler_sources']})
    return results, {path: sha256(root / path) for path in sources}


def validate_current_compiler(registry, compiler, root=ROOT):
    paths = registry.get('compiler_fingerprint_sources')
    if not isinstance(paths, list) or not paths or len(set(paths)) != len(paths):
        raise ValueError('Registry needs the ordered compiler fingerprint source recipe')
    sources = {str(repository_path(path)): (root / repository_path(path)).read_bytes() for path in paths}
    if hashlib.sha256(b''.join(sources.values())).hexdigest() != compiler:
        raise ValueError('Built compiler fingerprint differs from current source bytes')
    return {path: hashlib.sha256(data).hexdigest() for path, data in sources.items()}


def markdown(report):
    if 'apple_codegen_candidates' in report:
        row = report['apple_codegen_candidates']['summary']['union']
        apple = report['apple_specific_extensions']
        checkpoint = report.get('last_verified_checkpoint')
        checkpoint_row, basis = '', ''
        if report.get('implementation_only'):
            checkpoint_text = (f"{checkpoint['implemented']:,} / {checkpoint['total']:,}; compiler `{checkpoint['compiler_source_sha256'][:12]}`"
                               if checkpoint else 'Pending')
            checkpoint_row = f'| Last full instruction-verification checkpoint | {checkpoint_text} |\n'
            basis = 'Current counts reflect reviewed implementation and emission smoke checks. Full regression verification is deferred to integration checkpoints. '
        return ('| Measurement | Current evidence |\n| --- | --- |\n'
                f"| Apple M1–M5 candidate forms implemented | **{row['implemented']:,} / {row['total']:,} ({row['implementation_percentage']:.2f}%)** |\n"
                f"| Candidate forms partially implemented | {row['partial']:,} |\n"
                f"| Candidate forms unimplemented | {row['unsupported']:,} |\n" + checkpoint_row +
                f"| Apple-specific extension groups | {apple['implemented']} implemented / {apple['tracked']} tracked; inventory open |\n"
                f"| Complete binaries verified through Stela | {report['summary']['complete_binaries']['verified']:,} |\n\n"
                f"Pinned LLVM Apple CPU models mapped to Arm **2026-06**; compiler `{report['compiler_source_sha256'][:12]}`. " + basis +
                'Canonical encoding forms count once across reviewed execution profiles; aliases are excluded and partial forms earn no credit. '
                'This candidate inventory includes streaming SVE through SME, without general non-streaming SVE. '
                'Full hardware membership, M6 and Apple-private additions remain open; reviewed-profile instruction coverage does not establish complete CPU, application or macOS compatibility.\n\n'
                '[Apple profile inventory](tests/isa/apple-codegen-profiles.json) · '
                '[Arm reference checklist](tests/isa/a64-documented-checklist.json) · '
                '[Apple extensions](tests/isa/apple-specific-extensions.json) · '
                '[Scope and evidence](docs/development.md#apple-code-generation-candidate-inventory).\n')
    if 'documented_isa' in report:
        row = report['documented_isa']['summary']
        apple = report['apple_specific_extensions']
        return ('| Measurement | Current evidence |\n| --- | --- |\n'
                f"| Documented A64 ISA implemented | **{row['implemented']:,} / {row['total']:,} ({row['implementation_percentage']:.2f}%)** |\n"
                f"| Documented forms partially implemented | {row['partial']:,} |\n"
                f"| Documented forms unimplemented | {row['unsupported']:,} |\n"
                f"| Apple-specific extension groups | {apple['implemented']} implemented / {apple['tracked']} tracked; inventory open |\n"
                f"| Complete binaries verified through Stela | {report['summary']['complete_binaries']['verified']:,} |\n\n"
                f"Arm reference **2026-06**; compiler `{report['compiler_source_sha256'][:12]}`. "
                'Each canonical encoding form counts once across reviewed execution profiles; aliases are excluded and partial forms earn no credit. '
                'The fixed denominator includes optional and privileged A64 extensions, including forms beyond Apple hardware. '
                'This measures documented ISA implementation, not macOS or application completion.\n\n'
                '[Complete checklist](tests/isa/a64-documented-checklist.json) · '
                '[Apple extensions](tests/isa/apple-specific-extensions.json) · '
                '[Scope and evidence](docs/development.md#documented-a64-checklist).\n')
    row = report['summary']['reviewed']
    block = report.get('block_profile_evidence')
    block_rows = ''
    if block:
        counts = block['summary']['reviewed']
        groups = block['native_differential_evidence'].values()
        comparisons = sum(group['native_comparisons'] for group in groups
                          if group.get('comparison_field') != 'trap_state_exit_comparisons')
        traps = sum(group['native_comparisons'] for group in groups
                    if group.get('comparison_field') == 'trap_state_exit_comparisons')
        block_rows = (f"| Block-profile instruction forms implemented | {counts['implemented']:,} |\n"
                      f"| Native block state/exit comparisons | {comparisons:,} |\n")
        if counts['partial']:
            block_rows += f"| Block-profile forms partially implemented | {counts['partial']:,} |\n"
        if traps:
            block_rows += f"| Native synchronous-trap boundary comparisons | {traps:,} |\n"
    return ('| Measurement | Current evidence |\n| --- | --- |\n'
            f"| Leaf-profile instruction forms implemented | {row['implemented']:,} |\n"
            f"| Leaf-profile instruction forms partially implemented | {row['partial']:,} |\n"
            + block_rows +
            '| Required Apple-silicon ISA inventory | Incomplete; total unknown |\n'
            '| Required ISA completion | Unknown |\n'
            f"| Complete binaries verified through Stela | {report['summary']['complete_binaries']['verified']:,} |\n"
            '| Overall compatibility completion | Unknown |\n\n'
            f"Snapshot {report['measured_at_utc'].split('T')[0]} UTC; compiler `{report['compiler_source_sha256'][:12]}`.\n\n"
            'Reviewed forms cover bounded leaf/private-RAM and block-exit profiles, with aliases excluded. '
            'Profile counts overlap and are not added. '
            'They are an implementation count, not a percentage of the required Apple ISA. '
            'Complete binaries require full loading and execution; leaf tests do not qualify. '
            '[Scope and evidence](docs/development.md).\n')


def write_markdown(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as pending:
        pending.write(content)
        name = pending.name
    try:
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def update_readme(path, fragment):
    path = Path(path)
    text = path.read_text()
    start, end = '<!-- stela-instruction-progress:start -->', '<!-- stela-instruction-progress:end -->'
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('README needs exactly one progress marker pair')
    first, last = text.index(start) + len(start), text.index(end)
    if first > last:
        raise ValueError('README progress markers reversed')
    updated = text[:first] + '\n' + fragment.rstrip() + '\n' + text[last:]
    if path.read_text() != text:
        raise ValueError('README changed during update')
    write_markdown(path, updated)


def previous_checkpoint(path, root=ROOT):
    """Smoke-only updates preserve an archived verified baseline without advancing it."""
    path = Path(path)
    if not path.exists():
        return None
    data = path.read_bytes()
    previous = json.loads(data)
    digest = hashlib.sha256(data).hexdigest()
    archived = root / '.stela/evidence' / path.stem / (digest + '.json')
    if not archived.exists() or archived.read_bytes() != data:
        raise ValueError('Previous checkpoint is not bound to its evidence archive')
    if previous.get('implementation_only'):
        return previous.get('last_verified_checkpoint')
    if previous.get('kind') != 'apple_silicon_translation_progress' or not previous.get('native_differential_evidence'):
        return None
    row = previous['apple_codegen_candidates']['summary']['union']
    return {'implemented': row['implemented'], 'total': row['total'],
            'compiler_source_sha256': previous['compiler_source_sha256'],
            'measured_at_utc': previous['measured_at_utc'], 'report_sha256': digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, default=ROOT / 'tests/isa/apple-silicon-reviewed-forms.json')
    parser.add_argument('--block-registry', type=Path, default=ROOT / 'tests/isa/apple-silicon-block-forms.json')
    parser.add_argument('--service-registry', type=Path, default=ROOT / 'tests/isa/a64-service-forms.json')
    parser.add_argument('--checklist', type=Path, default=ROOT / 'tests/isa/a64-documented-checklist.json')
    parser.add_argument('--apple-profiles', type=Path, default=ROOT / 'tests/isa/apple-codegen-profiles.json')
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/progress/apple-silicon.json')
    parser.add_argument('--markdown-output', type=Path)
    parser.add_argument('--update-readme', action='store_true')
    parser.add_argument('--implementation-only', action='store_true',
                        help='Refresh implementation/emission counts while retaining the full verification checkpoint')
    args = parser.parse_args()
    checkpoint = previous_checkpoint(args.output) if args.implementation_only else None
    registry_data = args.registry.read_bytes()
    registry = json.loads(registry_data)
    rows = validate_registry(registry)
    block_data = args.block_registry.read_bytes()
    block_registry = json.loads(block_data)
    block_rows = validate_registry(block_registry)
    service_data = args.service_registry.read_bytes()
    service_registry = json.loads(service_data)
    service_rows = validate_registry(service_registry)
    catalog_data = args.checklist.read_bytes()
    catalog = json.loads(catalog_data)
    apple_profiles_data = args.apple_profiles.read_bytes()
    apple_profiles = json.loads(apple_profiles_data)
    apple = json.loads((ROOT / 'tests/isa/apple-specific-extensions.json').read_bytes())
    if apple.get('kind') != 'apple_specific_extension_ledger' or apple.get('inventory_complete') is not False:
        raise ValueError('Apple additions need a separate explicitly open inventory')
    if len({r['id'] for r in apple['extensions']}) != len(apple['extensions']) or any(r['status'] not in STATUSES for r in apple['extensions']):
        raise ValueError('Invalid Apple extension identity/status')
    if (block_registry['profile'].get('compiler_command') != 'compile-block'
            or block_registry['profile'].get('abi') != BLOCK_ABI):
        raise ValueError('Block registry must declare the native block-exit compiler ABI')
    executable_hash = sha256(args.cli)
    with tempfile.TemporaryDirectory(prefix='stela-apple-progress-') as temporary:
        compiler, probes = smoke_forms(args.cli, rows, rows, Path(temporary))
        block_directory = Path(temporary) / 'blocks'
        block_directory.mkdir()
        block_compiler, block_probes = smoke_forms(args.cli, block_rows, block_rows, block_directory, mode='block')
        service_directory = Path(temporary) / 'services'
        service_directory.mkdir()
        service_compiler, service_probes = smoke_forms(args.cli, service_rows, service_rows, service_directory, mode='service')
        if block_compiler != compiler or service_compiler != compiler:
            raise ValueError('Leaf and block compiler identities differ')
    if args.implementation_only:
        evidence, block_evidence, service_evidence = {}, {}, {}
        sources, block_sources, service_sources = [
            {path: sha256(ROOT / path) for row in group.values() for path in row['compiler_sources']}
            for group in (rows, block_rows, service_rows)]
    else:
        evidence, sources = validate_evidence(registry, rows, compiler)
        block_evidence, block_sources = validate_evidence(block_registry, block_rows, compiler,
                                                          executable_hash=executable_hash)
        service_evidence, service_sources = validate_evidence(service_registry, service_rows, compiler, executable_hash=executable_hash)
    assessed, documented_summary = a64_checklist.assess(catalog, [registry, block_registry, service_registry])
    apple_summary = apple_isa.assess(apple_profiles, assessed)
    assessed['compiler_source_sha256'] = compiler
    assessed['assessment_basis'] = 'reviewed_implementation_and_emission_smoke' if args.implementation_only else 'current_native_differential_evidence'
    assessed['last_verified_checkpoint'] = checkpoint
    assessed['evidence_reports'] = [{k: row[k] for k in ('report', 'report_sha256')}
                                   for group in (evidence, block_evidence, service_evidence) for row in group.values()]
    fingerprint_sources = validate_current_compiler(registry, compiler)
    if validate_current_compiler(block_registry, compiler) != fingerprint_sources:
        raise ValueError('Leaf and block fingerprint recipes differ')
    if (sha256(args.cli) != executable_hash or args.registry.read_bytes() != registry_data
            or args.block_registry.read_bytes() != block_data
            or args.service_registry.read_bytes() != service_data or args.checklist.read_bytes() != catalog_data
            or args.apple_profiles.read_bytes() != apple_profiles_data
            or validate_current_compiler(registry, compiler) != fingerprint_sources
            or validate_current_compiler(block_registry, compiler) != fingerprint_sources):
        raise ValueError('Compiler/registry changed during measurement')
    report = {'schema_version': 2, 'kind': 'apple_silicon_translation_progress',
              'implementation_only': args.implementation_only, 'last_verified_checkpoint': checkpoint,
              'measured_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
              'registry_version': registry['registry_version'], 'target_profile': registry['target_profile'],
              'instruction_sources': registry['instruction_sources'],
              'registry_sha256': hashlib.sha256(registry_data).hexdigest(),
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': sha256(__file__), 'compiler_sources_sha256': sources,
              'compiler_fingerprint_sources_sha256': fingerprint_sources,
              'profile': registry['profile'], 'summary': summarize(rows),
              'documented_isa': {'version': catalog['version'], 'facts_sha256': catalog['facts_sha256'],
                                'summary': documented_summary},
              'apple_codegen_candidates': {'version': apple_profiles['version'],
                  'facts_sha256': apple_profiles['facts_sha256'],
                  'inventory_sha256': hashlib.sha256(apple_profiles_data).hexdigest(),
                  'harness_source_sha256': sha256(apple_isa.__file__), 'summary': apple_summary,
                  'inventory_complete': False, 'hardware_membership_verified': False},
              'apple_specific_extensions': {'tracked': len(apple['extensions']),
                  'implemented': sum(r['status'] == 'implemented' for r in apple['extensions']),
                  'inventory_complete': False},
              'service_profile_evidence': {'registry_sha256': hashlib.sha256(service_data).hexdigest(),
                  'native_differential_evidence': service_evidence, 'compiler_sources_sha256': service_sources,
                  'compiler_smoke_probes': service_probes},
              'block_profile_evidence': {
                  'registry_version': block_registry['registry_version'],
                  'registry_sha256': hashlib.sha256(block_data).hexdigest(),
                  'profile': block_registry['profile'], 'summary': summarize(block_rows),
                  'overlap_with_leaf_form_ids': sorted(set(rows) & set(block_rows)),
                  'counts_are_not_additive': True, 'compiler_sources_sha256': block_sources,
                  'native_differential_evidence': block_evidence, 'compiler_smoke_probes': block_probes,
                  'reviewed_forms': [{'id': identity, 'status': row['status'], 'scope': row['scope']}
                                     for identity, row in block_rows.items()]},
              'native_differential_evidence': evidence, 'compiler_smoke_probes': probes,
              'reviewed_forms': [{'id': identity, 'status': row['status'], 'scope': row['scope']}
                                 for identity, row in rows.items()],
              'limits': 'Headline instruction percentage uses pinned public LLVM Apple M1–M5 code-generation candidate forms mapped to the June2026 Arm reference, deduplicated across reviewed execution profiles. Full Arm reference coverage remains secondary. Partial forms earn no credit. These models do not prove complete Apple hardware/mode/operand availability; M6, Apple-private additions and full CPU/VM conformance remain open. Differential tests establish evidence, not exhaustive correctness or complete application/macOS execution.'}
    archive = write_evidence(args.output, report)
    if args.markdown_output:
        write_markdown(args.markdown_output, markdown(report))
    if args.update_readme:
        a64_checklist.write(args.checklist, assessed)
        update_readme(ROOT / 'README.md', markdown(report))
    print(json.dumps({'report': str(args.output), 'archive': str(archive),
                      'compiler_source_sha256': compiler, 'summary': report['summary'],
                      'block_profile_summary': report['block_profile_evidence']['summary']}, indent=2))


if __name__ == '__main__':
    main()
