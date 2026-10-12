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

ROOT = Path(__file__).resolve().parents[1]
STATUSES = ('implemented', 'partial', 'unsupported')
RET = 0xd65f03c0


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


def compile_probe(cli, word, directory, expect_failure=None, run=subprocess.run):
    source = directory / 'source.arm64'
    source.write_bytes(struct.pack('<II', word, RET))
    output = directory / 'native'
    process = run([str(cli), 'compile-leaf', str(source), '--output-dir', str(output)],
                  capture_output=True, text=True, timeout=30)
    if expect_failure:
        if process.returncode == 0 or expect_failure not in process.stderr or output.exists():
            raise ValueError(f'Expected unsupported scope boundary {word:#x}: {process.stderr}')
        return {'word': f'0x{word:08x}', 'rejected': True, 'reason': expect_failure}
    if process.returncode != 0:
        raise ValueError(f'Reviewed supported form no longer emits {word:#x}: {process.stderr}')
    manifest = json.loads(process.stdout)
    if manifest.get('source_sha256') != sha256(source):
        raise ValueError('Compiler probe source identity mismatch')
    native = output / 'native.bin'
    if manifest.get('native_sha256') != sha256(native) or native.stat().st_size == 0:
        raise ValueError('Compiler probe native output identity mismatch')
    fingerprint = manifest.get('compiler_source_sha256')
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError('Compiler probe fingerprint missing')
    return {'word': f'0x{word:08x}', 'emitted': True, 'compiler_source_sha256': fingerprint,
            'source_sha256': manifest['source_sha256'], 'native_sha256': manifest['native_sha256'],
            'native_bytes': native.stat().st_size}


def smoke_forms(cli, forms, overrides, directory):
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
            probe = compile_probe(cli, word, location)
            if fingerprint is not None and fingerprint != probe['compiler_source_sha256']:
                raise ValueError('Compiler changed during ISA progress probes')
            fingerprint = probe['compiler_source_sha256']
            results.append({'id': identity, 'sample': index, 'assembly': f'{instruction.mnemonic} {instruction.op_str}', **probe})
        for index, sample in enumerate(row.get('rejected_samples', [])):
            location = directory / f'{len(results)}-rejected'
            location.mkdir()
            probe = compile_probe(cli, int(sample['word'], 16), location, sample['reason'])
            results.append({'id': identity, 'scope_boundary_sample': index, **probe})
    if fingerprint is None:
        location = directory / 'compiler-identity'
        location.mkdir()
        fingerprint = compile_probe(cli, RET, location)['compiler_source_sha256']
    return fingerprint, results


def validate_evidence(registry, overrides, compiler, root=ROOT):
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
        comparisons = next((report[key] for key in ('state_comparisons', 'state_and_memory_comparisons',
                           'register_state_comparisons', 'three_way_register_state_comparisons') if key in report), None)
        if type(comparisons) is not int or comparisons <= 0:
            raise ValueError(f'Native differential evidence has no comparisons: {name}')
        harness = root / repository_path(group['harness'])
        harness_hash = sha256(harness)
        recorded = report.get('harness_source_sha256')
        if recorded != harness_hash:
            raise ValueError(f'Stale differential harness evidence: {name}')
        shared = {}
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
        for source, digest in shared.items():
            if sha256(root / source) != digest:
                raise ValueError(f'Stale shared differential source evidence: {source}')
        results[name] = {'report': group['report'], 'report_sha256': hashlib.sha256(report_data).hexdigest(),
                         'harness': group['harness'], 'harness_source_sha256': harness_hash,
                         'report_binds_harness_hash': True,
                         'shared_sources_sha256': shared,
                         'native_comparisons': comparisons, 'compiler_source_sha256': compiler}
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
    row = report['summary']['reviewed']
    return ('| Measurement | Current evidence |\n| --- | --- |\n'
            f"| Reviewed instruction forms implemented | {row['implemented']:,} |\n"
            f"| Reviewed instruction forms partially implemented | {row['partial']:,} |\n"
            '| Required Apple-silicon ISA inventory | Incomplete; total unknown |\n'
            '| Required ISA completion | Unknown |\n'
            f"| Complete binaries verified through Stela | {report['summary']['complete_binaries']['verified']:,} |\n"
            '| Overall compatibility completion | Unknown |\n\n'
            f"Snapshot {report['measured_at_utc'].split('T')[0]} UTC; compiler `{report['compiler_source_sha256'][:12]}`.\n\n"
            'Reviewed forms cover the bounded leaf/private-RAM profile, with aliases excluded. '
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, default=ROOT / 'tests/isa/apple-silicon-reviewed-forms.json')
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/progress/apple-silicon.json')
    parser.add_argument('--markdown-output', type=Path)
    parser.add_argument('--update-readme', action='store_true')
    args = parser.parse_args()
    registry_data = args.registry.read_bytes()
    registry = json.loads(registry_data)
    rows = validate_registry(registry)
    executable_hash = sha256(args.cli)
    with tempfile.TemporaryDirectory(prefix='stela-apple-progress-') as temporary:
        compiler, probes = smoke_forms(args.cli, rows, rows, Path(temporary))
    evidence, sources = validate_evidence(registry, rows, compiler)
    fingerprint_sources = validate_current_compiler(registry, compiler)
    if (sha256(args.cli) != executable_hash or args.registry.read_bytes() != registry_data
            or validate_current_compiler(registry, compiler) != fingerprint_sources):
        raise ValueError('Compiler/registry changed during measurement')
    report = {'schema_version': 2, 'kind': 'apple_silicon_translation_progress',
              'measured_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
              'registry_version': registry['registry_version'], 'target_profile': registry['target_profile'],
              'instruction_sources': registry['instruction_sources'],
              'registry_sha256': hashlib.sha256(registry_data).hexdigest(),
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': sha256(__file__), 'compiler_sources_sha256': sources,
              'compiler_fingerprint_sources_sha256': fingerprint_sources,
              'profile': registry['profile'], 'summary': summarize(rows),
              'native_differential_evidence': evidence, 'compiler_smoke_probes': probes,
              'reviewed_forms': [{'id': identity, 'status': row['status'], 'scope': row['scope']}
                                 for identity, row in rows.items()],
              'limits': 'Apple-silicon arm64/arm64e to native x86_64 is the target. Required public and Apple-specific ISA inventory is incomplete. Reviewed form counts cannot establish an ISA or overall completion percentage. Status is reviewed implementation under the bounded profile plus current differential evidence and representative compile smoke; neither smoke nor differential tests prove exhaustive correctness. Complete binary loading/execution and OS boot remain unverified.'}
    archive = write_evidence(args.output, report)
    if args.markdown_output:
        write_markdown(args.markdown_output, markdown(report))
    if args.update_readme:
        update_readme(ROOT / 'README.md', markdown(report))
    print(json.dumps({'report': str(args.output), 'archive': str(archive),
                      'compiler_source_sha256': compiler, 'summary': report['summary']}, indent=2))


if __name__ == '__main__':
    main()
