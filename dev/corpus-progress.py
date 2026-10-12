#!/usr/bin/env python3
"""Secondary corpus occurrence measurements; not finite ISA-form support."""
import argparse
from bisect import bisect_right
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from evidence import write_evidence

ROOT = Path(__file__).resolve().parents[1]
PINNED_KERNEL_SHA256 = 'ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203'
VERIFICATION_KINDS = {'real_kernel_integer_leafs', 'real_kernel_controlled_ram_leafs',
                      'real_kernel_pair_leafs_with_ram_contracts'}
COUNT_FIELDS = ('source_word_instances', 'decoded_lifted_words', 'native_emitted_words',
                'unsupported_words', 'unresolved_control_flow_words', 'native_emitted_bytes')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def natural(value, field):
    if type(value) is not int or value < 0:
        raise ValueError(f'{field} must be a nonnegative integer')
    return value


def percentage(numerator, denominator):
    natural(numerator, 'numerator')
    natural(denominator, 'denominator')
    if numerator > denominator:
        raise ValueError('Numerator exceeds denominator')
    value = None if denominator == 0 else float(
        (Decimal(numerator) * 100 / Decimal(denominator)).quantize(Decimal('0.0001'), rounding=ROUND_HALF_UP))
    return {'numerator': numerator, 'denominator': denominator, 'units': 'source 4-byte instruction-word instances',
            'decimal_places': 4, 'rounding': 'nearest; ties upward', 'value': value}


def check_probe(probe, expected_source, compiler=None):
    if probe.get('schema_version') != 1 or probe.get('kind') != 'isolated_instruction_codegen_progress':
        raise ValueError('Unsupported instruction-progress report')
    if probe.get('source_sha256') != expected_source:
        raise ValueError('Instruction-progress source identity mismatch')
    fingerprint = probe.get('compiler_source_sha256')
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError('Missing compiler fingerprint')
    if compiler is not None and fingerprint != compiler:
        raise ValueError('Compiler changed during progress measurement')
    counts = probe.get('counts', {})
    for field in COUNT_FIELDS:
        natural(counts.get(field), field)
    total = counts['source_word_instances']
    emitted = counts['native_emitted_words']
    if emitted + counts['unsupported_words'] + counts['unresolved_control_flow_words'] != total:
        raise ValueError('Inconsistent isolated emission counts')
    if not emitted <= counts['decoded_lifted_words'] <= total:
        raise ValueError('Inconsistent lifted instruction count')
    if probe.get('percentage') != percentage(emitted, total):
        raise ValueError('Inconsistent isolated emission percentage')
    if probe.get('verified_words') is not None:
        raise ValueError('Isolated emission probe must not claim verification')
    return fingerprint


def measure(cli, source, expected_hash, compiler=None, manifest=None, run=subprocess.check_output):
    source = Path(source)
    if sha256(source) != expected_hash:
        raise ValueError(f'Pinned source changed: {source}')
    command = [str(cli), 'corpus-progress', str(source)]
    if manifest is not None:
        command += ['--fileset-manifest', str(manifest)]
    probe = json.loads(run(command, text=True, timeout=300))
    check_probe(probe, expected_hash, compiler)
    if sha256(source) != expected_hash:
        raise ValueError(f'Pinned source changed during measurement: {source}')
    if manifest is not None and probe.get('fileset_manifest_sha256') != sha256(manifest):
        raise ValueError('Instruction-progress fileset manifest identity mismatch')
    return probe


def aggregate(probes):
    if not probes:
        raise ValueError('Cannot aggregate an empty corpus')
    compiler = probes[0]['compiler_source_sha256']
    for probe in probes:
        check_probe(probe, probe['source_sha256'], compiler)
    counts = {field: sum(probe['counts'][field] for probe in probes) for field in COUNT_FIELDS}
    return {'inputs': len(probes), 'compiler_source_sha256': compiler, 'counts': counts,
            'percentage': percentage(counts['native_emitted_words'], counts['source_word_instances'])}


def instruction_intervals(manifest, source_size):
    """Unique embedded-image instruction ranges; do not count root umbrella ranges."""
    spans = []
    for image in manifest['images']:
        for section in image['sections']:
            if section.get('instructions') and not section.get('zero_fill'):
                start = natural(section.get('file_offset'), 'section file_offset')
                size = natural(section.get('bytes'), 'section bytes')
                if start % 4 or size % 4 or start + size > source_size:
                    raise ValueError('Invalid embedded instruction range')
                if size:
                    spans.append((start, start + size))
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def collect_verification(reports, kernel_bytes, kernel_hash, compiler, intervals, denominator):
    if not reports:
        return {'status': 'unknown_no_reports_supplied', 'unique_source_word_instances': None,
                'percentage': None, 'reports': []}
    if hashlib.sha256(kernel_bytes).hexdigest() != kernel_hash:
        raise ValueError('Kernel bytes do not match pinned source')
    if sum(end - start for start, end in intervals) // 4 != denominator:
        raise ValueError('Kernel instruction denominator differs from embedded manifest ranges')
    starts = [start for start, _ in intervals]
    offsets = set()
    identities = []
    passed_rows = 0
    for report_path, report, report_hash in reports:
        if report.get('kind') not in VERIFICATION_KINDS:
            raise ValueError(f'Unsupported verification report: {report_path}')
        if report.get('container_sha256') != kernel_hash:
            raise ValueError(f'Stale verification source: {report_path}')
        if 'passed' in report and report['passed'] is not True:
            raise ValueError(f'Failed verification report: {report_path}')
        if 'compiler_source_sha256' in report and report['compiler_source_sha256'] != compiler:
            raise ValueError(f'Stale verification compiler: {report_path}')
        rows = report.get('verified')
        if not isinstance(rows, list):
            raise ValueError(f'Missing verified rows: {report_path}')
        # Older integer reports bind the compiler in every passed row, rather
        # than at report level. An empty such report cannot prove its compiler.
        if not rows and report.get('compiler_source_sha256') != compiler:
            raise ValueError(f'Unbound empty verification report: {report_path}')
        included = 0
        for row in rows:
            if row.get('passed') is not True:
                continue
            if row.get('compiler_source_sha256') != compiler:
                raise ValueError(f'Stale verified row compiler: {report_path}')
            comparisons = row.get('state_and_memory_comparisons', row.get('state_comparisons'))
            if natural(comparisons, 'native comparison count') == 0:
                raise ValueError('Verified row has no native comparisons')
            offset = natural(row.get('file_offset'), 'verified file_offset')
            size = natural(row.get('source_bytes'), 'verified source_bytes')
            if offset % 4 or size == 0 or size % 4 or offset + size > len(kernel_bytes):
                raise ValueError('Invalid verified source range')
            if hashlib.sha256(kernel_bytes[offset:offset + size]).hexdigest() != row.get('source_sha256'):
                raise ValueError('Verified source bytes changed')
            native_path = row.get('native_artifact')
            if not isinstance(native_path, str) or sha256(native_path) != row.get('native_sha256'):
                raise ValueError('Verified native artifact missing or changed')
            for position in range(offset, offset + size, 4):
                interval = bisect_right(starts, position) - 1
                if interval < 0 or position + 4 > intervals[interval][1]:
                    raise ValueError('Verified word is outside measured instruction sections')
                offsets.add(position)
            included += 1
        passed_rows += included
        identities.append({'path': str(report_path), 'sha256': report_hash, 'passed_native_rows': included})
    return {'status': 'pinned_native_differential_prefixes', 'unique_source_word_instances': len(offsets),
            'passed_native_rows_before_deduplication': passed_rows,
            'percentage': percentage(len(offsets), denominator), 'reports': identities,
            'limits': 'Counts unique source file words contained in passing native differential prefixes. Does not prove each word was reached by test inputs, every input behaves correctly, or whole functions/OS are verified.'}


def markdown(report):
    kernel = report['kernel']['percentage']
    apps = report['applications_aggregate']['percentage']
    verification = report['kernel_native_differential_prefixes']['percentage']
    def row(label, ratio, denominator=None):
        if ratio is None:
            return f'| {label} | Unknown | {denominator:,} | Unknown |'
        value = 'N/A (empty corpus)' if ratio['value'] is None else f"{ratio['value']:.4f}%"
        return f"| {label} | {ratio['numerator']:,} | {ratio['denominator']:,} | {value} |"
    return ('| Measurement | Source instances | Corpus instances | Coverage |\n'
            '| --- | ---: | ---: | ---: |\n' +
            row('Kernel: isolated emission', kernel) + '\n' +
            row('Eight apps: isolated emission', apps) + '\n' +
            row('Kernel: tested prefixes', verification, kernel['denominator']) + '\n\n' +
            f"Snapshot {report['measured_at_utc'].split('T')[0]} UTC; compiler `{report['compiler_source_sha256'][:12]}`.\n\n"
            'Counts are instruction instances, not unique ISA encodings. '
            'Isolated emission checks code generation; tested prefixes provide bounded native differential evidence and may contain unreached words. '
            'These are corpus percentages, not a whole-macOS completion percentage. '
            '[Method and provenance](docs/development.md).\n')


def write_markdown(destination, text):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=destination.parent, delete=False) as pending:
        pending.write(text)
        name = pending.name
    try:
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--kernel', type=Path, default=ROOT / '.stela/26A434/kernelcache.vma2.macho')
    parser.add_argument('--fileset-manifest', type=Path, default=ROOT / '.stela/26A434/kernel-fileset-functions.json')
    parser.add_argument('--corpus', type=Path, default=ROOT / '.stela/corpus-pairs.json')
    parser.add_argument('--verification-report', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/progress/corpus.json')
    parser.add_argument('--markdown-output', type=Path)
    args = parser.parse_args()
    corpus_data = args.corpus.read_bytes()
    corpus = json.loads(corpus_data)
    if corpus.get('kind') != 'universal_macho_instruction_corpus' or len(corpus.get('files', [])) != 8:
        raise ValueError('Expected pinned eight-application corpus')
    if any(not row.get('paired_architectures') or 'error' in row for row in corpus['files']):
        raise ValueError('Corpus contains an unpaired or failed input')
    paths = [row['path'] for row in corpus['files']]
    if len(set(paths)) != 8:
        raise ValueError('Duplicate corpus paths')
    kernel_data = args.kernel.read_bytes()
    if hashlib.sha256(kernel_data).hexdigest() != PINNED_KERNEL_SHA256:
        raise ValueError('Pinned kernel identity mismatch')
    manifest_data = args.fileset_manifest.read_bytes()
    manifest = json.loads(manifest_data)
    if manifest.get('container_sha256') != PINNED_KERNEL_SHA256:
        raise ValueError('Fileset manifest is for a different source')
    executable_hash = sha256(args.cli)
    kernel = measure(args.cli, args.kernel, PINNED_KERNEL_SHA256, manifest=args.fileset_manifest)
    compiler = kernel['compiler_source_sha256']
    applications = []
    for row in corpus['files']:
        probe = measure(args.cli, row['path'], row['file_sha256'], compiler)
        applications.append({'path': row['path'], **probe})
    if sha256(args.cli) != executable_hash:
        raise ValueError('CLI executable changed during measurement')
    if args.fileset_manifest.read_bytes() != manifest_data or args.corpus.read_bytes() != corpus_data:
        raise ValueError('Pinned input manifest changed during measurement')
    reports = []
    for path in args.verification_report:
        data = path.read_bytes()
        reports.append((path, json.loads(data), hashlib.sha256(data).hexdigest()))
    verification = collect_verification(reports, kernel_data, PINNED_KERNEL_SHA256, compiler,
                                        instruction_intervals(manifest, len(kernel_data)),
                                        kernel['counts']['source_word_instances'])
    report = {'schema_version': 1, 'kind': 'pinned_corpus_occurrence_progress',
              'measured_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': sha256(__file__),
              'corpus_manifest_sha256': hashlib.sha256(corpus_data).hexdigest(),
              'fileset_manifest_sha256': hashlib.sha256(manifest_data).hexdigest(),
              'kernel': {'path': str(args.kernel), **kernel}, 'applications': applications,
              'applications_aggregate': aggregate(applications),
              'kernel_native_differential_prefixes': verification,
              'limits': 'Static source instruction-word instances from pinned executable sections. Isolated emitter success is not whole-block translation or behavioral verification. Inline data and unreachable code may occur. No whole-OS completion percentage is inferred.'}
    archive = write_evidence(args.output, report)
    if args.markdown_output:
        write_markdown(args.markdown_output, markdown(report))
    print(json.dumps({'report': str(args.output), 'archive': str(archive),
                      'kernel': kernel['percentage'], 'applications': report['applications_aggregate']['percentage'],
                      'kernel_native_differential_prefixes': verification}, indent=2))


if __name__ == '__main__':
    main()
