"""Synthetic progress tests; no Apple inputs or native execution required."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('translation_progress', Path(__file__).with_name('translation-progress.py'))
progress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(progress)

COMPILER = 'c' * 64


def probe(source_hash='a' * 64, emitted=2, total=3):
    return {'schema_version': 1, 'kind': 'isolated_instruction_codegen_progress',
            'source_sha256': source_hash, 'compiler_source_sha256': COMPILER,
            'counts': {'source_word_instances': total, 'decoded_lifted_words': emitted,
                       'native_emitted_words': emitted, 'unsupported_words': total - emitted,
                       'unresolved_control_flow_words': 0, 'native_emitted_bytes': emitted * 3},
            'percentage': progress.percentage(emitted, total), 'verified_words': None}


class ProgressTests(unittest.TestCase):
    def test_percentages_and_empty_scope(self):
        self.assertEqual(progress.percentage(1, 3)['value'], 33.3333)
        self.assertEqual(progress.percentage(1, 32)['value'], 3.125)
        self.assertEqual(progress.percentage(1, 320000)['value'], 0.0003)
        self.assertEqual(progress.percentage(3, 3)['value'], 100)
        self.assertIsNone(progress.percentage(0, 0)['value'])
        for numerator, denominator in ((4, 3), (-1, 3), (True, 3), (1, False)):
            with self.assertRaises(ValueError):
                progress.percentage(numerator, denominator)

    def test_aggregate_weights_instruction_counts(self):
        result = progress.aggregate([probe(emitted=1, total=2), probe(emitted=1, total=8)])
        self.assertEqual(result['percentage'], progress.percentage(2, 10))
        with self.assertRaises(ValueError):
            progress.aggregate([])

    def test_probe_rejects_stale_or_inconsistent_evidence(self):
        self.assertEqual(progress.check_probe(probe(), 'a' * 64), COMPILER)
        for mutate in (
            lambda row: row.update(source_sha256='b' * 64),
            lambda row: row.update(compiler_source_sha256='b' * 64),
            lambda row: row.update(verified_words=2),
            lambda row: row['counts'].update(unsupported_words=4),
            lambda row: row['counts'].update(decoded_lifted_words=0),
            lambda row: row['percentage'].update(value=100),
        ):
            row = probe()
            mutate(row)
            with self.assertRaises(ValueError):
                progress.check_probe(row, 'a' * 64, COMPILER)

    def test_measure_pins_before_and_after_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'synthetic.bin'
            path.write_bytes(b'input')
            digest = progress.sha256(path)
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                return json.dumps(probe(digest))
            self.assertEqual(progress.measure('cli', path, digest, run=run)['source_sha256'], digest)
            self.assertEqual(calls[0][1], 'instruction-progress')
            with self.assertRaises(ValueError):
                progress.measure('cli', path, 'b' * 64, run=run)
            def changed(command, **kwargs):
                path.write_bytes(b'changed')
                return json.dumps(probe(digest))
            with self.assertRaises(ValueError):
                progress.measure('cli', path, digest, run=changed)

    def test_manifest_intervals_exclude_root_and_deduplicate(self):
        manifest = {'root': {'sections': [{'instructions': True, 'file_offset': 0, 'bytes': 100}]},
                    'images': [{'sections': [{'instructions': True, 'file_offset': 4, 'bytes': 12},
                                             {'instructions': True, 'file_offset': 12, 'bytes': 8},
                                             {'instructions': False, 'file_offset': 20, 'bytes': 8},
                                             {'instructions': True, 'zero_fill': True, 'file_offset': 28, 'bytes': 4}]}]}
        self.assertEqual(progress.instruction_intervals(manifest, 32), [(4, 20)])
        manifest['images'][0]['sections'][0]['bytes'] = 3
        with self.assertRaises(ValueError):
            progress.instruction_intervals(manifest, 32)

    def test_readme_update_requires_one_ordered_pair_and_preserves_context(self):
        start = '<!-- stela-instruction-progress:start -->'
        end = '<!-- stela-instruction-progress:end -->'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'README.md'
            for text in ('none', start + start + end, end + start):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    progress.update_readme(path, 'new table')
                self.assertEqual(path.read_text(), text)
            path.write_text('before\n' + start + '\nold\n' + end + '\nafter\n')
            progress.update_readme(path, 'new table\n')
            self.assertEqual(path.read_text(), 'before\n' + start + '\nnew table\n' + end + '\nafter\n')

    def test_markdown_unknown_verification_and_exact_ratio(self):
        report = {'kernel': probe(emitted=1, total=3), 'applications_aggregate': probe(emitted=2, total=7),
                  'kernel_native_differential_prefixes': {'percentage': None},
                  'measured_at_utc': '2026-10-12T00:00:00Z', 'compiler_source_sha256': COMPILER}
        text = progress.markdown(report)
        self.assertIn('| 1 | 3 | 33.3333% |', text)
        self.assertIn('| Unknown | 3 | Unknown |', text)
        self.assertIn('not a whole-macOS completion percentage', text)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.native = Path(self.directory.name) / 'native.bin'
        self.native.write_bytes(b'\xc3')
        self.kernel = bytes(range(32))
        self.kernel_hash = hashlib.sha256(self.kernel).hexdigest()
        self.intervals = [(4, 24)]
        self.row = {'passed': True, 'compiler_source_sha256': COMPILER, 'state_comparisons': 16,
                    'file_offset': 4, 'source_bytes': 8, 'source_sha256': hashlib.sha256(self.kernel[4:12]).hexdigest(),
                    'native_artifact': str(self.native), 'native_sha256': progress.sha256(self.native)}
        self.report = {'kind': 'real_kernel_integer_leafs', 'container_sha256': self.kernel_hash,
                       'verified': [self.row], 'declined': [{'file_offset': 16, 'source_bytes': 4}]}

    def collect(self, reports=None, **kwargs):
        entries = [] if reports == [] else [(Path('synthetic.json'), report, 'f' * 64)
                                           for report in (reports or [self.report])]
        return progress.collect_verification(entries, kwargs.get('kernel', self.kernel), self.kernel_hash,
                                             COMPILER, self.intervals, kwargs.get('denominator', 5))

    def test_no_report_is_unknown_not_zero(self):
        result = self.collect([])
        self.assertIsNone(result['unique_source_word_instances'])
        self.assertIsNone(result['percentage'])

    def test_unique_word_offsets_across_overlapping_reports(self):
        second = copy.deepcopy(self.report)
        second['verified'][0].update(file_offset=8, source_sha256=hashlib.sha256(self.kernel[8:16]).hexdigest())
        # Failed and declined rows do not count, even when their metadata is bad.
        second['verified'].append({'passed': False})
        result = self.collect([self.report, second, self.report])
        self.assertEqual(result['unique_source_word_instances'], 3)
        self.assertEqual(result['percentage'], progress.percentage(3, 5))
        self.assertEqual(result['passed_native_rows_before_deduplication'], 3)

    def test_stale_container_compiler_and_source_bytes_fail_closed(self):
        for mutate in (
            lambda report: report.update(container_sha256='b' * 64),
            lambda report: report.update(compiler_source_sha256='b' * 64),
            lambda report: report['verified'][0].update(compiler_source_sha256='b' * 64),
            lambda report: report['verified'][0].update(source_sha256='b' * 64),
            lambda report: report['verified'][0].update(file_offset=5),
            lambda report: report['verified'][0].update(state_comparisons=0),
            lambda report: report.update(passed=False),
            lambda report: report.update(kind='arm_reference_only'),
        ):
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.assertRaises(ValueError):
                self.collect([report])
        with self.assertRaises(ValueError):
            self.collect(kernel=b'different')
        with self.assertRaises(ValueError):
            self.collect(denominator=4)

    def test_changed_native_artifact_is_not_verified(self):
        self.native.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.collect()

    def test_verified_rows_must_be_in_measured_sections(self):
        self.row.update(file_offset=0, source_sha256=hashlib.sha256(self.kernel[:8]).hexdigest())
        with self.assertRaises(ValueError):
            self.collect()

    def test_empty_old_report_requires_top_level_compiler_binding(self):
        self.report['verified'] = []
        with self.assertRaises(ValueError):
            self.collect()
        self.report['compiler_source_sha256'] = COMPILER
        self.assertEqual(self.collect()['unique_source_word_instances'], 0)


if __name__ == '__main__':
    unittest.main()
