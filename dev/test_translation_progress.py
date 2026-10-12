"""Synthetic Apple-silicon progress tests; no Apple input or native execution required."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('translation_progress', Path(__file__).with_name('translation-progress.py'))
progress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(progress)
COMPILER = 'c' * 64


def fixtures():
    base = {'category': 'base_integer_system', 'alias': False, 'source_file': 'synthetic.xml',
            'source_sha256': 'a' * 64, 'profile': 'test-profile', 'scope': 'Test width form',
            'review': 'Reviewed test implementation', 'compiler_sources': ['compiler.rs'],
            'evidence_groups': ['carry']}
    rows = [
        {**base, 'id': 'ADC_32_addsub_carry', 'status': 'implemented',
         'encoding_mask': '0xffe0fc00', 'encoding_value': '0x1a000000',
         'smoke_samples': [{'word': '0x1a000000', 'expected_mnemonics': ['adc']}]},
        {**base, 'id': 'RET_64R_branch_reg', 'status': 'partial',
         'encoding_mask': '0xfffffc1f', 'encoding_value': '0xd65f0000',
         'smoke_samples': [{'word': '0xd65f03c0', 'expected_mnemonics': ['ret']}],
         'rejected_samples': [{'word': '0xd65f0000', 'reason': 'unsupported'}]},
    ]
    return {'schema_version': 2, 'kind': 'reviewed_apple_silicon_instruction_forms',
            'registry_version': 'synthetic-v1', 'instruction_sources': [{'publisher': 'Synthetic'}],
            'target_profile': {'vendor': 'Apple', 'guest_architectures': ['arm64', 'arm64e'],
                               'host_architecture': 'x86_64', 'required_isa_inventory_complete': False,
                               'required_isa_form_count': None, 'inventory_limits': 'Incomplete synthetic list'},
            'profile': {'id': 'test-profile', 'outside_scope': ['OS boot']},
            'forms': rows, 'evidence_groups': {'carry': {'harness': 'carry.py',
                     'report': 'carry.json', 'kind': 'add_sub_carry_arm_vs_native_x86'}}}


class IsaProgressTests(unittest.TestCase):
    def test_reviewed_counts_never_manufacture_completion_denominator(self):
        registry = fixtures()
        rows = progress.validate_registry(registry)
        summary = progress.summarize(rows)
        self.assertEqual(summary['reviewed'], {'implemented': 1, 'partial': 1,
                                              'unsupported': 0, 'reviewed_forms': 2})
        self.assertIsNone(summary['required_isa_forms'])
        self.assertIsNone(summary['required_isa_completion_percentage'])
        self.assertIsNone(summary['overall_completion_percentage'])
        self.assertEqual(summary['complete_binaries']['verified'], 0)
        self.assertFalse(summary['complete_binaries']['full_binary_harness_available'])
        self.assertNotIn('sve', summary['categories'])

    def test_no_alias_or_duplicate_can_inflate_counts(self):
        for change in ('alias', 'duplicate'):
            registry = fixtures()
            if change == 'alias':
                registry['forms'][0]['alias'] = True
            else:
                registry['forms'][1]['id'] = registry['forms'][0]['id']
            with self.assertRaises(ValueError):
                progress.validate_registry(registry)

    def test_apple_target_and_incomplete_inventory_are_enforced(self):
        for field, value in (('vendor', 'Arm'), ('guest_architectures', ['aarch64']),
                             ('host_architecture', 'aarch64'), ('required_isa_inventory_complete', True),
                             ('required_isa_form_count', 148)):
            registry = fixtures()
            registry['target_profile'][field] = value
            with self.assertRaises(ValueError):
                progress.validate_registry(registry)

    def test_width_forms_must_match_their_actual_fixed_bits(self):
        registry = fixtures()
        registry['forms'][0]['smoke_samples'][0]['word'] = '0x9a000000'
        with self.assertRaises(ValueError):
            progress.validate_registry(registry)

    def test_extended_and_shifted_byte_offsets_are_distinct_forms(self):
        form = {'id': 'LDRB_32B_ldst_regoff', 'encoding_mask': '0xffe00c00',
                'encoding_value': '0x38600800', 'docvars': {'reguse': 'ext-reg'}}
        sample = {'word': '0x38604800', 'expected_mnemonics': ['ldrb']}
        progress.validate_sample(form, sample)
        sample['word'] = '0x38606800'
        with self.assertRaises(ValueError):
            progress.validate_sample(form, sample)
        form['docvars']['reguse'] = 'shifted-reg'
        progress.validate_sample(form, sample)

    def test_alias_mnemonic_smoke_does_not_create_a_second_support_unit(self):
        registry = fixtures()
        row = registry['forms'][0]
        row.update(id='ANDS_32_log_imm', encoding_mask='0xff800000', encoding_value='0x72000000',
                   smoke_samples=[{'word': '0x7200001f', 'expected_mnemonics': ['tst']}])
        registry['forms'] = [row]
        rows = progress.validate_registry(registry)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(progress, 'compile_probe', return_value={
                    'emitted': True, 'compiler_source_sha256': COMPILER}):
                compiler, probes = progress.smoke_forms('synthetic-cli', rows, rows, Path(temporary))
        self.assertEqual(compiler, COMPILER)
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]['id'], 'ANDS_32_log_imm')
        self.assertTrue(probes[0]['assembly'].startswith('tst '))
        self.assertEqual(progress.summarize(rows)['reviewed']['implemented'], 1)

    def test_reviewed_leaf_results_never_count_as_complete_binaries(self):
        registry = fixtures()
        registry['evidence_groups']['carry']['complete_binaries'] = 99
        rows = progress.validate_registry(registry)
        self.assertEqual(progress.summarize(rows)['complete_binaries']['verified'], 0)

    def test_invalid_status_source_facts_and_encoding_are_rejected(self):
        for field, value in (('status', 'emitted'), ('source_file', ''), ('source_sha256', ''),
                             ('encoding_value', '0xffffffff'), ('source_sha256', 'not-a-digest')):
            registry = fixtures()
            registry['forms'][0][field] = value
            with self.assertRaises(ValueError):
                progress.validate_registry(registry)

    def test_source_paths_cannot_escape_repository(self):
        for path in ('../compiler.rs', '/compiler.rs', ''):
            registry = fixtures()
            registry['forms'][0]['compiler_sources'] = [path]
            with self.assertRaises(ValueError):
                progress.validate_registry(registry)

    def test_smoke_alone_cannot_promote_unreviewed_support(self):
        for field in ('review', 'compiler_sources', 'evidence_groups', 'scope'):
            registry = fixtures()
            registry['forms'][0].pop(field)
            with self.assertRaises(ValueError):
                progress.validate_registry(registry)
        registry = fixtures()
        registry['forms'][1].pop('rejected_samples')
        with self.assertRaises(ValueError):
            progress.validate_registry(registry)

    def test_compile_probe_really_requires_native_artifact_and_source_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def fake(command, **kwargs):
                source = Path(command[2])
                output = Path(command[-1])
                output.mkdir()
                (output / 'native.bin').write_bytes(b'\xc3')
                manifest = {'source_sha256': progress.sha256(source), 'native_sha256': progress.sha256(output / 'native.bin'),
                            'compiler_source_sha256': COMPILER}
                return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
            result = progress.compile_probe('cli', 0x1a000000, directory, run=fake)
            self.assertTrue(result['emitted'])
            self.assertEqual(result['compiler_source_sha256'], COMPILER)
        with tempfile.TemporaryDirectory() as temporary:
            def rejected(command, **kwargs):
                return subprocess.CompletedProcess(command, 1, '', 'unsupported instruction')
            with self.assertRaises(ValueError):
                progress.compile_probe('cli', 0x1a000000, Path(temporary), run=rejected)

    def test_scope_boundary_must_reject_without_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            def rejected(command, **kwargs):
                return subprocess.CompletedProcess(command, 1, '', 'UnresolvedDirectTarget')
            self.assertTrue(progress.compile_probe('cli', 0x14000002, Path(temporary),
                            'UnresolvedDirectTarget', run=rejected)['rejected'])
            def accepted(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, '', '')
            with self.assertRaises(ValueError):
                progress.compile_probe('cli', 0x14000002, Path(temporary), 'UnresolvedDirectTarget', run=accepted)

    def test_markdown_reports_unknown_goal_progress_and_no_reviewed_ratio(self):
        rows = progress.validate_registry(fixtures())
        report = {'summary': progress.summarize(rows), 'measured_at_utc': '2026-10-12T00:00:00Z',
                  'compiler_source_sha256': COMPILER}
        text = progress.markdown(report)
        self.assertIn('| Leaf-profile instruction forms implemented | 1 |', text)
        self.assertIn('| Leaf-profile instruction forms partially implemented | 1 |', text)
        self.assertIn('| Required ISA completion | Unknown |', text)
        self.assertIn('| Overall compatibility completion | Unknown |', text)
        self.assertIn('| Complete binaries verified through Stela | 0 |', text)
        self.assertIn('aliases excluded', text)
        self.assertNotIn('%', text)

    def test_compiled_source_fingerprint_must_match_current_ordered_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'one.rs').write_bytes(b'one')
            (root / 'two.rs').write_bytes(b'two')
            registry = {'compiler_fingerprint_sources': ['one.rs', 'two.rs']}
            compiler = hashlib.sha256(b'onetwo').hexdigest()
            sources = progress.validate_current_compiler(registry, compiler, root)
            self.assertEqual(sources['one.rs'], hashlib.sha256(b'one').hexdigest())
            registry['compiler_fingerprint_sources'].reverse()
            with self.assertRaises(ValueError):
                progress.validate_current_compiler(registry, compiler, root)
            registry['compiler_fingerprint_sources'].reverse()
            (root / 'two.rs').write_bytes(b'unbuilt change')
            with self.assertRaises(ValueError):
                progress.validate_current_compiler(registry, compiler, root)

    def test_readme_update_only_replaces_one_ordered_marker_pair(self):
        start, end = '<!-- stela-instruction-progress:start -->', '<!-- stela-instruction-progress:end -->'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'README.md'
            path.write_text('before\n' + start + '\nold\n' + end + '\nafter\n')
            progress.update_readme(path, 'new\n')
            self.assertEqual(path.read_text(), 'before\n' + start + '\nnew\n' + end + '\nafter\n')
            for content in ('none', start + start + end, end + start):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    progress.update_readme(path, 'new')
                self.assertEqual(path.read_text(), content)


class BlockProgressTests(unittest.TestCase):
    def fake_compiler(self, mutation=None):
        def fake(command, **kwargs):
            self.assertEqual(command[1], 'compile-block')
            self.assertEqual(command[command.index('--guest-base') + 1], '0x10000000')
            source = Path(command[2])
            output = Path(command[command.index('--output-dir') + 1])
            output.mkdir()
            (output / 'native.bin').write_bytes(b'\xc3')
            manifest = {'source_sha256': hashlib.sha256(source.read_bytes()[:4]).hexdigest(),
                        'source_bytes': 4, 'abi': progress.BLOCK_ABI,
                        'native_sha256': progress.sha256(output / 'native.bin'),
                        'compiler_source_sha256': COMPILER}
            if mutation:
                mutation(manifest, source)
            return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
        return fake

    def test_block_probe_binds_consumed_prefix_instead_of_trailing_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = progress.compile_probe('cli', 0xd63f03c0, Path(temporary),
                                            run=self.fake_compiler(), mode='block')
        self.assertEqual(result['source_bytes'], 4)
        self.assertEqual(result['abi'], progress.BLOCK_ABI)
        with tempfile.TemporaryDirectory() as temporary:
            def full_source_hash(manifest, source):
                manifest['source_sha256'] = progress.sha256(source)
            with self.assertRaisesRegex(ValueError, 'source identity'):
                progress.compile_probe('cli', 0xd63f03c0, Path(temporary),
                                       run=self.fake_compiler(full_source_hash), mode='block')

    def test_block_probe_rejects_false_boundary_and_incompatible_abi(self):
        changes = [{'source_bytes': value} for value in (False, 0, -4, 8, 12, '4')]
        changes += [{'abi': 'leaf-abi'}, {'abi': None}]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                def mutate(manifest, _source):
                    manifest.update(change)
                with self.assertRaises(ValueError):
                    progress.compile_probe('cli', 0xd63f03c0, Path(temporary),
                                           run=self.fake_compiler(mutate), mode='block')

    def test_block_smoke_selects_block_compiler_without_changing_leaf_default(self):
        registry = fixtures()
        registry['forms'] = [registry['forms'][1]]
        registry['forms'][0]['status'] = 'implemented'
        registry['forms'][0].pop('rejected_samples')
        rows = progress.validate_registry(registry)
        for mode, expected_kwargs in (('leaf', {}), ('block', {'mode': 'block'})):
            with tempfile.TemporaryDirectory() as temporary:
                with patch.object(progress, 'compile_probe', return_value={
                        'emitted': True, 'compiler_source_sha256': COMPILER}) as probe:
                    progress.smoke_forms('cli', rows, rows, Path(temporary), mode=mode)
            self.assertEqual(probe.call_args.kwargs, expected_kwargs)

    def test_separate_profiles_do_not_inflate_instruction_count(self):
        root = Path(__file__).resolve().parents[1]
        leaf = progress.validate_registry(json.loads((root / 'tests/isa/apple-silicon-reviewed-forms.json').read_text()))
        block = progress.validate_registry(json.loads((root / 'tests/isa/apple-silicon-block-forms.json').read_text()))
        self.assertEqual(progress.summarize(leaf)['reviewed']['implemented'], 157)
        self.assertEqual(progress.summarize(leaf)['reviewed']['partial'], 9)
        self.assertEqual(progress.summarize(block)['reviewed']['implemented'], 12)
        self.assertEqual(len(set(leaf) & set(block)), 9)
        report = {'summary': progress.summarize(leaf), 'measured_at_utc': '2026-10-12T00:00:00Z',
                  'compiler_source_sha256': COMPILER,
                  'block_profile_evidence': {'summary': progress.summarize(block),
                      'native_differential_evidence': {'block': {'native_comparisons': 28704}}}}
        text = progress.markdown(report)
        self.assertIn('| Leaf-profile instruction forms implemented | 157 |', text)
        self.assertIn('| Block-profile control-flow forms implemented | 12 |', text)
        self.assertIn('| Native block state/exit comparisons | 28,704 |', text)
        self.assertIn('counts overlap and are not added', text)
        self.assertNotIn('| 169 |', text)
        self.assertNotIn('%', text)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.registry = fixtures()
        self.rows = progress.validate_registry(self.registry)
        (self.root / 'carry.py').write_text('synthetic harness')
        (self.root / 'compiler.rs').write_text('synthetic compiler')
        self.report = {'kind': 'add_sub_carry_arm_vs_native_x86', 'passed': True,
                       'compiler_source_sha256': COMPILER, 'three_way_register_state_comparisons': 42,
                       'harness_source_sha256': progress.sha256(self.root / 'carry.py')}
        self.write_report()

    def write_report(self):
        (self.root / 'carry.json').write_text(json.dumps(self.report))

    def test_requires_current_native_differential_evidence_and_source_hashes(self):
        reports, sources = progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.assertEqual(reports['carry']['native_comparisons'], 42)
        self.assertEqual(sources['compiler.rs'], progress.sha256(self.root / 'compiler.rs'))

    def test_failed_arm_only_stale_and_unbound_reports_cannot_count(self):
        original = copy.deepcopy(self.report)
        for changes in ({'passed': False}, {'kind': 'arm_reference_only'}, {'compiler_source_sha256': 'b' * 64},
                        {'three_way_register_state_comparisons': 0}, {'harness_source_sha256': 'b' * 64}):
            self.report = {**original, **changes}
            self.write_report()
            with self.assertRaises(ValueError):
                progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.report = original
        self.report.pop('harness_source_sha256')
        self.write_report()
        with self.assertRaises(ValueError):
            progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)

    def test_shared_runner_and_imported_sources_must_match_current_bytes(self):
        (self.root / 'dev').mkdir()
        runner = self.root / 'dev/differential.py'
        helper = self.root / 'dev/helper.py'
        runner.write_text('shared runner')
        helper.write_text('shared helper')
        self.report['shared_runner_sha256'] = progress.sha256(runner)
        self.report['shared_sources_sha256'] = {'helper.py': progress.sha256(helper)}
        self.write_report()
        evidence, _ = progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.assertEqual(len(evidence['carry']['shared_sources_sha256']), 2)
        helper.write_text('changed helper')
        with self.assertRaises(ValueError):
            progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)

    def test_conflicting_shared_runner_identities_are_rejected(self):
        (self.root / 'dev').mkdir()
        runner = self.root / 'dev/differential.py'
        runner.write_text('shared runner')
        self.report['shared_runner_sha256'] = progress.sha256(runner)
        self.report['shared_sources_sha256'] = {'dev/differential.py': 'b' * 64}
        self.write_report()
        with self.assertRaises(ValueError):
            progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)


    def test_block_evidence_requires_current_compiler_and_runtime_sources(self):
        self.registry['evidence_groups']['carry'].update(
            kind='arm64_block_control_flow_differential', abi=progress.BLOCK_ABI,
            required_shared_sources=['runtime.rs'])
        (self.root / 'runtime.rs').write_text('native runtime')
        self.report.update(kind='arm64_block_control_flow_differential', abi=progress.BLOCK_ABI,
                           single_block_state_exit_comparisons=28704,
                           multiblock_state_exit_comparisons=528,
                           rust_runtime_execution_comparisons=64,
                           shared_sources_sha256={'runtime.rs': progress.sha256(self.root / 'runtime.rs')})
        self.report.pop('three_way_register_state_comparisons')
        self.write_report()
        reports, _ = progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.assertEqual(reports['carry']['native_comparisons'], 28704)
        self.assertEqual(reports['carry']['rust_runtime_execution_comparisons'], 64)
        self.report['compiler_executable_sha256'] = 'd' * 64
        self.write_report()
        progress.validate_evidence(self.registry, self.rows, COMPILER, self.root, executable_hash='d' * 64)
        with self.assertRaisesRegex(ValueError, 'runtime executable'):
            progress.validate_evidence(self.registry, self.rows, COMPILER, self.root, executable_hash='e' * 64)
        current = copy.deepcopy(self.report)
        for changes in ({'compiler_source_sha256': 'b' * 64}, {'shared_sources_sha256': {}},
                        {'abi': 'leaf'}, {'rust_runtime_execution_comparisons': 0},
                        {'single_block_state_exit_comparisons': 0}):
            self.report = {**current, **changes}
            self.write_report()
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.report = current
        self.write_report()
        (self.root / 'runtime.rs').write_text('changed runtime')
        with self.assertRaisesRegex(ValueError, 'Stale shared'):
            progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)


if __name__ == '__main__':
    unittest.main()
