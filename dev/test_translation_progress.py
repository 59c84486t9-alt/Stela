"""Synthetic Apple-silicon progress tests; no Apple input or native execution required."""
import copy
from collections import Counter
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import a64_disassembly as disassembly

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
    def test_cssc_fixed_encoding_alternative_is_explicit_and_canonical(self):
        catalog = json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
        facts = progress.a64_checklist.validate(catalog)
        cssc = [row for row in facts.values()
                if any(feature['feature'] == 'FEAT_CSSC' for feature in row['features'])]
        self.assertEqual(len(cssc), 22)
        decoder = type('UnavailableDecoder', (), {'disasm': lambda self, data, address: iter(())})()
        for row in cssc:
            word = int(row['encoding_value'], 16) | 0x3ff
            mnemonic, assembly, basis = progress.smoke_decoding(decoder, word, row['id'], facts)
            self.assertEqual((mnemonic, assembly), (row['mnemonic'].lower(), row['mnemonic'].lower()))
            self.assertEqual(basis, 'pinned_arm_cssc_fixed_encoding')
            with self.assertRaises(ValueError):
                progress.smoke_decoding(decoder, word ^ (1 << 31), row['id'], facts)

    def test_fixed_encoding_alternative_does_not_cover_other_families_or_missing_facts(self):
        catalog = json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
        facts = progress.a64_checklist.validate(catalog)
        decoder = type('UnavailableDecoder', (), {'disasm': lambda self, data, address: iter(())})()
        for identity in ('ABS_32_dp_1src', 'RET_64R_branch_reg'):
            row = facts[identity]
            with self.assertRaises(ValueError):
                progress.smoke_decoding(decoder, int(row['encoding_value'], 16), identity)
        with self.assertRaises(ValueError):
            progress.smoke_decoding(decoder, progress.RET, 'RET_64R_branch_reg', facts)

    def test_implementation_refresh_preserves_archived_verification_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'apple-silicon.json'
            self.assertIsNone(progress.previous_checkpoint(path, root))
            report = {'kind': 'apple_silicon_translation_progress',
                      'native_differential_evidence': {'scalar': {}},
                      'compiler_source_sha256': COMPILER, 'measured_at_utc': '2026-10-13',
                      'apple_codegen_candidates': {'summary': {'union': {'implemented': 292, 'total': 3119}}}}
            def save():
                data = json.dumps(report).encode()
                path.write_bytes(data)
                archive = root / '.stela/evidence' / path.stem
                archive.mkdir(parents=True, exist_ok=True)
                (archive / (hashlib.sha256(data).hexdigest() + '.json')).write_bytes(data)
            path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                progress.previous_checkpoint(path, root)
            save()
            checkpoint = progress.previous_checkpoint(path, root)
            self.assertEqual(checkpoint['implemented'], 292)
            report.update(implementation_only=True, last_verified_checkpoint=checkpoint,
                          compiler_source_sha256='d' * 64, native_differential_evidence={})
            report['apple_codegen_candidates']['summary']['union']['implemented'] = 310
            save()
            self.assertEqual(progress.previous_checkpoint(path, root), checkpoint)

    def test_documented_checklist_uses_complete_pinned_facts_not_observed_subset(self):
        path = progress.ROOT / 'tests/isa/a64-documented-checklist.json'
        catalog = json.loads(path.read_bytes())
        rows = progress.a64_checklist.validate(catalog)
        self.assertEqual(len(rows), 4332)
        self.assertEqual(Counter(r['category'] for r in rows.values()),
                         {'base_integer_system': 954, 'fp_simd': 1212, 'sve': 1389, 'sme': 777})
        for mutation in ('remove', 'duplicate', 'facts', 'rehashed_facts'):
            changed = copy.deepcopy(catalog)
            if mutation == 'remove':
                changed['forms'].pop()
            elif mutation == 'duplicate':
                changed['forms'][-1] = changed['forms'][0]
            else:
                changed['forms'][0]['encoding_value'] = '0x00000000'
                if mutation == 'rehashed_facts':
                    changed['facts_sha256'] = progress.a64_checklist.facts_hash(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                progress.a64_checklist.validate(changed)

    def test_documented_counts_deduplicate_profiles_and_ignore_generated_status_claims(self):
        catalog = json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
        form = next(r for r in catalog['forms'] if r['id'] == 'RET_64R_branch_reg')
        row = {**form, 'source_sha256': catalog['source_files_sha256'][form['source_file']],
               'profile': 'one', 'scope': 'bounded reviewed semantics', 'status': 'partial'}
        catalog['forms'][0]['status'] = 'implemented'  # Generated fields cannot confer support.
        _, counts = progress.a64_checklist.assess(catalog, [{'forms': [row]}])
        self.assertEqual((counts['implemented'], counts['partial'], counts['implementation_percentage']), (0, 1, 0))
        assessed, counts = progress.a64_checklist.assess(catalog, [
            {'forms': [row]}, {'forms': [{**row, 'profile': 'two', 'status': 'implemented'}]},
            {'forms': [{**row, 'profile': 'three', 'status': 'implemented'}]}])
        self.assertEqual((counts['implemented'], counts['partial'], counts['total']), (1, 0, 4332))
        self.assertEqual(counts['implementation_percentage'], 100 / 4332)
        self.assertEqual(len(next(r for r in assessed['forms'] if r['id'] == row['id'])['profiles']), 3)
        for key, value in [('id', 'invented_alias'), ('encoding_mask', '0xffffffff'), ('source_sha256', '0' * 64)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                progress.a64_checklist.assess(catalog, [{'forms': [{**row, key: value}]}])

    def test_readme_reference_percentage_and_apple_ledger_are_separate(self):
        report = {'summary': progress.summarize(progress.validate_registry(fixtures())),
            'compiler_source_sha256': COMPILER,
            'documented_isa': {'summary': {'implemented': 277, 'partial': 13, 'unsupported': 4042,
                                          'total': 4332, 'implementation_percentage': 27700 / 4332}},
            'apple_specific_extensions': {'implemented': 0, 'tracked': 3}}
        text = progress.markdown(report)
        self.assertIn('277 / 4,332 (6.39%)', text)
        self.assertIn('13 |', text)
        self.assertIn('0 implemented / 3 tracked; inventory open', text)
        self.assertIn('not macOS or application completion', text)

    def test_readme_apple_candidates_replace_broader_arm_headline_without_claiming_hardware_completion(self):
        report = {'summary': progress.summarize(progress.validate_registry(fixtures())),
            'compiler_source_sha256': COMPILER,
            'documented_isa': {'summary': {'implemented': 284, 'total': 4332}},
            'apple_codegen_candidates': {'summary': {'union': {'implemented': 284, 'partial': 13,
                'unsupported': 2822, 'total': 3119, 'implementation_percentage': 28400 / 3119}}},
            'apple_specific_extensions': {'implemented': 0, 'tracked': 3}}
        text = progress.markdown(report)
        self.assertIn('284 / 3,119 (9.11%)', text)
        self.assertIn('streaming SVE through SME', text)
        self.assertIn('Full hardware membership and Apple-private additions remain open', text)
        self.assertNotIn('4,332', text)
        self.assertIn('reviewed execution profiles', text)
        report['implementation_only'] = True
        text = progress.markdown(report)
        self.assertIn('Last full instruction-verification checkpoint | Pending', text)
        self.assertIn('implementation and emission smoke checks', text)
        report['last_verified_checkpoint'] = {'implemented': 292, 'total': 3119,
                                              'compiler_source_sha256': 'd' * 64}
        self.assertIn('292 / 3,119; compiler `dddddddddddd`', progress.markdown(report))

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

    def test_nonterminal_block_probe_requires_its_declared_ret_boundary(self):
        def full_prefix(manifest, source):
            manifest.update(source_bytes=8, source_sha256=progress.sha256(source))
        with tempfile.TemporaryDirectory() as temporary:
            result = progress.compile_probe('cli', 0x1e222820, Path(temporary),
                run=self.fake_compiler(full_prefix), mode='block', expected_source_bytes=8)
        self.assertEqual(result['source_bytes'], 8)
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, 'boundary'):
            progress.compile_probe('cli', 0x1e222820, Path(temporary),
                run=self.fake_compiler(), mode='block', expected_source_bytes=8)
        registry = fixtures()
        row = registry['forms'][0]
        for invalid in (False, 0, 12, '8'):
            sample = {**row['smoke_samples'][0], 'consumed_source_bytes': invalid}
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                progress.validate_sample(row, sample)

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

    def test_crc_family_requires_its_own_two_profile_and_reserved_evidence(self):
        root = Path(__file__).resolve().parents[1]
        registry = json.loads((root / 'tests/isa/apple-silicon-reviewed-forms.json').read_text())
        rows = progress.validate_registry(registry)
        crc = [row for row in rows.values() if row['source_file'] in ('crc32.xml', 'crc32c.xml')]
        self.assertEqual(len(crc), 8)
        self.assertTrue(all(row['status'] == 'implemented' and row['evidence_groups'] == ['scalar_crc']
                            for row in crc))
        group = registry['evidence_groups']['scalar_crc']
        self.assertEqual(group['comparison_field'], 'crc_three_way_register_state_comparisons')
        required = group['required_measurements']
        for profile in ('baseline', 'sse4.2'):
            prefix = '/crc_profiles/sse4.2/' if profile == 'sse4.2' else 'crc_profiles.baseline.'
            self.assertEqual(required[prefix + 'programs'], 362)
            self.assertEqual(required[prefix + 'comparisons'], 136448)
        self.assertEqual(required['crc_block_state_comparisons'], 256)
        self.assertEqual(required['crc_reserved.reserved_forms'], 8)
        self.assertEqual(required['crc_reserved.native_explicit_declines'], 16)

    def test_separate_profiles_do_not_inflate_instruction_count(self):
        leaf_registry = fixtures()
        block_registry = copy.deepcopy(leaf_registry)
        block_registry['profile']['id'] = 'block-profile'
        for row in block_registry['forms']:
            row['profile'] = 'block-profile'
        leaf = progress.validate_registry(leaf_registry)
        block = progress.validate_registry(block_registry)
        self.assertEqual(progress.summarize(leaf)['reviewed']['implemented'], 1)
        self.assertEqual(progress.summarize(leaf)['reviewed']['partial'], 1)
        self.assertEqual(progress.summarize(block)['reviewed']['implemented'], 1)
        self.assertEqual(progress.summarize(block)['reviewed']['partial'], 1)
        self.assertEqual(set(leaf) & set(block), {'ADC_32_addsub_carry', 'RET_64R_branch_reg'})
        report = {'summary': progress.summarize(leaf), 'measured_at_utc': '2026-10-12T00:00:00Z',
                  'compiler_source_sha256': COMPILER,
                  'block_profile_evidence': {'summary': progress.summarize(block),
                      'native_differential_evidence': {
                          'block': {'native_comparisons': 28704},
                          'traps': {'native_comparisons': 320,
                                    'comparison_field': 'trap_state_exit_comparisons'}}}}
        text = progress.markdown(report)
        self.assertIn('| Leaf-profile instruction forms implemented | 1 |', text)
        self.assertIn('| Block-profile instruction forms implemented | 1 |', text)
        self.assertIn('| Native block state/exit comparisons | 28,704 |', text)
        self.assertIn('| Block-profile forms partially implemented | 1 |', text)
        self.assertIn('| Native synchronous-trap boundary comparisons | 320 |', text)
        self.assertIn('counts overlap and are not added', text)
        self.assertNotIn('| 171 |', text)
        self.assertNotIn('%', text)



class ScalableProgressTests(unittest.TestCase):
    def profile(self):
        return {'id': progress.SCALABLE_PROFILE, 'compiler_command': 'compile-leaf',
                'abi': progress.CONTEXT_LEAF_ABI, 'svl_bytes': 16, 'svcr': 3,
                'outside_scope': ['OS boot']}

    def fake_compiler(self, mutation=None):
        def fake(command, **kwargs):
            self.assertEqual(command[1], 'compile-leaf')
            self.assertEqual(command[command.index('--guest-profile') + 1], progress.SCALABLE_PROFILE)
            self.assertEqual(command[command.index('--guest-base') + 1], '0x10000000')
            self.assertEqual(command[command.index('--cpu-target') + 1], 'x86_64-baseline')
            source = Path(command[2])
            output = Path(command[command.index('--output-dir') + 1])
            output.mkdir()
            (output / 'native.bin').write_bytes(bytes(13) + b'\xc3\xc3')
            manifest = {'schema_version': 2, 'kind': 'raw_arm64_leaf_aot',
                        'abi': progress.CONTEXT_LEAF_ABI, 'target_cpu': 'x86_64-baseline',
                        'guest_base': progress.SCALABLE_GUEST_BASE, 'guest_instructions': 2,
                        'execution_profile': {'id': progress.SCALABLE_PROFILE,
                            'svl_bytes': int(command[command.index('--svl-bytes') + 1]),
                            'svcr': int(command[command.index('--svcr') + 1])},
                        'entry_prefix_bytes': 13, 'native_bytes': 15,
                        'source_map': [[progress.SCALABLE_GUEST_BASE, 13],
                                       [progress.SCALABLE_GUEST_BASE + 4, 14]],
                        'source_sha256': progress.sha256(source),
                        'native_sha256': progress.sha256(output / 'native.bin'),
                        'compiler_source_sha256': COMPILER}
            if mutation:
                mutation(manifest)
            return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
        return fake

    def probe(self, directory, **kwargs):
        return progress.compile_probe('cli', progress.RET, directory, mode='scalable',
            guest_profile=progress.SCALABLE_PROFILE, **kwargs)

    def test_explicit_uniform_profile_keeps_host_target_separate(self):
        for length in progress.SCALABLE_VECTOR_BYTES:
            for svcr in range(4):
                with self.subTest(length=length, svcr=svcr), tempfile.TemporaryDirectory() as directory:
                    result = self.probe(Path(directory), svl_bytes=length, svcr=svcr,
                                        run=self.fake_compiler())
                self.assertEqual(result['abi'], progress.CONTEXT_LEAF_ABI)
                self.assertEqual(result['execution_profile'], {
                    'id': progress.SCALABLE_PROFILE, 'svl_bytes': length, 'svcr': svcr})
                self.assertEqual(result['target_cpu'], 'x86_64-baseline')
                self.assertEqual(result['source_map'][0], [progress.SCALABLE_GUEST_BASE, 13])

    def test_context_manifest_accepts_emitted_target_id_instead_of_cli_alias(self):
        # Metadata from the retained core-integration/actual-ret-1 manifest.
        # TargetCpu::id canonicalizes the accepted CLI alias "baseline".
        manifest = {
            'schema_version': 2, 'kind': 'raw_arm64_leaf_aot',
            'abi': 'x86_64-sysv-guest-state-v1-context-direct-ram',
            'target_cpu': 'x86_64-baseline', 'guest_base': 268435456,
            'guest_instructions': 2, 'native_bytes': 15, 'entry_prefix_bytes': 13,
            'execution_profile': {'id': 'apple-sme2-streaming-v1', 'svl_bytes': 16, 'svcr': 1},
            'source_map': [[268435456, 13], [268435460, 14]],
        }
        source = bytes.fromhex('c0035fd6c0035fd6')
        progress.validate_context_manifest(manifest, source, 15, 16, 1)
        with self.assertRaisesRegex(ValueError, 'source/native metadata mismatch'):
            progress.validate_context_manifest({**manifest, 'target_cpu': 'baseline'}, source, 15, 16, 1)

    def test_missing_invalid_or_implicit_scalable_controls_never_call_compiler(self):
        configurations = [(value, 3) for value in (None, False, 0, 48, 512, '16')]
        configurations += [(16, value) for value in (None, False, -1, 4, '3')]
        for length, svcr in configurations:
            with self.subTest(length=length, svcr=svcr), tempfile.TemporaryDirectory() as directory:
                with patch.object(progress.subprocess, 'run') as run, self.assertRaises(ValueError):
                    self.probe(Path(directory), svl_bytes=length, svcr=svcr, run=run)
                run.assert_not_called()
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'context compiler lane'):
            progress.compile_probe('cli', progress.RET, Path(directory),
                guest_profile=progress.SCALABLE_PROFILE, svl_bytes=16, svcr=3)

    def test_context_probe_rejects_legacy_schema_abi_and_wrong_profile(self):
        mutations = [lambda m: m.update(schema_version=1),
                     lambda m: m.update(abi=progress.BLOCK_ABI),
                     lambda m: m.update(abi='x86_64-sysv-guest-state-v3-direct-ram'),
                     lambda m: m.update(kind='raw_arm64_block_aot'),
                     lambda m: m.pop('execution_profile'),
                     lambda m: m.update(execution_profile=None),
                     lambda m: m['execution_profile'].update(id='future-sme-profile'),
                     lambda m: m['execution_profile'].update(svl_bytes=32),
                     lambda m: m['execution_profile'].update(svcr=0),
                     lambda m: m['execution_profile'].update(svcr=True),
                     lambda m: m.update(target_cpu='native'),
                     lambda m: m.update(compiler_source_sha256='z' * 64)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    self.probe(Path(directory), svl_bytes=16, svcr=3,
                               run=self.fake_compiler(mutation))

    def test_context_source_map_binds_every_guest_instruction_after_wrapper(self):
        changes = [{'source_map': value} for value in (None, [], [[progress.SCALABLE_GUEST_BASE, 13]],
                   [[0, 13], [4, 14]], [[progress.SCALABLE_GUEST_BASE, 0], [progress.SCALABLE_GUEST_BASE+4, 14]],
                   [[progress.SCALABLE_GUEST_BASE, 13], [progress.SCALABLE_GUEST_BASE+4, 15]],
                   [[progress.SCALABLE_GUEST_BASE, 13], [progress.SCALABLE_GUEST_BASE+4, 12]],
                   [[progress.SCALABLE_GUEST_BASE, 13], [progress.SCALABLE_GUEST_BASE+4, True]])]
        changes += [{'entry_prefix_bytes': value} for value in (None, False, 0, 1, 14, 15)]
        changes += [{'guest_base': 0}, {'guest_instructions': 1}, {'native_bytes': 1},
                    {'source_sha256': 'a' * 64}, {'native_sha256': 'a' * 64}]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    self.probe(Path(directory), svl_bytes=16, svcr=3,
                               run=self.fake_compiler(lambda manifest: manifest.update(change)))

    def test_empty_registry_uses_context_ret_identity_without_support_credit(self):
        registry = fixtures()
        registry['forms'] = []
        registry['profile'] = self.profile()
        rows = progress.validate_registry(registry)
        self.assertEqual(rows, {})
        self.assertEqual(progress.summarize(rows)['reviewed']['implemented'], 0)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(progress, 'compile_probe', return_value={
                    'word': '0xd65f03c0', 'compiler_source_sha256': COMPILER}) as probe:
                compiler, results = progress.smoke_forms('cli', rows, rows, Path(directory),
                    mode='scalable', profile=registry['profile'])
        self.assertEqual(compiler, COMPILER)
        self.assertEqual(results, [{'compiler_identity_only': True,
                                  'word': '0xd65f03c0', 'compiler_source_sha256': COMPILER}])
        self.assertEqual(probe.call_args.args[1], progress.RET)
        self.assertEqual(probe.call_args.kwargs, {'mode': 'scalable',
            'guest_profile': progress.SCALABLE_PROFILE, 'svl_bytes': 16, 'svcr': 3})

    def test_scalable_registry_and_samples_require_explicit_profile_controls(self):
        registry = fixtures()
        registry['profile'] = self.profile()
        for row in registry['forms']:
            row['profile'] = progress.SCALABLE_PROFILE
            for sample in row['smoke_samples'] + row.get('rejected_samples', []):
                sample.update(svl_bytes=32, svcr=1)
        progress.validate_registry(registry)
        for change in ({'abi': progress.BLOCK_ABI}, {'compiler_command': 'compile-scalable'},
                       {'svl_bytes': 48}, {'svcr': None}):
            changed = copy.deepcopy(registry)
            changed['profile'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                progress.validate_registry(changed)
        for field in ('svl_bytes', 'svcr'):
            changed = copy.deepcopy(registry)
            changed['forms'][0]['smoke_samples'][0].pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                progress.validate_registry(changed)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(progress, 'compile_probe', return_value={
                    'compiler_source_sha256': COMPILER}) as probe:
                rows = progress.validate_registry(registry)
                progress.smoke_forms('cli', rows, rows, Path(directory), mode='scalable',
                                     profile=registry['profile'])
        self.assertEqual(probe.call_args.kwargs, {'mode': 'scalable',
            'guest_profile': progress.SCALABLE_PROFILE, 'svl_bytes': 32, 'svcr': 1})

    def test_four_execution_profiles_still_count_one_canonical_form(self):
        catalog = json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_text())
        form = next(row for row in catalog['forms'] if row['id'] == 'RET_64R_branch_reg')
        row = {**form, 'source_sha256': catalog['source_files_sha256'][form['source_file']],
               'scope': 'bounded reviewed semantics', 'status': 'implemented'}
        registries = [{'forms': [{**row, 'profile': profile}]} for profile in (
            'leaf', 'block', 'service', progress.SCALABLE_PROFILE)]
        assessed, summary = progress.a64_checklist.assess(catalog, registries)
        self.assertEqual((summary['implemented'], summary['partial']), (1, 0))
        self.assertEqual(len(next(form for form in assessed['forms'] if form['id'] == row['id'])['profiles']), 4)

    def test_pipeline_includes_four_registries_and_preserves_verification_basis(self):
        source_root = progress.ROOT
        for implementation_only in (False, True):
            with self.subTest(implementation_only=implementation_only), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'tests/isa').mkdir(parents=True)
                (root / 'tests/isa/apple-specific-extensions.json').write_text(json.dumps({
                    'kind': 'apple_specific_extension_ledger', 'inventory_complete': False, 'extensions': []}))
                (root / 'cli').write_text('mock compiler executable')
                registries = []
                for mode in ('leaf', 'block', 'service', 'scalable'):
                    registry = fixtures()
                    registry['forms'] = []
                    if mode == 'block':
                        registry['profile'].update(id='block', compiler_command='compile-block', abi=progress.BLOCK_ABI)
                    elif mode == 'service':
                        registry['profile'].update(id=progress.SERVICE_PROFILE, compiler_mode='service', abi=progress.SERVICE_ABI)
                    elif mode == 'scalable':
                        registry['profile'] = self.profile()
                    path = root / (mode + '.json')
                    path.write_text(json.dumps(registry))
                    registries.append(path)
                arguments = ['translation-progress.py', '--registry', str(registries[0]),
                    '--block-registry', str(registries[1]), '--service-registry', str(registries[2]),
                    '--scalable-registry', str(registries[3]), '--cli', str(root / 'cli'),
                    '--checklist', str(source_root / 'tests/isa/a64-documented-checklist.json'),
                    '--apple-profiles', str(source_root / 'tests/isa/apple-codegen-profiles.json'),
                    '--output', str(root / 'report.json')]
                if implementation_only:
                    arguments.append('--implementation-only')
                checkpoint = {'implemented': 292, 'total': 3119,
                              'compiler_source_sha256': 'd' * 64}
                def smoke(_cli, _forms, _overrides, _directory, **kwargs):
                    mode = kwargs.get('mode', 'leaf')
                    return COMPILER, [{'compiler_identity_only': True}] if mode == 'scalable' else []
                with patch.object(progress, 'ROOT', root), patch.object(sys, 'argv', arguments), \
                     patch.object(progress, 'previous_checkpoint', return_value=checkpoint), \
                     patch.object(progress, 'smoke_forms', side_effect=smoke) as probes, \
                     patch.object(progress, 'validate_evidence', return_value=({}, {})) as evidence, \
                     patch.object(progress, 'validate_current_compiler', return_value={}) as recipes, \
                     patch.object(progress, 'write_evidence', return_value=root / 'archive.json') as write, \
                     patch('builtins.print'):
                    progress.main()
                report = write.call_args.args[1]
                self.assertEqual(probes.call_count, 4)
                self.assertEqual(probes.call_args.kwargs['mode'], 'scalable')
                self.assertEqual(probes.call_args.kwargs['profile'], self.profile())
                self.assertEqual(evidence.call_count, 0 if implementation_only else 4)
                self.assertEqual(recipes.call_count, 8)
                self.assertEqual(report['last_verified_checkpoint'], checkpoint if implementation_only else None)
                self.assertEqual(report['implementation_only'], implementation_only)
                self.assertEqual(report['documented_isa']['summary']['implemented'], 0)
                self.assertEqual(report['scalable_profile_evidence']['summary']['reviewed']['implemented'], 0)
                self.assertEqual(report['scalable_profile_evidence']['profile'], self.profile())
                self.assertEqual(report['scalable_profile_evidence']['native_differential_evidence'], {})
                self.assertEqual(report['scalable_profile_evidence']['compiler_smoke_probes'],
                                 [{'compiler_identity_only': True}])
                self.assertEqual(report['scalable_profile_evidence']['registry_sha256'],
                                 progress.sha256(registries[3]))

    def test_actual_independent_length_decode_remains_canonical_and_word_bound(self):
        catalog = json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_text())
        facts = progress.a64_checklist.validate(catalog)
        decoder = type('UnavailableDecoder', (), {'disasm': lambda self, data, address: iter(())})()
        word = 0x04615820
        row = {'word': word, 'offset': 0, 'mnemonic': 'addspl',
               'operands': 'x0, x1, #1', 'assembly': 'addspl x0, x1, #1'}
        self.assertEqual(progress.smoke_decoding(decoder, word, 'addspl_r_ri_', facts, {word: row}),
                         ('addspl', 'addspl x0, x1, #1', 'apple_llvm21_objdump'))
        for identity, changed in (('addsvl_r_ri_', row),
                                  ('addspl_r_ri_', {**row, 'word': word ^ (1 << 24)}),
                                  ('addspl_r_ri_', {**row, 'mnemonic': 'unknown'})):
            with self.subTest(identity=identity, changed=changed), self.assertRaises(ValueError):
                progress.smoke_decoding(decoder, word, identity, facts, {word: changed})

    def test_unknown_scalable_encoding_still_requires_independent_decoder(self):
        decoder = type('UnavailableDecoder', (), {'disasm': lambda self, data, address: iter(())})()
        catalog = json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_text())
        facts = progress.a64_checklist.validate(catalog)
        scalable = next(row for row in facts.values() if row['category'] == 'sme')
        with self.assertRaisesRegex(ValueError, 'Independent decoder declined'):
            progress.smoke_decoding(decoder, int(scalable['encoding_value'], 16), scalable['id'], facts)



class DeclaredScalableProgressTests(unittest.TestCase):
    def profile(self):
        return {'id': 'sme-streaming-v2', 'compiler_command': 'compile-leaf',
                'abi': progress.CONTEXT_LEAF_ABI, 'svl_bytes': 16, 'svcr': 3,
                'features': ['FEAT_SME_I16I64', 'FEAT_SME2', 'FEAT_SME'],
                'max_svl_bytes': 256, 'zt0_enabled': False, 'dit': False,
                'outside_scope': ['block/cache and architectural DIT enforcement']}

    def declaration(self, profile=None):
        return progress.scalable_declaration(profile or self.profile())

    def manifest(self):
        # Exact field names/types and canonical feature order of the reviewed
        # generic V2 CLI schema; guest features remain separate from host CPU.
        return {'schema_version': 2, 'kind': 'raw_arm64_leaf_aot',
                'abi': 'x86_64-sysv-guest-state-v1-context-direct-ram',
                'target_cpu': 'x86_64-baseline', 'guest_base': 268435456,
                'guest_instructions': 2, 'native_bytes': 15, 'entry_prefix_bytes': 13,
                'execution_profile': {'id': 'sme-streaming-v2', 'svl_bytes': 16, 'svcr': 3,
                    'features': ['FEAT_SME', 'FEAT_SME2', 'FEAT_SME_I16I64'],
                    'max_svl_bytes': 256, 'zt0_enabled': False, 'dit': False},
                'source_map': [[268435456, 13], [268435460, 14]]}

    def validate_manifest(self, manifest):
        progress.validate_context_manifest(manifest, bytes.fromhex('c0035fd6c0035fd6'), 15, 16, 3,
            guest_profile='sme-streaming-v2', **self.declaration())

    def registry(self):
        registry = fixtures()
        registry['profile'] = ScalableProgressTests().profile()
        registry['execution_profiles'] = {'sme-i16i64-v2': self.profile()}
        for row in registry['forms']:
            row['profile'] = progress.SCALABLE_PROFILE
            for sample in row['smoke_samples'] + row.get('rejected_samples', []):
                sample.update(svl_bytes=16, svcr=3)
        registry['forms'][1]['profile'] = 'sme-i16i64-v2'
        return registry

    def test_explicit_features_are_canonicalized_without_implication(self):
        result = progress.validate_scalable_profile(self.profile())
        self.assertEqual(result, self.manifest()['execution_profile'])
        profile = self.profile()
        profile.update(features=['FEAT_SME'], max_svl_bytes=16)
        self.assertEqual(progress.validate_scalable_profile(profile)['features'], ['FEAT_SME'])
        profile.update(features=list(reversed(progress.SCALABLE_FEATURES)), zt0_enabled=True)
        self.assertEqual(progress.validate_scalable_profile(profile)['features'], sorted(progress.SCALABLE_FEATURES))

    def test_v2_missing_invalid_and_contradictory_declarations_decline(self):
        changes = [{'features': value} for value in (None, [], ['SME'], ['FEAT_future'],
            ['FEAT_SME2'], ['FEAT_SME', 'FEAT_SME'], ['FEAT_SME', 'FEAT_SME2p1'])]
        changes += [{'max_svl_bytes': value} for value in (None, False, 0, 48, '256')]
        changes += [{'zt0_enabled': value} for value in (None, 0, 'false')]
        changes += [{'dit': value} for value in (None, 0, True, 'false')]
        changes += [{'features': ['FEAT_SME'], 'zt0_enabled': True},
                    {'svl_bytes': 256, 'max_svl_bytes': 128}, {'undeclared_control': False}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                progress.validate_scalable_profile({**self.profile(), **change})
        for key in progress.SCALABLE_DECLARATION_FIELDS:
            profile = self.profile()
            profile.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                progress.validate_scalable_profile(profile)

    def test_v1_shape_rejects_every_v2_declaration(self):
        profile = ScalableProgressTests().profile()
        before = copy.deepcopy(profile)
        self.assertEqual(progress.validate_scalable_profile(profile), {
            'id': 'apple-sme2-streaming-v1', 'svl_bytes': 16, 'svcr': 3})
        self.assertEqual(profile, before)
        for key, value in self.declaration().items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                progress.validate_scalable_profile({**profile, key: value})

    def test_full_v2_manifest_contract_is_required(self):
        self.validate_manifest(self.manifest())
        for key in ('features', 'max_svl_bytes', 'zt0_enabled', 'dit'):
            changed = self.manifest()
            changed['execution_profile'].pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validate_manifest(changed)
        changes = [{'id': progress.SCALABLE_PROFILE}, {'features': ['FEAT_SME', 'FEAT_SME2']},
                   {'features': ['FEAT_SME_I16I64', 'FEAT_SME2', 'FEAT_SME']},
                   {'features': ['FEAT_SME', 'FEAT_SME2', 'FEAT_SME_I16I64', 'FEAT_SME_FA64']},
                   {'max_svl_bytes': 128}, {'max_svl_bytes': '256'},
                   {'zt0_enabled': True}, {'zt0_enabled': 0}, {'dit': True}, {'dit': 0},
                   {'undeclared_control': False}]
        for change in changes:
            changed = self.manifest()
            changed['execution_profile'].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate_manifest(changed)

    def test_explicit_host_target_is_checked_independently_of_guest_contract(self):
        manifest = self.manifest()
        manifest['target_cpu'] = 'x86_64-baseline+ssse3+sse4.1'
        with self.assertRaisesRegex(ValueError, 'source/native metadata mismatch'):
            self.validate_manifest(manifest)
        progress.validate_context_manifest(manifest, bytes.fromhex('c0035fd6c0035fd6'), 15, 16, 3,
            guest_profile='sme-streaming-v2', expected_target_cpu='x86_64-baseline+ssse3+sse4.1',
            **self.declaration())
        for target in (None, '', True, 'x86_64-baseline+ssse3'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                progress.validate_context_manifest(manifest, bytes.fromhex('c0035fd6c0035fd6'), 15, 16, 3,
                    guest_profile='sme-streaming-v2', expected_target_cpu=target, **self.declaration())

    def test_compile_probe_emits_only_explicit_v2_cli_contract(self):
        commands = []
        def fake(command, **kwargs):
            commands.append(command)
            source = Path(command[2])
            output = Path(command[command.index('--output-dir') + 1])
            output.mkdir()
            (output / 'native.bin').write_bytes(bytes(13) + b'\xc3\xc3')
            manifest = self.manifest()
            manifest.update(source_sha256=progress.sha256(source),
                native_sha256=progress.sha256(output / 'native.bin'), compiler_source_sha256=COMPILER)
            return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
        with tempfile.TemporaryDirectory() as directory:
            result = progress.compile_probe('cli', progress.RET, Path(directory), mode='scalable',
                guest_profile='sme-streaming-v2', svl_bytes=16, svcr=3, run=fake, **self.declaration())
        command = commands[0]
        self.assertEqual(command[1], 'compile-leaf')
        self.assertEqual(command[command.index('--guest-profile') + 1], 'sme-streaming-v2')
        self.assertEqual([command[index+1] for index, value in enumerate(command)
                          if value == '--guest-feature'], ['FEAT_SME', 'FEAT_SME2', 'FEAT_SME_I16I64'])
        self.assertEqual(command[command.index('--max-svl-bytes') + 1], '256')
        self.assertEqual(command[command.index('--zt0-enabled') + 1], 'false')
        self.assertNotIn('--dit', command)
        self.assertEqual(result['execution_profile'], self.manifest()['execution_profile'])

    def test_bad_declaration_never_invokes_compiler_or_writes_input(self):
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory)
            with patch.object(progress.subprocess, 'run') as run, self.assertRaises(ValueError):
                progress.compile_probe('cli', progress.RET, location, mode='scalable',
                    guest_profile='sme-streaming-v2', svl_bytes=16, svcr=3, run=run,
                    features=['FEAT_SME2'], max_svl_bytes=256, zt0_enabled=False, dit=False)
            run.assert_not_called()
            self.assertEqual(list(location.iterdir()), [])

    def test_specialization_keys_resolve_full_contract_without_replacing_v1(self):
        registry = self.registry()
        original = copy.deepcopy(registry)
        rows = progress.validate_registry(registry)
        self.assertEqual(rows['ADC_32_addsub_carry']['profile'], progress.SCALABLE_PROFILE)
        self.assertEqual(rows['RET_64R_branch_reg']['profile'], 'sme-i16i64-v2')
        self.assertEqual(registry, original)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(progress, 'compile_probe', return_value={
                    'compiler_source_sha256': COMPILER}) as probe:
                progress.smoke_forms('cli', rows, rows, Path(directory), mode='scalable',
                    profile=registry['profile'], execution_profiles=registry['execution_profiles'])
        self.assertEqual(probe.call_args_list[0].kwargs, {'mode': 'scalable',
            'guest_profile': 'apple-sme2-streaming-v1', 'svl_bytes': 16, 'svcr': 3})
        self.assertEqual(probe.call_args_list[-1].kwargs, {'mode': 'scalable',
            'guest_profile': 'sme-streaming-v2', 'svl_bytes': 16, 'svcr': 3, **self.declaration()})

    def test_distinct_explicit_svl_contracts_coexist(self):
        default = ScalableProgressTests().profile()
        contracts = {'svl16': self.profile(), 'svl32': {**self.profile(), 'svl_bytes': 32}}
        original = copy.deepcopy(contracts)
        profiles = progress.validate_scalable_profiles(default, contracts)
        self.assertEqual(profiles['svl16']['svl_bytes'], 16)
        self.assertEqual(profiles['svl32']['svl_bytes'], 32)
        self.assertEqual(contracts, original)
        self.assertEqual(profiles[default['id']], default)

    def test_distinct_explicit_svcr_contracts_coexist(self):
        contracts = {'sm': {**self.profile(), 'svcr': 1}, 'sm-za': self.profile()}
        profiles = progress.validate_scalable_profiles(ScalableProgressTests().profile(), contracts)
        self.assertEqual(profiles['sm']['svcr'], 1)
        self.assertEqual(profiles['sm-za']['svcr'], 3)

    def test_identical_execution_contract_keys_still_decline(self):
        first = self.profile()
        # Feature order and descriptions do not create a new execution identity.
        same = {**self.profile(), 'features': list(reversed(first['features'])),
                'description': 'Another description', 'outside_scope': ['Other wording']}
        with self.assertRaisesRegex(ValueError, 'Duplicate semantic execution-profile'):
            progress.validate_scalable_profiles(ScalableProgressTests().profile(), {'first': first, 'same': same})

    def test_ambiguous_duplicate_unknown_and_undeclared_profiles_fail(self):
        for value in ([], {}, {'alias': self.profile(), 'same': self.profile()},
                      {'': self.profile()}, {progress.SCALABLE_PROFILE: self.profile()},
                      {'bad': {**self.profile(), 'id': 'future-v3'}},
                      {'bad': {**self.profile(), 'ezt0': True}}):
            registry = self.registry()
            registry['execution_profiles'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                progress.validate_scalable_profiles(registry['profile'], value)
        for key in ('sme-streaming-v2', 'undeclared', None, []):
            registry = self.registry()
            registry['forms'][1]['profile'] = key
            with self.subTest(key=key), self.assertRaises(ValueError):
                progress.validate_registry(registry)
        registry = self.registry()
        for field in ('zt0_enabled', 'unknown_control'):
            registry = self.registry()
            registry['forms'][1]['smoke_samples'][0][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                progress.validate_registry(registry)

    def test_independent_decoding_batches_each_explicit_decoder_contract(self):
        registry = self.registry()
        registry['execution_profiles']['sme-i16i64-v2']['decoder_mattrs'] = ['+sme2p1']
        rows = progress.validate_registry(registry)
        facts = {identity: {**row, 'features': [], 'mnemonic': 'ADC' if identity.startswith('ADC') else 'RET'}
                 for identity, row in rows.items()}
        decoder = type('UnavailableDecoder', (), {'disasm': lambda self, data, address: iter(())})()
        def decode(words, directory, *, mattrs):
            decoded = []
            for index, word in enumerate(words):
                mnemonic = 'adc' if word == 0x1a000000 else 'ret'
                decoded.append({'word': word, 'offset': index * 4, 'mnemonic': mnemonic,
                                'operands': '', 'assembly': mnemonic})
            return {'rows': decoded, 'mattrs': list(mattrs)}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(progress, 'Cs', return_value=decoder), \
                 patch.object(disassembly, 'decode_words', side_effect=decode) as decode_call, \
                 patch.object(progress, 'compile_probe', return_value={'compiler_source_sha256': COMPILER}):
                _compiler, results = progress.smoke_forms('cli', rows, rows, Path(directory),
                    mode='scalable', profile=registry['profile'], canonical_facts=facts,
                    execution_profiles=registry['execution_profiles'])
        self.assertEqual(decode_call.call_count, 2)
        self.assertEqual({call.kwargs['mattrs'] for call in decode_call.call_args_list},
                         {disassembly.DEFAULT_MATTRS, ('+sme2p1',)})
        supported = [result for result in results if 'sample' in result]
        self.assertEqual([result['independent_decode_basis'] for result in supported],
                         ['apple_llvm21_objdump', 'apple_llvm21_objdump'])
        self.assertEqual(supported[1]['independent_decode_receipt']['mattrs'], ['+sme2p1'])

    def test_decoder_attributes_are_explicit_and_separate_from_guest_features(self):
        profile = self.profile()
        profile['decoder_mattrs'] = ['+sme2', '+sve2p1']
        execution = progress.validate_scalable_profile(profile)
        self.assertNotIn('decoder_mattrs', execution)
        self.assertNotIn('FEAT_SME2p1', execution['features'])
        for attrs in ([], ['+sme2', '+sme2'], ['+all,+sme2'], ['unknown'], [None], [{}]):
            with self.subTest(attrs=attrs), self.assertRaises(ValueError):
                progress.validate_scalable_profile({**profile, 'decoder_mattrs': attrs})


class RegistryPublicationPreservationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.base_path, self.candidate_path = root / 'base.json', root / 'candidate.json'
        self.base = {'schema_version': 2, 'kind': 'reviewed_apple_silicon_instruction_forms',
            'registry_version': 'reviewed-v1', 'profile': {'id': 'apple-sme2-streaming-v1'},
            'compiler_fingerprint_sources': ['compiler.rs'],
            'evidence_groups': {'old': {'report': 'old.json', 'scope': 'M1–M5 snapshot'},
                                'owned': {'report': 'owned.json'}},
            'forms': [{'id': 'old', 'status': 'implemented', 'scope': 'A–B unchanged'},
                      {'id': 'owned', 'status': 'partial', 'scope': 'Old owned scope'}]}
        self.base_path.write_text(json.dumps(self.base, ensure_ascii=False, indent=2) + '\n')

    def check(self, candidate=None, *, text=None, **permissions):
        if text is None:
            text = json.dumps(self.base if candidate is None else candidate, ensure_ascii=False, indent=2) + '\n'
        self.candidate_path.write_text(text)
        options = {'owned_form_ids': [], 'owned_evidence_group_ids': []}
        options.update(permissions)
        return progress.validate_registry_preservation(self.base_path, self.candidate_path, **options)

    def test_noop_preserves_exact_utf8_text_and_reports_bound_identities(self):
        report = self.check()
        self.assertTrue(report['passed'])
        self.assertEqual(report['base_sha256'], progress.sha256(self.base_path))
        self.assertEqual(report['candidate_sha256'], report['base_sha256'])
        self.assertEqual(report['entries']['forms']['preserved'], ['old', 'owned'])
        self.assertFalse(report['compiler_recipe_changed'])
        self.assertFalse(report['registry_version_changed'])

    def test_explicit_additions_updates_profiles_and_global_recipe_are_permitted(self):
        candidate = copy.deepcopy(self.base)
        candidate['registry_version'] = 'reviewed-v2'
        candidate['compiler_fingerprint_sources'].append('new.rs')
        candidate['forms'][1].update(status='implemented', scope='Reviewed owned scope')
        candidate['forms'].append({'id': 'new', 'status': 'implemented', 'scope': 'New form'})
        candidate['evidence_groups']['owned']['report'] = 'updated.json'
        candidate['evidence_groups']['new'] = {'report': 'new.json'}
        candidate['execution_profiles'] = {'new-v2': {'id': 'sme-streaming-v2', 'features': ['FEAT_SME']}}
        report = self.check(candidate, owned_form_ids=['owned', 'new'],
            owned_evidence_group_ids=['owned', 'new'], owned_execution_profile_keys=['new-v2'],
            allow_compiler_recipe_update=True, allow_registry_version_update=True)
        self.assertEqual(report['entries']['forms'], {'added': ['new'], 'updated': ['owned'], 'preserved': ['old']})
        self.assertEqual(report['entries']['evidence_groups']['preserved'], ['old'])
        self.assertEqual(report['entries']['execution_profiles']['added'], ['new-v2'])
        self.assertTrue(report['compiler_recipe_changed'])
        self.assertTrue(report['registry_version_changed'])

    def test_default_ascii_serialization_churn_fails_even_with_identical_parsed_rows(self):
        text = json.dumps(self.base, indent=2) + '\n'  # The actual accidental ensure_ascii=True failure.
        self.assertEqual(json.loads(text), self.base)
        with self.assertRaisesRegex(ValueError, 'unowned ID'):
            self.check(text=text)
        text = self.base_path.read_text().replace('"scope": "A–B unchanged"', '"scope":"A–B unchanged"')
        self.assertEqual(json.loads(text), self.base)
        with self.assertRaisesRegex(ValueError, 'unowned ID'):
            self.check(text=text)

    def test_unowned_row_and_group_edits_and_additions_fail(self):
        candidates = []
        row = copy.deepcopy(self.base); row['forms'][0]['status'] = 'partial'; candidates.append(row)
        group = copy.deepcopy(self.base); group['evidence_groups']['old']['report'] = 'rewritten.json'; candidates.append(group)
        added = copy.deepcopy(self.base); added['forms'].append({'id': 'new'}); candidates.append(added)
        added = copy.deepcopy(self.base); added['evidence_groups']['new'] = {}; candidates.append(added)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(ValueError, 'unowned ID'):
                self.check(candidate)

    def test_existing_ids_cannot_be_removed_or_reordered_even_when_owned(self):
        candidates = []
        row = copy.deepcopy(self.base); row['forms'].pop(); candidates.append(row)
        row = copy.deepcopy(self.base); row['forms'].reverse(); candidates.append(row)
        group = copy.deepcopy(self.base); group['evidence_groups'].pop('owned'); candidates.append(group)
        group = copy.deepcopy(self.base); group['evidence_groups'] = dict(reversed(list(group['evidence_groups'].items()))); candidates.append(group)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaisesRegex(ValueError, 'removed|reordered'):
                self.check(candidate, owned_form_ids=['old', 'owned'], owned_evidence_group_ids=['old', 'owned'])

    def test_metadata_flags_are_deny_default_and_restricted(self):
        for key, value in (('schema_version', 3), ('profile', {'id': 'sme-streaming-v2'}),
                           ('registry_version', 'reviewed-v2'), ('compiler_fingerprint_sources', ['new.rs']),
                           ('undeclared_global', True)):
            candidate = copy.deepcopy(self.base); candidate[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'metadata'):
                self.check(candidate)
        for key, value, permission in (('registry_version', 2, 'allow_registry_version_update'),
                                       ('compiler_fingerprint_sources', [], 'allow_compiler_recipe_update')):
            candidate = copy.deepcopy(self.base); candidate[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(candidate, **{permission: True})
        for permission in ('allow_registry_version_update', 'allow_compiler_recipe_update'):
            with self.subTest(permission=permission), self.assertRaises(ValueError):
                self.check(**{permission: 1})

    def test_execution_profile_ownership_cannot_rewrite_default_or_unowned_contracts(self):
        self.base['execution_profiles'] = {'old-v2': {'id': 'sme-streaming-v2', 'features': ['FEAT_SME']}}
        self.base_path.write_text(json.dumps(self.base, ensure_ascii=False, indent=2) + '\n')
        candidate = copy.deepcopy(self.base)
        candidate['execution_profiles']['new-v2'] = {'id': 'sme-streaming-v2', 'features': ['FEAT_SME', 'FEAT_SME2']}
        report = self.check(candidate, owned_execution_profile_keys=['new-v2'])
        self.assertEqual(report['entries']['execution_profiles']['preserved'], ['old-v2'])
        self.assertFalse(report['compiler_recipe_changed'])
        candidate['execution_profiles']['old-v2']['features'].append('FEAT_SME2p1')
        with self.assertRaisesRegex(ValueError, 'unowned ID'):
            self.check(candidate, owned_execution_profile_keys=['new-v2'])
        with self.assertRaisesRegex(ValueError, 'absent'):
            self.check(self.base, owned_execution_profile_keys=['missing'])

    def test_empty_registry_additions_preserve_container_framing_and_prior_rows(self):
        self.base['forms'] = []
        self.base['evidence_groups'] = {}
        self.base_path.write_text(json.dumps(self.base, ensure_ascii=False, indent=2) + '\n')
        candidate = copy.deepcopy(self.base)
        candidate['forms'].append({'id': 'first'})
        candidate['evidence_groups']['first'] = {'report': 'first.json'}
        report = self.check(candidate, owned_form_ids=['first'], owned_evidence_group_ids=['first'])
        self.assertEqual(report['entries']['forms']['added'], ['first'])
        self.assertFalse(report['registry_version_changed'])
        self.base_path.write_text(json.dumps(candidate, ensure_ascii=False, indent=2) + '\n')
        text = self.base_path.read_text().replace('\n  ]\n}', '\n ]\n}')
        with self.assertRaisesRegex(ValueError, 'framing'):
            self.check(text=text)

    def test_same_file_and_unowned_separator_whitespace_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'distinct'):
            progress.validate_registry_preservation(self.base_path, self.base_path,
                owned_form_ids=[], owned_evidence_group_ids=[])
        text = self.base_path.read_text().replace('"scope": "A–B unchanged"\n    },',
                                                  '"scope": "A–B unchanged"\n    }  ,')
        self.assertEqual(json.loads(text), self.base)
        with self.assertRaisesRegex(ValueError, 'unowned ID'):
            self.check(text=text)

    def test_empty_container_whitespace_is_unowned_and_metadata_flags_preserve_suffixes(self):
        self.base['forms'] = []
        self.base['evidence_groups'] = {}
        self.base_path.write_text(json.dumps(self.base, ensure_ascii=False, indent=2) + '\n')
        original = self.base_path.read_text()
        for text in (original.replace('"forms": []', '"forms": [ \n ]'),
                     original.replace('"evidence_groups": {}', '"evidence_groups": { \t }')):
            self.assertEqual(json.loads(text), self.base)
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'empty container framing'):
                self.check(text=text)
        text = original.replace('"registry_version": "reviewed-v1",',
                                '"registry_version": "reviewed-v2" \t ,')
        with self.assertRaisesRegex(ValueError, 'member framing'):
            self.check(text=text, allow_registry_version_update=True)
        text = original.replace('"compiler.rs"\n  ],', '"new.rs"\n  ] \t ,')
        with self.assertRaisesRegex(ValueError, 'member framing'):
            self.check(text=text, allow_compiler_recipe_update=True)

    def test_owned_append_retains_prior_final_entry_closing_whitespace(self):
        base = '{"evidence_groups":{"old":{}  },"forms":[{"id":"old"}  ]}\n'
        candidate = '{"evidence_groups":{"old":{}  ,"new":{}  },"forms":[{"id":"old"}  ,{"id":"new"}  ]}\n'
        self.base_path.write_text(base)
        result = self.check(text=candidate, owned_form_ids=['new'], owned_evidence_group_ids=['new'])
        self.assertEqual(result['entries']['forms']['preserved'], ['old'])
        self.assertEqual(result['entries']['evidence_groups']['preserved'], ['old'])
        changed = candidate.replace('{"id":"old"}  ,', '{"id":"old"}\t,')
        with self.assertRaisesRegex(ValueError, 'unowned ID'):
            self.check(text=changed, owned_form_ids=['new'], owned_evidence_group_ids=['new'])
        self.base_path.write_text('{"evidence_groups":{},"forms":[]  }\n')
        candidate = '{"evidence_groups":{},"forms":[]  ,"execution_profiles":{"new":{"id":"sme-streaming-v2"}}  }\n'
        result = self.check(text=candidate, owned_execution_profile_keys=['new'])
        self.assertEqual(result['entries']['execution_profiles']['added'], ['new'])
        self.base_path.write_text('{"evidence_groups":{},"forms":[],"schema_version":2  }\n')
        candidate = '{"evidence_groups":{},"forms":[],"schema_version":2  ,"execution_profiles":{"new":{}}  }\n'
        result = self.check(text=candidate, owned_execution_profile_keys=['new'])
        self.assertEqual(result['entries']['execution_profiles']['added'], ['new'])

    def test_json_ambiguity_duplicate_ids_and_format_churn_fail(self):
        original = self.base_path.read_text()
        malformed = [original.replace('"schema_version": 2,', '"schema_version": 2, "schema_version": 2,'),
                     original.replace('"report": "old.json"', '"report": "old.json", "report": "other.json"'),
                     original.replace('"schema_version": 2', '"schema_version": NaN'),
                     original[:-2] + ',}\n', original + '{}', original.replace('\n', '\r\n')]
        for text in malformed:
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                self.check(text=text)
        duplicate = copy.deepcopy(self.base); duplicate['forms'].append(duplicate['forms'][0])
        with self.assertRaisesRegex(ValueError, 'unique'):
            self.check(duplicate, owned_form_ids=['old'])
        reordered = dict(reversed(list(self.base.items())))
        with self.assertRaisesRegex(ValueError, 'reordered'):
            self.check(reordered)
        with self.assertRaisesRegex(ValueError, 'absent'):
            self.check(owned_form_ids=['typo'])

class LLVMDisassemblyGuards(unittest.TestCase):
    def test_llvm_hyphenated_feature_segments_are_explicit_and_unambiguous(self):
        for feature in ('+sme-i16i64', '+sme-f64f64', '-sme-i16i64'):
            with self.subTest(feature=feature):
                self.assertIsNotNone(disassembly.FEATURE_NAME.fullmatch(feature))
        for feature in ('+sme--i16i64', '+sme-', '+sme_i16i64', '+sme2,+all', ' +sme2', '+sme2 '):
            with self.subTest(feature=feature):
                self.assertIsNone(disassembly.FEATURE_NAME.fullmatch(feature))

    def fact(self):
        catalog = json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
        return progress.a64_checklist.validate(catalog)['sdot_z32_zzz_']

    def row(self):
        word = int(self.fact()['encoding_value'], 16)
        return disassembly.parse_disassembly(f' 0: {word:08x}\tsdot\tz0.s, z0.h, z0.h', [word])[0]

    def test_exact_actual_word_and_assembly_are_retained(self):
        row, fact = self.row(), self.fact()
        self.assertEqual(disassembly.validate_canonical(row, fact['id'], fact),
                         ('sdot', 'sdot z0.s, z0.h, z0.h', 'apple_llvm21_objdump'))

    def test_unknown_missing_extra_and_mismatched_words_fail(self):
        word = self.row()['word']
        for output in ('', f' 0: {word:08x}\t<unknown>',
                       f' 0: {word ^ 1:08x}\tsdot\tz0.s, z0.h, z0.h',
                       f' 4: {word:08x}\tsdot\tz0.s, z0.h, z0.h',
                       f' 0: {word:08x}\tsdot\tz0.s, z0.h, z0.h\n 4: {word:08x}\tsdot\tz0.s, z0.h, z0.h'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                disassembly.parse_disassembly(output, [word])

    def test_canonical_id_fixed_bits_and_mnemonic_are_independent_guards(self):
        row, fact = self.row(), self.fact()
        for changed, identity in ((row, 'udot_z32_zzz_'),
                                  ({**row, 'word': row['word'] ^ (1 << 31)}, fact['id']),
                                  ({**row, 'mnemonic': 'udot'}, fact['id'])):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                disassembly.validate_canonical(changed, identity, fact)
        with self.assertRaises(ValueError):
            disassembly.validate_canonical(row, fact['id'], fact, ['udot'])

    def test_tool_hash_and_version_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'llvm-tool'
            path.write_bytes(b'pinned tool bytes')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'hash differs'):
                disassembly.tool_identity(disassembly.PinnedTool(path, '0' * 64, 'Apple LLVM version21'))
            tool = disassembly.PinnedTool(path, digest, 'Apple LLVM version21')
            with patch.object(disassembly.subprocess, 'check_output', return_value='Other LLVM version21\n'):
                with self.assertRaisesRegex(ValueError, 'version differs'):
                    disassembly.tool_identity(tool)
            with patch.object(disassembly.subprocess, 'check_output', return_value='Apple LLVM version21\n'):
                self.assertEqual(disassembly.tool_identity(tool)['sha256'], digest)

    def test_invalid_words_and_feature_strings_fail_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            for words, features in (([], disassembly.DEFAULT_MATTRS), ([True], disassembly.DEFAULT_MATTRS),
                                    ([1 << 32], disassembly.DEFAULT_MATTRS), ([0], ('+sme2,+all',))):
                destination = Path(temporary) / 'unused'
                with self.assertRaises(ValueError):
                    disassembly.decode_words(words, destination, mattrs=features)
                self.assertFalse(destination.exists())


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

    def test_trap_group_cannot_count_unrelated_ordinary_comparisons(self):
        self.registry['evidence_groups']['carry'].update(
            comparison_field='trap_state_exit_comparisons',
            required_positive_counts=['trap_rust_runtime_execution_comparisons'])
        for changes in ({}, {'trap_state_exit_comparisons': 320},
                        {'trap_state_exit_comparisons': 320,
                         'trap_rust_runtime_execution_comparisons': 0}):
            self.report.update(changes)
            self.write_report()
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.report['trap_rust_runtime_execution_comparisons'] = 320
        self.write_report()
        reports, _ = progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.assertEqual(reports['carry']['native_comparisons'], 320)
        self.assertEqual(reports['carry']['trap_rust_runtime_execution_comparisons'], 320)

    def test_exact_measurements_preserve_literal_dots_in_profile_names(self):
        self.registry['evidence_groups']['carry']['required_measurements'] = {
            'groups.carry.comparisons': 32, '/cpu_profiles/sse4.2/comparisons': 16}
        self.report['groups'] = {'carry': {'comparisons': 32}}
        self.report['cpu_profiles'] = {'sse4.2': {'comparisons': 16}}
        self.write_report()
        progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        for malformed in ({'sse4.2': {'comparisons': 0}}, {'sse4': {'2': {'comparisons': 16}}}):
            self.report['cpu_profiles'] = malformed
            self.write_report()
            with self.assertRaisesRegex(ValueError, 'required measurement'):
                progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)

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


    def test_fresh_comparisons_cannot_substitute_for_required_historical_and_body_partitions(self):
        group = self.registry['evidence_groups']['carry']
        group.update(comparison_field='fresh_exact_original_comparisons',
                     required_positive_counts=['fresh_native_blocks_executed'],
                     required_measurements={
                         'historical_full_bridge.provenance_distinct_original_frames': 21658,
                         'historical_full_bridge.exact_original_comparisons': 21423,
                         'historical_full_bridge.counts.IRG_exact_original_State_RGSR_GCR': 9936,
                         'historical_full_bridge.counts.exact_original_State_RAM_tags': 11487,
                         'historical_full_bridge.counts.SP_oracle_policy_excluded': 208,
                         'historical_full_bridge.counts.allowed_unknown_prefix_different_from_original_choice': 27,
                         'current_body_identity_bridge.emitted_PC_word_entries': 810,
                         'current_body_identity_bridge.unique_original_words': 698})
        self.report.update(fresh_exact_original_comparisons=3, fresh_native_blocks_executed=4,
            historical_full_bridge={'provenance_distinct_original_frames': 21658,
                'exact_original_comparisons': 21423,
                'counts': {'IRG_exact_original_State_RGSR_GCR': 9936,
                          'exact_original_State_RAM_tags': 11487,
                          'SP_oracle_policy_excluded': 208,
                          'allowed_unknown_prefix_different_from_original_choice': 27}},
            current_body_identity_bridge={'emitted_PC_word_entries': 810, 'unique_original_words': 698})
        self.write_report()
        evidence, _ = progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.assertEqual(evidence['carry']['native_comparisons'], 3)
        current = copy.deepcopy(self.report)
        for key in group['required_measurements']:
            self.report = copy.deepcopy(current)
            target = self.report
            parts = key.split('.')
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] -= 1
            self.write_report()
            with self.subTest(key=key), self.assertRaises(ValueError):
                progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)
        self.report = current
        self.report['fresh_native_blocks_executed'] = 0
        self.write_report()
        with self.assertRaises(ValueError):
            progress.validate_evidence(self.registry, self.rows, COMPILER, self.root)


    def test_runtime_test_executable_is_distinct_from_cli_smoke_evidence(self):
        runtime = self.root / 'runtime-test'
        runtime.write_bytes(b'actual separately retained test executable')
        self.registry['evidence_groups']['carry']['require_runtime_executable'] = True
        self.report.update(runtime_executable_path='runtime-test', runtime_executable_sha256=progress.sha256(runtime))
        self.write_report()
        evidence, _ = progress.validate_evidence(self.registry, self.rows, COMPILER, self.root,
                                                executable_hash='d' * 64)
        self.assertEqual(evidence['carry']['runtime_executable_sha256'], progress.sha256(runtime))
        runtime.write_bytes(b'changed executable')
        with self.assertRaisesRegex(ValueError, 'runtime test executable'):
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




class PreferredAliasSourceGuards(unittest.TestCase):
    """Exercise source/fact binding with invented XML, not reference extracts."""

    def fixture(self):
        fact = {'id': 'synthetic_mova_form', 'instruction_id': 'synthetic_mova',
                'mnemonic': 'MOVA', 'category': 'sme', 'source_file': 'synthetic.xml',
                'encoding_mask': '0xfffff000', 'encoding_value': '0xc0000000',
                'features': []}
        canonical = b'''<instructionsection id="synthetic_mova" type="instruction">
          <alias_list><aliasref aliasfile="synthetic_alias.xml" aliaspageid="synthetic_mov">
          <aliaspref>Unconditionally</aliaspref></aliasref></alias_list></instructionsection>'''
        alias = b'''<instructionsection id="synthetic_mov" type="alias">
          <docvars><docvar key="alias_mnemonic" value="MOV"/>
          <docvar key="mnemonic" value="MOVA"/></docvars>
          <aliasto refiform="synthetic.xml" iformid="synthetic_mova"/>
          <classes><iclass><regdiagram>
          <box hibit="31" width="20"><c colspan="20">11000000000000000000</c></box>
          <box hibit="11"><c>0</c></box></regdiagram>
          <encoding name="synthetic_mov_form"><equivalent_to><asmtemplate>
          <a href="synthetic.xml#synthetic_mova_form">synthetic canonical</a>
          </asmtemplate><aliascond>Unconditionally</aliascond></equivalent_to>
          </encoding></iclass></classes></instructionsection>'''
        return fact, canonical, alias

    def archive(self, directory, canonical, alias):
        path = Path(directory) / 'synthetic.tar'
        with tarfile.open(path, 'w') as handle:
            for name, data in (('synthetic.xml', canonical), ('synthetic_alias.xml', alias)):
                if data is None:
                    continue
                member = tarfile.TarInfo(disassembly.a64_checklist.PREFIX + name)
                member.size = len(data)
                handle.addfile(member, io.BytesIO(data))
        return path

    def verified(self, path, fact, canonical, *, identities=None, expected_source=None):
        catalog = {'source_files_sha256': {'synthetic.xml':
                   expected_source or hashlib.sha256(canonical).hexdigest()}}
        with patch.object(disassembly.a64_checklist, 'validate', return_value={fact['id']: fact}), \
             patch.object(disassembly.a64_checklist, 'ARCHIVE_SHA',
                          hashlib.sha256(path.read_bytes()).hexdigest()):
            return disassembly.PreferredAliases(catalog, path,
                       [fact['id']] if identities is None else identities)

    def row(self, word=0xc0000001, mnemonic='mov'):
        return {'word': word, 'mnemonic': mnemonic, 'operands': 'synthetic operands',
                'assembly': mnemonic + ' synthetic operands'}

    def smoke(self, fact, *, mnemonic='mov', catalog=None, archive=None, expected=None):
        row = {**fact, 'status': 'implemented', 'profile': progress.SCALABLE_PROFILE,
               'smoke_samples': [{'word': '0xc0000001', 'svl_bytes': 16, 'svcr': 3,
                                  'expected_mnemonics': expected or [mnemonic]}]}
        forms = {fact['id']: row}
        profile = {'id': progress.SCALABLE_PROFILE, 'compiler_command': 'compile-leaf',
                   'abi': progress.CONTEXT_LEAF_ABI, 'svl_bytes': 16, 'svcr': 3}
        decoder = type('UnavailableDecoder', (), {'disasm': lambda self, data, address: iter(())})()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(progress, 'Cs', return_value=decoder), \
             patch.object(disassembly, 'decode_words', return_value={'rows': [self.row(mnemonic=mnemonic)]}), \
             patch.object(progress, 'compile_probe', return_value={'compiler_source_sha256': COMPILER}):
            return progress.smoke_forms('cli', forms, forms, Path(directory), mode='scalable',
                canonical_facts={fact['id']: fact}, profile=profile,
                canonical_catalog=catalog, arm_archive=archive)

    def test_progress_canonical_llvm_rows_need_no_alias_archive(self):
        fact, _canonical, _alias = self.fixture()
        with patch.object(disassembly, 'PreferredAliases') as aliases:
            compiler, results = self.smoke(fact, mnemonic='mova')
        aliases.assert_not_called()
        self.assertEqual(compiler, COMPILER)
        self.assertEqual(results[0]['independent_decode_basis'], disassembly.DECODE_BASIS)
        self.assertNotIn('independent_preferred_alias_facts', results[0])

    def test_progress_alias_rows_require_source_proof_and_retain_it(self):
        fact, canonical, alias = self.fixture()
        with self.assertRaisesRegex(ValueError, 'pinned Arm archive'):
            self.smoke(fact)
        with tempfile.TemporaryDirectory() as directory:
            archive = self.archive(directory, canonical, alias)
            catalog = {'source_files_sha256': {'synthetic.xml': hashlib.sha256(canonical).hexdigest()}}
            with patch.object(disassembly.a64_checklist, 'validate', return_value={fact['id']: fact}), \
                 patch.object(disassembly.a64_checklist, 'ARCHIVE_SHA', hashlib.sha256(archive.read_bytes()).hexdigest()):
                _compiler, results = self.smoke(fact, catalog=catalog, archive=archive)
                self.assertEqual(results[0]['assembly'], 'mov synthetic operands')
                evidence = results[0]['independent_preferred_alias_facts']
                self.assertEqual(evidence['archive_sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
                self.assertEqual(evidence['aliases'][0]['canonical_id'], fact['id'])
                with self.assertRaises(ValueError):
                    self.smoke(fact, catalog=catalog, archive=archive, expected=['mova'])
                with self.assertRaises(FileNotFoundError):
                    self.smoke(fact, catalog=catalog, archive=Path(directory) / 'absent.tar')

    def test_verified_alias_retains_canonical_identity_and_source_evidence(self):
        fact, canonical, alias = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, canonical, alias)
            verified = self.verified(path, fact, canonical)
            self.assertEqual(disassembly.validate_canonical(self.row(), fact['id'], fact,
                             ['mov'], preferred_aliases=verified),
                             ('mov', 'mov synthetic operands', disassembly.DECODE_BASIS))
            evidence = verified.evidence()
            self.assertEqual(len(evidence['aliases']), 1)
            self.assertEqual(evidence['aliases'][0]['canonical_id'], fact['id'])
            self.assertEqual(evidence['aliases'][0]['canonical_fact_sha256'],
                             disassembly.canonical_fact_digest(fact))
            self.assertEqual(evidence['source_files_sha256'], {
                disassembly.a64_checklist.PREFIX + 'synthetic.xml': hashlib.sha256(canonical).hexdigest(),
                disassembly.a64_checklist.PREFIX + 'synthetic_alias.xml': hashlib.sha256(alias).hexdigest()})

    def test_alias_requires_exact_reciprocal_unconditional_encoding_relation(self):
        fact, canonical, alias = self.fixture()
        mutations = [
            (canonical.replace(b'id="synthetic_mova"', b'id="other"'), alias),
            (canonical.replace(b'aliaspageid="synthetic_mov"', b'aliaspageid="other"'), alias),
            (canonical.replace(b'Unconditionally', b'conditional'), alias),
            (canonical.replace(b'</alias_list>', canonical[canonical.index(b'<aliasref'):canonical.index(b'</alias_list>')] + b'</alias_list>'), alias),
            (canonical, alias.replace(b'type="alias"', b'type="instruction"')),
            (canonical, alias.replace(b'refiform="synthetic.xml"', b'refiform="other.xml"')),
            (canonical, alias.replace(b'iformid="synthetic_mova"', b'iformid="other"')),
            (canonical, alias.replace(b'value="MOVA"', b'value="OTHER"')),
            (canonical, alias.replace(b'key="alias_mnemonic" value="MOV"', b'key="unrelated" value="MOV"')),
            (canonical, alias.replace(b'#synthetic_mova_form', b'#other_form')),
            (canonical, alias.replace(b'<aliascond>Unconditionally', b'<aliascond>conditional')),
        ]
        for index, (changed_canonical, changed_alias) in enumerate(mutations):
            with self.subTest(mutation=index), tempfile.TemporaryDirectory() as directory:
                path = self.archive(directory, changed_canonical, changed_alias)
                with self.assertRaises(ValueError):
                    self.verified(path, fact, changed_canonical)

    def test_archive_catalog_source_and_member_guards_fail_closed(self):
        fact, canonical, alias = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, canonical, alias)
            with patch.object(disassembly.a64_checklist, 'validate', return_value={fact['id']: fact}), \
                 patch.object(disassembly.a64_checklist, 'ARCHIVE_SHA', '0' * 64), \
                 self.assertRaises(ValueError):
                disassembly.PreferredAliases({}, path, [fact['id']])
            with self.assertRaises(ValueError):
                self.verified(path, fact, canonical, expected_source='0' * 64)
            for identities in ([], [fact['id'], fact['id']], ['missing']):
                with self.subTest(identities=identities), self.assertRaises(ValueError):
                    self.verified(path, fact, canonical, identities=identities)
            with patch.object(disassembly.a64_checklist, 'validate', side_effect=ValueError('catalog differs')), \
                 self.assertRaises(ValueError):
                disassembly.PreferredAliases({}, path, [fact['id']])
            path = self.archive(directory, canonical, None)
            with self.assertRaises(KeyError):
                self.verified(path, fact, canonical)

    def test_per_word_fixed_bits_fact_digest_mnemonic_and_expected_set_are_required(self):
        fact, canonical, alias = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, canonical, alias)
            verified = self.verified(path, fact, canonical)
            # Bit11 is variable in the canonical form but fixed zero by this alias.
            for row in (self.row(0xc0000801), self.row(0xd0000001), self.row(mnemonic='other')):
                with self.subTest(row=row), self.assertRaises(ValueError):
                    disassembly.validate_canonical(row, fact['id'], fact, preferred_aliases=verified)
            changed_fact = copy.deepcopy(fact)
            changed_fact['features'] = [{'feature': 'invented'}]
            with self.assertRaises(ValueError):
                disassembly.validate_canonical(self.row(), fact['id'], changed_fact, preferred_aliases=verified)
            with self.assertRaises(ValueError):
                disassembly.validate_canonical(self.row(), fact['id'], fact, ['mova'], preferred_aliases=verified)
            with self.assertRaises(ValueError):
                disassembly.validate_canonical(self.row(), fact['id'], fact, preferred_aliases={'mov': True})
            with self.assertRaises(ValueError):
                disassembly.validate_canonical(self.row(), fact['id'], fact)
            self.assertEqual(disassembly.validate_canonical(self.row(mnemonic='mova'), fact['id'], fact)[0], 'mova')
            changed_row = self.row()
            changed_row['assembly'] = 'mov tampered framing'
            with self.assertRaises(ValueError):
                disassembly.validate_canonical(changed_row, fact['id'], fact, preferred_aliases=verified)


class CompilerDepInfoGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.root = self.directory / 'source'
        self.root.mkdir()
        self.target = self.directory / 'target'
        self.target.mkdir()
        self.recipe = ['crates/stela-compiler/src/lib.rs', 'crates/stela-compiler/Cargo.toml', 'Cargo.lock']
        for relative, text in zip(self.recipe, ['use std::include as expand; expand!("hidden.rs");', '[package]', 'version = 4\n[[package]]\nname = "serde"\nversion = "1"\nsource = "registry+test"\nchecksum = "abc"\n']):
            self.write(self.root / relative, text)
        self.write(self.root / 'Cargo.toml', '[workspace]')
        self.write(self.root / 'src/main.rs', 'fn main() {}')
        self.inventory = self.directory / 'inventory.json'
        self.refresh_inventory()
        self.compiler = hashlib.sha256(b''.join((self.root / p).read_bytes() for p in self.recipe)).hexdigest()
        self.cli = self.target / 'stela'
        self.library = self.target / 'libstela_compiler-123.rlib'
        self.write(self.cli, 'executable')
        self.write(self.library, 'library')
        self.compiler_d = self.target / 'stela_compiler-123.d'
        self.cli_d = self.target / 'stela.d'
        self.inputs = [str(self.root / p) for p in self.recipe]
        self.cli_inputs = self.inputs + [str(self.root / 'src/main.rs')]
        self.write_dep_info()
        self.stdout = self.directory / 'cargo.jsonl'
        self.records = [
            {'reason': 'compiler-artifact', 'package_id': 'compiler', 'manifest_path': str(self.root / self.recipe[1]),
             'target': {'name': 'stela_compiler', 'kind': ['lib'], 'src_path': str(self.root / self.recipe[0])}, 'profile': {'test': False},
             'filenames': [str(self.library)], 'executable': None},
            {'reason': 'compiler-artifact', 'package_id': 'cli', 'manifest_path': str(self.root / 'Cargo.toml'),
             'target': {'name': 'stela', 'kind': ['bin'], 'src_path': str(self.root / 'src/main.rs')}, 'profile': {'test': False},
             'filenames': [str(self.cli)], 'executable': str(self.cli)},
            {'reason': 'build-finished', 'success': True}]
        self.write_stdout()
        stderr = self.directory / 'stderr'
        self.write(stderr, 'temporary')
        tools = {}
        for name in ('rustc', 'cargo'):
            binary, version = self.directory / name, self.directory / (name + '.version')
            self.write(binary, name)
            self.write(version, name + ' 1.0\n')
            tools[name], tools[name + '_version'] = self.ref(binary), self.ref(version)
        self.write(stderr, 'Running `' + str(self.directory / 'rustc') + ' CARGO_MANIFEST_DIR=' + str(self.root)
                   + ' CARGO=' + str(self.directory / 'cargo') + ' --crate-name stela --crate-type bin --extern stela_compiler=' + str(self.library) + '`\n')
        fingerprint_json = self.target.parent / '.fingerprint/stela-compiler-123/lib-stela_compiler.json'
        fingerprint_dep = fingerprint_json.with_name('dep-lib-stela_compiler')
        self.write(fingerprint_dep, 'cargo binary dep-info')
        self.write(fingerprint_json, json.dumps({'local': [{'CheckDepInfo': {
            'dep_info': '.fingerprint/stela-compiler-123/dep-lib-stela_compiler'}}]}))
        self.capture = {'kind': 'production_compiler_dep_info_v1', 'compiler_source_sha256': self.compiler,
            'compiler_fingerprint_json': self.ref(fingerprint_json), 'compiler_fingerprint_dep': self.ref(fingerprint_dep),
            'cli': self.ref(self.cli), 'compiler_package_id': 'compiler', 'toolchain': tools,
            'invocation': {'argv': [str(self.directory / 'cargo'), 'build', '--locked', '--message-format=json', '--bin', 'stela', '--target-dir', str(self.target.parent)],
                'cwd': str(self.root), 'returncode': 0, 'stdout': self.ref(self.stdout), 'stderr': self.ref(stderr)},
            'artifacts_sha256': {str(p): progress.sha256(p) for p in (self.cli, self.library)},
            'compiler_dep_info': self.ref(self.compiler_d), 'compiler_dep_info_cwd': str(self.root), 'cli_dep_info': self.ref(self.cli_d),
            'cargo_lock': self.ref(self.root / 'Cargo.lock'),
            'source_roots': {'freeze': {'path': str(self.root), 'inventory': self.ref(self.inventory)}},
            'packages': {'compiler': {'kind': 'workspace', 'manifest_path': str(self.root / self.recipe[1])},
                         'cli': {'kind': 'workspace', 'manifest_path': str(self.root / 'Cargo.toml')}},
            'inputs': {p: {'kind': 'workspace', 'root': 'freeze', 'relative_path': str(Path(p).relative_to(self.root)),
                           'sha256': progress.sha256(p)} for p in self.cli_inputs}}
        self.registry = {'compiler_fingerprint_sources': self.recipe}
        self.capture['toolchain']['cargo_invocation'] = dict(tools['cargo'])
        self.capture_path = self.directory / 'capture.json'

    @staticmethod
    def write(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    @staticmethod
    def ref(path):
        return {'path': str(path), 'sha256': progress.sha256(path)}

    def refresh_inventory(self):
        self.write(self.inventory, json.dumps({'files': {str(p.relative_to(self.root)): progress.sha256(p)
                                                       for p in self.root.rglob('*') if p.is_file()}}))

    def write_dep_info(self):
        escape = lambda p: p.replace(' ', '\\ ')
        self.write(self.compiler_d, escape(str(self.library)) + ': ' + ' '.join(map(escape, self.inputs)) + '\n')
        self.write(self.cli_d, escape(str(self.cli)) + ': ' + ' '.join(map(escape, self.cli_inputs)) + '\n')

    def write_stdout(self):
        self.write(self.stdout, '\n'.join(json.dumps(row) for row in self.records) + '\n')

    def validate(self):
        self.write(self.capture_path, json.dumps(self.capture))
        return progress.validate_compiler_dep_info(self.capture_path, progress.sha256(self.capture_path),
            [self.registry] * 4, cli=self.cli, compiler=self.compiler, root=self.root)

    def test_production_capture_and_recipe_equality(self):
        self.assertEqual(self.validate()['compiler_inputs'], 3)
        other = {'compiler_fingerprint_sources': list(reversed(self.recipe))}
        with self.assertRaisesRegex(ValueError, 'recipes differ'):
            progress.validate_compiler_source_recipes([self.registry, other], self.compiler, root=self.root)

    def test_alias_include_and_procedural_module_inputs_cannot_hide(self):
        for text in ('use std::include as expand; expand!("hidden.rs");', '#[generate_module] mod generated {}'):
            with self.subTest(source=text):
                self.write(self.root / 'hidden.rs', text)
                self.refresh_inventory()
                hidden = str(self.root / 'hidden.rs')
                self.inputs.append(hidden)
                self.cli_inputs.append(hidden)
                self.write_dep_info()
                self.capture['compiler_dep_info'] = self.ref(self.compiler_d)
                self.capture['cli_dep_info'] = self.ref(self.cli_d)
                self.capture['source_roots']['freeze']['inventory'] = self.ref(self.inventory)
                self.capture['inputs'][hidden] = {'kind': 'workspace', 'root': 'freeze', 'relative_path': 'hidden.rs',
                                                  'sha256': progress.sha256(hidden)}
                with self.assertRaisesRegex(ValueError, 'input closure differs'):
                    self.validate()
                self.inputs.pop()
                self.cli_inputs.pop()

    def test_production_artifact_ambiguity_and_test_profile_decline(self):
        self.records.insert(1, dict(self.records[0]))
        self.write_stdout(); self.capture['invocation']['stdout'] = self.ref(self.stdout)
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.validate()
        self.records.pop(1); self.records[0]['profile']['test'] = True
        self.write_stdout(); self.capture['invocation']['stdout'] = self.ref(self.stdout)
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            self.validate()

    def test_stale_dep_info_and_wrong_artifact_stem_decline(self):
        self.write(self.compiler_d, self.compiler_d.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'artifact bytes differ'):
            self.validate()
        other = self.target / 'stela_compiler-other.d'
        self.write(other, self.compiler_d.read_text())
        self.capture['compiler_dep_info'] = self.ref(other)
        with self.assertRaisesRegex(ValueError, 'artifact stem'):
            self.validate()

    def test_each_literal_alias_needs_its_own_provenance(self):
        old = self.inputs[1]
        alias = str(self.root / 'crates/stela-compiler/src/../Cargo.toml')
        self.inputs[1] = alias
        self.cli_inputs.append(alias)
        self.write_dep_info()
        self.capture['compiler_dep_info'] = self.ref(self.compiler_d)
        self.capture['cli_dep_info'] = self.ref(self.cli_d)
        with self.assertRaisesRegex(ValueError, 'literal emitted'):
            self.validate()
        self.capture['inputs'][alias] = dict(self.capture['inputs'][old])
        self.assertEqual(self.validate()['literal_input_paths'], 5)
        self.capture['inputs'][alias]['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'frozen inventory'):
            self.validate()

    def test_path_escape_and_source_inventory_mismatch_decline(self):
        item = self.capture['inputs'][self.inputs[0]]
        item['relative_path'] = '../source/' + self.recipe[0]
        with self.assertRaises(ValueError):
            self.validate()
        item['relative_path'] = 'Cargo.lock'
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.validate()

    def test_environment_and_generated_inputs_decline(self):
        self.write(self.compiler_d, self.compiler_d.read_text() + '# env-dep:OUT_DIR=/tmp/generated\n')
        self.capture['compiler_dep_info'] = self.ref(self.compiler_d)
        with self.assertRaisesRegex(ValueError, 'Environment-dependent'):
            self.validate()
        self.write_dep_info(); self.capture['compiler_dep_info'] = self.ref(self.compiler_d)
        self.capture['inputs'][self.inputs[0]]['kind'] = 'generated'
        with self.assertRaisesRegex(ValueError, 'generated emitted input'):
            self.validate()

    def test_build_failure_and_wrong_executable_decline(self):
        self.capture['invocation']['returncode'] = 1
        with self.assertRaisesRegex(ValueError, 'successful locked'):
            self.validate()
        self.capture['invocation']['returncode'] = 0
        self.records[-1]['success'] = False
        self.write_stdout(); self.capture['invocation']['stdout'] = self.ref(self.stdout)
        with self.assertRaisesRegex(ValueError, 'finish'):
            self.validate()

    def test_actual_link_command_must_select_captured_compiler(self):
        stderr = Path(self.capture['invocation']['stderr']['path'])
        self.write(stderr, stderr.read_text().replace(str(self.library), '/other/compiler.rlib'))
        self.capture['invocation']['stderr'] = self.ref(stderr)
        with self.assertRaisesRegex(ValueError, 'library link differs'):
            self.validate()

    def test_wrapper_and_unrelated_cwd_decline(self):
        stderr = Path(self.capture['invocation']['stderr']['path'])
        original = stderr.read_text()
        self.write(stderr, original.replace('Running `', 'Running `/unbound/wrapper '))
        self.capture['invocation']['stderr'] = self.ref(stderr)
        with self.assertRaisesRegex(ValueError, 'library link differs'):
            self.validate()
        self.write(stderr, original); self.capture['invocation']['stderr'] = self.ref(stderr)
        self.capture['invocation']['cwd'] = str(self.directory)
        with self.assertRaisesRegex(ValueError, 'workspace manifest'):
            self.validate()

    def test_fingerprint_must_link_selected_dep_info(self):
        path = Path(self.capture['compiler_fingerprint_json']['path'])
        for link in ('other/dep-lib-stela_compiler', 'dep-lib-stela_compiler',
                     'stela-compiler-123/dep-lib-stela_compiler'):
            with self.subTest(link=link):
                self.write(path, json.dumps({'local': [{'CheckDepInfo': {'dep_info': link}}]}))
                self.capture['compiler_fingerprint_json'] = self.ref(path)
                with self.assertRaisesRegex(ValueError, 'lost its dep-info link'):
                    self.validate()

    def test_target_directory_and_fingerprint_link_cannot_be_substituted_together(self):
        path = Path(self.capture['compiler_fingerprint_json']['path'])
        dep = Path(self.capture['compiler_fingerprint_dep']['path'])
        args = self.capture['invocation']['argv']
        args[args.index('--target-dir') + 1] = str(dep.parent)
        self.write(path, json.dumps({'local': [{'CheckDepInfo': {'dep_info': dep.name}}]}))
        self.capture['compiler_fingerprint_json'] = self.ref(path)
        with self.assertRaisesRegex(ValueError, 'contradict Cargo target'):
            self.validate()

    def test_equals_missing_and_duplicate_manifest_flags_decline(self):
        original = list(self.capture['invocation']['argv'])
        for suffix in (['--manifest-path=/other/Cargo.toml'], ['--manifest-path'],
                       ['--manifest-path', str(self.root / 'Cargo.toml'), '--manifest-path=' + str(self.root / 'Cargo.toml')]):
            with self.subTest(arguments=suffix):
                self.capture['invocation']['argv'] = original + suffix
                with self.assertRaisesRegex(ValueError, 'manifest'):
                    self.validate()

    def test_relative_rustc_inputs_keep_explicit_cwd_and_literal_spelling(self):
        absolute = list(self.inputs)
        self.inputs = [str(Path(p).relative_to(self.root)) for p in absolute]
        self.write_dep_info()
        self.capture['compiler_dep_info'] = self.ref(self.compiler_d)
        self.capture['cli_dep_info'] = self.ref(self.cli_d)
        for relative, old in zip(self.inputs, absolute):
            self.capture['inputs'][relative] = dict(self.capture['inputs'][old])
        self.assertEqual(self.validate()['literal_input_paths'], 7)
        self.capture['compiler_dep_info_cwd'] = str(self.directory)
        with self.assertRaisesRegex(ValueError, 'dep-info cwd'):
            self.validate()

    def test_external_artifacts_need_exact_lock_identity(self):
        external = self.target / 'libserde.rlib'; self.write(external, 'locked crate')
        identity = 'registry+test#serde@1'
        self.records.insert(0, {'reason': 'compiler-artifact', 'package_id': identity,
            'manifest_path': '/external/serde/Cargo.toml', 'target': {'name': 'serde', 'kind': ['lib']},
            'profile': {'test': False}, 'filenames': [str(external)], 'executable': None})
        self.write_stdout(); self.capture['invocation']['stdout'] = self.ref(self.stdout)
        self.capture['artifacts_sha256'][str(external)] = progress.sha256(external)
        package = {'kind': 'external_locked', 'manifest_path': '/external/serde/Cargo.toml',
                   'name': 'serde', 'version': '1', 'source': 'registry+test', 'checksum': 'abc'}
        self.capture['packages'][identity] = package
        self.assertEqual(self.validate()['external_locked_packages'], 1)
        package['checksum'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'checksum-bound'):
            self.validate()

    def test_dep_info_parser_declines_make_expressions_and_duplicates(self):
        rules, env = progress.parse_rust_dep_info('/target: /a\\ b /c\\\n /d\n/a\\ b:\n')
        self.assertEqual(rules['/target'], ['/a b', '/c', '/d'])
        self.assertEqual(env, {})
        for text in ('/target: $(wildcard *.rs)', '/target: /x\n/target: /x', '/target: /x\\q',
                     '/target: /x\n# env-dep:A=x\n# env-dep:A=y'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                progress.parse_rust_dep_info(text)


class SampleHostTargetTests(unittest.TestCase):
    def fake_compiler(self, manifest_target=None):
        def fake(command, **kwargs):
            target = command[command.index('--cpu-target') + 1]
            baseline_command = list(command)
            baseline_command[baseline_command.index('--cpu-target') + 1] = 'x86_64-baseline'
            result = ScalableProgressTests().fake_compiler()(baseline_command, **kwargs)
            manifest = json.loads(result.stdout)
            manifest['target_cpu'] = target if manifest_target is None else manifest_target
            return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
        return fake

    def probe(self, directory, **kwargs):
        return progress.compile_probe('cli', progress.RET, directory, mode='scalable',
            guest_profile=progress.SCALABLE_PROFILE, svl_bytes=16, svcr=3, **kwargs)

    def test_absent_host_target_keeps_canonical_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.probe(Path(directory), run=self.fake_compiler())
        self.assertEqual(result['target_cpu'], 'x86_64-baseline')
        self.assertEqual(result['execution_profile'], {'id': progress.SCALABLE_PROFILE, 'svl_bytes': 16, 'svcr': 3})

    def test_optional_host_target_is_forwarded_and_exact_manifest_target_retained(self):
        for target in ('x86_64-baseline+atomic-load16', 'x86_64-baseline+cx16',
                       'x86_64-baseline+atomic-load16+cx16'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                result = self.probe(Path(directory), cpu_target=target, run=self.fake_compiler())
            self.assertEqual(result['target_cpu'], target)
            self.assertEqual(result['execution_profile']['id'], progress.SCALABLE_PROFILE)

    def test_mismatched_canonical_target_and_alias_native_targets_decline(self):
        for target in ('x86_64-baseline+cx16', 'baseline', 'native'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, 'source/native metadata mismatch'):
                    self.probe(Path(directory), cpu_target=target, run=self.fake_compiler('x86_64-baseline'))

    def test_invalid_transport_values_decline_before_compiler(self):
        for target in ('', 1, True, [], {}, 'a' * 257, 'bad\nargument', 'bad\x00argument', '\ud800'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                with patch.object(progress.subprocess, 'run') as run:
                    with self.assertRaises(ValueError):
                        self.probe(Path(directory), cpu_target=target, run=run)
                    run.assert_not_called()
                    self.assertEqual(list(Path(directory).iterdir()), [])
        sample = {'word': '0xd65f03c0', 'expected_mnemonics': ['ret'], 'svl_bytes': 16, 'svcr': 3, 'cpu_target': None}
        with self.assertRaises(ValueError):
            progress.validate_scalable_sample(sample, ScalableProgressTests().profile())

    def test_target_syntax_and_capability_rejection_stays_with_rust(self):
        # Mock transport/error propagation; Rust's existing parser remains the
        # sole authority for unknown, duplicate and reordered suffixes.
        for target in ('x86_64-baseline+unknown', 'x86_64-baseline+cx16+cx16',
                       'x86_64-baseline+cx16+atomic-load16'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                calls = []
                def rejected(command, **kwargs):
                    calls.append(command)
                    return subprocess.CompletedProcess(command, 1, '', 'Rust target parser rejected target')
                with self.assertRaisesRegex(ValueError, 'Rust target parser rejected target'):
                    self.probe(Path(directory), cpu_target=target, run=rejected)
                self.assertEqual(calls[0][calls[0].index('--cpu-target') + 1], target)

    def test_sample_target_routes_to_supported_and_rejected_probes(self):
        registry = DeclaredScalableProgressTests().registry()
        row = registry['forms'][1]
        target = 'x86_64-baseline+atomic-load16'
        row['smoke_samples'][0]['cpu_target'] = target
        row['rejected_samples'] = [{'word': '0xd65f03c0', 'reason': 'scope limit', 'svl_bytes': 16,
                                    'svcr': 3, 'cpu_target': 'x86_64-baseline+cx16'}]
        rows = progress.validate_registry(registry)
        with tempfile.TemporaryDirectory() as directory, patch.object(progress, 'compile_probe', return_value={
                'compiler_source_sha256': COMPILER}) as probe:
            progress.smoke_forms('cli', rows, rows, Path(directory), mode='scalable',
                profile=registry['profile'], execution_profiles=registry['execution_profiles'])
        targets = [call.kwargs['cpu_target'] for call in probe.call_args_list if 'cpu_target' in call.kwargs]
        self.assertEqual(targets, [target, 'x86_64-baseline+cx16'])
        for call in probe.call_args_list:
            self.assertNotIn('cpu_target', call.kwargs.get('features', []))

    def test_legacy_samples_cannot_silently_ignore_explicit_host_target(self):
        for collection in ('smoke_samples', 'rejected_samples'):
            registry = fixtures()
            if collection == 'smoke_samples':
                registry['forms'][0][collection][0]['cpu_target'] = 'x86_64-baseline+cx16'
            else:
                registry['forms'][0][collection] = [{'cpu_target': 'x86_64-baseline+cx16'}]
            with self.subTest(collection=collection), self.assertRaisesRegex(ValueError, 'context compiler lane'):
                progress.validate_registry(registry)

    def test_host_target_is_not_a_guest_profile_declaration(self):
        profile = {**ScalableProgressTests().profile(), 'cpu_target': 'x86_64-baseline+cx16'}
        with self.assertRaises(ValueError):
            progress.validate_scalable_profile(profile)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'context compiler lane'):
            progress.compile_probe('cli', progress.RET, Path(directory), cpu_target='x86_64-baseline+cx16')


class SystemServiceProfileTests(unittest.TestCase):
    def contracts(self):
        default = {'id': progress.SERVICE_PROFILE, 'compiler_mode': 'service',
                   'abi': progress.SERVICE_ABI, 'outside_scope': ['System services']}
        system = {'id': progress.SYSTEM_PROFILE, 'compiler_mode': 'service',
                  'abi': progress.SYSTEM_ABI, 'outside_scope': ['Full CPU/OS']}
        return default, {progress.SYSTEM_PROFILE: system}

    def test_default_and_system_profiles_are_separate_and_bounded(self):
        default, additional = self.contracts()
        self.assertEqual(set(progress.validate_service_profiles(default, additional)),
                         {progress.SERVICE_PROFILE, progress.SYSTEM_PROFILE})
        for mutation in ({'abi': progress.SERVICE_ABI}, {'compiler_mode': 'leaf'}, {'id': 'unknown'}):
            changed = copy.deepcopy(additional)
            changed[progress.SYSTEM_PROFILE].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                progress.validate_service_profiles(default, changed)
        with self.assertRaises(ValueError):
            progress.validate_service_profiles(default, {default['id']: default})

    def test_mixed_service_rows_select_their_own_profile_without_new_lane(self):
        default, additional = self.contracts()
        registry = fixtures()
        registry['profile'] = default
        registry['execution_profiles'] = additional
        registry['forms'] = [registry['forms'][0]]
        registry['forms'][0]['profile'] = progress.SERVICE_PROFILE
        system = copy.deepcopy(registry['forms'][0])
        system.update(id='IRG_64I_dp_2src', profile=progress.SYSTEM_PROFILE,
                      encoding_mask='0xffe0fc00', encoding_value='0x9ac01000',
                      smoke_samples=[{'word': '0x9ac21020', 'expected_mnemonics': ['irg']}])
        registry['forms'].append(system)
        rows = progress.validate_registry(registry)
        with tempfile.TemporaryDirectory() as directory, patch.object(progress, 'compile_probe',
                return_value={'compiler_source_sha256': COMPILER}) as compile_probe:
            progress.smoke_forms('cli', rows, rows, Path(directory), mode='service',
                                 profile=default, execution_profiles=additional)
        self.assertEqual([call.kwargs['service_profile'] for call in compile_probe.call_args_list],
                         [progress.SERVICE_PROFILE, progress.SYSTEM_PROFILE])
        system['profile'] = 'undeclared-system'
        with self.assertRaises(ValueError):
            progress.validate_registry(registry)

    def fake_compiler(self, mutation=None):
        def run(command, **_kwargs):
            self.command = command
            source = Path(command[2])
            output = Path(command[command.index('--output-dir') + 1])
            output.mkdir()
            native = bytes.fromhex('48b80000001000000000ba0b000000c3')
            manifest = {'source_sha256': hashlib.sha256(source.read_bytes()[:4]).hexdigest(),
                        'source_bytes': 4, 'abi': progress.SYSTEM_ABI,
                        'compiler_source_sha256': COMPILER,
                        'target_cpu': 'x86_64-baseline', 'source_map': [[progress.SYSTEM_GUEST_BASE, 0]]}
            if mutation:
                native = mutation(manifest, native)
            (output / 'native.bin').write_bytes(native)
            manifest['native_sha256'] = progress.sha256(output / 'native.bin')
            return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
        return run

    def test_system_probe_uses_explicit_baseline_system_flags_and_abi(self):
        with tempfile.TemporaryDirectory() as directory:
            result = progress.compile_probe('cli', 0x9ac21020, Path(directory), mode='service',
                service_profile=progress.SYSTEM_PROFILE, run=self.fake_compiler())
        self.assertIn('--system-boundaries', self.command)
        self.assertNotIn('--software-pauth', self.command)
        self.assertNotIn('--software-clock', self.command)
        self.assertEqual(self.command[self.command.index('--cpu-target') + 1], progress.BASELINE_CPU_TARGET)
        self.assertEqual((result['abi'], result['source_bytes'], result['native_bytes']),
                         (progress.SYSTEM_ABI, 4, 16))

    def test_system_probe_rejects_wrong_pc_exit_target_or_map(self):
        def wrong_exit(_manifest, native):
            return native[:11] + bytes([12]) + native[12:]
        def wrong_pc(_manifest, native):
            return native[:2] + bytes([4]) + native[3:]
        def wrong_target(manifest, native):
            manifest['target_cpu'] = 'x86_64-baseline+cx16'
            return native
        def wrong_map(manifest, native):
            manifest['source_map'] = [[progress.SYSTEM_GUEST_BASE + 4, 0]]
            return native
        for mutation in (wrong_exit, wrong_pc, wrong_target, wrong_map):
            with tempfile.TemporaryDirectory() as directory, self.subTest(mutation=mutation), self.assertRaises(ValueError):
                progress.compile_probe('cli', 0x9ac21020, Path(directory), mode='service',
                    service_profile=progress.SYSTEM_PROFILE, run=self.fake_compiler(mutation))

    def test_service_profile_cannot_leak_into_leaf_or_unknown_lane(self):
        for mode, profile in [('leaf', progress.SYSTEM_PROFILE), ('service', 'unknown')]:
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                progress.compile_probe('cli', progress.RET, Path(directory), mode=mode,
                    service_profile=profile, run=lambda *_args, **_kwargs: self.fail('must not compile'))



class FollowingWordProbeTests(unittest.TestCase):
    PREFIX = 0x0420bc20
    FOLLOWING = '0x041a0040'

    def fake_compiler(self, mutation=None):
        def fake(command, **kwargs):
            source = Path(command[2]); data = source.read_bytes()
            self.assertEqual(data, bytes.fromhex('20bc200440001a04c0035fd6'))
            output = Path(command[command.index('--output-dir') + 1]); output.mkdir()
            native = bytes(13) + b'\x90' * 6 + b'\xc3'; (output / 'native.bin').write_bytes(native)
            manifest = {'schema_version': 2, 'kind': 'raw_arm64_leaf_aot', 'abi': progress.CONTEXT_LEAF_ABI,
                'target_cpu': 'x86_64-baseline', 'guest_base': progress.SCALABLE_GUEST_BASE,
                'guest_instructions': 3, 'native_bytes': len(native), 'entry_prefix_bytes': 13,
                'execution_profile': {'id': progress.SCALABLE_PROFILE, 'svl_bytes': 16, 'svcr': 3},
                'source_map': [[progress.SCALABLE_GUEST_BASE, 13], [progress.SCALABLE_GUEST_BASE + 4, 16],
                               [progress.SCALABLE_GUEST_BASE + 8, 19]],
                'source_sha256': hashlib.sha256(data).hexdigest(), 'native_sha256': progress.sha256(output / 'native.bin'),
                'compiler_source_sha256': COMPILER}
            if mutation: mutation(manifest)
            return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
        return fake

    def probe(self, directory, **kwargs):
        return progress.compile_probe('cli', self.PREFIX, directory, mode='scalable',
            guest_profile=progress.SCALABLE_PROFILE, svl_bytes=16, svcr=3, **kwargs)

    def registry(self):
        registry = fixtures(); registry['profile'] = ScalableProgressTests().profile()
        facts = progress.a64_checklist.validate(json.loads((progress.ROOT / 'tests/isa/a64-documented-checklist.json').read_text()))
        fact = facts['movprfx_z_z_']; row = copy.deepcopy(registry['forms'][0])
        row.update({key: fact[key] for key in ('id', 'source_file', 'encoding_mask', 'encoding_value')})
        row.update(profile=progress.SCALABLE_PROFILE, smoke_samples=[{
            'word': f'0x{self.PREFIX:08x}', 'expected_mnemonics': ['movprfx'],
            'following_words': [self.FOLLOWING], 'svl_bytes': 16, 'svcr': 3}])
        registry['forms'] = [row]
        return registry, facts

    def test_absent_following_words_preserves_existing_input_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory)
            result = SampleHostTargetTests().probe(location, run=SampleHostTargetTests().fake_compiler())
            self.assertEqual((location / 'source.arm64').read_bytes(), bytes.fromhex('c0035fd6c0035fd6'))
            self.assertNotIn('probe_source_words', result)

    def test_declared_following_word_binds_full_source_hash_instruction_count_and_map(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.probe(Path(directory), following_words=[self.FOLLOWING], run=self.fake_compiler())
        self.assertEqual(result['probe_source_words'], [f'0x{self.PREFIX:08x}', self.FOLLOWING, '0xd65f03c0'])
        self.assertEqual(result['source_sha256'], hashlib.sha256(bytes.fromhex('20bc200440001a04c0035fd6')).hexdigest())
        self.assertEqual(len(result['source_map']), 3)

    def test_malformed_bundle_declines_before_source_or_compiler(self):
        for value in ([], [self.FOLLOWING, self.FOLLOWING], self.FOLLOWING, [0x041a0040],
                      [True], [None], ['041a0040'], ['0x041a004000'], ['0xgggggggg']):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                with patch.object(progress.subprocess, 'run') as run:
                    with self.assertRaises(ValueError):
                        self.probe(Path(directory), following_words=value, run=run)
                    run.assert_not_called(); self.assertEqual(list(Path(directory).iterdir()), [])
        with self.assertRaises(ValueError):
            progress.validate_scalable_sample({'following_words': None}, ScalableProgressTests().profile())

    def test_compiler_cannot_change_declared_source_and_rehash_the_substitute(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = self.fake_compiler()
            def substituted(command, **kwargs):
                result = fake(command, **kwargs)
                source = Path(command[2]); source.write_bytes(bytes.fromhex('c0035fd6c0035fd6c0035fd6'))
                manifest = json.loads(result.stdout); manifest['source_sha256'] = progress.sha256(source)
                return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
            with self.assertRaisesRegex(ValueError, 'input changed'):
                self.probe(Path(directory), following_words=[self.FOLLOWING], run=substituted)

    def test_expected_pair_rejection_cannot_rebind_changed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            def substituted(command, **kwargs):
                Path(command[2]).write_bytes(bytes.fromhex('c0035fd6c0035fd6c0035fd6'))
                return subprocess.CompletedProcess(command, 1, '', 'invalid prefix/follower pair')
            with self.assertRaisesRegex(ValueError, 'input changed'):
                self.probe(Path(directory), following_words=[self.FOLLOWING],
                           expect_failure='invalid prefix/follower pair', run=substituted)

    def test_capstone_following_decode_is_retained_without_canonical_assessment(self):
        instruction = type('Instruction', (), {'mnemonic': 'and', 'op_str': 'z0.b, p0/m, z0.b, z2.b'})()
        decoder = type('Available', (), {'disasm': lambda self, data, address: iter([instruction])})()
        self.assertEqual(progress.decode_following_word(decoder, int(self.FOLLOWING,16), {}),
                         ('and', 'and z0.b, p0/m, z0.b, z2.b', 'capstone'))

    def test_bundle_rejects_partial_hash_and_missing_or_wrong_source_map(self):
        changes = [{'source_sha256': hashlib.sha256(bytes.fromhex('20bc2004')).hexdigest()},
                   {'guest_instructions': 2}, {'source_map': [[progress.SCALABLE_GUEST_BASE, 13],
                                                            [progress.SCALABLE_GUEST_BASE + 4, 16]]},
                   {'source_map': [[progress.SCALABLE_GUEST_BASE, 13], [progress.SCALABLE_GUEST_BASE + 8, 16],
                                   [progress.SCALABLE_GUEST_BASE + 4, 19]]}]
        for changed in changes:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.probe(Path(directory), following_words=[self.FOLLOWING],
                           run=self.fake_compiler(lambda m: m.update(changed)))

    def test_actual_compiler_pair_rejection_is_not_replaced_by_tool_workaround(self):
        with tempfile.TemporaryDirectory() as directory:
            def rejected(command, **kwargs):
                self.assertEqual(Path(command[2]).read_bytes(), bytes.fromhex('20bc2004c0035fd6c0035fd6'))
                return subprocess.CompletedProcess(command, 1, '', 'invalid prefix/follower pair')
            result = self.probe(Path(directory), following_words=['0xd65f03c0'],
                                expect_failure='invalid prefix/follower pair', run=rejected)
        self.assertTrue(result['rejected'])

    def test_follower_is_independently_decoded_and_retained_without_canonical_credit(self):
        registry, facts = self.registry(); rows = progress.validate_registry(registry)
        decoder = type('Unavailable', (), {'disasm': lambda self, data, address: iter(())})()
        receipt = {'rows': [
            {'word': self.PREFIX, 'offset': 0, 'mnemonic': 'movprfx', 'operands': 'z0, z1', 'assembly': 'movprfx z0, z1'},
            {'word': int(self.FOLLOWING, 16), 'offset': 4, 'mnemonic': 'and', 'operands': 'z0.b, p0/m, z0.b, z2.b',
             'assembly': 'and z0.b, p0/m, z0.b, z2.b'}]}
        with tempfile.TemporaryDirectory() as directory, patch.object(progress, 'Cs', return_value=decoder), \
             patch.object(disassembly, 'decode_words', return_value=receipt) as decode, \
             patch.object(progress, 'compile_probe', return_value={'compiler_source_sha256': COMPILER,
                 'source_map': [[progress.SCALABLE_GUEST_BASE,13], [progress.SCALABLE_GUEST_BASE+4,16],
                                [progress.SCALABLE_GUEST_BASE+8,19]], 'native_bytes': 20}) as probe:
            _, results = progress.smoke_forms('cli', rows, rows, Path(directory), mode='scalable',
                profile=registry['profile'], canonical_facts=facts)
        self.assertEqual(decode.call_args.args[0], sorted([self.PREFIX, int(self.FOLLOWING,16)]))
        self.assertEqual(probe.call_args.kwargs['following_words'], [self.FOLLOWING])
        self.assertEqual(len(results), 1); self.assertEqual(results[0]['id'], 'movprfx_z_z_')
        follower = results[0]['following_source'][0]
        self.assertFalse(follower['canonical_form_credit'])
        self.assertEqual(follower['native_span'], {'start':16,'end':19})
        self.assertEqual(results[0]['assessed_native_span'], {'start':13,'end':16})
        self.assertEqual(follower['independent_decode_basis'], 'apple_llvm21_objdump')
        self.assertEqual(progress.summarize(rows)['reviewed']['implemented'], 1)

    def test_unknown_or_misframed_follower_never_gets_decoder_credit(self):
        decoder = type('Unavailable', (), {'disasm': lambda self, data, address: iter(())})()
        word = int(self.FOLLOWING, 16)
        for row in (None, {'word':word,'mnemonic':'<unknown>','operands':'','assembly':'<unknown>'},
                    {'word':word,'mnemonic':'and','operands':'z0.b','assembly':'wrong'},
                    {'word':word+1,'mnemonic':'and','operands':'z0.b','assembly':'and z0.b'}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                progress.decode_following_word(decoder, word, {} if row is None else {word:row})

    def test_non_context_samples_cannot_silently_ignore_source_bundle(self):
        registry = fixtures(); registry['forms'][0]['smoke_samples'][0]['following_words'] = [self.FOLLOWING]
        with self.assertRaisesRegex(ValueError, 'context compiler lane'):
            progress.validate_registry(registry)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'context compiler lane'):
            progress.compile_probe('cli', self.PREFIX, Path(directory), following_words=[self.FOLLOWING])


class ContextCompilerProgressTests(unittest.TestCase):
    def profile(self, *, block=True):
        profile = DeclaredScalableProgressTests().profile()
        if block:
            profile.update(compiler_command='compile-block', abi=progress.CONTEXT_BLOCK_ABI,
                           numerical_features={'full_a64': False, 'ebf16': False, 'rpres': True})
        return profile

    def fake_compiler(self, consumed=4, mutation=None):
        def fake(command, **kwargs):
            source = Path(command[2]); output = Path(command[command.index('--output-dir') + 1])
            output.mkdir(); native = bytes(13) + bytes(consumed // 4) + b'\xc3'
            (output / 'native.bin').write_bytes(native)
            block = command[1] == 'compile-block'
            data = source.read_bytes()[:consumed] if block else source.read_bytes()
            features = [command[i + 1] for i, value in enumerate(command) if value == '--guest-feature']
            execution = progress.scalable_execution_profile(
                command[command.index('--guest-profile') + 1],
                int(command[command.index('--svl-bytes') + 1]), int(command[command.index('--svcr') + 1]),
                features=features, max_svl_bytes=int(command[command.index('--max-svl-bytes') + 1]),
                zt0_enabled=command[command.index('--zt0-enabled') + 1] == 'true', dit=False)
            manifest = {'schema_version': 2, 'kind': 'raw_arm64_block_aot' if block else 'raw_arm64_leaf_aot',
                'abi': progress.CONTEXT_BLOCK_ABI if block else progress.CONTEXT_LEAF_ABI,
                'target_cpu': command[command.index('--cpu-target') + 1],
                'guest_base': progress.SCALABLE_GUEST_BASE, 'guest_instructions': len(data) // 4,
                'execution_profile': execution, 'entry_prefix_bytes': 13, 'native_bytes': len(native),
                'source_map': [[progress.SCALABLE_GUEST_BASE + i * 4, 13 + i] for i in range(len(data) // 4)],
                'source_sha256': hashlib.sha256(data).hexdigest(), 'native_sha256': progress.sha256(output / 'native.bin'),
                'compiler_source_sha256': COMPILER}
            if block:
                manifest['source_bytes'] = consumed
                manifest['numerical_features'] = {key: command[command.index('--' + key.replace('_', '-')) + 1] == 'true'
                                                  for key in progress.NUMERICAL_FEATURE_FIELDS}
            if mutation:
                mutation(manifest)
            return subprocess.CompletedProcess(command, 0, json.dumps(manifest), '')
        return fake

    def probe(self, directory, *, block=True, **kwargs):
        profile = self.profile(block=block)
        return progress.compile_probe('cli', progress.RET, directory, mode='scalable',
            guest_profile=profile['id'], svl_bytes=profile['svl_bytes'], svcr=profile['svcr'],
            compiler_command=profile['compiler_command'], context_abi=profile['abi'],
            numerical_features=profile.get('numerical_features'), **progress.scalable_declaration(profile), **kwargs)

    def test_context_block_command_and_numerical_manifest(self):
        for consumed in (4, 8):
            with self.subTest(consumed=consumed), tempfile.TemporaryDirectory() as directory:
                result = self.probe(Path(directory), expected_source_bytes=consumed, run=self.fake_compiler(consumed))
                self.assertEqual(result['source_bytes'], consumed)
                self.assertEqual(result['abi'], progress.CONTEXT_BLOCK_ABI)
                self.assertEqual(len(result['source_map']), consumed // 4)
                self.assertEqual(result['numerical_features'], self.profile()['numerical_features'])
                self.assertEqual(result['compiler_command'], 'compile-block')

    def test_block_extent_is_checked_before_hashes(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'declared consumed boundary'):
            self.probe(Path(directory), expected_source_bytes=8,
                run=self.fake_compiler(4, lambda m: m.update(source_sha256='bad')))

    def test_block_manifest_requires_exact_schema_abi_and_numerical_fields(self):
        mutations = [lambda m: m.update(schema_version=1), lambda m: m.update(abi=progress.BLOCK_ABI),
                     lambda m: m.update(kind='raw_arm64_leaf_aot'), lambda m: m.pop('numerical_features'),
                     lambda m: m['numerical_features'].update(full_a64=0),
                     lambda m: m['numerical_features'].update(rpres=False),
                     lambda m: m['numerical_features'].update(unknown=False),
                     lambda m: m.update(source_map=[[progress.SCALABLE_GUEST_BASE, 0]]),
                     lambda m: m.update(guest_instructions=2)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                self.probe(Path(directory), run=self.fake_compiler(mutation=mutation))

    def test_direct_block_manifest_rejects_misaligned_or_wrong_consumed_extent(self):
        profile = self.profile()
        with tempfile.TemporaryDirectory() as directory:
            captured = {}
            fake = self.fake_compiler()
            def run(command, **kwargs):
                result = fake(command, **kwargs); captured.update(json.loads(result.stdout)); return result
            self.probe(Path(directory), run=run)
        for data in (b'', b'abc', bytes(8)):
            with self.subTest(source_bytes=len(data)), self.assertRaises(ValueError):
                progress.validate_context_manifest(captured, data, captured['native_bytes'], 16, 3,
                    guest_profile=profile['id'], compiler_command='compile-block',
                    context_abi=profile['abi'], numerical_features=profile['numerical_features'],
                    **progress.scalable_declaration(profile))

    def test_block_profile_requires_explicit_numerical_contract_and_exact_pair(self):
        for changed in ({'numerical_features': None}, {'numerical_features': {}},
                        {'numerical_features': {'full_a64': False, 'ebf16': False, 'rpres': 1}},
                        {'abi': progress.CONTEXT_LEAF_ABI}, {'compiler_command': 'compile-service'}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                progress.validate_scalable_profile({**self.profile(), **changed})
        for value in (None, self.profile()['numerical_features']):
            with self.subTest(value=value), self.assertRaises(ValueError):
                progress.validate_scalable_profile({**self.profile(block=False), 'numerical_features': value})

    def test_profile_identity_separates_command_abi_and_numerical_features(self):
        block = self.profile(); other = copy.deepcopy(block); other['numerical_features']['ebf16'] = True
        contracts = {'leaf': self.profile(block=False), 'block': block, 'other-numerical': other}
        profiles = progress.validate_scalable_profiles(ScalableProgressTests().profile(), contracts)
        self.assertEqual(set(profiles), set(contracts) | {progress.SCALABLE_PROFILE})
        with self.assertRaisesRegex(ValueError, 'Duplicate semantic'):
            progress.validate_scalable_profiles(ScalableProgressTests().profile(), {'one': block, 'same': copy.deepcopy(block)})

    def test_explicit_host_target_reaches_cli_and_exact_manifest_for_leaf_and_block(self):
        for block in (False, True):
            for target in ('x86_64-baseline+atomic-load16', 'x86_64-baseline+cx16'):
                with self.subTest(block=block, target=target), tempfile.TemporaryDirectory() as directory:
                    result = self.probe(Path(directory), block=block, cpu_target=target,
                                        run=self.fake_compiler(consumed=4 if block else 8))
                    self.assertEqual(result['target_cpu'], target)
                with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, 'source/native metadata'):
                    self.probe(Path(directory), block=block, cpu_target=target,
                        run=self.fake_compiler(consumed=4 if block else 8,
                            mutation=lambda m: m.update(target_cpu='x86_64-baseline')))



    def test_sample_options_keep_host_target_separate_from_guest_and_route_blocks(self):
        registry = DeclaredScalableProgressTests().registry()
        registry['execution_profiles']['sme-i16i64-v2'] = self.profile()
        row = registry['forms'][1]
        row['smoke_samples'][0]['cpu_target'] = 'x86_64-baseline+atomic-load16'
        row['smoke_samples'][0]['consumed_source_bytes'] = 4
        rows = progress.validate_registry(registry)
        with tempfile.TemporaryDirectory() as directory, patch.object(progress, 'compile_probe', return_value={
                'compiler_source_sha256': COMPILER}) as probe:
            progress.smoke_forms('cli', rows, rows, Path(directory), mode='scalable',
                profile=registry['profile'], execution_profiles=registry['execution_profiles'])
        options = next(call.kwargs for call in probe.call_args_list if 'cpu_target' in call.kwargs)
        self.assertEqual(options['cpu_target'], 'x86_64-baseline+atomic-load16')
        self.assertEqual(options['compiler_command'], 'compile-block')
        self.assertEqual(options['numerical_features'], self.profile()['numerical_features'])
        self.assertEqual(options['expected_source_bytes'], 4)
        for name in ('features', 'numerical_features', 'max_svl_bytes'):
            with self.subTest(field=name), self.assertRaises(ValueError):
                progress.validate_scalable_sample({**row['smoke_samples'][0], name: {}}, self.profile())


class ContextFollowingBoundaryTests(unittest.TestCase):
    def test_block_sample_cannot_declare_leaf_source_bundle(self):
        contract = ContextCompilerProgressTests().profile()
        sample = {'word': '0xd65f03c0', 'expected_mnemonics': ['ret'],
                  'svl_bytes': contract['svl_bytes'], 'svcr': contract['svcr'],
                  'following_words': ['0x041a0040']}
        with self.assertRaisesRegex(ValueError, 'context leaf command'):
            progress.validate_scalable_sample(sample, contract)

    def test_block_bundle_declines_before_source_or_compiler(self):
        contract = ContextCompilerProgressTests().profile()
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory)
            with self.assertRaisesRegex(ValueError, 'context leaf command'):
                progress.compile_probe('cli', 0x0420bc20, location, mode='scalable',
                    guest_profile=contract['id'], svl_bytes=contract['svl_bytes'], svcr=contract['svcr'],
                    compiler_command=contract['compiler_command'], context_abi=contract['abi'],
                    numerical_features=contract['numerical_features'], following_words=['0x041a0040'],
                    run=lambda *args, **kwargs: self.fail('Unsupported command combination launched compiler'),
                    **progress.scalable_declaration(contract))
            self.assertEqual(list(location.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
