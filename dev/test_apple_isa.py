"""Official Apple compiler inventory/predicate checks without private inputs or native execution."""
import copy
import json
from pathlib import Path
import unittest

import a64_checklist
import apple_isa


class AppleIsaTests(unittest.TestCase):
    def test_official_feature_snapshot_is_strict_and_hash_pinned(self):
        root = Path(__file__).resolve().parents[1]
        snapshot = json.loads((root / 'tests/isa/apple-clang-features.json').read_bytes())
        self.assertEqual(apple_isa.load_snapshot(snapshot), snapshot)
        self.assertEqual(set(snapshot['profiles']), set(apple_isa.CPUS))
        self.assertEqual(snapshot['tool']['version'], 'Apple clang version 21.0.0 (clang-2100.3.34.2)')
        for change in ('schema', 'extra_field', 'unknown_cpu', 'missing_cpu', 'target',
                       'command_cpu', 'feature', 'rehashed_feature', 'tool_hash', 'export_hash'):
            modified = copy.deepcopy(snapshot)
            if change == 'schema':
                modified['schema_version'] = 99
            elif change == 'extra_field':
                modified['unreviewed'] = True
            elif change == 'unknown_cpu':
                modified['profiles']['apple-m7'] = modified['profiles'].pop('apple-m6')
            elif change == 'missing_cpu':
                del modified['profiles']['apple-m6']
            elif change == 'target':
                modified['target'] = 'aarch64-unknown-none-elf'
            elif change == 'command_cpu':
                modified['profiles']['apple-m1']['command'][2] = '-mcpu=apple-m6'
            elif change in ('feature', 'rehashed_feature'):
                modified['profiles']['apple-m6']['architectural_features'].remove('FEAT_CPA')
            elif change == 'tool_hash':
                modified['tool']['sha256'] = '0' * 64
            else:
                modified['profiles']['apple-m1']['stdout_sha256'] = '0' * 64
            if change == 'rehashed_feature':
                modified['facts_sha256'] = apple_isa.snapshot_hash(modified)
            with self.subTest(change=change), self.assertRaises(ValueError):
                apple_isa.load_snapshot(modified)

    def test_exported_features_are_not_expanded_or_hardware_claims(self):
        root = Path(__file__).resolve().parents[1]
        snapshot = apple_isa.load_snapshot(json.loads((root / 'tests/isa/apple-clang-features.json').read_bytes()))
        enabled = set(snapshot['profiles']['apple-m6']['architectural_features'])
        self.assertIn('FEAT_FP8', enabled)
        for absent in ('FEAT_SVE', 'FEAT_SVE2', 'FEAT_FP8FMA', 'FEAT_FP8DOT2', 'FEAT_FP8DOT4'):
            self.assertNotIn(absent, enabled)
        self.assertFalse(apple_isa.feature_expression('FEAT_FP8 && FEAT_FP8FMA', enabled))
        self.assertIn('FEAT_BTI', snapshot['profiles']['apple-m1']['architectural_features'])
        self.assertIn('not a hardware capability', snapshot['basis'])

    def test_predicate_precedence_and_unknown_operand_conditions(self):
        enabled = {'FEAT_SME', 'FEAT_SME_I16I64'}
        self.assertTrue(apple_isa.feature_expression('FEAT_SVE || FEAT_SME', enabled))
        self.assertFalse(apple_isa.feature_expression('FEAT_SVE && FEAT_SME', enabled))
        self.assertFalse(apple_isa.feature_expression('(FEAT_SVE || FEAT_SME) && FEAT_SVE_AES', enabled))
        self.assertTrue(apple_isa.feature_expression('!FEAT_SVE && FEAT_SME', enabled))
        self.assertTrue(apple_isa.feature_expression("sz == '0' || FEAT_SME_I16I64", enabled))
        self.assertIsNone(apple_isa.feature_expression("sz == '0' || FEAT_SME_F64F64", enabled))
        self.assertFalse(apple_isa.feature_expression("FEAT_SVE && (sz == '0')", enabled))
        for invalid in ('FEAT_SME ||', '(FEAT_SME', 'FEAT_SME garbage', '__import__("os")', '', 'FEAT_SME FEAT_SVE'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                apple_isa.feature_expression(invalid, enabled)

    def test_sme_does_not_admit_nonstreaming_sve_only_forms(self):
        enabled = {'FEAT_SME'}
        self.assertTrue(apple_isa.candidate({'features': []}, enabled))
        self.assertTrue(apple_isa.candidate({'features': [{'feature': 'FEAT_SVE || FEAT_SME'}]}, enabled))
        self.assertFalse(apple_isa.candidate({'features': [{'feature': 'FEAT_SVE'}]}, enabled))
        with self.assertRaises(ValueError):
            apple_isa.candidate({'features': [{'name': 'v8Ap0'}]}, enabled)

    def test_checked_in_inventory_is_pinned_and_explicitly_open(self):
        root = Path(__file__).resolve().parents[1]
        catalog = json.loads((root / 'tests/isa/a64-documented-checklist.json').read_bytes())
        inventory = json.loads((root / 'tests/isa/apple-codegen-profiles.json').read_bytes())
        assessed, _ = a64_checklist.assess(catalog, [])
        summaries = apple_isa.assess(inventory, assessed)
        self.assertEqual(summaries['union']['total'], 3231)
        self.assertEqual(summaries['union']['implemented'], 0)
        self.assertEqual({cpu: row['total'] for cpu, row in summaries.items() if cpu != 'union'}, apple_isa.EXPECTED_COUNTS)
        self.assertEqual(sum(row['membership_basis'] == 'untagged_reference_candidate' for row in inventory['forms']), 301)
        self.assertEqual(len(inventory['sve_mode_audit']['pages']), 757)
        self.assertEqual(inventory['pending_profiles'], [])
        self.assertFalse(inventory['inventory_complete'])
        for cpu, profile in inventory['profiles'].items():
            self.assertFalse(profile['general_nonstreaming_sve'])
            self.assertEqual(profile['streaming_sve'], cpu in ('apple-m4', 'apple-m5', 'apple-m6'))

        self.assertEqual(sum(row['conditional_nonstreaming_check'] for row in inventory['sve_mode_audit']['pages'].values()), 41)
        by_id = {row['id']: row for row in inventory['forms']}
        self.assertEqual(by_id['ADDPT_64_addsub_pt']['cpus'], ['apple-m6'])
        self.assertEqual(by_id['PACM_HI_hints']['cpus'], ['apple-m6'])
        self.assertEqual(by_id['movt_zt_z_']['cpus'], ['apple-m6'])
        self.assertEqual(by_id['bf1cvt_z_z8_b2bf']['sve_mode'], 'streaming_only_candidate')

        original = next(row for row in catalog['forms'] if row['id'] == 'ADCS_32_addsub_carry')
        review = {**original, 'source_sha256': catalog['source_files_sha256'][original['source_file']],
                  'profile': 'synthetic', 'scope': 'synthetic semantics', 'status': 'partial'}
        partial, _ = a64_checklist.assess(catalog, [{'forms': [review]}])
        self.assertEqual(apple_isa.assess(inventory, partial)['union']['implementation_percentage'], 0)
        implemented, _ = a64_checklist.assess(catalog, [{'forms': [{**review, 'status': 'implemented'}]}])
        self.assertEqual(apple_isa.assess(inventory, implemented)['union']['implementation_percentage'], 100 / 3231)
        for change in ('membership', 'rehashed_membership', 'closed_inventory', 'hardware_claim', 'source'):
            modified = copy.deepcopy(inventory)
            if change in ('membership', 'rehashed_membership'):
                next(row for row in modified['forms'] if row['id'] == original['id'])['cpus'].remove('apple-m1')
            elif change == 'closed_inventory':
                modified['inventory_complete'] = True
            elif change == 'hardware_claim':
                modified['hardware_membership_verified'] = True
            else:
                modified['compiler']['sha256'] = '0' * 64
            if change == 'rehashed_membership':
                modified['facts_sha256'] = apple_isa.inventory_hash(modified)
            with self.subTest(change=change), self.assertRaises(ValueError):
                apple_isa.assess(modified, assessed)


if __name__ == '__main__':
    unittest.main()
