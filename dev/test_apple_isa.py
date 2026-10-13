"""Apple profile inventory/parser checks without private inputs or native execution."""
import copy
import json
from pathlib import Path
import unittest

import a64_checklist
import apple_isa


class AppleIsaTests(unittest.TestCase):
    def test_comments_strings_and_nested_arguments(self):
        text = '/* ignored */ def X : Extension<"a//b", "X", "FEAT_X", "comma, <angle>", [FeatureY]>; // ignored'
        stripped = apple_isa.without_comments(text)
        self.assertIn('"a//b"', stripped)
        self.assertNotIn('ignored', stripped)
        args = apple_isa.balanced_arguments(stripped, stripped.index('<'))
        self.assertEqual(args, ['"a//b"', '"X"', '"FEAT_X"', '"comma, <angle>"', '[FeatureY]'])
        self.assertEqual(apple_isa.split_arguments('[FeatureA, FeatureB], !listconcat([FeatureC], [FeatureD]), "x,y"'),
                         ['[FeatureA, FeatureB]', '!listconcat([FeatureC], [FeatureD])', '"x,y"'])
        for bad in ('<"unterminated>', '<FeatureA', '<[FeatureA)>'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                apple_isa.balanced_arguments(bad, 0)

    def test_architecture_defaults_are_not_implied_cpu_features(self):
        definitions = apple_isa.feature_definitions('''
            def FeatureBase : Extension<"base", "Base", "FEAT_Base, FEAT_Base2", "base">;
            def FeatureOptional : Extension<"optional", "Optional", "FEAT_Optional", "optional">;
            def HasV8_0aOps : Architecture64<8, 0, "a", "v8a", [FeatureBase], [FeatureOptional]>;
        ''')
        features, architectural = apple_isa.feature_closure(definitions, ['HasV8_0aOps'])
        self.assertEqual(features, {'HasV8_0aOps', 'FeatureBase'})
        self.assertEqual(architectural, {'FEAT_Base', 'FEAT_Base2'})
        with self.assertRaises(ValueError):
            apple_isa.literal_features('!listconcat([FeatureBase], [FeatureOptional])')

    def test_unknown_or_cyclic_features_fail_closed(self):
        with self.assertRaises(ValueError):
            apple_isa.feature_closure({}, ['FeatureMissing'])
        definitions = {'FeatureA': {'dependencies': ['FeatureB'], 'architectural': []},
                       'FeatureB': {'dependencies': ['FeatureA'], 'architectural': []}}
        with self.assertRaises(ValueError):
            apple_isa.feature_closure(definitions, ['FeatureA'])

    def test_cpu_aliases_use_literal_apple_model_roots(self):
        source = '''
          list<SubtargetFeature> AppleCPU = [HasV8_0aOps, FeatureBase];
          def : ProcessorModel<"apple-a14", Tune, ProcessorFeatures.AppleCPU, []>;
          def : ProcessorAlias<"apple-m1", "apple-a14">;
        '''
        self.assertEqual(apple_isa.cpu_roots(source, 'apple-m1'),
                         ('AppleCPU', ['HasV8_0aOps', 'FeatureBase']))
        with self.assertRaises(ValueError):
            apple_isa.cpu_roots(source, 'apple-m6')
        with self.assertRaises(ValueError):
            apple_isa.cpu_roots('def : ProcessorAlias<"a", "b">; def : ProcessorAlias<"b", "a">;', 'a')

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
        self.assertEqual(summaries['union']['total'], 3119)
        self.assertEqual(summaries['union']['implemented'], 0)
        self.assertEqual({cpu: row['total'] for cpu, row in summaries.items() if cpu != 'union'}, apple_isa.EXPECTED_COUNTS)
        self.assertEqual(sum(row['membership_basis'] == 'untagged_reference_candidate' for row in inventory['forms']), 301)
        self.assertEqual(len(inventory['sve_mode_audit']['pages']), 745)
        self.assertEqual(inventory['pending_profiles'], ['apple-m6'])
        self.assertFalse(inventory['inventory_complete'])
        for cpu, profile in inventory['profiles'].items():
            self.assertFalse(profile['general_nonstreaming_sve'])
            self.assertEqual(profile['streaming_sve'], cpu in ('apple-m4', 'apple-m5'))

        original = next(row for row in catalog['forms'] if row['id'] == 'ADCS_32_addsub_carry')
        review = {**original, 'source_sha256': catalog['source_files_sha256'][original['source_file']],
                  'profile': 'synthetic', 'scope': 'synthetic semantics', 'status': 'partial'}
        partial, _ = a64_checklist.assess(catalog, [{'forms': [review]}])
        self.assertEqual(apple_isa.assess(inventory, partial)['union']['implementation_percentage'], 0)
        implemented, _ = a64_checklist.assess(catalog, [{'forms': [{**review, 'status': 'implemented'}]}])
        self.assertEqual(apple_isa.assess(inventory, implemented)['union']['implementation_percentage'], 100 / 3119)
        for change in ('membership', 'rehashed_membership', 'closed_inventory', 'hardware_claim', 'source'):
            modified = copy.deepcopy(inventory)
            if change in ('membership', 'rehashed_membership'):
                next(row for row in modified['forms'] if row['id'] == original['id'])['cpus'].remove('apple-m1')
            elif change == 'closed_inventory':
                modified['inventory_complete'] = True
            elif change == 'hardware_claim':
                modified['hardware_membership_verified'] = True
            else:
                modified['llvm_commit'] = '0' * 40
            if change == 'rehashed_membership':
                modified['facts_sha256'] = apple_isa.inventory_hash(modified)
            with self.subTest(change=change), self.assertRaises(ValueError):
                apple_isa.assess(modified, assessed)


if __name__ == '__main__':
    unittest.main()
