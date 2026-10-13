"""Pure independent-model and receipt guards; no Stela/native execution."""
import copy
import importlib
import unittest
from collections import Counter

from differential import State, state_dict

suite = importlib.import_module('pauth-differential')


class PauthGuards(unittest.TestCase):
    def test_nibble_transforms_have_required_inverse_and_mix_involution(self):
        for word in [0, suite.MASK, 0x0123456789abcdef, 0xfedcba9876543210, 1 << 63]:
            self.assertEqual(suite.shuffle(suite.shuffle(word), True), word)
            self.assertEqual(suite.tweak(suite.tweak(word), True), word)
            self.assertEqual(suite.substitute(suite.substitute(word), True), word)
            self.assertEqual(suite.mix(suite.mix(word)), word)

    def test_full64_asl_math_fixtures_and_original_upper32_are_distinct_proofs(self):
        # Full64 comes from independent June2026 nibble-ASL math. Original PACGA
        # independently observes only each result's upper32, never its low half.
        vectors = [(0, 0, 0xf98eebd04f80fec6),
                   (0x3c810c2558894393, 0x33a14317477358e7, 0x7cec813deab63a55),
                   (0xdb75f319b483fcd5, 0xdd1af32ab32cfb22, 0x0a5f20d0d7776814),
                   (0x2524e003c1432543, 0xcfe77676c7b84f90, 0xdb69675548508432)]
        for data, modifier, expected in vectors:
            self.assertEqual(suite.qarma5(data, modifier, *suite.KEY), expected)

    def test_enabled_original_ib_signature_null_and_poison_facts(self):
        self.assertEqual(suite.sign_ib(0x1400, 0x2000), 0xce76000000001400)
        self.assertEqual(suite.sign_ib(0, 0), 0xf90e800000000000)
        self.assertEqual(suite.authenticate_ib(0xce76000000001400, 0x2000), (0x1400, True))
        for signed, modifier, key in [(0xce76000000001400, 0x2010, suite.KEY),
                                      (0xce76000000001400 ^ (1 << 63), 0x2000, suite.KEY),
                                      (0xce76000000001400, 0x2000, (suite.KEY[0] ^ 1, suite.KEY[1]))]:
            pointer, valid = suite.authenticate_ib(signed, modifier, key)
            self.assertFalse(valid)
            self.assertEqual(pointer >> 61 & 3, 2)

    def test_case_grid_covers_flags_keys_forms_and_all_sixteen_pac_bits(self):
        cases = list(suite.cases())
        self.assertEqual(len(cases), 3200)
        self.assertEqual(Counter(c['operation'] for c in cases), {'pacibsp': 1088, 'autibsp': 1472, 'retab': 640})
        for operation in suite.WORDS:
            self.assertEqual({c['flag'] for c in cases if c['operation'] == operation}, set(range(16)))
        self.assertEqual({int(c['name'].split('-')[-1]) for c in cases if c['name'].startswith('pac-bit-')},
                         set(range(47, 55)) | set(range(56, 64)))
        self.assertEqual({c['key'] for c in cases if c['name'] == 'canonical-sign'},
                         {suite.KEY, (0, 0), (suite.MASK, suite.MASK), (1, 2)})

    def test_math_preserves_full_state_prefix_and_retab_signed_lr(self):
        initial = suite.initial_state(suite.sign_ib(suite.STOP, 0x2000), 0x2000, 15)
        expected, pc, valid = suite.math_state('retab', initial)
        self.assertTrue(valid)
        self.assertEqual(pc, suite.STOP)
        self.assertEqual(expected.x[30], initial.x[30])
        preserved = State.from_buffer_copy(initial)
        preserved.x[7] = 42
        self.assertEqual(bytes(expected), bytes(preserved))
        expected, _, valid = suite.math_state('autibsp', initial, (1, 2))
        self.assertFalse(valid)
        self.assertEqual(bytes(expected)[248:], bytes(preserved)[248:])

    def test_legacy_noncanonical_classifier_rejects_any_extra_state_or_pc_change(self):
        initial = suite.initial_state(1 << 47, 0x2000, 0)
        expected, pc, _ = suite.math_state('pacibsp', initial)
        observed = State.from_buffer_copy(expected)
        observed.x[30] ^= (1 << 62) | (1 << 63)
        self.assertEqual(suite.validate_original('pacibsp', initial, expected, pc, observed, pc),
                         'invalid_extension_legacy_unicorn_observation')
        for index in [7, 30]:
            changed = State.from_buffer_copy(observed)
            changed.x[index] ^= 1
            with self.assertRaises(AssertionError):
                suite.validate_original('pacibsp', initial, expected, pc, changed, pc)
        changed = State.from_buffer_copy(observed)
        changed.v[31][1] ^= 1
        with self.assertRaises(AssertionError):
            suite.validate_original('pacibsp', initial, expected, pc, changed, pc)
        with self.assertRaises(AssertionError):
            suite.validate_original('pacibsp', initial, expected, pc, observed, pc + 4)

    def test_native_receipt_requires_helper_profile_full_state_and_actual_auth_result(self):
        initial = suite.initial_state(suite.STOP, 0x2000, 15)
        expected, pc, authenticated = suite.math_state('pacibsp', initial)
        descriptor = {'operation': 'sign_ib_sp', 'instruction_pc': suite.BASE + 4, 'next_pc': suite.BASE + 8}
        report = {'kind': 'native_block_run', 'abi': suite.ABI, 'software_pauth_profile': suite.PROFILE,
                  'complete_binary_verified': False, 'source_sha256': 'source', 'guest_base': suite.BASE,
                  'state': state_dict(expected), 'pc': pc,
                  'outcome': {'reason': {'kind': 'stop_address'}, 'blocks_executed': 1,
                              'last_exit': [suite.BASE + 4, 6], 'compiled_blocks': 1, 'disk_cache_hits': 0,
                              'memory_cache_hits': 0, 'pointer_authentication_events': [
                                  {'instruction': descriptor, 'next_pc': pc, 'authenticated': authenticated}]}}
        suite.validate_native(report, 'pacibsp', expected, pc, authenticated, 'source', True)
        for field, value in [('abi', 'ordinary'), ('pc', pc + 4), ('software_pauth_profile', None),
                             ('source_sha256', 'other'), ('complete_binary_verified', True)]:
            changed = copy.deepcopy(report)
            changed[field] = value
            with self.assertRaises(AssertionError):
                suite.validate_native(changed, 'pacibsp', expected, pc, authenticated, 'source', True)
        changed = copy.deepcopy(report)
        changed['state']['v'][31][1] ^= 1
        with self.assertRaises(AssertionError):
            suite.validate_native(changed, 'pacibsp', expected, pc, authenticated, 'source', True)
        changed = copy.deepcopy(report)
        changed['outcome']['pointer_authentication_events'][0]['authenticated'] = True
        with self.assertRaises(AssertionError):
            suite.validate_native(changed, 'pacibsp', expected, pc, authenticated, 'source', True)


if __name__ == '__main__':
    unittest.main()
