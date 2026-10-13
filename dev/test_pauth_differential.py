"""Pure independent-model and receipt guards; no Stela/native execution."""
import copy
import importlib
import unittest
from collections import Counter
from unittest.mock import patch

from differential import State, state_dict

suite = importlib.import_module('pauth-differential')


class PauthGuards(unittest.TestCase):
    def test_branch_grid_and_math_cover_sources_aliases_zero_sp_and_poisoned_link(self):
        rows = list(suite.branch_cases())
        forms = {(r['key'], r['link'], r['modifier'] == 'zero') for r in rows}
        self.assertEqual(len(forms), 8)
        self.assertEqual({r['target'] for r in rows}, set(range(32)))
        self.assertEqual({r['modifier'] for r in rows if isinstance(r['modifier'], int)}, set(range(31)))
        self.assertEqual({r['flag'] for r in rows}, set(range(16)))
        for link in (False, True):
            for key in ('ia', 'ib'):
                for target, modifier in [(0, 1), (30, 1), (0, 30), (30, 'sp')]:
                    for failed in (False, True):
                        initial = suite.initial_state(suite.STOP, 0x2000, 123)
                        value = initial.sp if modifier == 'sp' else initial.x[modifier]
                        initial.x[target] = suite.domain_sign(suite.STOP, value, key) ^ ((1 << 47) if failed else 0)
                        case = {'link': link, 'key': key, 'target': target, 'modifier': modifier}
                        expected, pc, valid = suite.branch_math(case, initial)
                        self.assertEqual(valid, not failed)
                        self.assertEqual(pc, suite.STOP if valid else suite.STOP | ((1 if key == 'ia' else 2) << 61))
                        before = State.from_buffer_copy(initial)
                        if link:
                            before.x[30] = suite.BASE + 4
                        self.assertEqual(bytes(expected), bytes(before))

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

    def test_clock_page_has_only_declared_consistent_fields(self):
        page = suite.clock_page(1234)
        self.assertEqual(len(page), 16384)
        import struct
        self.assertEqual(struct.unpack_from('<Q', page, 0x88)[0], (-1234) & suite.MASK)
        self.assertEqual(page[0x90:0x92], b'\x01\x01')
        self.assertEqual(struct.unpack_from('<Q', page, 0x98)[0], 1234)
        self.assertEqual(struct.unpack_from('<Q', page, 0xa8)[0], 0)
        self.assertEqual(page[:0x88], bytes(0x88))
        self.assertEqual(page[0xb0:], bytes(len(page) - 0xb0))

    def test_counter_destinations_include_x7_prefix_alias_and_xzr_discard(self):
        initial = suite.initial_state(suite.MASK, 0x220004000008, 15)
        for destination in range(32):
            expected = State.from_buffer_copy(initial)
            expected.x[7] = 42
            if destination != 31:
                expected.x[destination] = 1234567
            observed = suite.clock_instruction_math(initial, destination, 1234567)
            self.assertEqual(bytes(observed), bytes(expected))
            self.assertEqual(bytes(observed)[248:], bytes(initial)[248:])

    def test_complete_bootstrap_math_restores_frame_and_preserves_unwritten_ram(self):
        initial = suite.initial_state(0, 0x8f78, 15)
        initial.x[3] = 0
        before = bytes([0xa5]) * 4096
        state, stack, writes = suite.bootstrap_math(initial, before, 0x8000, 0x40000000000, 1234567)
        self.assertEqual((state.sp, state.x[29]), ((initial.sp & ~15) - 0x680, (initial.sp & ~15) - 0x10))
        self.assertEqual((state.x[0], state.x[8], state.x[9], state.nzcv), (1234567, 1234567, 0, 0x80000000))
        self.assertEqual((state.x[19], state.x[20]), (0, initial.x[20]))
        self.assertEqual(bytes(state)[260:], bytes(initial)[260:])
        target, valid = suite.authenticate_ib(state.x[30], state.sp)
        self.assertTrue(valid)
        self.assertEqual(target, 0x400000304a4)
        touched = {address - 0x8000 for event in writes for address in range(event['address'], event['address'] + event['bytes'])}
        self.assertEqual(len(writes), 9)
        self.assertEqual(len(touched), 136)
        self.assertTrue(all(stack[index] == before[index] for index in range(len(stack)) if index not in touched))

    def test_clock_probe_rejects_missing_or_altered_ram_page_snapshot_and_full_state(self):
        # The existing shared raw-input auditor is tested separately. Isolate
        # the new clock/full-RAM contract here using independent synthetic input.
        initial = suite.initial_state(0, 0x8f78, 15)
        initial.x[3] = 0
        slide, counter, sleep = 0x40000000000, 1234567, 1234
        expected, stack, _ = suite.bootstrap_math(initial, bytes(4096), 0x8000, slide, counter)
        image_effect = {'address': 0x600000, 'bytes': 4096, 'initial_sha256': 'image', 'final_sha256': 'image'}
        oracle = {'initial': state_dict(initial), 'state': state_dict(expected), 'counter': counter, 'sleep_ticks': sleep,
                  'stack_before_hex': bytes(4096).hex(), 'stack_after_hex': stack.hex(), 'memory_effects': [image_effect]}
        def pa(operation, pc, following, actual, authenticated):
            return {'instruction': {'operation': operation, 'instruction_pc': slide + pc, 'next_pc': slide + following},
                    'next_pc': slide + actual, 'authenticated': authenticated}
        snapshot = {'counter': counter, 'sleep_ticks': sleep}
        report = {'bootstrap_clock': True, 'abi': suite.CLOCK_ABI, 'software_pauth_profile': suite.PROFILE,
                  'pauth_instruction_executed': True, 'dyld': {'slide': slide}, 'entry_pc': slide + 0x4bf0,
                  'pc': slide + 0x304a4, 'stop_pc': slide + 0x304a4, 'target_pc': slide + 0x30460,
                  'original_prefix_words': [0x910003e0, 0x927cec1f, 0xd280001d, 0xd280001e, 0x1400ae18],
                  'target_analysis_profile': 'ordinary', 'target_analysis': {'supported': False},
                  'selected_profile_target_analysis': {'supported': True}, 'stack': {'base': 0x8000},
                  'state': state_dict(expected), 'stack_before_hex': bytes(4096).hex(), 'stack_after_hex': stack.hex(),
                  'memory_effects': [image_effect, {'address': 0x8000, 'bytes': 4096,
                      'initial_sha256': suite.digest(bytes(4096)), 'final_sha256': suite.digest(stack)}],
                  'mapped_regions': [{'guest_address': address, 'virtual_bytes': 4096, 'readable': True}
                                     for address in (0x600000, 0x8000)],
                  'clock': {'profile_id': suite.CLOCK_PROFILE, 'frequency': 1000000000,
                      'source_id': 'explicit-finite-replay-v1', 'snapshot': snapshot,
                      'region': {'guest_address': suite.CLOCK_BASE, 'virtual_bytes': 16384,
                                 'readable': True, 'writable': False, 'executable': False},
                      'events': [{'sequence': index, 'snapshot': snapshot} for index in (0, 1)],
                      'page_before_hex': suite.clock_page(sleep).hex(), 'page_after_hex': suite.clock_page(sleep).hex()},
                  'outcome': {'reason': {'kind': 'stop_address'}, 'blocks_executed': 11,
                      'last_exit': [slide + 0x805f0, 6], 'memory_cache_hits': 0,
                      'pointer_authentication_events': [pa('sign_ib_sp', 0x30460, 0x30464, 0x30464, None),
                          pa('sign_ib_sp', 0x8054c, 0x80550, 0x80550, None), pa('return_ib_sp', 0x805f0, 0x805f4, 0x304a4, True)],
                      'clock_events': [
                          {'instruction': {'operation': {'kind': 'instruction_synchronization'}, 'instruction_pc': slide + 0x805d4, 'next_pc': slide + 0x805d8}, 'next_pc': slide + 0x805d8, 'counter': None},
                          {'instruction': {'operation': {'kind': 'read_virtual_counter', 'destination': 8}, 'instruction_pc': slide + 0x805d8, 'next_pc': slide + 0x805dc}, 'next_pc': slide + 0x805dc, 'counter': counter}]}}
        shared = suite.importlib.import_module('dyld-entry-differential')
        with patch.object(shared, 'audit_process_input', return_value=initial):
            suite.audit_clock_probe(report, oracle, {}, None, {}, 'compiler', True)
            mutations = []
            changed = copy.deepcopy(report)
            changed['memory_effects'] = []
            mutations.append(changed)
            changed = copy.deepcopy(report)
            changed['memory_effects'][0]['final_sha256'] = 'other'
            mutations.append(changed)
            changed = copy.deepcopy(report)
            damaged = bytearray.fromhex(changed['clock']['page_after_hex'])
            damaged[0x91] = 0
            changed['clock']['page_after_hex'] = damaged.hex()
            mutations.append(changed)
            changed = copy.deepcopy(report)
            changed['clock']['snapshot'] = {'counter': counter + 1, 'sleep_ticks': sleep}
            mutations.append(changed)
            changed = copy.deepcopy(report)
            changed['state']['v'][31][1] ^= 1
            mutations.append(changed)
            changed = copy.deepcopy(report)
            changed['stack_after_hex'] = '01' + changed['stack_after_hex'][2:]
            mutations.append(changed)
            changed = copy.deepcopy(report)
            changed['outcome']['clock_events'][1]['counter'] += 1
            mutations.append(changed)
            for changed in mutations:
                with self.assertRaises(AssertionError):
                    suite.audit_clock_probe(changed, oracle, {}, None, {}, 'compiler', True)

    def test_generic_domains_preserve_data_tags_strip_and_key_specific_poison(self):
        for key in suite.DOMAIN_KEYS:
            data = key[0] == 'd'
            for pointer in (0, suite.STOP, suite.LOW, 0xffffffffffffffff, 0x8000000000001400):
                if not suite.domain_invalid_extension(pointer, key):
                    signed = suite.domain_sign(pointer, 0x2000, key)
                    self.assertEqual(suite.domain_authenticate(signed, 0x2000, key), (pointer, True))
                    self.assertEqual(suite.domain_strip(signed, data), pointer)
                    if data:
                        self.assertEqual(signed & suite.HIGH8, pointer & suite.HIGH8)
            signed = suite.domain_sign(suite.STOP, 0x2000, key)
            poisoned, valid = suite.domain_authenticate(signed ^ (1 << 47), 0x2000, key)
            self.assertFalse(valid)
            self.assertEqual((poisoned >> (53 if data else 61)) & 3, 1 if key[1] == 'a' else 2)

    def test_generic_grid_covers33_forms_all_flags_all_variable_destinations_aliases(self):
        cases = list(suite.generic_cases())
        self.assertEqual(len(cases), 2944)
        self.assertEqual(len(suite.basic_forms()), 33)
        for form in suite.basic_forms():
            selected = [case for case in cases if case['name'] == form['name']]
            self.assertEqual({c['flag'] for c in selected}, set(range(16)))
            if form['variable']:
                self.assertEqual({c['destination'] for c in selected}, set(range(32)))
            if form['variable'] and isinstance(form['modifier'], int):
                self.assertEqual({c['destination'] for c in selected if c['role'] == 'aliased_modifier'}, set(range(32)))

    def test_data_noncanonical_classifier_declines_any_additional_corruption(self):
        initial = suite.initial_state(0, 0x2000, 15)
        initial.x[0] = 1 << 47
        expected = suite.State.from_buffer_copy(initial)
        expected.x[0] = suite.domain_sign(initial.x[0], 0x2000, 'da')
        observed = suite.State.from_buffer_copy(expected)
        observed.x[0] ^= 1 << 54
        self.assertEqual(suite.classify_domain_original(expected, observed, 4, 4, 'sign', 'da', 0, initial.x[0]),
                         'invalid_extension_legacy_unicorn_observation')
        changed = suite.State.from_buffer_copy(observed)
        changed.v[31][1] ^= 1
        with self.assertRaises(AssertionError):
            suite.classify_domain_original(expected, changed, 4, 4, 'sign', 'da', 0, initial.x[0])
        with self.assertRaises(AssertionError):
            suite.classify_domain_original(expected, observed, 4, 8, 'sign', 'da', 0, initial.x[0])

    def test_signer_null_and_blended_modifier_have_exact_register_and_flag_effects(self):
        initial = suite.initial_state(0, 0x2000, 15)
        initial.x[0], initial.x[1], initial.x[2] = suite.METADATA_BASE, 0, 0x123456789abc
        expected = suite.signer_math(initial, 0xffff, 'da', True)
        preserved = suite.State.from_buffer_copy(initial); preserved.x[0] = 0
        self.assertEqual(bytes(expected), bytes(preserved))
        initial.x[1] = suite.STOP
        expected = suite.signer_math(initial, 0xabcd, 'da', True)
        self.assertEqual(expected.x[16], 0xabcd123456789abc)
        self.assertEqual(expected.x[2], expected.x[16])
        self.assertEqual(expected.x[0], suite.domain_sign(suite.STOP, expected.x[16], 'da'))
        self.assertEqual(expected.nzcv, 0x60000000)
        self.assertEqual(bytes(expected)[264:], bytes(initial)[264:])

    def test_signer_receipt_rejects_missing_memory_hash_read_or_fullstate(self):
        state = suite.initial_state(0, 0x2000, 15)
        source, memory = b'original', bytes(4096)
        receipt = [{'address': suite.METADATA_BASE, 'bytes': 4096, 'sha256': suite.digest(memory)}]
        report = {'state': state_dict(state), 'pc': suite.STOP, 'outcome': {'reason': {'kind': 'stop_address'}},
                  'abi': suite.ABI, 'complete_binary_verified': False, 'software_pauth_profile': suite.FULL_PROFILE,
                  'source_sha256': suite.digest(source), 'memory': {'memory_before': receipt, 'memory_after': receipt,
                  'memory_reads': [{'address': suite.METADATA_BASE, 'bytes': 4096, 'hex': memory.hex()}]}}
        suite.validate_signer_native(report, state, source, memory, 0)
        for field in ('memory_before', 'memory_after', 'memory_reads'):
            changed = copy.deepcopy(report); changed['memory'][field] = []
            with self.assertRaises(AssertionError):
                suite.validate_signer_native(changed, state, source, memory, 0)
        changed = copy.deepcopy(report); changed['state']['fpsr'] ^= 1
        with self.assertRaises(AssertionError):
            suite.validate_signer_native(changed, state, source, memory, 0)


if __name__ == '__main__':
    unittest.main()
