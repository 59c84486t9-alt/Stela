"""Fixture/oracle/batching checks; native evidence is produced by the harness."""
import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('bitfield_differential',
                                             Path(__file__).with_name('bitfield-differential.py'))
bitfield = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bitfield)


class BitfieldOracleTests(unittest.TestCase):
    def test_exact_complete_canonical_pair_set_and_roles(self):
        wanted = bitfield.canonical_pairs()
        self.assertEqual(len(wanted), 15360)
        observed = {role: set() for role in bitfield.ROLES}
        functions = bitfield.exhaustive_functions()
        self.assertEqual(len(functions), 61440)
        for function in functions:
            observed[function['role']].add(tuple(function['operations'][0][:3]))
        self.assertTrue(all(pairs == wanted for pairs in observed.values()))

    def test_encoding_fields_and_width_invariants(self):
        for form, rotation, last in bitfield.canonical_pairs():
            word = bitfield.encoding(form, rotation, last, 30, 7)
            self.assertEqual((word >> 16) & 63, rotation)
            self.assertEqual((word >> 10) & 63, last)
            self.assertEqual(word & 31, 30)
            self.assertEqual((word >> 5) & 31, 7)
            self.assertEqual((word >> 31) & 1, (word >> 22) & 1)
        with self.assertRaises(ValueError):
            bitfield.encoding('UBFM32', 32, 0, 0, 1)

    def test_unsigned_extract_and_wrapped_insert(self):
        self.assertEqual(bitfield.bit_reference(('UBFM64', 4, 7, 0, 1), 0xabc, 0xffff), 0xb)
        self.assertEqual(bitfield.bit_reference(('UBFM64', 56, 7, 0, 1), 0xabcd, 0xffff), 0xcd00)

    def test_signed_extract_and_wrapped_sign_fill(self):
        self.assertEqual(bitfield.bit_reference(('SBFM64', 8, 15, 0, 1), 0x8000, 0),
                         0xffffffffffffff80)
        self.assertEqual(bitfield.bit_reference(('SBFM64', 60, 3, 0, 1), 8, 0),
                         0xffffffffffffff80)
        self.assertEqual(bitfield.bit_reference(('SBFM64', 60, 3, 0, 1), 7, 0), 0x70)

    def test_bfm_preserves_both_sides_of_wrapped_field(self):
        self.assertEqual(bitfield.bit_reference(('BFM32', 28, 3, 0, 1), 0xa,
                                               0xdeadbeef00001234), 0x12a4)
        self.assertEqual(bitfield.bit_reference(('BFM32', 4, 7, 0, 1), 0xa0,
                                               0x12345678), 0x1234567a)

    def test_w_signed_write_zero_extends_and_preserves_other_fields(self):
        state = bitfield.initial_states()[15]
        state.x[1] = 0xdeadbeef00000080
        expected = bitfield.mathematical_reference([('SBFM32', 0, 7, 0, 1)], state)
        self.assertEqual(expected.x[0], 0xffffff80)
        self.assertEqual(list(expected.x)[1:], list(state.x)[1:])
        self.assertEqual((expected.sp, expected.nzcv, expected.reserved),
                         (state.sp, state.nzcv, state.reserved))

    def test_source_destination_alias_reads_original_both_operands(self):
        state = bitfield.initial_states()[0]
        state.x[7] = 0xdeadbeef12345678
        expected = bitfield.mathematical_reference([('BFM32', 28, 3, 7, 7)], state)
        self.assertEqual(expected.x[7], 0x12345688)

    def test_zero_source_preserves_only_bfm_non_field_bits(self):
        state = bitfield.initial_states()[0]
        state.x[0] = 0x12345678
        expected = bitfield.mathematical_reference([('BFM32', 4, 7, 0, 31)], state)
        self.assertEqual(expected.x[0], 0x12345670)
        expected = bitfield.mathematical_reference([('SBFM64', 3, 7, 0, 31)], state)
        self.assertEqual(expected.x[0], 0)

    def test_discard_destination_preserves_all_modeled_state(self):
        state = bitfield.initial_states()[5]
        self.assertEqual(bytes(bitfield.mathematical_reference([('BFM32', 28, 3, 31, 7)], state)),
                         bytes(state))

    def test_dirty_w_aliases_and_all_sixteen_flags(self):
        for index, template in enumerate(bitfield.initial_states()):
            for role, (destination, source) in bitfield.ROLES.items():
                ops = [('UBFM32', 13, 7, destination, source)]
                state = bitfield.input_state(template, ops, index)
                self.assertEqual(state.nzcv, index << 28)
                for register in (source, destination):
                    if register != 31:
                        self.assertNotEqual(state.x[register] >> 32, 0, role)

    def test_batches_contain_independent_mapped_ret_boundaries(self):
        functions = bitfield.exhaustive_functions()[:37]
        source, entries = bitfield.raw_source(functions)
        words = struct.unpack('<' + 'I' * (len(source) // 4), source)
        self.assertEqual(entries, list(range(0, 74, 2)))
        self.assertTrue(all(words[entry + 1] == bitfield.RET for entry in entries))

    def test_supplementary_register_sweep_chains_and_bounded_blocks(self):
        functions = bitfield.supplementary_functions()
        self.assertEqual(len(functions), 272)
        for form in bitfield.FORMS:
            sweep = [case['operations'][0] for case in functions if case['kind'] == 'all_registers'
                     and case['operations'][0][0] == form]
            self.assertEqual({op[3] for op in sweep}, set(range(32)))
            self.assertEqual({op[4] for op in sweep}, set(range(32)))
        self.assertEqual(len(bitfield.block_functions()), 36)
        self.assertTrue(all(len(case['operations']) + 1 <= 256 for case in bitfield.block_functions()))

    def test_reserved_fields_are_genuinely_invalid(self):
        self.assertEqual(len(bitfield.invalid_words()), 14)
        for word in bitfield.invalid_words():
            sf, n, opc = word >> 31, (word >> 22) & 1, (word >> 29) & 3
            rotation, last = (word >> 16) & 63, (word >> 10) & 63
            self.assertTrue(sf != n or opc == 3 or (sf == 0 and (rotation >= 32 or last >= 32)))

    def test_manifest_binds_every_instruction_and_rejects_prefix_or_duplicate_map(self):
        source = struct.pack('<II', bitfield.encoding('UBFM64', 4, 7, 0, 1), bitfield.RET)
        native = b'\x90\xc3'
        manifest = {'schema_version': 1, 'kind': 'raw_arm64_leaf_aot', 'abi': bitfield.LEAF_ABI,
                    'guest_base': bitfield.BASE, 'source_sha256': bitfield.digest(source),
                    'native_sha256': bitfield.digest(native), 'native_bytes': 2, 'verified': False,
                    'guest_instructions': 2, 'source_map': [[bitfield.BASE, 0], [bitfield.BASE + 4, 1]]}
        self.assertEqual(bitfield.validate_manifest(manifest, source, native, False), [0, 1])
        manifest['source_map'][1][1] = 0
        with self.assertRaises(AssertionError):
            bitfield.validate_manifest(manifest, source, native, False)
        manifest['source_map'] = [[bitfield.BASE, 0]]
        with self.assertRaises(AssertionError):
            bitfield.validate_manifest(manifest, source, native, False)


if __name__ == '__main__':
    unittest.main()
