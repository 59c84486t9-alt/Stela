"""Independent genuine chained binds, provider identity and cross-image reference."""
import importlib
from pathlib import Path
import platform
import struct
import tempfile
import unittest

bound = importlib.import_module('bound-image-differential')


class ExportFramingTests(unittest.TestCase):
    def test_retained_pair_survives_source_cleanup_and_preserves_previous_pairs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = [b'original main', b'original dylib']
            first = bound.retain_fixtures(root, original)
            self.assertEqual(first, bound.retain_fixtures(root, original))
            second = bound.retain_fixtures(root, [b'updated main', original[1]])
            self.assertNotEqual(first['directory'], second['directory'])
            self.assertEqual([Path(first[key]).read_bytes() for key in ('main', 'library')], original)
            Path(first['library']).write_bytes(b'corrupted')
            with self.assertRaisesRegex(AssertionError, 'retained fixture identity mismatch'):
                bound.retain_fixtures(root, original)

    def test_uleb_overflow_and_truncation_are_declined(self):
        for data in (b'\x80', b'\xff' * 10 + b'\x00'):
            with self.assertRaises(AssertionError):
                bound.uleb(data, 0, len(data))


@unittest.skipUnless(platform.system() == 'Darwin', 'genuine Apple linker fixture construction')
class BoundFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='bound-fixture-test-')
        cls.paths, cls.infos, cls.provenance = bound.build_fixtures(Path(cls.temporary.name))
        cls.inputs = [path.read_bytes() for path in cls.paths]
        cls.exports = bound.exports(cls.inputs[1], cls.infos[1])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_genuine_imports_and_export_trie_match_symbols(self):
        self.assertEqual(self.infos[1]['kind'], 6)
        self.assertEqual(self.infos[1]['install_name'], bound.INSTALL_NAME)
        self.assertEqual(set(self.exports), {'_bound_function', '_bound_seed'})
        for name, item in self.exports.items():
            self.assertEqual(item['value'], self.infos[1]['symbols'][name])
        for bases in bound.PLACEMENTS:
            decoded = bound.decode_fixups(self.inputs[0], self.infos[0], bases[0])
            self.assertEqual([item['library_ordinal'] for item in decoded['imports']], [1, 1])
            self.assertEqual([item['import_index'] for item in decoded['binds']], [1, 0])
            bindings = bound.resolve_bindings(self.infos[0], self.infos[1], decoded, self.exports, bases[1])
            self.assertEqual([item['value'] for item in bindings],
                             [bases[1] + self.infos[1]['symbols'][name] for name in ('_bound_function', '_bound_seed')])

    def test_all_original_cross_image_states_match_symbol_oracle(self):
        for bases in bound.PLACEMENTS:
            decoded = [bound.decode_fixups(data, info, base) for data, info, base in zip(self.inputs, self.infos, bases)]
            bindings = bound.resolve_bindings(self.infos[0], self.infos[1], decoded[0], self.exports, bases[1])
            for initial in bound.states(all_flags=True):
                initial.sp, initial.x[30], initial.reserved = bound.STACK_TOP, bound.STOP, 0xa5c39e71
                state, pc, memory, trace = bound.original(self.inputs, self.infos, initial, bases, decoded, bindings)
                self.assertEqual((state, pc, memory), bound.fixture_oracle(self.inputs, self.infos, initial, bases))
                self.assertEqual(len(trace), 21)
                self.assertEqual(state['x'][29], initial.x[29])
                self.assertEqual(state['sp'], initial.sp)

    def test_missing_export_does_not_fall_back_to_symbol_table(self):
        case = next(case for case in bound.declined_inputs(self.inputs, self.infos)
                    if case['name'] == 'missing_trie_export_with_original_symtab')
        info = bound.parse_image(case['library'])
        self.assertIn('_bound_function', info['symbols'])
        exported = bound.exports(case['library'], info)
        self.assertNotIn('_bound_function', exported)
        decoded = bound.decode_fixups(self.inputs[0], self.infos[0], bound.PLACEMENTS[0][0])
        with self.assertRaisesRegex(AssertionError, 'missing export'):
            bound.resolve_bindings(self.infos[0], info, decoded, exported, bound.PLACEMENTS[0][1])

    def test_wrong_positive_ordinal_cannot_resolve_same_named_other_provider(self):
        case = next(case for case in bound.declined_inputs(self.inputs, self.infos)
                    if case['name'] == 'wrong_positive_library_ordinal')
        decoded = bound.decode_fixups(case['main'], self.infos[0], bound.PLACEMENTS[0][0])
        with self.assertRaisesRegex(AssertionError, 'declared provider'):
            bound.resolve_bindings(self.infos[0], self.infos[1], decoded, self.exports, bound.PLACEMENTS[0][1])

    def test_reexport_is_valid_terminal_but_outside_reference_profile(self):
        case = next(case for case in bound.declined_inputs(self.inputs, self.infos)
                    if case['name'] == 'unsupported_regular_symbol_reexport')
        with self.assertRaisesRegex(AssertionError, 'unsupported reexport'):
            bound.exports(case['library'], self.infos[1])

    def test_authenticated_negative_is_actual_arm64e_auth_bind(self):
        case = next(case for case in bound.declined_inputs(self.inputs, self.infos)
                    if case['name'] == 'unsupported_authenticated_bind')
        decoded = bound.decode_fixups(self.inputs[0], self.infos[0], bound.PLACEMENTS[0][0])
        raw = struct.unpack_from('<Q', case['main'], decoded['binds'][0]['file_offset'])[0]
        self.assertEqual(raw >> 62, 3)
        with self.assertRaisesRegex(AssertionError, 'format2/6'):
            bound.decode_fixups(case['main'], self.infos[0], bound.PLACEMENTS[0][0])


if __name__ == '__main__':
    unittest.main()
