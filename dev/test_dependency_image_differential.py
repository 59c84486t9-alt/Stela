"""Genuine rpath metadata, nested guest calls and independent symbol-level state."""
import copy
import importlib
from pathlib import Path
import platform
import tempfile
import unittest

module = importlib.import_module('dependency-image-differential')


@unittest.skipUnless(platform.system() == 'Darwin', 'genuine Apple linker fixture construction')
class DependencyFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='dependency-fixture-test-')
        cls.root, cls.paths, cls.infos, cls.provenance = module.build_fixtures(Path(cls.temporary.name))
        cls.inputs = [path.read_bytes() for path in cls.paths]
        cls.exports = [module.bound.exports(data, info) for data, info in zip(cls.inputs, cls.infos)]
        cls.branch_root, cls.branch_paths, cls.branch_provenance = module.build_traversal_fixture(Path(cls.temporary.name))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_genuine_dependency_ordinals_and_both_path_tokens_are_preserved(self):
        self.assertEqual(self.infos[0]['rpaths'], ['@executable_path/../Frameworks'])
        self.assertEqual(self.infos[1]['rpaths'], ['@loader_path/private'])
        self.assertEqual(self.infos[0]['dependencies'][0], module.IDS[1])
        self.assertEqual(self.infos[1]['dependencies'][0], module.IDS[2])
        for info in self.infos:
            self.assertIn('/usr/lib/libSystem.B.dylib', info['dependencies'])
        self.assertIsNotNone(self.provenance['link_without_libSystem_probe'])
        self.assertNotEqual(self.provenance['link_without_libSystem_probe']['returncode'], 0)

    def test_actual_binds_select_middle_then_leaf_not_declared_unused_system(self):
        for bases in module.PLACEMENTS:
            decoded = [module.bound.decode_fixups(data, info, base) for data, info, base in zip(self.inputs, self.infos, bases)]
            bindings = module.resolve_all(self.infos, decoded, self.exports, bases)
            self.assertEqual([[item['provider_image'] for item in rows] for rows in bindings], [[1, 1], [2], []])
            self.assertEqual([[item['library_ordinal'] for item in rows] for rows in bindings], [[1, 1], [1], []])
            self.assertEqual([len(item['rebases']) for item in decoded], [0, 1, 1])

    def test_all_original_nested_states_data_and_frames_match_symbol_oracle(self):
        for bases in module.PLACEMENTS:
            decoded = [module.bound.decode_fixups(data, info, base) for data, info, base in zip(self.inputs, self.infos, bases)]
            bindings = module.resolve_all(self.infos, decoded, self.exports, bases)
            for initial in module.states(all_flags=True):
                initial.sp, initial.x[30], initial.reserved = module.STACK_TOP, module.STOP, 0xa5c39e71
                state, pc, memory, trace = module.original(self.inputs, self.infos, initial, bases, decoded, bindings)
                self.assertEqual((state, pc, memory), module.oracle(self.inputs, self.infos, initial, bases))
                self.assertEqual(len(trace), 32)
                self.assertEqual(state['sp'], initial.sp)
                self.assertEqual(state['x'][29], initial.x[29])
                self.assertEqual(len(bytes.fromhex(memory[-1]['bytes_hex'])), 32)
                self.assertEqual(sum(len(bytes.fromhex(row['bytes_hex'])) for row in memory[:-1]), 196608)

    def test_requester_and_ancestor_leaf_candidates_both_exist_as_valid_files(self):
        ancestor = self.root / 'app/Frameworks/libleaf-fixture.dylib'
        self.assertEqual(ancestor.read_bytes(), self.inputs[2])
        self.assertEqual(self.paths[2].read_bytes(), self.inputs[2])
        self.assertFalse((self.root / 'usr/lib/libSystem.B.dylib').exists())

    def test_genuine_branch_has_shared_x_and_distinct_y_load_chain_candidates(self):
        declarations = self.branch_provenance['declared_dependencies']
        self.assertEqual(declarations['main'][:2], ['/branch/A/libA.dylib', '/branch/B/libB.dylib'])
        self.assertEqual(declarations['A'][0], '/branch/shared/libC.dylib')
        self.assertEqual(declarations['C'][0], declarations['B'][0])
        self.assertEqual(declarations['X'][0], '@rpath/libY.dylib')
        for name in ('YA', 'YB'):
            info = module.parse_image(self.branch_paths[name].read_bytes())
            self.assertEqual(info['install_name'], '@rpath/libY.dylib')
            self.assertEqual(info['kind'], 6)
        self.assertNotEqual(self.branch_paths['YA'], self.branch_paths['YB'])

    def test_unavailable_actual_leaf_is_not_satisfied_by_same_named_other_image(self):
        infos = copy.deepcopy(self.infos)
        infos[2]['install_name'] = '@rpath/different-leaf.dylib'
        decoded = [module.bound.decode_fixups(data, info, base) for data, info, base in zip(self.inputs, self.infos, module.PLACEMENTS[0])]
        with self.assertRaisesRegex(AssertionError, 'missing declared guest provider'):
            module.resolve_all(infos, decoded, self.exports, module.PLACEMENTS[0])


if __name__ == '__main__':
    unittest.main()
