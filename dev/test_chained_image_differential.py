"""Independent original-execution and reject-before-execution fixup guards."""
import importlib
from pathlib import Path
import platform
import struct
import tempfile
import unittest

chained = importlib.import_module('chained-image-differential')


@unittest.skipUnless(platform.system() == 'Darwin', 'genuine Apple linker fixture construction')
class ChainedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='chained-fixture-test-')
        cls.image, cls.info, cls.provenance = chained.build_fixture(Path(cls.temporary.name))
        cls.data = cls.image.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_genuine_three_pointer_chain_matches_linker_symbols_at_both_bases(self):
        for base in chained.LOAD_BASES:
            fixups = chained.decode_rebases(self.data, self.info, base)
            slide = base - self.info['preferred_base']
            self.assertEqual(fixups['pointer_formats'], [6])
            self.assertEqual(len(fixups['rebases']), 3)
            self.assertEqual([row['value'] for row in fixups['rebases']],
                             [self.info['symbols'][name] + slide for name in
                              ('_chained_seed', '_chained_output', '_chained_callee')])
            self.assertEqual([row['guest_address'] for row in fixups['rebases']],
                             [self.info['symbols']['_chained_pointers'] + slide + offset for offset in (0, 8, 16)])
            self.assertEqual([(row['raw'] >> 51) & 0xfff for row in fixups['rebases']], [2, 2, 0])

    def test_all_original_states_data_and_stack_match_symbol_oracle(self):
        for base in chained.LOAD_BASES:
            fixups = chained.decode_rebases(self.data, self.info, base)
            for initial in chained.states(all_flags=True):
                initial.sp, initial.x[30], initial.reserved = chained.STACK_TOP, chained.STOP, 0xa5c39e71
                state, pc, memory, trace = chained.original(self.data, self.info, initial, fixups)
                self.assertEqual((state, pc, memory), chained.fixture_oracle(self.data, self.info, initial, base))
                self.assertEqual(state['sp'], initial.sp)
                self.assertEqual(state['x'][29], initial.x[29])
                self.assertEqual(state['x'][30], chained.STOP)
                self.assertEqual(state['nzcv'], initial.nzcv)
                self.assertEqual(len(trace), 16)

    def test_malformed_or_unsupported_fixup_inputs_are_declined(self):
        for negative in chained.negative_inputs(self.data, self.info):
            with self.subTest(name=negative['name']):
                with self.assertRaises(AssertionError):
                    chained.decode_rebases(negative['data'], self.info, chained.LOAD_BASES[0])

    def test_authenticated_negative_sets_real_auth_bit_and_arm64e_format(self):
        negative = next(row for row in chained.negative_inputs(self.data, self.info)
                        if row['name'] == 'actual_authenticated_pointer')['data']
        slot = chained.decode_rebases(self.data, self.info, chained.LOAD_BASES[0])['rebases'][0]['file_offset']
        self.assertEqual(struct.unpack_from('<Q', negative, slot)[0] >> 63, 1)
        payload = self.info['chained_payload']['offset']
        starts = struct.unpack_from('<I', negative, payload + 4)[0]
        offsets = struct.unpack_from(f"<{len(self.info['segments'])}I", negative, payload + starts + 4)
        node = payload + starts + next(offset for offset in offsets if offset)
        self.assertEqual(struct.unpack_from('<H', negative, node + 6)[0], 9)

    def test_decoding_and_reference_initialization_preserve_linked_file(self):
        before = self.image.read_bytes()
        fixups = chained.decode_rebases(self.data, self.info, chained.LOAD_BASES[0])
        memories = chained.initialized_segments(self.data, self.info, fixups)
        segment = next(segment for segment in self.info['segments'] if segment['name'] == '__DATA_CONST')
        self.assertEqual(segment['flags'] & 0x10, 0x10)
        const_address = segment['address'] + chained.LOAD_BASES[0] - self.info['preferred_base']
        for row in fixups['rebases']:
            self.assertEqual(struct.unpack_from('<Q', memories[const_address], row['guest_address'] - const_address)[0], row['value'])
            self.assertNotEqual(row['raw'], row['value'])
        self.assertEqual(self.image.read_bytes(), before)
        self.assertTrue(self.provenance['linked_executable_unchanged'])

    def test_invalid_load_base_rejected_before_reference_memory_mapping(self):
        for base in (0, chained.LOAD_BASES[0] + 4, 1 << 47):
            with self.assertRaises(AssertionError):
                chained.decode_rebases(self.data, self.info, base)


if __name__ == '__main__':
    unittest.main()
