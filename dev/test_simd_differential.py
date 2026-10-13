"""Independent encoding/coverage and SIMD byte-oracle regression checks."""
import ctypes
import importlib
import struct
import unittest

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import State, state_dict, seed_extended_state

suite = importlib.import_module('simd-differential')


class SimdDifferentialTests(unittest.TestCase):
    def test_known_original_words_decode_to_expected_reviewed_operands(self):
        self.assertEqual(suite.memory_encoding(8, True, 0, 8, 1504, 'unsigned'), 0xfd42f100)
        self.assertEqual(suite.memory_encoding(16, True, 0, 29, -88, 'unscaled'), 0x3cda83a0)
        self.assertEqual(suite.movi_encoding(True, 0, 0), 0x6f00e400)
        self.assertEqual(suite.movi_encoding(False, 255, 31), 0x2f07e7ff)

    def test_every_emitted_operation_has_an_independent_simd_decode(self):
        leaves, blocks = suite.programs()
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for program in leaves + blocks:
            for operation in program['operations']:
                decoded = list(decoder.disasm(struct.pack('<I', operation['word']), 0))
                self.assertEqual(len(decoded), 1)
                self.assertIn(decoded[0].mnemonic, ('ldr', 'str', 'ldur', 'stur', 'movi'))
        self.assertEqual(len(leaves), 3596)
        self.assertEqual(len(blocks), 42)
        self.assertEqual(sum(p['flags'] for p in leaves + blocks), 33248)
        self.assertEqual(len(suite.fault_cases()), 134)
        self.assertFalse(any(p['width'] == 16 and not p['loading'] and p['protection'] == 'crossing'
                             for p in suite.fault_cases()))

    def test_complete_form_mask_and_register_denominators_are_explicit(self):
        leaves, blocks = suite.programs()
        operations = [o for p in leaves + blocks for o in p['operations']]
        self.assertEqual(len({suite.canonical_form(o) for o in operations}), 42)
        for lanes in (False, True):
            self.assertEqual({o['mask'] for o in operations if o['kind'] == 'movi' and o['two_lanes'] == lanes}, set(range(256)))
            self.assertEqual({o['rt'] for o in operations if o['kind'] == 'movi' and o['two_lanes'] == lanes}, set(range(32)))
        self.assertEqual({o['rt'] for o in operations}, set(range(32)))
        self.assertEqual({o['rn'] for o in operations if o['kind'] == 'memory'}, set(range(32)))

    def test_scalar_load_zeroes_all_upper_vector_bits_and_preserves_every_other_field(self):
        for width in (1, 2, 4, 8):
            for rt in (0, 31):
                initial = State()
                initial.x[0] = 0x8000
                initial.v[rt][:] = [suite.MASK, suite.MASK]
                initial.reserved = 0x12345678
                ram = bytes(range(256)) * 64
                expected, observed = suite.mathematical([suite.memory_op(width, True, rt, 0, 16, 'unsigned')], initial, ram, 0x8000)
                self.assertEqual(list(expected.v[rt]), [int.from_bytes(ram[16:16 + width], 'little'), 0])
                for index in range(32):
                    if index != rt:
                        self.assertEqual(list(expected.v[index]), list(initial.v[index]))
                self.assertEqual(observed, ram)
                self.assertEqual((list(expected.x), expected.sp, expected.nzcv, expected.reserved, expected.fpcr, expected.fpsr),
                                 (list(initial.x), initial.sp, initial.nzcv, initial.reserved, initial.fpcr, initial.fpsr))

    def test_store_extent_cross_bank_alias_and_pre_post_writeback(self):
        for width in suite.WIDTHS:
            for mode in suite.MODES:
                initial = State()
                initial.x[7] = 0x8800
                initial.v[7][:] = [0x0123456789abcdef, 0xfedcba9876543210]
                ram = b'\xa5' * 4096
                operation = suite.memory_op(width, False, 7, 7, 16, mode)
                expected, observed = suite.mathematical([operation], initial, ram, 0x8000)
                offset = 0x800 + (0 if mode == 'post' else 16)
                value = struct.pack('<2Q', *initial.v[7])[:width]
                self.assertEqual(observed, ram[:offset] + value + ram[offset + width:])
                self.assertEqual(expected.x[7], initial.x[7] + (16 if mode in ('pre', 'post') else 0))
                self.assertEqual(list(expected.v[7]), list(initial.v[7]))

    def test_all_movi_masks_expand_each_byte_and_single_d_clears_high_lane(self):
        initial = State()
        ram = b'\x5a' * 4096
        for mask in range(256):
            byte_pattern = bytes(255 if mask & (1 << bit) else 0 for bit in range(8))
            low = int.from_bytes(byte_pattern, 'little')
            for lanes in (False, True):
                state, observed = suite.mathematical([suite.movi_op(lanes, mask, 31)], initial, ram, 0x8000)
                self.assertEqual(list(state.v[31]), [low, low if lanes else 0])
                self.assertEqual(observed, ram)
                self.assertEqual(list(state.x), list(initial.x))

    def test_bad_encoding_inputs_and_invalid_oracle_accesses_decline(self):
        for args in [(3, True, 0, 0, 0, 'unsigned'), (16, True, 32, 0, 0, 'unsigned'),
                     (8, True, 0, 0, 1, 'unsigned'), (8, True, 0, 0, -1, 'unsigned'),
                     (16, True, 0, 0, 65536, 'unsigned'), (16, True, 0, 0, 256, 'pre')]:
            with self.assertRaises(ValueError):
                suite.memory_encoding(*args)
        state = State()
        state.sp = 0x8001
        with self.assertRaises(ValueError):
            suite.mathematical([suite.memory_op(16, True, 0, 31, 0, 'unsigned')], state, bytes(4096), 0x8000)
        state.x[0] = 0x9000
        with self.assertRaises(ValueError):
            suite.mathematical([suite.memory_op(16, True, 0, 0, 0, 'unsigned')], state, bytes(4096), 0x8000)


if __name__ == '__main__':
    unittest.main()
