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

    def test_pair_encodings_and_independent_decoder_keep_all18_forms(self):
        self.assertEqual(suite.pair_encoding(16, False, 0, 0, 1, 0, 'offset'), 0xad000020)
        self.assertEqual(suite.pair_encoding(16, True, 0, 31, 31, 32, 'post'), 0xacc17fe0)
        leaves, blocks = suite.pair_programs()
        self.assertEqual((len(leaves), len(blocks)), (2607, 18))
        self.assertEqual(sum(p['flags'] for p in leaves + blocks), 11760)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        pairs = [o for p in leaves + blocks for o in p['operations'] if o['kind'] == 'pair']
        forms = {suite.canonical_form(o) for o in pairs}
        self.assertEqual(len(forms), 18)
        for operation in pairs:
            decoded = list(decoder.disasm(struct.pack('<I', operation['word']), 0))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0].mnemonic, 'ldp' if operation['loading'] else 'stp')
        for form in forms:
            operations = [o for o in pairs if suite.canonical_form(o) == form]
            self.assertEqual({o['rt'] for o in operations}, set(range(32)))
            self.assertEqual({o['rt2'] for o in operations}, set(range(32)))
            self.assertEqual({o['rn'] for o in operations}, set(range(32)))
            if form.startswith('STP'):
                self.assertEqual({o['rt'] for o in operations if o['rt'] == o['rt2']}, set(range(32)))
            else:
                self.assertTrue(all(o['rt'] != o['rt2'] for o in operations))

    def test_pair_load_upper_zero_two_positions_and_independent_base_bank(self):
        for width in suite.PAIR_WIDTHS:
            for mode in suite.PAIR_MODES:
                initial = State()
                initial.x[0] = 0x8800
                initial.v[0][:] = [suite.MASK, suite.MASK]
                initial.v[31][:] = [suite.MASK, suite.MASK]
                memory = bytes(range(256)) * 16
                expected, observed = suite.mathematical([suite.pair_op(width, True, 0, 31, 0, 16, mode)], initial, memory, 0x8000)
                offset = 0x800 + (0 if mode == 'post' else 16)
                for slot, register in enumerate((0, 31)):
                    value = int.from_bytes(memory[offset + slot * width:offset + (slot + 1) * width], 'little')
                    self.assertEqual(list(expected.v[register]), [value & suite.MASK, value >> 64])
                self.assertEqual(expected.x[0], initial.x[0] + (16 if mode in ('pre', 'post') else 0))
                self.assertEqual(observed, memory)
                for register in range(1, 31):
                    self.assertEqual(list(expected.v[register]), list(initial.v[register]))
                self.assertEqual((expected.fpcr, expected.fpsr, expected.nzcv, expected.reserved),
                                 (initial.fpcr, initial.fpsr, initial.nzcv, initial.reserved))

    def test_duplicate_pair_stores_preserve_both_elements_and_duplicate_loads_decline_math(self):
        for width in suite.PAIR_WIDTHS:
            for register in (0, 31):
                state = State()
                state.x[0] = 0x8800
                state.v[register][:] = [0x0123456789abcdef, 0xfedcba9876543210]
                memory = b'\xa5' * 4096
                expected, observed = suite.mathematical([suite.pair_op(width, False, register, register, 0, 0, 'offset')], state, memory, 0x8000)
                element = struct.pack('<2Q', *state.v[register])[:width]
                self.assertEqual(observed, memory[:0x800] + element * 2 + memory[0x800 + 2 * width:])
                self.assertEqual(bytes(expected), bytes(state))
                with self.assertRaises(ValueError):
                    suite.mathematical([suite.pair_op(width, True, register, register, 0, 0, 'offset')], state, memory, 0x8000)
        self.assertEqual(len(suite.declined_pair_encodings()), 33)
        for register in (0, 7, 31):
            self.assertTrue(any(case['reason'] == 'constrained_duplicate_load' and case['word'] & 31 == register
                                for case in suite.declined_pair_encodings()))

    def test_pair_fault_profiles_require_sp_for_sp_policy_and_complete_first_elements(self):
        cases = suite.pair_fault_cases()
        self.assertEqual(len(cases), 122)
        for case in cases:
            self.assertFalse(case['protection'] == 'crossing')
            if case['protection'] == 'sp_alignment':
                self.assertEqual(case['rn'], 31)
            if case['protection'] == 'pair_readonly':
                self.assertFalse(case['loading'])
            if case['protection'] in ('pair_second', 'pair_readonly') and case['rn'] == 31:
                target = 0x9000 - case['width']
                base = target - (case['offset'] if case['mode'] != 'post' else 0)
                self.assertEqual(base % 16, 0)

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


    def test_pair_fault_classification_keeps_exact_unicorn_difference_and_rejects_other_changes(self):
        for width in suite.PAIR_WIDTHS:
            case = {'loading': True, 'protection': 'pair_second', 'width': width, 'rt': 0}
            initial = State()
            native = State.from_buffer_copy(initial)
            native.x[7] = 99
            original = State.from_buffer_copy(native)
            value = int.from_bytes(b'\xa5' * width, 'little')
            original.v[0][:] = [value & suite.MASK, value >> 64]
            self.assertEqual(suite.validate_pair_fault_state(case, initial, native, original, b'\xa5' * width),
                             'unicorn_second_load_divergence')
            wrong = State.from_buffer_copy(original)
            wrong.v[31][0] ^= 1
            with self.assertRaises(AssertionError):
                suite.validate_pair_fault_state(case, initial, native, wrong, b'\xa5' * width)
            wrong = State.from_buffer_copy(native)
            wrong.x[0] ^= 1
            with self.assertRaises(AssertionError):
                suite.validate_pair_fault_state(case, initial, wrong, original, b'\xa5' * width)
            case['protection'] = 'guard'
            self.assertEqual(suite.validate_pair_fault_state(case, initial, native, native, b'\xa5' * width),
                             'original_native_full_state_equal')
            with self.assertRaises(AssertionError):
                suite.validate_pair_fault_state(case, initial, native, original, b'\xa5' * width)
            case['protection'] = 'sp_alignment'
            self.assertEqual(suite.validate_pair_fault_state(case, initial, native, None, b'\xa5' * width), 'sp_policy_only')
            with self.assertRaises(AssertionError):
                suite.validate_pair_fault_state(case, initial, native, native, b'\xa5' * width)


if __name__ == '__main__':
    unittest.main()
