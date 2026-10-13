"""Independent arithmetic-oracle and finite-field coverage checks."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest

from differential import State, state_dict

SPEC = importlib.util.spec_from_file_location('arithmetic_differential', Path(__file__).with_name('arithmetic-differential.py'))
suite = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(suite)


class ArithmeticOracleTests(unittest.TestCase):
    def test_original_carry_programs_are_byte_identical(self):
        cases = suite.carry_cases()
        self.assertEqual(len(cases), 368)
        source = b''.join(struct.pack('<' + 'I' * len(case['words']), *case['words']) for case in cases)
        self.assertEqual(hashlib.sha256(source).hexdigest(), suite.LEGACY_CARRY_CORPUS)

    def test_extensions_truncate_before_signedness_and_shift(self):
        for width in (0, 1):
            mask = (1 << (32 << width)) - 1
            self.assertEqual(suite.extend_value(0x123456789abc0080, width, 0, 0), 0x80)
            self.assertEqual(suite.extend_value(0x123456789abc0080, width, 4, 0), (-128) & mask)
            self.assertEqual(suite.extend_value(0x123456789abc8000, width, 1, 0), 0x8000)
            self.assertEqual(suite.extend_value(0x123456789abc8000, width, 5, 0), (-32768) & mask)
            self.assertEqual(suite.extend_value(0x1234567880000000, width, 2, 0), 0x80000000)
            self.assertEqual(suite.extend_value(0x1234567880000000, width, 6, 0), (-0x80000000) & mask)
            for option in range(8):
                for shift in range(5):
                    self.assertEqual(suite.extend_value(suite.MASK, width, option, shift),
                                     ((-1 if option & 4 else (1 << min(8 << (option & 3), 32 << width)) - 1) << shift) & mask)
        self.assertEqual(suite.extend_value(0x12345678ffffffff, 0, 3, 0), 0xffffffff)
        self.assertEqual(suite.extend_value(0x12345678ffffffff, 0, 7, 0), 0xffffffff)

    def test_wsp_zero_extends_and_register31_roles_are_distinct(self):
        state = State()
        state.sp, state.x[1], state.x[2], state.nzcv = 0xdeadc0deffffffff, 9, 1, 0xf0000000
        expected = state_dict(state)
        expected['sp'] = 0
        word = suite.extended_encoding(0, 0, 0, 31, 31, 2, 2, 0)
        self.assertEqual(suite.mathematical_reference([word, suite.RET], state), expected)
        expected = state_dict(state)
        expected['x'][0] = 9
        word = suite.extended_encoding(1, 0, 0, 0, 1, 31, 7, 4)
        self.assertEqual(suite.mathematical_reference([word, suite.RET], state), expected)
        expected = state_dict(state)
        expected['nzcv'] = 0x60000000
        word = suite.extended_encoding(0, 0, 1, 31, 31, 2, 2, 0)
        self.assertEqual(suite.mathematical_reference([word, suite.RET], state), expected)

    def test_signed_operand_overlap_and_real_dyld_compare(self):
        state = State()
        state.x[1], state.x[2], state.nzcv = 3, 0x1234567880, 0x90000000
        expected = state_dict(state)
        expected['x'][2] = (-253) & suite.MASK
        word = suite.extended_encoding(1, 0, 0, 2, 1, 2, 4, 1)
        self.assertEqual(suite.mathematical_reference([word, suite.RET], state), expected)
        state.x[19], state.x[8] = 0x10000, 0xffffdead0000ffff
        expected = state_dict(state)
        expected['nzcv'] = 0x20000000
        self.assertEqual(suite.mathematical_reference([0xeb28227f, suite.RET], state), expected)

    def test_signed_overflow_and_no_borrow_are_independent(self):
        for width in (0, 1):
            bits = 32 << width
            state = State()
            state.x[1], state.x[2] = (1 << (bits - 1)) - 1, 1
            word = suite.extended_encoding(width, 0, 1, 0, 1, 2, 0, 0)
            result = suite.mathematical_reference([word, suite.RET], state)
            self.assertEqual(result['nzcv'], 0x90000000)
            state.x[1], state.x[2] = 0, 0xff
            word = suite.extended_encoding(width, 1, 1, 0, 1, 2, 4, 0)
            result = suite.mathematical_reference([word, suite.RET], state)
            self.assertEqual((result['x'][0], result['nzcv']), (1, 0))

    def test_fresh_carry_consumer_and_preserved_unmodeled_fields(self):
        state = State()
        state.x[1], state.x[2], state.nzcv, state.reserved = suite.MASK, 1, 0x90000000, 0x13572468
        words = [suite.extended_encoding(1, 0, 1, 0, 1, 2, 0, 0),
                 suite.encoding(1, 0, 0, 4, 31, 31), suite.RET]
        expected = state_dict(state)
        expected['x'][0], expected['x'][4], expected['nzcv'] = 0, 1, 0x60000000
        self.assertEqual(suite.mathematical_reference(words, state), expected)

    def test_all_forms_extensions_shifts_and_register_roles_have_fixtures(self):
        cases = suite.extended_cases()
        all_registers = [case for case in cases if case['kind'] == 'all_registers']
        self.assertEqual(len(all_registers), 320)
        for case in all_registers:
            for bit in (0, 5, 16):
                self.assertEqual({(word >> bit) & 31 for word in case['words'][:-1]}, set(range(32)))
        for width in (0, 1):
            for subtract in (0, 1):
                for flags in (0, 1):
                    self.assertEqual({(case['option'], case['shift']) for case in all_registers
                                      if (case['width'], case['subtract'], case['flags']) == (width, subtract, flags)},
                                     {(option, shift) for option in range(8) for shift in range(5)})


if __name__ == '__main__':
    unittest.main()
