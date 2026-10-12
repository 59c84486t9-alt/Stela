"""Oracle checks independent of compiler builds and native execution."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'integer_math_differential', Path(__file__).with_name('integer-math-differential.py'))
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


class IntegerMathOracleTests(unittest.TestCase):
    def test_signed_rounds_toward_zero_and_handles_architectural_extremes(self):
        for bits in (32, 64):
            mask, minimum = (1 << bits) - 1, 1 << (bits - 1)
            for n, d, expected in ((7, 3, 2), (-7, 3, -2), (7, -3, -2),
                                   (-7, -3, 2), (-1, 2, 0), (minimum, -1, minimum),
                                   (minimum, 0, 0), (-7, 0, 0)):
                self.assertEqual(suite.quotient(n, d, bits, True), expected & mask)

    def test_unsigned_and_w32_truncation_do_not_use_signed_host_interpretation(self):
        self.assertEqual(suite.quotient(0xffffffffffffffff, 2, 64, False), 0x7fffffffffffffff)
        self.assertEqual(suite.quotient(0xdeadc0de80000000, 0xbeef0000ffffffff, 32, True),
                         0x80000000)
        self.assertEqual(suite.quotient(0xdeadc0deffffffff, 0xbeef000000000003, 32, False),
                         0x55555555)
        self.assertEqual(suite.quotient(123, 0xbeef000000000000, 32, False), 0)

    def test_division_fields_do_not_alias_accumulator_bits(self):
        for form, base in suite.DIVIDE_FORMS.items():
            self.assertEqual(suite.encoding(form, 0, 0, 0), base)
            self.assertEqual(suite.encoding(form, 3, 5, 7), base | (7 << 16) | (5 << 5) | 3)

    def test_program_inventory_preserves_multiply_and_covers_each_register_role(self):
        cases = suite.cases()
        self.assertEqual(sum(c['form'] in suite.MULTIPLY_FORMS for c in cases), 544)
        for form in suite.DIVIDE_FORMS:
            words = [c['words'][0] for c in cases if c['form'] == form
                     and c['kind'] == 'all_registers']
            for shift in (0, 5, 16):
                self.assertEqual({(word >> shift) & 31 for word in words}, set(range(32)))
            self.assertEqual(len(list(suite.boundary_values(form))), 144)

    def test_overlap_remainder_and_zr_preserve_other_state(self):
        state = suite.State()
        state.x[:] = [0xdeadc0de00000000 | i for i in range(31)]
        state.x[1], state.x[2] = (-7) & suite.MASK, 3
        state.sp, state.nzcv, state.reserved = 0x1110, 0xf0000000, 0x12345678
        words = [suite.encoding('SDIV64', 4, 1, 2),
                 suite.encoding('MSUB64', 1, 4, 2, 1),
                 suite.encoding('SDIV64', 31, 4, 31), suite.RET]
        expected = {'x': list(state.x), 'sp': state.sp, 'nzcv': state.nzcv,
                    'reserved': state.reserved}
        expected['x'][4], expected['x'][1] = (-2) & suite.MASK, suite.MASK
        self.assertEqual(suite.mathematical_reference(words, state), expected)


if __name__ == '__main__':
    unittest.main()
