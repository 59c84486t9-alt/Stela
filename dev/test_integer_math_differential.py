"""Oracle checks independent of compiler builds and native execution."""
import importlib.util
from differential import state_dict as complete_state
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
        expected = complete_state(state)
        expected['x'][4], expected['x'][1] = (-2) & suite.MASK, suite.MASK
        self.assertEqual(suite.mathematical_reference(words, state), expected)

    def test_unary_zero_all_leading_counts_and_byte_orders(self):
        for bits in (32, 64):
            form = 'CLZ' + str(bits)
            self.assertEqual(suite.unary_reference(form, 0), bits)
            for bit in range(bits):
                self.assertEqual(suite.unary_reference(form, 1 << bit), bits - 1 - bit)
            self.assertEqual(suite.unary_reference(form, (1 << bits) - 1), 0)
        self.assertEqual(suite.unary_reference('CLZ32', 0xdeadc0de00000000), 32)
        self.assertEqual(suite.unary_reference('REV32', 0xdeadc0de01234567), 0x67452301)
        self.assertEqual(suite.unary_reference('REV16_32', 0xdeadc0deaabbccdd), 0xbbaaddcc)
        for form in ('REV32', 'REV16_32'):
            for value in (0, 1, 0xffffffff, 0x01234567, 0x80000000):
                self.assertEqual(suite.unary_reference(form, suite.unary_reference(form, value)), value)

    def test_unary_register_pairs_and_encoded_boundary_aliases(self):
        cases = suite.cases()
        for form, base in suite.UNARY_FORMS.items():
            words = [word for c in cases if c['form'] == form
                     and c['kind'] == 'all_register_pairs' for word in c['words'][:-1]]
            self.assertEqual({(word & 31, (word >> 5) & 31) for word in words},
                             {(d, n) for d in range(32) for n in range(32)})
            self.assertTrue(all(word & 0xfffffc00 == base for word in words))
            state = suite.State()
            state.x[:] = [0xfedcba9876543210] * 31
            for c in (c for c in cases if c['form'] == form and c['kind'] == 'unary_boundaries'):
                before = list(state.x)
                suite.initialize_boundary(c, state, (0, 0, 0))
                source = (c['words'][0] >> 5) & 31
                if source == 31:
                    self.assertEqual(list(state.x), before)
                else:
                    self.assertEqual(state.x[source] & (0xffffffff if form.endswith('32')
                                                       else suite.MASK), 0)


if __name__ == '__main__':
    unittest.main()
