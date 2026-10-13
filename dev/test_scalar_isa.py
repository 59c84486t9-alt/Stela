"""Focused scalar ISA oracle checks; full differential sweeps are explicit milestones."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest

from differential import State, state_dict, state_dict as complete_state


def load_suite(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


arithmetic = load_suite('arithmetic-differential.py', 'arithmetic_differential')
math = load_suite('integer-math-differential.py', 'integer_math_differential')
bitfield = load_suite('bitfield-differential.py', 'bitfield_differential')


class ArithmeticOracleTests(unittest.TestCase):
    def test_original_carry_programs_are_byte_identical(self):
        cases = arithmetic.carry_cases()
        self.assertEqual(len(cases), 368)
        source = b''.join(struct.pack('<' + 'I' * len(case['words']), *case['words']) for case in cases)
        self.assertEqual(hashlib.sha256(source).hexdigest(), arithmetic.LEGACY_CARRY_CORPUS)

    def test_reused_arm_machine_resets_complete_state_between_observations(self):
        from differential import reference, states
        programs = [case['words'] for case in arithmetic.carry_cases()[::41]]
        programs += [case['words'] for case in arithmetic.extended_cases()[::397]]
        for words in programs:
            source = struct.pack('<' + 'I' * len(words), *words)
            reused = arithmetic.reusable_reference(source)
            for state in states(all_flags=True):
                self.assertEqual(reused(state), reference(source, state))

    def test_extensions_truncate_before_signedness_and_shift(self):
        for width in (0, 1):
            mask = (1 << (32 << width)) - 1
            self.assertEqual(arithmetic.extend_value(0x123456789abc0080, width, 0, 0), 0x80)
            self.assertEqual(arithmetic.extend_value(0x123456789abc0080, width, 4, 0), (-128) & mask)
            self.assertEqual(arithmetic.extend_value(0x123456789abc8000, width, 1, 0), 0x8000)
            self.assertEqual(arithmetic.extend_value(0x123456789abc8000, width, 5, 0), (-32768) & mask)
            self.assertEqual(arithmetic.extend_value(0x1234567880000000, width, 2, 0), 0x80000000)
            self.assertEqual(arithmetic.extend_value(0x1234567880000000, width, 6, 0), (-0x80000000) & mask)
            for option in range(8):
                for shift in range(5):
                    self.assertEqual(arithmetic.extend_value(arithmetic.MASK, width, option, shift),
                                     ((-1 if option & 4 else (1 << min(8 << (option & 3), 32 << width)) - 1) << shift) & mask)
        self.assertEqual(arithmetic.extend_value(0x12345678ffffffff, 0, 3, 0), 0xffffffff)
        self.assertEqual(arithmetic.extend_value(0x12345678ffffffff, 0, 7, 0), 0xffffffff)

    def test_wsp_zero_extends_and_register31_roles_are_distinct(self):
        state = State()
        state.sp, state.x[1], state.x[2], state.nzcv = 0xdeadc0deffffffff, 9, 1, 0xf0000000
        expected = state_dict(state)
        expected['sp'] = 0
        word = arithmetic.extended_encoding(0, 0, 0, 31, 31, 2, 2, 0)
        self.assertEqual(arithmetic.mathematical_reference([word, arithmetic.RET], state), expected)
        expected = state_dict(state)
        expected['x'][0] = 9
        word = arithmetic.extended_encoding(1, 0, 0, 0, 1, 31, 7, 4)
        self.assertEqual(arithmetic.mathematical_reference([word, arithmetic.RET], state), expected)
        expected = state_dict(state)
        expected['nzcv'] = 0x60000000
        word = arithmetic.extended_encoding(0, 0, 1, 31, 31, 2, 2, 0)
        self.assertEqual(arithmetic.mathematical_reference([word, arithmetic.RET], state), expected)

    def test_signed_operand_overlap_and_real_dyld_compare(self):
        state = State()
        state.x[1], state.x[2], state.nzcv = 3, 0x1234567880, 0x90000000
        expected = state_dict(state)
        expected['x'][2] = (-253) & arithmetic.MASK
        word = arithmetic.extended_encoding(1, 0, 0, 2, 1, 2, 4, 1)
        self.assertEqual(arithmetic.mathematical_reference([word, arithmetic.RET], state), expected)
        state.x[19], state.x[8] = 0x10000, 0xffffdead0000ffff
        expected = state_dict(state)
        expected['nzcv'] = 0x20000000
        self.assertEqual(arithmetic.mathematical_reference([0xeb28227f, arithmetic.RET], state), expected)

    def test_signed_overflow_and_no_borrow_are_independent(self):
        for width in (0, 1):
            bits = 32 << width
            state = State()
            state.x[1], state.x[2] = (1 << (bits - 1)) - 1, 1
            word = arithmetic.extended_encoding(width, 0, 1, 0, 1, 2, 0, 0)
            result = arithmetic.mathematical_reference([word, arithmetic.RET], state)
            self.assertEqual(result['nzcv'], 0x90000000)
            state.x[1], state.x[2] = 0, 0xff
            word = arithmetic.extended_encoding(width, 1, 1, 0, 1, 2, 4, 0)
            result = arithmetic.mathematical_reference([word, arithmetic.RET], state)
            self.assertEqual((result['x'][0], result['nzcv']), (1, 0))

    def test_fresh_carry_consumer_and_preserved_unmodeled_fields(self):
        state = State()
        state.x[1], state.x[2], state.nzcv, state.reserved = arithmetic.MASK, 1, 0x90000000, 0x13572468
        words = [arithmetic.extended_encoding(1, 0, 1, 0, 1, 2, 0, 0),
                 arithmetic.encoding(1, 0, 0, 4, 31, 31), arithmetic.RET]
        expected = state_dict(state)
        expected['x'][0], expected['x'][4], expected['nzcv'] = 0, 1, 0x60000000
        self.assertEqual(arithmetic.mathematical_reference(words, state), expected)

    def test_all_forms_extensions_shifts_and_register_roles_have_fixtures(self):
        cases = arithmetic.extended_cases()
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

class IntegerMathOracleTests(unittest.TestCase):
    def test_signed_rounds_toward_zero_and_handles_architectural_extremes(self):
        for bits in (32, 64):
            mask, minimum = (1 << bits) - 1, 1 << (bits - 1)
            for n, d, expected in ((7, 3, 2), (-7, 3, -2), (7, -3, -2),
                                   (-7, -3, 2), (-1, 2, 0), (minimum, -1, minimum),
                                   (minimum, 0, 0), (-7, 0, 0)):
                self.assertEqual(math.quotient(n, d, bits, True), expected & mask)

    def test_unsigned_and_w32_truncation_do_not_use_signed_host_interpretation(self):
        self.assertEqual(math.quotient(0xffffffffffffffff, 2, 64, False), 0x7fffffffffffffff)
        self.assertEqual(math.quotient(0xdeadc0de80000000, 0xbeef0000ffffffff, 32, True),
                         0x80000000)
        self.assertEqual(math.quotient(0xdeadc0deffffffff, 0xbeef000000000003, 32, False),
                         0x55555555)
        self.assertEqual(math.quotient(123, 0xbeef000000000000, 32, False), 0)

    def test_division_fields_do_not_alias_accumulator_bits(self):
        for form, base in math.DIVIDE_FORMS.items():
            self.assertEqual(math.encoding(form, 0, 0, 0), base)
            self.assertEqual(math.encoding(form, 3, 5, 7), base | (7 << 16) | (5 << 5) | 3)

    def test_program_inventory_preserves_multiply_and_covers_each_register_role(self):
        cases = math.cases()
        self.assertEqual(sum(c['form'] in math.MULTIPLY_FORMS for c in cases), 544)
        for form in math.DIVIDE_FORMS:
            words = [c['words'][0] for c in cases if c['form'] == form
                     and c['kind'] == 'all_registers']
            for shift in (0, 5, 16):
                self.assertEqual({(word >> shift) & 31 for word in words}, set(range(32)))
            self.assertEqual(len(list(math.boundary_values(form))), 144)

    def test_overlap_remainder_and_zr_preserve_other_state(self):
        state = math.State()
        state.x[:] = [0xdeadc0de00000000 | i for i in range(31)]
        state.x[1], state.x[2] = (-7) & math.MASK, 3
        state.sp, state.nzcv, state.reserved = 0x1110, 0xf0000000, 0x12345678
        words = [math.encoding('SDIV64', 4, 1, 2),
                 math.encoding('MSUB64', 1, 4, 2, 1),
                 math.encoding('SDIV64', 31, 4, 31), math.RET]
        expected = complete_state(state)
        expected['x'][4], expected['x'][1] = (-2) & math.MASK, math.MASK
        self.assertEqual(math.mathematical_reference(words, state), expected)

    def test_unary_zero_all_leading_counts_and_byte_orders(self):
        for bits in (32, 64):
            form = 'CLZ' + str(bits)
            self.assertEqual(math.unary_reference(form, 0), bits)
            for bit in range(bits):
                self.assertEqual(math.unary_reference(form, 1 << bit), bits - 1 - bit)
            self.assertEqual(math.unary_reference(form, (1 << bits) - 1), 0)
        self.assertEqual(math.unary_reference('CLZ32', 0xdeadc0de00000000), 32)
        self.assertEqual(math.unary_reference('REV32', 0xdeadc0de01234567), 0x67452301)
        self.assertEqual(math.unary_reference('REV16_32', 0xdeadc0deaabbccdd), 0xbbaaddcc)
        self.assertEqual(math.unary_reference('REV64', 0x0123456789abcdef), 0xefcdab8967452301)
        self.assertEqual(math.unary_reference('REV16_64', 0x0123456789abcdef), 0x23016745ab89efcd)
        self.assertEqual(math.unary_reference('REV32_64', 0x0123456789abcdef), 0x67452301efcdab89)
        for bits in (32, 64):
            mask = (1 << bits) - 1
            for value in (0, mask):
                self.assertEqual(math.unary_reference('CLS' + str(bits), value), bits - 1)
            for bit in range(bits):
                self.assertEqual(math.unary_reference('RBIT' + str(bits), 1 << bit), 1 << (bits - 1 - bit))
            for count in range(bits - 1):
                value = 1 << (bits - count - 2)
                self.assertEqual(math.unary_reference('CLS' + str(bits), value), count)
                self.assertEqual(math.unary_reference('CLS' + str(bits), mask ^ value), count)
        for form in ('REV32', 'REV16_32'):
            for value in (0, 1, 0xffffffff, 0x01234567, 0x80000000):
                self.assertEqual(math.unary_reference(form, math.unary_reference(form, value)), value)

    def test_unary_register_pairs_and_encoded_boundary_aliases(self):
        cases = math.cases()
        for form, base in math.UNARY_FORMS.items():
            words = [word for c in cases if c['form'] == form
                     and c['kind'] == 'all_register_pairs' for word in c['words'][:-1]]
            self.assertEqual({(word & 31, (word >> 5) & 31) for word in words},
                             {(d, n) for d in range(32) for n in range(32)})
            self.assertTrue(all(word & 0xfffffc00 == base for word in words))
            state = math.State()
            state.x[:] = [0xfedcba9876543210] * 31
            for c in (c for c in cases if c['form'] == form and c['kind'] == 'unary_boundaries'):
                before = list(state.x)
                math.initialize_boundary(c, state, (0, 0, 0))
                source = (c['words'][0] >> 5) & 31
                if source == 31:
                    self.assertEqual(list(state.x), before)
                else:
                    self.assertEqual(state.x[source] & (0xffffffff if form.endswith('32')
                                                       else math.MASK), 0)

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


if __name__ == "__main__":
    unittest.main()
