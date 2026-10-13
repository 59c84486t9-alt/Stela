"""Focused scalar ISA oracle checks; full differential sweeps are explicit milestones."""
import hashlib
import argparse
import io
import json
import tarfile
import tempfile
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from differential import State, state_dict, state_dict as complete_state


def load_suite(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


arithmetic = load_suite('arithmetic-differential.py', 'arithmetic_differential')
math = load_suite('integer-math-differential.py', 'integer_math_differential')
bitfield = load_suite('bitfield-differential.py', 'bitfield_differential')
x86_mappings = load_suite('x86-mappings.py', 'x86_mappings')


register_offset = load_suite('register-offset-differential.py', 'register_offset_differential')
pc_relative = load_suite('pc-relative-differential.py', 'pc_relative_differential')
memory_faults = load_suite('memory-faults.py', 'memory_faults')


class MemoryBatchOracleTests(unittest.TestCase):
    def test_scalar_crossing_store_faults_include_zero_register_and_every_width(self):
        cases = memory_faults.cases()
        for size in (1, 2, 3):
            for destination in (1, 31):
                self.assertTrue(any(case["size"] == size and case["opcode"] == 0 and case["rt"] == destination
                                    and case.get("crossing_bytes") == 1 for case in cases))

    def test_simd_corpus_distinguishes_sp_from_zero_index_for_all_extensions(self):
        cases = register_offset.simd_cases()
        for option in register_offset.INDEX_OPTIONS:
            self.assertTrue(any(case["rn"] == 31 and case["rm"] == 31 and case["option"] == option for case in cases))

    def test_simd_register_offset_extends_before_scaling_and_zeros_upper_bits(self):
        state = State()
        state.x[0], state.x[2] = 0x1040, 0xdeadbeeffffffffe
        state.v[31][:] = [0xffffffffffffffff, 0xffffffffffffffff]
        ram = bytes(range(128))
        case = {"simd": True, "size": 1, "opcode": 1, "rn": 0, "rt": 31, "rm": 2,
                "option": register_offset.OPTION_SXTW, "scaled": True}
        expected = state_dict(state)
        expected["v"][31] = [int.from_bytes(ram[60:62], "little"), 0]
        expected["memory"] = ram
        self.assertEqual(register_offset.mathematical_reference(case, state, 0x1000, ram), expected)

    def test_simd_register_banks_are_distinct_and_exact_store_width(self):
        state = State()
        state.x[1], state.x[2] = 0x1003, 0
        state.v[1][:] = [0x123456789abcdef0, 0xfedcba9876543210]
        ram = bytes(range(64))
        case = {"simd": True, "size": 0, "opcode": 0, "rn": 1, "rt": 1, "rm": 2,
                "option": register_offset.OPTION_LSL, "scaled": False}
        expected = state_dict(state)
        expected["memory"] = ram[:3] + b"\xf0" + ram[4:]
        self.assertEqual(register_offset.mathematical_reference(case, state, 0x1000, ram), expected)

    def test_literal_uses_actual_pc_signed_offset_and_integer_zero_register(self):
        state = State()
        ram = bytes(range(32))
        case = {"form": "ldrsw", "immediate": -1, "destination": 3, "base": 0x1004, "prefix": 2}
        negative_ram = ram[:8] + b"\x00\x00\x00\x80" + ram[12:]
        expected = state_dict(state)
        expected["x"][3] = 0xffffffff80000000
        expected["memory"] = negative_ram
        self.assertEqual(pc_relative.literal_math(case, state, 0x1000, negative_ram), expected)
        case["destination"] = 31
        expected["x"][3] = state.x[3]
        self.assertEqual(pc_relative.literal_math(case, state, 0x1000, negative_ram), expected)
        case["immediate"] = -100
        with self.assertRaisesRegex(ValueError, 'outside supplied RAM'):
            pc_relative.literal_math(case, state, 0x1000, ram)

    def test_literal_vector31_is_writable_and_load_clears_upper_bits(self):
        state = State()
        state.v[31][:] = [0xffffffffffffffff, 0xffffffffffffffff]
        case = {"form": "s", "immediate": 1, "destination": 31, "base": 0x1000, "prefix": 1}
        ram = bytes(range(32))
        expected = state_dict(state)
        expected["v"][31] = [0x0b0a0908, 0]
        expected["memory"] = ram
        self.assertEqual(pc_relative.literal_math(case, state, 0x1000, ram), expected)

    def test_literal_mathematical_address_wraps_at_architectural_width(self):
        state = State()
        case = {"form": "x", "immediate": 2, "destination": 0,
                "base": pc_relative.MASK - 7, "prefix": 1}
        ram = bytes(range(32))
        expected = state_dict(state)
        expected["x"][0] = int.from_bytes(ram[4:12], "little")
        expected["memory"] = ram
        self.assertEqual(pc_relative.literal_math(case, state, 0, ram), expected)

    def test_literal_encoding_bounds_and_corpus_cover_six_forms(self):
        for form, (base, _) in pc_relative.LITERAL_FORMS.items():
            self.assertEqual(pc_relative.literal_encoding(form, 0, 31), base | 31)
            self.assertEqual(pc_relative.literal_encoding(form, -1, 0), base | 0xffffe0)
            for invalid in (-(1 << 18) - 1, 1 << 18):
                with self.assertRaises(ValueError):
                    pc_relative.literal_encoding(form, invalid, 0)
        cases = pc_relative.literal_cases()
        self.assertEqual({case["form"] for case in cases}, set(pc_relative.LITERAL_FORMS))
        self.assertTrue(any(case["destination"] == 31 for case in cases))



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

class FlagOracleTests(unittest.TestCase):
    def test_corpus_exhausts_immediates_crm_and_source_registers(self):
        cases = arithmetic.flag_cases()
        self.assertEqual(len(cases), 1180)
        rmif = [case['words'][0] for case in cases if case['kind'] == 'immediates']
        self.assertEqual({((word >> arithmetic.RMIF_ROTATE_SHIFT) & 63, word & 15) for word in rmif},
                         {(rotation, mask) for rotation in range(64) for mask in range(16)})
        half_rotation = next(case for case in cases if case['kind'] == 'immediates'
                             and (case['words'][0] >> arithmetic.RMIF_ROTATE_SHIFT) & 63 == 32
                             and case['words'][0] & 15 == 15)
        self.assertTrue(any((value & 15) != ((value >> 32) & 15)
                            for value in arithmetic.flag_values(half_rotation)))
        for form in ('CFINV', 'AXFLAG', 'XAFLAG'):
            words = [case['words'][0] for case in cases if case['form'] == form and case['kind'] == 'ignored_crm']
            self.assertEqual({(word >> arithmetic.IGNORED_CRM_SHIFT) & 15 for word in words}, set(range(16)))
        for form in ('RMIF', 'SETF8', 'SETF16'):
            self.assertEqual({case['source'] for case in cases if case['form'] == form
                              and case['kind'] == 'source_registers'}, set(range(32)))
        for form in arithmetic.FLAG_FORMS:
            self.assertEqual({case['kind'] for case in cases if case['form'] == form
                              and case['kind'].endswith('_chain')}, {'carry_chain', 'conditional_chain'})

    def test_flag_boolean_truth_tables_and_ignored_crm_match_original(self):
        from differential import states
        from unicorn import arm64_const as arm
        for form in ('CFINV', 'AXFLAG', 'XAFLAG'):
            for crm in range(16):
                words = [arithmetic.flag_encoding(form, crm=crm), arithmetic.RET]
                original = arithmetic.reusable_reference(struct.pack('<2I', *words), arm.UC_CPU_ARM64_MAX,
                                                          oracle_declines=crm != 0)
                for initial in states(all_flags=True):
                    initial.reserved = 0x5a17c0de
                    expected = arithmetic.flag_reference(words, initial)
                    self.assertEqual(original(initial), expected if crm == 0 else None)
                    expected['nzcv'] = initial.nzcv
                    self.assertEqual(expected, complete_state(initial))

    def test_rmif_wrap_mask_and_zero_source_match_original(self):
        from differential import states
        from unicorn import arm64_const as arm
        for rotation in (0, 1, 31, 32, 61, 62, 63):
            for mask in (0, 1, 2, 4, 8, 15):
                words = [arithmetic.flag_encoding('RMIF', rotation=rotation, mask=mask), arithmetic.RET]
                original = arithmetic.reusable_reference(struct.pack('<2I', *words), arm.UC_CPU_ARM64_MAX)
                case = {'form': 'RMIF', 'source': 1, 'words': words}
                for value in arithmetic.flag_values(case):
                    for initial in states(all_flags=True):
                        initial.x[1] = value
                        expected = arithmetic.flag_reference(words, initial)
                        self.assertEqual(original(initial), expected)
                        unchanged = (~mask & 15) << 28
                        self.assertEqual(expected['nzcv'] & unchanged, initial.nzcv & unchanged)
        initial = State()
        initial.nzcv, initial.x[1], initial.sp = 0xf0000000, arithmetic.MASK, arithmetic.MASK
        words = [arithmetic.flag_encoding('RMIF', source=31), arithmetic.RET]
        expected = complete_state(initial)
        expected['nzcv'] = 0
        self.assertEqual(arithmetic.flag_reference(words, initial), expected)
        original = arithmetic.reusable_reference(struct.pack('<2I', *words), arm.UC_CPU_ARM64_MAX)
        self.assertEqual(original(initial), expected)

    def test_setf_boundaries_dirty_upper_bits_and_carry_preservation(self):
        from differential import states
        from unicorn import arm64_const as arm
        for form in ('SETF8', 'SETF16'):
            for source in (1, 31):
                words = [arithmetic.flag_encoding(form, source), arithmetic.RET]
                original = arithmetic.reusable_reference(struct.pack('<2I', *words), arm.UC_CPU_ARM64_MAX)
                for value in arithmetic.flag_values({'form': form, 'source': source}):
                    for initial in states(all_flags=True):
                        initial.x[1], initial.sp = value, arithmetic.MASK
                        expected = arithmetic.flag_reference(words, initial)
                        self.assertEqual(original(initial), expected)
                        self.assertEqual(expected['nzcv'] & arithmetic.CARRY_FLAG, initial.nzcv & arithmetic.CARRY_FLAG)
                        if source == 31:
                            self.assertEqual(expected['nzcv'], (initial.nzcv & arithmetic.CARRY_FLAG) | 0x40000000)
        initial = State()
        initial.x[1] = 0xdeadc0de00000100
        self.assertEqual(arithmetic.flag_reference([arithmetic.flag_encoding('SETF8'), arithmetic.RET], initial)['nzcv'],
                         0x50000000)

    def test_flag_dependency_chains_use_fresh_guest_flags_after_host_clobbers(self):
        from differential import states
        from unicorn import arm64_const as arm
        for case in arithmetic.flag_cases():
            if not case['kind'].endswith('_chain'):
                continue
            words = case['words']
            original = arithmetic.reusable_reference(struct.pack('<' + 'I' * len(words), *words), arm.UC_CPU_ARM64_MAX)
            for value in arithmetic.flag_values(case):
                for initial in states(all_flags=True):
                    if value is not None:
                        initial.x[case['source']] = value
                    self.assertEqual(original(initial), arithmetic.flag_reference(words, initial))


class IntegerMathOracleTests(unittest.TestCase):
    def test_crc_known_vectors_polynomial_difference_and_uncomplemented_updates(self):
        import zlib
        for castagnoli, expected in ((False, 0xcbf43926), (True, 0xe3069283)):
            accumulator = 0xffffffff
            for byte in b'123456789':
                accumulator = math.crc_reference(accumulator, byte, 8, castagnoli)
            self.assertEqual(accumulator ^ 0xffffffff, expected)
        self.assertEqual(zlib.crc32(b'123456789'), 0xcbf43926)
        for castagnoli in (False, True):
            self.assertEqual(math.crc_reference(0, 0, 64, castagnoli), 0)
            for bits in (8, 16, 32, 64):
                self.assertEqual(math.crc_reference(0xdeadc0de12345678, math.MASK, bits, castagnoli),
                                 math.crc_reference(0x12345678, (1 << bits) - 1, bits, castagnoli))
                value, accumulator = 0x0123456789abcdef, 0x76543210
                folded = accumulator
                for byte in value.to_bytes(8, 'little')[:bits // 8]:
                    folded = math.crc_reference(folded, byte, 8, castagnoli)
                self.assertEqual(math.crc_reference(accumulator, value, bits, castagnoli), folded)

    def test_crc_affine_power_matches_literal_repeated_updates(self):
        state = State()
        state.x[0], state.x[2] = 0xdeadc0de12345678, 0x0123456789abcdef
        for form, word in math.CRC_FORMS.items():
            for count in (1, 2, 3, 31, 128):
                value = state.x[0]
                for _ in range(count):
                    value = math.crc_reference(value, state.x[2], math.crc_data_bits(word),
                                               bool(word & math.CRC_CASTAGNOLI_BIT))
                expected = complete_state(state)
                expected['x'][0] = value
                self.assertEqual(math.crc_repeated_state(form, True, state, count), expected)

    def test_crc_corpus_all_forms_register_roles_aliases_and_dirty_upper_bits(self):
        cases = math.crc_cases()
        self.assertEqual(len(cases), 362)
        for form in math.CRC_FORMS:
            words = [c['words'][0] for c in cases if c['form'] == form and c['kind'] == 'all_registers']
            for shift in (0, 5, 16):
                self.assertEqual({(word >> shift) & 31 for word in words}, set(range(32)))
            state = State()
            state.x[1], state.x[2] = math.MASK, 0x0123456789abcdef
            state.nzcv, state.reserved = 0xf0000000, 0x12345678
            word = math.encoding(form, 2, 1, 2)
            expected = complete_state(state)
            bits = 8 << ((word >> 10) & 3)
            expected['x'][2] = math.crc_reference(state.x[1], state.x[2], bits, bool(word & (1 << 12)))
            self.assertEqual(math.mathematical_reference([word, math.RET], state), expected)
            word = math.encoding(form, 31, 31, 31)
            self.assertEqual(math.mathematical_reference([word, math.RET], state), complete_state(state))

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


class X86MappingCatalogTests(unittest.TestCase):
    """Source integrity/search checks, never instruction-semantic evidence."""

    def test_operation_comparisons_and_sequence_warnings_are_preserved(self):
        xml = b'''<intrinsics_list version="fixture"><intrinsic name="fixture" sequence="TRUE">
          <return type="__m128i" etype="SI8"/><parameter type="__m128i" etype="SI8" varname="a"/>
          <description>signed saturation</description><operation>a &lt; b AND c &gt; d</operation>
          <instruction name="PADDSB" form="xmm, xmm"/><CPUID>SSE2</CPUID>
        </intrinsic></intrinsics_list>'''
        record, = x86_mappings.intrinsic_records(xml, {'url': 'fixture', 'sha256': 'source-hash'})
        self.assertEqual(record['operation'], 'a < b AND c > d')
        self.assertEqual(record['sequence'], 'TRUE')
        self.assertEqual(record['parameters'][0]['etype'], 'SI8')
        self.assertIsNone(record['flags'])

    def test_xml_and_tar_inputs_have_explicit_safety_bounds(self):
        for xml in (b'<!DOCTYPE x><intrinsics_list/>', b'<!ENTITY x "value"><intrinsics_list/>',
                    '<!DOCTYPE x><intrinsics_list/>'.encode('utf-16')):
            with self.assertRaisesRegex(ValueError, 'DTD/entity'):
                x86_mappings.parse_intrinsics(xml)
        with self.assertRaisesRegex(ValueError, 'not Intel Intrinsics'):
            x86_mappings.parse_intrinsics(b'<unrelated/>')

        def make_archive(names):
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w:gz') as tar:
                for name in names:
                    member = tarfile.TarInfo(name)
                    member.size = 1
                    tar.addfile(member, io.BytesIO(b'x'))
            return archive.getvalue()

        with self.assertRaisesRegex(ValueError, 'unsafe'):
            list(x86_mappings.xed_files(make_archive(['xed/datafiles/../../outside.txt'])))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            list(x86_mappings.xed_files(make_archive(['xed/datafiles/test.txt'] * 2)))
        oversized = tarfile.TarInfo('xed/ignored.bin')
        oversized.size = 16 * 1024 * 1024 + 1
        with self.assertRaisesRegex(ValueError, 'expanded member/total byte bounds'):
            list(x86_mappings.xed_files(oversized.tobuf() + bytes(1024)))
        self.assertEqual(list(x86_mappings.xed_files(make_archive(['xed/datafiles/test.txt']))),
                         [('datafiles/test.txt', 'x')])

    def test_xed_preserves_source_patterns_flags_and_explicit_isa_cpuid(self):
        source = dict(revision='a' * 40, sha256='archive-hash')
        cpuid = x86_mappings.cpuid_records([('datafiles/cpuid.xed.txt',
            'XED_ISA_SET_SSE2: sse2.1.0.edx.26\n')], source)
        text = '''INSTRUCTIONS()::
{
ICLASS: PADDSB
EXTENSION: SSE2
FLAGS: MUST [ zf-mod ]
PATTERN: first
OPERANDS: REG0:rw
IFORM: FIRST
PATTERN: second
OPERANDS: REG0:rw MEM0:r
}
'''
        record, = x86_mappings.xed_records(text, 'datafiles/fixture.txt', source, cpuid)
        self.assertEqual(record['patterns'], [{'pattern': 'first', 'operands': 'REG0:rw', 'iform': 'FIRST'},
                                               {'pattern': 'second', 'operands': 'REG0:rw MEM0:r'}])
        self.assertEqual(record['flags'], ['MUST [ zf-mod ]'])
        self.assertEqual(record['cpuid']['SSE2'][0]['raw'], 'sse2.1.0.edx.26')
        self.assertIsNone(record['operation'])
        self.assertEqual(record['reference']['locator'], 'datafiles/fixture.txt:2')
        with self.assertRaisesRegex(ValueError, 'unclosed'):
            list(x86_mappings.xed_records(text[:-2], 'fixture', source, cpuid))

    def test_build_query_limits_and_mutation_checks_without_external_sources(self):
        xml = b'''<intrinsics_list><intrinsic name="fixture"><return type="__m128i"/>
          <description>signed saturation</description><operation>1234567890''' + b'x' * 8000 + b'''</operation>
          <instruction name="PADDSB"/><CPUID>SSE2</CPUID></intrinsic></intrinsics_list>'''
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as tar:
            data = b'INSTRUCTIONS()::\n{\nICLASS: PADDSB\nEXTENSION: SSE2\nPATTERN: fixture\nOPERANDS: REG0:rw\n}\n'
            member = tarfile.TarInfo('xed-fixture/datafiles/xed-isa.txt')
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = []
            for kind, data in [('intrinsics', xml), ('xed', archive.getvalue())]:
                sources.append(dict(kind=kind, url='fixture' if kind == 'intrinsics' else
                    'https://codeload.github.com/intelxed/xed/tar.gz/' + 'a' * 40, revision='a' * 40,
                    sha256=x86_mappings.digest(data), bytes=len(data),
                    blob=x86_mappings.save_content(root, 'blobs', data, '.fixture')))
            manifest = x86_mappings.canonical(dict(sources=sources))
            current = dict(manifest=x86_mappings.save_content(root, 'manifests', manifest, '.json'),
                           manifest_sha256=x86_mappings.digest(manifest))
            x86_mappings.write_current(root, current)
            built = x86_mappings.build(argparse.Namespace(root=root))
            self.assertEqual(built['counts']['intrinsics'], 1)
            self.assertEqual(built['counts']['xed_source_patterns'], 1)
            with patch.object(x86_mappings.urllib.request, 'urlopen', side_effect=AssertionError('unexpected network access')):
                reused = x86_mappings.fetch(argparse.Namespace(root=root, intrinsics_url='fixture',
                    intrinsics_sha256=x86_mappings.digest(xml), xed_revision='a' * 40, refresh=False))
                self.assertTrue(reused['reused'])
            self.assertEqual(x86_mappings.read_current(root)['index'], built['index'])
            args = argparse.Namespace(root=root, kind='all', mnemonic=['paddsb'], feature=['SSE2'],
                                      words=['saturation'], limit=1, chars=4, patterns=1, budget=8000)
            result = x86_mappings.query(args)
            self.assertEqual((result['matches'], result['returned']), (1, 1))
            self.assertEqual(result['results'][0]['operation'], '1234')
            self.assertEqual(result['results'][0]['operation_truncated_chars'], 8006)
            args.chars, args.budget = 12000, 2048
            bounded = x86_mappings.query(args)
            self.assertEqual((bounded['returned'], bounded['omitted_by_budget']), (0, 1))
            self.assertLessEqual(len(json.dumps(bounded, ensure_ascii=False)) + 1, 2048)
            args.words, args.mnemonic = [], ['does_not_exist']
            self.assertEqual(x86_mappings.query(args)['matches'], 0)
            x86_mappings.stats(argparse.Namespace(root=root, command='verify'))
            source_path = root / sources[0]['blob']
            source_path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'source hash/size mismatch'):
                x86_mappings.stats(argparse.Namespace(root=root, command='verify'))
            source_path.write_bytes(xml)
            current = x86_mappings.read_current(root)
            (root / current['index']).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'index SHA256 mismatch'):
                x86_mappings.stats(argparse.Namespace(root=root, command='verify'))
            with self.assertRaisesRegex(ValueError, 'escapes catalog root'):
                x86_mappings.safe_artifact(root, '../outside')


if __name__ == "__main__":
    unittest.main()
