"""Independent encoding/coverage and SIMD byte-oracle regression checks."""
import ctypes
from contextlib import nullcontext
import importlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import State, state_dict, seed_extended_state

suite = importlib.import_module('simd-differential')


class SimdDifferentialTests(unittest.TestCase):
    def test_bfloat16_inventory_covers_all_shapes_indices_and_alias_roles(self):
        functions = suite.bfloat16_functions()
        facts = {row['id']: row for row in json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        self.assertEqual((len(functions), len({op['word'] for op in functions})), (202, 202))
        self.assertEqual(len({op['canonical_id'] for op in functions}), 7)
        self.assertEqual(len({suite.bfloat16_shape(op) for op in functions}), 12)
        self.assertEqual(len({(suite.bfloat16_shape(op), op['index']) for op in functions}), 32)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for op in functions:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            decoded = list(decoder.disasm(struct.pack('<I', op['word']), 0))
            self.assertEqual([instruction.mnemonic for instruction in decoded], [op['name']])
            if op['kind'] == 'multiply' and op['index'] is not None:
                self.assertLess(op['m'], 16)
            if op['kind'] == 'conversion':
                self.assertNotIn('a', op)
            else:
                self.assertEqual(op['a'], op['d'])
        for args, options in ((('dot', 8), {}), (('conversion', 16), {}),
                (('multiply', 16), {'m':16, 'index':7}), (('matrix', 8), {'m':2})):
            with self.assertRaises(ValueError):
                suite.bfloat16_operation(*args, **options)

    def test_bfloat16_mnemonics_reach_mocked_compiler_for_every_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(suite.subprocess, 'check_output', side_effect=RuntimeError('reached mocked compiler')) as compile_call:
                for index, op in enumerate(suite.bfloat16_functions()):
                    with self.assertRaisesRegex(RuntimeError, 'reached mocked compiler'):
                        suite.compile_batch(Path('mock-stela'), Path(temporary), [{'operations': [op]}], index, block=True)
                self.assertEqual(compile_call.call_count, 202)

    def test_bfloat16_unavailable_supplementary_oracle_has_no_equality_credit(self):
        initial = State()
        initial.x[30] = suite.STOP
        op = suite.bfloat16_operation('dot', 8, m=2)
        record = {'function': 0, 'operation': op, 'initial': bytes(initial), 'expected': bytes(initial),
            'unsupported': False, 'case': 0, 'producer': 'unit_supplementary_unavailable'}
        batch = {'source': struct.pack('<II', op['word'], suite.RET), 'native': b'',
            'cohort': suite.BFLOAT16_NUMERICAL_FOCUS}
        def wrapper(state, address, mxcsr, exit_pointer):
            observed = ctypes.cast(exit_pointer, ctypes.POINTER(suite.NumericalNativeExit)).contents
            observed.kind, observed.next_pc = suite.NUMERICAL_RETURN_EXIT, suite.STOP
            observed.mxcsr_before = observed.mxcsr_after = mxcsr
        machine = Mock()
        with patch.object(suite, 'executable', side_effect=lambda _: nullcontext(0)), \
                patch.object(suite.ctypes, 'CFUNCTYPE', return_value=lambda _: wrapper), \
                patch.object(suite, 'Uc', return_value=machine):
            counts = suite.execute_numerical_batches([batch], {'records': [record]})
        machine.emu_start.assert_not_called()
        self.assertEqual(counts['unicorn_original_unavailable_cases'], 1)
        self.assertEqual(counts['unicorn_original_complete_state_comparisons'], 0)
        self.assertEqual(counts['raw_inline_original_complete_state_comparisons'], 1)
        self.assertEqual(counts['caller_mxcsr_preservation_comparisons'], 16)

    def test_bfloat16_staging_selects_full_vm_and_interleaved_parity(self):
        op = suite.bfloat16_operation('multiply', 16, m=2, index=7, parity=1)
        initial = suite.bfloat16_state(op, 0, [1, 2, 3, 4], [5, 6, 7, 8], [9])
        left = struct.unpack('<8H', struct.pack('<2Q', *initial.v[1]))
        right = struct.unpack('<8H', struct.pack('<2Q', *initial.v[2]))
        self.assertEqual(left[1::2], (5, 6, 7, 8))
        self.assertEqual(right[7], 9)
        self.assertTrue(all(value == suite.BFLOAT16_INFINITY | 1 for value in left[::2]))
        self.assertEqual(struct.unpack('<4I', struct.pack('<2Q', *initial.v[0])), (1, 2, 3, 4))
        op = suite.bfloat16_operation('dot', 8, m=31, index=3)
        initial = suite.bfloat16_state(op, 1, [1, 2], [3, 4, 5, 6], [7, 8])
        self.assertEqual(struct.unpack('<8H', struct.pack('<2Q', *initial.v[31]))[6:], (7, 8))

    def test_bfloat16_closed_integer_models_cover_rounding_and_domain_refusal(self):
        left, right = (0x3f80, 0x3980), (0x3f80, 0x3900)
        for ah in (0, suite.NUMERICAL_AH):
            for mode in range(4):
                control = ah | mode << suite.NUMERICAL_ROUND_SHIFT | suite.BFLOAT16_EBF
                standard = suite.bfloat16_standard_dot(control, 0xbf800000, left, right)
                self.assertEqual(standard, 0x34000000)
                self.assertEqual(suite.bfloat16_standard_dot(control, standard, left, right), 0x3f800002)
                enhanced = suite.bfloat16_enhanced_dot(control, 0xbf800000, left, right)
                self.assertEqual(enhanced, 0x34000000 if mode == 1 else 0x80000000 if mode == 2 else 0)
                self.assertEqual(suite.bfloat16_enhanced_dot(control, enhanced, left, right), 0x3f800002 if mode == 1 else 0x3f800000)
        for model, addend, lhs in ((suite.bfloat16_standard_dot, 0x7fc00000, left),
                (suite.bfloat16_enhanced_dot, 0, (1, 0x3f80))):
            with self.assertRaises(suite.Bfloat16ModelDomainError):
                model(0, addend, lhs, right)

    def test_bfloat16_profile_validates_unmodified_enhanced_original(self):
        producer = {'cpu_registers': {'ID_AA64ISAR1_EL1': '0x111211110211502'}}
        for kind in ('dot', 'matrix'):
            op = suite.bfloat16_operation(kind, 16, m=2)
            initial = suite.bfloat16_state(op, 0, [0xbf800000] * 4, [0x3f80, 0x3980] * 4, [0x3f80, 0x3900] * 4, suite.BFLOAT16_EBF)
            original = suite.bfloat16_dot_profile_state(op, initial, True)
            expected = suite.bfloat16_profile_expectation(op, initial, original, producer)
            self.assertEqual(expected.v[0][0] & 0xffffffff, 0x34000000 if kind == 'dot' else 0x3f800002)
            self.assertEqual(expected.fpcr, suite.BFLOAT16_EBF)
            original.v[1][0] ^= 1
            with self.assertRaises(AssertionError):
                suite.bfloat16_profile_expectation(op, initial, original, producer)

    def test_bfloat16_enable_acceptance_and_reserved_policy_are_separate(self):
        for kind, width in (('conversion', 2), ('dot', 8), ('multiply', 16), ('matrix', 16)):
            op = suite.bfloat16_operation(kind, width, m=None if kind == 'conversion' else 2)
            for ah in (0, suite.NUMERICAL_AH):
                initial = State()
                initial.fpcr = suite.BFLOAT16_EBF | suite.NUMERICAL_TRAP_ENABLE_MASK | ah
                self.assertEqual(suite.bfloat16_accepts_enabled_control(op, initial), kind in ('dot', 'matrix') or bool(ah))
                self.assertEqual(suite.bfloat16_control_policy(op, initial, {}), kind in ('conversion', 'multiply'))
        family = suite.FULL_FRAME_NUMERICAL_COHORTS[suite.BFLOAT16_NUMERICAL_FOCUS]
        self.assertFalse(family['supplementary_original_available'])
        self.assertEqual(family['supplementary_original_evidence']['sha256'], '838e4d9f084c88f790eacdb952da88255b1d389e3c10e1c91afe381f9f8723b3')
        for op in suite.bfloat16_functions():
            expected = {'vfmadd132ps': 1} if op['kind'] == 'multiply' else {}
            self.assertEqual(suite.numerical_fma_expectation(op, 'x86_64-baseline+fma', family['native_fma_operations']), expected)
            self.assertTrue(suite.numerical_fma_accounting_matches(op, 'x86_64-baseline+f16c', {}, family))
            self.assertFalse(suite.numerical_fma_accounting_matches(op, 'x86_64-baseline+f16c', {'vfmadd132ps': 1}, family))

    def test_bfloat16_corpus_is_bounded_and_helpers_have_distinct_fixed_sources(self):
        functions, cases = suite.bfloat16_corpus()
        self.assertEqual(len(cases), 21002)
        self.assertEqual({record['function'] for record in cases}, set(range(202)))
        imported = [dict(record, operation=functions[record['function']]) for record in cases]
        helpers = suite.bfloat16_helpers(imported)
        self.assertEqual((len(suite.bfloat16_runtime_cases(imported)), len(helpers)), (315, 12))
        self.assertEqual(suite.bfloat16_helpers(imported, set()), [])
        self.assertLessEqual(315 + 6 * len(helpers), 425)
        self.assertEqual(sum(record['label'] == 'exact_cancel' for record in cases), 40)
        self.assertEqual(sum(record['label'] == 'matrix_stage_order' for record in cases), 8)
        for record in helpers:
            op = record['operation']
            initial = State.from_buffer_copy(record['initial'])
            self.assertEqual(record['label'], 'helper_quiet_nan')
            self.assertEqual((op['d'], op['n']), (0, 1))
            if op['kind'] == 'conversion':
                self.assertEqual(initial.v[1][0] & 0xffffffff, 0x7fc00003)
            else:
                self.assertEqual(op['m'], 2)
                self.assertEqual(initial.v[0][0] & 0xffffffff, 0x7fc00000)
            self.assertEqual((initial.fpcr, initial.fpsr), (0, 0))

    def test_widening_encodings_cover_every_form_width_layout_and_alias(self):
        facts = {row['id']: row for row in json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        functions = suite.widening_functions()
        self.assertEqual((len(functions), len({op['word'] for op in functions})), (496, 496))
        self.assertEqual(len({op['canonical_id'] for op in functions}), 8)
        self.assertEqual(len({suite.widening_shape(op) for op in functions}), 16)
        self.assertEqual(len({(suite.widening_shape(op), op['index']) for op in functions}), 72)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for op in functions:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            decoded = list(decoder.disasm(struct.pack('<I', op['word']), 0))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0].mnemonic, op['name'])
            self.assertEqual((op['lane'], op['source_lane'], op['a']), (4, 2, op['d']))
            self.assertEqual(op['source_lane_offset'], op['bytes'] // 4 if op['upper'] else 0)
            if op['index'] is not None:
                self.assertLess(op['m'], 16)
        for args, options in ((('fmla', 8), {}), (('fmlal', 4), {}),
                (('fmlal', 8), {'m': 16, 'index': 0}), (('fmlsl2', 16), {'index': 8})):
            with self.assertRaises(ValueError):
                suite.widening_operation(*args, **options)

    def test_widening_source_parts_indices_and_accumulator_snapshot_are_distinct(self):
        triples = [(0x3f800000, 0x4000, 0x3800), (0x40000000, 0x4200, 0x3800)]
        op = suite.widening_operation('fmlal2', 8)
        initial = suite.widening_state(op, 0, triples, suite.NUMERICAL_NEP)
        left = struct.unpack('<8H', struct.pack('<2Q', *initial.v[1]))
        right = struct.unpack('<8H', struct.pack('<2Q', *initial.v[2]))
        self.assertEqual(left[2:4], (0x4000, 0x4200))
        self.assertEqual(right[2:4], (0x3800, 0x3800))
        self.assertEqual(left[:2], (0x7c05, 0x7c05))
        self.assertEqual(initial.v[0][0], 0x400000003f800000)
        indexed = suite.widening_operation('fmlal2', 8, index=7)
        initial = suite.widening_state(indexed, 1, triples)
        right = struct.unpack('<8H', struct.pack('<2Q', *initial.v[2]))
        self.assertEqual(right[7], 0x3800)
        self.assertEqual(right[:7], (0x7c05,) * 7)
        alias = suite.widening_operation('fmlal2', 8, d=1, n=1)
        initial = suite.widening_state(alias, 2, triples)
        self.assertEqual(struct.unpack('<8H', struct.pack('<2Q', *initial.v[1]))[2:4], (0x4000, 0x4200))
        self.assertNotEqual(initial.v[1][0], 0x400000003f800000)
        with self.assertRaises(ValueError):
            suite.widening_state(op, 0, [(0x3f800000, 0x10000, 0x3c00)] * 2)

    def test_widening_original_nan_classes_are_not_prequieted_or_prenegated(self):
        triples = {label: (addend, left, right) for label, addend, left, right in suite.widening_triples()}
        self.assertEqual(triples['left_snan_positive'][1], 0x7c05)
        self.assertEqual(triples['right_snan_negative'][2], 0xfc05)
        self.assertEqual(triples['addend_snan_negative'][0], 0xff800005)
        op = suite.widening_operation('fmlsl2', 8)
        initial = suite.widening_state(op, 0, [triples['left_snan_positive']] * 2, suite.NUMERICAL_AH)
        self.assertEqual((initial.v[1][0] >> 32) & 0xffff, 0x7c05)
        self.assertEqual(triples['cancel_negative'], (0xbf800000, 0x3c01, 0x3bfe))

    def test_widening_mnemonics_reach_mocked_compiler_for_every_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(suite.subprocess, 'check_output', side_effect=RuntimeError('reached mocked compiler')) as compile_call:
                for index, op in enumerate(suite.widening_functions()):
                    with self.assertRaisesRegex(RuntimeError, 'reached mocked compiler'):
                        suite.compile_batch(Path('mock-stela'), Path(temporary), [{'operations': [op]}], index, block=True)
                self.assertEqual(compile_call.call_count, 496)

    def test_widening_optional_fma_still_requires_exact_opcode_and_capability(self):
        family = suite.FULL_FRAME_NUMERICAL_COHORTS[suite.WIDENING_NUMERICAL_FOCUS]
        for name, mnemonic in (('fmlal', 'vfmadd132ps'), ('fmlsl2', 'vfnmadd132ps')):
            op = suite.widening_operation(name, 16)
            for target in ('x86_64-baseline', 'x86_64-baseline+f16c'):
                self.assertTrue(suite.numerical_fma_accounting_matches(op, target, {}, family))
                self.assertFalse(suite.numerical_fma_accounting_matches(op, target, {mnemonic: 1}, family))
            for target in ('x86_64-baseline+fma', 'x86_64-baseline+f16c+fma'):
                self.assertTrue(suite.numerical_fma_accounting_matches(op, target, {}, family))
                self.assertTrue(suite.numerical_fma_accounting_matches(op, target, {mnemonic: 1}, family))
                self.assertFalse(suite.numerical_fma_accounting_matches(op, target, {mnemonic: 2}, family))
                self.assertFalse(suite.numerical_fma_accounting_matches(op, target, {'vfmadd213ps': 1}, family))
        old = suite.FULL_FRAME_NUMERICAL_COHORTS[suite.FUSED_NUMERICAL_FOCUS]
        op = suite.fused_numerical_operation('fmadd', 4, 4, True, 0, 1, 2, 3)
        self.assertFalse(suite.numerical_fma_accounting_matches(op, 'x86_64-baseline+fma', {}, old))
        self.assertNotIn('accepts_enabled_control', family)
        self.assertNotIn('profile_expectation', family)

    def test_widening_cache_helper_is_a_quiet_nan_fixed_point(self):
        functions, cases = suite.widening_corpus()
        records = [dict(case, operation=functions[case['function']]) for case in cases]
        helpers = suite.widening_helpers(records)
        self.assertEqual(len(helpers), 16)
        for record in helpers:
            op = record['operation']
            initial = State.from_buffer_copy(record['initial'])
            self.assertEqual(record['label'], 'directed_addend_qnan_positive')
            self.assertEqual((op['d'], op['n'], op['m']), (0, 1, 2))
            self.assertEqual((initial.fpcr, initial.fpsr), (0, 0))
            accumulator = struct.unpack('<4I', struct.pack('<2Q', *initial.v[op['d']]))
            self.assertEqual(accumulator[:op['source_lane_count']], (0x7fc00003,) * op['source_lane_count'])
            for register in (op['n'], op['m']):
                source = struct.unpack('<8H', struct.pack('<2Q', *initial.v[register]))
                positions = [op['index']] if register == op['m'] and op['index'] is not None else range(op['source_lane_offset'], op['source_lane_offset'] + op['source_lane_count'])
                self.assertTrue(all(source[position] == 0x3c00 for position in positions))
            # A sole quiet Single NaN plus normal Half multiplicands preserves
            # its original payload/status forever. The first Q0 commit clears
            # upper64, and every following commit leaves the full state fixed.
            self.assertEqual(op['merge'], 'none')
            if op['bytes'] == 8:
                self.assertNotEqual(initial.v[op['d']][1], 0)

    def test_widening_corpus_and_runtime_are_bounded_and_all_enables_refuse(self):
        functions, cases = suite.widening_corpus()
        self.assertEqual(len(cases), 21256)
        self.assertEqual({case['function'] for case in cases}, set(range(496)))
        imported = [dict(case, operation=functions[case['function']]) for case in cases]
        self.assertEqual(sum(bool(State.from_buffer_copy(case['initial']).fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK) for case in cases), 168)
        self.assertEqual(len(suite.widening_runtime_cases(imported)), 216)
        self.assertEqual(len(suite.widening_helpers(imported)), 16)
        self.assertEqual(suite.widening_helpers(imported, set()), [])
        self.assertLessEqual(len(suite.widening_runtime_cases(imported)) + 6 * len(suite.widening_helpers(imported)), 425)

    def test_remaining_binary_forms_reach_compiler_after_independent_decode(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(suite.subprocess, 'check_output', side_effect=RuntimeError('reached mocked compiler')) as compile_call:
                for index, op in enumerate(suite.binary_remaining_functions()):
                    with self.assertRaisesRegex(RuntimeError, 'reached mocked compiler'):
                        suite.compile_batch(Path('mock-stela'), directory, [{'operations': [op]}], index, block=True)
                self.assertEqual(compile_call.call_count, 636)

    def test_remaining_binary_encodings_cover_every_form_width_index_and_alias(self):
        facts = {row['id']: row for row in json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        functions = suite.binary_remaining_functions()
        self.assertEqual((len(functions), len({op['word'] for op in functions})), (636, 636))
        self.assertEqual(len({op['canonical_id'] for op in functions}), 23)
        self.assertEqual(len({suite.binary_remaining_shape(op) for op in functions}), 43)
        self.assertEqual(len({(suite.binary_remaining_shape(op), op['index']) for op in functions}), 107)
        for op in functions:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            decoded = list(decoder.disasm(struct.pack('<I', op['word']), 0))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0].mnemonic, op['name'])
            if op['index'] is not None and op['lane'] == 2:
                self.assertLess(op['m'], 16)
            if op['input_kind'] == 'scalar_pair':
                self.assertIsNone(op['m'])
                self.assertEqual(op['source_lane_count'], 2)
                self.assertEqual(op['merge'], 'none')
        for args, keywords in ((('fnmul', 4, 16, False), {}), (('faddp', 2, 2, True), {}),
                (('fmulx', 8, 8, False), {}), (('fmul', 2, 8, False), {'m': 16, 'index': 0}),
                (('fmul', 8, 16, False), {'index': 2})):
            with self.assertRaises(ValueError):
                suite.binary_remaining_operation(*args, **keywords)

    def test_remaining_binary_state_preserves_pair_order_and_upper_index_selection(self):
        op = suite.binary_remaining_operation('faddp', 2, 8, False)
        state = suite.binary_remaining_state(op, 0, [(1, 2), (3, 4), (5, 6), (7, 8)])
        self.assertEqual(struct.unpack('<8H', struct.pack('<2Q', *state.v[1])), (1, 2, 3, 4, 0x7c05, 0x7c05, 0x7c05, 0x7c05))
        self.assertEqual(struct.unpack('<4H', struct.pack('<Q', state.v[2][0])), (5, 6, 7, 8))
        scalar = suite.binary_remaining_operation('faddp', 2, 2, True, m=None)
        state = suite.binary_remaining_state(scalar, 1, [(0x3c00, 0x4000)])
        self.assertEqual(state.v[1][0] & 0xffffffff, 0x40003c00)
        self.assertNotEqual(state.v[1][0] >> 32, 0)
        indexed = suite.binary_remaining_operation('fmul', 4, 8, False, index=3)
        state = suite.binary_remaining_state(indexed, 2, [(0x3f800000, 0x40000000), (0x40400000, 0x40000000)])
        self.assertEqual(state.v[1][0], 0x404000003f800000)
        self.assertEqual(state.v[2][1] >> 32, 0x40000000)
        self.assertNotEqual(state.v[2][0] & 0xffffffff, 0x40000000)

    def test_remaining_binary_scalar_nep_merges_left_but_pair_clears(self):
        for name, m in (('fnmul', 2), ('fabd', 2), ('faddp', None)):
            op = suite.binary_remaining_operation(name, 4, 4, True, m=m)
            initial = suite.binary_remaining_state(op, 0, [(0x3f800000, 0x40000000)], suite.NUMERICAL_NEP)
            original = State.from_buffer_copy(initial)
            original.v[0][:] = initial.v[1] if name != 'faddp' else (0, 0)
            original.v[0][0] = original.v[0][0] & ~0xffffffff | 0x40400000
            suite.validate_binary_remaining_original_effects(initial, original, op)
            original.v[0][1] ^= 1
            with self.assertRaises(AssertionError):
                suite.validate_binary_remaining_original_effects(initial, original, op)
        descriptor = suite.FULL_FRAME_NUMERICAL_COHORTS[suite.BINARY_REMAINING_FOCUS]
        self.assertNotIn('accepts_enabled_control', descriptor)
        self.assertNotIn('profile_expectation', descriptor)
        self.assertNotIn('native_fma_operations', descriptor)

    def test_remaining_binary_corpus_and_runtime_stay_within_approved_budget(self):
        functions, cases = suite.binary_remaining_corpus()
        self.assertEqual(len(cases), 33518)
        imported = [dict(case, operation=functions[case['function']]) for case in cases]
        self.assertEqual(sum(bool(State.from_buffer_copy(case['initial']).fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK) for case in cases), 462)
        self.assertEqual({case['function'] for case in cases}, set(range(636)))
        self.assertEqual(len(suite.binary_remaining_runtime_cases(imported)), 363)
        self.assertEqual(len(suite.binary_remaining_helpers(imported)), 43)
        self.assertEqual(suite.binary_remaining_helpers(imported, set()), [])
        self.assertLessEqual(len(suite.binary_remaining_runtime_cases(imported)) + 6 * len(suite.binary_remaining_helpers(imported)), 621)

    def test_fullframe_fma_expectations_follow_family_and_independent_host_capability(self):
        families = suite.FULL_FRAME_NUMERICAL_COHORTS
        fused = families[suite.FUSED_NUMERICAL_FOCUS]['native_fma_operations']
        refinement = families[suite.REFINEMENT_NUMERICAL_FOCUS]['native_fma_operations']
        self.assertIs(fused, suite.FUSED_NATIVE_OPERATIONS)
        self.assertEqual(refinement, {'frecps': 'vfnmadd', 'frsqrts': 'vfnmadd'})
        single = suite.refinement_operation('frecps', 4, 4, True)
        double = suite.refinement_operation('frsqrts', 8, 16, False)
        half = suite.refinement_operation('frecps', 2, 2, True)
        self.assertEqual(suite.numerical_fma_expectation(single, 'x86_64-baseline+fma', refinement), {'vfnmadd132ss': 1})
        self.assertEqual(suite.numerical_fma_expectation(double, 'x86_64-baseline+fma', refinement), {'vfnmadd132pd': 1})
        self.assertEqual(suite.numerical_fma_expectation(half, 'x86_64-baseline+fma+f16c', refinement), {})
        self.assertEqual(suite.numerical_fma_expectation(single, 'x86_64-baseline+f16c', refinement), {})
        self.assertEqual(suite.numerical_fma_expectation(single, 'x86_64-baseline', refinement), {})
        estimate = families[suite.ESTIMATE_NUMERICAL_FOCUS].get('native_fma_operations')
        self.assertIsNone(estimate)
        self.assertEqual(suite.numerical_fma_expectation(single, 'x86_64-baseline+fma', estimate), {})

    def test_estimate_and_refinement_words_match_all_reviewed_forms(self):
        facts = {row['id']: row for row in json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for functions, words, forms, arrangements in ((suite.estimate_functions(), 92, 12, 23), (suite.refinement_functions(), 96, 8, 16)):
            self.assertEqual((len(functions), len({op['word'] for op in functions})), (words, words))
            self.assertEqual(len({op['canonical_id'] for op in functions}), forms)
            self.assertEqual(len({suite.numerical_unary_shape(op) for op in functions}), arrangements)
            for op in functions:
                fact = facts[op['canonical_id']]
                self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
                decoded = list(decoder.disasm(struct.pack('<I', op['word']), 0))
                self.assertEqual(len(decoded), 1)
                self.assertEqual(decoded[0].mnemonic, op['name'])
        for args in (('urecpe', 4, 4, True), ('ursqrte', 8, 16, False), ('frecpx', 4, 8, False), ('frecpe', 8, 8, False)):
            with self.assertRaises(ValueError):
                suite.estimate_operation(*args)

    def test_estimate_integer_profile_split_preserves_raw_controls_status_and_nep(self):
        op = suite.estimate_operation('frecpe', 4, 4, True)
        initial = suite.numerical_unary_state(op, 0, [0x3f800000], suite.NUMERICAL_AH | suite.NUMERICAL_NEP | suite.NUMERICAL_TRAP_ENABLE_MASK, 0x0800009f)
        standard = suite.estimate_single_profile_state(op, initial, False)
        enhanced = suite.estimate_single_profile_state(op, initial, True)
        self.assertEqual(standard.v[0][0] & 0xffffffff, 0x3f7f8000)
        self.assertEqual(enhanced.v[0][0] & 0xffffffff, 0x3f7ff000)
        self.assertEqual(standard.fpsr, initial.fpsr)
        self.assertEqual(standard.fpcr, initial.fpcr)
        self.assertEqual(standard.v[0][1], initial.v[0][1])
        enhanced.fpcr &= ~suite.NUMERICAL_TRAP_ENABLE_MASK
        derived = suite.estimate_profile_expectation(op, initial, enhanced, {'cpu_registers': {'ID_AA64ISAR2_EL1': '0x110012'}})
        self.assertEqual(bytes(derived), bytes(standard))
        enhanced.v[31][0] ^= 1
        with self.assertRaises(AssertionError):
            suite.estimate_profile_expectation(op, initial, enhanced, {'cpu_registers': {'ID_AA64ISAR2_EL1': '0x110012'}})
        for name in ('frecpe', 'frsqrte'):
            op = suite.estimate_operation(name, 4, 4, True)
            for raw, expected in ((0x80000001, 0xff800000), (0, 0x7f800000), (0x7f800005, 0x7fc00005)):
                state = suite.numerical_unary_state(op, 0, [raw], suite.NUMERICAL_AH)
                self.assertEqual(suite.estimate_single_profile_state(op, state, False).v[0][0], expected)
            coincident = suite.numerical_unary_state(op, 0, [0], suite.NUMERICAL_AH)
            original = suite.estimate_single_profile_state(op, coincident, True)
            self.assertIsNotNone(suite.estimate_profile_expectation(op, coincident, original, {'cpu_registers': {'ID_AA64ISAR2_EL1': '0x110012'}}))

    def test_estimate_and_refinement_enabled_control_boundaries_are_operation_specific(self):
        initial = State()
        initial.fpcr = suite.NUMERICAL_TRAP_ENABLE_MASK
        for name in ('urecpe', 'ursqrte'):
            self.assertTrue(suite.numerical_suppressed_enables(suite.estimate_operation(name, 4, 8, False), initial))
        for op in (suite.estimate_operation('frecpx', 4, 4, True), suite.refinement_operation('frsqrts', 4, 4, True)):
            self.assertFalse(suite.numerical_suppressed_enables(op, initial))
            initial.fpcr |= suite.NUMERICAL_AH
            self.assertTrue(suite.numerical_suppressed_enables(op, initial))
            initial.fpcr &= ~suite.NUMERICAL_AH

    def test_refinement_scalar_merges_original_left_and_rejects_unsuppressed_ah_status(self):
        op = suite.refinement_operation('frecps', 4, 4, True)
        initial = suite.vector_numerical_state(op, 0, [(0x3f800000, 0x3f800000)], suite.NUMERICAL_NEP)
        original = State.from_buffer_copy(initial)
        original.v[0][:] = initial.v[1]
        original.v[0][0] = original.v[0][0] & ~0xffffffff | 0x3f800000
        suite.validate_refinement_original_effects(initial, original, op)
        original.v[0][1] = initial.v[0][1]
        with self.assertRaises(AssertionError):
            suite.validate_refinement_original_effects(initial, original, op)
        initial.fpcr = suite.NUMERICAL_AH
        original = State.from_buffer_copy(initial)
        original.v[0][:] = [0, 0]
        original.fpsr = 1
        with self.assertRaises(AssertionError):
            suite.validate_refinement_original_effects(initial, original, op)
        self.assertEqual(suite.refinement_pairs(2)[34], (0x3c01, 0x3ffe))
        self.assertEqual(suite.refinement_pairs(2)[35], (0x3c02, 0x41fd))
        self.assertEqual(suite.refinement_pairs(2)[36], (0x5c00, 0x5c00))

    def test_reciprocal_corpus_and_cli_budgets_remain_bounded(self):
        for generate, select, expected_frames, expected_selected in ((suite.estimate_corpus, suite.estimate_runtime_cases, 36734, 272),
                (suite.refinement_corpus, suite.refinement_runtime_cases, 12720, 324)):
            functions, records = generate()
            self.assertEqual(len(records), expected_frames)
            imported, refused, accepted = [], 0, 0
            for record in records:
                op, initial = functions[record['function']], State.from_buffer_copy(record['initial'])
                if initial.fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK:
                    allowed = suite.numerical_suppressed_enables(op, initial)
                    accepted += allowed
                    refused += not allowed
                imported.append(dict(record, operation=op))
            self.assertEqual((refused, accepted), (70, 98) if expected_frames==36734 else (56, 56))
            selected = select(imported)
            self.assertEqual(len(selected), expected_selected)
            self.assertLessEqual(len(selected)+6*len(suite.estimate_refinement_helpers(imported)), 425)
            self.assertEqual(suite.estimate_refinement_helpers(imported, set()), [])
        functions, records = suite.estimate_corpus()
        tables = {op['name']: set() for op in functions if op['name'] != 'frecpx'}
        for record in records:
            if record['label'].startswith('table_'):
                tables[functions[record['function']]['name']].add(int(record['label'].split('_')[1]))
        for name, keys in tables.items():
            self.assertEqual(keys, set(range(256 if name in ('frecpe', 'urecpe') else 128, 512)))

    def test_model_and_control_policy_inline_counts_are_separate_even_for_coincident_states(self):
        initial = State()
        initial.x[30] = suite.STOP
        op = suite.estimate_operation('frecpe', 4, 4, True)
        records = []
        for basis, control, policy in (('direct_original', 0, False),
                ('requested_control_policy', suite.NUMERICAL_AH|suite.NUMERICAL_TRAP_ENABLE_MASK, True),
                ('standard_profile_model', suite.NUMERICAL_AH|suite.NUMERICAL_TRAP_ENABLE_MASK, True)):
            state = State.from_buffer_copy(initial)
            state.fpcr = control
            records.append({'function': 0, 'operation': op, 'initial': bytes(state), 'expected': bytes(state),
                'equality_basis': basis, 'control_policy_success': policy, 'unsupported': False, 'case': len(records), 'producer': 'unit_accounting'})
        batch = {'source': struct.pack('<II', op['word'], suite.RET), 'native': b''}
        def wrapper(state, address, mxcsr, exit_pointer):
            observed = ctypes.cast(exit_pointer, ctypes.POINTER(suite.NumericalNativeExit)).contents
            observed.kind, observed.next_pc = suite.NUMERICAL_RETURN_EXIT, suite.STOP
            observed.mxcsr_before = observed.mxcsr_after = mxcsr
        machine = Mock()
        machine.reg_read.return_value = suite.STOP
        with patch.object(suite, 'executable', side_effect=lambda _:nullcontext(0)), \
                patch.object(suite.ctypes, 'CFUNCTYPE', return_value=lambda _:wrapper), \
                patch.object(suite, 'Uc', return_value=machine), patch.object(suite, 'initialize_arm'), \
                patch.object(suite, 'capture_arm', return_value=State.from_buffer_copy(records[0]['expected'])):
            counts = suite.execute_numerical_batches([batch], {'records': records})
        self.assertEqual(counts['raw_inline_complete_state_comparisons'], 3)
        self.assertEqual(counts['raw_inline_original_complete_state_comparisons'], 1)
        self.assertEqual(counts['raw_inline_control_policy_comparisons'], 1)
        self.assertEqual(counts['raw_inline_profile_model_comparisons'], 1)

    def test_numerical_and_fp_register_workers_visit_every_caller_mxcsr_environment(self):
        initial = State()
        initial.x[30] = suite.STOP
        operation = suite.sqrt_numerical_operation(4, 4, True)
        record = {'function': 0, 'operation': operation, 'initial': bytes(initial), 'expected': bytes(initial),
                  'unsupported': False, 'case': 0, 'producer': 'unit_control_flow'}
        batch = {'source': struct.pack('<II', operation['word'], suite.RET), 'native': b'', 'offsets': [0]}
        requested = []
        def wrapper(state, address, mxcsr, exit_pointer):
            observed = ctypes.cast(exit_pointer, ctypes.POINTER(suite.NumericalNativeExit)).contents
            observed.kind, observed.next_pc = suite.NUMERICAL_RETURN_EXIT, suite.STOP
            observed.mxcsr_before = observed.mxcsr_after = mxcsr
            requested.append(mxcsr)
        machine = Mock()
        machine.reg_read.return_value = suite.STOP
        expected = {masks | status | mode << suite.NUMERICAL_MXCSR_ROUND_SHIFT
                    for masks in (0, suite.NUMERICAL_MXCSR_ALL_MASKS)
                    for status in (0, suite.NUMERICAL_MXCSR_ALL_STATUS) for mode in range(4)}
        with patch.object(suite, 'executable', side_effect=lambda _: nullcontext(0)), \
                patch.object(suite.ctypes, 'CFUNCTYPE', return_value=lambda _: wrapper), \
                patch.object(suite, 'Uc', return_value=machine), \
                patch.object(suite, 'initialize_arm'), \
                patch.object(suite, 'capture_arm', return_value=initial), \
                patch.object(suite, 'load_fp_register_oracle', return_value={'records': [record]}), \
                patch.object(suite, 'fp_register_policy_cases', return_value=[]):
            numerical = suite.execute_numerical_batches([batch], {'records': [record]})
            self.assertEqual(numerical['caller_mxcsr_preservation_comparisons'], 16)
            self.assertEqual(set(requested[1:]), expected)
            self.assertEqual(len(requested), 17)
            requested.clear()
            registers = suite.execute_fp_register_batches([batch])
            self.assertEqual(registers['caller_mxcsr_preservation_comparisons'], 16)
            self.assertEqual(set(requested[1:]), expected)
            self.assertEqual(len(requested), 17)

    def test_sqrt_forms_arrangements_and_alias_words_match_primary_facts(self):
        functions = suite.sqrt_numerical_functions()
        self.assertEqual((len(functions), len({op['word'] for op in functions})), (32, 32))
        self.assertEqual(len({op['canonical_id'] for op in functions}), 5)
        self.assertEqual(len({suite.numerical_unary_shape(op) for op in functions}), 8)
        facts = {row['id']: row for row in json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for op in functions:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            decoded = list(decoder.disasm(struct.pack('<I', op['word']), 0))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0].mnemonic, 'fsqrt')
            self.assertEqual((op['word'] & 31, op['word'] >> 5 & 31), (op['d'], op['n']))
        for arguments in ((8, 8, False), (4, 16, True), (2, 4, False), (4, 4, True, 32)):
            with self.assertRaises(ValueError):
                suite.sqrt_numerical_operation(*arguments)

    def test_sqrt_near_midpoint_inputs_straddle_exact_squared_boundaries(self):
        for lane, fraction, bias in ((2, 10, 15), (4, 23, 127), (8, 52, 1023)):
            values = dict(suite.sqrt_numerical_values(lane))
            self.assertEqual((len(values), len(set(values.values()))), (72, 72))
            self.assertEqual(values['four_below_positive'] + 1, values['four_positive'])
            self.assertEqual(values['four_above_positive'] - 1, values['four_positive'])
            midpoints = suite.sqrt_numerical_midpoints(lane)
            roots = (1 << fraction, (1 << fraction) + 1, 3 << (fraction - 1), (1 << (fraction + 1)) - 2)
            for index, root in enumerate(roots):
                lower, upper = midpoints[index * 2][1], midpoints[index * 2 + 1][1]
                self.assertEqual(upper, lower + 1)
                scaled = []
                for raw in (lower, upper):
                    significand = (1 << fraction) | raw & ((1 << fraction) - 1)
                    exponent = (raw >> fraction) - bias
                    scaled.append(significand << (exponent + fraction + 2))
                midpoint_squared = (2 * root + 1) ** 2
                self.assertLess(scaled[0], midpoint_squared)
                self.assertGreater(scaled[1], midpoint_squared)

    def test_sqrt_reuses_unary_old_destination_merge_and_inactive_lane_contract(self):
        scalar = suite.sqrt_numerical_operation(2, 2, True)
        initial = suite.numerical_unary_state(scalar, 0, [1], suite.NUMERICAL_NEP)
        result = State.from_buffer_copy(initial)
        result.v[0][0] = result.v[0][0] & ~0xffff | 0x0c00
        suite.validate_numerical_unary_original_effects(initial, result, scalar)
        result.v[0][1] = initial.v[1][1]
        with self.assertRaises(AssertionError):
            suite.validate_numerical_unary_original_effects(initial, result, scalar)
        vector = suite.sqrt_numerical_operation(4, 8, False)
        source = suite.numerical_unary_state(vector, 0, [0x3f800000, 0x40000000])
        self.assertEqual(source.v[1][1], 0xff800005ff800005)
        cleared = State.from_buffer_copy(source)
        cleared.v[0][:] = [0, 0]
        suite.validate_numerical_unary_original_effects(source, cleared, vector)
        cleared.v[0][1] = 1
        with self.assertRaises(AssertionError):
            suite.validate_numerical_unary_original_effects(source, cleared, vector)

    def test_sqrt_corpus_controls_precise_enables_and_runtime_budget_are_bounded(self):
        functions, records = suite.sqrt_numerical_corpus()
        self.assertEqual(len(records), 11123)
        enables, modes, imported = set(), set(), []
        for index, record in enumerate(records):
            op = functions[record['function']]
            initial = State.from_buffer_copy(record['initial'])
            unsupported = bool(initial.fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK)
            imported.append(dict(record, operation=op, unsupported=unsupported))
            if unsupported:
                enables.add((op['canonical_id'], initial.fpcr))
            if record['label'] == 'control_minsubnormal_negative':
                modes.add((suite.numerical_unary_shape(op), initial.fpcr))
            self.assertEqual(record['case'], index)
            self.assertEqual(record['initial_state_sha256'], suite.digest(record['initial']))
        self.assertEqual(len(enables), 35)
        self.assertEqual(len(modes), 8 * 12 * 4)
        selected = suite.sqrt_numerical_runtime_cases(imported)
        self.assertEqual(len(selected), 243)
        self.assertLessEqual(len(selected) + len(suite.sqrt_numerical_helpers(imported)) * 6, 425)
        self.assertEqual(suite.sqrt_numerical_helpers(imported, set()), [])
        self.assertIn('control_minsubnormal_positive', {r['label'] for r in selected})
        self.assertIn('control_minsubnormal_negative', {r['label'] for r in selected})

    def test_sqrt_descriptor_declares_own_scope_and_unary_refactor_preserves_frint_inputs(self):
        family = suite.FULL_FRAME_NUMERICAL_COHORTS[suite.SQRT_NUMERICAL_FOCUS]
        self.assertEqual(family['forms'], 5)
        self.assertIs(family['loader'], suite.load_sqrt_numerical_oracle)
        self.assertIn('H/S/D square root', family['limits'])
        self.assertNotIn('integral rounding', family['limits'])
        _, records = suite.round_integral_corpus()
        inputs = b''.join(struct.pack('<Q', record['function']) + record['initial'] + bytes(8) for record in records)
        self.assertEqual(suite.digest(inputs), '68e82a2ff491450e478f65eb2d59f3d6ed3b743fe1550eba2020280ff4ce4249')

    def test_round_integral_forms_and_every_arrangement_match_pinned_encoding_facts(self):
        functions = suite.round_integral_functions()
        self.assertEqual((len(functions), len({op['word'] for op in functions})), (304, 304))
        self.assertEqual(len({op['canonical_id'] for op in functions}), 47)
        self.assertEqual(len({suite.numerical_unary_shape(op) for op in functions}), 76)
        facts = {row['id']: row for row in json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for op in functions:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            decoded = list(decoder.disasm(struct.pack('<I', op['word']), 0))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0].mnemonic, op['name'])
            self.assertEqual((op['word'] & 31, op['word'] >> 5 & 31), (op['d'], op['n']))
            if op['bounded_bits']:
                self.assertNotEqual(op['lane'], 2)
        for arguments in (('frint32z', 2, 2, True), ('frintn', 8, 8, False), ('frintx', 4, 16, True), ('frintn', 4, 4, True, 32)):
            with self.assertRaises(ValueError):
                suite.round_integral_operation(*arguments)

    def test_round_integral_exact_values_cover_post_round_range_and_signed_neighbors(self):
        for lane in (2, 4, 8):
            values = dict(suite.numerical_unary_values(lane))
            self.assertEqual((len(values), len(set(values.values()))), (54, 54))
            sign = 1 << (lane * 8 - 1)
            self.assertEqual(values['zero_negative'], sign)
            self.assertEqual(values['half_negative'], values['half_positive'] | sign)
            self.assertEqual(values['half_below_positive'] + 1, values['half_positive'])
            self.assertEqual(values['half_above_positive'] - 1, values['half_positive'])
        for name in ('frint32x', 'frint64z'):
            for lane in (4, 8):
                op = suite.round_integral_operation(name, lane, lane, True)
                bounds = dict(suite.round_integral_bound_values(op))
                expected = 12 if name.startswith('frint32') and lane == 8 else 6
                self.assertEqual(len(bounds), expected)
                self.assertEqual(bounds['bound_below_positive'] + 1, bounds['bound_exact_positive'])
                self.assertEqual(bounds['bound_above_positive'] - 1, bounds['bound_exact_positive'])
                if expected == 12:
                    self.assertIn('bound_half_below_negative', bounds)
                    self.assertIn('bound_half_above_positive', bounds)

    def test_round_integral_scalar_merges_old_destination_and_vector64_clears_upper(self):
        op = suite.round_integral_operation('frintx', 4, 4, True)
        initial = State()
        initial.fpcr = suite.NUMERICAL_NEP
        initial.v[0][:] = [0x1234567800000000, 0x1234]
        initial.v[1][:] = [0xabcdef0000000000, 0xabcd]
        original = State.from_buffer_copy(initial)
        original.v[0][0] |= 0x3f800000
        suite.validate_numerical_unary_original_effects(initial, original, op)
        original.v[0][1] = initial.v[1][1]
        with self.assertRaises(AssertionError):
            suite.validate_numerical_unary_original_effects(initial, original, op)
        initial.fpcr = 0
        original.v[0][:] = [0x3f800000, 0]
        suite.validate_numerical_unary_original_effects(initial, original, op)
        vector = suite.round_integral_operation('frintn', 4, 8, False)
        original.v[0][1] = 1
        with self.assertRaises(AssertionError):
            suite.validate_numerical_unary_original_effects(initial, original, vector)

    def test_round_integral_corpus_keeps_controls_enables_sticky_and_mixed_status_scope(self):
        functions, records = suite.round_integral_corpus()
        self.assertEqual(len(records), 27281)
        imported, enable_forms = [], set()
        for index, record in enumerate(records):
            op = functions[record['function']]
            initial = State.from_buffer_copy(record['initial'])
            unsupported = bool(initial.fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK)
            imported.append(dict(record, case=index, operation=op, unsupported=unsupported))
            if unsupported:
                enable_forms.add((op['canonical_id'], initial.fpcr))
            if record['label'] == 'mixed_3_0' and op['bounded_bits']:
                raw = struct.pack('<2Q', *initial.v[op['n']])
                values = dict(suite.numerical_unary_values(op['lane']))
                self.assertEqual(int.from_bytes(raw[:op['lane']], 'little'), values['infinity_positive'])
                self.assertEqual(int.from_bytes(raw[op['lane']:2 * op['lane']], 'little'), values['half_positive'])
        self.assertEqual(len(enable_forms), 47 * 7)
        selected = suite.round_integral_runtime_cases(imported)
        self.assertEqual(len(selected), 714)
        self.assertEqual(suite.round_integral_helpers(imported, set()), [])
        self.assertLessEqual(len(suite.round_integral_helpers(imported)), 26)
        selected_labels = {record['label'] for record in selected}
        self.assertIn('ah_round_half_negative', selected_labels)
        self.assertIn('round_bound_half_below_negative', selected_labels)
        self.assertIn('value_bound_exact_negative', selected_labels)
        self.assertEqual({State.from_buffer_copy(r['initial']).fpsr for r in records if r['label'] == 'sticky_status'},
                         {1, 1 << 4, 1 << 27, suite.FP_REGISTER_MASKS['fpsr']})

    def test_fullframe_family_limits_identify_integral_rounding_scope(self):
        families = suite.FULL_FRAME_NUMERICAL_COHORTS
        self.assertTrue(all(isinstance(family['limits'], str) and family['limits'] for family in families.values()))
        self.assertEqual(len({family['limits'] for family in families.values()}), len(families))
        limits = families[suite.ROUND_INTEGRAL_FOCUS]['limits']
        self.assertIn('H/S/D integral rounding', limits)
        self.assertIn('bounded 32/64-bit rounding', limits)
        self.assertIn('retained-enable refusals', limits)
        self.assertNotIn('JSCVT', limits)
        self.assertNotIn('conversion', limits)

    def test_round_integral_fullframe_descriptor_and_frozen_serialization_are_reused(self):
        family = suite.FULL_FRAME_NUMERICAL_COHORTS[suite.ROUND_INTEGRAL_FOCUS]
        self.assertEqual(family['forms'], 47)
        self.assertIs(family['loader'], suite.load_round_integral_oracle)
        op = suite.round_integral_operation('frintn', 4, 4, True)
        initial = suite.numerical_unary_state(op, 0, [dict(suite.numerical_unary_values(4))['half_positive']])
        record = {'function': 0, 'function_index': 0, 'label': 'half', 'initial': bytes(initial),
                  'initial_state_sha256': suite.digest(bytes(initial))}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def write_plan(path, value):
                path.write_text(json.dumps(value))
                return path
            with patch.object(suite, 'write_evidence', side_effect=write_plan), patch.object(suite, 'ROOT', directory):
                suite.prepare_full_frame_numerical_oracle(directory, [op], [record], suite.ROUND_INTEGRAL_FOCUS)
                frozen = (directory / 'inputs.bin').read_bytes()
                self.assertEqual(len(frozen), 800)
                self.assertEqual(frozen[8:792], bytes(initial))
                suite.prepare_full_frame_numerical_oracle(directory, [op], [record], suite.ROUND_INTEGRAL_FOCUS)
                changed = dict(record, initial=bytes(784))
                with self.assertRaises(AssertionError):
                    suite.prepare_full_frame_numerical_oracle(directory, [op], [changed], suite.ROUND_INTEGRAL_FOCUS)

    def test_comparison_minmax_forms_shapes_and_fixed_encodings_are_complete(self):
        functions = suite.comparison_minmax_functions()
        self.assertEqual(len(functions), 2590)
        self.assertEqual(len({op['word'] for op in functions}), 2590)
        self.assertEqual(len({op['canonical_id'] for op in functions}), 102)
        self.assertEqual(len({suite.comparison_minmax_shape(op) for op in functions}), 174)
        checklist = json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
        facts = {row['id']: row for row in checklist['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for operation in functions:
            fact = facts[operation['canonical_id']]
            self.assertEqual(operation['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            instruction, = decoder.disasm(struct.pack('<I', operation['word']), 0)
            self.assertEqual(instruction.mnemonic, operation['name'])
        for name in ('fcmp', 'fcmpe'):
            for lane in (2, 4, 8):
                self.assertEqual({op['m'] for op in functions if op['name'] == name and op['lane'] == lane and op['zero_form']}, set(range(32)))

    def test_comparison_condition_table_covers_all_flags_and_al_nv_are_true(self):
        for nibble in range(16):
            n, z, c, v = (bool(nibble & mask) for mask in (8, 4, 2, 1))
            expected = (z, not z, c, not c, n, not n, v, not v,
                c and not z, not c or z, n == v, n != v, not z and n == v, z or n != v, True, True)
            self.assertEqual(tuple(suite.numerical_condition_holds(condition, nibble << 28) for condition in range(16)), expected)
        with self.assertRaises(ValueError):
            suite.numerical_condition_holds(16, 0)

    def test_comparison_minmax_scalar_merge_sources_and_clear_forms_are_distinct(self):
        initial = State()
        initial.fpcr = suite.NUMERICAL_NEP
        initial.v[0][:], initial.v[1][:], initial.v[2][:] = [1, 2], [3, 4], [5, 6]
        predicate = suite.comparison_minmax_operation('fcmeq', 4, 4, True)
        original = State.from_buffer_copy(initial)
        original.v[0][:] = [5 & ~0xffffffff, 6]
        suite.validate_comparison_minmax_original_effects(initial, original, predicate)
        original.v[0][1] = 4
        with self.assertRaises(AssertionError):
            suite.validate_comparison_minmax_original_effects(initial, original, predicate)
        binary = suite.comparison_minmax_operation('fmin', 4, 4, True, family='minmax_binary')
        original.v[0][:] = [3 & ~0xffffffff, 4]
        suite.validate_comparison_minmax_original_effects(initial, original, binary)
        zero = suite.comparison_minmax_operation('fcmeq', 4, 4, True, zero=True)
        original.v[0][:] = [0, 0]
        suite.validate_comparison_minmax_original_effects(initial, original, zero)
        pair = suite.comparison_minmax_operation('fminp', 2, 2, True, family='minmax_pair')
        self.assertEqual(pair['source_lane_count'], 2)
        self.assertEqual(pair['source_bytes'], 4)
        suite.validate_comparison_minmax_original_effects(initial, original, pair)

    def test_conditional_failed_effect_validation_requires_exact_fallback_and_status(self):
        operation = suite.comparison_minmax_operation('fccmp', 4, 4, True, family='flag_compare', condition=0, immediate=13)
        initial = State()
        initial.fpcr, initial.fpsr = suite.NUMERICAL_TRAP_ENABLE_MASK, 0x80
        original = State.from_buffer_copy(initial)
        original.nzcv = 13 << 28
        suite.validate_comparison_minmax_original_effects(initial, original, operation)
        original.fpsr |= 1
        with self.assertRaises(AssertionError):
            suite.validate_comparison_minmax_original_effects(initial, original, operation)
        original.fpsr, original.nzcv = initial.fpsr, 12 << 28
        with self.assertRaises(AssertionError):
            suite.validate_comparison_minmax_original_effects(initial, original, operation)

    def test_comparison_minmax_reduction_layouts_contain_genuine_fold_discriminators(self):
        for name, expected in (('fminnmv', [0x3f800000, 0x40000000, 0x7f80002b, 0x40400000]),
                               ('fmaxnmv', [0x40000000, 0x40400000, 0x7f80002b, 0x3f800000])):
            operation = suite.comparison_minmax_operation(name, 4, 16, True, family='minmax_reduce')
            layouts = suite.comparison_minmax_layouts(operation)
            self.assertEqual(len(layouts), 64)
            self.assertIn(expected, [left for left, _ in layouts])
        operation = suite.comparison_minmax_operation('fminnmv', 2, 16, True, family='minmax_reduce')
        signaling = suite.comparison_minmax_values(2)[0][8]
        layouts = suite.comparison_minmax_layouts(operation)
        self.assertEqual({left.index(signaling) for left, _ in layouts if left.count(signaling) == 1}, set(range(8)))

    def test_comparison_minmax_corpus_retains_exact_policy_classes_and_full_enable_scope(self):
        functions, records = suite.comparison_minmax_corpus()
        self.assertEqual(len(records), 39724)
        classes = {'compatible': 0, 'refusal': 0, 'policy': 0}
        refusal_forms, failed_conditions, sticky = set(), set(), 0
        imported = []
        for record in records:
            operation = functions[record['function']]
            initial = State.from_buffer_copy(record['initial'])
            enabled = bool(initial.fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK)
            taken = operation['condition'] is None or suite.numerical_condition_holds(operation['condition'], initial.nzcv)
            refusal, policy = enabled and taken, enabled and not taken
            classes['refusal' if refusal else 'policy' if policy else 'compatible'] += 1
            if refusal:
                refusal_forms.add(operation['canonical_id'])
            if policy:
                failed_conditions.add(operation['condition'])
            sticky += bool(initial.fpsr)
            imported.append({**record, 'operation': operation, 'unsupported': refusal, 'control_policy_success': policy})
        self.assertEqual(classes, {'compatible': 37768, 'refusal': 1356, 'policy': 600})
        self.assertEqual(len(refusal_forms), 102)
        self.assertEqual(failed_conditions, set(range(14)))
        self.assertEqual(sticky, 918)
        selected = suite.comparison_minmax_runtime_cases(imported)
        self.assertEqual({record['operation']['canonical_id'] for record in selected}, {op['canonical_id'] for op in functions})
        self.assertTrue(any(record['control_policy_success'] for record in selected))
        self.assertEqual(suite.comparison_minmax_helpers(imported, set()), [])

    def test_conversion_encodings_cover_all_classic_forms_and_match_pinned_fixed_bits(self):
        functions = suite.conversion_numerical_functions()
        self.assertEqual(len(functions), 1416)
        self.assertEqual(len({op['word'] for op in functions}), len(functions))
        self.assertEqual(len({op['canonical_id'] for op in functions}), 163)
        checklist = json.loads((suite.ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
        facts = {row['id']: row for row in checklist['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for operation in functions:
            fact = facts[operation['canonical_id']]
            self.assertEqual(operation['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            instruction, = decoder.disasm(struct.pack('<I', operation['word']), 0)
            suffix = '2' if operation['source_part'] or operation['destination_part'] else ''
            self.assertEqual(instruction.mnemonic, operation['name'] + suffix)
            self.assertEqual(operation['word'] & 31, operation['d'])
            self.assertEqual(operation['word'] >> 5 & 31, operation['n'])
        self.assertTrue(any(op['name'] == 'fjcvtzs' for op in functions))

    def test_conversion_fixed_scales_and_returns_preserve_source_and_destination_gprs(self):
        for operation in suite.conversion_numerical_functions():
            bits = operation['integer_bits']
            if operation['fracbits']:
                self.assertIn(operation['fracbits'], (1, bits // 2, bits))
            used = {operation[role] for bank, role in (('source_bank', 'n'), ('destination_bank', 'd'))
                    if operation[bank] == 'general' and operation[role] != 31}
            self.assertNotIn(operation['return_register'], used)
            word = suite.numerical_return_word(operation)
            instruction, = Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(struct.pack('<I', word), 0)
            self.assertEqual(instruction.mnemonic, 'ret')
            self.assertEqual(word >> 5 & 31, operation['return_register'])
        self.assertEqual(suite.numerical_return_word({}), suite.RET)
        with self.assertRaises(ValueError):
            suite.numerical_return_word({'return_register': 31})

    def test_conversion_rejects_unallocated_shapes_widths_and_fixed_modes(self):
        invalid = (('fcvt', 4, 4, 'scalar', 0, 1), ('fcvtl', 4, 2, 'vector', 0, 1),
                   ('fcvtxn', 4, 2, 'vector', 0, 1), ('fcvtn', 8, 4, 'scalar', 0, 1),
                   ('fcvtzs', 8, 8, 'vector64', 0, 1), ('fcvtzs', 4, 4, 'general', 0, 1, 64),
                   ('fcvtns', 4, 4, 'general', 0, 1, 32, 1),
                   ('ucvtf', 4, 4, 'general', 0, 1, 32, 0, False),
                   ('fjcvtzs', 4, 4, 'general', 0, 1, 32))
        for arguments in invalid:
            with self.assertRaises(ValueError):
                suite.conversion_numerical_operation(*arguments)

    def test_conversion_exact_dyadic_inputs_cover_half_overflow_and_normal_ties(self):
        self.assertEqual(suite.conversion_exact_positive_bits(4, 131040, 0), 0x47fff000)
        self.assertEqual(suite.conversion_exact_positive_bits(8, 131040, 0), 0x40fffe0000000000)
        self.assertIsNone(suite.conversion_exact_positive_bits(2, 131040, 0))
        self.assertEqual(suite.conversion_exact_positive_bits(2, 1, -24), 1)
        self.assertIsNone(suite.conversion_exact_positive_bits(2, 1, -25))
        operation = suite.conversion_numerical_operation('fcvt', 8, 2, 'scalar', 0, 1)
        values = dict(suite.conversion_numerical_values(operation))
        self.assertEqual(values['alternative_half_overflow_tie'], 0x40fffe0000000000)
        self.assertEqual(values['target_overflow_tie'], 0x40effe0000000000)

    def test_conversion_source_halves_inactive_poison_and_general_w_input(self):
        for part in (0, 1):
            operation = suite.conversion_numerical_operation('fcvtl', 2, 4, 'vector', 0, 1, part=part)
            state = suite.conversion_numerical_state(operation, 17, [1, 2, 3, 4])
            packed = state.v[1][0] | state.v[1][1] << 64
            self.assertEqual([(packed >> ((part * 4 + index) * 16)) & 65535 for index in range(4)], [1, 2, 3, 4])
            poison = dict(suite.conversion_numerical_values(operation))['snan']
            self.assertEqual([(packed >> (((1 - part) * 4 + index) * 16)) & 65535 for index in range(4)], [poison] * 4)
        operation = suite.conversion_numerical_operation('scvtf', 4, 8, 'general', 0, 30, 32)
        state = suite.conversion_numerical_state(operation, 17, [0x80000001])
        self.assertEqual(state.x[30] & 0xffffffff, 0x80000001)
        self.assertNotEqual(state.x[30] >> 32, 0)
        self.assertEqual(operation['return_register'], 29)

    def test_conversion_supplementary_unicorn_difference_is_exact_flushed_subnormal_z_only(self):
        operation = suite.conversion_numerical_operation('fjcvtzs', 8, 4, 'general', 0, 1, 32)
        initial = State()
        initial.fpcr, initial.v[1][0] = suite.NUMERICAL_FZ, 1
        expected = State.from_buffer_copy(initial)
        observed = State.from_buffer_copy(expected)
        observed.nzcv = 0x40000000
        self.assertTrue(suite.conversion_unicorn_flushed_javascript_difference(operation, initial, observed, expected))
        initial.v[1][0] |= 1 << 63
        self.assertTrue(suite.conversion_unicorn_flushed_javascript_difference(operation, initial, observed, expected))
        observed.x[7] = 1
        self.assertFalse(suite.conversion_unicorn_flushed_javascript_difference(operation, initial, observed, expected))
        observed.x[7], initial.v[1][0] = 0, 0
        self.assertFalse(suite.conversion_unicorn_flushed_javascript_difference(operation, initial, observed, expected))
        initial.v[1][0], initial.fpcr = 1, suite.NUMERICAL_FZ | suite.NUMERICAL_AH
        self.assertFalse(suite.conversion_unicorn_flushed_javascript_difference(operation, initial, observed, expected))

    def test_conversion_supplementary_fixed_half_difference_only_allows_exact_upper16_extension(self):
        operation = suite.conversion_numerical_operation('fcvtzs', 2, 2, 'scalar', 0, 1, fracbits=1)
        initial = State()
        expected = State.from_buffer_copy(initial)
        expected.v[0][0] = 0xfffe
        observed = State.from_buffer_copy(expected)
        observed.v[0][0] = 0xfffffffe
        self.assertIsNotNone(suite.conversion_unicorn_difference(operation, initial, observed, expected))
        observed.fpsr = 1
        self.assertIsNone(suite.conversion_unicorn_difference(operation, initial, observed, expected))
        observed.fpsr, observed.v[0][0] = 0, 0xffff7fff
        expected.v[0][0] = 0x7fff
        self.assertIsNone(suite.conversion_unicorn_difference(operation, initial, observed, expected))
        initial.fpcr, expected.v[0][0], observed.v[0][0] = suite.NUMERICAL_NEP, 0xfffe, 0xfffffffe
        self.assertIsNone(suite.conversion_unicorn_difference(operation, initial, observed, expected))

    def test_conversion_effect_validation_enforces_old_destination_nep_and_narrow2(self):
        initial = State()
        initial.v[0][:] = [0x123456789abcdef0, 0xfedcba9876543210]
        initial.fpcr = suite.NUMERICAL_NEP
        operation = suite.conversion_numerical_operation('fcvt', 8, 4, 'scalar', 0, 1)
        original = State.from_buffer_copy(initial)
        original.v[0][0] = original.v[0][0] & ~0xffffffff | 0x3f800000
        suite.validate_conversion_original_effects(initial, original, operation)
        original.v[0][1] ^= 1
        with self.assertRaises(AssertionError):
            suite.validate_conversion_original_effects(initial, original, operation)
        operation = suite.conversion_numerical_operation('fcvtn', 8, 4, 'vector', 0, 1, part=1)
        original = State.from_buffer_copy(initial)
        original.v[0][1] = 0
        suite.validate_conversion_original_effects(initial, original, operation)
        original.v[0][0] ^= 1
        with self.assertRaises(AssertionError):
            suite.validate_conversion_original_effects(initial, original, operation)
        operation = suite.conversion_numerical_operation('fcvtzs', 8, 4, 'general', 0, 1, 32)
        original = State.from_buffer_copy(initial)
        original.x[0] = 1 << 32
        with self.assertRaises(AssertionError):
            suite.validate_conversion_original_effects(initial, original, operation)

    def test_conversion_corpus_scope_keeps_all_controls_precise_enables_and_lr_operands(self):
        functions, records = suite.conversion_numerical_corpus()
        self.assertEqual(len(records), 33380)
        self.assertEqual({record['function'] for record in records}, set(range(1416)))
        imported = [{**record, 'operation': functions[record['function']],
            'unsupported': bool(State.from_buffer_copy(record['initial']).fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK)} for record in records]
        selected = suite.conversion_numerical_runtime_cases(imported)
        self.assertEqual(len(selected), 867)
        self.assertEqual(len({record['operation']['canonical_id'] for record in selected}), 163)
        self.assertEqual({State.from_buffer_copy(record['initial']).fpcr for record in selected if record['unsupported']},
                         {*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), suite.NUMERICAL_TRAP_ENABLE_MASK})
        self.assertTrue(any(record['operation']['return_register'] == 29 for record in selected))
        self.assertEqual(len(suite.conversion_numerical_helpers(imported)), 26)

    def test_fused_encodings_cover_all_modes_register_roles_and_indexed_selectors(self):
        functions = suite.fused_numerical_functions()
        self.assertEqual(len(functions), 648)
        self.assertEqual(len({op['word'] for op in functions}), len(functions))
        self.assertEqual(len({suite.fused_numerical_form(op) for op in functions}), 24)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for operation in functions:
            instruction, = decoder.disasm(struct.pack('<I', operation['word']), 0)
            self.assertEqual(instruction.mnemonic, operation['name'])
            letter = {2: 'h', 4: 's', 8: 'd'}[operation['lane']]
            if operation['name'] in suite.FUSED_SCALAR_BASES:
                operands = [f"{letter}{operation[role]}" for role in ('d', 'n', 'm', 'a')]
            else:
                arrangement = str(operation['bytes'] // operation['lane']) + letter
                operands = [(f"{letter}{operation[role]}" if operation['scalar'] else
                             f"v{operation[role]}.{arrangement}") for role in ('d', 'n')]
                operands.append(f"v{operation['m']}.{letter}[{operation['index']}]" if operation['index'] is not None
                                else f"v{operation['m']}.{arrangement}")
            self.assertEqual(instruction.op_str, ', '.join(operands))
        for lane in (2, 4, 8):
            self.assertEqual({op['index'] for op in functions if op['index'] is not None and op['lane'] == lane},
                             set(range(16 // lane)))
        half = [op for op in functions if op['index'] is not None and op['lane'] == 2]
        self.assertEqual(max(op['m'] for op in half), 15)
        self.assertTrue(any(op['d'] == op['n'] == op['m'] == op['a'] == 31 for op in functions))

    def test_fused_encoding_rejects_unallocated_shapes_and_indexed_fields(self):
        for arguments in (('fmadd', 4, 4, True, 0, 1, 2, None, None),
                          ('fmadd', 8, 8, True, 0, 1, 2, 3, 0),
                          ('fmla', 8, 8, False, 0, 1, 2, None, None),
                          ('fmla', 2, 16, False, 0, 1, 16, None, 0),
                          ('fmls', 8, 16, False, 0, 1, 2, None, 2),
                          ('fmla', 4, 4, True, 0, 1, 2, 3, 0)):
            with self.assertRaises(ValueError):
                suite.fused_numerical_operation(*arguments)

    def test_fused_input_triples_preserve_selected_lane_and_poison_inactive_inputs(self):
        for lane in (2, 4, 8):
            index = 16 // lane - 1
            operation = suite.fused_numerical_operation('fmla', lane, lane, True, 0, 1, 2, index=index)
            initial = suite.fused_numerical_state(operation, 1, [(7, 11, 13)], suite.NUMERICAL_NEP, True)
            bits, mask = lane * 8, (1 << (lane * 8)) - 1
            self.assertEqual(initial.v[0][0] & mask, 7)
            self.assertEqual(initial.v[1][0] & mask, 11)
            right = initial.v[2][0] | initial.v[2][1] << 64
            self.assertEqual(right >> (index * bits) & mask, 13)
            poison = next(triple[1] for triple in suite.fused_numerical_triples(lane) if triple[0] == 'snan_addend')
            self.assertEqual([right >> (element * bits) & mask for element in range(16 // lane) if element != index],
                             [poison] * (16 // lane - 1))
            self.assertEqual(initial.fpcr, suite.NUMERICAL_NEP)
            self.assertEqual(initial.fpsr, suite.FP_REGISTER_MASKS['fpsr'])
            self.assertNotEqual(initial.v[0][1], 0)

    def test_fused_single_round_residual_fixture_is_nonzero_exact_arithmetic(self):
        from fractions import Fraction
        for lane, fraction in ((2, 10), (4, 23), (8, 52)):
            label, a, n, m = suite.fused_numerical_triples(lane)[2]
            self.assertEqual(label, 'single_round_residual')
            ulp = Fraction(1, 1 << fraction)
            self.assertEqual((1 + ulp) * (1 - ulp) - 1, -ulp * ulp)
            self.assertEqual(n & ((1 << fraction) - 1), 1)
            self.assertEqual(a ^ (1 << (lane * 8 - 1)), n - 1)
            self.assertEqual(m, n - 3)

    def test_fused_corpus_and_runtime_scope_include_controls_status_aliases_and_precise_declines(self):
        functions, records = suite.fused_numerical_corpus()
        self.assertEqual(len(records), 18402)
        self.assertEqual({record['function'] for record in records}, set(range(len(functions))))
        imported = [{**record, 'operation': functions[record['function']],
                     'unsupported': bool(State.from_buffer_copy(record['initial']).fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK)}
                    for record in records]
        selected = suite.fused_numerical_runtime_cases(imported)
        self.assertEqual(len(selected), 326)
        self.assertEqual(len({suite.fused_numerical_form(record['operation']) for record in selected}), 24)
        declines = [record for record in selected if record['unsupported']]
        self.assertEqual(len(declines), 42)
        self.assertEqual({State.from_buffer_copy(record['initial']).fpcr for record in declines},
                         {*(1 << bit for bit in (8, 9, 10, 11, 12, 15)), suite.NUMERICAL_TRAP_ENABLE_MASK})
        self.assertEqual(len(suite.fused_numerical_helpers(imported)), 12)
        self.assertTrue(any(record['label'].startswith('active_snan_addend_') for record in selected))
        self.assertEqual({State.from_buffer_copy(record['initial']).fpcr for record in selected
                          if record['label'] == 'single_round_residual'},
                         {*suite.FUSED_ROUNDING_CONTROLS, suite.NUMERICAL_AH, suite.NUMERICAL_NEP})

    def test_vector_numerical_encodings_cover_arrangements_aliases_and_v31(self):
        functions = suite.vector_numerical_functions()
        words = [operation['word'] for operation in functions]
        decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(struct.pack('<140I', *words), 0))
        self.assertEqual(len(set(words)), 140)
        self.assertEqual(len(decoded), 140)
        for operation, instruction in zip(functions, decoded):
            self.assertEqual(instruction.mnemonic, operation['name'])
            arrangement = str(operation['bytes'] // operation['lane']) + {2: 'h', 4: 's', 8: 'd'}[operation['lane']]
            self.assertEqual(instruction.op_str, ', '.join(f'v{operation[role]}.{arrangement}' for role in ('d', 'n', 'm')))
        self.assertEqual({(op['lane'], op['bytes']) for op in functions}, set(suite.VECTOR_NUMERICAL_SHAPES))
        for arguments in (('fmax', 4, 16, 0, 1, 2), ('fadd', 8, 8, 0, 1, 2),
                          ('fadd', 4, 16, -1, 1, 2), ('fadd', 2, 8, 0, 1, 32)):
            with self.assertRaises(ValueError):
                suite.vector_numerical_operation(*arguments)

    def test_vector_numerical_inputs_poison_inactive_lanes_without_changing_active_pairs(self):
        for lane, width in suite.VECTOR_NUMERICAL_SHAPES:
            operation = suite.vector_numerical_operation('fdiv', lane, width, 0, 1, 2)
            pairs = [(element + 1, element + 17) for element in range(width // lane)]
            state = suite.vector_numerical_state(operation, 7, pairs, suite.NUMERICAL_NEP, True)
            bits, mask = lane * 8, (1 << (lane * 8)) - 1
            for register, side in ((1, 0), (2, 1)):
                value = state.v[register][0] | state.v[register][1] << 64
                self.assertEqual([(value >> (element * bits)) & mask for element in range(width // lane)],
                                 [pair[side] for pair in pairs])
                if width == 8:
                    self.assertNotEqual(state.v[register][1], 0)
            self.assertEqual((state.fpcr, state.fpsr, state.reserved),
                             (suite.NUMERICAL_NEP, suite.FP_REGISTER_MASKS['fpsr'], suite.VECTOR_NUMERICAL_CANARY))
            with self.assertRaises(ValueError):
                suite.vector_numerical_state(operation, 7, pairs[:-1])

    def test_vector_original_frame_imports_every_architectural_field_keeps_metadata_canary(self):
        initial = State()
        initial.reserved = suite.VECTOR_NUMERICAL_CANARY
        initial.x[:] = [99] * 31
        snapshot = bytearray(suite.FP_REGISTER_RECORD_BYTES)
        registers = [0x1000000000000000 + register for register in range(31)]
        vectors = [0x8000000000000000 + limb for limb in range(64)]
        struct.pack_into('<31Q', snapshot, 0, *registers)
        struct.pack_into('<4Q', snapshot, suite.VECTOR_NUMERICAL_STATUS_OFFSET,
                         0x48010100, 0xa0000005, suite.NUMERICAL_NEP, 0x08000012)
        struct.pack_into('<64Q', snapshot, suite.VECTOR_NUMERICAL_VECTORS_OFFSET, *vectors)
        observed = suite.full_frame_numerical_original_state(initial, snapshot)
        self.assertEqual(list(observed.x), registers)
        self.assertEqual((observed.sp, observed.nzcv, observed.fpcr, observed.fpsr),
                         (0x48010100, 0xa0000000, suite.NUMERICAL_NEP, 0x08000012))
        self.assertEqual([limb for vector in observed.v for limb in vector], vectors)
        self.assertEqual(observed.reserved, initial.reserved)
        for invalid in (snapshot[:-1], snapshot + bytes(1)):
            with self.assertRaises(AssertionError):
                suite.full_frame_numerical_original_state(initial, invalid)

    def test_vector_runtime_selection_keeps_both_widths_semantic_lanes_aliases_and_traps(self):
        records = []
        for function, operation in enumerate(suite.vector_numerical_functions()):
            for control, label, unsupported in ((0, 'directed_pack_0', False),
                    (suite.NUMERICAL_NEP, 'alias_pattern_0', False),
                    (suite.NUMERICAL_AH, 'active_snan_left_0', False),
                    (suite.NUMERICAL_TRAP_ENABLE_MASK, 'trap_enable_readback_only', True)):
                initial = State()
                initial.fpcr, initial.fpsr = control, 0
                records.append({'function': function, 'operation': operation, 'case': len(records),
                                'initial': bytes(initial), 'label': label, 'unsupported': unsupported})
        selected = suite.vector_numerical_runtime_cases(records)
        self.assertEqual(len(selected), 200)
        aliases = [record for record in selected if State.from_buffer_copy(record['initial']).fpcr == suite.NUMERICAL_NEP]
        self.assertEqual({record['function'] for record in aliases}, set(range(140)))
        semantic = [record for record in selected if record['label'] == 'active_snan_left_0']
        self.assertEqual(len(semantic), 20)
        self.assertEqual({(record['operation']['lane'], record['operation']['bytes']) for record in semantic},
                         set(suite.VECTOR_NUMERICAL_SHAPES))
        self.assertEqual(sum(record['unsupported'] for record in selected), 20)

    def test_fp_register_encodings_cover_exactly_all_four_operands_and_all_rt(self):
        functions = suite.fp_register_functions()
        words = [function['operations'][0]['word'] for function in functions]
        self.assertEqual(len(set(words)), 128)
        decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(struct.pack('<128I', *words), 0))
        self.assertEqual(len(decoded), 128)
        self.assertEqual([instruction.mnemonic for instruction in decoded], ['mrs'] * 32 + ['msr'] * 32 + ['mrs'] * 32 + ['msr'] * 32)
        self.assertEqual([instruction.op_str for instruction in decoded if 'xzr' in instruction.op_str],
                         ['xzr, fpcr', 'fpcr, xzr', 'xzr, fpsr', 'fpsr, xzr'])
        for name in suite.FP_REGISTER_WORDS:
            for rt in (-1, 32):
                with self.assertRaises(ValueError):
                    suite.fp_register_operation(name, rt)

    def test_fp_register_reads_zero_extend_without_normalizing_imported_storage(self):
        initial = State.from_buffer_copy(suite.states()[0])
        initial.fpcr, initial.fpsr, initial.nzcv = 0xffffffff, 0xffffffff, 0xf0000000
        for register, mask in suite.FP_REGISTER_MASKS.items():
            for rt in (0, 30, 31):
                actual = suite.fp_register_expected(suite.fp_register_operation('mrs_' + register, rt), initial)
                expected = State.from_buffer_copy(initial)
                if rt != 31:
                    expected.x[rt] = mask
                self.assertEqual(bytes(actual), bytes(expected))
                self.assertEqual(getattr(actual, register), 0xffffffff)

    def test_fp_register_writes_replace_all_storage_keep_enables_and_separate_status(self):
        initial = State.from_buffer_copy(suite.states()[0])
        initial.fpcr, initial.fpsr, initial.nzcv = 0xffffffff, 0xffffffff, 0x90000000
        for register, mask in suite.FP_REGISTER_MASKS.items():
            for rt in (0, 30, 31):
                for value in (0, (1 << 64) - 1, 0xfeedface00009f00, 1 << 27):
                    initial.x[0 if rt == 31 else rt] = value
                    actual = suite.fp_register_expected(suite.fp_register_operation('msr_' + register, rt), initial)
                    expected = State.from_buffer_copy(initial)
                    setattr(expected, register, 0 if rt == 31 else value & mask)
                    self.assertEqual(bytes(actual), bytes(expected))
        self.assertEqual(suite.FP_REGISTER_MASKS['fpcr'] & suite.NUMERICAL_TRAP_ENABLE_MASK,
                         suite.NUMERICAL_TRAP_ENABLE_MASK)

    def test_fp_register_policy_cases_cover_raw_imports_every_bit_and_128_roles(self):
        records = suite.fp_register_policy_cases()
        self.assertEqual(len(records), 640)
        self.assertEqual({record['function'] for record in records}, set(range(128)))
        for index in (32, 96):
            self.assertEqual({record['bit'] for record in records if record['function'] == index and 'bit' in record}, set(range(64)))
        self.assertTrue(any(State.from_buffer_copy(record['initial']).fpcr & ~suite.FP_REGISTER_MASKS['fpcr'] for record in records))
        self.assertTrue(any(State.from_buffer_copy(record['initial']).fpsr & ~suite.FP_REGISTER_MASKS['fpsr'] for record in records))

    def test_fp_register_runtime_chain_exposes_status_then_clears_before_repeat_and_ret(self):
        initial = State.from_buffer_copy(suite.states()[0])
        initial.fpcr, initial.fpsr, initial.x[30] = suite.NUMERICAL_NEP, 0, suite.STOP
        expected = State.from_buffer_copy(initial)
        expected.fpsr = 0x12
        record = {'initial': bytes(initial), 'expected': bytes(expected), 'operation': {'word': 0x1e221820}}
        code, entered, intermediate, final = suite.fp_register_chain(record)
        decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, 0))
        self.assertEqual([instruction.mnemonic for instruction in decoded],
                         ['msr', 'msr', 'fdiv', 'mrs', 'msr', 'mrs', 'fdiv', 'mrs', 'msr', 'mrs', 'ret'])
        self.assertEqual(entered.fpsr, suite.FP_REGISTER_MASKS['fpsr'])
        self.assertNotEqual(entered.fpcr, intermediate.fpcr)
        self.assertEqual((intermediate.fpcr, intermediate.fpsr), (suite.NUMERICAL_NEP, 0x12))
        self.assertEqual((final.x[3], final.x[4], final.x[5], final.x[6], final.fpsr), (0x12, 0, 0x12, 0, 0))

    def test_block_manifest_binds_only_its_consumed_prefix_without_losing_original_input(self):
        source = struct.pack('<II', 0x1ee22820, suite.RET)
        native = bytes.fromhex('48b80010000000000000ba09000000c3')
        manifest = {'schema_version': 1, 'abi': suite.BLOCK_ABI, 'guest_base': 0x1000,
                    'source_bytes': 4, 'source_sha256': suite.digest(source[:4]),
                    'native_sha256': suite.digest(native), 'native_bytes': len(native),
                    'source_map': [[0x1000, 0]], 'verified': False, 'target_cpu': 'x86_64-baseline'}
        self.assertEqual(suite.validate_manifest(manifest, source, native, True, guest_base=0x1000), [0])
        for changed in ({'source_bytes': 0}, {'source_bytes': 2}, {'source_bytes': 12},
                        {'source_sha256': suite.digest(source)}, {'source_map': [[0x1000, 0], [0x1004, 10]]}):
            with self.assertRaises(AssertionError):
                suite.validate_manifest({**manifest, **changed}, source, native, True, guest_base=0x1000)
        with self.assertRaises(AssertionError):
            suite.validate_manifest({**manifest, 'abi': suite.LEAF_ABI, 'guest_instructions': 1},
                                    source, native, False, guest_base=0x1000)

    def test_terminal_numerical_accounting_has_no_invented_ret_mapping_or_bytes(self):
        operation = {'name': 'fadd', 'lane': 2, 'word': 0x1ee22820}
        source = struct.pack('<II', operation['word'], suite.RET)
        stub = bytes.fromhex('48b80010000000000000ba09000000c3')
        batch = {'functions': [{'operations': [operation]}], 'source': source,
                 'compiled_source': source[:4], 'native': stub, 'instruction_offsets': [0]}
        accounting = suite.numerical_native_accounting(batch)
        self.assertEqual((accounting['compiled_source_bytes'], accounting['input_source_bytes']), (4, 8))
        self.assertEqual((accounting['fp_body_bytes'], accounting['guest_ret_native_bytes']), (16, 0))
        self.assertEqual(accounting['native_instructions'], 3)
        ret = bytes.fromhex('488b87f0000000ba04000000c3')
        ordinary = {**batch, 'compiled_source': source, 'native': b'\x90' + ret, 'instruction_offsets': [0, 1]}
        accounting = suite.numerical_native_accounting(ordinary)
        self.assertEqual((accounting['compiled_source_bytes'], accounting['fp_body_bytes'], accounting['guest_ret_native_bytes']), (8, 1, 13))

    def test_many_half_cache_contains_eight_exact_prefix_helpers_and_one_ret(self):
        operation = {'word': 0x1ee22820}
        source, repeated = suite.numerical_half_chain_sources(operation)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        decoded = list(decoder.disasm(repeated, 0x1000))
        self.assertEqual([instruction.mnemonic for instruction in decoded], ['fadd'] * 8 + ['ret', 'mov', 'b'])
        self.assertEqual(decoded[-1].op_str, '#0x1000')
        self.assertEqual(decoded[-2].op_str, 'x30, x11')
        self.assertEqual(len(source), 36)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'cache'
            compiler = 'a' * 64
            for index in range(9):
                entry = cache / str(index)
                entry.mkdir(parents=True)
                pc = 0x1000 + index * 4
                native = (bytes.fromhex('48b8') + struct.pack('<Q', pc) + bytes.fromhex('ba09000000c3')
                          if index < 8 else bytes.fromhex('488b87f0000000ba04000000c3'))
                manifest = {'identity': {'guest_base': pc, 'source_sha256': suite.digest(source[index * 4:index * 4 + 4]),
                    'compiler_source_sha256': compiler, 'abi': suite.BLOCK_ABI, 'target_cpu': 'x86_64-baseline'},
                    'source_map': [[pc, 0]], 'native_bytes': len(native), 'native_sha256': suite.digest(native), 'verified': False}
                (entry / 'native.bin').write_bytes(native)
                (entry / 'manifest.json').write_text(json.dumps(manifest))
            artifacts = suite.numerical_half_cache_artifacts(cache, source, 0x1000, compiler, evidence_root=root)
            self.assertEqual(len(artifacts), 9)
            self.assertEqual(sum(artifact['native_bytes'] for artifact in artifacts), 141)
            (cache / '0/native.bin').write_bytes((cache / '0/native.bin').read_bytes() + b'\x90')
            with self.assertRaises(AssertionError):
                suite.numerical_half_cache_artifacts(cache, source, 0x1000, compiler, evidence_root=root)

    def test_numerical_original_state_keeps_transport_registers_and_captures_every_vector(self):
        initial = State()
        seed_extended_state(initial, 19)
        initial.x[:] = range(31)
        initial.sp, initial.reserved = 0x12345678, 0x51ad1234
        values = [value for vector in initial.v for value in vector]
        values[62:64] = [0x7ff8000000000001, 0xabcdef0123456789]
        captured = struct.pack('<64Q4I', *values, 0xf0000000, 7, 0x0800009f, 0x1234)
        expected = suite.numerical_expected_state(initial, captured)
        self.assertEqual(list(expected.x), list(initial.x))
        self.assertEqual((expected.sp, expected.reserved), (initial.sp, initial.reserved))
        self.assertEqual(list(expected.v[31]), values[62:64])
        self.assertEqual((expected.nzcv, expected.fpcr, expected.fpsr), (0xf0000000, 7, 0x0800009f))
        with self.assertRaises(AssertionError):
            suite.numerical_expected_state(initial, captured[:-1])
        with self.assertRaises(AssertionError):
            suite.numerical_expected_state(initial, captured[:-4] + bytes(4))

    def test_numerical_capture_requires_bound_original_sources_and_checks_all_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt = {'files': {}}
            for name in ('inputs.bin', 'results.bin', 'cases.json', 'guest.S', 'guest.elf', 'original.py'):
                data = name.encode()
                (directory / name).write_bytes(data)
                receipt['files'][name] = {'sha256': suite.digest(data), 'bytes': len(data)}
            path = directory / 'receipt.json'
            path.write_text(json.dumps(receipt))
            expected_hash = suite.digest(path.read_bytes())
            suite.numerical_capture(path, expected_hash)
            (directory / 'guest.elf').write_bytes(b'changed')
            with self.assertRaises(AssertionError):
                suite.numerical_capture(path, expected_hash)
            with self.assertRaises(AssertionError):
                suite.numerical_capture(path, '0' * 64)
            receipt['files'].pop('guest.S')
            path.write_text(json.dumps(receipt))
            with self.assertRaises(AssertionError):
                suite.numerical_capture(path, suite.digest(path.read_bytes()))

    def test_numerical_runtime_selection_preserves_controls_aliases_and_typed_declines(self):
        records = []
        for function, (name, lane) in enumerate((('fadd', 2), ('fdiv', 8))):
            for fpcr in (0, 4, 7, 1 << 8, suite.NUMERICAL_TRAP_ENABLE_MASK):
                initial = State()
                initial.fpcr, initial.fpsr = fpcr, 0
                records.append({'producer': 'fixture', 'case': len(records), 'function': function,
                    'operation': {'name': name, 'lane': lane}, 'label': 'zero_pp', 'initial': bytes(initial),
                    'unsupported': bool(fpcr & suite.NUMERICAL_TRAP_ENABLE_MASK)})
        selected = suite.numerical_runtime_cases(records)
        compatible = [record for record in selected if not record['unsupported']]
        self.assertEqual({State.from_buffer_copy(record['initial']).fpcr for record in compatible}, {0, 4, 7})
        self.assertEqual({record['function'] for record in compatible}, {0, 1})
        self.assertEqual(len({(record['producer'], record['case']) for record in selected}), len(selected))
        self.assertTrue(any(record['unsupported'] for record in selected))

    def test_numerical_mxcsr_wrapper_installs_captures_and_restores_around_actual_call(self):
        decoded = suite.decode_native_stream(suite.NUMERICAL_MXCSR_WRAPPER)
        self.assertEqual([instruction.mnemonic for instruction in decoded],
                         ['sub', 'stmxcsr', 'mov', 'mov', 'ldmxcsr', 'stmxcsr', 'call',
                          'mov', 'mov', 'mov', 'stmxcsr', 'ldmxcsr', 'add', 'ret'])
        self.assertEqual(decoded[0].op_str, 'rsp, 0x18')
        self.assertEqual(decoded[6].op_str, 'rsi')
        self.assertEqual(decoded[10].op_str, 'dword ptr [rcx + 0x10]')
        self.assertEqual(decoded[11].op_str, 'dword ptr [rsp]')
        self.assertEqual(suite.NumericalNativeExit.mxcsr_after.offset, 16)
        self.assertEqual(suite.NumericalNativeExit.mxcsr_before.offset, 20)

    def test_numerical_runtime_selection_keeps_arithmetic_and_status_cases_beside_first_zero(self):
        records = []
        required = set()
        for name in ('fadd', 'fsub', 'fmul', 'fdiv'):
            for lane in (2, 4, 8):
                flush = suite.NUMERICAL_FZ16 if lane == 2 else suite.NUMERICAL_FZ
                scenarios = ((0, 'zero_pp'), (0, 'one_opposite_one'), (0, 'qnan_snan'),
                             (suite.NUMERICAL_AH, 'zero_pp'), (suite.NUMERICAL_AH, 'normal_boundary_midpoint'),
                             (flush, 'zero_pp'), (flush, 'minimum_normal_half'),
                             (suite.NUMERICAL_ROUND_NEGATIVE, 'zero_pp'),
                             (suite.NUMERICAL_ROUND_NEGATIVE, 'maximum_maximum'))
                for control, label in scenarios:
                    initial = State()
                    initial.fpcr, initial.fpsr = control, 0
                    records.append({'producer': 'fixture', 'case': len(records), 'function': len(records),
                        'operation': {'name': name, 'lane': lane}, 'label': label,
                        'initial': bytes(initial), 'unsupported': False})
                    required.add((name, lane, control, label))
        selected = suite.numerical_runtime_cases(records)
        actual = {(record['operation']['name'], record['operation']['lane'],
                   State.from_buffer_copy(record['initial']).fpcr, record['label']) for record in selected}
        self.assertEqual(actual, required)

    def test_numerical_synthetic_control_words_decode_to_the_declared_loop_and_prefix(self):
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        words = (suite.NUMERICAL_ADD_X7_ONE, suite.NUMERICAL_ADD_X8_TWO,
                 suite.NUMERICAL_SUBS_X10_ONE, suite.NUMERICAL_CBNZ_X10_BACK_TWO)
        decoded = list(decoder.disasm(struct.pack('<4I', *words), 0x1000))
        self.assertEqual([(instruction.mnemonic, instruction.op_str) for instruction in decoded],
                         [('add', 'x7, x7, #1'), ('add', 'x8, x8, #2'),
                          ('subs', 'x10, x10, #1'), ('cbnz', 'x10, #0x1004')])

    def test_narrowing_shift_encodings_cover_all_immediates_and_allocated_shapes(self):
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        operations = [op for function in suite.narrowing_shift_programs() for op in function['operations']]
        for operation in operations:
            decoded = list(decoder.disasm(struct.pack('<I', operation['word']), 0))
            self.assertEqual(len(decoded), 1, operation)
            self.assertEqual(decoded[0].mnemonic.rstrip('2'), operation['name'], operation)
            self.assertTrue(operation['scalar'] or operation['upper'] == decoded[0].mnemonic.endswith('2'))
        for name in suite.NARROW_SHIFT_BASES:
            for lane in (1, 2, 4):
                for scalar, upper in ((False, False), (False, True), (True, False)):
                    subset = [op for op in operations if (op['name'], op['output_lane'], op['scalar'], op['upper']) == (name, lane, scalar, upper)]
                    self.assertEqual({op['amount'] for op in subset}, set(range(1, lane * 8 + 1)))
                    self.assertEqual({op['d'] for op in subset}, set(range(32)))
                    self.assertTrue(any(op['d'] == op['n'] == 31 for op in subset))

    def test_narrowing_rounding_carry_saturation_and_high_half_preservation(self):
        initial = State()
        initial.fpsr = 0x1f
        initial.v[0][:] = [0x0123456789abcdef, suite.MASK]
        initial.v[1][:] = [suite.MASK, suite.MASK]
        operation = next(function['operations'][0] for function in suite.narrowing_shift_programs()
                         if len(function['operations']) == 1 and all(function['operations'][0].get(key) == value
                         for key, value in {'name': 'uqrshrn', 'output_lane': 4, 'amount': 32, 'upper': True, 'd': 0}.items()))
        observed = suite.narrowing_shift_mathematical([operation], initial)
        self.assertEqual(observed['v'][0], [0x0123456789abcdef, suite.MASK])
        self.assertEqual(observed['fpsr'], suite.FPSR_QC | 0x1f)
        operation = {**operation, 'scalar': True, 'upper': False, 'bytes': 4}
        initial.v[1][:] = [0, suite.MASK]
        self.assertEqual(suite.narrowing_shift_mathematical([operation], initial)['v'][0], [0, 0])
        self.assertEqual(suite.narrowing_shift_mathematical([operation], initial)['fpsr'], 0x1f)
        initial.fpsr |= suite.FPSR_QC
        self.assertEqual(suite.narrowing_shift_mathematical([operation], initial)['fpsr'], initial.fpsr)

    def test_dot_round_encodings_cover_indices_registers_and_scalar_shapes(self):
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        operations = [op for function in suite.dot_round_product_programs() for op in function['operations']]
        for operation in operations:
            decoded = list(decoder.disasm(struct.pack('<I', operation['word']), 0))
            self.assertEqual(len(decoded), 1, operation)
            self.assertEqual(decoded[0].mnemonic, operation['name'], operation)
            if operation['index'] is not None:
                self.assertIn(f"[{operation['index']}]", decoded[0].op_str)
                if operation['lane'] == 2:
                    self.assertLess(operation['m'], 16)
        for name in ('sqrdmlah', 'sqrdmlsh'):
            for lane in (2, 4):
                subset = [op for op in operations if op['name'] == name and op['lane'] == lane]
                self.assertEqual({op['index'] for op in subset if op['index'] is not None}, set(range(16 // lane)))
                self.assertEqual({op['scalar'] for op in subset}, {False, True})
                self.assertEqual({op['d'] for op in subset}, set(range(32)))
        for name in ('sdot', 'udot'):
            subset = [op for op in operations if op['name'] == name]
            self.assertEqual({op['index'] for op in subset}, {None, 0, 1, 2, 3})
            self.assertEqual({op['m'] for op in subset}, set(range(32)))

    def test_rounding_doubling_accumulate_is_fused_and_qc_tracks_only_final_saturation(self):
        for lane in (2, 4):
            bits = lane * 8
            minimum, mask = 1 << (bits - 1), (1 << bits) - 1
            initial = State()
            initial.fpsr = 0x1f
            initial.v[0][:] = [mask, suite.MASK]
            initial.v[1][:] = [minimum, suite.MASK]
            initial.v[2][:] = [minimum, suite.MASK]
            operation = {'name': 'sqrdmlah', 'd': 0, 'n': 1, 'm': 2, 'lane': lane,
                         'output_lane': lane, 'bytes': lane, 'index': None}
            observed = suite.dot_round_product_mathematical([operation], initial)
            self.assertEqual(observed['v'][0], [minimum - 1, 0])
            self.assertEqual(observed['fpsr'], 0x1f)
            initial.v[0][:] = [0, suite.MASK]
            self.assertEqual(suite.dot_round_product_mathematical([operation], initial)['fpsr'], 0x1f | suite.FPSR_QC)
            initial.v[1][:] = [1, suite.MASK]
            initial.v[2][:] = [1 << (bits - 2), suite.MASK]
            self.assertEqual(suite.dot_round_product_mathematical([operation], initial)['v'][0], [1, 0])
            self.assertEqual(suite.dot_round_product_mathematical([{**operation, 'name': 'sqrdmlsh'}], initial)['v'][0], [0, 0])

    def test_dot_math_wraps_accumulation_and_uses_selected_four_byte_group(self):
        initial = State()
        initial.fpsr = suite.FPSR_QC | 0x1f
        initial.v[0][:] = [suite.MASK, suite.MASK]
        initial.v[1][:] = [suite.MASK, suite.MASK]
        initial.v[2][:] = [0, 0xffffffff00000000]
        operation = {'name': 'udot', 'd': 0, 'n': 1, 'm': 2, 'lane': 1,
                     'output_lane': 4, 'bytes': 8, 'index': 3}
        observed = suite.dot_round_product_mathematical([operation], initial)
        lane = 4 * 255 * 255 - 1
        self.assertEqual(observed['v'][0], [lane | (lane << 32), 0])
        self.assertEqual(observed['fpsr'], initial.fpsr)
        operation['name'] = 'sdot'
        self.assertEqual(suite.dot_round_product_mathematical([operation], initial)['v'][0], [3 | (3 << 32), 0])

    def test_floating_sign_oracle_preserves_nan_payload_and_destination_merge(self):
        for lane in (2,4,8):
            bits=lane*8;fraction=bits-{2:5,4:8,8:11}[lane]-1
            infinity=((1<<(bits-fraction-1))-1)<<fraction
            for name in ('fabs','fneg'):
                operation=next(f['operations'][0] for f in suite.floating_bit_programs() if len(f['operations'])==1
                    and all(f['operations'][0].get(k)==v for k,v in {'name':name,'scalar':True,'lane':lane,'d':0,'n':1}.items()))
                initial=State();initial.v[0][:]=[suite.MASK,suite.MASK]
                for payload in (infinity|1,infinity|(1<<(fraction-1))|3):
                    value=payload|(1<<(bits-1));initial.v[1][:]=[value,0x123456789abcdef0]
                    initial.fpcr=0x07c80007 # AH+NEP+FIZ+AHP+DN+FZ/FZ16+rounding
                    expected=suite.floating_bit_mathematical([operation],initial)
                    result=expected['v'][0][0]|(expected['v'][0][1]<<64)
                    self.assertEqual(result,(((1<<128)-1)^((1<<bits)-1))|value)
                    self.assertEqual((expected['fpcr'],expected['fpsr'],expected['nzcv']),
                                     (initial.fpcr,initial.fpsr,initial.nzcv))
                    initial.fpcr=0
                    expected=suite.floating_bit_mathematical([operation],initial)
                    self.assertEqual(expected['v'][0],[payload,0])
                initial.v[1][:]=[infinity,0xdeadbeef];initial.fpcr=2
                expected=suite.floating_bit_mathematical([operation],initial)
                self.assertEqual(expected['v'][0],[infinity if name=='fabs' else infinity|(1<<(bits-1)),0])

    def test_fcsel_raw_signaling_nan_zeroes_upper_with_nep_and_al_nv(self):
        for lane in (2,4,8):
            mask=(1<<(lane*8))-1
            for condition in (0,1,14,15):
                operation=next(f['operations'][0] for f in suite.floating_bit_programs() if len(f['operations'])==1
                    and all(f['operations'][0].get(k)==v for k,v in {'name':'fcsel','lane':lane,'condition':condition,'d':0,'n':1}.items()))
                for flags in range(16):
                    initial=State();initial.v[0][:]=[suite.MASK,suite.MASK];initial.v[1][:]=[suite.MASK,0x1122]
                    initial.v[2][:]=[0x123456789abcdef0,0x3344];initial.fpcr=0x07c80007;initial.nzcv=flags<<28
                    left=condition>=14 or ((bool(flags&4)) if condition==0 else not bool(flags&4))
                    expected=suite.floating_bit_mathematical([operation],initial)
                    self.assertEqual(expected['v'][0],[initial.v[1 if left else 2][0]&mask,0])

    def test_floating_qemu_fixture_keeps_original_words_and_cases_cover_control_modes(self):
        programs=suite.floating_bit_programs()
        shapes={(op['name'],op['lane'],op['bytes'],op['scalar']) for f in programs for op in f['operations']}
        self.assertEqual(len(shapes),19)
        self.assertTrue(any(op['d']==op['n']==31 for f in programs for op in f['operations']))
        subset=[next(f for f in programs if len(f['operations'])==1 and f['operations'][0]['name']=='fabs')]
        cases=list(suite.floating_bit_cases(subset,exhaustive_half=False))
        self.assertEqual({s.fpcr&7 for _,s in cases},set(range(8)))
        self.assertEqual({bool(s.fpcr&(1<<26)) for _,s in cases},{False,True})
        source=suite.floating_qemu_source(subset,len(cases))
        self.assertIn(f'.inst 0x{subset[0]["operations"][0]["word"]:08x}',source)
        self.assertIn('mrs x0,fpcr',source)
        self.assertIn('mrs x0,fpsr',source)

    def test_native_binary_accounting_partitions_guest_bodies_and_ret(self):
        operation={'name':'fixture','lane':8,'bytes':8,'word':0}
        batch={'native':bytes.fromhex('31c0c3'),'source':struct.pack('<II',0,suite.RET),
            'functions':[{'operations':[operation]}],'entries':[0],'instruction_offsets':[0,2]}
        report=suite.native_binary_accounting(batch)
        self.assertEqual(report['static_native_instructions_including_ret'],2)
        self.assertEqual(report['static_body_native_instructions'],1)
        self.assertEqual(report['static_body_native_bytes'],2)
        self.assertEqual(report['harness_ret_bytes'],1)
        self.assertEqual(report['body_native_to_guest_byte_expansion'],0.5)
        self.assertEqual(report['static_opcode_histogram'],{'ret':1,'xor':1})
        self.assertEqual(report['single_operation_shapes'][0]['native_instructions_min'],1)
        for offsets in ([1,2],[0,1],[0]):
            with self.assertRaises(AssertionError): suite.native_binary_accounting({**batch,'instruction_offsets':offsets})
        with self.assertRaises(AssertionError): suite.decode_native_stream(bytes.fromhex('900f'))
        self.assertEqual(suite.native_mnemonic('pclmulhqhqdq'),'pclmulqdq')

    def test_native_dynamic_trace_counts_loop_repeats_and_requires_return(self):
        # mov ecx,3; dec ecx; jnz dec; ret: four static instructions, eight dynamic.
        native=bytes.fromhex('b903000000ffc975fcc3');initial=State()
        observed,counts=suite.emulate_native_trace(native,0,len(native),initial)
        self.assertEqual(bytes(observed),bytes(initial))
        self.assertEqual(counts['dynamic_native_instructions_including_ret'],8)
        self.assertEqual(counts['dynamic_body_native_instructions'],7)
        self.assertEqual(counts['unique_native_instruction_addresses'],4)
        self.assertEqual(counts['backward_edges_taken'],2)
        with self.assertRaises(AssertionError):
            suite.emulate_native_trace(bytes.fromhex('ebfec3'),0,3,initial,instruction_budget=8)
        with self.assertRaises(AssertionError):
            suite.emulate_native_trace(bytes.fromhex('eb0090c3'),0,2,initial,instruction_budget=8)

    def test_immediate_oracle_uses_exact_numeric_float_bits_and_upper_lane_preservation(self):
        for lane,one in [(2,0x3c00),(4,0x3f800000),(8,0x3ff0000000000000)]:
            self.assertEqual(suite.immediate_float_bits(0x70,lane),one)
        initial=State()
        initial.x[0]=0x0123456789abcdef
        initial.v[31][:]=[0xfedcba9876543210,suite.MASK]
        operation={'kind':'fp_move','direction':'to_vector','d':31,'n':0,'lane':8,'upper':True}
        observed=suite.immediate_mathematical([operation],initial)
        self.assertEqual(observed['v'][31],[0xfedcba9876543210,0x0123456789abcdef])
        operation.update(n=31)
        self.assertEqual(suite.immediate_mathematical([operation],initial)['v'][31],[0xfedcba9876543210,0])

    def test_halving_oracle_keeps_overflow_borrow_and_narrow_round_carry(self):
        initial=State()
        initial.v[1][:]=[suite.MASK]*2
        initial.v[2][:]=[suite.MASK]*2
        base={'d':0,'n':1,'m':2,'lane':1,'output_lane':1,'bytes':16,'upper':False,
              'signed':False,'operation':'half','subtract':False,'round':False,'accumulate':False}
        self.assertEqual(suite.halving_mathematical([base],initial)['v'][0],[suite.MASK]*2)
        initial.v[1][:]=[0,0]
        self.assertEqual(suite.halving_mathematical([{**base,'subtract':True}],initial)['v'][0],[0x8080808080808080]*2)
        initial.v[1][:]=[suite.MASK]*2
        initial.v[0][:]=[0x0123456789abcdef,suite.MASK]
        observed=suite.halving_mathematical([{**base,'operation':'high','lane':2,'bytes':8,'upper':True,'round':True}],initial)
        self.assertEqual(observed['v'][0],[0x0123456789abcdef,0])
        self.assertEqual(observed['fpsr'],initial.fpsr)

    def test_indexed_product_oracle_keeps_index_source_and_modular_signed_long_accumulation(self):
        initial=State();seed_extended_state(initial,19)
        initial.v[1][:]=[0xdeadbeefcafebabe,0x80000000ffffffff]
        initial.v[2][:]=[0x123456789abcdef0,0xffffffff00000002]
        initial.v[0][:]=[0x7fffffffffffffff,0xffffffffffffffff]
        base={'name':'smlal','d':0,'n':1,'m':2,'lane':4,'output_lane':8,'bytes':16,
            'upper':True,'signed':True,'accumulate':'add','index':3}
        observed=suite.indexed_product_mathematical([base],initial)
        self.assertEqual(observed['v'][0],[0x8000000000000000,0x7fffffff])
        for field in ('x','sp','nzcv','reserved','fpcr','fpsr'):
            self.assertEqual(observed[field],state_dict(initial)[field])
        self.assertEqual(suite.indexed_product_mathematical([{**base,'accumulate':'sub'}],initial)['v'][0],
            [0x7ffffffffffffffe,0xffffffff7fffffff])
        self.assertEqual(suite.indexed_product_mathematical([{**base,'signed':False,'accumulate':None}],initial)['v'][0],
            [0xfffffffe00000001,0x7fffffff80000000])
        alias={**base,'d':2,'n':2,'m':2,'upper':False,'output_lane':4,'bytes':8,'accumulate':'add'}
        expected=suite.indexed_product_mathematical([alias],initial)
        # selected -1 cancels each old low word before Q=0 clearing.
        self.assertEqual(expected['v'][2],[0,0])

    def test_indexed_product_generator_independently_decodes_all_indices_registers_and_aliases(self):
        decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
        operations=[op for program in suite.indexed_product_programs() for op in program['operations']]
        for operation in operations:
            decoded=list(decoder.disasm(struct.pack('<I',operation['word']),0))
            self.assertEqual(len(decoded),1,operation)
            self.assertEqual(decoded[0].mnemonic.rstrip('2'),operation['name'],operation)
            self.assertIn(f"v{operation['m']}.",decoded[0].op_str,operation)
            self.assertIn(f"[{operation['index']}]",decoded[0].op_str,operation)
            if operation['lane']==2: self.assertLess(operation['m'],16)
        for name in ('mul','mla','mls','smull','umull','smlal','umlal','smlsl','umlsl'):
            for lane in (2,4):
                subset=[o for o in operations if o['name']==name and o['lane']==lane]
                self.assertEqual({o['index'] for o in subset},set(range(16//lane)))
                self.assertEqual({o['d'] for o in subset},set(range(32)))
                self.assertEqual({o['m'] for o in subset},set(range(16 if lane==2 else 32)))
                self.assertTrue(any(o['d']==o['m']==o['n'] for o in subset))

    def test_doubling_product_oracle_keeps_separate_saturation_and_rounding(self):
        initial=State();initial.fpsr=0x1f
        initial.v[1][:]=[0x8000,0];initial.v[2][:]=[0x8000,0]
        initial.v[0][:]=[0xffffffff,0xffffffffffffffff]
        base={'d':0,'n':1,'m':2,'lane':2,'output_lane':4,'bytes':4,'upper':False,'index':None}
        observed=suite.doubling_product_mathematical([{**base,'name':'sqdmlal'}],initial)
        self.assertEqual(observed['v'][0],[0x7ffffffe,0])
        self.assertEqual(observed['fpsr'],(1<<27)|0x1f)
        observed=suite.doubling_product_mathematical([{**base,'name':'sqdmlsl'}],initial)
        self.assertEqual(observed['v'][0],[0x80000000,0])
        high={**base,'name':'sqrdmulh','output_lane':2,'bytes':2}
        self.assertEqual(suite.doubling_product_mathematical([high],initial)['v'][0],[0x7fff,0])
        initial.v[1][:]=[0xffff,0];initial.v[2][:]=[0x4000,0]
        self.assertEqual(suite.doubling_product_mathematical([high],initial)['v'][0],[0,0])
        self.assertEqual(suite.doubling_product_mathematical([{**high,'name':'sqdmulh'}],initial)['v'][0],[0xffff,0])

    def test_polynomial_oracle_is_carryless_and_selects_both_upper_inputs(self):
        initial=State();initial.fpsr=(1<<27)|0x1f
        initial.v[1][:]=[3,1<<63];initial.v[2][:]=[3,1<<63]
        base={'name':'pmull','d':0,'n':1,'m':2,'lane':8,'output_lane':16,'bytes':16,'upper':True,'index':None}
        observed=suite.doubling_product_mathematical([base],initial)
        self.assertEqual(observed['v'][0],[0,1<<62])
        self.assertEqual(observed['fpsr'],initial.fpsr)
        self.assertEqual(suite.doubling_product_mathematical([{**base,'upper':False}],initial)['v'][0],[5,0])

    def test_doubling_product_generator_independently_decodes_each_allocated_form(self):
        decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
        operations=[op for program in suite.doubling_product_programs() for op in program['operations']]
        for operation in operations:
            decoded=list(decoder.disasm(struct.pack('<I',operation['word']),0))
            self.assertEqual(len(decoded),1,operation)
            self.assertEqual(decoded[0].mnemonic.rstrip('2'),operation['name'],operation)
        for name in ('sqdmulh','sqrdmulh','sqdmull','sqdmlal','sqdmlsl'):
            subset=[o for o in operations if o['name']==name]
            self.assertEqual({o['d'] for o in subset},set(range(32)))
            for lane in (2,4):
                self.assertEqual({o['index'] for o in subset if o['lane']==lane and o['index'] is not None},set(range(16//lane)))

    def test_product_oracle_keeps_full_signed_products_and_pretruncation_differences(self):
        initial=State()
        initial.v[1][:]=[0,0x80000000ffffffff]
        initial.v[2][:]=[0,0xffffffff00000002]
        base={'d':0,'n':1,'m':2,'lane':4,'output_lane':8,'bytes':16,'upper':True,
              'signed':True,'wide_left':False,'operation':'product','accumulate':None}
        self.assertEqual(suite.product_mathematical([base],initial)['v'][0],[suite.MASK-1,0x80000000])
        self.assertEqual(suite.product_mathematical([{**base,'signed':False}],initial)['v'][0],
                         [0x1fffffffe,0x7fffffff80000000])
        initial.v[1][:]=[0x8080808080808080]*2
        initial.v[2][:]=[0x7f7f7f7f7f7f7f7f]*2
        observed=suite.product_mathematical([{**base,'lane':1,'output_lane':1,'upper':False,'operation':'difference'}],initial)
        self.assertEqual(observed['v'][0],[suite.MASK,suite.MASK])
        self.assertEqual(observed['fpsr'],initial.fpsr)

    def test_saturation_oracle_handles_mixed_65_bit_sums_and_sticky_qc(self):
        initial=State()
        initial.fpsr=0x1f
        base={'d':0,'n':1,'m':2,'lane':8,'output_lane':8,'bytes':8,'upper':False}
        initial.v[0][:]=[1<<63,0]
        initial.v[1][:]=[suite.MASK,0]
        observed=suite.saturating_mathematical([{**base,'name':'suqadd'}],initial)
        self.assertEqual(observed['v'][0],[(1<<63)-1,0])
        self.assertEqual(observed['fpsr'],0x1f)
        initial.v[0][:]=[suite.MASK,0]
        observed=suite.saturating_mathematical([{**base,'name':'suqadd'}],initial)
        self.assertEqual(observed['v'][0],[(1<<63)-1,0])
        self.assertEqual(observed['fpsr'],(1<<27)|0x1f)
        initial.v[1][:]=[1<<63,0]
        observed=suite.saturating_mathematical([{**base,'name':'usqadd'}],initial)
        self.assertEqual(observed['v'][0],[(1<<63)-1,0])
        self.assertEqual(observed['fpsr'],0x1f)
        initial.fpsr=(1<<27)|0x1f
        initial.v[1][:]=[0,0]
        self.assertEqual(suite.saturating_mathematical([{**base,'name':'uqadd'}],initial)['fpsr'],initial.fpsr)

    def test_reduction_oracle_distinguishes_signed_long_sums_and_pair_grouping(self):
        initial=State()
        initial.v[1][:]=[suite.MASK,suite.MASK]
        base={'d':0,'n':1,'m':2,'lane':1,'bytes':16}
        self.assertEqual(suite.reduction_mathematical([{**base,'name':'saddlv'}],initial)['v'][0],[0xfff0,0])
        self.assertEqual(suite.reduction_mathematical([{**base,'name':'uaddlv'}],initial)['v'][0],[4080,0])
        initial.v[1][:]=struct.unpack('<2Q',bytes(range(16)))
        initial.v[2][:]=struct.unpack('<2Q',bytes(reversed(range(16))))
        observed=suite.reduction_mathematical([{**base,'name':'addp','bytes':8}],initial)
        self.assertEqual(observed['v'][0],[int.from_bytes(bytes([1,5,9,13,29,25,21,17]),'little'),0])

    def test_registered_register_cohorts_cover_each_form_and_destination(self):
        registry=json.loads((suite.ROOT/'tests/isa/apple-silicon-reviewed-forms.json').read_text())
        for group,generator,count in [('simd_integer',suite.integer_programs,38),
                ('simd_rearrange',suite.rearrange_programs,27),('simd_shifts',suite.shift_programs,26),
                ('simd_reductions',suite.reduction_programs,22),('simd_saturating',suite.saturating_programs,22),
                ('simd_products',suite.product_programs,25),
                ('simd_indexed_products',suite.indexed_product_programs,9),
                ('simd_floating_bits',suite.floating_bit_programs,13),('simd_halving',suite.halving_programs,16),
                ('simd_immediates',suite.immediate_programs,30),
                ('simd_register_shifts',suite.register_shift_programs,22),
                ('simd_doubling_products',suite.doubling_product_programs,22)]:
            forms=[f for f in registry['forms'] if group in f.get('evidence_groups',[])]
            operations=[o for p in generator() for o in p['operations']]
            self.assertEqual(len(forms),count,group)
            for form in forms:
                matches=[o for o in operations if o['word']&int(form['encoding_mask'],16)==int(form['encoding_value'],16)]
                self.assertTrue(matches,form['id'])
                self.assertEqual({o['d'] for o in matches},set(range(32)),form['id'])

    def test_register_shift_encodings_cover_allocated_sizes_and_every_destination(self):
        operations=[o for p in suite.register_shift_programs() for o in p['operations']]
        decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
        for op in operations:
            decoded=list(decoder.disasm(struct.pack('<I',op['word']),0))
            self.assertEqual(len(decoded),1,hex(op['word']))
            self.assertEqual(decoded[0].mnemonic,op['name'])
        for name in ('sshl','ushl','srshl','urshl','sqshl','uqshl','sqrshl','uqrshl'):
            for scalar in (False,True):
                matches=[o for o in operations if o['name']==name and o['scalar']==scalar and not o['immediate']]
                self.assertEqual({o['d'] for o in matches},set(range(32)))
                self.assertEqual({o['lane'] for o in matches},{8} if scalar and 'q' not in name else {1,2,4,8})
        for name in ('sqshl','uqshl','sqshlu'):
            for scalar in (False,True):
                matches=[o for o in operations if o['name']==name and o['scalar']==scalar and o['immediate']]
                self.assertEqual({o['d'] for o in matches},set(range(32)))
                self.assertEqual({o['lane'] for o in matches},{1,2,4,8})

    def test_register_shift_oracle_large_counts_rounding_qc_and_signed_to_unsigned_zero(self):
        initial=State();initial.fpsr=0x1f;initial.v[1][:]=[suite.MASK,suite.MASK]
        base={'d':0,'n':1,'m':2,'lane':8,'bytes':8,'signed':False,'unsigned_result':True,
              'round':True,'saturating':False,'immediate':False}
        initial.v[2][:]=[0xfedcba98765432c0,0]
        self.assertEqual(suite.register_shift_mathematical([base],initial)['v'][0],[1,0])
        self.assertEqual(suite.register_shift_mathematical([{**base,'signed':True}],initial)['v'][0],[0,0])
        initial.v[2][:]=[0x0123456789abcd80,0]
        self.assertEqual(suite.register_shift_mathematical([base],initial)['v'][0],[0,0])
        self.assertEqual(suite.register_shift_mathematical([{**base,'signed':True,'round':False}],initial)['v'][0],[suite.MASK,0])
        initial.v[2][:]=[127,0]
        observed=suite.register_shift_mathematical([{**base,'saturating':True}],initial)
        self.assertEqual(observed['v'][0],[suite.MASK,0]);self.assertEqual(observed['fpsr'],0x800001f)
        initial.v[1][:]=[0,suite.MASK]
        observed=suite.register_shift_mathematical([{**base,'saturating':True}],initial)
        self.assertEqual(observed['v'][0],[0,0]);self.assertEqual(observed['fpsr'],0x1f)
        initial.v[1][:]=[suite.MASK,suite.MASK]
        mixed={**base,'signed':True,'saturating':True,'immediate':True,'amount':0}
        observed=suite.register_shift_mathematical([mixed],initial)
        self.assertEqual(observed['v'][0],[0,0]);self.assertEqual(observed['fpsr'],0x800001f)
        initial.fpsr=0x800001f;initial.v[1][:]=[0,0]
        self.assertEqual(suite.register_shift_mathematical([mixed],initial)['fpsr'],0x800001f)

    def test_register_shift_directed_seed_has_extreme_signed_bytes_and_poisoned_count_bits(self):
        operation=next(p['operations'][0] for p in suite.register_shift_programs()
                       if not p['operations'][0]['immediate'] and p['operations'][0]['lane']==8
                       and p['operations'][0]['scalar'] and p['operations'][0]['n']!=p['operations'][0]['m'])
        seen=set()
        for pattern in range(suite.register_shift_pattern_count([operation])):
            initial=State();suite.register_shift_seed(initial,[operation],pattern,0)
            count=initial.v[operation['m']][0];seen.add(count&255)
            if pattern<suite.register_shift_pattern_count([operation])-2: self.assertNotEqual(count>>8,0)
        self.assertTrue({0x80,0x7f,0xc0,0x40,0xff,0}.issubset(seen))

    def test_immediate_doubling_seeds_hit_exact_saturation_thresholds(self):
        for signed, unsigned, expected_qc in [(True,False,[False,True,False,True]),
                (False,True,[False,True,True,False]),(True,True,[True,True,False,False])]:
            for lane in (1,2,4,8):
                operation=next(p['operations'][0] for p in suite.register_shift_programs()
                    if all(p['operations'][0].get(k)==v for k,v in
                        {'immediate':True,'amount':1,'signed':signed,'unsigned_result':unsigned,
                         'lane':lane,'d':0,'n':1}.items()))
                self.assertEqual(suite.register_shift_pattern_count([operation]),12)
                for pattern,qc in zip(range(6,10),expected_qc):
                    initial=State();suite.register_shift_seed(initial,[operation],pattern,0)
                    expected=suite.register_shift_mathematical([operation],initial)
                    self.assertEqual(bool(expected['fpsr']&(1<<27)),qc,(signed,unsigned,lane,pattern))

    def test_shift_oracle_full_width_rounding_boundaries(self):
        initial=State()
        initial.v[1][:]=[suite.MASK,suite.MASK]
        base={'d':0,'n':1,'lane':8,'output_lane':8,'bytes':8,'amount':64,'upper':False}
        self.assertEqual(suite.shift_mathematical([{**base,'name':'urshr'}],initial)['v'][0],[1,0])
        self.assertEqual(suite.shift_mathematical([{**base,'name':'srshr'}],initial)['v'][0],[0,0])
        self.assertEqual(suite.shift_mathematical([{**base,'name':'sshr'}],initial)['v'][0],[suite.MASK,0])

    def test_table_corpus_contains_register_wrapping_and_both_widths(self):
        operations=[o for p in suite.rearrange_programs() for o in p['operations']]
        for name in ('tbl','tbx'):
            tables=[o for o in operations if o['name']==name]
            self.assertEqual({o['registers'] for o in tables},{1,2,3,4})
            self.assertEqual({o['bytes'] for o in tables},{8,16})
            self.assertTrue(any(o['n']==31 and o['d']==o['m'] for o in tables))

    def test_lane_oracle_has_independent_signed_width_zero_and_preserved_lane_rules(self):
        initial=State()
        initial.v[31][:]=[0x80,0xffffffffffffffff]
        operation={'name':'smov','d':0,'n':31,'m':0,'lane':1,'bytes':8,'index':0}
        observed=suite.rearrange_mathematical([operation],initial)
        self.assertEqual(observed['x'][0],0xffffff80) # signed W write still clears X high half
        operation['bytes']=16
        self.assertEqual(suite.rearrange_mathematical([operation],initial)['x'][0],0xffffffffffffff80)
        ins={'name':'insg','d':31,'n':31,'m':0,'lane':1,'bytes':16,'index':7}
        observed=suite.rearrange_mathematical([ins],initial)
        self.assertEqual(observed['v'][31],[0x80,0xffffffffffffffff])

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
