"""Independent encoding/coverage and SIMD byte-oracle regression checks."""
import ctypes
import importlib
import json
import struct
import unittest

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import State, state_dict, seed_extended_state

suite = importlib.import_module('simd-differential')


class SimdDifferentialTests(unittest.TestCase):
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
                ('simd_products',suite.product_programs,25),('simd_halving',suite.halving_programs,16),
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
