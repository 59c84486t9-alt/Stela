"""Independent encoding/coverage and SIMD byte-oracle regression checks."""
import ctypes
import importlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import State, state_dict, seed_extended_state

suite = importlib.import_module('simd-differential')


class SimdDifferentialTests(unittest.TestCase):
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
