"""Pure family models and focused shared-runner infrastructure guards."""
import ctypes
import importlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import nullcontext

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import ROOT, BASE, State, seed_extended_state
from simd_fixtures import aes, sha12, sha512, sha3, i8mm, structure_memory, ordinary_memory, atomic_memory, atomic_pair_memory, ordered_unscaled_memory, tag_arithmetic
import simd_fixture_runner as runner
import simd_original
import simd_memory_runner
import hashlib

engine = importlib.import_module('simd-differential')

class TagArithmeticAdapterTests(unittest.TestCase):
    @staticmethod
    def feature_header():
        header = bytearray(simd_original.HEADER_BYTES)
        registers = [0] * len(simd_original.CPU_REGISTERS)
        registers[0], registers[4] = 4, 2 << 8
        struct.pack_into('<9Q', header, 0, *registers)
        struct.pack_into('<2Q', header, simd_original.TAG_CONTROL_HEADER_OFFSET, *simd_original.TAG_CONTROLS.values())
        return header

    @staticmethod
    def frame(initial, final, subject_pc=0x8000, undefined=False):
        result = bytearray(simd_original.RECORD_BYTES)
        result[:256] = bytes(final)[:256]
        result[320:832] = bytes(final)[264:776]
        fpcr, fpsr = initial.fpcr & simd_original.QEMU_FPCR_MASK, initial.fpsr & simd_original.QEMU_FPSR_MASK
        fields = {'sp': final.sp, 'spsr': final.nzcv | simd_original.PSTATE_EL0T_MASKED,
            'fpcr': fpcr, 'fpsr': fpsr, 'pre_fpcr': fpcr, 'pre_fpsr': fpsr,
            'esr': simd_original.TAG_UNDEFINED_ESR if undefined else (0x15 << 26) | (1 << 25) | simd_original.SVC_IMMEDIATE,
            'elr': subject_pc if undefined else subject_pc + 8, 'current_el': 4,
            'cpacr': simd_original.FP_ACCESS_ENABLED, 'marker': simd_original.COMPLETED_MARKER}
        for name, value in fields.items(): struct.pack_into('<Q', result, simd_original.LAYOUT[name], value)
        return result

    def test_actual_GPR_corpus_has_no_vector_merge_or_X30_normalization(self):
        operations, records = runner.fixture_corpus(tag_arithmetic)
        original_operations, original_cases = tag_arithmetic.corpus()
        self.assertEqual(operations, original_operations)
        self.assertTrue(all(op['output_kind'] == 'gpr' and 'merge' not in op for op in operations))
        self.assertEqual([record['initial'] for record in records], [case['initial'] for case in original_cases])
        self.assertTrue(any(State.from_buffer_copy(record['initial']).x[30] != engine.STOP for record in records))
        self.assertEqual({op['canonical_id'] for op in operations}, set(tag_arithmetic.CANONICAL_FORMS))

    def test_expected_State_allows_only_encoded_GPR_SP_and_SUBPS_flags(self):
        family = tag_arithmetic
        initial = family.initial_state(0, 0)
        for name in family.FORMS:
            for destination in (0, 30, 31):
                op = family.operation(name, d=destination, n=30)
                result = runner.expected_state(family, op, initial)
                self.assertEqual(bytes(result), bytes(family.expected(op, initial)))
                permitted = set(op['written_gprs'])
                for register in set(range(31)) - permitted: self.assertEqual(result.x[register], initial.x[register])
                if not op['writes_sp']: self.assertEqual(result.sp, initial.sp)
                if not op['writes_nzcv']: self.assertEqual(result.nzcv, initial.nzcv)
        op = family.operation('addg')
        for field, value in (('word', op['word'] ^ 1), ('d', 3), ('n', 4), ('written_gprs', [2]),
                             ('writes_sp', True), ('writes_nzcv', True), ('written_vectors', [0])):
            with self.assertRaises(AssertionError): runner.expected_state(family, {**op, field: value}, initial)
        correct = family.expected(op, initial)
        for offset in (8 * 4, 248, 256, 260, 264, 776, 780):
            damaged = bytearray(bytes(correct))
            damaged[offset] ^= 1
            with patch.object(family, 'expected', return_value=State.from_buffer_copy(damaged)):
                with self.assertRaises(AssertionError): runner.expected_state(family, op, initial)

    def test_tag_feature_controls_and_typed_effect_metadata_reject_mutations(self):
        header = self.feature_header()
        self.assertEqual(simd_original.validate_tag_features(header)['MTE'], 2)
        for offset, value in ((4 * 8, 1 << 8), (4 * 8, 4 << 8), (0, 0),
                (simd_original.TAG_CONTROL_HEADER_OFFSET, simd_original.TAG_SCTLR & ~simd_original.TAG_ATA0),
                (simd_original.TAG_CONTROL_HEADER_OFFSET, simd_original.TAG_SCTLR | 1 << 38),
                (simd_original.TAG_CONTROL_HEADER_OFFSET + 8, 1)):
            changed = bytearray(header)
            struct.pack_into('<Q', changed, offset, value)
            with self.assertRaises(AssertionError): simd_original.validate_tag_features(changed)
        for name in tag_arithmetic.FORMS:
            for d in (0, 30, 31):
                op = tag_arithmetic.operation(name, d=d)
                self.assertEqual(simd_original.tag_destinations(op), (set(op['written_gprs']), set(), op['writes_sp'], op['writes_nzcv']))
                for key, value in (('word', op['word'] ^ 1), ('d', (d + 1) % 32), ('n', 7),
                        ('canonical_id', 'wrong'), ('output_kind', 'vector'), ('writes_sp', 1),
                        ('writes_sp', not op['writes_sp']), ('writes_nzcv', not op['writes_nzcv']), ('written_gprs', [1, 1])):
                    with self.assertRaises(AssertionError): simd_original.tag_destinations({**op, key: value})
                role = 'tag_offset' if name in ('addg', 'subg') else 'm'
                with self.assertRaises(AssertionError): simd_original.tag_destinations({**op, role: 3})

    def test_only_exact_nonzero_ADDG_SUBG_UNDEF_preserves_full_frame(self):
        initial = tag_arithmetic.initial_state(0, 0)
        initial.x[30] = 0x76543210abcdef01
        inputs = struct.pack('<Q', 0) + bytes(initial) + bytes(8)
        subjects = [{'instruction_pc': 0x8000, 'expected_elr': 0x8008}]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            def check(op, frame):
                (directory / 'results.bin').write_bytes(self.feature_header() + frame)
                return simd_original.validate_results(directory, [op], [{}], inputs, subjects, tag_arithmetic.FOCUS)
            for name in ('addg', 'subg'):
                for soft in (1, 2, 3):
                    op = tag_arithmetic.operation(name, soft_bits=soft)
                    frame = self.frame(initial, initial, undefined=True)
                    observed = check(op, frame)['tag_soft_fixed_undefined_cases']
                    self.assertEqual([row['case_index'] for row in observed], [0])
                    self.assertEqual(observed[0]['word'], op['word'])
                    for offset in (0, 248, 256, 264, 272, 320):
                        damaged = bytearray(frame)
                        damaged[offset] ^= 1
                        with self.assertRaises(AssertionError): check(op, damaged)
                    for field, value in (('esr', simd_original.TAG_UNDEFINED_ESR | 1), ('elr', 0x8004),
                            ('spsr', initial.nzcv | simd_original.PSTATE_EL0T_MASKED | 1 << 28)):
                        damaged = bytearray(frame)
                        struct.pack_into('<Q', damaged, simd_original.LAYOUT[field], value)
                        with self.assertRaises(AssertionError): check(op, damaged)
            sp_op = tag_arithmetic.operation('addg', d=31, soft_bits=1)
            sp_frame = self.frame(initial, initial, undefined=True)
            check(sp_op, sp_frame)
            struct.pack_into('<Q', sp_frame, simd_original.LAYOUT['sp'], initial.sp ^ 1)
            with self.assertRaises(AssertionError): check(sp_op, sp_frame)
            for name in tag_arithmetic.FORMS:
                op = tag_arithmetic.operation(name)
                with self.assertRaises(AssertionError): check(op, self.frame(initial, initial, undefined=True))
                normal = self.frame(initial, tag_arithmetic.expected(op, initial))
                self.assertEqual(check(op, normal)['tag_soft_fixed_undefined_cases'], [])
                struct.pack_into('<Q', normal, simd_original.LAYOUT['elr'], 0x800c)
                with self.assertRaises(AssertionError): check(op, normal)

    def test_load_original_preserves_real_X30_and_classifies_case_index(self):
        initial = tag_arithmetic.initial_state(0, 0)
        initial.x[30], initial.fpcr, initial.fpsr = 0x76543210abcdef01, 0, 0
        (ROOT / '.stela').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.stela') as temporary:
            directory = Path(temporary)
            for undefined in (False, True):
                op = tag_arithmetic.operation('addg', n=30, soft_bits=1) if undefined else tag_arithmetic.operation('subp', n=30)
                case = {'function': 0, 'runtime': True, 'initial': bytes(initial)}
                family = SimpleNamespace(FOCUS=tag_arithmetic.FOCUS, CANONICAL_FORMS=(op['canonical_id'],),
                    functions=lambda: [op], corpus=lambda: ([op], [case]), expected=tag_arithmetic.expected,
                    validate_effects=tag_arithmetic.validate_effects)
                operations, cases = runner.fixture_corpus(family)
                final = initial if undefined else tag_arithmetic.expected(op, initial)
                values = {'functions.json': simd_original.json_bytes([{**operations[0], 'source_hex': struct.pack('<II', op['word'], engine.RET).hex()}]),
                    'cases.json': simd_original.json_bytes([{key: value for key, value in cases[0].items() if key != 'initial'}]),
                    'inputs.bin': struct.pack('<Q', 0) + bytes(initial) + bytes(8),
                    'results.bin': self.feature_header() + self.frame(initial, final, undefined=undefined), 'guest.elf': b'fixture-ELF'}
                for name, data in values.items(): (directory / name).write_bytes(data)
                files = {name: {'sha256': engine.digest(data), 'bytes': len(data)} for name, data in values.items()}
                producer = {'passed_transport_and_architectural_frame_checks': True, 'cases': 1, 'directory': str(directory.relative_to(ROOT)),
                    'files': files, 'tag_soft_fixed_undefined_cases': [{'case_index': 0}] if undefined else []}
                receipt_path, pointer_path = directory / 'producer.json', directory / 'pointer.json'
                def publish():
                    receipt_path.write_bytes(simd_original.json_bytes(producer))
                    pointer_path.write_bytes(simd_original.json_bytes({'directory': producer['directory'],
                        'receipt': {'path': str(receipt_path.relative_to(ROOT)), 'sha256': engine.digest(receipt_path.read_bytes())}}))
                publish()
                def word_at(elf, address): return op['word'] if address == 0x8000 else engine.FP_REGISTER_SVC
                with patch.object(engine, 'fp_register_elf_word', side_effect=word_at):
                    loaded = runner.load_original(engine, family, pointer_path)['records'][0]
                    self.assertEqual(State.from_buffer_copy(loaded['initial']).x[30], initial.x[30])
                    self.assertEqual(State.from_buffer_copy(loaded['expected']).x[30], initial.x[30])
                    self.assertEqual(State.from_buffer_copy(loaded['primary_expected']).x[30], initial.x[30])
                    self.assertEqual(loaded['equality_basis'], 'soft_fixed_execute_as_policy' if undefined else 'direct_original')
                    if undefined:
                        producer['tag_soft_fixed_undefined_cases'] = [{'case_index': 1}]
                        publish()
                        with self.assertRaises(AssertionError): runner.load_original(engine, family, pointer_path)


class AtomicPairMemoryFixtureTests(unittest.TestCase):
    def test_allocated_eight_forms_all_pair_roles_bases_and_independent_decode(self):
        family = atomic_pair_memory
        operations = family.functions()
        self.assertEqual(len(family.CANONICAL_FORMS), 8)
        self.assertEqual(len(operations), 3464)
        source = b''.join(struct.pack('<II', op['word'], engine.RET) for op in operations)
        result = family.validate_source_words(source, [{'operations': [op]} for op in operations], set())
        self.assertEqual(result['capstone_decode_fallback_words'], 0)
        for canonical in family.CANONICAL_FORMS:
            rows = [op for op in operations if op['canonical_id'] == canonical]
            self.assertEqual({(op['rs'], op['rt']) for op in rows}, {(rs, rt) for rs in range(0, 32, 2) for rt in range(0, 32, 2)})
            self.assertEqual({op['rn'] for op in rows}, set(range(32)))
            for register in range(0, 32, 2):
                for rt in (register, (register + 2) % 32):
                    self.assertTrue({register, register + 1, rt, rt + 1, 31} <=
                        {op['rn'] for op in rows if op['rs'] == register and op['rt'] == rt})
            for op in rows:
                self.assertEqual(op['word'] & family.CASP_CLASS_MASK, family.CASP_CLASS)
                self.assertEqual(op['compare'], [op['rs'], op['rs'] + 1])
                self.assertEqual(op['source'], [op['rt'], op['rt'] + 1])
                self.assertEqual(op['written_gprs'], [r for r in op['compare'] if r != 31])
        corrupted = {**operations[0], 'compare': [0, 3]}
        with self.assertRaises(AssertionError):
            family.validate_source_words(struct.pack('<II', corrupted['word'], engine.RET), [{'operations': [corrupted]}], set())

    def test_full_corpus_matches_independent_packed_pair_math_and_all_flags(self):
        family = atomic_pair_memory
        operations, cases = family.corpus()
        memory, flags, positions, modes = family.memory_template(), {}, {}, set()
        self.assertEqual(len(cases), 10592)
        self.assertEqual(len(memory), 8192)
        for case in cases:
            op, initial = operations[case['function']], State.from_buffer_copy(case['initial'])
            width, position = op['element_bytes'], case['position']
            mask = (1 << (width * 8)) - 1
            incoming = [0 if register == 31 else initial.x[register] & mask for register in op['compare']]
            replacement = [0 if register == 31 else initial.x[register] & mask for register in op['source']]
            old = [int.from_bytes(memory[position + half * width:position + (half + 1) * width], 'little') for half in range(2)]
            expected = State.from_buffer_copy(bytes(initial))
            for register, value in zip(op['compare'], old):
                if register != 31: expected.x[register] = value
            expected_ram = bytearray(memory)
            if incoming == old:
                expected_ram[position:position + width * 2] = b''.join(value.to_bytes(width, 'little') for value in replacement)
            actual, ram, fault = family.expected(op, initial, memory)
            self.assertIsNone(fault)
            self.assertEqual(bytes(actual), bytes(expected))
            self.assertEqual(ram, bytes(expected_ram))
            self.assertEqual(case['compare_matches'], incoming == old)
            self.assertEqual(len(bytes(actual)), 784)
            flags.setdefault(op['canonical_id'], set()).add(initial.nzcv >> 28)
            positions.setdefault(width, set()).add(position % 16)
            modes.add(case['compare_mode'])
        self.assertEqual(modes, {'match', 'low_mismatch', 'high_mismatch'})
        self.assertTrue(all(values == set(range(16)) for values in flags.values()))
        self.assertEqual(positions, {4: set(range(9)), 8: {0}})

    def test_pair_model_atomic_faults_permissions_alignment_and_ZR(self):
        family = atomic_pair_memory
        for width in family.WIDTHS:
            op = family.operation(width)
            total = op['total_bytes']
            initial = family.initial_state(op, 0, 16)
            memory = family.memory_template()[:64]
            for matches in (True, False):
                current = State.from_buffer_copy(bytes(initial))
                if not matches: current.x[0] ^= 1
                actual, ram, fault = family.expected(op, current, memory, readonly=True)
                self.assertEqual(fault['kind'], 'memory')
                self.assertEqual(bytes(actual), bytes(current))
                self.assertEqual(ram, memory)
            for offset in range(16):
                current = State.from_buffer_copy(bytes(initial))
                current.x[5] = family.RAM_ADDRESS + 16 + offset
                actual, ram, fault = family.expected(op, current, memory)
                self.assertEqual(fault is None, offset + total <= 16)
                if fault:
                    self.assertEqual(fault['kind'], 'sca_alignment')
                    self.assertEqual(bytes(actual), bytes(current))
                    self.assertEqual(ram, memory)
            for accessible in range(16, 16 + total):
                actual, ram, fault = family.expected(op, initial, memory, accessible=accessible)
                self.assertEqual(fault['kind'], 'memory')
                self.assertEqual(bytes(actual), bytes(initial))
                self.assertEqual(ram, memory)
            sp_op = family.operation(width, rs=30, rt=30, rn=31)
            current = family.initial_state(sp_op, 0, 16, compare=(1, 0))
            current.sp = family.RAM_ADDRESS + 1
            actual, ram, fault = family.expected(sp_op, current, memory, accessible=0)
            self.assertEqual(fault['kind'], 'sp_alignment')
            self.assertEqual(bytes(actual), bytes(current))
            memory = bytearray(64)
            memory[16:16 + width] = (1).to_bytes(width, 'little')
            current.sp = family.RAM_ADDRESS + 16
            actual, ram, fault = family.expected(sp_op, current, memory)
            self.assertIsNone(fault)
            self.assertEqual(actual.x[30], 1)
            self.assertEqual(actual.sp, current.sp)
            self.assertEqual(ram, bytes(memory))

    def test_independent_Cx16_and_all_odd_first_declines(self):
        family = atomic_pair_memory
        for op in family.shapes():
            self.assertEqual(family.supported_on_profile(op, 'x86_64-baseline'), op['total_bytes'] == 8)
            self.assertEqual(family.supported_on_profile(op, 'x86_64-baseline+atomic-load16'), op['total_bytes'] == 8)
            self.assertTrue(family.supported_on_profile(op, 'x86_64-baseline+cx16'))
            self.assertTrue(family.supported_on_profile(op, 'x86_64-baseline+atomic-load16+cx16'))
            for register in range(1, 32, 2):
                for field in ('rs', 'rt'):
                    with self.assertRaises(ValueError): family.operation(op['element_bytes'], op['order'], **{field: register})
        declined = family.declined_encodings()
        self.assertEqual(len(declined), 260)
        self.assertEqual(sum(row['reason'] == 'Cx16_host_capability' for row in declined), 4)
        self.assertEqual(simd_memory_runner.family_module(family.FOCUS), family)
        for case in family.fault_selection():
            op = family.fault_operation(family.shapes()[case['function']], case)
            state = family.fault_initial_state(op, case, 0)
            self.assertEqual(len(bytes(state)), 784)
            if case['protection'] == 'readonly' and op['rs'] != 30:
                width, mask = op['element_bytes'], (1 << (op['element_bytes'] * 8)) - 1
                old = int.from_bytes(b'\xa5' * width, 'little')
                values = [state.x[register] & mask for register in op['compare']]
                self.assertEqual(values == [old, old], case['compare_matches'])

    def test_pair_bounded_histories_and_original_two_orders_reject_torn_state_RAM(self):
        import simd_atomic_original as smp
        family = atomic_pair_memory
        self.assertEqual(len(family.concurrency_cases()), 20)
        pairs = smp.pair_default_pairs(trials=1)
        self.assertEqual(len(pairs), 8)
        files, plan, _ = smp.input_files(pairs, focus=smp.PAIR_FOCUS)
        self.assertEqual((len(files['inputs.bin']), len(files['memory.bin']), len(plan)), (8 * 1600, 8 * 8192, 8))
        for case in pairs:
            for order in ((0, 1), (1, 0)):
                memory, finals, rows = case['memory'], list(case['initial']), []
                for thread in order:
                    initial, op = State.from_buffer_copy(case['initial'][thread]), case['programs'][thread][0]
                    final, memory, fault = family.history_expected(op, initial, memory)
                    self.assertIsNone(fault)
                    finals[thread] = bytes(final)
                    rows.append({'operation': op, 'initial_state_hex': bytes(initial).hex(), 'final_state_hex': bytes(final).hex(), 'begin': 0, 'end': 1})
                self.assertTrue(family.linearization_allowed(rows, case['memory'], final_ram=memory))
                simd_memory_runner.validate_atomic_smp_trial(case, finals, memory, None, family)
                damaged = list(finals)
                state = State.from_buffer_copy(damaged[0])
                state.x[1] ^= 1
                damaged[0] = bytes(state)
                with self.assertRaises(AssertionError):
                    simd_memory_runner.validate_atomic_smp_trial(case, damaged, memory, None, family)
                damaged_ram = memory[:-1] + bytes([memory[-1] ^ 1])
                self.assertFalse(family.linearization_allowed(rows, case['memory'], final_ram=damaged_ram))
                with self.assertRaises(AssertionError):
                    simd_memory_runner.validate_atomic_smp_trial(case, finals, damaged_ram, None, family)
                with self.assertRaises(ValueError): family.linearization_allowed(rows * 9, case['memory'])
        for case in family.concurrency_cases():
            self.assertEqual(len(family.concurrency_plan(case, [0, 1])), 11392)
            self.assertEqual(case['kind'], 0)
            for kind in range(1, 5):
                with self.assertRaises(ValueError): family.concurrency_plan({**case, 'kind': kind}, [0, 1])
            self.assertLessEqual(case['threads'] * case['iterations'], 16)
            self.assertTrue(all(30 not in op.get('written_gprs', []) for program in case['programs'] for op in program))

    def test_pair_observer_metadata_and_normal_return_ABI_wrapper_call(self):
        from capstone import CS_ARCH_X86, CS_MODE_64
        family = atomic_pair_memory
        for shape in family.shapes():
            for first in (0, 30):
                op = family.operation(shape['element_bytes'], shape['order'], rs=first, rt=first, rn=31)
                self.assertEqual(simd_original.memory_destinations(op), (set(op['written_gprs']), set(), False))
                with self.assertRaises(AssertionError): simd_original.memory_destinations({**op, 'total_bytes': 4})
                with self.assertRaises(AssertionError): simd_original.memory_destinations({**op, 'written_gprs': [0, 0]})
        native, entry = b'\x90\x90\xc3', 1
        wrapped, prefix = simd_memory_runner.normal_return_rbx_wrapper(native, entry)
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(wrapped[:prefix], 0))
        self.assertEqual([instruction.mnemonic for instruction in decoded], ['push', 'movabs', 'call', 'mov', 'pop', 'ret'])
        self.assertEqual(decoded[2].op_str, hex(prefix + entry))
        self.assertEqual(wrapped[prefix:], native)
        self.assertEqual(struct.unpack_from('<Q', wrapped, 3)[0], simd_memory_runner.NORMAL_RBX_SENTINEL)
        self.assertEqual(prefix, 21)
        for invalid in (-1, len(native)):
            with self.assertRaises(ValueError): simd_memory_runner.normal_return_rbx_wrapper(native, invalid)

    def test_previous_scalar_SMP_inputs_and_observer_assembly_remain_frozen(self):
        import simd_atomic_original as smp
        files, plan, _ = smp.input_files(smp.default_pairs())
        expected = {'pair-plan.json': 'ffa787a4df09921c77ec7b211864378f30eacd8667f8584b12bdc650a95b523a',
            'inputs.bin': '8b90f6223c91854c75a24b0411c99c0796e7495631842235ff3421152aa7c6b6',
            'memory.bin': '60724f0a65a0171b5731feb83d63ab905826b3dd0572b1ae8aea2daac30c9317',
            'canonical-source.arm64': 'e81affb6ca4f7c54c7a7238ef3922c3854387aadc50538559a878bcece1e6687',
            'input-plan.json': '04932bf8cc90f54372f50c94adf7fa6381f3573f3b85d4b9c8d72e177ae29e9b'}
        self.assertEqual({name: engine.digest(data) for name, data in files.items()}, expected)
        self.assertEqual(engine.digest(smp.assembly(plan).encode()), 'a6d7f8b519a5a4a70d3db87c2a7310a57db1f9b9fe600b513f117d2d768f605e')

    def test_previous_scalar_atomic_corpus_bytes_remain_frozen(self):
        operations, cases = atomic_memory.corpus()
        compact = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(engine.digest(compact(operations)), 'deb705b7dbe00812fd1f351e55f14a1ce01bee1dd22bb9216d887764ccb52f43')
        self.assertEqual(engine.digest(compact([{k: v for k, v in case.items() if k != 'initial'} for case in cases])),
                         '0714d3ed93c040d3c953ed712419fbc664eb545ee22894a57328dab211b706c8')
        inputs = b''.join(struct.pack('<Q', case['function']) + case['initial'] + bytes(8) for case in cases)
        self.assertEqual(engine.digest(inputs), '8794a4922ad5ed983d50213d28b827995e4a4fc1658c46cbbf00a57e76759b5f')
        self.assertEqual(engine.digest(atomic_memory.memory_template()), '89e65d5009df72c2afc3e63ed9dc8d1ec6be190814a229732bc2b2be926c4e59')


class OrderedUnscaledFixtureTests(unittest.TestCase):
    def test_full_forms_words_models_and_actual_target_filter(self):
        family = ordered_unscaled_memory
        operations, cases = family.corpus()
        self.assertEqual((len(family.CANONICAL_FORMS), len(operations), len(cases)), (13, 1808, 2202))
        source = b''.join(struct.pack('<II', op['word'], engine.RET) for op in operations)
        self.assertEqual(family.validate_source_words(source, [{'operations': [op]} for op in operations], set())['capstone_decode_fallback_words'], 0)
        self.assertEqual(sum(family.supported_on_profile(op, 'baseline') for op in operations), 1067)
        self.assertTrue(all(family.supported_on_profile(op, 'x86_64-baseline+atomic-load16') for op in operations))
        flags, offsets = {}, set()
        memory = family.memory_template()
        for case in cases:
            op, initial = operations[case['function']], State.from_buffer_copy(case['initial'])
            actual, ram, fault = family.expected(op, initial, memory)
            self.assertIsNone(fault)
            position, width = family.effective_address(op, initial) - family.RAM_ADDRESS, op['element_bytes']
            expected, expected_ram = State.from_buffer_copy(bytes(initial)), bytearray(memory)
            if op['loading']:
                value = int.from_bytes(memory[position:position + width], 'little', signed=op['signed'])
                if op['rt'] != 31: expected.x[op['rt']] = value & ((1 << op['output_bits']) - 1)
            else:
                value = 0 if op['rt'] == 31 else initial.x[op['rt']] & ((1 << (width * 8)) - 1)
                expected_ram[position:position + width] = value.to_bytes(width, 'little')
            self.assertEqual(bytes(actual), bytes(expected))
            self.assertEqual(ram, bytes(expected_ram))
            flags.setdefault(op['canonical_id'], set()).add(initial.nzcv >> 28)
            offsets.add(op['offset'])
            self.assertNotIn('rs', op)
        self.assertTrue(all(values == set(range(16)) for values in flags.values()))
        self.assertTrue({-256, -1, 0, 1, 255} <= offsets)
        self.assertEqual(simd_memory_runner.family_module(family.FOCUS), family)

    def test_all_thirteen_ordered_histories_use_actual_EA_aliases_and_complete_bytes(self):
        family = ordered_unscaled_memory
        cases = family.concurrency_cases()
        self.assertEqual(len(cases), 13)
        baseline = [case for case in cases if all(family.supported_on_profile(op, 'baseline') for program in case['programs'] for op in program)]
        self.assertEqual(len(baseline), 4)
        self.assertEqual(sum(case['alias'] for case in cases), 6)
        for case in cases:
            self.assertEqual(len(family.concurrency_plan(case, [0, 1])), 11392)
            states, bases = [], []
            for thread, raw in enumerate(case['initial']):
                base = family.RAM_ADDRESS + (0x100000 if case['alias'] and thread & 1 else 0)
                bases.append(base)
                states.append(atomic_memory.relocate_state(raw, base))
            memory, rows = case['memory'], []
            for iteration in range(case['iterations']):
                for thread in range(case['threads']):
                    op, initial = case['programs'][thread][0], State.from_buffer_copy(bytes(states[thread]))
                    final, memory, fault = family.history_expected(op, initial, memory, bases[thread])
                    self.assertIsNone(fault)
                    rows.append({'operation': op, 'initial_state_hex': bytes(initial).hex(), 'final_state_hex': bytes(final).hex(),
                                 'ram_address': bases[thread], 'begin': len(rows) * 2, 'end': len(rows) * 2 + 1})
                    states[thread] = final
            self.assertTrue(family.linearization_allowed(rows, case['memory'], final_ram=memory))
            damaged = [dict(row) for row in rows]
            altered = State.from_buffer_copy(bytes.fromhex(damaged[0]['final_state_hex']))
            altered.nzcv ^= 1 << 28
            damaged[0]['final_state_hex'] = bytes(altered).hex()
            self.assertFalse(family.linearization_allowed(damaged, case['memory'], final_ram=memory))
            self.assertFalse(family.linearization_allowed(rows, case['memory'], final_ram=memory[:-1] + bytes([memory[-1] ^ 1])))
            self.assertTrue(all(row['operation']['offset'] in (-17, 17) for row in rows))

    def test_SP_offset_snapshot_and_source_fault_order(self):
        family = ordered_unscaled_memory
        for canonical, _, width, output_bits, _, _ in family.FORMS:
            if width == 1 or not output_bits: continue
            for offset in (9 - width, -7 - width):
                op = family.operation(canonical, rn=31, offset=offset)
                initial = family.initial_state(op, 0, 512 + offset % 16)
                self.assertTrue(family.snapshot_read(op, initial))
                self.assertFalse(family.supported_on_profile(op, 'x86_64-baseline'))
                self.assertTrue(family.supported_on_profile(op, 'x86_64-baseline+atomic-load16'))
                self.assertEqual(family.effective_address(op, initial) & ~15, family.RAM_ADDRESS + 512)
                self.assertEqual(simd_original.memory_destinations(op), ({1}, set(), False))
            op = family.operation(canonical, rn=31, offset=-1)
            initial = State()
            initial.sp = family.RAM_ADDRESS + 1
            state, ram, fault = family.expected(op, initial, bytes(64), accessible=0)
            self.assertEqual(fault['kind'], 'sp_alignment')
            self.assertEqual(bytes(state), bytes(initial))
            self.assertEqual(ram, bytes(64))
            initial.sp = family.RAM_ADDRESS + 16
            state, ram, fault = family.expected(op, initial, bytes(64), accessible=0)
            self.assertEqual(fault['kind'], 'sca_alignment')


class AtomicMemoryFixtureTests(unittest.TestCase):
    def test_exact173_forms_register_roles_and_source_alias_decode(self):
        family = atomic_memory
        operations = family.functions()
        self.assertEqual(len(family.CANONICAL_FORMS), 173)
        self.assertEqual(len(operations), len({op['word'] for op in operations}))
        source = b''.join(struct.pack('<II', op['word'], engine.RET) for op in operations)
        validation = family.validate_source_words(source, [{'operations': [op]} for op in operations], {op['name'] for op in operations})
        self.assertEqual(validation['capstone_decode_fallback_words'], 0)
        self.assertEqual(len(validation['decoded_store_aliases']), 256)
        for canonical in family.CANONICAL_FORMS:
            selected = [op for op in operations if op['canonical_id'] == canonical]
            if selected[0]['layout'] == 'barrier':
                self.assertEqual({op['option'] for op in selected}, set(range(16)))
                continue
            self.assertEqual({op['rn'] for op in selected}, set(range(32)))
            self.assertEqual({op['rt'] for op in selected}, set(range(32)))
            if selected[0]['layout'] in ('cas', 'rmw'):
                self.assertEqual({op['rs'] for op in selected}, set(range(32)))
                for role in ('rs', 'rt', 'rn'):
                    self.assertTrue(any(op[role] == 31 for op in selected))
            for op in selected:
                self.assertEqual(op['word'] >> 5 & 31, op['rn'])
                self.assertEqual(op['word'] & 31, op['rt'])

    def test_bounded_full_corpus_controls_flags_and_baseline_subset(self):
        family = atomic_memory
        operations, cases = family.corpus()
        self.assertLess(len(operations), 10000)
        self.assertLess(len(cases), 20000)
        flags = {}
        for case in cases:
            op = operations[case['function']]
            initial = State.from_buffer_copy(case['initial'])
            expected, ram, fault = family.expected(op, initial, family.memory_template())
            self.assertIsNone(fault, (case, op))
            self.assertEqual(len(case['initial']), 784)
            self.assertEqual(len(ram), 8192)
            self.assertEqual((expected.nzcv, expected.reserved, expected.fpcr, expected.fpsr),
                             (initial.nzcv, initial.reserved, initial.fpcr, initial.fpsr))
            flags.setdefault(op['canonical_id'], set()).add(initial.nzcv >> 28)
        self.assertTrue(all(values == set(range(16)) for values in flags.values()))
        admitted = [op for op in operations if family.supported_on_profile(op, 'baseline')]
        self.assertEqual(len(admitted), 8292)
        self.assertEqual({op['canonical_id'] for op in admitted}, set(family.CANONICAL_FORMS))
        excluded = [op for op in operations if not family.supported_on_profile(op, 'baseline')]
        self.assertEqual(len(excluded), 240)
        self.assertTrue(all(op['operation'] in ('ldar', 'ldapr') and op['rn'] != 31 and op['element_bytes'] > 1 for op in excluded))

    def test_CAS_stages_alias_inputs_and_returns_old_without_flags(self):
        family = atomic_memory
        for width in family.WIDTHS:
            mask = (1 << (width * 8)) - 1
            for rs, rt, rn in ((0, 1, 5), (0, 0, 5), (5, 1, 5), (0, 5, 5), (5, 5, 5), (31, 31, 31)):
                op = family.operation('cas', width, 'acquire_release', rs, rt, rn)
                position = family.address_match_position(width) if rs == rn != 31 else family.edge_positions(width)[0]
                initial = family.initial_state(op, 4, position, operand=mask, compare=0)
                old = int.from_bytes(family.memory_template()[position:position + width], 'little')
                state, ram, fault = family.expected(op, initial, family.memory_template())
                self.assertIsNone(fault)
                expected = State.from_buffer_copy(initial)
                if rs != 31: expected.x[rs] = old
                self.assertEqual(bytes(state), bytes(expected))
                compare = 0 if rs == 31 else initial.x[rs] & mask
                value = (0 if rt == 31 else initial.x[rt] & mask) if compare == old else old
                self.assertEqual(ram[position:position + width], value.to_bytes(width, 'little'))
                self.assertEqual(ram[:position], family.memory_template()[:position])

    def test_narrow_signed_minmax_and_unchanged_RMW_write_permission(self):
        family = atomic_memory
        expected = {'add': 129, 'clear': 128, 'xor': 129, 'set': 129,
                    'signed_max': 1, 'signed_min': 128, 'unsigned_max': 128, 'unsigned_min': 1, 'swap': 1}
        for kind, value in expected.items():
            op = family.operation(kind, 1)
            state = family.initial_state(op, 1, 0, operand=0xffff000000000001)
            final, ram, fault = family.expected(op, state, b'\x80' + bytes(31))
            self.assertIsNone(fault)
            self.assertEqual(final.x[1], 128)
            self.assertEqual(ram[0], value)
            _, ram, fault = family.expected(op, state, b'\x80' + bytes(31), readonly=True)
            self.assertEqual(fault['kind'], 'memory')
            self.assertEqual(ram, b'\x80' + bytes(31))
        for width in (1, 2, 4):
            mask = (1 << (8 * width)) - 1
            self.assertEqual(family.rmw_value('add', mask, 1, width), 0)
            self.assertEqual(family.rmw_value('signed_max', 1 << (8 * width - 1), 1, width), 1)

    def test_SCA16_SP_and_failed_CAS_permissions_precede_effects(self):
        family = atomic_memory
        for width in family.WIDTHS:
            for offset in range(16):
                op = family.operation('add', width)
                initial = family.initial_state(op, 0, offset)
                state, ram, fault = family.expected(op, initial, bytes(64))
                self.assertEqual(fault is None, offset + width <= 16)
                if fault:
                    self.assertEqual(fault['kind'], 'sca_alignment')
                    self.assertEqual(bytes(state), bytes(initial))
                    self.assertEqual(ram, bytes(64))
            op = family.operation('cas', width)
            initial = family.initial_state(op, 1, 0, operand=0, compare=1)
            state, ram, fault = family.expected(op, initial, bytes(64), readonly=True)
            self.assertEqual(fault['kind'], 'memory')
            self.assertEqual(bytes(state), bytes(initial))
            self.assertEqual(ram, bytes(64))
        op = family.operation('add', 8, rn=31)
        initial = family.initial_state(op, 2, 0)
        initial.sp += 15
        _, _, fault = family.expected(op, initial, bytes(64), accessible=0)
        self.assertEqual(fault['kind'], 'sp_alignment')

    def test_atomic_feature_header_preserves_default_observer_identity(self):
        default = simd_original.assembly([0x4e284820, 0x0e005820], 2)
        self.assertEqual(hashlib.sha256(default.encode()).hexdigest(), 'fcc2fc835b22f0352e553d497b88ef5c67d7e8e24490bdb695960dfcfeab87c0')
        header = bytearray(1024)
        registers = [0] * 9
        registers[3], registers[8] = 1 << 20, 2 << 20
        struct.pack_into('<9Q', header, 0, *registers)
        struct.pack_into('<4Q', header, simd_original.MEMORY_CONTROL_HEADER_OFFSET, *simd_original.MEMORY_CONTROLS.values())
        struct.pack_into('<Q', header, simd_original.ATOMIC_FEATURE_HEADER_OFFSET, 1 << 32)
        result = simd_original.validate_atomic_features(header)
        self.assertEqual(result['fields'], {'LSE_Atomic': 2, 'LRCPC': 1, 'LSE2_AT': 1})
        self.assertEqual(simd_original.validate_atomic_features(header, focus=atomic_pair_memory.FOCUS), result)
        with self.assertRaises(AssertionError): simd_original.validate_atomic_features(header, focus=ordered_unscaled_memory.FOCUS)
        ordered_header = bytearray(header)
        struct.pack_into('<Q', ordered_header, 3 * 8, 2 << 20)
        self.assertEqual(simd_original.validate_atomic_features(ordered_header, focus=ordered_unscaled_memory.FOCUS)['fields']['LRCPC'], 2)
        for offset in (3 * 8, 8 * 8, simd_original.ATOMIC_FEATURE_HEADER_OFFSET):
            changed = bytearray(header)
            changed[offset:offset + 8] = bytes(8)
            with self.assertRaises(AssertionError): simd_original.validate_atomic_features(changed)
        memory = {'ram_address': atomic_memory.RAM_ADDRESS, 'ram_bytes': 8192, 'record_bytes': 9216}
        assembly = simd_original.assembly([atomic_memory.operation()['word']], 1, memory, 'atomic_memory')
        self.assertIn('mrs x0,ID_AA64MMFR2_EL1\nstr x0,[x1,#104]', assembly)
        self.assertNotIn('ID_AA64MMFR2_EL1', simd_original.assembly([atomic_memory.operation()['word']], 1, memory))

    def test_atomic_declared_destinations_and_fixed_concurrency_plan(self):
        family = atomic_memory
        self.assertEqual(simd_original.memory_destinations(family.operation('cas', rs=7)), ({7}, set(), False))
        self.assertEqual(simd_original.memory_destinations(family.operation('add', rt=31)), (set(), set(), False))
        for case in family.concurrency_cases():
            data = family.concurrency_plan(case, list(range(case['threads'])))
            self.assertEqual(len(data), 11392)
            self.assertEqual(struct.unpack_from('<Q', data)[0], 0x314e414c504d5441)
            self.assertEqual(data[64:848], case['initial'][0])
            self.assertEqual(data[-8192:], case['memory'])
            self.assertLessEqual(case['threads'], 4)
            self.assertLessEqual(case['iterations'], 256)
            for program in case['programs']:
                self.assertTrue(all(op['rn'] in (5, 6) for op in program if op['layout'] != 'barrier'))

    def test_bounded_linearization_uses_full_states_and_final_RAM(self):
        family = atomic_memory
        op = family.operation('add', 8)
        memory, history = bytes(64), []
        for index in range(2):
            initial = family.initial_state(op, index, 0, operand=1)
            final, memory, _ = family.expected(op, initial, memory)
            history.append({'operation': op, 'initial_state_hex': bytes(initial).hex(),
                            'final_state_hex': bytes(final).hex(), 'begin': index * 2, 'end': index * 2 + 1})
        self.assertTrue(family.linearization_allowed(history, bytes(64), final_ram=memory))
        self.assertFalse(family.linearization_allowed(history, bytes(64), final_ram=bytes(64)))
        damaged = [dict(row) for row in history]
        state = State.from_buffer_copy(bytes.fromhex(damaged[1]['final_state_hex']))
        state.nzcv ^= 1 << 28
        damaged[1]['final_state_hex'] = bytes(state).hex()
        self.assertFalse(family.linearization_allowed(damaged, bytes(64)))
        with self.assertRaises(ValueError): family.linearization_allowed(history * 9, bytes(64))

    def test_source_SCA_fault_and_snapshot_fault_addresses_remain_distinct(self):
        family = atomic_memory
        op = family.operation('ldar', 4)
        initial = family.initial_state(op, 0, 5)
        source, _, fault = family.expected(op, initial, bytes(64), accessible=0)
        self.assertEqual(fault['kind'], 'memory')
        self.assertEqual(fault['address'], family.RAM_ADDRESS + 5)
        self.assertEqual((initial.x[5] & ~15), family.RAM_ADDRESS)
        self.assertEqual(bytes(source), bytes(initial))
        initial.x[5] = family.RAM_ADDRESS + 15
        _, _, fault = family.expected(op, initial, bytes(64), accessible=0)
        self.assertEqual(fault['kind'], 'sca_alignment')

    def test_cross8_ordered_reader_writer_history_is_exact_byte_atomic(self):
        family = atomic_memory
        selected = [case for case in family.concurrency_cases() if case['id'].startswith('cross8_')]
        self.assertEqual(len(selected), 6)
        for case in selected:
            writer, reader = [program[0] for program in case['programs']]
            initial = [family.relocate_state(raw, family.RAM_ADDRESS) for raw in case['initial']]
            self.assertGreater((initial[0].x[5] & 7) + case['width'], 8)
            history, ram = [], case['memory']
            for index, op in ((0, writer), (1, reader)):
                final, ram, fault = family.expected(op, initial[index], ram)
                self.assertIsNone(fault)
                history.append({'operation': op, 'initial_state_hex': bytes(initial[index]).hex(),
                                'final_state_hex': bytes(final).hex(), 'begin': index, 'end': index + 2})
            self.assertTrue(family.linearization_allowed(history, case['memory'], final_ram=ram))
            damaged = [dict(row) for row in history]
            final = State.from_buffer_copy(bytes.fromhex(damaged[1]['final_state_hex']))
            final.x[1] ^= 0x100
            damaged[1]['final_state_hex'] = bytes(final).hex()
            self.assertFalse(family.linearization_allowed(damaged, case['memory'], final_ram=ram))
            self.assertFalse(family.supported_on_profile(reader, 'baseline'))

    def test_litmus_ledger_binding_rejects_program_memory_value_and_base_drift(self):
        family = atomic_memory
        cases = [case for case in family.concurrency_cases() if case['kind'] == 4]
        model = {'program_words': {case['allowed_outcomes']: [[op['word'] for op in program] for program in case['programs']] for case in cases}}
        for case in cases:
            family.validate_litmus_case(case, model)
            with self.assertRaises(AssertionError): family.validate_litmus_case({**case, 'memory': b'\x01' + case['memory'][1:]}, model)
            for register in (0, 5, 6):
                state = State.from_buffer_copy(case['initial'][0])
                state.x[register] ^= 1
                with self.assertRaises(AssertionError): family.validate_litmus_case({**case, 'initial': [bytes(state), case['initial'][1]]}, model)
            changed = {'program_words': {key: [list(program) for program in programs] for key, programs in model['program_words'].items()}}
            changed['program_words'][case['allowed_outcomes']][0][0] ^= 1
            with self.assertRaises(AssertionError): family.validate_litmus_case(case, changed)

    def test_original_fault_opt_in_completion_and_error_framing_defaults_strict(self):
        from unittest.mock import Mock, call
        from unicorn import UcError, UC_ERR_EXCEPTION
        spec = importlib.util.spec_from_file_location('fixture_atomic_original_faults', ROOT / 'dev/memory-faults.py')
        faults = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(faults)
        initial = State()
        machine = Mock()
        machine.mem_read.return_value = b'\xa5' * 4096
        machine.reg_read.return_value = BASE + 4
        source = struct.pack('<II', atomic_memory.operation()['word'], engine.RET)
        with patch.object(faults, 'Uc', return_value=machine), patch.object(faults, 'initialize_arm'), patch.object(faults, 'capture_arm', return_value=initial):
            with self.assertRaises(AssertionError): faults.arm_fault(source, initial, 0x8000, 4096, False)
            machine.ctl_set_cpu_model.assert_not_called()
            machine.reset_mock()
            result = faults.arm_fault(source, initial, 0x8000, 4096, False, allow_completion=True, retain_error=True,
                                      cpu_model=faults.arm.UC_CPU_ARM64_MAX)
            self.assertEqual(machine.mock_calls[0], call.ctl_set_cpu_model(faults.arm.UC_CPU_ARM64_MAX))
            self.assertEqual(machine.mock_calls[1], call.mem_map(BASE // 4096 * 4096, 0x10000))
            self.assertEqual(result[3], {'completed': True, 'error': None})
            machine.emu_start.side_effect = UcError(UC_ERR_EXCEPTION)
            result = faults.arm_fault(source, initial, 0x8000, 4096, False, allow_completion=True, retain_error=True)
            self.assertFalse(result[3]['completed'])
            self.assertEqual(result[3]['error']['errno'], UC_ERR_EXCEPTION)
            self.assertEqual(result[3]['error']['pc'], BASE + 4)
            self.assertEqual(len(result[1]), 4096)

    def test_atomic_oracle_review_validates_retained_source_and_witness_identities(self):
        root = ROOT / '.stela'
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            directory = Path(temporary)
            artifact = directory / 'source-and-witness.bin'
            artifact.write_bytes(b'retained-source-and-witness')
            identity = {'path': str(artifact.relative_to(ROOT)), 'bytes': artifact.stat().st_size,
                        'sha256': engine.digest(artifact.read_bytes())}
            receipt_path = directory / 'review.json'
            receipt = {'kind': 'reviewed_unicorn_2_1_4_narrow_signed_atomic_minmax_limitation', 'passed': True,
                'classification': {'operations': ['signed_min', 'signed_max'], 'widths': [1, 2, 4]},
                'required_control_readbacks': {'ISAR0': 2 << 20}, 'source_files': [identity],
                'witness': identity, 'witness_files': [identity]}
            receipt_path.write_bytes(simd_original.json_bytes(receipt))
            with patch.object(simd_memory_runner, 'ATOMIC_ORACLE_REVIEW', receipt_path):
                actual, binding = simd_memory_runner.atomic_oracle_review(engine)
                self.assertEqual(actual, receipt)
                self.assertEqual(binding['sha256'], engine.digest(receipt_path.read_bytes()))
                artifact.write_bytes(b'changed-source-and-witness')
                with self.assertRaises(AssertionError): simd_memory_runner.atomic_oracle_review(engine)
                receipt_path.write_bytes(simd_original.json_bytes({**receipt, 'passed': False}))
                with self.assertRaises(AssertionError): simd_memory_runner.atomic_oracle_review(engine)

    def test_signed_narrow_oracle_defect_requires_exact_scope_and_complete_effects(self):
        review = {'engine_version': 'reviewed-version', 'installed_library': {'sha256': 'reviewed-library'},
                  'required_control_readbacks': {'ISAR0': 2 << 20, 'cpacr_el1': 0x300000}}
        controls = {'engine': 'Unicorn', 'version': review['engine_version'], 'installed_library': review['installed_library'],
                    'cpu': 'MAX', 'pstate': 0, 'final_pstate': 0, **review['required_control_readbacks']}
        event, case = {'completed': True, 'error': None}, {'protection': 'mapped'}
        for width in (1, 2, 4):
            for kind in ('signed_min', 'signed_max'):
                op = atomic_memory.operation(kind, width)
                initial = atomic_memory.initial_state(op, 0, 16, operand=0)
                memory = b'\xa5' * 64
                expected, signed_ram, fault = atomic_memory.expected(op, initial, memory)
                self.assertIsNone(fault)
                alternative = bytearray(memory)
                alternative[16:16 + width] = ((0 if kind == 'signed_min' else int.from_bytes(b'\xa5' * width, 'little'))).to_bytes(width, 'little')
                def check(**changes):
                    arguments = dict(op=op, case=case, initial=initial, memory=memory, ram_address=atomic_memory.RAM_ADDRESS,
                        expected=expected, expected_ram=signed_ram, original=expected, original_ram=bytes(alternative),
                        event=event, faults=[], controls=controls, review=review)
                    arguments.update(changes)
                    return simd_memory_runner.atomic_narrow_signed_oracle_difference(**arguments)
                self.assertTrue(check())
                edge = State.from_buffer_copy(bytes(initial))
                edge.x[op['rn']] = atomic_memory.RAM_ADDRESS + len(memory) - width
                edge_state, edge_signed_ram, edge_fault = atomic_memory.expected(op, edge, memory)
                self.assertIsNone(edge_fault)
                edge_alternative = bytearray(memory)
                edge_alternative[-width:] = alternative[16:16 + width]
                self.assertTrue(check(case={'protection': 'structure_crossing', 'cut': width}, initial=edge,
                    expected=edge_state, expected_ram=edge_signed_ram, original=edge_state,
                    original_ram=bytes(edge_alternative)))
                self.assertFalse(check(case={'protection': 'structure_crossing', 'cut': width - 1}, initial=edge,
                    expected=edge_state, expected_ram=edge_signed_ram, original=edge_state,
                    original_ram=bytes(edge_alternative)))
                outside = State.from_buffer_copy(bytes(edge))
                outside.x[op['rn']] += width
                self.assertFalse(check(case={'protection': 'structure_crossing', 'cut': width}, initial=outside))
                self.assertFalse(check(case={'protection': 'guard'}))
                self.assertFalse(check(case={'protection': 'readonly'}))
                self.assertFalse(check(controls={**controls, 'version': 'different'}))
                self.assertFalse(check(controls={**controls, 'ISAR0': 0}))
                self.assertFalse(check(controls={**controls, 'pstate': 4}))
                self.assertFalse(check(controls={**controls, 'final_pstate': 1 << 28}))
                self.assertFalse(check(controls={**controls, 'installed_library': {'sha256': 'different'}}))
                self.assertFalse(check(event={'completed': False, 'error': None}))
                self.assertFalse(check(event={'completed': True, 'error': {'errno': 1}}))
                self.assertFalse(check(faults=[{'address': atomic_memory.RAM_ADDRESS}]))
                self.assertFalse(check(original_ram=signed_ram))
                damaged = bytearray(alternative)
                damaged[-1] ^= 1
                self.assertFalse(check(original_ram=bytes(damaged)))
                damaged_state = State.from_buffer_copy(bytes(expected))
                damaged_state.nzcv ^= 1 << 28
                self.assertFalse(check(original=damaged_state))
                if width > 1:
                    unaligned = State.from_buffer_copy(bytes(initial))
                    unaligned.x[op['rn']] += 1
                    self.assertFalse(check(initial=unaligned))
                self.assertFalse(check(op={**op, 'element_bytes': 8}))
                self.assertFalse(check(op={**op, 'operation': 'unsigned_min'}))

    def test_CAS_counter_history_enforces_exact_transition_real_time_order(self):
        family = atomic_memory
        event = lambda old, success, begin, end: {'old': old, 'success': success, 'begin': begin, 'end': end}
        inverse = [event(0, True, 0, 100), event(1, True, 10, 11), event(2, True, 0, 100), event(3, True, 1, 2)]
        self.assertFalse(family.cas_counter_history_allowed(inverse, 4))
        successes = [event(0, True, 0, 100), event(1, True, 0, 100)]
        self.assertFalse(family.cas_counter_history_allowed(successes + [event(2, False, 1, 2), event(1, False, 3, 4)], 2))
        self.assertFalse(family.cas_counter_history_allowed([event(0, True, 0, 1), event(0, False, 2, 3)], 1))
        self.assertFalse(family.cas_counter_history_allowed([event(1, False, 0, 1), event(0, True, 2, 3)], 1))
        allowed = [event(0, False, 0, 1), event(0, True, 2, 3), event(1, False, 4, 7),
                   event(1, False, 5, 8), event(1, True, 9, 10), event(2, False, 11, 12)]
        self.assertTrue(family.cas_counter_history_allowed(allowed, 2))

    def test_shared_original_pointer_retains_immutable_receipt_and_previous_pointer(self):
        root = ROOT / '.stela'
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            directory = Path(temporary)
            previous = b'{"previous": true}\n'
            (directory / 'receipt.json').write_bytes(previous)
            capture = directory / 'immutable-capture'
            capture.mkdir()
            receipt_path = capture / 'receipt.json'
            receipt = {'files': {'results.bin': {'bytes': 3, 'sha256': engine.digest(b'raw')}}}
            receipt_path.write_bytes(simd_original.json_bytes(receipt))
            before = receipt_path.read_bytes()
            simd_original.publish_pointer(directory, receipt_path, 'atomic_memory_smp', receipt)
            pointer = json.loads((directory / 'receipt.json').read_bytes())
            self.assertEqual(pointer['directory'], str(capture.relative_to(ROOT)))
            self.assertEqual(pointer['receipt']['path'], str(receipt_path.relative_to(ROOT)))
            self.assertEqual(pointer['receipt']['sha256'], engine.digest(before))
            self.assertEqual(pointer['files'], receipt['files'])
            self.assertEqual(receipt_path.read_bytes(), before)
            history = directory / 'pointer-history' / (engine.digest(previous) + '.json')
            self.assertEqual(history.read_bytes(), previous)
            first = (directory / 'receipt.json').read_bytes()
            simd_original.publish_pointer(directory, receipt_path, 'atomic_memory_smp', receipt)
            self.assertEqual((directory / 'receipt.json').read_bytes(), first)
            self.assertEqual((directory / 'pointer-history' / (engine.digest(first) + '.json')).read_bytes(), first)

    def test_original_SMP_model_checks_all_State_RAM_bytes_and_both_cross8_orders(self):
        import simd_atomic_original as smp
        cases = smp.default_pairs()
        relative = [case for case in atomic_memory.concurrency_cases() if case['kind'] == 4]
        model = {'program_words': {case['id']: [[op['word'] for op in program] for program in case['programs']] for case in relative},
                 'allowed_outcomes': {case['id']: [[0, 1], [1, 0], [1, 1]] for case in relative}}
        model['allowed_outcomes']['publication_ldar'] = [[0, 0], [0, 1], [1, 1]]
        model['allowed_outcomes']['publication_ldapr'] = [[0, 0], [0, 1], [1, 1]]
        for case in cases:
            if case['kind'] == 4:
                states = [State.from_buffer_copy(raw) for raw in case['initial']]
                if case['id'].startswith('publication_'):
                    states[1].x[1], states[1].x[2] = 1, 1
                else:
                    states[0].x[1], states[1].x[1] = 0, 1
                ram = bytearray(case['memory'])
                ram[:8] = ram[64:72] = (1).to_bytes(8, 'little')
                finals = list(map(bytes, states))
                simd_memory_runner.validate_atomic_smp_trial(case, finals, bytes(ram), model)
                altered = [bytearray(raw) for raw in finals]
                altered[0][400] ^= 1
                with self.assertRaises(AssertionError):
                    simd_memory_runner.validate_atomic_smp_trial(case, list(map(bytes, altered)), bytes(ram), model)
                with self.assertRaises(AssertionError):
                    simd_memory_runner.validate_atomic_smp_trial(case, finals, bytes(ram[:-1]) + b'\1', model)
                changed_model = {**model, 'allowed_outcomes': {**model['allowed_outcomes'], case['id']: []}}
                with self.assertRaises(AssertionError):
                    simd_memory_runner.validate_atomic_smp_trial(case, finals, bytes(ram), changed_model)
            else:
                for order in ((0, 1), (1, 0)):
                    ram, finals = case['memory'], list(case['initial'])
                    for thread in order:
                        final, ram, fault = atomic_memory.expected(case['programs'][thread][0], State.from_buffer_copy(case['initial'][thread]), ram)
                        self.assertIsNone(fault)
                        finals[thread] = bytes(final)
                    self.assertEqual(simd_memory_runner.validate_atomic_smp_trial(case, finals, ram, model), list(order))
                    altered = list(finals)
                    state = State.from_buffer_copy(altered[1])
                    state.x[1] ^= 0x100
                    altered[1] = bytes(state)
                    with self.assertRaises(AssertionError):
                        simd_memory_runner.validate_atomic_smp_trial(case, altered, ram, model)
                    with self.assertRaises(AssertionError):
                        simd_memory_runner.validate_atomic_smp_trial(case, finals, ram[:-1] + bytes([ram[-1] ^ 1]), model)

    def test_shared_transport_default_command_and_result_bounds(self):
        destination = Path('/tmp/stela-observer-guard')
        memory = {'ram_address': atomic_memory.RAM_ADDRESS, 'ram_bytes': 8192, 'record_bytes': 9216}
        for plan, stride, ram_size in ((None, 1024, '512M'), (memory, 9216, '5G')):
            with patch.object(simd_original, 'memory_plan', return_value=plan), patch.object(simd_original, 'execute_transport') as transport:
                simd_original.execute(destination, Path('/mock/qemu'), 3)
            actual_destination, command, size = transport.call_args.args[:3]
            self.assertEqual(actual_destination, destination)
            self.assertEqual(size, 1024 + 3 * stride)
            self.assertEqual(command[command.index('-machine') + 1], 'virt,secure=off,virtualization=off')
            self.assertEqual(command[command.index('-cpu') + 1], 'max')
            self.assertEqual(command[command.index('-m') + 1], ram_size)
            self.assertIn(f'loader,file={destination / "inputs.bin"},addr=0x41000000,force-raw=on', command)
            self.assertEqual(any('memory.bin' in str(item) for item in command), plan is not None)


class OrdinaryMemoryFixtureTests(unittest.TestCase):
    def test_exact27_pinned_forms_and_independent_decoding(self):
        family = ordinary_memory
        facts = {row['id']: row for row in json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        self.assertEqual(len(family.CANONICAL_FORMS), 27)
        self.assertEqual(len(family.PARTIAL_FORMS), 5)
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        operations = family.functions()
        self.assertEqual(len(operations), len({op['word'] for op in operations}))
        for op in operations:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            decoded = list(decoder.disasm(struct.pack('<I', op['word']), BASE))
            if decoded:
                self.assertEqual(len(decoded), 1, op)
                self.assertEqual(decoded[0].mnemonic, op['name'], op)
            else:
                self.assertIn(op['canonical_id'], family.CAPSTONE_ALIAS_GAPS)
                self.assertEqual(op['rn'], op['rt'])
                self.assertLess(op['rt'], 31)
            gprs, vectors, sp = simd_original.memory_destinations(op)
            self.assertFalse(sp)
            self.assertEqual(gprs, set(op['written_gprs']))
            self.assertEqual(vectors, set(op['written_vectors']))
        source = b''.join(struct.pack('<II', op['word'], engine.RET) for op in operations)
        validation = family.validate_source_words(source, [{'operations': [op]} for op in operations], {op['name'] for op in operations})
        self.assertEqual(validation['capstone_decode_fallback_words'], 186)
        for canonical in family.CANONICAL_FORMS:
            selected = [op for op in operations if op['canonical_id'] == canonical]
            if selected[0]['layout'] != 'prefetch':
                self.assertEqual({op['rt'] for op in selected}, set(range(32)))
                self.assertEqual({op['rn'] for op in selected}, set(range(32)))
            if selected[0]['layout'] == 'pair':
                self.assertEqual({op['rt2'] for op in selected}, set(range(32)))
                self.assertEqual(any(op['rt'] == op['rt2'] for op in selected), not selected[0]['loading'])

    def test_pinned_alias_fallback_rejects_changed_words_neighbors_and_facts(self):
        family = ordinary_memory
        op = family.unprivileged('LDTRB_32_ldst_unpriv', rt=0, rn=0)
        def validate(operation, **kwargs):
            source = struct.pack('<II', operation['word'], engine.RET)
            return family.validate_source_words(source, [{'operations': [operation]}], {'ldtrb'}, **kwargs)
        self.assertEqual(validate(op)['capstone_decode_fallback_words'], 1)
        for changed in ({**op, 'word': op['word'] ^ 1 << 10},
                        {**op, 'canonical_id': 'LDTRH_32_ldst_unpriv'},
                        {**op, 'rn': 1}, {**op, 'offset': 1}, {**op, 'name': 'ldr'}):
            with self.assertRaises(AssertionError):
                validate(changed)
        catalog = json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())
        catalog['forms'][0]['encoding_value'] = '0xffffffff'
        with self.assertRaises(ValueError):
            validate(op, catalog=catalog)

    def test_success_corpus_full_states_controls_RAM_and_runtime_forms(self):
        family = ordinary_memory
        operations, cases = family.corpus()
        self.assertEqual(sum(case['runtime'] for case in cases), 27)
        self.assertEqual({operations[case['function']]['canonical_id'] for case in cases if case['runtime']}, set(family.CANONICAL_FORMS))
        for case in cases:
            initial = State.from_buffer_copy(case['initial'])
            self.assertEqual(len(case['initial']), 784)
            expected, ram, fault = family.expected(operations[case['function']], initial, family.memory_template())
            self.assertIsNone(fault, case)
            self.assertEqual(len(ram), 8192)
            self.assertEqual((expected.nzcv, expected.reserved, expected.fpcr, expected.fpsr),
                             (initial.nzcv, initial.reserved, initial.fpcr, initial.fpsr))
        self.assertIs(simd_memory_runner.family_module('ordinary_memory'), family)
        self.assertIs(simd_memory_runner.family_module('structure_memory'), structure_memory)
        with self.assertRaises(ValueError):
            simd_memory_runner.family_module('unknown')

    def test_signed_unsigned_loads_upper_zero_and_base_alias(self):
        family = ordinary_memory
        for canonical, _, width, bits, _ in family.UNPRIVILEGED:
            if not bits:
                continue
            op = family.unprivileged(canonical, rt=5, rn=5, offset=-1)
            initial = family.initial_state(op, 1, 1)
            memory = bytes([0, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
            state, ram, fault = family.expected(op, initial, memory)
            self.assertIsNone(fault)
            value = int.from_bytes(memory[1:1 + width], 'little', signed=op['signed']) & ((1 << bits) - 1)
            self.assertEqual(state.x[5], value)
            self.assertEqual(ram, memory)
            op = family.unprivileged(canonical, rt=31)
            initial = family.initial_state(op, 2, 0)
            state, _, fault = family.expected(op, initial, bytes(8), accessible=0)
            self.assertEqual(bytes(state), bytes(initial))
            self.assertEqual(fault['kind'], 'memory')

    def test_pair_complete_staging_and_exact_unicorn_second_vector_effect(self):
        family = ordinary_memory
        for width, vector, _, _ in family.PAIR_WIDTHS:
            op = family.pair(width, True, vector, rt=5, rt2=31, rn=5)
            initial = family.initial_state(op, 3, 0)
            memory = bytes(range(32))
            source, ram, fault = family.expected(op, initial, memory, accessible=width)
            predicted, predicted_ram, _ = family.expected(op, initial, memory, accessible=width, policy='unicorn')
            self.assertEqual(bytes(source), bytes(initial))
            self.assertEqual(ram, memory)
            self.assertEqual(predicted_ram, memory)
            self.assertEqual(fault['ordinal'], 1)
            expected = State.from_buffer_copy(initial)
            if vector:
                value = int.from_bytes(memory[:width], 'little')
                expected.v[5][:] = [value & ((1 << 64) - 1), value >> 64]
            self.assertEqual(bytes(predicted), bytes(expected))
            success, _, fault = family.expected(op, initial, memory)
            self.assertIsNone(fault)
            if vector:
                self.assertEqual(bytes(success.v[31]), memory[width:2 * width] + bytes(16 - width))
            else:
                self.assertEqual(success.x[5], int.from_bytes(memory[:width], 'little'))

    def test_store_prefix_every_byte_cut_duplicate_sources_and_ZR(self):
        family = ordinary_memory
        operations = [family.unprivileged(row[0], rt=31) for row in family.UNPRIVILEGED if not row[3]]
        operations += [family.pair(width, False, vector, rt=31, rt2=31) for width, vector, _, _ in family.PAIR_WIDTHS]
        for op in operations:
            initial = family.initial_state(op, 4, 0)
            width = op['element_bytes']
            element = bytes(initial.v[31])[:width] if op.get('vector') else bytes(width)
            data = element * (2 if op['layout'] == 'pair' else 1)
            memory = bytes([0xa5]) * 64
            for cut in range(op['total_bytes']):
                source, ram, fault = family.expected(op, initial, memory, accessible=cut)
                self.assertEqual(bytes(source), bytes(initial))
                self.assertEqual(ram, data[:cut] + memory[cut:])
                self.assertIsNotNone(fault)
            _, ram, fault = family.expected(op, initial, memory, readonly=True)
            self.assertEqual(ram, memory)
            self.assertEqual(fault['address'], family.RAM_ADDRESS)

    def test_retained_EL0_STTRH_crossing_prediction_keeps_successful_byte(self):
        # Actual Unicorn2.1.4 EL0 cut1 retained 0xd1 before the guard fault.
        family = ordinary_memory
        op = family.unprivileged('STTRH_32_ldst_unpriv')
        initial = State()
        initial.x[1] = 0xf0123456789abcd1
        initial.x[5] = family.RAM_ADDRESS + 4095
        memory = b'\xa5' * 4096
        for policy in ('source', 'unicorn'):
            state, ram, fault = family.expected(op, initial, memory, policy=policy)
            self.assertEqual(bytes(state), bytes(initial))
            self.assertEqual(ram, memory[:-1] + b'\xd1')
            self.assertEqual(fault['address'], family.RAM_ADDRESS + 4096)

    def test_SP_checked_before_offset_and_prefetch_never_checks_access(self):
        family = ordinary_memory
        for op in (family.unprivileged('LDTR_64_ldst_unpriv', rn=31, offset=-1),
                   family.pair(8, True, False, rn=31, offset=-8)):
            initial = State()
            initial.sp = family.RAM_ADDRESS + 1
            state, ram, fault = family.expected(op, initial, bytes(64))
            self.assertEqual(fault['kind'], 'sp_alignment')
            self.assertEqual(bytes(state), bytes(initial))
            self.assertEqual(ram, bytes(64))
        for mode in family.PREFETCH_FORMS:
            op = family.prefetch(mode, rn=31)
            initial = State()
            initial.sp = (1 << 64) - 1
            state, ram, fault = family.expected(op, initial, bytes(64), accessible=0, readonly=True)
            self.assertIsNone(fault)
            self.assertEqual(bytes(state), bytes(initial))
            self.assertEqual(ram, bytes(64))

    def test_illegal_encodings_and_explicit_partial_destination_declines(self):
        family = ordinary_memory
        for width, vector, _, _ in family.PAIR_WIDTHS:
            for register in range(32):
                with self.assertRaises(ValueError):
                    family.pair(width, True, vector, register, register)
        declines = family.declined_encodings()
        self.assertEqual(len(declines), 160)
        self.assertEqual({case['canonical_id'] for case in declines}, set(family.PARTIAL_FORMS))
        for case in declines:
            self.assertEqual(case['word'] & 31, case['word'] >> 10 & 31)
        for option in (0, 1, 4, 5):
            with self.assertRaises(ValueError):
                family.prefetch('register', option=option)
        for hint in range(24, 32):
            with self.assertRaises(ValueError):
                family.prefetch('register', hint)
        for op in family.shapes():
            if op['layout'] == 'unprivileged':
                for offset in (-257, 256):
                    with self.assertRaises(ValueError):
                        family.unprivileged(op['canonical_id'], offset=offset)

    def test_declared_original_destinations_reject_invalid_metadata(self):
        family = ordinary_memory
        op = family.pair(8, True, False, rt=0, rt2=30)
        self.assertEqual(simd_original.memory_destinations(op), ({0, 30}, set(), False))
        op = family.pair(16, True, True, rt=0, rt2=31)
        self.assertEqual(simd_original.memory_destinations(op), (set(), {0, 31}, False))
        for key, invalid in (('written_gprs', [31]), ('written_gprs', [-1]), ('written_gprs', [True]),
                             ('written_vectors', [32]), ('written_vectors', [1, 1]), ('written_vectors', None)):
            with self.assertRaises(AssertionError):
                simd_original.memory_destinations({**op, key: invalid})

    def test_fault_selection_prefetch_nonfaults_and_default_structure_identity(self):
        family = ordinary_memory
        selected = simd_memory_runner.native_fault_selection(family=family)
        self.assertEqual(selected, family.fault_selection())
        shapes = family.shapes()
        for case in selected:
            op = simd_memory_runner.fault_operation(shapes[case['function']], case['rn'], family, case)
            self.assertEqual(op['rn'], case['rn'])
            if op['mode'] != 'literal':
                self.assertEqual(op['word'] >> 5 & 31, case['rn'])
        self.assertEqual(len(simd_memory_runner.native_fault_selection()), 931)
        self.assertEqual(len(simd_memory_runner.native_fault_selection(True)), 290)
        op = family.prefetch()
        batch = {'native': b'\x90\xc3', 'source': struct.pack('<II', op['word'], engine.RET),
                 'instruction_offsets': [0, 1], 'functions': [{'operations': [op]}], 'entries': [0]}
        accounting = simd_memory_runner.native_binary_accounting(engine, batch)
        self.assertEqual(accounting['static_body_native_bytes'], 1)
        self.assertEqual(accounting['bodies'][0]['layout'], 'prefetch')


class StructureMemoryFixtureTests(unittest.TestCase):
    def test_exact150_inventory_1134_shapes_and_independent_decoding(self):
        shapes = structure_memory.shapes()
        self.assertEqual(len(shapes), 1134)
        self.assertEqual({layout: sum(op['layout'] == layout for op in shapes) for layout in ('multiple', 'lane', 'replicate')},
                         {'multiple': 318, 'lane': 720, 'replicate': 96})
        self.assertEqual(len(structure_memory.CANONICAL_FORMS), 150)
        facts = {row['id']: row for row in json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        operations = structure_memory.functions()
        self.assertEqual(len({op['word'] for op in operations}), len(operations))
        for op in operations:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            decoded = list(decoder.disasm(struct.pack('<I', op['word']), BASE))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0].mnemonic, op['name'])
        for canonical in structure_memory.CANONICAL_FORMS:
            positions = [op for op in operations if op['canonical_id'] == canonical]
            self.assertEqual({op['rt'] for op in positions}, set(range(32)))
            self.assertEqual({op['rn'] for op in positions}, set(range(32)))
            if positions[0]['mode'] == 'register':
                self.assertEqual({op['rm'] for op in positions}, set(range(31)))
                self.assertTrue(any(op['rm'] == op['rn'] for op in positions))

    def test_success_inputs_all_alignments_crossings_and_complete_frames(self):
        operations, cases = structure_memory.corpus()
        shape_words = {op['word'] for op in structure_memory.shapes()}
        self.assertEqual(len(cases), 15206)
        self.assertEqual(len([case for case in cases if case['runtime']]), 150)
        by_function = {}
        for case in cases:
            self.assertEqual(len(case['initial']), 784)
            by_function.setdefault(case['function'], []).append(case)
        for function, op in enumerate(operations):
            selected = by_function[function]
            if op['word'] in shape_words:
                self.assertEqual({case['alignment'] for case in selected}, set(range(8)))
                if op['total_bytes'] > 1:
                    self.assertTrue(any(case['path'] == 'crossing' for case in selected))
            for case in selected[:1]:
                initial = State.from_buffer_copy(case['initial'])
                expected, ram, fault = structure_memory.expected(op, initial, structure_memory.memory_template())
                self.assertIsNone(fault)
                self.assertEqual(len(ram), 8192)
                self.assertEqual(expected.nzcv, initial.nzcv)
                self.assertEqual(expected.fpcr, initial.fpcr)
                self.assertEqual(expected.fpsr, initial.fpsr)
                self.assertEqual(expected.reserved, initial.reserved)

    def test_explicit_source_and_qemu_fault_partitions_without_normalization(self):
        op = structure_memory.operation('multiple', structures=2, vector_bytes=8, mode='immediate')
        initial = structure_memory.initial_state(op, 7, 0)
        memory = bytes(range(64))
        source, ram, fault = structure_memory.expected(op, initial, memory, accessible=3)
        original_prediction, _, _ = structure_memory.expected(op, initial, memory, accessible=3, policy='qemu')
        first = bytearray(struct.pack('<2Q', *initial.v[31]))
        second = bytearray(struct.pack('<2Q', *initial.v[0]))
        first[0:2], second[0:1] = bytes((0, 2)), bytes((1,))
        first[8:], second[8:] = bytes(8), bytes(8)
        self.assertEqual(bytes(source.v[31]), first)
        self.assertEqual(bytes(source.v[0]), second)
        self.assertEqual(source.x[5], initial.x[5])
        self.assertEqual(ram, memory)
        self.assertEqual(fault['ordinal'], 3)
        self.assertEqual(original_prediction.v[31][1], initial.v[31][1])
        self.assertNotEqual(bytes(source), bytes(original_prediction))
        op = structure_memory.operation('multiple', loading=False, structures=2, element_bytes=2)
        initial = structure_memory.initial_state(op, 8, 0)
        source, ram, _ = structure_memory.expected(op, initial, memory, accessible=5)
        _, qemu_ram, _ = structure_memory.expected(op, initial, memory, accessible=5, policy='qemu')
        expected = bytes(initial.v[31])[:2] + bytes(initial.v[0])[:2] + bytes(initial.v[31])[2:3]
        self.assertEqual(ram[:5], expected)
        self.assertEqual(qemu_ram[4:], memory[4:])
        self.assertEqual(bytes(source), bytes(initial))

    def test_lane_poison_preservation_replicate_exact_footprint_and_alias_increment(self):
        for width in (1, 2, 4, 8):
            for index in range(16 // width):
                op = structure_memory.operation('lane', structures=4, element_bytes=width, index=index)
                initial = structure_memory.initial_state(op, index + width, 0)
                memory = bytes(range(64))
                expected, ram, fault = structure_memory.expected(op, initial, memory)
                self.assertIsNone(fault)
                for slot in range(4):
                    register = (31 + slot) % 32
                    vector = bytearray(bytes(initial.v[register]))
                    vector[index * width:(index + 1) * width] = memory[slot * width:(slot + 1) * width]
                    self.assertEqual(bytes(expected.v[register]), vector)
                self.assertEqual(ram, memory)
            op = structure_memory.operation('replicate', structures=4, vector_bytes=8, element_bytes=width)
            initial = structure_memory.initial_state(op, width, 0)
            expected, _, fault = structure_memory.expected(op, initial, bytes(range(64)), accessible=3 * width)
            self.assertIsNotNone(fault)
            for slot in range(3):
                chunk = bytes(range(slot * width, (slot + 1) * width))
                self.assertEqual(bytes(expected.v[(31 + slot) % 32]), chunk * (8 // width) + bytes(8))
            self.assertEqual(bytes(expected.v[2]), bytes(initial.v[2]))
        op = structure_memory.operation('lane', mode='register', rn=5, rm=5)
        initial = structure_memory.initial_state(op, 1, 0)
        expected, _, _ = structure_memory.expected(op, initial, bytes(range(64)))
        self.assertEqual(expected.x[5], initial.x[5] * 2)
        op = structure_memory.operation('lane', rn=31)
        initial = structure_memory.initial_state(op, 1, 0)
        initial.sp += 1
        expected, ram, fault = structure_memory.expected(op, initial, bytes(64))
        self.assertEqual(fault['kind'], 'sp_alignment')
        self.assertEqual(bytes(expected), bytes(initial))
        self.assertEqual(ram, bytes(64))

    def test_optional_memory_observer_default_identity_and_bounded_copy(self):
        assembly = simd_original.assembly([0x4e284820, 0x0e005820], 2)
        self.assertEqual(hashlib.sha256(assembly.encode()).hexdigest(),
                         'fcc2fc835b22f0352e553d497b88ef5c67d7e8e24490bdb695960dfcfeab87c0')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.assertIsNone(simd_original.memory_plan(directory))
            memory = structure_memory.memory_template()
            (directory / 'memory.bin').write_bytes(memory)
            plan = {'ram_address': structure_memory.RAM_ADDRESS, 'ram_bytes': 8192,
                    'initial_ram_sha256': hashlib.sha256(memory).hexdigest()}
            (directory / 'memory-plan.json').write_text(json.dumps(plan))
            parsed = simd_original.memory_plan(directory)
            self.assertEqual(parsed['record_bytes'], 9216)
            extended = simd_original.assembly([structure_memory.shapes()[0]['word']], 1, parsed)
            self.assertIn('restore_ram:', extended)
            self.assertIn('snapshot_ram:', extended)
            self.assertIn('add x1,sp,#1024', extended)
            self.assertIn('movz x3,#9216', extended)
            self.assertLess(extended.index('msr SCTLR_EL1,x0'), extended.index('restore_ram:'))
            self.assertLess(extended.index('memory_code_pages:'), extended.index('msr SCTLR_EL1,x0'))
            self.assertIn('memory_l1_blocks:', extended)
            self.assertIn('memory_l2_blocks:', extended)
            self.assertIn('memory_l3_pages:', extended)
            for index, register in enumerate(simd_original.MEMORY_CONTROLS):
                offset = simd_original.MEMORY_CONTROL_HEADER_OFFSET + index * 8
                self.assertIn(f'mrs x0,{register}\nstr x0,[x1,#{offset}]', extended)
            plan['ram_address'] += 4096
            (directory / 'memory-plan.json').write_text(json.dumps(plan))
            with self.assertRaises(AssertionError):
                simd_original.memory_plan(directory)

    def test_memory_observer_requires_actual_normal_memory_controls_and_code_bounds(self):
        header = bytearray(simd_original.HEADER_BYTES)
        offset = simd_original.MEMORY_CONTROL_HEADER_OFFSET
        struct.pack_into('<4Q', header, offset, *simd_original.MEMORY_CONTROLS.values())
        self.assertEqual(simd_original.validate_memory_controls(header),
                         {name: hex(value) for name, value in simd_original.MEMORY_CONTROLS.items()})
        for index in range(4):
            changed = bytearray(header)
            changed[offset + index * 8] ^= 1
            with self.assertRaises(AssertionError):
                simd_original.validate_memory_controls(changed)
        # ELF64 section fields: name, type, flags, address, offset, size, ...
        section = (0, 1, simd_original.ELF_EXECINSTR, simd_original.TEXT_ADDRESS, 0,
                   simd_original.MEMORY_CODE_END - simd_original.TEXT_ADDRESS, 0, 0, 4, 0)
        simd_original.validate_memory_text([section])
        for start, size in ((simd_original.TEXT_ADDRESS - 4, 4),
                            (simd_original.MEMORY_CODE_END - 4, 8)):
            changed = (*section[:3], start, 0, size, *section[6:])
            with self.assertRaises(AssertionError):
                simd_original.validate_memory_text([changed])

    def test_memory_accounting_binds_rip_pools_and_rejects_code_data_overlap(self):
        # movdqu xmm6,[rip+5]; jmp +16; sixteen mask bytes; ret
        native = bytes.fromhex('f30f6f3505000000 e910000000') + bytes(range(16)) + b'\xc3'
        op = structure_memory.operation('multiple')
        batch = {'native': native, 'source': struct.pack('<II', op['word'], engine.RET),
                 'instruction_offsets': [0, len(native) - 1], 'functions': [{'operations': [op]}], 'entries': [0]}
        accounting = simd_memory_runner.native_binary_accounting(engine, batch)
        self.assertEqual(accounting['constant_pool_bytes'], 16)
        self.assertEqual(accounting['static_body_native_instructions'], 2)
        self.assertEqual(accounting['static_native_bytes_including_ret'], len(native))
        batch['native'] = bytes.fromhex('f30f6f35f8ffffff e910000000') + bytes(range(16)) + b'\xc3'
        with self.assertRaises(AssertionError):
            simd_memory_runner.native_binary_accounting(engine, batch)

    def test_illegal_combinations_and_bounded_fault_selection(self):
        for values in ({'layout': 'multiple', 'structures': 2, 'vector_bytes': 8, 'element_bytes': 8},
                       {'layout': 'replicate', 'loading': False}, {'layout': 'lane', 'element_bytes': 8, 'index': 2},
                       {'layout': 'lane', 'mode': 'register', 'rm': 31}):
            with self.assertRaises(ValueError):
                structure_memory.operation(**values)
        selected = simd_memory_runner.native_fault_selection()
        self.assertLess(len(selected), 1000)
        first_access = simd_memory_runner.native_fault_selection(first_access_only=True)
        self.assertEqual(len(first_access), 290)
        self.assertEqual(first_access, [case for case in selected if case['protection'] != 'structure_crossing'])
        self.assertEqual({case['protection'] for case in first_access},
                         {'guard', 'readonly', 'sp_alignment', 'sp_alignment8'})
        shapes = structure_memory.shapes()
        self.assertEqual({shapes[case['function']]['canonical_id'] for case in selected}, set(structure_memory.CANONICAL_FORMS))
        sp = [case for case in selected if case['protection'].startswith('sp_alignment')]
        self.assertEqual(len(sp), 30)
        self.assertEqual({(shapes[case['function']]['layout'], shapes[case['function']]['loading'],
                           shapes[case['function']]['mode'], case['protection']) for case in sp},
                         {(layout, loading, mode, protection)
                          for layout, loading in (('multiple', False), ('multiple', True),
                                                  ('lane', False), ('lane', True), ('replicate', True))
                          for mode in structure_memory.MODES for protection in ('sp_alignment', 'sp_alignment8')})
        for case in sp:
            op = simd_memory_runner.fault_operation(shapes[case['function']], case['rn'])
            self.assertEqual(op['rn'], 31)
            self.assertEqual(op['word'] >> 5 & 31, 31)


class AesFixtureTests(unittest.TestCase):
    def test_published_substitution_and_column_anchors(self):
        self.assertEqual(aes.SBOX[0], 99)
        self.assertEqual(aes.SBOX[83], 237)
        self.assertEqual(aes.INVERSE_SBOX[99], 0)
        self.assertEqual(aes.INVERSE_SBOX[237], 83)
        original = bytes.fromhex('d4bf5d30') + bytes(12)
        mixed = bytes.fromhex('046681e5') + bytes(12)
        self.assertEqual(aes.mix_columns(original), mixed)
        self.assertEqual(aes.mix_columns(mixed, True), original)

    def test_every_register_encoding_and_bounded_runtime_corpus(self):
        (functions, records) = aes.corpus()
        self.assertEqual(len(functions), 4096)
        self.assertEqual(len(records), 4880)
        self.assertEqual(len({op['word'] for op in functions}), 4096)
        self.assertEqual({op['canonical_id'] for op in functions}, set(aes.CANONICAL_FORMS))
        for op in functions:
            self.assertEqual(op['word'] & aes.FORM_MASK, aes.FORM_VALUES[op['name']])
        runtime = [record for record in records if record['runtime']]
        self.assertEqual(len(runtime), 60)
        self.assertEqual({functions[record['function']]['name'] for record in runtime}, set(aes.FORM_VALUES))
        self.assertTrue(all((len(record['initial']) == 784 for record in records)))

    def test_aliases_and_complete_unrelated_state_preservation(self):
        for (name, byte) in [('aese', 99), ('aesd', 82)]:
            initial = aes.initial_state(17)
            result = aes.expected(aes.operation(name, 31, 31), initial)
            self.assertEqual(aes.vector_bytes(result, 31), bytes([byte] * 16))
            self.assertEqual(bytes(result)[:aes.State.v.offset + 31 * 16], bytes(initial)[:aes.State.v.offset + 31 * 16])
            self.assertEqual(bytes(result)[aes.State.v.offset + 32 * 16:], bytes(initial)[aes.State.v.offset + 32 * 16:])
        for name in aes.FORM_VALUES:
            initial = aes.initial_state(23)
            result = aes.expected(aes.operation(name, 7, 31), initial)
            start = aes.State.v.offset + 7 * 16
            self.assertEqual(bytes(result)[:start], bytes(initial)[:start])
            self.assertEqual(bytes(result)[start + 16:], bytes(initial)[start + 16:])

    def test_linear_inverse_on_every_column_basis_bit(self):
        for bit in range(128):
            value = (1 << bit).to_bytes(16, 'little')
            self.assertEqual(aes.mix_columns(aes.mix_columns(value), True), value)

    def test_independent_host_aes_feature_policy(self):
        self.assertEqual(aes.optional_opcodes('x86_64-baseline'), set())
        self.assertEqual(aes.optional_opcodes('x86_64-baseline+ssse3'), {'pshufb'})
        expected = {'aesenclast', 'aesdeclast', 'aesenc', 'aesimc'}
        self.assertEqual(aes.optional_opcodes('x86_64-baseline+aes'), expected)
        self.assertEqual(aes.optional_opcodes('x86_64-baseline+ssse3+sse4.1+sse4.2+pclmulqdq+aes'), expected)


class Sha12FixtureTests(unittest.TestCase):
    def test_sha12_exact_source_forms_alias_roles_and_bounded_full_state_corpus(self):
        (ops, records) = sha12.corpus()
        facts = {row['id']: row for row in json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_text())['forms']}
        self.assertEqual((len(ops), len(records), len(sha12.CANONICAL_FORMS)), (98, 25088, 10))
        self.assertEqual({op['canonical_id'] for op in ops}, set(sha12.CANONICAL_FORMS))
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for op in ops:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            self.assertEqual([row.mnemonic for row in decoder.disasm(struct.pack('<I', op['word']), 0)], [op['name']])
        selected = [row for row in records if row.get('runtime')]
        self.assertEqual(len(selected), 90)
        self.assertEqual({ops[row['function']]['canonical_id'] for row in selected}, set(sha12.CANONICAL_FORMS))
        self.assertEqual({State.from_buffer_copy(row['initial']).nzcv >> 28 for row in records}, set(range(16)))
        self.assertEqual({State.from_buffer_copy(row['initial']).fpcr for row in selected}, {0, 130023424, 524288, 130547712})
        for row in selected:
            initial = State.from_buffer_copy(row['initial'])
            op = ops[row['function']]
            result = sha12.expected(op, initial)
            result.v[op['d']][:] = initial.v[op['d']]
            self.assertEqual(bytes(result), bytes(initial))

    def test_sha12_h_scalar_clearing_and_independent_features(self):
        op = sha12.operation('sha1h', d=31, n=31)
        initial = State()
        initial.v[31][:] = [18446744073709551615, 18446744073709551615]
        initial.fpcr = 4294967295
        initial.fpsr = 4294967295
        initial.nzcv = 4026531840
        result = sha12.expected(op, initial)
        self.assertEqual(list(result.v[31]), [4294967295, 0])
        self.assertEqual((result.fpcr, result.fpsr, result.nzcv), (initial.fpcr, initial.fpsr, initial.nzcv))
        for target in ('x86_64-baseline', 'x86_64-baseline+pclmulqdq+fma+f16c'):
            self.assertEqual(sha12.optional_opcodes(target), set())
        self.assertEqual(sha12.optional_opcodes('x86_64-baseline+ssse3+sse4.1+sse4.2'), {'palignr'})
        self.assertEqual(sha12.optional_opcodes('x86_64-baseline+sha'), {'sha1rnds4', 'sha1msg2', 'sha256rnds2', 'sha256msg1', 'sha256msg2'})
        self.assertEqual(sha12.optional_opcodes('x86_64-baseline+ssse3+sha'), {'palignr', 'sha1rnds4', 'sha1msg2', 'sha256rnds2', 'sha256msg1', 'sha256msg2'})


class Sha512FixtureTests(unittest.TestCase):
    def test_sha512_fixtures_bind_four_exact_forms_aliases_and_complete_corpus(self):
        (functions, records) = sha512.corpus()
        self.assertEqual((len(functions), len(records)), (157, 1488))
        self.assertEqual(sum((record['runtime'] for record in records)), 90)
        self.assertEqual(len({operation['word'] for operation in functions}), 157)
        self.assertEqual({operation['canonical_id'] for operation in functions}, set(sha512.CANONICAL_FORMS))
        facts = {row['id']: row for row in json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for operation in functions:
            fact = facts[operation['canonical_id']]
            self.assertEqual(operation['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            self.assertEqual([instruction.mnemonic for instruction in decoder.disasm(struct.pack('<I', operation['word']), 0)], [operation['name']])
            self.assertFalse(operation['scalar'])
            self.assertEqual((operation['lane'], operation['bytes'], operation['output_kind']), (8, 16, 'vector'))
        for name in sha512.FORMS:
            positions = [operation for operation in functions if operation['name'] == name and operation['layout'] == 'all_registers']
            self.assertEqual({operation['d'] for operation in positions}, set(range(32)))
            self.assertEqual({operation['n'] for operation in positions}, set(range(32)))
            if name != 'sha512su0':
                self.assertEqual({operation['m'] for operation in positions}, set(range(32)))
        self.assertEqual({record['function'] for record in records}, set(range(157)))
        for record in records:
            self.assertEqual(len(record['initial']), ctypes.sizeof(State))
        for name in sha512.FORMS:
            first = next((index for (index, operation) in enumerate(functions) if operation['name'] == name))
            self.assertEqual({record['pattern'] for record in records if record['function'] == first}, set(range(72)))
        with self.assertRaises(ValueError):
            sha512.operation('sha512h', d=32)
        with self.assertRaises(ValueError):
            sha512.operation('sha512su2')

    def test_sha512_hash_oracle_matches_independent_two_round_recurrence(self):
        mask = (1 << 64) - 1

        def rotate(value, amount):
            return sum(((value >> (bit + amount) % 64 & 1) << bit for bit in range(64)))

        def rounds(state, words):
            (a, b, c, d, e, f, g, h) = state
            for word in words:
                sigma1 = rotate(e, 14) ^ rotate(e, 18) ^ rotate(e, 41)
                sigma0 = rotate(a, 28) ^ rotate(a, 34) ^ rotate(a, 39)
                choose = (f ^ g) & e ^ g
                majority = a & b | (a | b) & c
                first = h + sigma1 + choose + word & mask
                second = sigma0 + majority & mask
                (a, b, c, d, e, f, g, h) = (first + second & mask, a, b, c, d + first & mask, e, f, g)
            return (a, b, c, d, e, f, g, h)
        for (index, operation) in enumerate(sha512.functions()):
            if operation['name'] not in ('sha512h', 'sha512h2'):
                continue
            for pattern in (1, 3, 70):
                initial = sha512.initial_state(index, pattern, 15)
                (w0, w1) = initial.v[operation['d']]
                (x0, x1) = initial.v[operation['n']]
                (y0, y1) = initial.v[operation['m']]
                if operation['name'] == 'sha512h':
                    synthetic = (0, 0, -x1 & mask, y0, y1, x0, x1, 0)
                    (a, b, c, d, e, f, g, h) = rounds(synthetic, (w1, w0))
                    reference = [e, f - y0 & mask]
                else:
                    synthetic = (y0, y1, x0, -w1 & mask, 0, 0, 0, 0)
                    (a, b, c, d, e, f, g, h) = rounds(synthetic, (w1, w0))
                    reference = [a, b]
                observed = sha512.expected(operation, initial)
                self.assertEqual(list(observed.v[operation['d']]), reference)
                observed.v[operation['d']][:] = initial.v[operation['d']]
                self.assertEqual(bytes(observed), bytes(initial))

    def test_sha512_schedule_lane_order_old_destination_and_unused_high_source(self):
        mask = (1 << 64) - 1
        initial = sha512.initial_state(0, 0, 15)
        initial.v[0][:] = [7, 11]
        initial.v[1][:] = [13, 17]
        initial.v[2][:] = [19, 23]

        def small(value, rotations, amount):
            rotated = [sum(((value >> (bit + rotation) % 64 & 1) << bit for bit in range(64))) for rotation in rotations]
            return rotated[0] ^ rotated[1] ^ value // (1 << amount)
        expected = {'sha512su0': [7 + small(11, (1, 8), 7) & mask, 11 + small(13, (1, 8), 7) & mask], 'sha512su1': [7 + small(13, (19, 61), 6) + 19 & mask, 11 + small(17, (19, 61), 6) + 23 & mask]}
        for name in expected:
            operation = sha512.operation(name)
            output = sha512.expected(operation, initial)
            self.assertEqual(list(output.v[0]), expected[name])
            output.v[0][:] = initial.v[0]
            self.assertEqual(bytes(output), bytes(initial))
        for name in ('sha512h2', 'sha512su0'):
            operation = sha512.operation(name)
            original = sha512.expected(operation, initial)
            poisoned = State.from_buffer_copy(initial)
            poisoned.v[1][1] ^= mask
            output = sha512.expected(operation, poisoned)
            self.assertEqual(list(output.v[0]), list(original.v[0]))
        alias = sha512.operation('sha512su0', d=31, n=31)
        initial.v[31][:] = [7, 11]
        self.assertEqual(list(sha512.expected(alias, initial).v[31]), [7 + small(11, (1, 8), 7) & mask, 11 + small(7, (1, 8), 7) & mask])


class Sha3FixtureTests(unittest.TestCase):
    def test_sha3_inventory_all_immediates_equality_partitions_and_v31_roles(self):
        functions = sha3.functions()
        facts = {row['id']: row for row in json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        self.assertEqual(len({operation['word'] for operation in functions}), len(functions))
        self.assertEqual({operation['canonical_id'] for operation in functions}, set(sha3.CANONICAL_FORMS))
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for operation in functions:
            fact = facts[operation['canonical_id']]
            self.assertEqual(operation['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            self.assertEqual([instruction.mnemonic for instruction in decoder.disasm(struct.pack('<I', operation['word']), 0)], [operation['name']])
            self.assertEqual((operation['bytes'], operation['scalar'], operation['output_kind']), (16, False, 'vector'))
        for name in sha3.FORMS:
            matching = [operation for operation in functions if operation['name'] == name]
            self.assertEqual({operation['d'] for operation in matching}, set(range(32)))
            roles = ('d', 'n', 'm', 'a') if name in ('eor3', 'bcax') else ('d', 'n', 'm')
            for role in roles:
                self.assertTrue(any((operation[role] == 31 for operation in matching)), (name, role))
            partitions = set(sha3.alias_partitions(len(roles)))
            self.assertEqual(len(partitions), 15 if len(roles) == 4 else 5)
            for amount in range(64) if name == 'xar' else (None,):
                observed = set()
                for operation in matching:
                    if amount is not None and operation['amount'] != amount:
                        continue
                    groups = {}
                    observed.add(tuple((groups.setdefault(operation[role], len(groups)) for role in roles)))
                self.assertEqual(observed, partitions, (name, amount))
        self.assertEqual(len(sha3.representatives(functions)), 11)
        self.assertEqual({operation['name'] for operation in sha3.chain()}, set(sha3.FORMS))
        for (name, options) in [('sha512', {}), ('xar', {'amount': -1}), ('xar', {'amount': 64}), ('rax1', {'amount': 1}), ('bcax', {'a': 32}), ('eor3', {'n': -1})]:
            with self.assertRaises(ValueError):
                sha3.operation(name, **options)

    def test_sha3_truth_table_and_complement_operand_order(self):
        initial = State()
        for (name, truth) in [('eor3', (0, 1, 1, 0, 1, 0, 0, 1)), ('bcax', (0, 0, 1, 0, 1, 1, 0, 1))]:
            operation = sha3.operation(name)
            for (row, output) in enumerate(truth):
                sha3.seed(initial, operation, row)
                result = sha3.expected(operation, initial)
                self.assertEqual(list(result.v[0]), [sha3.MASK64 if output else 0, sha3.MASK64 if truth[row ^ 7] else 0])
        initial.v[1][:] = [0, 0]
        initial.v[2][:] = [17361641481138401520, 12297829382473034410]
        initial.v[31][:] = [1085102592571150095, 6148914691236517205]
        result = sha3.expected(sha3.operation('bcax'), initial)
        self.assertEqual(list(result.v[0]), list(initial.v[2]))

    def test_sha3_bit_index_rotates_keep_lanes_independent_for_all_immediates(self):
        initial = State()
        initial.v[1][:] = [81985529216486895, 9223372036854775809]
        initial.v[2][:] = [0, 0]
        for rotation in range(64):
            result = sha3.expected(sha3.operation('xar', amount=rotation), initial)
            expected = []
            for value in initial.v[1]:
                bits = f'{value:064b}'
                expected.append(int(bits[-rotation:] + bits[:-rotation], 2) if rotation else value)
            self.assertEqual(list(result.v[0]), expected, rotation)
        initial.v[2][:] = [9223372036854775809, 1]
        result = sha3.expected(sha3.operation('rax1'), initial)
        self.assertEqual(list(result.v[0]), [initial.v[1][0] ^ 3, initial.v[1][1] ^ 2])

    def test_sha3_source_snapshot_and_preservation_are_complete_784_byte_states(self):
        initial = State()
        seed_extended_state(initial, 1443)
        (initial.x[0], initial.sp, initial.reserved) = (4660, 22136, 2882400001)
        (initial.nzcv, initial.fpcr, initial.fpsr) = (4026531840, 130588423, 134217887)
        for name in sha3.FORMS:
            operation = sha3.operation(name, d=31, n=31, m=31, a=31, amount=63 if name == 'xar' else 0)
            actual = sha3.expected(operation, initial)
            expected = State.from_buffer_copy(initial)
            if name == 'xar':
                expected.v[31][:] = [0, 0]
            elif name == 'rax1':
                expected.v[31][:] = [value ^ (value << 1 & sha3.MASK64 | value >> 63) for value in initial.v[31]]
            self.assertEqual(bytes(actual), bytes(expected), name)
        self.assertEqual(ctypes.sizeof(State), 784)
        (functions, records) = sha3.corpus()
        self.assertEqual({record['function'] for record in records}, set(range(len(functions))))
        self.assertTrue(all((len(record['initial']) == 784 for record in records)))
        policy = [record for record in records if record['label'].startswith('extended_control_')]
        self.assertEqual(len(policy), 11 * 6)
        self.assertTrue(all(('original' not in record and 'oracle_limit' not in record for record in records)))
        self.assertLessEqual(sum((record['runtime'] for record in records)), 96)
        self.assertEqual({State.from_buffer_copy(record['initial']).fpcr for record in policy}, set(sha3.EXTENDED_CONTROLS))
        representatives = set(sha3.representatives(functions))
        for index in representatives:
            matching = [record for record in records if record['function'] == index and (not record['label'].startswith('extended_control_'))]
            self.assertEqual({State.from_buffer_copy(record['initial']).nzcv >> 28 for record in matching}, set(range(16)))
            self.assertEqual({State.from_buffer_copy(record['initial']).fpcr for record in matching}, set(sha3.STANDARD_CONTROLS))
        original = bytes(initial)
        for operation in sha3.chain():
            initial = sha3.expected(operation, initial)
        self.assertNotEqual(bytes(initial), original)


class I8mmFixtureTests(unittest.TestCase):
    def test_i8mm_canonical_layouts_register_roles_and_encoded_fields(self):
        ops = i8mm.functions()
        self.assertEqual((len(ops), len({op['word'] for op in ops})), (798, 798))
        layouts = {(op['name'], op['bytes'], op['index']) for op in ops}
        self.assertEqual(len(layouts), 21)
        facts = {row['id']: row for row in json.loads((ROOT / 'tests/isa/a64-documented-checklist.json').read_bytes())['forms']}
        for op in ops:
            fact = facts[op['canonical_id']]
            self.assertEqual(op['word'] & int(fact['encoding_mask'], 0), int(fact['encoding_value'], 0))
            self.assertEqual((op['word'] & 31, op['word'] >> 5 & 31, op['word'] >> 16 & 31), (op['d'], op['n'], op['m']))
            if op['index'] is not None:
                self.assertEqual((op['word'] >> 11 & 1) << 1 | op['word'] >> 21 & 1, op['index'])
        self.assertEqual({op['canonical_id'] for op in ops}, set(i8mm.CANONICAL_FORMS))
        for layout in layouts:
            selected = [op for op in ops if (op['name'], op['bytes'], op['index']) == layout]
            for role in ('d', 'n', 'm'):
                self.assertEqual({op[role] for op in selected}, set(range(32)))
        for (args, options) in ((('smmla', 8), {}), (('ummla', 16, 0), {}), (('sudot', 16), {}), (('usdot', 16, 4), {}), (('usdot', 8), {'m': 32})):
            with self.assertRaises(ValueError):
                i8mm.operation(*args, **options)

    def test_i8mm_matrix_column_storage_row_order_and_wrapped_addend(self):
        state = State()
        state.v[1][:] = struct.unpack('<2Q', bytes([1] + [0] * 7 + [0, 2] + [0] * 6))
        state.v[2][:] = struct.unpack('<2Q', bytes([3] + [0] * 7 + [0, 4] + [0] * 6))
        state.v[0][:] = struct.unpack('<2Q', struct.pack('<4I', 4294967295, 2147483647, 2147483648, 4294967294))
        for name in i8mm.MATRIX_BASES:
            actual = i8mm.expected(i8mm.operation(name), state)
            self.assertEqual(struct.unpack('<4I', struct.pack('<2Q', *actual.v[0])), (2, 2147483647, 2147483648, 6))
        (state.v[1][:], state.v[2][:], state.v[0][:]) = ([9259542123273814144] * 2, [18446744073709551615] * 2, [0, 0])
        for (name, expected) in (('smmla', 1024), ('ummla', 261120), ('usmmla', -1024 & 4294967295)):
            actual = i8mm.expected(i8mm.operation(name), state)
            self.assertEqual(struct.unpack('<4I', struct.pack('<2Q', *actual.v[0])), (expected,) * 4)

    def test_i8mm_index_reads_all_vm_bits_and_writes_only_destination(self):
        for name in ('usdot', 'sudot'):
            op = i8mm.operation(name, 8, 3, m=31)
            state = State()
            seed_extended_state(state, 123)
            state.v[0][:] = [0, 18446744073709551615]
            (left, right) = (bytes([255]) * 8 + bytes([128]) * 8, bytes(12) + bytes([128]) * 4)
            if name == 'sudot':
                (left, right) = (bytes([128]) * 16, bytes(12) + bytes([255]) * 4)
            (state.v[1][:], state.v[31][:]) = (struct.unpack('<2Q', left), struct.unpack('<2Q', right))
            before = bytes(state)
            actual = i8mm.expected(op, state)
            expected = State.from_buffer_copy(state)
            value = -130560 & 4294967295
            expected.v[0][:] = [value | value << 32, 0]
            self.assertEqual(bytes(actual), bytes(expected))
            self.assertEqual(bytes(state), before)

    def test_i8mm_all_aliases_use_snapshots_and_never_saturate(self):
        state = State()
        state.v[31][:] = [72340172838076673] * 2
        actual = i8mm.expected(i8mm.operation('smmla', d=31, n=31, m=31), state)
        self.assertEqual(list(actual.v[31]), [72340207197815049] * 2)
        for name in ('usdot', 'sudot'):
            state.v[1][:] = [9187201950435737471] * 2 if name == 'sudot' else [18446744073709551615] * 2
            state.v[2][:] = [18446744073709551615] * 2 if name == 'sudot' else [9187201950435737471] * 2
            state.v[0][:] = [0, 0]
            state.fpsr = 134217759
            op = i8mm.operation(name, 16, 0 if name == 'sudot' else None)
            actual = i8mm.expected(op, state)
            self.assertEqual(struct.unpack('<4I', struct.pack('<2Q', *actual.v[0])), (129540,) * 4)
            self.assertEqual(actual.fpsr, state.fpsr)

    def test_i8mm_corpus_and_runtime_budget_cover_every_layout_and_control(self):
        (ops, records) = i8mm.corpus()
        self.assertEqual((len(ops), len(records)), (798, 13440))
        self.assertEqual({record['function'] for record in records}, set(range(798)))
        runtime = [record for record in records if record['runtime']]
        self.assertEqual(len(runtime), 95)
        self.assertEqual({(ops[r['function']]['name'], ops[r['function']]['bytes'], ops[r['function']]['index']) for r in runtime}, {(op['name'], op['bytes'], op['index']) for op in ops})
        self.assertEqual({State.from_buffer_copy(r['initial']).fpcr >> 22 & 3 for r in runtime}, {0, 1, 2, 3})
        self.assertEqual({bool(State.from_buffer_copy(r['initial']).fpsr & i8mm.FPSR_QC) for r in runtime}, {False, True})
        self.assertEqual(i8mm.optional_opcodes('x86_64-baseline+fma'), set())
        self.assertEqual(i8mm.optional_opcodes('x86_64-baseline+ssse3+sse4.1'), {'phaddd'})


class FixtureRunnerTests(unittest.TestCase):
    def setUp(self):
        self.op = sha3.operation('eor3', d=0, n=1, m=2, a=3)
        initial = State()
        seed_extended_state(initial, 1234)
        initial.x[30] = engine.STOP
        self.initial = initial
        self.family = SimpleNamespace(FOCUS='sha3', CANONICAL_FORMS=(self.op['canonical_id'],),
            functions=lambda:[self.op], corpus=lambda:([self.op], [{'function':0, 'label':'toy', 'initial':bytes(initial), 'runtime':True}]),
            expected=sha3.expected)

    def test_interface_rejects_missing_form_runtime_and_short_state(self):
        operations, records = runner.fixture_corpus(self.family)
        self.assertEqual((len(operations), len(records)), (1, 1))
        self.assertEqual(operations[0]['merge'], 'none')
        self.family.corpus = lambda:([self.op], [{'function':0, 'label':'toy', 'initial':bytes(self.initial), 'runtime':False}])
        with self.assertRaisesRegex(AssertionError, 'runtime selection'):
            runner.fixture_corpus(self.family)
        self.family.corpus = lambda:([self.op], [{'function':0, 'label':'toy', 'initial':bytes(7), 'runtime':True}])
        with self.assertRaisesRegex(AssertionError, 'framing'):
            runner.fixture_corpus(self.family)

    def test_expected_model_cannot_modify_fp_status_or_input_state(self):
        original = bytes(self.initial)
        runner.expected_state(self.family, self.op, self.initial)
        self.assertEqual(bytes(self.initial), original)
        def bad_model(operation, initial):
            initial.fpsr ^= 1
            return initial
        self.family.expected = bad_model
        with self.assertRaisesRegex(AssertionError, 'outside its destination'):
            runner.expected_state(self.family, self.op, self.initial)
        self.assertEqual(bytes(self.initial), original)

    def test_repeated_model_replays_accumulator_instead_of_reusing_first_result(self):
        def accumulating(operation, initial):
            state = State.from_buffer_copy(initial)
            state.v[operation['d']][0] = (state.v[operation['d']][0] + 7) & ((1 << 64) - 1)
            return state
        self.family.expected = accumulating
        one = runner.apply_operations(self.family, [self.op], self.initial)
        three = runner.apply_operations(self.family, [self.op] * 3, self.initial)
        self.assertEqual((three.v[0][0] - one.v[0][0]) & ((1 << 64) - 1), 14)
        self.assertNotEqual(bytes(three), bytes(one))

    def test_admission_uses_independent_decoder_before_mocked_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(engine.subprocess, 'check_output', side_effect=RuntimeError('compiler reached')) as compile_call:
                with self.assertRaisesRegex(RuntimeError, 'compiler reached'):
                    engine.compile_batch(Path('mock-stela'), Path(temporary), [{'operations':[self.op]}], 0,
                        allowed_mnemonics={'eor3'})
                self.assertEqual(compile_call.call_count, 1)
                with self.assertRaisesRegex(AssertionError, 'Independent decoder'):
                    engine.compile_batch(Path('mock-stela'), Path(temporary), [{'operations':[self.op]}], 0,
                        allowed_mnemonics={'not-the-decoded-instruction'})
                self.assertEqual(compile_call.call_count, 1)

    def test_leaf_wrapper_does_not_treat_undefined_exit_scratch_as_block_exit(self):
        expected = runner.expected_state(self.family, self.op, self.initial)
        record = {'function':0, 'case':0, 'operation':self.op, 'initial':bytes(self.initial),
            'expected':bytes(expected), 'equality_basis':'direct_original'}
        requested = []
        def wrapper(state, address, mxcsr, exit_pointer):
            ctypes.memmove(state, bytes(expected), ctypes.sizeof(State))
            observed = ctypes.cast(exit_pointer, ctypes.POINTER(engine.NumericalNativeExit)).contents
            observed.kind, observed.next_pc = 0xdead, 0xbeef
            observed.mxcsr_before = observed.mxcsr_after = mxcsr
            requested.append(mxcsr)
        batches = [{'cohort':'sha3', 'oracle_path':'unit-only', 'native':b'', 'offsets':[0], 'function_base':0}]
        with patch.object(runner, 'family_module', return_value=self.family), \
                patch.object(runner, 'load_original', return_value={'records':[record]}), \
                patch.object(engine, 'executable', side_effect=lambda _:nullcontext(0)), \
                patch.object(runner.ctypes, 'CFUNCTYPE', return_value=lambda _:wrapper):
            result = runner.execute_batches(engine, batches)
        self.assertEqual(result['complete_native_state_comparisons'], 1)
        self.assertEqual(result['direct_original_math_native_comparisons'], 1)
        self.assertEqual(result['caller_mxcsr_preservation_comparisons'], 16)
        self.assertEqual(len(set(requested)), 16)

    def test_dependency_manifest_includes_fixture_adapter_package_and_shared_engine(self):
        identities = runner.dependencies(engine, sha3)
        for source in (Path(engine.__file__), Path(runner.__file__), Path(sha3.__file__),
                Path(sha3.__file__).parent / '__init__.py', ROOT / 'dev/differential.py', ROOT / 'dev/evidence.py'):
            self.assertEqual(identities[str(source.relative_to(ROOT))], engine.digest(source.read_bytes()))

    def test_original_storage_policy_preserves_raw_frames_and_never_credits_direct_equality(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.stela/research/integer-crypto-harness') as temporary:
            directory = Path(temporary)
            self.initial.fpcr = 0x9f00
            operations, cases = runner.fixture_corpus(self.family)
            expected = runner.expected_state(self.family, self.op, self.initial)
            observed = State.from_buffer_copy(expected)
            observed.fpcr = 0
            snapshot = bytearray(1024)
            struct.pack_into('<31Q', snapshot, 0, *observed.x)
            struct.pack_into('<4Q', snapshot, 248, observed.sp, observed.nzcv | 0x3c0, observed.fpcr, observed.fpsr)
            struct.pack_into('<5Q', snapshot, engine.VECTOR_NUMERICAL_EXCEPTION_OFFSET,
                engine.FP_REGISTER_EC_SVC << 26, BASE + 8, 4, engine.VECTOR_NUMERICAL_CPACR_FPEN, engine.VECTOR_NUMERICAL_ORIGINAL_MARKER)
            struct.pack_into('<64Q', snapshot, engine.VECTOR_NUMERICAL_VECTORS_OFFSET, *[value for vector in observed.v for value in vector])
            struct.pack_into('<2Q', snapshot, engine.VECTOR_NUMERICAL_READBACK_OFFSET, 0, self.initial.fpsr)
            files = {'functions.json':json.dumps([{**operations[0], 'source_hex':struct.pack('<II', self.op['word'], engine.RET).hex()}]).encode(),
                'cases.json':json.dumps([{key:value for key, value in cases[0].items() if key != 'initial'}]).encode(),
                'inputs.bin':struct.pack('<Q', 0) + bytes(self.initial) + bytes(8),
                'results.bin':bytes(1024) + bytes(snapshot), 'guest.elf':b'unit-test-elf'}
            for name, data in files.items():
                (directory / name).write_bytes(data)
            producer = {'directory':str(directory.relative_to(ROOT)), 'cases':1,
                'passed_transport_and_architectural_frame_checks':True,
                'files':{name:{'sha256':engine.digest(data), 'bytes':len(data)} for name, data in files.items()}}
            receipt = directory / 'receipt.json'
            receipt.write_text(json.dumps(producer))
            pointer = directory / 'pointer.json'
            pointer.write_text(json.dumps({'directory':producer['directory'],
                'receipt':{'path':str(receipt.relative_to(ROOT)), 'sha256':engine.digest(receipt.read_bytes())}}))
            word_at = {BASE:self.op['word'], BASE + 4:engine.FP_REGISTER_SVC}
            with patch.object(engine, 'fp_register_elf_word', side_effect=lambda elf, pc:word_at[pc]):
                loaded = runner.load_original(engine, self.family, pointer)
            record = loaded['records'][0]
            self.assertEqual(record['equality_basis'], 'requested_storage_policy')
            self.assertEqual(State.from_buffer_copy(record['primary_expected']).fpcr, 0)
            self.assertEqual(State.from_buffer_copy(record['expected']).fpcr, 0x9f00)
            self.assertEqual(State.from_buffer_copy(record['initial']).fpcr, 0x9f00)
            self.assertEqual((directory / 'results.bin').read_bytes(), files['results.bin'])

    def test_promoted_observer_takes_explicit_focus_and_frozen_source_bindings(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.stela/research/integer-crypto-harness') as temporary:
            directory = Path(temporary)
            operations, records = runner.fixture_corpus(self.family)
            engine.prepare_full_frame_numerical_oracle(directory, operations, records, 'sha3')
            with patch.object(simd_original, 'tools_and_bindings', side_effect=RuntimeError('tools reached')) as tools:
                with self.assertRaisesRegex(AssertionError, 'Frozen original source binding changed'):
                    simd_original.prepare(directory, 'sha3', {'dev/differential.py':'incorrect'})
                tools.assert_not_called()
                with self.assertRaisesRegex(ValueError, 'Invalid original observer focus'):
                    simd_original.prepare(directory, '../not-a-focus', {})
                tools.assert_not_called()
                with self.assertRaisesRegex(RuntimeError, 'tools reached'):
                    simd_original.prepare(directory, 'sha3',
                        {'dev/differential.py':engine.digest((ROOT / 'dev/differential.py').read_bytes())})
                self.assertEqual(tools.call_count, 1)
