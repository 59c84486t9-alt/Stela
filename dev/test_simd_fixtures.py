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
from simd_fixtures import aes, sha12, sha512, sha3, i8mm, structure_memory, ordinary_memory
import simd_fixture_runner as runner
import simd_original
import simd_memory_runner
import hashlib

engine = importlib.import_module('simd-differential')

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
