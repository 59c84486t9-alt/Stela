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
from simd_fixtures import aes, sha12, sha512, sha3, i8mm
import simd_fixture_runner as runner
import simd_original

engine = importlib.import_module('simd-differential')

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
