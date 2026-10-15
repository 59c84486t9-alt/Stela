"""Protocol and ABI guards for the shared scalable evidence adapters."""

from dataclasses import replace
import ctypes
import struct
from pathlib import Path
import tempfile
import unittest

import scalable_frame as frame
import scalable_fixture_runner as native
import scalable_original as original


class ScalableFrameGuards(unittest.TestCase):
    def test_all_generic_lengths_roundtrip_with_exact_low_aliases(self):
        for length in range(frame.MIN_VECTOR_BYTES, frame.MAX_VECTOR_BYTES + 1,
                            frame.MIN_VECTOR_BYTES):
            with self.subTest(length=length):
                snapshot = frame.snapshot_from_banks(length, valid=frame.Component.PRIMARY | frame.Component.Z)
                encoded = snapshot.to_bytes()
                self.assertEqual(frame.Snapshot.from_bytes(encoded).to_bytes(), encoded)
                self.assertEqual(len(encoded), frame.offsets(length)['record_bytes'])
                self.assertEqual(len(encoded) % frame.RECORD_ALIGNMENT, 0)

    def test_sme_profile_rejects_general_sve_lengths(self):
        for length in range(frame.MIN_VECTOR_BYTES, frame.MAX_VECTOR_BYTES + 1,
                            frame.MIN_VECTOR_BYTES):
            if length in frame.SME_LENGTHS:
                self.assertEqual(frame.require_sme_length(length), length)
            else:
                with self.assertRaises(ValueError):
                    frame.require_sme_length(length)

    def test_alias_disagreement_is_never_repaired_by_parser(self):
        snapshot = frame.seeded_snapshot(32, b'alias')
        encoded = bytearray(snapshot.to_bytes())
        encoded[frame.offsets(32)['z']] ^= 1
        with self.assertRaisesRegex(ValueError, 'aliases'):
            frame.Snapshot.from_bytes(bytes(encoded))

    def test_truncated_extended_reordered_and_nonzero_padding_fail(self):
        encoded = frame.seeded_snapshot(16, b'framing').to_bytes()
        for changed in (encoded[:-1], encoded + b'\0', b'REVERSED' + encoded[8:]):
            with self.subTest(length=len(changed)):
                with self.assertRaises(ValueError):
                    frame.Snapshot.from_bytes(changed)
        changed = bytearray(encoded)
        changed[-1] = 1
        with self.assertRaisesRegex(ValueError, 'padding'):
            frame.Snapshot.from_bytes(bytes(changed))

    def test_missing_original_component_fails_instead_of_comparing_zeroes(self):
        snapshot = frame.seeded_snapshot(16, b'ffr')
        self.assertFalse(snapshot.valid & frame.Component.FFR)
        with self.assertRaisesRegex(AssertionError, 'not observed'):
            frame.compare(snapshot, snapshot, snapshot.valid | frame.Component.FFR)

    def test_complete_state_and_control_tampering_is_detected(self):
        snapshot = frame.seeded_snapshot(32, b'effects')
        primary = bytearray(snapshot.primary)
        primary[0] ^= 1
        with self.assertRaisesRegex(AssertionError, 'primary'):
            frame.compare(snapshot, replace(snapshot, primary=bytes(primary)), snapshot.valid)
        changed = replace(snapshot, controls={**snapshot.controls,
                                             'tpidr2_el0': snapshot.control('tpidr2_el0') ^ 1})
        with self.assertRaisesRegex(AssertionError, 'tpidr2'):
            frame.compare(snapshot, changed, snapshot.valid)

    def test_seed_is_repeatable_dirty_and_length_bounded(self):
        for length in frame.SME_LENGTHS:
            snapshot = frame.seeded_snapshot(length, b'dirty')
            self.assertEqual(snapshot.digest(), frame.seeded_snapshot(length, b'dirty').digest())
            self.assertNotEqual(snapshot.z[0], snapshot.z[31])
            self.assertNotEqual(snapshot.p[0], snapshot.p[15])
            self.assertFalse(snapshot.valid & (frame.Component.FFR | frame.Component.FPMR))
            fpcr, fpsr = struct.unpack_from('<II', snapshot.primary, frame.PRIMARY_FPCR_OFFSET)
            self.assertFalse(fpcr & ~frame.SEED_FPCR_MASK)
            self.assertFalse(fpsr & ~frame.SEED_FPSR_MASK)

    def test_shared_projection_preserves_unmodeled_banks_and_aliases(self):
        initial = frame.seeded_snapshot(64, b'projection')
        projected = frame.snapshot_to_state(initial)
        self.assertEqual(frame.snapshot_from_state(initial, projected).to_bytes(), initial.to_bytes())
        projected['x'][30] ^= 1
        projected['z'][31] = bytes([0x5a]) * initial.svl_bytes
        projected['p'][15] ^= 1
        output = frame.snapshot_from_state(initial, projected)
        self.assertEqual(output.za, initial.za)
        self.assertEqual(output.zt0, initial.zt0)
        self.assertEqual(output.controls, initial.controls)
        self.assertEqual(output.primary[frame.PRIMARY_VECTOR_OFFSET + 31 * frame.FIXED_VECTOR_BYTES:
                                        frame.PRIMARY_VECTOR_OFFSET + 32 * frame.FIXED_VECTOR_BYTES], bytes([0x5a]) * 16)
        projected['p'][0] = 1 << initial.svl_bytes
        with self.assertRaisesRegex(ValueError, 'Packed predicate'):
            frame.snapshot_from_state(initial, projected)


class ScalableNativeGuards(unittest.TestCase):
    def test_ctypes_offsets_match_production_pointer_contract(self):
        self.assertEqual(ctypes.sizeof(native.ExecutionContext), 32)
        self.assertEqual(ctypes.sizeof(native.ScalableStateView), 72)
        for name, offset in (('svl_bytes', 0), ('svcr', 8), ('tpidr2_el0', 16),
                             ('fpmr', 24), ('z_upper', 32), ('predicates', 40),
                             ('ffr', 48), ('za', 56), ('zt0', 64)):
            self.assertEqual(getattr(native.ScalableStateView, name).offset, offset)

    def test_native_ret_preserves_all_valid_banks_for_every_sme_length(self):
        for length in frame.SME_LENGTHS:
            with self.subTest(length=length):
                snapshot = frame.seeded_snapshot(length, b'actual native RET')
                observed, ram = native.execute_native(native.HOST_RET, snapshot)
                frame.compare(snapshot, observed, snapshot.valid)
                self.assertIsNone(ram)

    def test_pointer_header_and_canary_mutations_are_rejected(self):
        initial = frame.seeded_snapshot(32, b'guards')
        state = native.NativeState(initial)
        state.context.version += 1
        with self.assertRaisesRegex(AssertionError, 'context identity'):
            state.snapshot()
        state = native.NativeState(initial)
        state.view.za += 1
        with self.assertRaisesRegex(AssertionError, 'allocation identity'):
            state.snapshot()
        state = native.NativeState(initial)
        ctypes.c_uint8.from_address(state.za.address - 1).value ^= 1
        with self.assertRaisesRegex(AssertionError, 'boundary'):
            state.snapshot()

    def test_mode_changes_cannot_bypass_runtime_boundary(self):
        state = native.NativeState(frame.seeded_snapshot(32, b'mode'))
        state.view.svcr ^= frame.SVCR_SM
        with self.assertRaisesRegex(AssertionError, 'runtime service'):
            state.snapshot()

    def test_model_snapshot_cannot_impersonate_original(self):
        snapshot = frame.seeded_snapshot(16, b'provenance')
        with self.assertRaisesRegex(AssertionError, 'genuine architectural'):
            native.verify_native_case(native.HOST_RET, snapshot, snapshot,
                                      snapshot, required=snapshot.valid)

    def test_native_ram_roundtrip_preserves_every_byte(self):
        snapshot = frame.seeded_snapshot(16, b'RAM')
        ram = bytes((index * 31) & 255 for index in range(native.RAM_BYTES))
        observed, observed_ram = native.execute_native(native.HOST_RET, snapshot, ram=ram)
        frame.compare(snapshot, observed, snapshot.valid)
        self.assertEqual(observed_ram, ram)

    def test_corpus_binds_actual_words_and_reindexes_every_input(self):
        initial = frame.seeded_snapshot(16, b'corpus', case_index=50, function_index=60)
        cases = [{'operation': {'word': 0xd503201f, 'canonical_id': 'nop_hi_hints'},
                  'initial': initial, 'expected': initial, 'required': initial.valid}
                 for _ in range(2)]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'chunk'
            manifest = native.prepare_corpus(directory, cases, source_paths=[Path(__file__)])
            self.assertEqual(manifest['cases'], 2)
            self.assertEqual(manifest['functions'], 1)
            inputs = native.read_snapshots((directory / 'inputs.bin').read_bytes())
            self.assertEqual([row.case_index for row in inputs], [0, 1])
            self.assertEqual([row.function_index for row in inputs], [0, 0])
            with self.assertRaises(FileExistsError):
                native.prepare_corpus(directory, cases, source_paths=[Path(__file__)])


class ScalableOriginalTests(unittest.TestCase):
    def setUp(self):
        self.subjects = [{'id': 'nop', 'word': 0xd503201f}]
        self.initial = frame.seeded_snapshot(16, b'observer-guards')

    def test_sme_lengths_remain_explicit(self):
        with self.assertRaisesRegex(ValueError, 'power-of-two'):
            original.assembly([self.subjects[0]['word']], 1, 48)

    def test_exact_subject_word_has_one_function(self):
        with self.assertRaisesRegex(ValueError, 'one function'):
            original.validate_inputs(self.subjects * 2, [self.initial])

    def test_streaming_input_requires_complete_banks(self):
        incomplete = replace(self.initial, valid=self.initial.valid & ~frame.Component.P)
        with self.assertRaisesRegex(ValueError, 'initialized Z/P'):
            original.validate_inputs(self.subjects, [incomplete])

    def test_case_indices_cannot_be_relabelled(self):
        with self.assertRaisesRegex(ValueError, 'contiguous'):
            original.validate_inputs(self.subjects, [replace(self.initial, case_index=7)])

    def test_capture_chunks_are_bounded(self):
        with self.assertRaisesRegex(ValueError, '128'):
            original.validate_inputs(self.subjects, [self.initial] * (original.MAX_CAPTURE_CASES + 1))

    def test_spill_precedes_destructive_mode_change(self):
        source, _ = original.assembly([self.subjects[0]['word']], 1, 256)
        capture = source[source.index('exception_entry:'):]
        self.assertLess(capture.index('str z31,'), capture.index('smstop sm'))
        self.assertLess(capture.index('str p15,'), capture.index('smstop sm'))
        self.assertLess(capture.index('mrs x0,fpsr'), capture.index('smstop sm'))
        self.assertNotIn('rdffr', source.lower())
        self.assertNotIn('wrffr', source.lower())

    def test_ram_extension_preserves_frame_offsets(self):
        _, registers = original.assembly([self.subjects[0]['word']], 1, 64)
        source, memory = original.assembly([self.subjects[0]['word']], 1, 64,
                                           ram_bytes=frame.RAM_BYTES)
        for name in ('primary', 'z', 'p', 'ffr', 'za', 'zt0', 'frame_bytes'):
            self.assertEqual(registers[name], memory[name])
        self.assertEqual(memory['raw_bytes'] - registers['raw_bytes'], frame.RAM_BYTES)
        self.assertIn('restore_ram:', source)
        self.assertIn('snapshot_ram:', source)

    def test_access_profile_has_no_ordinary_sve(self):
        self.assertIn('sve=off', original.CPU_PROFILE)
        self.assertIn('sme_fa64=off', original.CPU_PROFILE)
        source, _ = original.assembly([self.subjects[0]['word']], 1, 16)
        self.assertNotIn('msr zcr_el1', source.lower())
        self.assertEqual(original.FP_ACCESS | original.SME_ACCESS, 0x3300000)


class ScalableProfileGuards(unittest.TestCase):
    def receipt(self, bf16=False):
        profile = original.SVE_STREAMING_BF16_V2 if bf16 else original.SME_ONLY_V2
        values = {
            'CurrentEL': original.CURRENT_EL1,
            'ID_AA64PFR0_EL1': 1 << original.ID_PFR0_SVE_SHIFT if bf16 else 0,
            'ID_AA64PFR1_EL1': original.SME2_MINIMUM_FIELD << original.ID_PFR1_SME_SHIFT,
            'ID_AA64SMFR0_EL1': 2 << original.ID_SMFR0_SMEVER_SHIFT,
            'ID_AA64ZFR0_EL1': 1 << original.ID_ZFR0_B16B16_SHIFT if bf16 else 0,
            'ID_AA64MMFR2_EL1': original.LSE2_AT_FIELD << original.ID_MMFR2_AT_SHIFT,
            'SMCR_EL1': original.SMCR_ZT0_ENABLE,
            'CPACR_EL1': profile.cpacr,
        }
        return {'profile_id': profile.id, 'cpu_profile': profile.cpu,
                'requested_svl_bytes': frame.MIN_VECTOR_BYTES,
                'actual_profile': {name: hex(value) for name, value in values.items()},
                'bindings': {'selected_qemu': {
                    'binary': {'path': '/oracle/qemu', 'sha256': 'bound-core'},
                    'executed_binary': {'path': '/oracle/qemu', 'sha256': 'bound-core',
                                        'bytes': 4096, 'kind': 'thin-little-endian-mach-o-64-execute'},
                    'build_receipt_sha256': 'bound-build'}}}

    def test_both_explicit_v2_profiles_validate(self):
        for bf16 in (False, True):
            native.validate_v2_profile(self.receipt(bf16))

    def test_unknown_or_mismatched_cpu_profile_is_rejected(self):
        receipt = self.receipt()
        receipt['profile_id'] = 'unversioned-max'
        with self.assertRaisesRegex(AssertionError, 'Unknown'):
            native.validate_v2_profile(receipt)
        receipt = self.receipt()
        receipt['cpu_profile'] = original.SVE_STREAMING_BF16_V2.cpu
        with self.assertRaisesRegex(AssertionError, 'CPU profile'):
            native.validate_v2_profile(receipt)

    def test_mmfr2_readback_cannot_be_omitted_or_zeroed(self):
        receipt = self.receipt()
        receipt['actual_profile']['ID_AA64MMFR2_EL1'] = '0x0'
        with self.assertRaisesRegex(AssertionError, 'feature profile'):
            native.validate_v2_profile(receipt)

    def test_bf16_feature_and_fa64_boundaries_are_explicit(self):
        receipt = self.receipt(True)
        receipt['actual_profile']['ID_AA64ZFR0_EL1'] = '0x0'
        with self.assertRaisesRegex(AssertionError, 'BF16'):
            native.validate_v2_profile(receipt)
        receipt = self.receipt(True)
        receipt['actual_profile']['SMCR_EL1'] = hex(original.SMCR_ZT0_ENABLE | original.SMCR_FA64)
        with self.assertRaisesRegex(AssertionError, 'feature profile'):
            native.validate_v2_profile(receipt)

    def test_privilege_and_effective_length_are_bound(self):
        for name, value in (('CurrentEL', 0), ('SMCR_EL1', original.SMCR_ZT0_ENABLE | 1)):
            receipt = self.receipt()
            receipt['actual_profile'][name] = hex(value)
            with self.assertRaisesRegex(AssertionError, 'feature profile'):
                native.validate_v2_profile(receipt)

    def test_executed_core_cannot_differ_from_wrapper_build_identity(self):
        receipt = self.receipt()
        receipt['bindings']['selected_qemu']['executed_binary']['sha256'] = 'different-core'
        with self.assertRaisesRegex(AssertionError, 'executed QEMU'):
            native.validate_v2_profile(receipt)


# Pure numerical regressions; no original or translated instruction executes.
from simd_fixtures.sve_floating import arithmetic as _future83_arithmetic
from simd_fixtures.sve_floating import arithmetic_scalar as _future83_scalar
from simd_fixtures.sve_floating import arithmetic_estimate as _future83_estimate
from simd_fixtures.sve_floating import arithmetic_special as _future83_special
from simd_fixtures.sve_floating import half_dot as _future83_half
from simd_fixtures.sve_floating import control as _future83_control
from simd_fixtures.sve_floating.ieee import LaneResult as _Future83LaneResult


class Future83NumericalModelTests(unittest.TestCase):
    def test_rounding_midpoint_and_fused_residual(self):
        model = _future83_scalar
        # 1 + 2^-24 is a Single midpoint. Directed rounding changes one ULP.
        for rounding, expected in ((0, 0x3f800000), (1, 0x3f800001)):
            with self.subTest(rounding=rounding):
                self.assertEqual(model.binary_lane(model.BinaryOperation.ADD, 32,
                                                   rounding << 22, 0x3f800000, 0x33800000),
                                 _Future83LaneResult(expected, _future83_control.FPSR_INEXACT))
        # (1 + 2^-23)(1 - 2^-23) - 1 = -2^-46, requiring fused rounding.
        self.assertEqual(model.fused_lane(model.FusedOperation.ADD, 32, 0,
                                         0xbf800000, 0x3f800001, 0x3f7ffffe),
                         _Future83LaneResult(0xa8800000))

    def test_inactive_signaling_nan_merges_without_exception(self):
        model = _future83_arithmetic
        left = struct.pack('<4I', 0x3f800000, 0x7f800001, 0x7f800001, 0x7f800001)
        right = struct.pack('<4I', *([0x40000000] * 4))
        old = struct.pack('<4I', 0xdeadbeef, 0x11223344, 0x55667788, 0x99aabbcc)
        result = model.evaluate_vector(model.ArithmeticSpec(_future83_scalar.BinaryOperation.ADD, 32),
                                       (left, right), old, b'\x01\x00',
                                       fpsr=_future83_control.FPSR_QC)
        self.assertEqual(result.destination, struct.pack('<I', 0x40400000) + old[4:])
        self.assertEqual(result.fpsr, _future83_control.FPSR_QC)

    def test_indexed_arithmetic_repeats_each_128_bit_segment(self):
        model = _future83_arithmetic
        source = bytearray(struct.pack('<8I', *([0x3f800000] * 8)))
        indexed = struct.pack('<8I', 0, 0x40000000, 0, 0, 0, 0x40400000, 0, 0)
        before = bytes(source)
        spec = model.ArithmeticSpec(_future83_scalar.BinaryOperation.MULTIPLY, 32,
                                    model.Layout.INDEXED, index=1)
        result = model.evaluate_vector(spec, (source, indexed), source)
        self.assertEqual(result.destination, struct.pack('<8I', *([0x40000000] * 4 + [0x40400000] * 4)))
        self.assertEqual(result.fpsr, 0)
        self.assertEqual(bytes(source), before)

    def test_scalar_reduction_clears_upper_destination(self):
        model = _future83_arithmetic
        source = struct.pack('<4I', 0x3f800000, 0x40000000, 0x40400000, 0x40800000)
        spec = model.ArithmeticSpec(_future83_scalar.BinaryOperation.ADD, 32,
                                    model.Layout.SCALAR_REDUCTION)
        result = model.evaluate_vector(spec, (source,), b'\xff' * 16)
        self.assertEqual(result.destination, struct.pack('<I', 0x41200000) + bytes(12))
        self.assertEqual(result.fpsr, 0)

    def test_estimate_special_values_and_integer_exponents(self):
        model = _future83_estimate
        self.assertEqual(model.evaluate_lane(model.Kind.SQRT, 32, 0, 0x40800000),
                         _Future83LaneResult(0x40000000))
        self.assertEqual(model.evaluate_lane(model.Kind.RECIPROCAL, 32, 0, 0x80000000),
                         _Future83LaneResult(0xff800000, _future83_control.FPSR_DIVIDE_BY_ZERO))
        self.assertEqual(model.evaluate_lane(model.Kind.UNSIGNED_RECIPROCAL, 32, 0xffffffff, 0),
                         _Future83LaneResult(0xffffffff))
        self.assertEqual(_future83_special.logb_lane(32, 0, 0x41000000), _Future83LaneResult(3))
        self.assertEqual(_future83_special.logb_lane(32, 0, 0),
                         _Future83LaneResult(0x80000000, _future83_control.FPSR_INVALID))
        self.assertEqual(_future83_special.scale_lane(32, 0, 0x3fc00000, 0xffffffff),
                         _Future83LaneResult(0x3f400000))

    def test_half_dot_rounds_pair_before_accumulator(self):
        # The pair sum 1 + 2^-24 rounds to 1 before adding -1. A three-term
        # fused expression would incorrectly preserve the 2^-24 residual.
        self.assertEqual(_future83_half.dot_lane(0, 0xbf800000,
                                                (0x3c00, 0x0001), (0x3c00, 0x3c00)),
                         _Future83LaneResult(0, _future83_control.FPSR_INEXACT))
        self.assertEqual(_future83_half.dot_lane(0, 0, (1, 0), (1, 0)),
                         _Future83LaneResult(0x27800000))
        self.assertEqual(_future83_half.dot_lane(_future83_control.FPCR_FZ16, 0, (1, 0), (1, 0)),
                         _Future83LaneResult(0))

    def test_half_widening_index_top_and_segment_selection(self):
        model = _future83_half
        destination = struct.pack('<8I', *([0x3f800000] * 8))
        # Bottom lanes contain sNaNs; selecting top must avoid their exceptions.
        left = struct.pack('<16H', *([0x7c01, 0x3c00] * 8))
        right = struct.pack('<16H', *([0x4000] * 8 + [0x4200] * 8))
        result = model.evaluate(model.Kind.MULTIPLY_ADD_LONG, destination, left, right,
                                index=0, top=True, fpsr=_future83_control.FPSR_QC)
        self.assertEqual(result.value, struct.pack('<8I', *([0x40400000] * 4 + [0x40800000] * 4)))
        self.assertEqual((result.fpsr, result.exceptions), (_future83_control.FPSR_QC, 0))



if __name__ == '__main__':
    unittest.main()
