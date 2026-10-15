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



# Pure model guards adapted from retained conversion/rounding/BF selftests.
# These tests do not execute original Arm or translated native instructions.
import itertools
from fractions import Fraction as _Next63Fraction
from simd_fixtures.sve_floating import conversion as _next63_conversion
from simd_fixtures.sve_floating import rounding as _next63_rounding
from simd_fixtures.sve_floating import bfloat16 as _next63_bfloat16
_NEXT63_FORMATS = {16: (10, 5, 15), 32: (23, 8, 127), 64: (52, 11, 1023)}

def _next63_rounding_reference(op, size, control, bits):
    f, e, bias = _NEXT63_FORMATS[size]
    mask = (1 << size) - 1
    bits &= mask
    sign = bits >> (size - 1)
    frac = bits & ((1 << f) - 1)
    exp = (bits >> f) & ((1 << e) - 1)
    signbits = sign << (size - 1)
    maxexp = (1 << e) - 1
    if exp == maxexp:
        if frac == 0:
            return bits, 0
        status = 0 if frac >> (f - 1) else _next63_rounding.FPSR_INVALID
        if control & _next63_rounding.FPCR_DN:
            return ((bool(control & _next63_rounding.FPCR_AH) << (size - 1)) | (maxexp << f) | (1 << (f - 1))), status
        return bits | (1 << (f - 1)), status
    if exp == 0:
        if frac == 0:
            return signbits, 0
        if size == 16 and control & _next63_rounding.FPCR_FZ16:
            return signbits, 0
        if size != 16:
            fz = bool(control & _next63_rounding.FPCR_FZ) and not control & _next63_rounding.FPCR_AH
            if fz or control & _next63_rounding.FPCR_FIZ:
                return signbits, _next63_rounding.FPSR_INPUT_DENORMAL if fz else 0
        value = _Next63Fraction(frac) * _Next63Fraction(2) ** (1 - bias - f)
    else:
        value = _Next63Fraction((1 << f) + frac) * _Next63Fraction(2) ** (exp - bias - f)
    if sign:
        value = -value
    lower = value.numerator // value.denominator
    error = value - lower
    mode = {
        'FRINTN': 0, 'FRINTP': 1, 'FRINTM': 2, 'FRINTZ': 3, 'FRINTA': 4,
        'FRINTI': (control >> _next63_rounding.FPCR_ROUNDING_SHIFT) & 3,
        'FRINTX': (control >> _next63_rounding.FPCR_ROUNDING_SHIFT) & 3,
    }[op]
    up = {
        0: error > _Next63Fraction(1, 2) or error == _Next63Fraction(1, 2) and lower & 1,
        1: error != 0,
        2: False,
        3: error != 0 and lower < 0,
        4: error > _Next63Fraction(1, 2) or error == _Next63Fraction(1, 2) and lower >= 0,
    }[mode]
    integer = lower + bool(up)
    status = _next63_rounding.FPSR_INEXACT if op == 'FRINTX' and error else 0
    if integer == 0:
        return signbits, status
    integer = abs(integer)
    exponent = integer.bit_length() - 1
    mantissa = _Next63Fraction(integer) * _Next63Fraction(2) ** (f - exponent) - (1 << f)
    assert mantissa.denominator == 1
    return signbits | ((exponent + bias) << f) | int(mantissa), status

class Next63NumericalModelTests(unittest.TestCase):
    def test_conversion_lane_controls_and_saturation(self):
        model = _next63_conversion
        lane = model.conversion_lane
        check = self.assertEqual
        check(lane(0x7c01, 16, 32, model.Kind.PRECISION, model.FPCR_AHP), model.LaneResult(0x7fc02000, model.FPSR_INVALID))
        check(lane(1, 16, 32, model.Kind.PRECISION, model.FPCR_FZ16), model.LaneResult(0x33800000))
        check(lane(1, 16, 32, model.Kind.FP_TO_SIGNED, model.FPCR_FZ16), model.LaneResult(0))
        check(lane(1, 32, 64, model.Kind.PRECISION, model.FPCR_AH).exceptions, model.FPSR_INPUT_DENORMAL)
        check(lane(1, 32, 64, model.Kind.PRECISION, model.FPCR_FZ), model.LaneResult(0, model.FPSR_INPUT_DENORMAL))
        check(lane(1, 32, 64, model.Kind.PRECISION, model.FPCR_FIZ), model.LaneResult(0))
        check(lane(0xbfc00000, 32, 32, model.Kind.FP_TO_UNSIGNED), model.LaneResult(0, model.FPSR_INVALID))
        check(lane(0xbf000000, 32, 32, model.Kind.FP_TO_UNSIGNED), model.LaneResult(0, model.FPSR_INEXACT))
        check(lane(0x7f800001, 32, 16, model.Kind.BFLOAT, model.FPCR_AH), model.LaneResult(0x7fc0))
        check(lane(0x7f800001, 32, 16, model.Kind.BFLOAT, model.FPCR_AH | model.FPCR_DN), model.LaneResult(0xffc0))
        check(lane(1, 32, 16, model.Kind.BFLOAT, model.FPCR_AH), model.LaneResult(0))
        check(lane(0x3f808000, 32, 16, model.Kind.BFLOAT), model.LaneResult(0x3f80, model.FPSR_INEXACT))
        check(lane(0x3ff0000000000001, 64, 32, model.Kind.PRECISION_ODD), model.LaneResult(0x3f800001, model.FPSR_INEXACT))
        check(lane(0xffffffffffffffff, 64, 16, model.Kind.SIGNED_TO_FP), model.LaneResult(0xbc00))
        check(lane(0x41e0000000000000, 64, 32, model.Kind.FP_TO_SIGNED), model.LaneResult(0x7fffffff, model.FPSR_INVALID))
        check(lane(0xc1e0000000000000, 64, 32, model.Kind.FP_TO_SIGNED), model.LaneResult(0x80000000))
        check(lane(0x43e0000000000000, 64, 64, model.Kind.FP_TO_SIGNED), model.LaneResult(0x7fffffffffffffff, model.FPSR_INVALID))
        check(lane(0x43e0000000000000, 64, 64, model.Kind.FP_TO_UNSIGNED), model.LaneResult(0x8000000000000000))
        check(lane(0x43f0000000000000, 64, 64, model.Kind.FP_TO_UNSIGNED), model.LaneResult(0xffffffffffffffff, model.FPSR_INVALID))
        check(lane(0xffffffffffffffff, 64, 64, model.Kind.UNSIGNED_TO_FP), model.LaneResult(0x43f0000000000000, model.FPSR_INEXACT))
        check(lane(0xffffffffffffffff, 64, 64, model.Kind.UNSIGNED_TO_FP, 3 << model.FPCR_ROUNDING_SHIFT),
                  model.LaneResult(0x43efffffffffffff, model.FPSR_INEXACT))
        check(lane(1, 32, 16, model.Kind.PRECISION), model.LaneResult(0, model.FPSR_UNDERFLOW | model.FPSR_INEXACT))
        check(lane(0x33800000, 32, 16, model.Kind.PRECISION, model.FPCR_FZ16), model.LaneResult(1))
        check(lane(0x38000000, 32, 16, model.Kind.PRECISION), model.LaneResult(0x200))

    def test_conversion_vector_routing_and_refusal(self):
        model = _next63_conversion
        check = self.assertEqual
        source = (0xbff0000000000000).to_bytes(8, 'little') * 2
        old = bytes(range(16))
        spec = model.ConversionSpec(model.Kind.FP_TO_SIGNED, 64, 32)
        check(model.evaluate_vector(spec, source, old, b'\x01\x01').destination, b'\xff' * 16)
        check(model.evaluate_vector(spec, source, old, b'\xfe\xfe').destination, old)
        # Top narrowing preserves every low half under both predication modes.
        source = (0x3ff0000000000000).to_bytes(8, 'little') * 2
        for merging in (False, True):
            spec = model.ConversionSpec(model.Kind.PRECISION, 64, 32, model.Layout.NARROW_TOP, merging)
            result = model.evaluate_vector(spec, source, old, b'\x01\x00').destination
            check(result[:4], old[:4])
            check(result[4:8], (0x3f800000).to_bytes(4, 'little'))
            check(result[8:12], old[8:12])
            check(result[12:], old[12:] if merging else bytes(4))
        source = b''.join(x.to_bytes(2, 'little') for x in [0, 0x3c00, 0, 0x4000] * 2)
        spec = model.ConversionSpec(model.Kind.PRECISION, 16, 32, model.Layout.WIDEN_TOP)
        check(model.evaluate_vector(spec, source, old, b'\x11\x11').destination,
              b''.join(x.to_bytes(4, 'little') for x in [0x3f800000, 0x40000000] * 2))
        # Refusal happens before returning any output; inactive lanes never evaluate.
        spec = model.ConversionSpec(model.Kind.PRECISION, 16, 32)
        check(model.evaluate_vector(spec, source, old, bytes(2), 1 << 8).destination, old)

        for enable in (1 << x for x in (8, 9, 10, 11, 12, 15)):
            with self.assertRaises(model.UnsupportedFpControls):
                model.evaluate_vector(spec, source, old, b"\x01\x00", enable)

    def test_rounding_vectors_aliasing_sticky_status_and_refusal(self):
        m = _next63_rounding
        FORMATS = _NEXT63_FORMATS
        controls = [mode << m.FPCR_ROUNDING_SHIFT for mode in range(4)] + [m.FPCR_AH | m.FPCR_FZ | m.FPCR_DN]
        for size, (f, e, bias) in FORMATS.items():
            lane_bytes = size // 8
            snan = (((1 << e) - 1) << f) | 1
            halfway = (bias + 1) << f | (1 << (f - 2))  # 2.5
            for vl in (16, 32, 64, 128, 256):
                lanes = vl // lane_bytes
                source = b''.join((halfway if lane % 2 == 0 else snan).to_bytes(lane_bytes, 'little') for lane in range(lanes))
                tail = bytes(range(31))
                dest = bytes((index * 73 + 9) & 255 for index in range(vl)) + tail
                alternating = sum(1 << (lane * lane_bytes) for lane in range(0, lanes, 2))
                ignored_predicate_bits = sum(1 << (offset + 1) for offset in range(0, vl, lane_bytes))
                for op, control in itertools.product(m.OPERATIONS, controls):
                    actual = m.evaluate_vector(op, size, control, 0x88000005, source, dest, alternating | ignored_predicate_bits, vl)
                    expected = bytearray(dest)
                    fresh = 0
                    for lane in range(0, lanes, 2):
                        bits, status = _next63_rounding_reference(op, size, control, halfway)
                        offset = lane * lane_bytes
                        expected[offset:offset + lane_bytes] = bits.to_bytes(lane_bytes, 'little')
                        fresh |= status
                    self.assertEqual(actual.destination, bytes(expected))
                    self.assertEqual(actual.fpsr, 0x88000005 | fresh)
                    self.assertEqual(actual.exceptions, fresh)
                    self.assertEqual(actual.active_lanes, (lanes + 1) // 2)
                    self.assertEqual(actual.destination[vl:], tail)
                    byte_pred = (alternating | ignored_predicate_bits).to_bytes(vl // 8, 'little')
                    self.assertEqual(m.evaluate_vector(op, size, control, 0x88000005, source, dest, byte_pred, vl), actual)
                    # Alias snapshot: inactive bytes preserve original aliased input.
                    alias = bytearray(source + tail)
                    alias_original = bytes(alias)
                    aliased = m.evaluate_vector(op, size, control, 0, alias, alias, alternating, vl)
                    self.assertEqual(bytes(alias), alias_original)
                    self.assertEqual(aliased.destination[vl:], tail)
                    for lane in range(1, lanes, 2):
                        offset = lane * lane_bytes
                        self.assertEqual(aliased.destination[offset:offset + lane_bytes], source[offset:offset + lane_bytes])

                for enable in (1, 2, 4, 8, 16, 128, 159):
                    control = enable << m.FP_EXCEPTION_ENABLE_SHIFT
                    actual = m.evaluate_vector('FRINTX', size, control, 0x88000005, source, dest, ignored_predicate_bits, vl)
                    self.assertEqual(actual, m.VectorResult(dest, 0x88000005, 0, 0))
                    try:
                        m.evaluate_vector('FRINTX', size, control, 0, source, dest, 1, vl)
                    except m.UnsupportedControl as error:
                        self.assertEqual(error.enabled_exceptions, enable)
                    else:
                        raise AssertionError('active numerical exception enables silently accepted')


        # AHP and NEP are ignored, and enabled controls decline even exact zero.
        for size, (f, e, bias) in FORMATS.items():
            for op in m.OPERATIONS:
                for value in (0, 1, bias << f, (((1 << e) - 1) << f) | 1):
                    self.assertEqual(m.evaluate_lane(op, size, 0, value), m.evaluate_lane(op, size, (1 << 26) | (1 << 2), value))
                for enable in (1, 2, 4, 8, 16, 128, 159):
                    try:
                        m.evaluate_lane(op, size, enable << m.FP_EXCEPTION_ENABLE_SHIFT, 0)
                    except m.UnsupportedControl as error:
                        self.assertEqual(error.enabled_exceptions, enable)
                    else:
                        raise AssertionError('exact zero bypassed numerical control decline')

            # Distinct active lanes independently contribute sticky IOC and IXC.
            lane_bytes = size // 8
            snan = (((1 << e) - 1) << f) | 1
            halfway = (bias + 1) << f | (1 << (f - 2))
            source = snan.to_bytes(lane_bytes, 'little') + halfway.to_bytes(lane_bytes, 'little') + bytes(16 - 2 * lane_bytes)
            actual = m.evaluate_vector('FRINTX', size, 0, 1 << 27, source, bytes(16), 1 | (1 << lane_bytes))
            self.assertEqual(actual.exceptions, m.FPSR_INVALID | m.FPSR_INEXACT)
            self.assertEqual(actual.fpsr, (1 << 27) | m.FPSR_INVALID | m.FPSR_INEXACT)

    def test_bfloat16_directed_controls_and_status(self):
        m = _next63_bfloat16
        equal = self.assertEqual
        def vector(value, width=2, length=16):
            return value.to_bytes(width, 'little') * (length // width)

        def scalar(kind, a, b, c=0, fpcr=0, width=2, **kwargs):
            out = m.evaluate(kind, vector(c, width), vector(a), vector(b), fpcr=fpcr, **kwargs)
            return int.from_bytes(out.value[:width], 'little'), out.exceptions

        for mode in range(4):
            equal(scalar('add', 0x3f80, 0xbf80, fpcr=mode << 22), (0x8000 if mode == 2 else 0, 0))
            equal(scalar('mul', 0x3f81, 0x3f7e, fpcr=mode << 22), ([0x3f80, 0x3f80, 0x3f7f, 0x3f7f][mode], 16))
            equal(scalar('mlal', 0x3f80, 0x3380, 0x3f800000, width=4, fpcr=2 | mode << 22), (0x3f800000, 0))
        for kind in ('min', 'max'):
            equal(scalar(kind, 0x7fc1, 0x3f80, fpcr=2), (0x3f80, 1))
            equal(scalar(kind, 0x3f80, 0x7f81, fpcr=2), (0x7f81, 1))
        equal(scalar('maxnm', 0x7fc1, 0x3f80, fpcr=2), (0x3f80, 0))
        equal(scalar('minnm', 0x7fc1, 0x7f81, fpcr=2), (0x7fc1, 1))
        equal(scalar('mla', 0, 0x7f80, 0x7fc1), (0x7fc0, 1))
        equal(scalar('mla', 0, 0x7f80, 0x7fc1, fpcr=2), (0x7fc1, 0))
        equal(scalar('mul', 1, 0x3f80, fpcr=1 << 24), (0, 128))
        equal(scalar('mul', 1, 0x3f80, fpcr=1), (0, 0))
        equal(scalar('mul', 1, 0x3f80, fpcr=2), (1, 128))
        equal(scalar('mlsl', 0x7f80, 0x3f80, width=4, fpcr=2), (0xff800000, 0))
        equal(scalar('mlsl', 0x7f81, 0x3f80, width=4, fpcr=2), (0x7fc10000, 0))
        equal(scalar('mul', 0x0080, 0x3f00, fpcr=1 << 24), (0, 8))
        equal(scalar('mul', 0x0080, 0x3f00, fpcr=2 | 1 << 24), (0, 24))
        equal(scalar('mul', 0x7f7f, 0x4000), (0x7f80, 20))
        equal(scalar('mul', 0x7f7f, 0x4000, fpcr=3 << 22), (0x7f7f, 20))

    def test_bfloat16_vector_routing_and_refusal(self):
        m = _next63_bfloat16
        equal = self.assertEqual
        def vector(value, width=2, length=16):
            return value.to_bytes(width, 'little') * (length // width)

        def scalar(kind, a, b, c=0, fpcr=0, width=2, **kwargs):
            out = m.evaluate(kind, vector(c, width), vector(a), vector(b), fpcr=fpcr, **kwargs)
            return int.from_bytes(out.value[:width], 'little'), out.exceptions

        for length in (16, 32, 64, 128, 256):
            right = b''.join(vector(0x3f80 + segment * 128) for segment in range(length // 16))
            out = m.evaluate('mul', vector(0x7777, length=length), vector(0x3f80, length=length), right, index=7, fpsr=0xa5000000)
            equal(out.value, right)
            equal(out.fpsr, 0xa5000000)
            out = m.evaluate('mul', vector(0x7777, length=length), vector(0x7f81, length=length), vector(0x3f80, length=length), predicate=0)
            equal(out.value, vector(0x7777, length=length))
            equal(out.exceptions, 0)
            out = m.evaluate('mul', vector(0x7777, length=length), vector(0x3f80, length=length), right, predicate=1)
            equal(out.value[2:], vector(0x7777, length=length)[2:])

        # Widening bottom/top routing and indexed segment reuse remain independent of destination.
        for top in (False, True):
            left = b''.join(x.to_bytes(2, 'little') for x in [0x3f80, 0x4000] * 8)
            right = vector(0x3f80, length=16) + vector(0x4000, length=16)
            out = m.evaluate('mlal', vector(0, 4, 32), left, right, top=top, index=7)
            expected = vector(0x40000000 if top else 0x3f800000, 4) + vector(0x40800000 if top else 0x40000000, 4)
            equal(out.value, expected)
        for kwargs in ({'fpcr': -1}, {'fpsr': 1 << 32}, {'predicate': -1}, {'predicate': 1 << 16}, {'index': 8}, {'top': True}):
            try:
                m.evaluate('mul', vector(0), vector(0x3f80), vector(0x3f80), **kwargs)
                raise AssertionError('invalid input was silently accepted')
            except ValueError:
                pass

        for kind in ("add", "mul", "mla", "mlal"):
            with self.assertRaises(m.UnsupportedControl):
                scalar(kind, 0x3f80, 0x3f80, fpcr=0x100, profile=m.Profile(full_a64=True))



if __name__ == '__main__':
    unittest.main()
