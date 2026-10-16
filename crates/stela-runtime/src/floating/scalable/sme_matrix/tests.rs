use super::*;
const OUTER_TEST_SVL_BYTES: usize = 16;
const OUTER_SINGLE_MINUS_ONE: u32 = 0xbf80_0000;
const OUTER_SINGLE_NEGATIVE_ZERO: u32 = 0x8000_0000;
const OUTER_SINGLE_FUSED_RESULT: u32 = 0xa880_0000;
const OUTER_SINGLE_FUSED_LEFT: u32 = 0x3f80_0001;
const OUTER_SINGLE_FUSED_RIGHT: u32 = 0x3f7f_fffe;
const OUTER_SINGLE_FMA_WORD: u32 = 0x8081_0000;
const OUTER_HALF_FMS_WORD: u32 = 0x81a0_2010;
const OUTER_BFLOAT_FMS_WORD: u32 = 0x8180_2010;

fn outer_test_state() -> (GuestState, ScalableState) {
    use stela_compiler::aarch64::scalable::{ScalableMode, VectorLength};
    let mut state = GuestState::default();
    let mut scalable = ScalableState::new(
        VectorLength::from_bytes(OUTER_TEST_SVL_BYTES).unwrap(),
        true,
    );
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    (state, scalable)
}

#[test]
fn outer_fused_result_is_staged_without_touching_guest_banks() {
    let (mut state, mut scalable) = outer_test_state();
    let mut source = [0; OUTER_TEST_SVL_BYTES];
    for lane in source.as_chunks_mut::<SINGLE_BYTES>().0 {
        lane.copy_from_slice(&OUTER_SINGLE_FUSED_LEFT.to_le_bytes());
    }
    scalable.write_z(&mut state, 0, &source).unwrap();
    for lane in source.as_chunks_mut::<SINGLE_BYTES>().0 {
        lane.copy_from_slice(&OUTER_SINGLE_FUSED_RIGHT.to_le_bytes());
    }
    scalable.write_z(&mut state, 1, &source).unwrap();
    scalable
        .write_predicate(0, &[0xff; OUTER_TEST_SVL_BYTES / BITS_PER_BYTE])
        .unwrap();
    let width = size_of::<u32>();
    for row in 0..OUTER_TEST_SVL_BYTES / width {
        let mut bytes = [0; OUTER_TEST_SVL_BYTES];
        for lane in bytes.chunks_exact_mut(width) {
            lane.copy_from_slice(&OUTER_SINGLE_MINUS_ONE.to_le_bytes());
        }
        scalable
            .write_za(row * width * OUTER_TEST_SVL_BYTES, &bytes)
            .unwrap();
    }
    let original_state = state.clone();
    let mut original_za = [0; OUTER_TEST_SVL_BYTES * OUTER_TEST_SVL_BYTES];
    scalable.read_za(0, &mut original_za).unwrap();
    let operand = fp_matrix::decode_outer(OUTER_SINGLE_FMA_WORD).unwrap();
    let mut scratch = [0; OUTER_TEST_SVL_BYTES * OUTER_TEST_SVL_BYTES / SINGLE_BYTES];
    let staged =
        complete_outer(&state, &scalable, &operand, floating::FPCR_DN, &mut scratch).unwrap();
    for row in 0..OUTER_TEST_SVL_BYTES / width {
        for column in 0..OUTER_TEST_SVL_BYTES / width {
            assert_eq!(
                read_lane(staged.row(row), column, width),
                u64::from(OUTER_SINGLE_FUSED_RESULT)
            );
        }
    }
    let mut actual_za = [0; OUTER_TEST_SVL_BYTES * OUTER_TEST_SVL_BYTES];
    scalable.read_za(0, &mut actual_za).unwrap();
    assert_eq!(state, original_state);
    assert_eq!(actual_za, original_za);
}

#[test]
fn outer_subtraction_keeps_masked_zero_positive() {
    for word in [OUTER_HALF_FMS_WORD, OUTER_BFLOAT_FMS_WORD] {
        let (state, mut scalable) = outer_test_state();
        // P0 selects left member0; P1 selects both right members. Active left
        // +0 becomes -0, whereas masked member1 must stay +0. Pair sum is +0.
        scalable.write_predicate(0, &[0x01, 0]).unwrap();
        scalable.write_predicate(1, &[0x05, 0]).unwrap();
        scalable
            .write_za(0, &OUTER_SINGLE_NEGATIVE_ZERO.to_le_bytes())
            .unwrap();
        let operand = fp_matrix::decode_outer(word).unwrap();
        let mut scratch = [0; OUTER_TEST_SVL_BYTES * OUTER_TEST_SVL_BYTES / SINGLE_BYTES];
        let staged =
            complete_outer(&state, &scalable, &operand, floating::FPCR_DN, &mut scratch).unwrap();
        assert_eq!(read_lane(staged.row(0), 0, size_of::<u32>()), 0);
        let mut original = [0; size_of::<u32>()];
        scalable.read_za(0, &mut original).unwrap();
        assert_eq!(u32::from_le_bytes(original), OUTER_SINGLE_NEGATIVE_ZERO);
    }
}

#[test]
fn staging_initializes_every_borrowed_byte_and_rejects_wrong_slice_size() {
    let (_, mut scalable) = outer_test_state();
    let first = [0x35; OUTER_TEST_SVL_BYTES];
    let last = [0xc7; OUTER_TEST_SVL_BYTES];
    scalable.write_za(0, &first).unwrap();
    scalable
        .write_za((OUTER_TEST_SVL_BYTES - 1) * OUTER_TEST_SVL_BYTES, &last)
        .unwrap();
    let mut scratch = [0xa5; 2 * OUTER_TEST_SVL_BYTES];
    let staged = ZaResults::stage(&scalable, &[0, OUTER_TEST_SVL_BYTES - 1], &mut scratch).unwrap();
    assert_eq!(staged.row(0), first);
    assert_eq!(staged.row(1), last);
    assert!(ZaResults::stage(&scalable, &[0], &mut [0; OUTER_TEST_SVL_BYTES - 1]).is_err());
}

#[test]
fn outer_dot_bfloat_negation_ignores_ah_but_half_preserves_nan_sign() {
    const BFLOAT_SIGNALING_NAN: u16 = 0x7f81;
    const BFLOAT_NEGATIVE_SIGNALING_NAN: u16 = 0xff81;
    const HALF_SIGNALING_NAN: u16 = 0x7c01;
    assert_eq!(
        outer_negate_dot_member(DotFormat::BFloat16, floating::FPCR_AH, BFLOAT_SIGNALING_NAN),
        BFLOAT_NEGATIVE_SIGNALING_NAN,
    );
    assert_eq!(
        outer_negate_dot_member(DotFormat::Half, floating::FPCR_AH, HALF_SIGNALING_NAN),
        HALF_SIGNALING_NAN,
    );
}

#[test]
fn za_numeric_helpers_preserve_raw_controls_status_and_unrelated_state() {
    use stela_compiler::aarch64::floating::features::NumericalFeatures;
    const BFLOAT_SIGNALING_NAN: u16 = 0x7f81;
    const BFLOAT_DOT_WORD: u32 = 0xc150_1018;
    const NEGATIVE_DEFAULT_NAN: u32 = 0xffc0_0000;
    const STICKY_STATUS: u32 = 0x0800_009f;
    let (mut state, mut scalable) = outer_test_state();
    let source = BFLOAT_SIGNALING_NAN
        .to_le_bytes()
        .repeat(OUTER_TEST_SVL_BYTES / HALF_BYTES);
    scalable.write_z(&mut state, 0, &source).unwrap();
    state.fpcr = floating::FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK | FPCR_EBF;
    state.fpsr = STICKY_STATUS;
    let original = state.clone();
    let controls = NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
    complete(
        &mut state,
        &mut scalable,
        &fp_matrix::decode(BFLOAT_DOT_WORD).unwrap(),
        controls,
    )
    .unwrap();
    assert_eq!(state, original);
    let mut row = [0; OUTER_TEST_SVL_BYTES];
    for physical in [0, OUTER_TEST_SVL_BYTES / 2] {
        scalable
            .read_za(physical * OUTER_TEST_SVL_BYTES, &mut row)
            .unwrap();
        for lane in row.as_chunks::<SINGLE_BYTES>().0 {
            assert_eq!(u32::from_le_bytes(*lane), NEGATIVE_DEFAULT_NAN);
        }
    }
}

#[test]
fn failure_after_first_row_evaluation_does_not_commit_any_za_bytes() {
    use stela_compiler::aarch64::floating::features::NumericalFeatures;
    const SINGLE_GROUP_FMA_WORD: u32 = 0xc1a1_1800;
    let (mut state, mut scalable) = outer_test_state();
    let mut initial_za = [0x5a; OUTER_TEST_SVL_BYTES * OUTER_TEST_SVL_BYTES];
    initial_za[..SINGLE_BYTES].copy_from_slice(&OUTER_SINGLE_MINUS_ONE.to_le_bytes());
    scalable.write_za(0, &initial_za).unwrap();
    let ones = 0x3f80_0000_u32
        .to_le_bytes()
        .repeat(OUTER_TEST_SVL_BYTES / SINGLE_BYTES);
    for register in [28, 31] {
        scalable.write_z(&mut state, register, &ones).unwrap();
    }
    let original = state.clone();
    let Operand::Vector(mut operand) = fp_matrix::decode(SINGLE_GROUP_FMA_WORD).unwrap() else {
        panic!("vector group");
    };
    // A malformed descriptor makes its second source read fail after the
    // first staged row has been evaluated. No staged prefix may escape.
    operand.sources = Sources::Group {
        left: 31,
        right: 28,
    };
    let controls = NumericalControls::new(0, true, NumericalFeatures::default());
    assert!(
        complete(
            &mut state,
            &mut scalable,
            &Operand::Vector(operand),
            controls
        )
        .is_err()
    );
    let mut actual = [0; OUTER_TEST_SVL_BYTES * OUTER_TEST_SVL_BYTES];
    scalable.read_za(0, &mut actual).unwrap();
    assert_eq!(actual, initial_za);
    assert_eq!(state, original);
    // The failed evaluation returns its scratch space; a later instruction
    // initializes those bytes from ZA and completes.
    operand.sources = Sources::Group {
        left: 28,
        right: 28,
    };
    for expected in [0_u32, 0x3f80_0000] {
        complete(
            &mut state,
            &mut scalable,
            &Operand::Vector(operand),
            controls,
        )
        .unwrap();
        let mut lane = [0; SINGLE_BYTES];
        scalable.read_za(0, &mut lane).unwrap();
        assert_eq!(u32::from_le_bytes(lane), expected);
        assert_eq!(state, original);
    }
}

#[test]
fn immutable_ebf_availability_selects_distinct_dot_rounding_without_status() {
    use stela_compiler::aarch64::floating::features::NumericalFeatures;
    const INDEXED_BFLOAT_DOT_WORD: u32 = 0xc152_1018;
    const BFLOAT_MIDPOINT_PAIR: u32 = 0x3980_3f80;
    const CLASSIC_CANCELLATION_RESULT: u32 = 0x3400_0000;
    for (available, expected) in [(false, CLASSIC_CANCELLATION_RESULT), (true, 0)] {
        let (mut state, mut scalable) = outer_test_state();
        let source = BFLOAT_MIDPOINT_PAIR
            .to_le_bytes()
            .repeat(OUTER_TEST_SVL_BYTES / SINGLE_BYTES);
        for register in [0, 1, 2] {
            scalable.write_z(&mut state, register, &source).unwrap();
        }
        let initial = OUTER_SINGLE_MINUS_ONE
            .to_le_bytes()
            .repeat(OUTER_TEST_SVL_BYTES * OUTER_TEST_SVL_BYTES / SINGLE_BYTES);
        scalable.write_za(0, &initial).unwrap();
        state.fpcr = FPCR_EBF | FPCR_EXCEPTION_ENABLE_MASK;
        state.fpsr = 0x0800_009f;
        let original = state.clone();
        let controls = NumericalControls::new(
            state.fpcr,
            true,
            NumericalFeatures::new(true, available, false),
        );
        complete(
            &mut state,
            &mut scalable,
            &fp_matrix::decode(INDEXED_BFLOAT_DOT_WORD).unwrap(),
            controls,
        )
        .unwrap();
        assert_eq!(state, original);
        let mut row = [0; OUTER_TEST_SVL_BYTES];
        for physical in [0, OUTER_TEST_SVL_BYTES / 2] {
            scalable
                .read_za(physical * OUTER_TEST_SVL_BYTES, &mut row)
                .unwrap();
            for lane in row.as_chunks::<SINGLE_BYTES>().0 {
                assert_eq!(u32::from_le_bytes(*lane), expected);
            }
        }
    }
}
