use super::*;
use stela_compiler::aarch64::{
    floating::{FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, INVALID},
    scalable::{ScalableMode, VectorLength},
};

fn complete_profile(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    full_a64: bool,
) -> Result<(), CompletionError> {
    use stela_compiler::aarch64::floating::features::NumericalFeatures;
    let controls = NumericalControls::new(
        state.fpcr,
        true,
        NumericalFeatures::new(full_a64, false, false),
    );
    super::complete(state, scalable, operand, controls)
}

const FIRST_SOURCE: u8 = 1;
const SECOND_SOURCE: u8 = 2;
const LAST_REGISTER: u8 = 31;
const SINGLE_ONE: u64 = 0x3f80_0000;
const SINGLE_TWO: u64 = 0x4000_0000;
const SINGLE_THREE: u64 = 0x4040_0000;
const SINGLE_SIGNALING_NAN: u64 = 0x7f80_0001;
const SINGLE_QUIET_NAN: u64 = 0x7fc0_0001;

fn setup(length: usize) -> (GuestState, ScalableState) {
    let mut state = GuestState {
        x: std::array::from_fn(|index| 0x1234_0000_0000_0000 | index as u64),
        nzcv: 0xa000_0000,
        sp: 0x1111_2222_3333_4444,
        exclusive_bytes: 0xaaaa_5555,
        exclusive_address: 0,
        exclusive_value: 0,
        daif: 0,
        pending: 0,
        ..GuestState::default()
    };
    let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    state.fpsr = FPSR_QC;
    (state, scalable)
}

fn put(
    scalable: &mut ScalableState,
    state: &mut GuestState,
    register: u8,
    values: &[u64],
    format: Format,
) {
    let element_bytes = format.bits() as usize / BITS_PER_BYTE;
    let mut bytes = vec![0; scalable.vector_length().bytes()];
    for (lane, value) in values.iter().enumerate() {
        write_lane(&mut bytes, lane, element_bytes, *value);
    }
    scalable.write_z(state, register, &bytes).unwrap();
}

fn get(scalable: &ScalableState, state: &GuestState, register: u8, format: Format) -> Vec<u64> {
    let element_bytes = format.bits() as usize / BITS_PER_BYTE;
    let mut bytes = vec![0; scalable.vector_length().bytes()];
    scalable.read_z(state, register, &mut bytes).unwrap();
    bytes
        .chunks_exact(element_bytes)
        .map(|source| {
            let mut bits = [0; size_of::<u64>()];
            bits[..element_bytes].copy_from_slice(source);
            u64::from_le_bytes(bits)
        })
        .collect()
}

fn binary(destination: u8, predicate: Option<u8>) -> Operand {
    Operand {
        kind: Kind::Binary(BinaryOperation::Add),
        format: Format::Single,
        destination,
        predicate,
        inputs: Inputs::Binary {
            left: Source::Vector(FIRST_SOURCE),
            right: Source::Vector(SECOND_SOURCE),
        },
        shape: ResultShape::Vector,
    }
}

fn set_predicate(scalable: &mut ScalableState, lanes: &[usize], format: Format) {
    let element_bytes = format.bits() as usize / BITS_PER_BYTE;
    let mut predicate = vec![0; scalable.vector_length().predicate_bytes()];
    for lane in lanes {
        let bit = lane * element_bytes;
        predicate[bit / BITS_PER_BYTE] |= 1 << (bit % BITS_PER_BYTE);
    }
    scalable.write_predicate(0, &predicate).unwrap();
}

#[test]
fn streaming_enables_accumulate_but_full_a64_refuses_before_effects() {
    let (mut state, mut scalable) = setup(32);
    put(
        &mut scalable,
        &mut state,
        FIRST_SOURCE,
        &[0; 8],
        Format::Single,
    );
    put(
        &mut scalable,
        &mut state,
        SECOND_SOURCE,
        &[0; 8],
        Format::Single,
    );
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let mut operand = binary(LAST_REGISTER, None);
    operand.kind = Kind::Binary(BinaryOperation::Divide);
    complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
    assert_eq!(
        get(&scalable, &state, LAST_REGISTER, Format::Single),
        vec![SINGLE_INFINITY | SINGLE_QUIET_BIT; 8]
    );
    assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
    assert_eq!(state.fpsr, FPSR_QC | INVALID);
    let before = state.clone();
    let upper = get(&scalable, &state, LAST_REGISTER, Format::Single);
    assert!(matches!(
        complete_profile(&mut state, &mut scalable, &operand, true),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(state, before);
    assert_eq!(get(&scalable, &state, LAST_REGISTER, Format::Single), upper);
}

#[test]
fn inactive_numeric_lanes_never_refuse_controls_or_change_status() {
    let (mut state, mut scalable) = setup(64);
    put(
        &mut scalable,
        &mut state,
        LAST_REGISTER,
        &[SINGLE_SIGNALING_NAN; 16],
        Format::Single,
    );
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let before = state.clone();
    complete_profile(
        &mut state,
        &mut scalable,
        &binary(LAST_REGISTER, Some(0)),
        true,
    )
    .unwrap();
    assert_eq!(state, before);
    assert_eq!(
        get(&scalable, &state, LAST_REGISTER, Format::Single),
        vec![SINGLE_SIGNALING_NAN; 16]
    );
}

#[test]
fn indexed_destination_alias_uses_original_segment_sources() {
    let (mut state, mut scalable) = setup(32);
    put(
        &mut scalable,
        &mut state,
        FIRST_SOURCE,
        &[SINGLE_ONE; 8],
        Format::Single,
    );
    put(
        &mut scalable,
        &mut state,
        LAST_REGISTER,
        &[0, SINGLE_TWO, 0, 0, 0, SINGLE_THREE, 0, 0],
        Format::Single,
    );
    let operand = Operand {
        kind: Kind::Binary(BinaryOperation::Multiply),
        format: Format::Single,
        destination: LAST_REGISTER,
        predicate: None,
        inputs: Inputs::Binary {
            left: Source::Vector(FIRST_SOURCE),
            right: Source::Indexed {
                register: LAST_REGISTER,
                index: 1,
            },
        },
        shape: ResultShape::Vector,
    };
    complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
    assert_eq!(
        get(&scalable, &state, LAST_REGISTER, Format::Single),
        vec![
            SINGLE_TWO,
            SINGLE_TWO,
            SINGLE_TWO,
            SINGLE_TWO,
            SINGLE_THREE,
            SINGLE_THREE,
            SINGLE_THREE,
            SINGLE_THREE
        ]
    );
}

#[test]
fn pairwise_predicates_select_output_not_input_lanes() {
    let (mut state, mut scalable) = setup(16);
    put(
        &mut scalable,
        &mut state,
        LAST_REGISTER,
        &[SINGLE_ONE; 4],
        Format::Single,
    );
    put(
        &mut scalable,
        &mut state,
        SECOND_SOURCE,
        &[SINGLE_SIGNALING_NAN, SINGLE_ONE, SINGLE_ONE, SINGLE_ONE],
        Format::Single,
    );
    set_predicate(&mut scalable, &[1], Format::Single);
    let mut operand = binary(LAST_REGISTER, Some(0));
    operand.inputs = Inputs::Pairwise {
        left: LAST_REGISTER,
        right: SECOND_SOURCE,
    };
    complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
    assert_eq!(
        get(&scalable, &state, LAST_REGISTER, Format::Single),
        vec![SINGLE_ONE, SINGLE_QUIET_NAN, SINGLE_ONE, SINGLE_ONE]
    );
    assert_eq!(state.fpsr, FPSR_QC | INVALID);
}

#[test]
fn quad_base_preserves_raw_nan_then_v_write_clears_upper_z() {
    let (mut state, mut scalable) = setup(16);
    put(
        &mut scalable,
        &mut state,
        FIRST_SOURCE,
        &[SINGLE_SIGNALING_NAN; 4],
        Format::Single,
    );
    set_predicate(&mut scalable, &[0, 1, 2, 3], Format::Single);
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let operand = Operand {
        kind: Kind::Binary(BinaryOperation::Add),
        format: Format::Single,
        destination: LAST_REGISTER,
        predicate: Some(0),
        inputs: Inputs::Reduction {
            source: FIRST_SOURCE,
        },
        shape: ResultShape::QuadReduction,
    };
    complete_profile(&mut state, &mut scalable, &operand, true).unwrap();
    assert_eq!(
        get(&scalable, &state, LAST_REGISTER, Format::Single),
        vec![SINGLE_SIGNALING_NAN; 4]
    );
    assert_eq!(state.fpsr, FPSR_QC);
    let (mut state, mut scalable) = setup(32);
    put(
        &mut scalable,
        &mut state,
        FIRST_SOURCE,
        &[
            SINGLE_ONE, SINGLE_ONE, SINGLE_ONE, SINGLE_ONE, SINGLE_TWO, SINGLE_TWO, SINGLE_TWO,
            SINGLE_TWO,
        ],
        Format::Single,
    );
    set_predicate(&mut scalable, &(0..8).collect::<Vec<_>>(), Format::Single);
    complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
    assert_eq!(
        get(&scalable, &state, LAST_REGISTER, Format::Single),
        vec![
            SINGLE_THREE,
            SINGLE_THREE,
            SINGLE_THREE,
            SINGLE_THREE,
            0,
            0,
            0,
            0
        ]
    );
}

#[test]
fn inactive_complex_component_cannot_raise_invalid() {
    let (mut state, mut scalable) = setup(16);
    put(
        &mut scalable,
        &mut state,
        LAST_REGISTER,
        &[SINGLE_ONE; 4],
        Format::Single,
    );
    put(
        &mut scalable,
        &mut state,
        FIRST_SOURCE,
        &[SINGLE_ONE; 4],
        Format::Single,
    );
    put(
        &mut scalable,
        &mut state,
        SECOND_SOURCE,
        &[
            SINGLE_SIGNALING_NAN,
            SINGLE_ONE,
            SINGLE_SIGNALING_NAN,
            SINGLE_ONE,
        ],
        Format::Single,
    );
    set_predicate(&mut scalable, &[1, 3], Format::Single);
    let operand = Operand {
        kind: Kind::ComplexMultiplyAdd(Rotation::Degrees0),
        format: Format::Single,
        destination: LAST_REGISTER,
        predicate: Some(0),
        inputs: Inputs::Fused {
            addend: LAST_REGISTER,
            left: FIRST_SOURCE,
            right: Source::Vector(SECOND_SOURCE),
        },
        shape: ResultShape::Vector,
    };
    complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
    assert_eq!(
        get(&scalable, &state, LAST_REGISTER, Format::Single),
        vec![SINGLE_ONE, SINGLE_TWO, SINGLE_ONE, SINGLE_TWO]
    );
    assert_eq!(state.fpsr, FPSR_QC);
}

#[test]
fn reciprocal_precision_requires_the_bound_feature_single_width_and_ah() {
    use stela_compiler::aarch64::{
        floating::features::NumericalFeatures, simd::estimate::Kind as EstimateKind,
    };
    const INPUT: u64 = 0x3f81_2345;
    for (kind, standard, enhanced) in [
        (EstimateKind::Reciprocal, 0x3f7d_8000, 0x3f7d_b800),
        (EstimateKind::ReciprocalSquareRoot, 0x3f7e_8000, 0x3f7e_d000),
    ] {
        for ah in [0, FPCR_AH] {
            for rpres in [false, true] {
                let (mut state, mut scalable) = setup(16);
                state.fpcr = ah | FPCR_EXCEPTION_ENABLE_MASK;
                put(
                    &mut scalable,
                    &mut state,
                    FIRST_SOURCE,
                    &[INPUT; 4],
                    Format::Single,
                );
                let operand = Operand {
                    kind: Kind::Estimate(kind),
                    format: Format::Single,
                    destination: LAST_REGISTER,
                    predicate: None,
                    inputs: Inputs::Unary {
                        source: FIRST_SOURCE,
                    },
                    shape: ResultShape::Vector,
                };
                let controls = NumericalControls::new(
                    state.fpcr,
                    true,
                    NumericalFeatures::new(false, false, rpres),
                );
                super::complete(&mut state, &mut scalable, &operand, controls).unwrap();
                let expected = if rpres && ah != 0 { enhanced } else { standard };
                assert_eq!(
                    get(&scalable, &state, LAST_REGISTER, Format::Single),
                    vec![expected; 4]
                );
                assert_eq!(state.fpcr, ah | FPCR_EXCEPTION_ENABLE_MASK);
                assert_eq!(state.fpsr, FPSR_QC);
            }
        }
        let (mut state, mut scalable) = setup(16);
        state.fpcr = FPCR_AH;
        const HALF_ONE: u64 = 0x3c00;
        put(
            &mut scalable,
            &mut state,
            FIRST_SOURCE,
            &[HALF_ONE; 8],
            Format::Half,
        );
        let operand = Operand {
            kind: Kind::Estimate(kind),
            format: Format::Half,
            destination: LAST_REGISTER,
            predicate: None,
            inputs: Inputs::Unary {
                source: FIRST_SOURCE,
            },
            shape: ResultShape::Vector,
        };
        let controls =
            NumericalControls::new(state.fpcr, true, NumericalFeatures::new(false, false, true));
        super::complete(&mut state, &mut scalable, &operand, controls).unwrap();
        let expected =
            floating::estimate::evaluate(kind, Format::Half, state.fpcr, HALF_ONE).unwrap();
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Half),
            vec![expected.bits; 8]
        );
    }
}

#[test]
fn empty_number_reductions_return_default_nan_identity() {
    for fpcr in [0, FPCR_AH] {
        let (mut state, mut scalable) = setup(32);
        state.fpcr = fpcr;
        let operand = Operand {
            kind: Kind::MinMax(MinMaxOperation::MinimumNumber),
            format: Format::Single,
            destination: LAST_REGISTER,
            predicate: Some(0),
            inputs: Inputs::Reduction {
                source: FIRST_SOURCE,
            },
            shape: ResultShape::QuadReduction,
        };
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        let nan = SINGLE_INFINITY
            | SINGLE_QUIET_BIT
            | if fpcr == 0 {
                0
            } else {
                1 << (Format::Single.bits() - 1)
            };
        assert_eq!(
            get(&scalable, &state, LAST_REGISTER, Format::Single),
            vec![nan, nan, nan, nan, 0, 0, 0, 0]
        );
        assert_eq!(state.fpsr, FPSR_QC);
    }
}
