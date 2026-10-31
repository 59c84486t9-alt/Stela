use super::*;
use stela_compiler::aarch64::{
    floating::{
        FPCR_AH, FPCR_EBF, FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, INVALID,
        features::NumericalFeatures,
    },
    scalable::{ScalableMode, VectorLength},
};

const DESTINATION: u8 = 31;
const LEFT: u8 = 1;
const RIGHT: u8 = 2;
const BFLOAT_ONE: u16 = 0x3f80;
const BFLOAT_TWO: u16 = 0x4000;
const BFLOAT_SIGNALING_NAN: u16 = 0x7f81;
const SINGLE_ONE: u32 = 0x3f80_0000;
const SINGLE_TWO: u32 = 0x4000_0000;

fn complete_profile(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    full_a64: bool,
) -> Result<(), CompletionError> {
    let controls = NumericalControls::new(
        state.fpcr,
        scalable.mode().streaming(),
        NumericalFeatures::new(full_a64, false, false),
    );
    super::complete(state, scalable, operand, controls)
}

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
    width: usize,
) {
    let mut bytes = vec![0; scalable.vector_length().bytes()];
    for (source, destination) in values.iter().zip(bytes.chunks_exact_mut(width)) {
        destination.copy_from_slice(&source.to_le_bytes()[..width]);
    }
    scalable.write_z(state, register, &bytes).unwrap();
}

fn get(scalable: &ScalableState, state: &GuestState, register: u8) -> Vec<u8> {
    let mut bytes = vec![0; scalable.vector_length().bytes()];
    scalable.read_z(state, register, &mut bytes).unwrap();
    bytes
}

fn base(kind: Kind) -> Operand {
    Operand {
        kind,
        destination: DESTINATION,
        left: LEFT,
        right: RightOperand::Vector(RIGHT),
        predicate: None,
    }
}

fn put_predicate(scalable: &mut ScalableState, offsets: &[usize]) {
    let mut bytes = vec![0; scalable.vector_length().predicate_bytes()];
    for offset in offsets {
        bytes[offset / BITS_PER_BYTE] |= 1 << (offset % BITS_PER_BYTE);
    }
    scalable.write_predicate(0, &bytes).unwrap();
}

#[test]
fn indexed_destination_alias_snapshots_each_original_segment() {
    for length in [16, 32, MAX_VECTOR_BYTES] {
        let (mut state, mut scalable) = setup(length);
        let lanes = length / BFLOAT_BYTES;
        put(
            &mut scalable,
            &mut state,
            LEFT,
            &vec![u64::from(BFLOAT_ONE); lanes],
            BFLOAT_BYTES,
        );
        let mut values = vec![0; lanes];
        let per_segment = VECTOR_CHUNK_BYTES / BFLOAT_BYTES;
        for (segment, output) in values.chunks_exact_mut(per_segment).enumerate() {
            output[per_segment - 1] = u64::from(BFLOAT_ONE) + (segment as u64 + 1) * 128;
        }
        put(
            &mut scalable,
            &mut state,
            DESTINATION,
            &values,
            BFLOAT_BYTES,
        );
        let before = state.clone();
        let mut operand = base(Kind::Binary(BinaryOperation::Multiply));
        operand.right = RightOperand::Indexed {
            register: DESTINATION,
            index: (per_segment - 1) as u8,
        };
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        let expected = values
            .chunks_exact(per_segment)
            .flat_map(|segment| vec![(segment[per_segment - 1] as u16).to_le_bytes(); per_segment])
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(get(&scalable, &state, DESTINATION), expected);
        let mut expected_state = before;
        expected_state.v[usize::from(DESTINATION)] = state.v[usize::from(DESTINATION)];
        assert_eq!(state, expected_state);
    }
}

#[test]
fn inactive_lanes_skip_numeric_controls_and_status() {
    let (mut state, mut scalable) = setup(64);
    let lanes = scalable.vector_length().bytes() / BFLOAT_BYTES;
    for register in [DESTINATION, LEFT, RIGHT] {
        put(
            &mut scalable,
            &mut state,
            register,
            &vec![u64::from(BFLOAT_SIGNALING_NAN); lanes],
            BFLOAT_BYTES,
        );
    }
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let before = state.clone();
    let mut operand = base(Kind::MultiplyAdd { subtract: false });
    operand.predicate = Some(0);
    let original = get(&scalable, &state, DESTINATION);
    complete_profile(&mut state, &mut scalable, &operand, true).unwrap();
    assert_eq!(state, before);
    assert_eq!(get(&scalable, &state, DESTINATION), original);
    put_predicate(&mut scalable, &[BFLOAT_BYTES]);
    assert!(matches!(
        complete_profile(&mut state, &mut scalable, &operand, true),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(state, before);
    assert_eq!(get(&scalable, &state, DESTINATION), original);
    complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
    let actual = get(&scalable, &state, DESTINATION);
    assert_eq!(&actual[..BFLOAT_BYTES], &original[..BFLOAT_BYTES]);
    assert_eq!(
        &actual[BFLOAT_BYTES..2 * BFLOAT_BYTES],
        &0x7fc1_u16.to_le_bytes()
    );
    assert_eq!(&actual[2 * BFLOAT_BYTES..], &original[2 * BFLOAT_BYTES..]);
    assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
    assert_eq!(state.fpsr, FPSR_QC | INVALID);
}

#[test]
fn widening_parity_reads_original_destructive_accumulator() {
    for part in [VectorPart::Bottom, VectorPart::Top] {
        let (mut state, mut scalable) = setup(32);
        put(
            &mut scalable,
            &mut state,
            DESTINATION,
            &[u64::from(SINGLE_ONE); 8],
            SINGLE_BYTES,
        );
        put(
            &mut scalable,
            &mut state,
            RIGHT,
            &[u64::from(BFLOAT_ONE); 16],
            BFLOAT_BYTES,
        );
        let mut operand = base(Kind::MultiplyLong {
            subtract: false,
            part,
        });
        operand.left = DESTINATION;
        complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
        let expected = if part == VectorPart::Bottom {
            SINGLE_ONE
        } else {
            SINGLE_TWO
        };
        assert_eq!(
            get(&scalable, &state, DESTINATION),
            expected.to_le_bytes().repeat(8)
        );
        assert_eq!(state.fpsr, FPSR_QC);
    }
}

#[test]
fn widening_ah_suppression_differs_from_nonwidening_arithmetic() {
    let (mut state, mut scalable) = setup(16);
    put(
        &mut scalable,
        &mut state,
        LEFT,
        &[u64::from(BFLOAT_SIGNALING_NAN); 8],
        BFLOAT_BYTES,
    );
    put(
        &mut scalable,
        &mut state,
        RIGHT,
        &[u64::from(BFLOAT_ONE); 8],
        BFLOAT_BYTES,
    );
    state.fpcr = FPCR_AH | FPCR_EXCEPTION_ENABLE_MASK;
    complete_profile(
        &mut state,
        &mut scalable,
        &base(Kind::MultiplyLong {
            subtract: true,
            part: VectorPart::Top,
        }),
        true,
    )
    .unwrap();
    assert_eq!(state.fpsr, FPSR_QC);
    assert_eq!(
        get(&scalable, &state, DESTINATION),
        0x7fc1_0000_u32.to_le_bytes().repeat(4)
    );
    let before = state.clone();
    assert!(matches!(
        complete_profile(
            &mut state,
            &mut scalable,
            &base(Kind::MultiplyAdd { subtract: true }),
            true
        ),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(state, before);
}

#[test]
fn classic_dot_ignores_raw_ebf_and_preserves_status_with_all_aliases() {
    let (mut state, mut scalable) = setup(32);
    put(
        &mut scalable,
        &mut state,
        DESTINATION,
        &[u64::from(SINGLE_ONE); 8],
        SINGLE_BYTES,
    );
    state.fpcr = FPCR_EBF | FPCR_EXCEPTION_ENABLE_MASK;
    let mut operand = base(Kind::Dot);
    operand.left = DESTINATION;
    operand.right = RightOperand::Indexed {
        register: DESTINATION,
        index: 3,
    };
    complete_profile(&mut state, &mut scalable, &operand, true).unwrap();
    assert_eq!(
        get(&scalable, &state, DESTINATION),
        SINGLE_TWO.to_le_bytes().repeat(8)
    );
    assert_eq!(state.fpsr, FPSR_QC);
    assert_eq!(state.fpcr, FPCR_EBF | FPCR_EXCEPTION_ENABLE_MASK);
}

#[test]
fn clamp_and_subtract_read_the_destination_first() {
    let (mut state, mut scalable) = setup(16);
    put(
        &mut scalable,
        &mut state,
        LEFT,
        &[u64::from(BFLOAT_ONE); 8],
        BFLOAT_BYTES,
    );
    put(
        &mut scalable,
        &mut state,
        RIGHT,
        &[u64::from(BFLOAT_TWO); 8],
        BFLOAT_BYTES,
    );
    complete_profile(&mut state, &mut scalable, &base(Kind::Clamp), false).unwrap();
    assert_eq!(
        get(&scalable, &state, DESTINATION),
        BFLOAT_ONE.to_le_bytes().repeat(8)
    );
    let mut operand = base(Kind::MultiplyAdd { subtract: true });
    operand.left = DESTINATION;
    complete_profile(&mut state, &mut scalable, &operand, false).unwrap();
    assert_eq!(
        get(&scalable, &state, DESTINATION),
        (BFLOAT_ONE | 0x8000).to_le_bytes().repeat(8)
    );
}

#[test]
fn invalid_shape_or_index_and_nonstreaming_state_fail_without_effects() {
    let (mut state, mut scalable) = setup(32);
    let before = state.clone();
    let original = get(&scalable, &state, DESTINATION);
    for mut operand in [base(Kind::Dot), base(Kind::Clamp)] {
        operand.predicate = Some(0);
        assert!(matches!(
            complete_profile(&mut state, &mut scalable, &operand, false),
            Err(CompletionError::State(_))
        ));
    }
    let mut operand = base(Kind::Dot);
    operand.right = RightOperand::Indexed {
        register: RIGHT,
        index: 4,
    };
    assert!(matches!(
        complete_profile(&mut state, &mut scalable, &operand, false),
        Err(CompletionError::State(_))
    ));
    assert_eq!(state, before);
    assert_eq!(get(&scalable, &state, DESTINATION), original);
    scalable
        .apply_mode(&mut state, ScalableMode::new(false, false))
        .unwrap();
    let before = state.clone();
    assert!(matches!(
        complete_profile(
            &mut state,
            &mut scalable,
            &base(Kind::Binary(BinaryOperation::Add)),
            false
        ),
        Err(CompletionError::State(_))
    ));
    assert_eq!(state, before);
}
#[test]
fn enhanced_dot_requires_both_feature_availability_and_control_selection() {
    const BFLOAT_MINIMUM: u64 = 0x0080;
    const BFLOAT_HALF: u64 = 0x3f00;
    const SINGLE_MINIMUM: u32 = 0x0080_0000;
    for available in [false, true] {
        for selected in [false, true] {
            let (mut state, mut scalable) = setup(32);
            put(
                &mut scalable,
                &mut state,
                LEFT,
                &[BFLOAT_MINIMUM; 16],
                BFLOAT_BYTES,
            );
            put(
                &mut scalable,
                &mut state,
                RIGHT,
                &[BFLOAT_HALF; 16],
                BFLOAT_BYTES,
            );
            state.fpcr = FPCR_EXCEPTION_ENABLE_MASK | if selected { FPCR_EBF } else { 0 };
            let controls = NumericalControls::new(
                state.fpcr,
                true,
                NumericalFeatures::new(true, available, false),
            );
            super::complete(&mut state, &mut scalable, &base(Kind::Dot), controls).unwrap();
            let expected = if available && selected {
                SINGLE_MINIMUM
            } else {
                0
            };
            assert_eq!(
                get(&scalable, &state, DESTINATION),
                expected.to_le_bytes().repeat(8)
            );
            assert_eq!(state.fpsr, FPSR_QC);
            assert_eq!(
                state.fpcr,
                FPCR_EXCEPTION_ENABLE_MASK | if selected { FPCR_EBF } else { 0 }
            );
        }
    }
}
