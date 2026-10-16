use super::*;
use stela_compiler::aarch64::{
    floating::{
        FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, Format, INPUT_DENORMAL, INVALID,
        features::NumericalFeatures,
    },
    scalable::{ScalableMode, VectorLength},
    sve::floating::comparison::Kind,
};

const FIRST: u8 = 1;
const SECOND: u8 = 31;
const GOVERNING: u8 = 7;
const PREDICATE_DESTINATION: u8 = 15;
const SINGLE_ONE: u64 = 0x3f80_0000;
const SINGLE_QUIET_NAN: u64 = 0x7fc0_0001;
const SINGLE_SIGNALING_NAN: u64 = 0x7f80_0001;

fn complete_with_profile(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    full_a64: bool,
) -> Result<(), CompletionError> {
    let controls = NumericalControls::new(
        state.fpcr,
        true,
        NumericalFeatures::new(full_a64, false, false),
    );
    complete(state, scalable, operand, controls)
}

fn setup(length: usize) -> (GuestState, ScalableState) {
    let mut state = GuestState::default();
    let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    state.nzcv = 0xa000_0000;
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    state.fpsr = FPSR_QC;
    for register in 0..32 {
        let bytes: Vec<_> = (0..length)
            .map(|index| (index as u8).wrapping_mul(19).wrapping_add(register))
            .collect();
        scalable.write_z(&mut state, register, &bytes).unwrap();
    }
    for register in 0..16 {
        scalable
            .write_predicate(register, &vec![0xff; length / BITS_PER_BYTE])
            .unwrap();
    }
    scalable
        .write_ffr(&vec![0xa5; length / BITS_PER_BYTE])
        .unwrap();
    scalable.write_za(0, &vec![0x3c; length * length]).unwrap();
    scalable.write_zt0(0, &[0x69; 64]).unwrap();
    (state, scalable)
}

fn banks(state: &GuestState, scalable: &ScalableState) -> Vec<u8> {
    let length = scalable.vector_length();
    let mut result = Vec::new();
    for register in 0..32 {
        let mut vector = vec![0; length.bytes()];
        scalable.read_z(state, register, &mut vector).unwrap();
        result.extend(vector);
    }
    for register in 0..16 {
        let mut predicate = vec![0; length.predicate_bytes()];
        scalable.read_predicate(register, &mut predicate).unwrap();
        result.extend(predicate);
    }
    let mut ffr = vec![0; length.predicate_bytes()];
    scalable.read_ffr(&mut ffr).unwrap();
    result.extend(ffr);
    let mut za = vec![0; length.bytes() * length.bytes()];
    scalable.read_za(0, &mut za).unwrap();
    result.extend(za);
    let mut zt0 = [0; 64];
    scalable.read_zt0(0, &mut zt0).unwrap();
    result.extend(zt0);
    result
}

fn fill(state: &mut GuestState, scalable: &mut ScalableState, register: u8, lanes: &[u64]) {
    let length = scalable.vector_length().bytes();
    let bytes: Vec<_> = (0..length / size_of::<u32>())
        .flat_map(|index| (lanes[index % lanes.len()] as u32).to_le_bytes())
        .collect();
    scalable.write_z(state, register, &bytes).unwrap();
}

fn operand(kind: Kind, destination: u8) -> Operand {
    Operand {
        kind,
        format: Format::Single,
        destination,
        governing: GOVERNING,
        left: FIRST,
        right: Some(SECOND),
    }
}

#[test]
fn predicate_alias_and_nonleading_bits_preserve_all_other_banks() {
    for length in [16, 32, 64, 128, 256] {
        let (mut state, mut scalable) = setup(length);
        fill(
            &mut state,
            &mut scalable,
            FIRST,
            &[
                SINGLE_ONE,
                SINGLE_QUIET_NAN,
                SINGLE_ONE,
                SINGLE_SIGNALING_NAN,
            ],
        );
        fill(&mut state, &mut scalable, SECOND, &[SINGLE_ONE]);
        let mut mask = vec![0xaa; length / BITS_PER_BYTE];
        for offset in (0..length).step_by(size_of::<u32>() * 2) {
            mask[offset / BITS_PER_BYTE] |= 1 << (offset % BITS_PER_BYTE);
        }
        scalable.write_predicate(GOVERNING, &mask).unwrap();
        let mut expected = scalable.clone();
        let expected_state = state.clone();
        let mut output = vec![0; length / BITS_PER_BYTE];
        for offset in (0..length).step_by(size_of::<u32>() * 2) {
            output[offset / BITS_PER_BYTE] |= 1 << (offset % BITS_PER_BYTE);
        }
        expected.write_predicate(GOVERNING, &output).unwrap();
        complete_with_profile(
            &mut state,
            &mut scalable,
            &operand(Kind::Equal, GOVERNING),
            false,
        )
        .unwrap();
        assert_eq!(state, expected_state);
        assert_eq!(banks(&state, &scalable), banks(&expected_state, &expected));
    }
}

#[test]
fn active_status_is_sticky_and_raw_controls_remain() {
    let (mut state, mut scalable) = setup(32);
    state.fpcr |= FPCR_AH;
    fill(
        &mut state,
        &mut scalable,
        FIRST,
        &[SINGLE_QUIET_NAN, SINGLE_SIGNALING_NAN, 1, SINGLE_ONE],
    );
    fill(&mut state, &mut scalable, SECOND, &[SINGLE_ONE]);
    let original = state.clone();
    complete_with_profile(
        &mut state,
        &mut scalable,
        &operand(Kind::NotEqual, PREDICATE_DESTINATION),
        false,
    )
    .unwrap();
    assert_eq!(state.fpcr, original.fpcr);
    assert_eq!(state.nzcv, original.nzcv);
    assert_eq!(state.fpsr, FPSR_QC | INVALID | INPUT_DENORMAL);
    assert_eq!(state.v, original.v);
}

#[test]
fn fa64_enable_refuses_without_any_effect_but_inactive_does_not() {
    let (mut state, mut scalable) = setup(64);
    let original = state.clone();
    let original_banks = banks(&state, &scalable);
    assert!(matches!(
        complete_with_profile(
            &mut state,
            &mut scalable,
            &operand(Kind::Equal, GOVERNING),
            true
        ),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(state, original);
    assert_eq!(banks(&state, &scalable), original_banks);
    scalable.write_predicate(GOVERNING, &[0xaa; 8]).unwrap();
    complete_with_profile(
        &mut state,
        &mut scalable,
        &operand(Kind::Equal, GOVERNING),
        true,
    )
    .unwrap();
    let mut output = [0xff; 8];
    scalable.read_predicate(GOVERNING, &mut output).unwrap();
    assert_eq!(output, [0; 8]);
    assert_eq!(state, original);
}
