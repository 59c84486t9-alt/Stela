use super::*;
use stela_compiler::aarch64::{
    floating::{
        FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, INVALID, OVERFLOW, features::NumericalFeatures,
    },
    scalable::{ScalableMode, VectorLength},
    sme::fp_vector,
};

const TEST_SVL_BYTES: usize = 16;
const SINGLE_ONE: u32 = 0x3f80_0000;
const SINGLE_ONE_AND_HALF: u32 = 0x3fc0_0000;
const SINGLE_TWO: u32 = 0x4000_0000;
const SIGNALING_FIVE: u32 = 0x7f80_0005;
const QUIET_FIVE: u32 = 0x7fc0_0005;
const QUIET_SEVEN: u32 = 0x7fc0_0007;
const SIGNALING_NINE: u32 = 0x7f80_0009;
const QUIET_NINE: u32 = 0x7fc0_0009;
const FMAX_SINGLE_QUARTET: u32 = 0xc1a0_a900;
const FRINTN_PAIR: u32 = 0xc1a8_e000;
const FCVTN_PAIR: u32 = 0xc120_e020;
const FCVT_PAIR: u32 = 0xc120_e000;

fn setup() -> (GuestState, ScalableState) {
    let mut state = GuestState::default();
    let mut scalable = ScalableState::new(VectorLength::from_bytes(TEST_SVL_BYTES).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    state.fpsr = FPSR_QC | OVERFLOW;
    (state, scalable)
}

fn write_single(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    register: u8,
    words: &[u32; 4],
) {
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    scalable.write_z(state, register, &bytes).unwrap();
}

fn read_vector(state: &GuestState, scalable: &ScalableState, register: u8) -> [u8; TEST_SVL_BYTES] {
    let mut bytes = [0; TEST_SVL_BYTES];
    scalable.read_z(state, register, &mut bytes).unwrap();
    bytes
}

#[test]
fn broadcast_alias_keeps_original_signaling_nan_priority_for_entire_group() {
    let (mut state, mut scalable) = setup();
    for (register, value) in [SIGNALING_FIVE, QUIET_SEVEN, SINGLE_ONE, SIGNALING_NINE]
        .into_iter()
        .enumerate()
    {
        write_single(&mut state, &mut scalable, register as u8, &[value; 4]);
    }
    let operand = fp_vector::decode(FMAX_SINGLE_QUARTET).unwrap();
    complete(
        &mut state,
        &mut scalable,
        &operand,
        NumericalControls::new(0, true, NumericalFeatures::default()),
    )
    .unwrap();
    for (register, expected) in [QUIET_FIVE, QUIET_FIVE, QUIET_FIVE, QUIET_NINE]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            read_vector(&state, &scalable, register as u8).as_slice(),
            expected.to_le_bytes().repeat(4)
        );
    }
    assert_eq!(state.fpsr, FPSR_QC | OVERFLOW | INVALID);
}

#[test]
fn narrowing_alias_uses_distinct_consecutive_and_interleaved_placements() {
    const FIRST: [u32; 4] = [0x3f80_0000, 0x4000_0000, 0x4040_0000, 0x4080_0000];
    const SECOND: [u32; 4] = [0x40a0_0000, 0x40c0_0000, 0x40e0_0000, 0x4100_0000];
    const CONSECUTIVE: [u16; 8] = [
        0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600, 0x4700, 0x4800,
    ];
    const INTERLEAVED: [u16; 8] = [
        0x3c00, 0x4500, 0x4000, 0x4600, 0x4200, 0x4700, 0x4400, 0x4800,
    ];
    for (word, expected) in [(FCVT_PAIR, CONSECUTIVE), (FCVTN_PAIR, INTERLEAVED)] {
        let (mut state, mut scalable) = setup();
        write_single(&mut state, &mut scalable, 0, &FIRST);
        write_single(&mut state, &mut scalable, 1, &SECOND);
        let before_source = read_vector(&state, &scalable, 0);
        let operand = fp_vector::decode(word | 1).unwrap();
        complete(
            &mut state,
            &mut scalable,
            &operand,
            NumericalControls::new(0, true, NumericalFeatures::default()),
        )
        .unwrap();
        let expected: Vec<u8> = expected
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        assert_eq!(read_vector(&state, &scalable, 1).as_slice(), expected);
        assert_eq!(read_vector(&state, &scalable, 0), before_source);
        assert_eq!(state.fpsr, FPSR_QC | OVERFLOW);
    }
}

#[test]
fn streaming_enable_mask_preserves_storage_and_full_a64_refusal_preserves_outputs() {
    let (mut state, mut scalable) = setup();
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    write_single(&mut state, &mut scalable, 0, &[SINGLE_ONE_AND_HALF; 4]);
    write_single(&mut state, &mut scalable, 1, &[SINGLE_ONE_AND_HALF; 4]);
    let operand = fp_vector::decode(FRINTN_PAIR).unwrap();
    let before = state.clone();
    assert!(
        complete(
            &mut state,
            &mut scalable,
            &operand,
            NumericalControls::new(
                FPCR_EXCEPTION_ENABLE_MASK,
                true,
                NumericalFeatures::new(true, false, false)
            )
        )
        .is_err()
    );
    assert_eq!(state, before);
    complete(
        &mut state,
        &mut scalable,
        &operand,
        NumericalControls::new(
            FPCR_EXCEPTION_ENABLE_MASK,
            true,
            NumericalFeatures::default(),
        ),
    )
    .unwrap();
    assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
    assert_eq!(state.fpsr, FPSR_QC | OVERFLOW);
    for register in 0..PAIR_COUNT {
        assert_eq!(
            read_vector(&state, &scalable, register).as_slice(),
            SINGLE_TWO.to_le_bytes().repeat(4)
        );
    }
}
