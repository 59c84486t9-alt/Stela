use super::*;
use stela_compiler::aarch64::{
    floating::{FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, INEXACT, features::NumericalFeatures},
    scalable::{ScalableMode, VectorLength},
    sve::dot::decode,
};

const DESTINATION: u8 = 0;
const LEFT: u8 = 1;
const RIGHT: u8 = 2;
const HALF_ONE: u16 = 0x3c00;
const SINGLE_NEGATIVE_ONE: u32 = 0xbf80_0000;

fn controls(fpcr: u32, full_a64: bool) -> NumericalControls {
    NumericalControls::new(fpcr, true, NumericalFeatures::new(full_a64, false, false))
}

fn setup(length: usize) -> (GuestState, ScalableState) {
    let mut state = GuestState::default();
    let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    state.fpsr = FPSR_QC;
    (state, scalable)
}

fn put_half(state: &mut GuestState, scalable: &mut ScalableState, register: u8, values: &[u16]) {
    let bytes: Vec<_> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    scalable.write_z(state, register, &bytes).unwrap();
}

fn read(state: &GuestState, scalable: &ScalableState, register: u8) -> Vec<u8> {
    let mut bytes = vec![0; scalable.vector_length().bytes()];
    scalable.read_z(state, register, &mut bytes).unwrap();
    bytes
}

#[test]
fn dot_keeps_both_roundings_and_sticky_status_at_every_length() {
    for length in [16, 32, 64, 128, 256] {
        let (mut state, mut scalable) = setup(length);
        let addends: Vec<_> =
            std::iter::repeat_n(SINGLE_NEGATIVE_ONE.to_le_bytes(), length / SINGLE_BYTES)
                .flatten()
                .collect();
        scalable.write_z(&mut state, DESTINATION, &addends).unwrap();
        put_half(
            &mut state,
            &mut scalable,
            LEFT,
            &(0..length / HALF_BYTES)
                .map(|lane| {
                    if lane % PAIR_ELEMENTS == 0 {
                        HALF_ONE
                    } else {
                        1
                    }
                })
                .collect::<Vec<_>>(),
        );
        put_half(
            &mut state,
            &mut scalable,
            RIGHT,
            &vec![HALF_ONE; length / HALF_BYTES],
        );
        let operand = decode(0x64208000 | (u32::from(LEFT) << 5) | (u32::from(RIGHT) << 16))
            .unwrap()
            .unwrap();
        state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
        complete(
            &mut state,
            &mut scalable,
            &operand,
            controls(FPCR_EXCEPTION_ENABLE_MASK, false),
        )
        .unwrap();
        assert_eq!(read(&state, &scalable, DESTINATION), vec![0; length]);
        assert_eq!(state.fpsr, FPSR_QC | INEXACT);
        assert_eq!(state.fpcr, FPCR_EXCEPTION_ENABLE_MASK);
    }
}

#[test]
fn indexed_widening_repeats_the_selected_source_in_each_segment() {
    let length = 32;
    let (mut state, mut scalable) = setup(length);
    put_half(
        &mut state,
        &mut scalable,
        LEFT,
        &vec![HALF_ONE; length / HALF_BYTES],
    );
    put_half(
        &mut state,
        &mut scalable,
        RIGHT,
        &[HALF_ONE, 0, 0, 0, 0, 0, 0, 0, 0x4000, 0, 0, 0, 0, 0, 0, 0],
    );
    let operand = decode(0x64a04000 | (u32::from(LEFT) << 5) | (u32::from(RIGHT) << 16))
        .unwrap()
        .unwrap();
    complete(&mut state, &mut scalable, &operand, controls(0, false)).unwrap();
    let result = read(&state, &scalable, DESTINATION);
    assert_eq!(single(&result, 0), 0x3f80_0000);
    assert_eq!(single(&result, VECTOR_CHUNK_BYTES), 0x4000_0000);
}

#[test]
fn retained_full_a64_enables_refuse_before_any_destination_or_status_commit() {
    let (mut state, mut scalable) = setup(32);
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    let original = state.clone();
    let before = read(&state, &scalable, DESTINATION);
    let operand = decode(0x64208000).unwrap().unwrap();
    assert!(matches!(
        complete(
            &mut state,
            &mut scalable,
            &operand,
            controls(FPCR_EXCEPTION_ENABLE_MASK, true)
        ),
        Err(CompletionError::UnsupportedControl(_))
    ));
    assert_eq!(state, original);
    assert_eq!(read(&state, &scalable, DESTINATION), before);
}
