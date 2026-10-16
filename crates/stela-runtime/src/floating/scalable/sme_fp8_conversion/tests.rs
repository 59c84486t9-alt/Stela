use super::*;
use stela_compiler::aarch64::{
    floating::{FPCR_EXCEPTION_ENABLE_MASK, FPSR_QC, features::NumericalFeatures},
    scalable::{ScalableMode, VectorLength},
    sme::fp8_conversion::{self, F1CVT_MZ2_Z8, F1CVTL_MZ2_Z8, FCVT_Z8_MZ4, FCVTN_Z8_MZ4},
};

fn setup(length: usize) -> (GuestState, ScalableState) {
    let mut state = GuestState::default();
    let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
    scalable
        .apply_mode(&mut state, ScalableMode::new(true, true))
        .unwrap();
    state.fpsr = FPSR_QC;
    (state, scalable)
}

fn read(state: &GuestState, scalable: &ScalableState, register: u8) -> Vec<u8> {
    let mut output = vec![0; scalable.vector_length().bytes()];
    scalable.read_z(state, register, &mut output).unwrap();
    output
}

fn controls(fpcr: u32, full_a64: bool) -> NumericalControls {
    NumericalControls::new(fpcr, true, NumericalFeatures::new(full_a64, false, false))
}

#[test]
fn widening_aliases_snapshot_inputs_for_both_group_orders_at_all_lengths() {
    for length in [16, 32, 64, 128, 256] {
        for word in [F1CVT_MZ2_Z8, F1CVTL_MZ2_Z8] {
            let (mut state, mut scalable) = setup(length);
            let input: Vec<u8> = (0..length).map(|lane| lane as u8).collect();
            scalable.write_z(&mut state, 31, &input).unwrap();
            let operand = fp8_conversion::decode(word | 31 << 5 | 30).unwrap();
            complete(&mut state, &mut scalable, &operand, controls(0, false)).unwrap();
            let results = [read(&state, &scalable, 30), read(&state, &scalable, 31)];
            let mut status = FPSR_QC;
            for (lane, value) in input.iter().enumerate() {
                let outcome = fp8::from_fp8(ConversionFormat::Half, false, 0, 0, *value).unwrap();
                let (register, index) = if word == F1CVTL_MZ2_Z8 {
                    (lane % 2, lane / 2)
                } else {
                    (lane / (length / 2), lane % (length / 2))
                };
                assert_eq!(
                    &results[register][index * 2..index * 2 + 2],
                    &(outcome.bits as u16).to_le_bytes()
                );
                status |= outcome.exceptions;
            }
            assert_eq!(state.fpsr, status);
        }
    }
}

#[test]
fn narrowing_quartet_alias_and_interleave_preserve_original_four_sources() {
    for word in [FCVT_Z8_MZ4, FCVTN_Z8_MZ4] {
        let (mut state, mut scalable) = setup(16);
        let inputs = [0x3f80_0000u32, 0x4000_0000, 0x4040_0000, 0x4080_0000];
        for (index, input) in inputs.iter().enumerate() {
            scalable
                .write_z(&mut state, 28 + index as u8, &input.to_le_bytes().repeat(4))
                .unwrap();
        }
        let operand = fp8_conversion::decode(word | 28 << 5 | 31).unwrap();
        complete(&mut state, &mut scalable, &operand, controls(0, false)).unwrap();
        let output = read(&state, &scalable, 31);
        for (register, input) in inputs.iter().enumerate() {
            let expected = fp8::to_fp8(ConversionFormat::Single, 0, 0, u64::from(*input)).unwrap();
            for lane in 0..4 {
                let index = if word == FCVTN_Z8_MZ4 {
                    lane * 4 + register
                } else {
                    register * 4 + lane
                };
                assert_eq!(output[index], expected.bits as u8);
            }
            if register < 3 {
                assert_eq!(
                    read(&state, &scalable, 28 + register as u8),
                    input.to_le_bytes().repeat(4)
                );
            }
        }
        assert_eq!(state.fpsr, FPSR_QC);
    }
}

#[test]
fn unsupported_controls_mode_and_forged_groups_have_no_effects() {
    let (mut state, mut scalable) = setup(16);
    state.fpcr = FPCR_EXCEPTION_ENABLE_MASK;
    scalable.set_fpmr(u64::MAX);
    let operand = fp8_conversion::decode(F1CVT_MZ2_Z8).unwrap();
    let before = state.clone();
    let z_before: Vec<_> = (0..32).map(|r| read(&state, &scalable, r)).collect();
    let unsupported = controls(state.fpcr, true);
    assert!(complete(&mut state, &mut scalable, &operand, unsupported).is_err());
    assert_eq!(state, before);
    assert_eq!(scalable.fpmr(), u64::MAX);
    assert_eq!(
        (0..32)
            .map(|r| read(&state, &scalable, r))
            .collect::<Vec<_>>(),
        z_before
    );
    let mut forged = operand;
    forged.destination.first = 31;
    assert!(complete(&mut state, &mut scalable, &forged, controls(0, false)).is_err());
    scalable
        .apply_mode(&mut state, ScalableMode::new(false, true))
        .unwrap();
    let before = state.clone();
    assert!(complete(&mut state, &mut scalable, &operand, controls(0, false)).is_err());
    assert_eq!(state, before);
}
