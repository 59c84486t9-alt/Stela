//! Transactional predicated absolute extrema; inactive lanes remain raw bits.

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;
use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::absolute_minmax,
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES},
        sve::floating::faminmax::Operand,
    },
};

const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    if !scalable.mode().streaming() {
        return Err(anyhow!("scalable absolute extrema require streaming state").into());
    }
    let length = scalable.vector_length();
    let vector_bytes = length.bytes();
    let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    let mut destination = [0; MAX_VECTOR_BYTES];
    let mut right = [0; MAX_VECTOR_BYTES];
    let mut governing = [0; MAX_PREDICATE_BYTES];
    scalable.read_z(state, operand.destination, &mut destination[..vector_bytes])?;
    scalable.read_predicate(
        operand.governing,
        &mut governing[..length.predicate_bytes()],
    )?;
    let active =
        |offset: usize| governing[offset / BITS_PER_BYTE] & (1 << (offset % BITS_PER_BYTE)) != 0;
    if !(0..vector_bytes).step_by(element_bytes).any(active) {
        return Ok(());
    }
    if operand.right == operand.destination {
        right[..vector_bytes].copy_from_slice(&destination[..vector_bytes]);
    } else {
        scalable.read_z(state, operand.right, &mut right[..vector_bytes])?;
    }
    let mut exceptions = 0;
    for offset in (0..vector_bytes).step_by(element_bytes) {
        if !active(offset) {
            continue;
        }
        let mut left_bits = [0; size_of::<u64>()];
        let mut right_bits = [0; size_of::<u64>()];
        left_bits[..element_bytes].copy_from_slice(&destination[offset..offset + element_bytes]);
        right_bits[..element_bytes].copy_from_slice(&right[offset..offset + element_bytes]);
        let outcome = absolute_minmax::evaluate(
            operand.format,
            operand.operation,
            controls.fpcr,
            u64::from_le_bytes(left_bits),
            u64::from_le_bytes(right_bits),
        )?;
        destination[offset..offset + element_bytes]
            .copy_from_slice(&outcome.bits.to_le_bytes()[..element_bytes]);
        exceptions |= outcome.exceptions;
    }
    scalable.write_z(state, operand.destination, &destination[..vector_bytes])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{
            FPCR_AH, FPCR_DN, FPCR_EXCEPTION_ENABLE_MASK, FPCR_FIZ, FPCR_FZ, FPCR_FZ16, FPSR_QC,
            Format, INVALID, absolute_minmax::AbsoluteMinMaxOperation, features::NumericalFeatures,
        },
        scalable::{ScalableMode, VectorLength},
    };

    fn setup(length: usize) -> (GuestState, ScalableState) {
        let mut state = GuestState {
            nzcv: 0xa000_0000,
            fpsr: FPSR_QC,
            fpcr: FPCR_AH | FPCR_FIZ | FPCR_FZ | FPCR_FZ16 | FPCR_EXCEPTION_ENABLE_MASK,
            ..GuestState::default()
        };
        let mut scalable = ScalableState::new(VectorLength::from_bytes(length).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(true, true))
            .unwrap();
        state.fpsr = FPSR_QC;
        for register in 0..32 {
            scalable
                .write_z(
                    &mut state,
                    register,
                    &(0..length)
                        .map(|i| (i as u8).wrapping_mul(19).wrapping_add(register))
                        .collect::<Vec<_>>(),
                )
                .unwrap();
        }
        for register in 0..16 {
            scalable
                .write_predicate(register, &vec![0xaa; length / 8])
                .unwrap();
        }
        scalable.write_ffr(&vec![0x96; length / 8]).unwrap();
        scalable.write_za(0, &vec![0x3c; length * length]).unwrap();
        scalable.write_zt0(0, &[0x69; 64]).unwrap();
        scalable.set_tpidr2_el0(0x1234_5678);
        scalable.set_fpmr(0x77);
        (state, scalable)
    }

    fn banks(state: &GuestState, scalable: &ScalableState) -> Vec<u8> {
        let length = scalable.vector_length();
        let mut bytes = Vec::new();
        for register in 0..32 {
            let mut value = vec![0; length.bytes()];
            scalable.read_z(state, register, &mut value).unwrap();
            bytes.extend(value);
        }
        for register in 0..16 {
            let mut value = vec![0; length.predicate_bytes()];
            scalable.read_predicate(register, &mut value).unwrap();
            bytes.extend(value);
        }
        let mut value = vec![0; length.predicate_bytes()];
        scalable.read_ffr(&mut value).unwrap();
        bytes.extend(value);
        let mut value = vec![0; length.bytes() * length.bytes()];
        scalable.read_za(0, &mut value).unwrap();
        bytes.extend(value);
        let mut value = [0; 64];
        scalable.read_zt0(0, &mut value).unwrap();
        bytes.extend(value);
        bytes.extend(scalable.tpidr2_el0().to_le_bytes());
        bytes.extend(scalable.fpmr().to_le_bytes());
        bytes
    }

    fn operand(format: Format, alias: bool, operation: AbsoluteMinMaxOperation) -> Operand {
        Operand {
            operation,
            format,
            destination: 31,
            governing: 7,
            right: if alias { 31 } else { 0 },
        }
    }

    #[test]
    fn complete_banks_aliases_inactive_poison_flush_controls_and_status() {
        for length in [16, 32, 64, 128, 256] {
            for format in [Format::Half, Format::Single, Format::Double] {
                let width = format.bits() as usize / 8;
                for alias in [false, true] {
                    for operation in [
                        AbsoluteMinMaxOperation::Minimum,
                        AbsoluteMinMaxOperation::Maximum,
                    ] {
                        let (mut state, mut scalable) = setup(length);
                        let negative_denormal = (1_u64 << (format.bits() - 1)) | 1;
                        let signaling_nan = match format {
                            Format::Half => 0xfc03,
                            Format::Single => 0xff80_0003,
                            Format::Double => 0xfff0_0000_0000_0003,
                        };
                        let mut input = Vec::new();
                        let mut right = Vec::new();
                        let mut output = Vec::new();
                        let mut governing = vec![0xaa; length / 8];
                        for index in 0..length / width {
                            let bits = if index % 2 == 0 {
                                negative_denormal
                            } else {
                                signaling_nan
                            };
                            input.extend(&bits.to_le_bytes()[..width]);
                            right.extend(&2_u64.to_le_bytes()[..width]);
                            let expected = if index % 2 != 0 {
                                bits
                            } else if alias || operation == AbsoluteMinMaxOperation::Minimum {
                                1
                            } else {
                                2
                            };
                            output.extend(&expected.to_le_bytes()[..width]);
                            if index % 2 == 0 {
                                let offset = index * width;
                                governing[offset / 8] |= 1 << (offset % 8);
                            }
                        }
                        scalable.write_z(&mut state, 31, &input).unwrap();
                        scalable.write_z(&mut state, 0, &right).unwrap();
                        scalable.write_predicate(7, &governing).unwrap();
                        let mut expected_state = state.clone();
                        let mut expected_scalable = scalable.clone();
                        expected_scalable
                            .write_z(&mut expected_state, 31, &output)
                            .unwrap();
                        let controls =
                            NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
                        complete(
                            &mut state,
                            &mut scalable,
                            &operand(format, alias, operation),
                            controls,
                        )
                        .unwrap();
                        assert_eq!(state, expected_state);
                        assert_eq!(
                            banks(&state, &scalable),
                            banks(&expected_state, &expected_scalable)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn active_nan_is_sticky_and_fa64_enabled_controls_roll_back() {
        let (mut state, mut scalable) = setup(64);
        let format = Format::Single;
        scalable
            .write_z(&mut state, 31, &0xff80_0123_u32.to_le_bytes().repeat(16))
            .unwrap();
        scalable.write_predicate(7, &[0xff; 8]).unwrap();
        let original = state.clone();
        let original_banks = banks(&state, &scalable);
        let controls =
            NumericalControls::new(state.fpcr, true, NumericalFeatures::new(true, false, false));
        assert!(matches!(
            complete(
                &mut state,
                &mut scalable,
                &operand(format, false, AbsoluteMinMaxOperation::Minimum),
                controls
            ),
            Err(CompletionError::UnsupportedControl(_))
        ));
        assert_eq!(state, original);
        assert_eq!(banks(&state, &scalable), original_banks);
        scalable.write_predicate(7, &[0xaa; 8]).unwrap();
        complete(
            &mut state,
            &mut scalable,
            &operand(format, false, AbsoluteMinMaxOperation::Maximum),
            controls,
        )
        .unwrap();
        assert_eq!(state, original);
        scalable.write_predicate(7, &[0xff; 8]).unwrap();
        state.fpcr |= FPCR_DN;
        let controls = NumericalControls::new(state.fpcr, true, NumericalFeatures::default());
        complete(
            &mut state,
            &mut scalable,
            &operand(format, false, AbsoluteMinMaxOperation::Minimum),
            controls,
        )
        .unwrap();
        let mut output = vec![0; 64];
        scalable.read_z(&state, 31, &mut output).unwrap();
        assert_eq!(output, 0x7fc0_0000_u32.to_le_bytes().repeat(16));
        assert_eq!(state.fpsr, FPSR_QC | INVALID);
        assert_eq!(state.fpcr, original.fpcr | FPCR_DN);
        assert_eq!(state.nzcv, original.nzcv);
    }
}
