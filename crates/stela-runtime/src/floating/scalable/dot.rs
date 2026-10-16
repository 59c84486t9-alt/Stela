//! Whole-instruction streaming Half dot and widening numerical completion.
//! Read roles are snapshotted before evaluation; result and sticky status commit
//! once, after every lane has completed under the selected effective FP controls.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{self, widening::WideningOperation},
        scalable::{ElementSize, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES},
        sve::dot::{Kind, Operand, RightOperand, VectorPart},
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const HALF_BYTES: usize = size_of::<u16>();
const SINGLE_BYTES: usize = size_of::<u32>();
const INDEXED_SOURCE_REGISTERS: u8 = 8;
const PAIR_ELEMENTS: usize = 2;

fn half(source: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(source[offset..offset + HALF_BYTES].try_into().unwrap())
}

fn single(source: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(source[offset..offset + SINGLE_BYTES].try_into().unwrap())
}

/// Complete only Half FDOT/FMLAL/FMLSL; integer DOT uses the total native mapping.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    if !scalable.mode().streaming() {
        return Err(anyhow!("scalable Half dot requires streaming state").into());
    }
    let index_limit = match operand.kind {
        Kind::HalfDot => VECTOR_CHUNK_BYTES / SINGLE_BYTES,
        Kind::HalfMultiplyLong { .. } => VECTOR_CHUNK_BYTES / HALF_BYTES,
        _ => return Err(anyhow!("integer dot has no Half numerical completion").into()),
    };
    if operand.element_size != ElementSize::Word {
        return Err(anyhow!("Half dot output elements must be Single").into());
    }
    let (right_register, index) = match operand.right {
        RightOperand::Vector(register) => (register, None),
        RightOperand::Indexed { register, index }
            if register < INDEXED_SOURCE_REGISTERS && usize::from(index) < index_limit =>
        {
            (register, Some(usize::from(index)))
        }
        RightOperand::Indexed { .. } => {
            return Err(anyhow!("Half dot indexed source exceeds its encoded field").into());
        }
    };
    let length = scalable.vector_length().bytes();
    let mut destination = [0; MAX_VECTOR_BYTES];
    let mut left = [0; MAX_VECTOR_BYTES];
    let mut right = [0; MAX_VECTOR_BYTES];
    scalable.read_z(state, operand.destination, &mut destination[..length])?;
    scalable.read_z(state, operand.left, &mut left[..length])?;
    scalable.read_z(state, right_register, &mut right[..length])?;
    let fpcr = controls.fpcr;
    let mut result = [0; MAX_VECTOR_BYTES];
    let mut exceptions = 0;
    for offset in (0..length).step_by(SINGLE_BYTES) {
        let segment = offset - offset % VECTOR_CHUNK_BYTES;
        let addend = single(&destination, offset);
        let outcome = match operand.kind {
            Kind::HalfDot => {
                let right_offset = index.map_or(offset, |index| segment + index * SINGLE_BYTES);
                let pair = |source: &[u8], start: usize| {
                    core::array::from_fn::<_, PAIR_ELEMENTS, _>(|element| {
                        half(source, start + element * HALF_BYTES)
                    })
                };
                floating::dot::evaluate(
                    fpcr,
                    addend,
                    pair(&left, offset),
                    pair(&right, right_offset),
                )?
            }
            Kind::HalfMultiplyLong { subtract, part } => {
                let left_offset = offset
                    + if part == VectorPart::Top {
                        HALF_BYTES
                    } else {
                        0
                    };
                let right_offset = index.map_or(left_offset, |index| segment + index * HALF_BYTES);
                let operation = if subtract {
                    WideningOperation::Subtract
                } else {
                    WideningOperation::Add
                };
                floating::widening::evaluate(
                    operation,
                    fpcr,
                    addend,
                    half(&left, left_offset),
                    half(&right, right_offset),
                )?
            }
            _ => unreachable!("non-Half dot rejected before snapshots"),
        };
        result[offset..offset + SINGLE_BYTES].copy_from_slice(&(outcome.bits as u32).to_le_bytes());
        exceptions |= outcome.exceptions;
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
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

    fn put_half(
        state: &mut GuestState,
        scalable: &mut ScalableState,
        register: u8,
        values: &[u16],
    ) {
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
}
