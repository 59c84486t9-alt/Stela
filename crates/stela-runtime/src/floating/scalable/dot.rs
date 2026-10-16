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
mod tests;
