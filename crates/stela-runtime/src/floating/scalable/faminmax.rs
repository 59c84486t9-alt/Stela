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
mod tests;
