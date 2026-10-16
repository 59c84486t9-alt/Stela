//! Predicated merging SVE integral rounding with staged architectural commit.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::rounding::{self, RoundingOperation},
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES},
        sve::floating::rounding::Operand,
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

fn read_lane(source: &[u8], offset: usize, element_bytes: usize) -> u64 {
    let mut bytes = [0; size_of::<u64>()];
    bytes[..element_bytes].copy_from_slice(&source[offset..offset + element_bytes]);
    u64::from_le_bytes(bytes)
}

/// Complete one merging FRINT instruction using the central scalable setter.
/// Raw FPCR and every inactive element remain unchanged. Numerical enables are
/// effective streaming controls; FA64 retains the precise unsupported boundary.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    if !scalable.mode().streaming() {
        return Err(anyhow!("scalable rounding requires streaming state").into());
    }
    if !matches!(
        operand.operation,
        RoundingOperation::NearestEven
            | RoundingOperation::NearestAway
            | RoundingOperation::TowardPositive
            | RoundingOperation::TowardNegative
            | RoundingOperation::TowardZero
            | RoundingOperation::Current
            | RoundingOperation::CurrentExact
    ) {
        return Err(anyhow!("bounded FRINT is not a merging SVE rounding operand").into());
    }
    let length = scalable.vector_length().bytes();
    let predicate_bytes = scalable.vector_length().predicate_bytes();
    let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    let mut source = [0; MAX_VECTOR_BYTES];
    let mut result = [0; MAX_VECTOR_BYTES];
    let mut predicate = [0; MAX_PREDICATE_BYTES];
    scalable.read_z(state, operand.source, &mut source[..length])?;
    scalable.read_z(state, operand.destination, &mut result[..length])?;
    scalable.read_predicate(operand.governing, &mut predicate[..predicate_bytes])?;
    let mut exceptions = 0;
    for offset in (0..length).step_by(element_bytes) {
        if predicate[offset / BITS_PER_BYTE] & (1 << (offset % BITS_PER_BYTE)) == 0 {
            continue;
        }
        let outcome = rounding::evaluate(
            operand.format,
            operand.operation,
            controls.fpcr,
            read_lane(&source, offset, element_bytes),
        )?;
        result[offset..offset + element_bytes]
            .copy_from_slice(&outcome.bits.to_le_bytes()[..element_bytes]);
        exceptions |= outcome.exceptions;
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
