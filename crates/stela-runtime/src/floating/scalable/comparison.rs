//! Complete one SVE FP comparison with staged vector sources and packed P output.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES},
        sve::floating::comparison::{self, Operand},
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

/// No destination or FPSR effects commit until every active lane succeeds.
/// The caller resolves enabled-feature access and the selected FA64 profile.
/// Ordinary streaming masks numerical trap enables while retaining raw FPCR.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    if !scalable.mode().streaming() {
        return Err(anyhow!("scalable FP comparison requires streaming state").into());
    }
    let length = scalable.vector_length();
    let vector_bytes = length.bytes();
    let predicate_bytes = length.predicate_bytes();
    let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    let mut left = [0; MAX_VECTOR_BYTES];
    let mut right = [0; MAX_VECTOR_BYTES];
    let mut governing = [0; MAX_PREDICATE_BYTES];
    scalable.read_z(state, operand.left, &mut left[..vector_bytes])?;
    if let Some(register) = operand.right {
        if register == operand.left {
            right[..vector_bytes].copy_from_slice(&left[..vector_bytes]);
        } else {
            scalable.read_z(state, register, &mut right[..vector_bytes])?;
        }
    }
    scalable.read_predicate(operand.governing, &mut governing[..predicate_bytes])?;
    let mut result = [0; MAX_PREDICATE_BYTES];
    let mut exceptions = 0;
    for offset in (0..vector_bytes).step_by(element_bytes) {
        let byte = offset / BITS_PER_BYTE;
        let bit = offset % BITS_PER_BYTE;
        if governing[byte] & (1 << bit) == 0 {
            continue;
        }
        let outcome = comparison::evaluate(
            operand.kind,
            operand.format,
            controls.fpcr,
            read_lane(&left, offset, element_bytes),
            read_lane(&right, offset, element_bytes),
        )?;
        result[byte] |= u8::from(outcome.predicate) << bit;
        exceptions |= outcome.exceptions;
    }
    // A complete P write clears nonleading and inactive group bits. Pg may
    // alias Pd because its entire original value was snapshotted above.
    scalable.write_predicate(operand.destination, &result[..predicate_bytes])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
