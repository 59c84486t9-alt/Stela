//! Completion of SME2 FAMIN/FAMAX and FSCALE.
use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{absolute_minmax, exponent},
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES, VECTOR_REGISTER_COUNT},
        sme::extrema_scale::{Kind, Operand},
    },
};

const MAX_GROUP_COUNT: usize = 4;
type GroupBytes = [[u8; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];

fn snapshot(
    state: &GuestState,
    scalable: &ScalableState,
    first: u8,
    count: u8,
) -> Result<GroupBytes, CompletionError> {
    if !matches!(count, 1 | 2 | 4)
        || !first.is_multiple_of(count)
        || usize::from(first) + usize::from(count) > usize::from(VECTOR_REGISTER_COUNT)
    {
        return Err(anyhow::anyhow!("invalid SME extrema/scale register group").into());
    }
    let length = scalable.vector_length().bytes();
    let mut values = [[0; MAX_VECTOR_BYTES]; MAX_GROUP_COUNT];
    for (index, output) in values.iter_mut().take(usize::from(count)).enumerate() {
        scalable.read_z(state, first + index as u8, &mut output[..length])?;
    }
    Ok(values)
}

fn lane(values: &[u8], offset: usize, bytes: usize) -> u64 {
    let mut result = [0; size_of::<u64>()];
    result[..bytes].copy_from_slice(&values[offset..offset + bytes]);
    u64::from_le_bytes(result)
}

/// All original inputs are captured before lane evaluation, including a scale
/// broadcast alias within the destination group. Unsupported controls commit
/// neither Z output nor FPSR. FPCR, NZCV, P, ZA, ZT and FPMR are preserved.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    if !scalable.mode().streaming() {
        return Err(anyhow::anyhow!("SME extrema/scale requires streaming state").into());
    }
    let count = operand.group.count();
    if !operand.right_grouped && (operand.kind != Kind::Scale || operand.right >= 16) {
        return Err(anyhow::anyhow!("invalid SME extrema/scale broadcast operand").into());
    }
    let mut results = snapshot(state, scalable, operand.destination, count)?;
    let rights = snapshot(
        state,
        scalable,
        operand.right,
        if operand.right_grouped { count } else { 1 },
    )?;
    let length = scalable.vector_length().bytes();
    let bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    let mut exceptions = 0;
    for (index, result) in results.iter_mut().take(usize::from(count)).enumerate() {
        let right = &rights[if operand.right_grouped { index } else { 0 }];
        for offset in (0..length).step_by(bytes) {
            let left = lane(result, offset, bytes);
            let right = lane(right, offset, bytes);
            let outcome = match operand.kind {
                Kind::AbsoluteMinMax(operation) => {
                    absolute_minmax::evaluate(operand.format, operation, controls.fpcr, left, right)
                }
                Kind::Scale => exponent::scale(operand.format, controls.fpcr, left, right),
            }?;
            result[offset..offset + bytes].copy_from_slice(&outcome.bits.to_le_bytes()[..bytes]);
            exceptions |= outcome.exceptions;
        }
    }
    for (index, result) in results.iter().take(usize::from(count)).enumerate() {
        scalable.write_z(state, operand.destination + index as u8, &result[..length])?;
    }
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
