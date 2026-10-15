//! Staged core binary SVE arithmetic; other allocations remain unadmitted.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{self, BinaryOperation},
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

fn active(predicate: Option<&[u8]>, lane: usize, element_bytes: usize) -> bool {
    predicate.is_none_or(|predicate| {
        let bit = lane * element_bytes;
        predicate[bit / BITS_PER_BYTE] & (1 << (bit % BITS_PER_BYTE)) != 0
    })
}

fn write_lane(output: &mut [u8], lane: usize, element_bytes: usize, bits: u64) {
    let offset = lane * element_bytes;
    output[offset..offset + element_bytes].copy_from_slice(&bits.to_le_bytes()[..element_bytes]);
}

fn read_lane(source: &[u8], lane: usize, element_bytes: usize) -> u64 {
    let offset = lane * element_bytes;
    let mut bits = [0; size_of::<u64>()];
    bits[..element_bytes].copy_from_slice(&source[offset..offset + element_bytes]);
    u64::from_le_bytes(bits)
}

/// The immutable source gate selects only seven forward vector-register forms.
/// Every active H/S/D lane is evaluated exactly; no outputs commit on error.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming(),
        "scalable arithmetic requires streaming state",
    )?;
    let (
        Kind::Binary(operation),
        Inputs::Binary {
            left: Source::Vector(left_register),
            right: Source::Vector(right_register),
        },
    ) = (operand.kind, operand.inputs)
    else {
        return Err(anyhow!("scalable numerical kind/operand shape differ").into());
    };
    require(
        operand.shape == ResultShape::Vector,
        "non-reduction has a reduction result shape",
    )?;
    require(
        matches!(
            operation,
            BinaryOperation::Add | BinaryOperation::Subtract | BinaryOperation::Multiply
        ) || (operation == BinaryOperation::Divide && operand.predicate.is_some()),
        "unadmitted scalable binary operation",
    )?;
    require(
        operand.predicate.is_none() || left_register == operand.destination,
        "unadmitted scalable binary source direction",
    )?;
    let length = scalable.vector_length().bytes();
    let element_bytes = operand.format.bits() as usize / BITS_PER_BYTE;
    let count = length / element_bytes;
    let mut left = [0; MAX_VECTOR_BYTES];
    let mut right = [0; MAX_VECTOR_BYTES];
    scalable.read_z(state, left_register, &mut left[..length])?;
    scalable.read_z(state, right_register, &mut right[..length])?;
    let mut predicate_storage = [0; MAX_PREDICATE_BYTES];
    let predicate = if let Some(register) = operand.predicate {
        let bytes = scalable.vector_length().predicate_bytes();
        scalable.read_predicate(register, &mut predicate_storage[..bytes])?;
        Some(&predicate_storage[..bytes])
    } else {
        None
    };
    let mut result = [0; MAX_VECTOR_BYTES];
    scalable.read_z(state, operand.destination, &mut result[..length])?;
    let mut exceptions = 0;
    for lane in 0..count {
        if !active(predicate, lane, element_bytes) {
            continue;
        }
        let outcome = floating::evaluate(
            operand.format,
            operation,
            controls.fpcr,
            read_lane(&left, lane, element_bytes),
            read_lane(&right, lane, element_bytes),
        )?;
        exceptions |= outcome.exceptions;
        write_lane(&mut result, lane, element_bytes, outcome.bits);
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}
