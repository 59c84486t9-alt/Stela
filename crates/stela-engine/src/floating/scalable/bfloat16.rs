//! Completion of SVE BF16 instructions.

use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            FPCR_EBF, Outcome,
            bfloat16::{
                self,
                arithmetic::{self, BfloatBinaryOperation},
            },
            minmax::MinMaxOperation,
        },
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES},
        sve::{
            dot::{RightOperand, VectorPart},
            floating::bfloat16::{BinaryOperation, Kind, Operand},
        },
    },
};
use stela_contracts::require;

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const BFLOAT_BYTES: usize = size_of::<u16>();
const SINGLE_BYTES: usize = size_of::<u32>();
const DOT_COMPONENTS: usize = 2;
const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

struct Sources {
    destination: [u8; MAX_VECTOR_BYTES],
    left: [u8; MAX_VECTOR_BYTES],
    right: [u8; MAX_VECTOR_BYTES],
}

impl Sources {
    fn snapshot(
        state: &GuestState,
        scalable: &ScalableState,
        operand: &Operand,
    ) -> crate::Result<Self> {
        let mut result = Self {
            destination: [0; MAX_VECTOR_BYTES],
            left: [0; MAX_VECTOR_BYTES],
            right: [0; MAX_VECTOR_BYTES],
        };
        let length = scalable.vector_length().bytes();
        let right = match operand.right {
            RightOperand::Vector(register) | RightOperand::Indexed { register, .. } => register,
        };
        scalable.read_z(
            state,
            operand.destination,
            &mut result.destination[..length],
        )?;
        scalable.read_z(state, operand.left, &mut result.left[..length])?;
        scalable.read_z(state, right, &mut result.right[..length])?;
        Ok(result)
    }
}

fn read_bfloat(source: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        source[offset..offset + BFLOAT_BYTES]
            .try_into()
            .expect("BF lane"),
    )
}

fn read_single(source: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        source[offset..offset + SINGLE_BYTES]
            .try_into()
            .expect("Single lane"),
    )
}

fn active(predicate: Option<&[u8]>, byte_offset: usize) -> bool {
    predicate.is_none_or(|mask| {
        mask[byte_offset / BITS_PER_BYTE] & (1 << (byte_offset % BITS_PER_BYTE)) != 0
    })
}

fn right_offset(operand: &Operand, byte_offset: usize) -> usize {
    match operand.right {
        RightOperand::Vector(_) => byte_offset,
        RightOperand::Indexed { index, .. } => {
            let index_bytes = if operand.kind == Kind::Dot {
                SINGLE_BYTES
            } else {
                BFLOAT_BYTES
            };
            byte_offset - byte_offset % VECTOR_CHUNK_BYTES + usize::from(index) * index_bytes
        }
    }
}

fn evaluate_binary(
    operation: BinaryOperation,
    fpcr: u32,
    left: u16,
    right: u16,
) -> Result<Outcome, CompletionError> {
    let result = match operation {
        BinaryOperation::Add => arithmetic::binary(BfloatBinaryOperation::Add, fpcr, left, right)?,
        BinaryOperation::Subtract => {
            arithmetic::binary(BfloatBinaryOperation::Subtract, fpcr, left, right)?
        }
        BinaryOperation::Multiply => {
            arithmetic::binary(BfloatBinaryOperation::Multiply, fpcr, left, right)?
        }
        BinaryOperation::Maximum => {
            arithmetic::minmax(MinMaxOperation::Maximum, fpcr, left, right)?
        }
        BinaryOperation::MaximumNumber => {
            arithmetic::minmax(MinMaxOperation::MaximumNumber, fpcr, left, right)?
        }
        BinaryOperation::Minimum => {
            arithmetic::minmax(MinMaxOperation::Minimum, fpcr, left, right)?
        }
        BinaryOperation::MinimumNumber => {
            arithmetic::minmax(MinMaxOperation::MinimumNumber, fpcr, left, right)?
        }
    };
    Ok(result)
}

fn evaluate(
    operand: &Operand,
    sources: &Sources,
    byte_offset: usize,
    controls: NumericalControls,
) -> Result<Outcome, CompletionError> {
    let fpcr = controls.fpcr;
    let right = right_offset(operand, byte_offset);
    Ok(match operand.kind {
        Kind::Binary(operation) => evaluate_binary(
            operation,
            fpcr,
            read_bfloat(&sources.left, byte_offset),
            read_bfloat(&sources.right, right),
        )?,
        Kind::Clamp => arithmetic::clamp(
            fpcr,
            read_bfloat(&sources.destination, byte_offset),
            read_bfloat(&sources.left, byte_offset),
            read_bfloat(&sources.right, right),
        )?,
        Kind::MultiplyAdd { subtract } => {
            let left = read_bfloat(&sources.left, byte_offset);
            let left = if subtract {
                bfloat16::negate(fpcr, left)
            } else {
                left
            };
            arithmetic::fused(
                fpcr,
                read_bfloat(&sources.destination, byte_offset),
                left,
                read_bfloat(&sources.right, right),
            )?
        }
        Kind::Dot => {
            let mut left = [0; DOT_COMPONENTS];
            let mut right_values = [0; DOT_COMPONENTS];
            for component in 0..DOT_COMPONENTS {
                left[component] =
                    read_bfloat(&sources.left, byte_offset + component * BFLOAT_BYTES);
                right_values[component] =
                    read_bfloat(&sources.right, right + component * BFLOAT_BYTES);
            }
            let addend = read_single(&sources.destination, byte_offset);
            if controls.features.ebf16() && fpcr & FPCR_EBF != 0 {
                bfloat16::extended_dot::evaluate(fpcr, addend, left, right_values)
            } else {
                Outcome {
                    bits: u64::from(bfloat16::dot_add(fpcr, addend, left, right_values)),
                    exceptions: 0,
                }
            }
        }
        Kind::MultiplyLong { subtract, part } => {
            let parity = match part {
                VectorPart::Bottom => 0,
                VectorPart::Top => BFLOAT_BYTES,
            };
            let left = read_bfloat(&sources.left, byte_offset + parity);
            let left = if subtract {
                bfloat16::negate(fpcr, left)
            } else {
                left
            };
            let right = if matches!(operand.right, RightOperand::Vector(_)) {
                right + parity
            } else {
                right
            };
            bfloat16::multiply_add(
                fpcr,
                read_single(&sources.destination, byte_offset),
                left,
                read_bfloat(&sources.right, right),
            )?
        }
    })
}

/// Complete one BF16 instruction without changing raw FPCR or unrelated state.
/// With FA64, enabled numerical traps are refused. BFDOT uses the enhanced
/// semantics only when FEAT_EBF16 is present and FPCR.EBF is set.
pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require!(
        scalable.mode().streaming(),
        "scalable BF arithmetic requires streaming state",
    );
    if operand.predicate.is_some() {
        require!(
            matches!(operand.kind, Kind::Binary(_) | Kind::MultiplyAdd { .. }),
            "BF operation has no predicated form",
        );
    }
    if let RightOperand::Indexed { index, .. } = operand.right {
        require!(
            matches!(
                operand.kind,
                Kind::Binary(BinaryOperation::Multiply)
                    | Kind::MultiplyAdd { .. }
                    | Kind::Dot
                    | Kind::MultiplyLong { .. }
            ),
            "BF operation has no indexed form",
        );
        let indexed_bytes = if operand.kind == Kind::Dot {
            SINGLE_BYTES
        } else {
            BFLOAT_BYTES
        };
        require!(
            usize::from(index) < VECTOR_CHUNK_BYTES / indexed_bytes,
            "BF source index outside its segment",
        );
    }
    let sources = Sources::snapshot(state, scalable, operand)?;
    let mut predicate_storage = [0; MAX_PREDICATE_BYTES];
    let predicate = if let Some(register) = operand.predicate {
        let length = scalable.vector_length().predicate_bytes();
        scalable.read_predicate(register, &mut predicate_storage[..length])?;
        Some(&predicate_storage[..length])
    } else {
        None
    };
    let length = scalable.vector_length().bytes();
    let element_bytes = operand.kind.output_bits() as usize / BITS_PER_BYTE;
    let mut result = sources.destination;
    let mut exceptions = 0;
    for byte_offset in (0..length).step_by(element_bytes) {
        if !active(predicate, byte_offset) {
            continue;
        }
        let outcome = evaluate(operand, &sources, byte_offset, controls)?;
        result[byte_offset..byte_offset + element_bytes]
            .copy_from_slice(&outcome.bits.to_le_bytes()[..element_bytes]);
        exceptions |= outcome.exceptions;
    }
    scalable.write_z(state, operand.destination, &result[..length])?;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
