//! Completion of SME FP8 ZA arithmetic.

use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{Format, fp8},
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT},
        sme::fp8_matrix::{Operand, OuterOperand, RightSource, VectorOperand, VectorOperation},
    },
};

use super::{
    CompletionError, NumericalControls,
    sme_matrix::{ZaResults, read_lane, read_z, require, selector, write_lane},
};
use crate::scalable::ScalableState;

const MAX_GROUPS: usize = 4;
const MAX_ROWS: usize = MAX_GROUPS * MAX_GROUPS;
const MAX_TERMS: usize = 4;
const MAX_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

fn width(format: Format) -> Result<usize, CompletionError> {
    require(
        matches!(format, Format::Half | Format::Single),
        "FP8 ZA accumulation requires Half or Single",
    )?;
    Ok(format.bits() as usize / BITS_PER_BYTE)
}

struct Sources {
    left: [[u8; MAX_VECTOR_BYTES]; MAX_GROUPS],
    right: [[u8; MAX_VECTOR_BYTES]; MAX_GROUPS],
    grouped_right: bool,
    index: Option<usize>,
}

fn snapshot_sources(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &VectorOperand,
) -> Result<Sources, CompletionError> {
    let groups = usize::from(operand.groups);
    require(matches!(groups, 1 | 2 | 4), "invalid FP8 ZA source group")?;
    let vertical = matches!(operand.operation, VectorOperation::VerticalDot { .. });
    let source_groups = if vertical { 2 } else { groups };
    let (right, grouped_right, index) = match operand.right {
        RightSource::Vector(register) => (register, false, None),
        RightSource::Group(register) => (register, true, None),
        RightSource::Indexed { register, index } => (register, false, Some(usize::from(index))),
    };
    let left = usize::from(operand.left);
    let right = usize::from(right);
    let registers = usize::from(VECTOR_REGISTER_COUNT);
    let wrap_left = matches!(operand.right, RightSource::Vector(_)) && !vertical;
    require(
        left < registers && right < registers,
        "FP8 ZA source register out of range",
    )?;
    require(
        (wrap_left || (left.is_multiple_of(source_groups) && left + source_groups <= registers))
            && (!grouped_right || (right.is_multiple_of(groups) && right + groups <= registers))
            && (grouped_right || right < registers / 2),
        "FP8 ZA source group exceeds its encoding",
    )?;
    let bytes = width(operand.accumulator)?;
    let index_limit = if operand.operation == VectorOperation::MultiplyAdd {
        VECTOR_CHUNK_BYTES
    } else {
        VECTOR_CHUNK_BYTES / bytes
    };
    require(
        index.is_none_or(|index| index < index_limit),
        "FP8 ZA source index out of range",
    )?;
    require(
        !vertical || index.is_some(),
        "FP8 vertical dot requires indexed source",
    )?;
    require(
        operand.accumulator != Format::Half
            || !matches!(
                operand.operation,
                VectorOperation::VerticalDot { top: true }
            ),
        "Half FP8 vertical dot has no top form",
    )?;
    let mut result = Sources {
        left: [[0; MAX_VECTOR_BYTES]; MAX_GROUPS],
        right: [[0; MAX_VECTOR_BYTES]; MAX_GROUPS],
        grouped_right,
        index,
    };
    for group in 0..source_groups {
        result.left[group] = read_z(state, scalable, ((left + group) % registers) as u8)?;
    }
    for group in 0..if grouped_right { groups } else { 1 } {
        result.right[group] = read_z(state, scalable, (right + group) as u8)?;
    }
    Ok(result)
}

fn complete_vector<'scratch>(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &VectorOperand,
    fpcr: u32,
    scratch: &'scratch mut [u8],
) -> Result<ZaResults<'scratch>, CompletionError> {
    let bytes = width(operand.accumulator)?;
    let groups = usize::from(operand.groups);
    let sources = snapshot_sources(state, scalable, operand)?;
    let long = operand.operation == VectorOperation::MultiplyAdd;
    let vertical = matches!(operand.operation, VectorOperation::VerticalDot { .. });
    require(
        !vertical || groups == bytes,
        "FP8 vertical dot output group differs",
    )?;
    require(long || groups != 1, "FP8 dot requires multiple ZA vectors")?;
    let rows_per_group = if long { bytes } else { 1 };
    let length = scalable.vector_length().bytes();
    let stride = length / groups;
    let mut base = ((u64::from(selector(state, operand.vector_select)?)
        + u64::from(operand.offset))
        % stride as u64) as usize;
    base -= base % rows_per_group;
    let mut rows = [0; MAX_ROWS];
    for group in 0..groups {
        for parity in 0..rows_per_group {
            rows[group * rows_per_group + parity] = base + group * stride + parity;
        }
    }
    let mut result = ZaResults::stage(scalable, &rows[..groups * rows_per_group], scratch)?;
    let segment_elements = VECTOR_CHUNK_BYTES / bytes;
    for group in 0..groups {
        let right = &sources.right[if sources.grouped_right { group } else { 0 }];
        for parity in 0..rows_per_group {
            let row = group * rows_per_group + parity;
            for element in 0..length / bytes {
                let segment = element - element % segment_elements;
                let mut left_terms = [0; MAX_TERMS];
                let mut right_terms = [0; MAX_TERMS];
                let terms = if long {
                    left_terms[0] = sources.left[group][bytes * element + parity];
                    let right_byte = sources
                        .index
                        .map_or(bytes * element + parity, |index| bytes * segment + index);
                    right_terms[0] = right[right_byte];
                    1
                } else if vertical {
                    let left_byte = bytes * element + group;
                    left_terms[0] = sources.left[0][left_byte];
                    left_terms[1] = sources.left[1][left_byte];
                    let top = matches!(
                        operand.operation,
                        VectorOperation::VerticalDot { top: true }
                    );
                    let right_byte = bytes
                        * (segment + sources.index.expect("validated indexed source"))
                        + if top { size_of::<u16>() } else { 0 };
                    right_terms[..2].copy_from_slice(&right[right_byte..right_byte + 2]);
                    2
                } else {
                    let left_byte = bytes * element;
                    let right_byte = bytes * sources.index.map_or(element, |index| segment + index);
                    left_terms[..bytes]
                        .copy_from_slice(&sources.left[group][left_byte..left_byte + bytes]);
                    right_terms[..bytes].copy_from_slice(&right[right_byte..right_byte + bytes]);
                    bytes
                };
                let addend = read_lane(result.row(row), element, bytes);
                let bits = fp8::dot_add(
                    operand.accumulator,
                    fpcr,
                    scalable.fpmr(),
                    addend,
                    &left_terms[..terms],
                    &right_terms[..terms],
                );
                write_lane(result.row_mut(row), element, bytes, bits);
            }
        }
    }
    Ok(result)
}

fn active(predicate: &[u8], byte: usize) -> bool {
    predicate[byte / BITS_PER_BYTE] & (1 << (byte % BITS_PER_BYTE)) != 0
}

fn complete_outer<'scratch>(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &OuterOperand,
    fpcr: u32,
    scratch: &'scratch mut [u8],
) -> Result<ZaResults<'scratch>, CompletionError> {
    let bytes = width(operand.accumulator)?;
    require(
        usize::from(operand.tile) < bytes,
        "FP8 ZA tile out of range",
    )?;
    require(
        operand.row_predicate < 8 && operand.column_predicate < 8,
        "FP8 ZA predicate out of range",
    )?;
    let left = read_z(state, scalable, operand.left)?;
    let right = read_z(state, scalable, operand.right)?;
    let length = scalable.vector_length().bytes();
    let dimension = length / bytes;
    let mut row_predicate = [0; MAX_PREDICATE_BYTES];
    let mut column_predicate = [0; MAX_PREDICATE_BYTES];
    scalable.read_predicate(
        operand.row_predicate,
        &mut row_predicate[..length / BITS_PER_BYTE],
    )?;
    scalable.read_predicate(
        operand.column_predicate,
        &mut column_predicate[..length / BITS_PER_BYTE],
    )?;
    let mut rows = [0; MAX_VECTOR_BYTES / size_of::<u16>()];
    for (row, physical) in rows.iter_mut().enumerate().take(dimension) {
        *physical = usize::from(operand.tile) + row * bytes;
    }
    let mut result = ZaResults::stage(scalable, &rows[..dimension], scratch)?;
    for row in 0..dimension {
        for column in 0..dimension {
            let mut left_terms = [0; MAX_TERMS];
            let mut right_terms = [0; MAX_TERMS];
            let mut any_active = false;
            for term in 0..bytes {
                let row_byte = bytes * row + term;
                let column_byte = bytes * column + term;
                let row_active = active(&row_predicate, row_byte);
                let column_active = active(&column_predicate, column_byte);
                any_active |= row_active && column_active;
                if row_active {
                    left_terms[term] = left[row_byte];
                }
                if column_active {
                    right_terms[term] = right[column_byte];
                }
            }
            if !any_active {
                continue;
            }
            let addend = read_lane(result.row(row), column, bytes);
            let bits = fp8::dot_add(
                operand.accumulator,
                fpcr,
                scalable.fpmr(),
                addend,
                &left_terms[..bytes],
                &right_terms[..bytes],
            );
            write_lane(result.row_mut(row), column, bytes, bits);
        }
    }
    Ok(result)
}

pub(super) fn complete(
    state: &mut GuestState,
    scalable: &mut ScalableState,
    operand: &Operand,
    controls: NumericalControls,
) -> Result<(), CompletionError> {
    require(
        scalable.mode().streaming() && scalable.mode().za_enabled(),
        "FP8 ZA arithmetic requires streaming and ZA state",
    )?;
    let rows = match operand {
        Operand::Vector(operand) => {
            usize::from(operand.groups)
                * if operand.operation == VectorOperation::MultiplyAdd {
                    width(operand.accumulator)?
                } else {
                    1
                }
        }
        Operand::Outer(operand) => scalable.vector_length().bytes() / width(operand.accumulator)?,
    };
    scalable.with_za_row_scratch(rows, |scalable, scratch| {
        let result = match operand {
            Operand::Vector(operand) => {
                complete_vector(state, scalable, operand, controls.fpcr, scratch)?
            }
            Operand::Outer(operand) => {
                complete_outer(state, scalable, operand, controls.fpcr, scratch)?
            }
        };
        result.commit(scalable);
        Ok(())
    })
}

#[cfg(test)]
mod tests;
