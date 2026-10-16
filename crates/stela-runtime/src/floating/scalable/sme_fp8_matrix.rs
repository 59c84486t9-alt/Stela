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
mod tests {
    use super::*;
    use stela_compiler::aarch64::{
        floating::{FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, features::NumericalFeatures},
        scalable::{ScalableMode, VectorLength},
    };

    const TEST_SVL_BYTES: usize = 16;
    const E4M3_ONE: u8 = 0x38;
    const E4M3_SOURCES: u64 = 1 | (1 << fp8::FPMR_F8S2_SHIFT);
    const HALF_ONE: u64 = 0x3c00;
    const HALF_TWO: u64 = 0x4000;
    const SINGLE_ONE: u64 = 0x3f80_0000;
    const SINGLE_FOUR: u64 = 0x4080_0000;

    fn state() -> (GuestState, ScalableState) {
        let mut state = GuestState {
            fpcr: FPCR_EXCEPTION_ENABLE_MASK,
            fpsr: 0x0800_009f,
            ..GuestState::default()
        };
        let mut scalable =
            ScalableState::new(VectorLength::from_bytes(TEST_SVL_BYTES).unwrap(), true);
        scalable
            .apply_mode(&mut state, ScalableMode::new(true, true))
            .unwrap();
        scalable.set_fpmr(E4M3_SOURCES);
        for register in 0..VECTOR_REGISTER_COUNT {
            scalable
                .write_z(&mut state, register, &[E4M3_ONE; TEST_SVL_BYTES])
                .unwrap();
        }
        (state, scalable)
    }

    fn controls(state: &GuestState) -> NumericalControls {
        NumericalControls::new(state.fpcr, true, NumericalFeatures::default())
    }

    fn vector(operation: VectorOperation, accumulator: Format, groups: u8) -> VectorOperand {
        VectorOperand {
            operation,
            accumulator,
            groups,
            left: 0,
            right: RightSource::Vector(0),
            vector_select: 8,
            offset: 0,
        }
    }

    #[test]
    fn every_vector_layout_preserves_unselected_rows_and_raw_state() {
        for format in [Format::Half, Format::Single] {
            let bytes = width(format).unwrap();
            for groups in [1, 2, 4] {
                for operation in [VectorOperation::Dot, VectorOperation::MultiplyAdd] {
                    if groups == 1 && operation == VectorOperation::Dot {
                        continue;
                    }
                    for right in [
                        RightSource::Vector(0),
                        RightSource::Group(0),
                        RightSource::Indexed {
                            register: 0,
                            index: 15,
                        },
                    ] {
                        if operation == VectorOperation::Dot
                            && matches!(right, RightSource::Indexed { .. })
                        {
                            continue;
                        }
                        if groups == 1 && matches!(right, RightSource::Group(_)) {
                            continue;
                        }
                        let (mut state, mut scalable) = state();
                        let original = state.clone();
                        let mut operand = vector(operation, format, groups);
                        operand.right = right;
                        let selected_rows = usize::from(groups)
                            * if operation == VectorOperation::MultiplyAdd {
                                bytes
                            } else {
                                1
                            };
                        let controls = controls(&state);
                        complete(
                            &mut state,
                            &mut scalable,
                            &Operand::Vector(operand),
                            controls,
                        )
                        .unwrap();
                        assert_eq!(state, original);
                        assert_eq!(scalable.fpmr(), E4M3_SOURCES);
                        let mut za = [0; TEST_SVL_BYTES * TEST_SVL_BYTES];
                        scalable.read_za(0, &mut za).unwrap();
                        let expected = match (operation, format) {
                            (VectorOperation::MultiplyAdd, Format::Half) => HALF_ONE,
                            (VectorOperation::MultiplyAdd, Format::Single) => SINGLE_ONE,
                            (_, Format::Half) => HALF_TWO,
                            (_, Format::Single) => SINGLE_FOUR,
                            (_, Format::Double) => unreachable!(),
                        };
                        let mut changed = 0;
                        for row in za.as_chunks::<TEST_SVL_BYTES>().0 {
                            if row.iter().any(|byte| *byte != 0) {
                                changed += 1;
                                for element in 0..TEST_SVL_BYTES / bytes {
                                    assert_eq!(read_lane(row, element, bytes), expected);
                                }
                            }
                        }
                        assert_eq!(changed, selected_rows);
                    }
                }
            }
        }
    }

    #[test]
    fn vertical_pairs_cross_source_registers_and_select_bottom_or_top() {
        for (format, top) in [
            (Format::Half, false),
            (Format::Single, false),
            (Format::Single, true),
        ] {
            let (mut state, mut scalable) = state();
            let bytes = width(format).unwrap();
            // The first source contributes1, the second2. A pair with right1 sums3.
            scalable
                .write_z(&mut state, 1, &[0x40; TEST_SVL_BYTES])
                .unwrap();
            if format == Format::Single {
                let mut right = [E4M3_ONE; TEST_SVL_BYTES];
                for quartet in right.as_chunks_mut::<4>().0 {
                    quartet[2..].fill(0x40);
                }
                scalable.write_z(&mut state, 2, &right).unwrap();
            }
            let original = state.clone();
            let mut operand = vector(VectorOperation::VerticalDot { top }, format, bytes as u8);
            operand.right = RightSource::Indexed {
                register: 2,
                index: (VECTOR_CHUNK_BYTES / bytes - 1) as u8,
            };
            let controls = controls(&state);
            complete(
                &mut state,
                &mut scalable,
                &Operand::Vector(operand),
                controls,
            )
            .unwrap();
            assert_eq!(state, original);
            let mut row = [0; TEST_SVL_BYTES];
            for group in 0..bytes {
                scalable
                    .read_za(group * (TEST_SVL_BYTES / bytes) * TEST_SVL_BYTES, &mut row)
                    .unwrap();
                for element in 0..TEST_SVL_BYTES / bytes {
                    assert_eq!(
                        read_lane(&row, element, bytes),
                        if format == Format::Half {
                            0x4200
                        } else if top {
                            0x40c0_0000
                        } else {
                            0x4040_0000
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn inactive_outer_cells_preserve_signaling_nan_without_classifying() {
        let (mut state, mut scalable) = state();
        state.fpcr |= FPCR_AH;
        let original = state.clone();
        let before = [0x01; TEST_SVL_BYTES * TEST_SVL_BYTES];
        scalable.write_za(0, &before).unwrap();
        scalable
            .write_predicate(0, &[0; TEST_SVL_BYTES / BITS_PER_BYTE])
            .unwrap();
        let operand = OuterOperand {
            accumulator: Format::Single,
            tile: 3,
            left: 0,
            right: 0,
            row_predicate: 0,
            column_predicate: 0,
        };
        let controls = controls(&state);
        complete(
            &mut state,
            &mut scalable,
            &Operand::Outer(operand),
            controls,
        )
        .unwrap();
        let mut actual = [0; TEST_SVL_BYTES * TEST_SVL_BYTES];
        scalable.read_za(0, &mut actual).unwrap();
        assert_eq!(actual, before);
        assert_eq!(state, original);
    }

    #[test]
    fn malformed_sources_fail_without_committing_and_release_scratch() {
        let (mut state, mut scalable) = state();
        let before = [0xa5; TEST_SVL_BYTES * TEST_SVL_BYTES];
        scalable.write_za(0, &before).unwrap();
        let mut operand = vector(VectorOperation::MultiplyAdd, Format::Single, 4);
        operand.right = RightSource::Group(30);
        let controls = controls(&state);
        assert!(
            complete(
                &mut state,
                &mut scalable,
                &Operand::Vector(operand),
                controls
            )
            .is_err()
        );
        let mut actual = [0; TEST_SVL_BYTES * TEST_SVL_BYTES];
        scalable.read_za(0, &mut actual).unwrap();
        assert_eq!(actual, before);
        operand.right = RightSource::Group(0);
        complete(
            &mut state,
            &mut scalable,
            &Operand::Vector(operand),
            controls,
        )
        .unwrap();
    }
}
