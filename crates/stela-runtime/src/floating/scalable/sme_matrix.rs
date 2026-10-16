//! Transactional ZA floating completion; source banks are never guest outputs.
//! ZA numerical helpers force default NaNs and suppress numerical FPSR effects
//! independently of FA64. Only affected physical ZA rows are staged.

use anyhow::anyhow;
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            self, BinaryOperation, FPCR_DN, FPCR_EBF, FPCR_EXCEPTION_ENABLE_MASK, Format,
            bfloat16::arithmetic::BfloatBinaryOperation, fused::FusedOperation,
        },
        scalable::{BITS_PER_BYTE, MAX_VECTOR_BYTES, VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT},
        sme::fp_matrix::{
            self, DotFormat, MatrixFormat, Operand, OuterNumericalKind, Sources, VectorOperand,
            VectorOperation,
        },
    },
};

use super::{CompletionError, NumericalControls};
use crate::scalable::ScalableState;

const HALF_BYTES: usize = size_of::<u16>();
const SINGLE_BYTES: usize = size_of::<u32>();
const MAX_ZA_ROWS: usize = MAX_VECTOR_BYTES / HALF_BYTES;

pub(super) fn require(condition: bool, message: &'static str) -> Result<(), CompletionError> {
    if condition {
        Ok(())
    } else {
        Err(anyhow!(message).into())
    }
}

pub(super) struct ZaResults<'scratch> {
    rows: [usize; MAX_ZA_ROWS],
    count: usize,
    length: usize,
    bytes: &'scratch mut [u8],
}

impl<'scratch> ZaResults<'scratch> {
    pub(super) fn stage(
        scalable: &ScalableState,
        rows: &[usize],
        bytes: &'scratch mut [u8],
    ) -> Result<Self, CompletionError> {
        require(
            !rows.is_empty() && rows.len() <= MAX_ZA_ROWS,
            "ZA result row count differs",
        )?;
        let length = scalable.vector_length().bytes();
        require(
            bytes.len() == rows.len() * length,
            "ZA staging byte count differs",
        )?;
        let mut result = Self {
            rows: [0; MAX_ZA_ROWS],
            count: rows.len(),
            length,
            bytes,
        };
        for (index, row) in rows.iter().copied().enumerate() {
            require(
                row < length && !rows[..index].contains(&row),
                "ZA result rows overlap or exceed SVL",
            )?;
            result.rows[index] = row;
            scalable.read_za(row * length, result.row_mut(index))?;
        }
        Ok(result)
    }

    pub(super) fn row(&self, index: usize) -> &[u8] {
        let start = index * self.length;
        &self.bytes[start..start + self.length]
    }

    pub(super) fn row_mut(&mut self, index: usize) -> &mut [u8] {
        let start = index * self.length;
        &mut self.bytes[start..start + self.length]
    }

    pub(super) fn commit(self, scalable: &mut ScalableState) {
        for index in 0..self.count {
            // All rows were validated against this same exclusively borrowed
            // owner before evaluation. No mode, length or backing changes occur.
            scalable
                .write_za(self.rows[index] * self.length, self.row(index))
                .expect("staged ZA rows retain their validated backing");
        }
    }
}

pub(super) fn read_z(
    state: &GuestState,
    scalable: &ScalableState,
    register: u8,
) -> Result<[u8; MAX_VECTOR_BYTES], CompletionError> {
    let mut bytes = [0; MAX_VECTOR_BYTES];
    scalable.read_z(
        state,
        register,
        &mut bytes[..scalable.vector_length().bytes()],
    )?;
    Ok(bytes)
}

pub(super) fn selector(state: &GuestState, register: u8) -> Result<u32, CompletionError> {
    require(
        (8..=11).contains(&register),
        "ZA vector selector must be W8..W11",
    )?;
    Ok(state.x[usize::from(register)] as u32)
}

pub(super) fn read_lane(bytes: &[u8], lane: usize, width: usize) -> u64 {
    let mut result = [0; size_of::<u64>()];
    let start = lane * width;
    result[..width].copy_from_slice(&bytes[start..start + width]);
    u64::from_le_bytes(result)
}

pub(super) fn write_lane(bytes: &mut [u8], lane: usize, width: usize, bits: u64) {
    let start = lane * width;
    bytes[start..start + width].copy_from_slice(&bits.to_le_bytes()[..width]);
}

fn numerical_lane(
    format: MatrixFormat,
    operation: VectorOperation,
    fpcr: u32,
    addend: u64,
    left: u64,
    right: u64,
) -> Result<u64, CompletionError> {
    let outcome = match (format, operation) {
        (MatrixFormat::Float(format), VectorOperation::Add | VectorOperation::Subtract) => {
            floating::evaluate(
                format,
                if operation == VectorOperation::Add {
                    BinaryOperation::Add
                } else {
                    BinaryOperation::Subtract
                },
                fpcr,
                addend,
                right,
            )?
        }
        (
            MatrixFormat::Float(format),
            VectorOperation::MultiplyAdd | VectorOperation::MultiplySubtract,
        ) => floating::fused::evaluate(
            format,
            if operation == VectorOperation::MultiplyAdd {
                FusedOperation::Add
            } else {
                FusedOperation::Subtract
            },
            fpcr,
            addend,
            left,
            right,
        )?,
        (MatrixFormat::BFloat16, VectorOperation::Add | VectorOperation::Subtract) => {
            floating::bfloat16::arithmetic::binary(
                if operation == VectorOperation::Add {
                    BfloatBinaryOperation::Add
                } else {
                    BfloatBinaryOperation::Subtract
                },
                fpcr,
                addend as u16,
                right as u16,
            )?
        }
        (
            MatrixFormat::BFloat16,
            VectorOperation::MultiplyAdd | VectorOperation::MultiplySubtract,
        ) => {
            let left = if operation == VectorOperation::MultiplySubtract {
                floating::bfloat16::arithmetic::negate(fpcr, left as u16)
            } else {
                left as u16
            };
            floating::bfloat16::arithmetic::fused(fpcr, addend as u16, left, right as u16)?
        }
    };
    // Every caller uses a ZA helper with fpexc=FALSE. Guest FPSR is unchanged.
    Ok(outcome.bits)
}

fn dot_lane(
    kind: DotFormat,
    fpcr: u32,
    addend: u32,
    left: [u16; 2],
    right: [u16; 2],
) -> Result<u32, CompletionError> {
    Ok(match kind {
        DotFormat::Half => floating::dot::evaluate(fpcr, addend, left, right)?.bits as u32,
        DotFormat::BFloat16 if fpcr & FPCR_EBF != 0 => {
            floating::bfloat16::extended_dot::evaluate(fpcr, addend, left, right).bits as u32
        }
        DotFormat::BFloat16 => floating::bfloat16::dot_add(fpcr, addend, left, right),
    })
}

fn complete_vector<'scratch>(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &VectorOperand,
    fpcr: u32,
    scratch: &'scratch mut [u8],
) -> Result<ZaResults<'scratch>, CompletionError> {
    let length = scalable.vector_length();
    let count = usize::from(operand.group.count());
    require(
        count == 2 || count == 4,
        "ZA vector arithmetic group must contain two or four rows",
    )?;
    let rows = operand
        .vectors(length, selector(state, operand.vector_select)?)
        .map(usize::from);
    let mut result = ZaResults::stage(scalable, &rows[..count], scratch)?;
    let width = operand.format.element_size().bytes();
    for group in 0..count {
        let (left_register, right_register) = match operand.sources {
            Sources::AddendGroup { first } => {
                require(
                    matches!(
                        operand.operation,
                        VectorOperation::Add | VectorOperation::Subtract
                    ),
                    "ZA addend group requires add/subtract",
                )?;
                (None, first + group as u8)
            }
            Sources::Single { left, right } => {
                (Some((left + group as u8) % VECTOR_REGISTER_COUNT), right)
            }
            Sources::Group { left, right } => (Some(left + group as u8), right + group as u8),
            Sources::Indexed { left, right, .. } => (Some(left + group as u8), right),
        };
        let left = left_register
            .map(|register| read_z(state, scalable, register))
            .transpose()?;
        let right = read_z(state, scalable, right_register)?;
        for lane in 0..length.bytes() / width {
            let addend = read_lane(result.row(group), lane, width);
            let left_bits = left.as_ref().map_or(0, |left| read_lane(left, lane, width));
            let right_lane = usize::from(operand.right_element(lane as u16));
            let bits = numerical_lane(
                operand.format,
                operand.operation,
                fpcr,
                addend,
                left_bits,
                read_lane(&right, right_lane, width),
            )?;
            write_lane(result.row_mut(group), lane, width, bits);
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
        "SME matrix arithmetic requires streaming and ZA state",
    )?;
    let fpcr = (controls.fpcr | FPCR_DN) & !FPCR_EXCEPTION_ENABLE_MASK;
    let rows = match operand {
        Operand::Vector(operand) => usize::from(operand.group.count()),
        Operand::Dot(operand) => usize::from(operand.group.count()),
        Operand::Long(operand) => usize::from(operand.group.count()) * LONG_RESULT_ROWS,
        Operand::Outer(operand) => {
            scalable.vector_length().bytes() / operand.destination.element_size().bytes()
        }
    };
    scalable.with_za_row_scratch(rows, |scalable, scratch| {
        let result = match operand {
            Operand::Vector(operand) => complete_vector(state, scalable, operand, fpcr, scratch)?,
            Operand::Dot(operand) => complete_dot(state, scalable, operand, fpcr, scratch)?,
            Operand::Long(operand) => complete_long(state, scalable, operand, fpcr, scratch)?,
            Operand::Outer(operand) => complete_outer(state, scalable, operand, fpcr, scratch)?,
        };
        result.commit(scalable);
        Ok(())
    })
}

const DOT_SOURCE_GROUP_MAX: usize = fp_matrix::Group::Four.count() as usize;
const DOT_PRODUCT_TERMS: usize = 2;
const LONG_RESULT_ROWS: usize = DOT_PRODUCT_TERMS;
const DOT_HALVES_PER_SINGLE: usize = SINGLE_BYTES / HALF_BYTES;
const DOT_SEGMENT_ELEMENTS: usize = VECTOR_CHUNK_BYTES / SINGLE_BYTES;
const DOT_REGISTER_COUNT: usize = VECTOR_REGISTER_COUNT as usize;
const DOT_INDEXED_REGISTER_COUNT: usize = DOT_REGISTER_COUNT / DOT_PRODUCT_TERMS;
const DOT_BFLOAT_WIDEN_SHIFT: u32 = u16::BITS;

/// Snapshot only instruction source groups, before staging/evaluating results.
/// Single-right forms share one right snapshot; matching groups snapshot each.
struct DotSourceSnapshots {
    left: [[u8; MAX_VECTOR_BYTES]; DOT_SOURCE_GROUP_MAX],
    right: [[u8; MAX_VECTOR_BYTES]; DOT_SOURCE_GROUP_MAX],
    grouped_right: bool,
    index: Option<usize>,
}

impl DotSourceSnapshots {
    fn right(&self, group: usize) -> &[u8; MAX_VECTOR_BYTES] {
        &self.right[if self.grouped_right { group } else { 0 }]
    }

    fn selected_element(&self, element: usize) -> usize {
        self.index.map_or(element, |index| {
            element - element % DOT_SEGMENT_ELEMENTS + index
        })
    }

    fn selected_long_element(&self, element: usize, parity: usize) -> usize {
        self.index
            .map_or(DOT_HALVES_PER_SINGLE * element + parity, |index| {
                DOT_HALVES_PER_SINGLE * (element - element % DOT_SEGMENT_ELEMENTS) + index
            })
    }
}

fn snapshot_dot_sources(
    state: &GuestState,
    scalable: &ScalableState,
    sources: fp_matrix::Sources,
    groups: usize,
    long: bool,
) -> Result<DotSourceSnapshots, CompletionError> {
    let (left, right, grouped_right, wrap_left, index) = match sources {
        fp_matrix::Sources::Single { left, right } => (left, right, false, true, None),
        fp_matrix::Sources::Group { left, right } => (left, right, true, false, None),
        fp_matrix::Sources::Indexed { left, right, index } => {
            (left, right, false, false, Some(usize::from(index)))
        }
        fp_matrix::Sources::AddendGroup { .. } => {
            return Err(anyhow::anyhow!("ZA dot/long requires two Z source roles").into());
        }
    };
    if usize::from(left) >= DOT_REGISTER_COUNT || usize::from(right) >= DOT_REGISTER_COUNT {
        return Err(anyhow::anyhow!("ZA dot/long source register is outside Z0..Z31").into());
    }
    if (!wrap_left && usize::from(left) + groups > DOT_REGISTER_COUNT)
        || (grouped_right && usize::from(right) + groups > DOT_REGISTER_COUNT)
        || (!grouped_right && usize::from(right) >= DOT_INDEXED_REGISTER_COUNT)
    {
        return Err(anyhow::anyhow!("ZA dot/long source group exceeds its encoded field").into());
    }
    let index_limit = VECTOR_CHUNK_BYTES / if long { HALF_BYTES } else { SINGLE_BYTES };
    if index.is_some_and(|index| index >= index_limit) {
        return Err(anyhow::anyhow!("ZA dot/long index exceeds one 128-bit segment").into());
    }
    let mut snapshots = DotSourceSnapshots {
        left: [[0; MAX_VECTOR_BYTES]; DOT_SOURCE_GROUP_MAX],
        right: [[0; MAX_VECTOR_BYTES]; DOT_SOURCE_GROUP_MAX],
        grouped_right,
        index,
    };
    for group in 0..groups {
        let register = (usize::from(left) + group) % DOT_REGISTER_COUNT;
        snapshots.left[group] = read_z(state, scalable, register as u8)?;
    }
    for group in 0..if grouped_right { groups } else { 1 } {
        let register = usize::from(right) + group;
        snapshots.right[group] = read_z(state, scalable, register as u8)?;
    }
    Ok(snapshots)
}

fn dot_row_base(selector: u32, offset: u8, stride: usize) -> usize {
    // Selection reads W, then mathematical addition, then modulo. Do not let
    // host u32 addition overflow before applying the selected ZA row modulus.
    ((u64::from(selector) + u64::from(offset)) % stride as u64) as usize
}

fn complete_dot<'scratch>(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &fp_matrix::DotOperand,
    fpcr: u32,
    scratch: &'scratch mut [u8],
) -> Result<ZaResults<'scratch>, CompletionError> {
    let length = scalable.vector_length().bytes();
    let groups = usize::from(operand.group.count());
    if operand.vertical
        && (groups != DOT_PRODUCT_TERMS
            || !matches!(operand.sources, fp_matrix::Sources::Indexed { .. }))
    {
        return Err(
            anyhow::anyhow!("ZA vertical dot requires an indexed two-register group").into(),
        );
    }
    let sources = snapshot_dot_sources(state, scalable, operand.sources, groups, false)?;
    let stride = length / groups;
    let base = dot_row_base(
        selector(state, operand.vector_select)?,
        operand.offset,
        stride,
    );
    let row_indices: [usize; DOT_SOURCE_GROUP_MAX] =
        core::array::from_fn(|group| base + group * stride);
    let mut results = ZaResults::stage(scalable, &row_indices[..groups], scratch)?;
    for group in 0..groups {
        for element in 0..length / SINGLE_BYTES {
            let left = if operand.vertical {
                core::array::from_fn(|term| {
                    read_lane(
                        &sources.left[term],
                        DOT_HALVES_PER_SINGLE * element + group,
                        HALF_BYTES,
                    ) as u16
                })
            } else {
                core::array::from_fn(|term| {
                    read_lane(
                        &sources.left[group],
                        DOT_HALVES_PER_SINGLE * element + term,
                        HALF_BYTES,
                    ) as u16
                })
            };
            let selected = sources.selected_element(element);
            let right = core::array::from_fn(|term| {
                read_lane(
                    sources.right(group),
                    DOT_HALVES_PER_SINGLE * selected + term,
                    HALF_BYTES,
                ) as u16
            });
            let addend = read_lane(results.row(group), element, SINGLE_BYTES) as u32;
            let value = dot_lane(operand.kind, fpcr, addend, left, right)?;
            write_lane(
                results.row_mut(group),
                element,
                SINGLE_BYTES,
                u64::from(value),
            );
        }
    }
    Ok(results)
}

fn complete_long<'scratch>(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &fp_matrix::LongOperand,
    fpcr: u32,
    scratch: &'scratch mut [u8],
) -> Result<ZaResults<'scratch>, CompletionError> {
    let length = scalable.vector_length().bytes();
    let groups = usize::from(operand.group.count());
    let sources = snapshot_dot_sources(state, scalable, operand.sources, groups, true)?;
    let stride = length / groups;
    let selected = dot_row_base(
        selector(state, operand.vector_select)?,
        operand.offset,
        stride,
    );
    let base = selected - selected % LONG_RESULT_ROWS;
    let row_indices: [usize; DOT_SOURCE_GROUP_MAX * LONG_RESULT_ROWS] =
        core::array::from_fn(|index| {
            base + index / LONG_RESULT_ROWS * stride + index % LONG_RESULT_ROWS
        });
    let mut results =
        ZaResults::stage(scalable, &row_indices[..groups * LONG_RESULT_ROWS], scratch)?;
    for group in 0..groups {
        for parity in 0..LONG_RESULT_ROWS {
            let row = group * LONG_RESULT_ROWS + parity;
            for element in 0..length / SINGLE_BYTES {
                let left = read_lane(
                    &sources.left[group],
                    DOT_HALVES_PER_SINGLE * element + parity,
                    HALF_BYTES,
                ) as u16;
                let right = read_lane(
                    sources.right(group),
                    sources.selected_long_element(element, parity),
                    HALF_BYTES,
                ) as u16;
                let addend = read_lane(results.row(row), element, SINGLE_BYTES) as u32;
                let value = match operand.kind {
                    fp_matrix::DotFormat::Half => {
                        let operation = if operand.subtract {
                            floating::widening::WideningOperation::Subtract
                        } else {
                            floating::widening::WideningOperation::Add
                        };
                        // The shared widening primitive applies FPNeg{16} before
                        // classification and ignores AHP through FPUnpack.
                        floating::widening::evaluate(operation, fpcr, addend, left, right)?.bits
                    }
                    fp_matrix::DotFormat::BFloat16 => {
                        let operation = if operand.subtract {
                            fp_matrix::VectorOperation::MultiplySubtract
                        } else {
                            fp_matrix::VectorOperation::MultiplyAdd
                        };
                        // FPNeg on bit-widened BF16 preserves BFNeg's AH NaN
                        // rule; the shared Single primitive keeps one rounding.
                        numerical_lane(
                            fp_matrix::MatrixFormat::Float(floating::Format::Single),
                            operation,
                            fpcr,
                            u64::from(addend),
                            u64::from(u32::from(left) << DOT_BFLOAT_WIDEN_SHIFT),
                            u64::from(u32::from(right) << DOT_BFLOAT_WIDEN_SHIFT),
                        )?
                    }
                };
                write_lane(results.row_mut(row), element, SINGLE_BYTES, value);
            }
        }
    }
    Ok(results)
}

const OUTER_DOT_MEMBERS: usize = 2;
const MAX_OUTER_PREDICATE_BYTES: usize = MAX_VECTOR_BYTES / BITS_PER_BYTE;

fn outer_active(predicate: &[u8], element: usize, element_bytes: usize) -> bool {
    let bit = element * element_bytes;
    predicate[bit / BITS_PER_BYTE] & (1 << (bit % BITS_PER_BYTE)) != 0
}

fn outer_dot_kind(operand: &fp_matrix::OuterOperand) -> Result<Option<DotFormat>, CompletionError> {
    match (operand.numerical_kind, operand.destination, operand.input) {
        (OuterNumericalKind::FusedMultiplyAdd, destination, input) if destination == input => {
            Ok(None)
        }
        (
            OuterNumericalKind::HalfDotThenAdd,
            MatrixFormat::Float(Format::Single),
            MatrixFormat::Float(Format::Half),
        ) => Ok(Some(DotFormat::Half)),
        (
            OuterNumericalKind::BfloatDotThenAdd,
            MatrixFormat::Float(Format::Single),
            MatrixFormat::BFloat16,
        ) => Ok(Some(DotFormat::BFloat16)),
        _ => Err(anyhow::anyhow!("inconsistent floating outer-product format").into()),
    }
}

fn outer_negate_dot_member(kind: DotFormat, fpcr: u32, bits: u16) -> u16 {
    match kind {
        DotFormat::Half => floating::sign::negate(Format::Half, fpcr, u64::from(bits)) as u16,
        DotFormat::BFloat16 => {
            // BFMOPS (BF16->F32) explicitly sets honor_altfp=FALSE. Reuse the
            // architectural BFNeg helper with AH disabled for this transform.
            floating::bfloat16::arithmetic::negate(fpcr & !floating::FPCR_AH, bits)
        }
    }
}

fn complete_outer<'scratch>(
    state: &GuestState,
    scalable: &ScalableState,
    operand: &fp_matrix::OuterOperand,
    fpcr: u32,
    scratch: &'scratch mut [u8],
) -> Result<ZaResults<'scratch>, CompletionError> {
    let dot_kind = outer_dot_kind(operand)?;
    let length = scalable.vector_length();
    let element_bytes = operand.destination.element_size().bytes();
    let dimension = length.bytes() / element_bytes;
    if usize::from(operand.tile) >= element_bytes || dimension > MAX_ZA_ROWS {
        return Err(anyhow::anyhow!("floating outer-product tile is out of range").into());
    }

    // Snapshot both complete source vectors and predicate banks before staging
    // any output. Identical source registers are valid; no source bank is written.
    let left = read_z(state, scalable, operand.left)?;
    let right = read_z(state, scalable, operand.right)?;
    let mut row_predicate = [0; MAX_OUTER_PREDICATE_BYTES];
    let mut column_predicate = [0; MAX_OUTER_PREDICATE_BYTES];
    let predicate_bytes = length.predicate_bytes();
    scalable.read_predicate(operand.row_predicate, &mut row_predicate[..predicate_bytes])?;
    scalable.read_predicate(
        operand.column_predicate,
        &mut column_predicate[..predicate_bytes],
    )?;

    // A tile owns every element_bytes-th physical ZA byte-vector. Snapshot only
    // those rows, preserving aliases and untouched cells without cloning full ZA.
    let mut row_indices = [0; MAX_ZA_ROWS];
    for (row, physical) in row_indices.iter_mut().enumerate().take(dimension) {
        *physical = usize::from(operand.tile) + row * element_bytes;
    }
    let mut results = ZaResults::stage(scalable, &row_indices[..dimension], scratch)?;
    let operation = if operand.subtract {
        VectorOperation::MultiplySubtract
    } else {
        VectorOperation::MultiplyAdd
    };

    for row in 0..dimension {
        if let Some(kind) = dot_kind {
            let input_bytes = operand.input.element_size().bytes();
            let row_active = core::array::from_fn::<_, OUTER_DOT_MEMBERS, _>(|member| {
                outer_active(
                    &row_predicate,
                    OUTER_DOT_MEMBERS * row + member,
                    input_bytes,
                )
            });
            let mut row_pair = core::array::from_fn::<_, OUTER_DOT_MEMBERS, _>(|member| {
                if row_active[member] {
                    read_lane(&left, OUTER_DOT_MEMBERS * row + member, input_bytes) as u16
                } else {
                    0
                }
            });
            if operand.subtract {
                for member in 0..OUTER_DOT_MEMBERS {
                    if row_active[member] {
                        row_pair[member] = outer_negate_dot_member(kind, fpcr, row_pair[member]);
                    }
                }
            }
            for column in 0..dimension {
                let column_active = core::array::from_fn::<_, OUTER_DOT_MEMBERS, _>(|member| {
                    outer_active(
                        &column_predicate,
                        OUTER_DOT_MEMBERS * column + member,
                        input_bytes,
                    )
                });
                if !(0..OUTER_DOT_MEMBERS).any(|member| row_active[member] && column_active[member])
                {
                    continue;
                }
                // Mask each source independently. Negating masked +0 would
                // change signed-zero behavior; only active left members above
                // underwent the architectural subtraction transform.
                let column_pair = core::array::from_fn::<_, OUTER_DOT_MEMBERS, _>(|member| {
                    if column_active[member] {
                        read_lane(&right, OUTER_DOT_MEMBERS * column + member, input_bytes) as u16
                    } else {
                        0
                    }
                });
                let addend = read_lane(results.row(row), column, element_bytes) as u32;
                let bits = dot_lane(kind, fpcr, addend, row_pair, column_pair)?;
                write_lane(results.row_mut(row), column, element_bytes, u64::from(bits));
            }
        } else {
            if !outer_active(&row_predicate, row, element_bytes) {
                continue;
            }
            let left_bits = read_lane(&left, row, element_bytes);
            for column in 0..dimension {
                if !outer_active(&column_predicate, column, element_bytes) {
                    continue;
                }
                let addend = read_lane(results.row(row), column, element_bytes);
                let right_bits = read_lane(&right, column, element_bytes);
                let bits = numerical_lane(
                    operand.destination,
                    operation,
                    fpcr,
                    addend,
                    left_bits,
                    right_bits,
                )?;
                write_lane(results.row_mut(row), column, element_bytes, bits);
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests;
