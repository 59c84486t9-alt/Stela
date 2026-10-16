//! Transactional classic BF16 conversion, dot, multiply-add and matrix completion.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{
            FPCR_NEP, Format, UnsupportedControl,
            bfloat16::{self, BFLOAT16_BITS},
        },
        simd::{
            arithmetic::Shape,
            bfloat16::{
                ConversionMode, ConversionOperand, DotOperand, DotSource, MatrixOperand,
                MultiplyOperand, MultiplySource, Operand,
            },
        },
    },
};

use super::{VECTOR_LIMBS, read_lane, write_lane};

const PAIR_LANES: u32 = 2;
const SINGLE_VECTOR_LANES: u32 = Shape::Vector128.lane_count(Format::Single);
const UPPER_NARROW_START: u32 = u64::BITS / BFLOAT16_BITS;
const MATRIX_DIMENSION: u32 = 2;
const MATRIX_ROW_LANES: u32 = MATRIX_DIMENSION * PAIR_LANES;

fn pair(vector: &[u64; VECTOR_LIMBS], first: u32) -> [u16; PAIR_LANES as usize] {
    [
        read_lane(vector, BFLOAT16_BITS, first) as u16,
        read_lane(vector, BFLOAT16_BITS, first + 1) as u16,
    ]
}

fn conversion(
    state: &GuestState,
    operand: &ConversionOperand,
) -> Result<([u64; VECTOR_LIMBS], u32), UnsupportedControl> {
    let old = state.v[usize::from(operand.destination)];
    let source = state.v[usize::from(operand.source)];
    let (mut result, start, lanes) = match operand.mode {
        ConversionMode::Scalar => (
            if state.fpcr & FPCR_NEP != 0 {
                old
            } else {
                [0; VECTOR_LIMBS]
            },
            0,
            1,
        ),
        ConversionMode::Narrow { upper: false } => ([0; VECTOR_LIMBS], 0, SINGLE_VECTOR_LANES),
        ConversionMode::Narrow { upper: true } => {
            ([old[0], 0], UPPER_NARROW_START, SINGLE_VECTOR_LANES)
        }
    };
    let mut exceptions = 0;
    for lane in 0..lanes {
        let outcome = bfloat16::convert(
            state.fpcr,
            read_lane(&source, Format::Single.bits(), lane) as u32,
        )?;
        write_lane(&mut result, BFLOAT16_BITS, start + lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    Ok((result, exceptions))
}

fn dot(state: &GuestState, operand: &DotOperand) -> [u64; VECTOR_LIMBS] {
    let addend = state.v[usize::from(operand.destination)];
    let left = state.v[usize::from(operand.left)];
    let (register, index) = match operand.right {
        DotSource::Vector(register) => (register, None),
        DotSource::Indexed { register, index } => (register, Some(u32::from(index))),
    };
    let right = state.v[usize::from(register)];
    let mut result = [0; VECTOR_LIMBS];
    for lane in 0..operand.shape.lane_count(Format::Single) {
        let left_start = lane * PAIR_LANES;
        let right_start = index.map_or(left_start, |index| index * PAIR_LANES);
        let bits = bfloat16::dot_add(
            state.fpcr,
            read_lane(&addend, Format::Single.bits(), lane) as u32,
            pair(&left, left_start),
            pair(&right, right_start),
        );
        write_lane(&mut result, Format::Single.bits(), lane, u64::from(bits));
    }
    result
}

fn multiply_add(
    state: &GuestState,
    operand: &MultiplyOperand,
) -> Result<([u64; VECTOR_LIMBS], u32), UnsupportedControl> {
    let addend = state.v[usize::from(operand.destination)];
    let left = state.v[usize::from(operand.left)];
    let (register, index) = match operand.right {
        MultiplySource::Vector(register) => (register, None),
        MultiplySource::Indexed { register, index } => (register, Some(u32::from(index))),
    };
    let right = state.v[usize::from(register)];
    let mut result = [0; VECTOR_LIMBS];
    let mut exceptions = 0;
    for lane in 0..SINGLE_VECTOR_LANES {
        let left_lane = operand.parity.source_lane(lane);
        let outcome = bfloat16::multiply_add(
            state.fpcr,
            read_lane(&addend, Format::Single.bits(), lane) as u32,
            read_lane(&left, BFLOAT16_BITS, left_lane) as u16,
            read_lane(&right, BFLOAT16_BITS, index.unwrap_or(left_lane)) as u16,
        )?;
        write_lane(&mut result, Format::Single.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    Ok((result, exceptions))
}

fn matrix(state: &GuestState, operand: &MatrixOperand) -> [u64; VECTOR_LIMBS] {
    let addend = state.v[usize::from(operand.destination)];
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let mut result = [0; VECTOR_LIMBS];
    for row in 0..MATRIX_DIMENSION {
        for column in 0..MATRIX_DIMENSION {
            let lane = row * MATRIX_DIMENSION + column;
            let mut bits = read_lane(&addend, Format::Single.bits(), lane) as u32;
            for index in 0..MATRIX_DIMENSION {
                bits = bfloat16::dot_add(
                    state.fpcr,
                    bits,
                    pair(&left, row * MATRIX_ROW_LANES + index * PAIR_LANES),
                    pair(&right, column * MATRIX_ROW_LANES + index * PAIR_LANES),
                );
            }
            write_lane(&mut result, Format::Single.bits(), lane, u64::from(bits));
        }
    }
    result
}

pub(super) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let (destination, result, exceptions) = match operand {
        Operand::Conversion(operand) => {
            let (result, exceptions) = conversion(state, operand)?;
            (operand.destination, result, exceptions)
        }
        Operand::Dot(operand) => (operand.destination, dot(state, operand), 0),
        Operand::MultiplyAdd(operand) => {
            let (result, exceptions) = multiply_add(state, operand)?;
            (operand.destination, result, exceptions)
        }
        Operand::Matrix(operand) => (operand.destination, matrix(state, operand), 0),
    };
    state.v[usize::from(destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
