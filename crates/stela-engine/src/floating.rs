//! Software completion of scalar and AdvSIMD floating-point instructions, applied
//! to saved guest state as one transaction.
mod arithmetic;
mod bfloat16;
mod comparison;
mod complex;
mod estimate;
mod extrema_scale;
#[cfg(all(test, feature = "std", target_arch = "x86_64"))]
mod fused_native_tests;
mod minmax;
mod refinement;
mod rounding;
pub(crate) mod scalable;
mod sqrt;
mod widening;

use stela_compiler::{
    GuestState,
    aarch64::{
        FloatingPointOperation, Register,
        floating::{
            FPCR_NEP, UnsupportedControl, fused,
            integer::{self, IntegerRounding, IntegerWidth},
            precision,
        },
        simd::{
            arithmetic::Shape,
            conversion::{
                self, IntegerConversion, IntegerOperand, PrecisionMode, PrecisionOperand,
            },
        },
    },
};

const VECTOR_LIMBS: usize = 2;

fn read_lane(vector: &[u64; VECTOR_LIMBS], lane_bits: u32, lane: u32) -> u64 {
    let bit_offset = lane * lane_bits;
    let limb = (bit_offset / u64::BITS) as usize;
    let shift = bit_offset % u64::BITS;
    let lane_mask = u64::MAX >> (u64::BITS - lane_bits);
    (vector[limb] >> shift) & lane_mask
}

fn write_lane(vector: &mut [u64; VECTOR_LIMBS], lane_bits: u32, lane: u32, bits: u64) {
    let bit_offset = lane * lane_bits;
    let limb = (bit_offset / u64::BITS) as usize;
    let shift = bit_offset % u64::BITS;
    let lane_mask = u64::MAX >> (u64::BITS - lane_bits);
    vector[limb] = (vector[limb] & !(lane_mask << shift)) | ((bits & lane_mask) << shift);
}

pub(crate) fn complete(
    state: &mut GuestState,
    operation: &FloatingPointOperation,
) -> Result<(), UnsupportedControl> {
    let (destination, merge_register, left_register, right_register, right_lane, format, shape) =
        match operation {
            FloatingPointOperation::Binary(operand) => return arithmetic::complete(state, operand),
            FloatingPointOperation::Widening(operand) => return widening::complete(state, operand),
            FloatingPointOperation::BFloat16(operand) => return bfloat16::complete(state, operand),
            FloatingPointOperation::Complex(operand) => return complex::complete(state, operand),
            FloatingPointOperation::Fused(operand) => (
                operand.destination,
                operand.addend,
                operand.left,
                operand.right,
                operand.right_lane,
                operand.format,
                operand.shape,
            ),
            FloatingPointOperation::Conversion(operand) => {
                return complete_conversion(state, operand);
            }
            FloatingPointOperation::Comparison(operand) => {
                return comparison::complete(state, operand);
            }
            FloatingPointOperation::ExtremaScale(operand) => {
                return extrema_scale::complete(state, operand);
            }
            FloatingPointOperation::MinMax(operand) => return minmax::complete(state, operand),
            FloatingPointOperation::Rounding(operand) => return rounding::complete(state, operand),
            FloatingPointOperation::SquareRoot(operand) => return sqrt::complete(state, operand),
            FloatingPointOperation::Estimate(operand) => return estimate::complete(state, operand),
            FloatingPointOperation::Refinement(operand) => {
                return refinement::complete(state, operand);
            }
        };
    // Snapshot every source before evaluating any lane, including an indexed
    // source outside a vector64 destination's active lanes.
    let merge = state.v[usize::from(merge_register)];
    let left = state.v[usize::from(left_register)];
    let right = state.v[usize::from(right_register)];
    let mut result = if shape == Shape::Scalar && state.fpcr & FPCR_NEP != 0 {
        merge
    } else {
        [0; VECTOR_LIMBS]
    };
    let mut exceptions = 0;
    for lane in 0..shape.lane_count(format) {
        let left = read_lane(&left, format.bits(), lane);
        let right = read_lane(&right, format.bits(), right_lane.map_or(lane, u32::from));
        let outcome = match operation {
            FloatingPointOperation::Fused(operand) => fused::evaluate(
                format,
                operand.operation,
                state.fpcr,
                read_lane(&merge, format.bits(), lane),
                left,
                right,
            )?,
            FloatingPointOperation::Binary(_)
            | FloatingPointOperation::Widening(_)
            | FloatingPointOperation::BFloat16(_)
            | FloatingPointOperation::Complex(_)
            | FloatingPointOperation::Conversion(_)
            | FloatingPointOperation::Comparison(_)
            | FloatingPointOperation::ExtremaScale(_)
            | FloatingPointOperation::MinMax(_)
            | FloatingPointOperation::Rounding(_)
            | FloatingPointOperation::SquareRoot(_)
            | FloatingPointOperation::Estimate(_)
            | FloatingPointOperation::Refinement(_) => {
                unreachable!("non-arithmetic numerical family dispatched above")
            }
        };
        write_lane(&mut result, format.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

fn scalar_result(state: &GuestState, destination: u8) -> [u64; VECTOR_LIMBS] {
    if state.fpcr & FPCR_NEP != 0 {
        state.v[usize::from(destination)]
    } else {
        [0; VECTOR_LIMBS]
    }
}

fn complete_conversion(
    state: &mut GuestState,
    operand: &conversion::Operand,
) -> Result<(), UnsupportedControl> {
    match operand {
        conversion::Operand::Precision(operand) => complete_precision(state, operand),
        conversion::Operand::FromInteger(operand) => complete_from_integer(state, operand),
        conversion::Operand::ToInteger { operand, rounding } => {
            complete_to_integer(state, operand, *rounding)
        }
        conversion::Operand::JavaScript {
            destination,
            source,
        } => {
            let outcome = integer::to_javascript(state.fpcr, state.v[usize::from(*source)][0])?;
            write_register(
                state,
                *destination,
                outcome.result.bits & IntegerWidth::Bits32.mask(),
            );
            state.nzcv = outcome.nzcv;
            state.fpsr |= outcome.result.exceptions;
            Ok(())
        }
    }
}

fn complete_precision(
    state: &mut GuestState,
    operand: &PrecisionOperand,
) -> Result<(), UnsupportedControl> {
    let source = state.v[usize::from(operand.source)];
    let source_format = operand.mode.source_format();
    let destination_format = operand.mode.destination_format();
    let (mut result, source_start, destination_start, lanes, rounding) = match operand.mode {
        PrecisionMode::Scalar { rounding, .. } => {
            (scalar_result(state, operand.destination), 0, 0, 1, rounding)
        }
        PrecisionMode::Widen { upper, .. } => (
            [0; VECTOR_LIMBS],
            if upper {
                u64::BITS / source_format.bits()
            } else {
                0
            },
            0,
            Shape::Vector128.lane_count(destination_format),
            precision::PrecisionRounding::Fpcr,
        ),
        PrecisionMode::Narrow {
            upper, rounding, ..
        } => (
            if upper {
                [state.v[usize::from(operand.destination)][0], 0]
            } else {
                [0; VECTOR_LIMBS]
            },
            0,
            if upper {
                u64::BITS / destination_format.bits()
            } else {
                0
            },
            Shape::Vector128.lane_count(source_format),
            rounding,
        ),
    };
    let mut exceptions = 0;
    for lane in 0..lanes {
        let outcome = precision::evaluate(
            source_format,
            destination_format,
            rounding,
            state.fpcr,
            read_lane(&source, source_format.bits(), source_start + lane),
        )?;
        write_lane(
            &mut result,
            destination_format.bits(),
            destination_start + lane,
            outcome.bits,
        );
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

fn read_register(state: &GuestState, register: Register) -> u64 {
    match register {
        Register::X(index) => state.x[usize::from(index)],
        Register::Zero => 0,
        Register::Sp => unreachable!("conversion registers never denote SP"),
    }
}

fn write_register(state: &mut GuestState, register: Register, bits: u64) {
    match register {
        Register::X(index) => state.x[usize::from(index)] = bits,
        Register::Zero => {}
        Register::Sp => unreachable!("conversion registers never denote SP"),
    }
}

fn complete_from_integer(
    state: &mut GuestState,
    operand: &IntegerConversion,
) -> Result<(), UnsupportedControl> {
    let integer_format = operand.integer.format();
    let shape = operand.integer.shape();
    let source = match operand.integer {
        IntegerOperand::General { register, .. } => [read_register(state, register), 0],
        IntegerOperand::Simd { register, .. } => state.v[usize::from(register)],
    };
    let mut result = if shape == Shape::Scalar {
        scalar_result(state, operand.float)
    } else {
        [0; VECTOR_LIMBS]
    };
    let mut exceptions = 0;
    for lane in 0..shape.lane_count(operand.format) {
        let outcome = integer::from_integer(
            integer_format,
            operand.format,
            operand.frac_bits,
            state.fpcr,
            read_lane(&source, integer_format.width.bits(), lane),
        )?;
        write_lane(&mut result, operand.format.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.float)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

fn complete_to_integer(
    state: &mut GuestState,
    operand: &IntegerConversion,
    rounding: IntegerRounding,
) -> Result<(), UnsupportedControl> {
    let source = state.v[usize::from(operand.float)];
    let integer_format = operand.integer.format();
    let shape = operand.integer.shape();
    let mut result = match operand.integer {
        IntegerOperand::Simd {
            register,
            shape: Shape::Scalar,
            ..
        } => scalar_result(state, register),
        _ => [0; VECTOR_LIMBS],
    };
    let mut exceptions = 0;
    for lane in 0..shape.lane_count(operand.format) {
        let outcome = integer::to_integer(
            operand.format,
            integer_format,
            operand.frac_bits,
            rounding,
            state.fpcr,
            read_lane(&source, operand.format.bits(), lane),
        )?;
        write_lane(&mut result, integer_format.width.bits(), lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    match operand.integer {
        IntegerOperand::General { register, .. } => {
            write_register(state, register, result[0] & integer_format.width.mask())
        }
        IntegerOperand::Simd { register, .. } => state.v[usize::from(register)] = result,
    }
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests;
