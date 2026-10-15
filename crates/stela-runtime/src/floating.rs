//! Transactional scalar/vector numerical completion over saved guest state.
mod arithmetic;
mod bfloat16;
mod comparison;
mod complex;
mod estimate;
mod extrema_scale;
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
mod tests {
    use super::*;
    use stela_compiler::aarch64::floating::{
        BinaryOperation, DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AH, FPCR_AHP,
        FPCR_EXCEPTION_ENABLE_SHIFT, FPSR_QC, Format, INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW,
        UNDERFLOW, fused::FusedOperation,
    };
    use stela_compiler::aarch64::floating::{integer::IntegerFormat, precision::PrecisionRounding};
    use stela_compiler::aarch64::simd::{
        arithmetic::{Inputs, Operand},
        fused::Operand as FusedOperand,
    };

    const VECTOR_REGISTER_COUNT: usize = 32;
    const LAST_VECTOR_REGISTER: u8 = (VECTOR_REGISTER_COUNT - 1) as u8;
    const LOW_LIMB: usize = 0;
    const HIGH_LIMB: usize = 1;
    const RETAINED_FPSR_BITS: u32 = FPSR_QC | INEXACT | (1 << 31);
    const ALIASES: [(u8, u8, u8); 9] = [
        (0, 1, 2),
        (1, 1, 2),
        (2, 1, 2),
        (1, 1, 1),
        (0, 1, 1),
        (LAST_VECTOR_REGISTER, 1, 2),
        (0, LAST_VECTOR_REGISTER, 2),
        (0, 1, LAST_VECTOR_REGISTER),
        (
            LAST_VECTOR_REGISTER,
            LAST_VECTOR_REGISTER,
            LAST_VECTOR_REGISTER,
        ),
    ];
    const VECTOR_ARRANGEMENTS: [(Shape, Format); 5] = [
        (Shape::Vector64, Format::Half),
        (Shape::Vector128, Format::Half),
        (Shape::Vector64, Format::Single),
        (Shape::Vector128, Format::Single),
        (Shape::Vector128, Format::Double),
    ];
    const FORMATS: [(Format, u64, u64, u64, u64, u64); 3] = [
        (Format::Half, 0x3c00, 0x4000, 0x4200, 0x7c00, 0x7e00),
        (
            Format::Single,
            0x3f80_0000,
            0x4000_0000,
            0x4040_0000,
            0x7f80_0000,
            0x7fc0_0000,
        ),
        (
            Format::Double,
            0x3ff0_0000_0000_0000,
            0x4000_0000_0000_0000,
            0x4008_0000_0000_0000,
            0x7ff0_0000_0000_0000,
            0x7ff8_0000_0000_0000,
        ),
    ];

    fn initial_state() -> GuestState {
        GuestState {
            x: std::array::from_fn(|index| 0xdead_beef_1234_5678 ^ index as u64),
            sp: 0xfeed_0000_0000_0003,
            nzcv: 0xa000_0000,
            reserved: 0xa5c3_9e71,
            v: std::array::from_fn(|index| {
                [
                    0x89ab_cdef_0123_4567 ^ index as u64,
                    0xfedc_ba98_7654_3210 ^ ((index as u64) << 32),
                ]
            }),
            fpcr: FPCR_AHP,
            fpsr: RETAINED_FPSR_BITS,
        }
    }

    fn set_lane(state: &mut GuestState, register: u8, format: Format, bits: u64) {
        let mask = u64::MAX >> (u64::BITS - format.bits());
        let lane = &mut state.v[usize::from(register)][LOW_LIMB];
        *lane = (*lane & !mask) | bits;
    }

    fn write_vector_lane(vector: &mut [u64; VECTOR_LIMBS], format: Format, lane: u32, bits: u64) {
        let lane_bits = format.bits();
        let offset = lane * lane_bits;
        let limb = (offset / u64::BITS) as usize;
        let shift = offset % u64::BITS;
        let mask = u64::MAX >> (u64::BITS - lane_bits);
        vector[limb] = (vector[limb] & !(mask << shift)) | (bits << shift);
    }

    #[test]
    fn scalar_add_merges_original_left_and_handles_every_alias_role() {
        for (format, one, two, three, _, _) in FORMATS {
            for nep in [false, true] {
                for (destination, left, right) in ALIASES {
                    let mut state = initial_state();
                    state.fpcr |= if nep { FPCR_NEP } else { 0 };
                    set_lane(&mut state, left, format, one);
                    if right != left {
                        set_lane(&mut state, right, format, two);
                    }
                    let original_left = state.v[usize::from(left)];
                    let mut expected = state.clone();
                    let mut vector = if nep {
                        original_left
                    } else {
                        [0; VECTOR_LIMBS]
                    };
                    let mask = u64::MAX >> (u64::BITS - format.bits());
                    vector[LOW_LIMB] =
                        (vector[LOW_LIMB] & !mask) | if left == right { two } else { three };
                    expected.v[usize::from(destination)] = vector;
                    let operand = Operand {
                        operation: BinaryOperation::Add,
                        format,
                        shape: Shape::Scalar,
                        destination,
                        inputs: Inputs::Elementwise { left, right },
                    };
                    complete(&mut state, &operand.into()).unwrap();
                    assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                }
            }
        }
    }

    #[test]
    fn operation_selection_forwards_subtract_multiply_and_divide() {
        for (operation, result) in [
            (BinaryOperation::Subtract, 0xbf80_0000),
            (BinaryOperation::Multiply, 0x4000_0000),
            (BinaryOperation::Divide, 0x3f00_0000),
        ] {
            let mut state = initial_state();
            set_lane(&mut state, 1, Format::Single, 0x3f80_0000);
            set_lane(&mut state, 2, Format::Single, 0x4000_0000);
            let mut expected = state.clone();
            expected.v[usize::from(LAST_VECTOR_REGISTER)] = [result, 0];
            complete(
                &mut state,
                &Operand {
                    operation,
                    format: Format::Single,
                    shape: Shape::Scalar,
                    destination: LAST_VECTOR_REGISTER,
                    inputs: Inputs::Elementwise { left: 1, right: 2 },
                }
                .into(),
            )
            .unwrap();
            assert_eq!(state, expected, "{operation:?}");
        }
    }

    #[test]
    fn exception_bits_are_sticky_and_other_state_survives() {
        for (format, one, _, _, infinity, default_nan) in FORMATS {
            for (left, result, exception) in
                [(one, infinity, DIVIDE_BY_ZERO), (0, default_nan, INVALID)]
            {
                let mut state = initial_state();
                set_lane(&mut state, 1, format, left);
                set_lane(&mut state, 2, format, 0);
                let mut expected = state.clone();
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = [result, 0];
                expected.fpsr |= exception;
                let operand = Operand {
                    operation: BinaryOperation::Divide,
                    format,
                    shape: Shape::Scalar,
                    destination: LAST_VECTOR_REGISTER,
                    inputs: Inputs::Elementwise { left: 1, right: 2 },
                };
                complete(&mut state, &operand.into()).unwrap();
                assert_eq!(state, expected, "{operand:?}, exception={exception:#x}");
            }
        }
    }

    #[test]
    fn unsupported_controls_leave_complete_state_unchanged() {
        for (format, ..) in FORMATS {
            for enabled in [
                INVALID,
                DIVIDE_BY_ZERO,
                OVERFLOW,
                UNDERFLOW,
                INEXACT,
                INPUT_DENORMAL,
                EXCEPTIONS,
            ] {
                for nep in [false, true] {
                    let mut state = initial_state();
                    state.fpcr |= enabled << FPCR_EXCEPTION_ENABLE_SHIFT;
                    state.fpcr |= if nep { FPCR_NEP } else { 0 };
                    let expected = state.clone();
                    let operand = Operand {
                        operation: BinaryOperation::Multiply,
                        format,
                        shape: Shape::Scalar,
                        destination: LAST_VECTOR_REGISTER,
                        inputs: Inputs::Elementwise {
                            left: LAST_VECTOR_REGISTER,
                            right: LAST_VECTOR_REGISTER,
                        },
                    };
                    assert_eq!(
                        complete(&mut state, &operand.into()),
                        Err(UnsupportedControl {
                            enabled_exceptions: enabled
                        })
                    );
                    assert_eq!(state, expected);
                }
            }
        }
    }

    #[test]
    fn vector_lanes_snapshot_aliases_and_ignore_nep_and_inactive_upper_bits() {
        for (shape, format) in VECTOR_ARRANGEMENTS {
            let (_, one, two, ..) = FORMATS.iter().copied().find(|row| row.0 == format).unwrap();
            let exponent_unit = two - one;
            for nep in [false, true] {
                for (destination, left, right) in ALIASES {
                    let mut state = initial_state();
                    state.fpcr |= if nep { FPCR_NEP } else { 0 };
                    let mut expected_vector = [0; VECTOR_LIMBS];
                    for lane in 0..shape.lane_count(format) {
                        // Different powers of two in every lane expose stale
                        // limbs, reversed lanes and early aliased-source writes.
                        let left_bits = one + u64::from(lane) * exponent_unit;
                        write_vector_lane(&mut state.v[usize::from(left)], format, lane, left_bits);
                        if left != right {
                            write_vector_lane(&mut state.v[usize::from(right)], format, lane, one);
                        }
                        let sum = if left == right {
                            left_bits + exponent_unit
                        } else if lane == 0 {
                            two
                        } else {
                            left_bits + (exponent_unit >> lane)
                        };
                        write_vector_lane(&mut expected_vector, format, lane, sum);
                    }
                    if shape == Shape::Vector64 {
                        let inactive_snan = match format {
                            Format::Half => 0x7c01_7c01_7c01_7c01,
                            Format::Single => 0x7f80_0001_7f80_0001,
                            Format::Double => unreachable!("no vector64 double arrangement"),
                        };
                        state.v[usize::from(left)][HIGH_LIMB] = inactive_snan;
                        state.v[usize::from(right)][HIGH_LIMB] = inactive_snan;
                    }
                    let mut expected = state.clone();
                    expected.v[usize::from(destination)] = expected_vector;
                    let operand = Operand {
                        operation: BinaryOperation::Add,
                        format,
                        shape,
                        destination,
                        inputs: Inputs::Elementwise { left, right },
                    };
                    complete(&mut state, &operand.into()).unwrap();
                    assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                }
            }
        }
    }

    #[test]
    fn vector_exception_union_is_committed_with_the_complete_result() {
        let left_lanes = [0x7f7f_ffff, 0x0080_0000, 0x3f80_0000, 0];
        let right_lanes = [0x0080_0000, 0x7f7f_ffff, 0, 0];
        // Packed independently: +infinity, +zero, +infinity, default quiet NaN.
        let result_vector = [0x0000_0000_7f80_0000, 0x7fc0_0000_7f80_0000];
        for destination in [0, 1, 2, LAST_VECTOR_REGISTER] {
            let mut state = initial_state();
            state.fpcr |= FPCR_NEP;
            state.fpsr &= !EXCEPTIONS;
            for lane in 0..Shape::Vector128.lane_count(Format::Single) {
                let index = lane as usize;
                write_vector_lane(&mut state.v[1], Format::Single, lane, left_lanes[index]);
                write_vector_lane(&mut state.v[2], Format::Single, lane, right_lanes[index]);
            }
            let mut expected = state.clone();
            expected.v[usize::from(destination)] = result_vector;
            expected.fpsr |= OVERFLOW | UNDERFLOW | INEXACT | DIVIDE_BY_ZERO | INVALID;
            complete(
                &mut state,
                &Operand {
                    operation: BinaryOperation::Divide,
                    format: Format::Single,
                    shape: Shape::Vector128,
                    destination,
                    inputs: Inputs::Elementwise { left: 1, right: 2 },
                }
                .into(),
            )
            .unwrap();
            assert_eq!(state, expected, "destination={destination}");
        }
    }

    #[test]
    fn unsupported_vector_controls_preserve_all_sources_destination_and_status() {
        for (shape, format) in VECTOR_ARRANGEMENTS {
            for enabled in [
                INVALID,
                DIVIDE_BY_ZERO,
                OVERFLOW,
                UNDERFLOW,
                INEXACT,
                INPUT_DENORMAL,
                EXCEPTIONS,
            ] {
                for (destination, left, right) in ALIASES {
                    let mut state = initial_state();
                    state.fpcr |= FPCR_NEP | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                    let expected = state.clone();
                    let operand = Operand {
                        operation: BinaryOperation::Multiply,
                        format,
                        shape,
                        destination,
                        inputs: Inputs::Elementwise { left, right },
                    };
                    assert_eq!(
                        complete(&mut state, &operand.into()),
                        Err(UnsupportedControl {
                            enabled_exceptions: enabled
                        })
                    );
                    assert_eq!(state, expected, "{operand:?}");
                }
            }
        }
    }

    // The fifteen equality partitions cover all four operand roles; the final
    // cases place V31 in each role and in the fully aliased instruction.
    const FUSED_ALIASES: [(u8, u8, u8, u8); 20] = [
        (0, 1, 2, 3),
        (1, 1, 2, 3),
        (2, 1, 2, 3),
        (3, 1, 2, 3),
        (0, 1, 1, 3),
        (0, 1, 2, 1),
        (0, 1, 2, 2),
        (1, 1, 2, 2),
        (2, 1, 2, 1),
        (2, 1, 1, 2),
        (1, 1, 1, 2),
        (1, 1, 2, 1),
        (1, 2, 1, 1),
        (0, 1, 1, 1),
        (1, 1, 1, 1),
        (LAST_VECTOR_REGISTER, 1, 2, 3),
        (0, LAST_VECTOR_REGISTER, 2, 3),
        (0, 1, LAST_VECTOR_REGISTER, 3),
        (0, 1, 2, LAST_VECTOR_REGISTER),
        (
            LAST_VECTOR_REGISTER,
            LAST_VECTOR_REGISTER,
            LAST_VECTOR_REGISTER,
            LAST_VECTOR_REGISTER,
        ),
    ];
    const FUSED_OPERATIONS: [FusedOperation; 4] = [
        FusedOperation::Add,
        FusedOperation::Subtract,
        FusedOperation::NegatedAdd,
        FusedOperation::NegatedSubtract,
    ];
    const INDEXED_HALF_LAST_REGISTER: u8 = 15;

    fn small_integer_bits(format: Format, value: i32) -> u64 {
        let positive = match format {
            Format::Half => [0, 0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600],
            Format::Single => [
                0,
                0x3f80_0000,
                0x4000_0000,
                0x4040_0000,
                0x4080_0000,
                0x40a0_0000,
                0x40c0_0000,
            ],
            Format::Double => [
                0,
                0x3ff0_0000_0000_0000,
                0x4000_0000_0000_0000,
                0x4008_0000_0000_0000,
                0x4010_0000_0000_0000,
                0x4014_0000_0000_0000,
                0x4018_0000_0000_0000,
            ],
        };
        positive[value.unsigned_abs() as usize]
            | if value < 0 {
                1 << (format.bits() - 1)
            } else {
                0
            }
    }

    fn source_integer(register: u8, lane: u32) -> i32 {
        1 + ((u32::from(register) + lane) % 2) as i32
    }

    fn integer_fused(operation: FusedOperation, addend: i32, left: i32, right: i32) -> i32 {
        match operation {
            FusedOperation::Add => addend + left * right,
            FusedOperation::Subtract => addend - left * right,
            FusedOperation::NegatedAdd => -addend - left * right,
            FusedOperation::NegatedSubtract => -addend + left * right,
        }
    }

    fn fused_state(format: Format) -> GuestState {
        let mut state = initial_state();
        for register in 0..VECTOR_REGISTER_COUNT {
            for lane in 0..Shape::Vector128.lane_count(format) {
                write_vector_lane(
                    &mut state.v[register],
                    format,
                    lane,
                    small_integer_bits(format, source_integer(register as u8, lane)),
                );
            }
        }
        state
    }

    #[test]
    fn scalar_fused_merges_addend_and_snapshots_all_four_register_roles() {
        for (format, ..) in FORMATS {
            for operation in FUSED_OPERATIONS {
                for nep in [false, true] {
                    for (destination, addend, left, right) in FUSED_ALIASES {
                        let mut state = fused_state(format);
                        state.fpcr |= if nep { FPCR_NEP } else { 0 };
                        let mut expected = state.clone();
                        let mut vector = if nep {
                            state.v[usize::from(addend)]
                        } else {
                            [0; VECTOR_LIMBS]
                        };
                        let result = integer_fused(
                            operation,
                            source_integer(addend, 0),
                            source_integer(left, 0),
                            source_integer(right, 0),
                        );
                        write_vector_lane(
                            &mut vector,
                            format,
                            0,
                            small_integer_bits(format, result),
                        );
                        expected.v[usize::from(destination)] = vector;
                        let operand = FusedOperand {
                            operation,
                            format,
                            shape: Shape::Scalar,
                            destination,
                            addend,
                            left,
                            right,
                            right_lane: None,
                        };
                        complete(&mut state, &operand.into()).unwrap();
                        assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                    }
                }
            }
        }
    }

    #[test]
    fn vector_fused_snapshots_accumulator_and_ignores_nep_and_inactive_lanes() {
        for (shape, format) in VECTOR_ARRANGEMENTS {
            for operation in [FusedOperation::Add, FusedOperation::Subtract] {
                for nep in [false, true] {
                    for (destination, left, right) in ALIASES {
                        let mut state = fused_state(format);
                        state.fpcr |= if nep { FPCR_NEP } else { 0 };
                        if shape == Shape::Vector64 {
                            let inactive_snan = match format {
                                Format::Half => 0x7c01_7c01_7c01_7c01,
                                Format::Single => 0x7f80_0001_7f80_0001,
                                Format::Double => unreachable!(),
                            };
                            for register in [destination, left, right] {
                                state.v[usize::from(register)][HIGH_LIMB] = inactive_snan;
                            }
                        }
                        let mut expected = state.clone();
                        let mut vector = [0; VECTOR_LIMBS];
                        for lane in 0..shape.lane_count(format) {
                            let result = integer_fused(
                                operation,
                                source_integer(destination, lane),
                                source_integer(left, lane),
                                source_integer(right, lane),
                            );
                            write_vector_lane(
                                &mut vector,
                                format,
                                lane,
                                small_integer_bits(format, result),
                            );
                        }
                        expected.v[usize::from(destination)] = vector;
                        let operand = FusedOperand {
                            operation,
                            format,
                            shape,
                            destination,
                            addend: destination,
                            left,
                            right,
                            right_lane: None,
                        };
                        complete(&mut state, &operand.into()).unwrap();
                        assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                    }
                }
            }
        }
    }

    #[test]
    fn indexed_fused_reads_high_source_lanes_before_aliased_destination_commits() {
        for (format, ..) in FORMATS {
            let right = if format == Format::Half {
                INDEXED_HALF_LAST_REGISTER
            } else {
                LAST_VECTOR_REGISTER
            };
            let right_lane = (Shape::Vector128.lane_count(format) - 1) as u8;
            for shape in [Shape::Scalar, Shape::Vector64, Shape::Vector128] {
                if shape == Shape::Vector64 && format == Format::Double {
                    continue;
                }
                for operation in [FusedOperation::Add, FusedOperation::Subtract] {
                    for nep in [false, true] {
                        for (destination, left) in [(0, 1), (right, 1), (0, right), (right, right)]
                        {
                            let mut state = fused_state(format);
                            state.fpcr |= if nep { FPCR_NEP } else { 0 };
                            let mut expected = state.clone();
                            let mut vector = if shape == Shape::Scalar && nep {
                                state.v[usize::from(destination)]
                            } else {
                                [0; VECTOR_LIMBS]
                            };
                            for lane in 0..shape.lane_count(format) {
                                let result = integer_fused(
                                    operation,
                                    source_integer(destination, lane),
                                    source_integer(left, lane),
                                    source_integer(right, u32::from(right_lane)),
                                );
                                write_vector_lane(
                                    &mut vector,
                                    format,
                                    lane,
                                    small_integer_bits(format, result),
                                );
                            }
                            expected.v[usize::from(destination)] = vector;
                            let operand = FusedOperand {
                                operation,
                                format,
                                shape,
                                destination,
                                addend: destination,
                                left,
                                right,
                                right_lane: Some(right_lane),
                            };
                            complete(&mut state, &operand.into()).unwrap();
                            assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn indexed_fused_does_not_evaluate_unselected_signaling_nan_lanes() {
        for (format, one, two, three, infinity, _) in FORMATS {
            let right = if format == Format::Half {
                INDEXED_HALF_LAST_REGISTER
            } else {
                LAST_VECTOR_REGISTER
            };
            let right_lane = (Shape::Vector128.lane_count(format) - 1) as u8;
            for shape in [Shape::Scalar, Shape::Vector64, Shape::Vector128] {
                if shape == Shape::Vector64 && format == Format::Double {
                    continue;
                }
                let mut state = initial_state();
                for lane in 0..Shape::Vector128.lane_count(format) {
                    write_vector_lane(&mut state.v[0], format, lane, one);
                    write_vector_lane(&mut state.v[1], format, lane, one);
                    write_vector_lane(&mut state.v[usize::from(right)], format, lane, infinity | 1);
                }
                write_vector_lane(
                    &mut state.v[usize::from(right)],
                    format,
                    u32::from(right_lane),
                    two,
                );
                let mut expected = state.clone();
                let mut vector = [0; VECTOR_LIMBS];
                for lane in 0..shape.lane_count(format) {
                    write_vector_lane(&mut vector, format, lane, three);
                }
                expected.v[0] = vector;
                let operand = FusedOperand {
                    operation: FusedOperation::Add,
                    format,
                    shape,
                    destination: 0,
                    addend: 0,
                    left: 1,
                    right,
                    right_lane: Some(right_lane),
                };
                complete(&mut state, &operand.into()).unwrap();
                assert_eq!(state, expected, "{operand:?}");
            }
        }
    }

    #[test]
    fn fused_exception_union_is_sticky_and_committed_with_all_lanes() {
        let addends = [0, 0, 0x3f80_0000, 0];
        let left_lanes = [0x7f7f_ffff, 0x0080_0000, 0, 1];
        let right_lanes = [0x4000_0000, 0x0080_0000, 0x7f80_0000, 0x3f80_0000];
        for destination in [0, 1, 2, 3, LAST_VECTOR_REGISTER] {
            let mut state = initial_state();
            state.fpcr |= FPCR_AH;
            state.fpsr &= !EXCEPTIONS;
            for lane in 0..Shape::Vector128.lane_count(Format::Single) {
                let index = lane as usize;
                for (register, bits) in [
                    (1, addends[index]),
                    (2, left_lanes[index]),
                    (3, right_lanes[index]),
                ] {
                    write_vector_lane(&mut state.v[register], Format::Single, lane, bits);
                }
            }
            let mut expected = state.clone();
            expected.v[usize::from(destination)] = [0x0000_0000_7f80_0000, 0x0000_0001_ffc0_0000];
            expected.fpsr |= OVERFLOW | UNDERFLOW | INEXACT | INVALID | INPUT_DENORMAL;
            let operand = FusedOperand {
                operation: FusedOperation::Add,
                format: Format::Single,
                shape: Shape::Vector128,
                destination,
                addend: 1,
                left: 2,
                right: 3,
                right_lane: None,
            };
            complete(&mut state, &operand.into()).unwrap();
            assert_eq!(state, expected, "destination={destination}");
        }
    }

    #[test]
    fn unsupported_fused_controls_preserve_the_complete_state() {
        let arrangements = [
            (Shape::Scalar, Format::Half),
            (Shape::Scalar, Format::Single),
            (Shape::Scalar, Format::Double),
        ]
        .into_iter()
        .chain(VECTOR_ARRANGEMENTS);
        for (shape, format) in arrangements {
            for enabled in [
                INVALID,
                DIVIDE_BY_ZERO,
                OVERFLOW,
                UNDERFLOW,
                INEXACT,
                INPUT_DENORMAL,
                EXCEPTIONS,
            ] {
                for (destination, addend, left, right) in FUSED_ALIASES {
                    let mut state = fused_state(format);
                    state.fpcr |= FPCR_NEP | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                    let expected = state.clone();
                    let operand = FusedOperand {
                        operation: FusedOperation::Add,
                        format,
                        shape,
                        destination,
                        addend,
                        left,
                        right,
                        right_lane: Some((Shape::Vector128.lane_count(format) - 1) as u8),
                    };
                    assert_eq!(
                        complete(&mut state, &operand.into()),
                        Err(UnsupportedControl {
                            enabled_exceptions: enabled
                        })
                    );
                    assert_eq!(state, expected, "{operand:?}");
                }
            }
        }
    }

    const CONVERSION_ALIASES: [(u8, u8); 5] = [
        (0, 1),
        (1, 1),
        (LAST_VECTOR_REGISTER, 1),
        (0, LAST_VECTOR_REGISTER),
        (LAST_VECTOR_REGISTER, LAST_VECTOR_REGISTER),
    ];

    fn conversion_state() -> GuestState {
        let mut state = initial_state();
        state.fpcr &= !FPCR_AHP;
        state.fpsr &= !EXCEPTIONS;
        state
    }

    fn integer_format(format: Format, signed: bool) -> IntegerFormat {
        IntegerFormat {
            signed,
            width: match format {
                Format::Half => IntegerWidth::Bits16,
                Format::Single => IntegerWidth::Bits32,
                Format::Double => IntegerWidth::Bits64,
            },
        }
    }

    #[test]
    fn scalar_precision_merges_old_destination_for_every_format_pair_and_alias() {
        for (source_format, ..) in FORMATS {
            for (destination_format, ..) in FORMATS {
                if source_format == destination_format {
                    continue;
                }
                for nep in [false, true] {
                    for (destination, source) in CONVERSION_ALIASES {
                        let mut state = conversion_state();
                        state.fpcr |= if nep { FPCR_NEP } else { 0 };
                        set_lane(
                            &mut state,
                            source,
                            source_format,
                            small_integer_bits(source_format, 3),
                        );
                        let mut expected = state.clone();
                        let mut vector = if nep {
                            state.v[usize::from(destination)]
                        } else {
                            [0; VECTOR_LIMBS]
                        };
                        write_vector_lane(
                            &mut vector,
                            destination_format,
                            0,
                            small_integer_bits(destination_format, 3),
                        );
                        expected.v[usize::from(destination)] = vector;
                        let operand = conversion::Operand::Precision(PrecisionOperand {
                            destination,
                            source,
                            mode: PrecisionMode::Scalar {
                                source: source_format,
                                destination: destination_format,
                                rounding: PrecisionRounding::Fpcr,
                            },
                        });
                        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                        assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                    }
                }
            }
        }
    }

    #[test]
    fn widening_selects_source_half_before_aliasing_and_fills_all_destination_lanes() {
        for (source_format, destination_format) in [
            (Format::Half, Format::Single),
            (Format::Single, Format::Double),
        ] {
            for upper in [false, true] {
                for nep in [false, true] {
                    for (destination, source) in CONVERSION_ALIASES {
                        let mut state = conversion_state();
                        state.fpcr |= if nep { FPCR_NEP } else { 0 };
                        for lane in 0..Shape::Vector128.lane_count(source_format) {
                            write_vector_lane(
                                &mut state.v[usize::from(source)],
                                source_format,
                                lane,
                                small_integer_bits(source_format, 1 + (lane % 6) as i32),
                            );
                        }
                        let mut expected = state.clone();
                        let mut vector = [0; VECTOR_LIMBS];
                        let source_start = if upper {
                            u64::BITS / source_format.bits()
                        } else {
                            0
                        };
                        for lane in 0..Shape::Vector128.lane_count(destination_format) {
                            write_vector_lane(
                                &mut vector,
                                destination_format,
                                lane,
                                small_integer_bits(
                                    destination_format,
                                    1 + ((source_start + lane) % 6) as i32,
                                ),
                            );
                        }
                        expected.v[usize::from(destination)] = vector;
                        let operand = conversion::Operand::Precision(PrecisionOperand {
                            destination,
                            source,
                            mode: PrecisionMode::Widen {
                                source: source_format,
                                upper,
                            },
                        });
                        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                        assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                    }
                }
            }
        }
    }

    #[test]
    fn widening_does_not_evaluate_the_unselected_source_half() {
        for (source_format, destination_format, signaling_nan) in [
            (Format::Half, Format::Single, 0x7c01),
            (Format::Single, Format::Double, 0x7f80_0001),
        ] {
            for upper in [false, true] {
                let mut state = conversion_state();
                for lane in 0..Shape::Vector128.lane_count(source_format) {
                    let in_upper = lane >= u64::BITS / source_format.bits();
                    let bits = if in_upper == upper {
                        small_integer_bits(source_format, 1)
                    } else {
                        signaling_nan
                    };
                    write_vector_lane(
                        &mut state.v[usize::from(LAST_VECTOR_REGISTER)],
                        source_format,
                        lane,
                        bits,
                    );
                }
                let mut expected = state.clone();
                let mut vector = [0; VECTOR_LIMBS];
                for lane in 0..Shape::Vector128.lane_count(destination_format) {
                    write_vector_lane(
                        &mut vector,
                        destination_format,
                        lane,
                        small_integer_bits(destination_format, 1),
                    );
                }
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = vector;
                let operand = conversion::Operand::Precision(PrecisionOperand {
                    destination: LAST_VECTOR_REGISTER,
                    source: LAST_VECTOR_REGISTER,
                    mode: PrecisionMode::Widen {
                        source: source_format,
                        upper,
                    },
                });
                complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                assert_eq!(state, expected, "{operand:?}");
            }
        }
    }

    #[test]
    fn narrowing_places_result_in_requested_half_and_preserves_only_upper_form_low_half() {
        for (source_format, destination_format) in [
            (Format::Single, Format::Half),
            (Format::Double, Format::Single),
        ] {
            for upper in [false, true] {
                for rounding in [PrecisionRounding::Fpcr, PrecisionRounding::ToOdd] {
                    if rounding == PrecisionRounding::ToOdd && destination_format == Format::Half {
                        continue;
                    }
                    for (destination, source) in CONVERSION_ALIASES {
                        let mut state = conversion_state();
                        state.fpcr |= FPCR_NEP;
                        for lane in 0..Shape::Vector128.lane_count(source_format) {
                            write_vector_lane(
                                &mut state.v[usize::from(source)],
                                source_format,
                                lane,
                                small_integer_bits(source_format, 1 + lane as i32),
                            );
                        }
                        let mut expected = state.clone();
                        let mut vector = if upper {
                            [state.v[usize::from(destination)][LOW_LIMB], 0]
                        } else {
                            [0; VECTOR_LIMBS]
                        };
                        let destination_start = if upper {
                            u64::BITS / destination_format.bits()
                        } else {
                            0
                        };
                        for lane in 0..Shape::Vector128.lane_count(source_format) {
                            write_vector_lane(
                                &mut vector,
                                destination_format,
                                destination_start + lane,
                                small_integer_bits(destination_format, 1 + lane as i32),
                            );
                        }
                        expected.v[usize::from(destination)] = vector;
                        let operand = conversion::Operand::Precision(PrecisionOperand {
                            destination,
                            source,
                            mode: PrecisionMode::Narrow {
                                destination: destination_format,
                                upper,
                                rounding,
                            },
                        });
                        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                        assert_eq!(state, expected, "{operand:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn narrowing_unions_status_and_odd_rounding_retains_a_low_significand_bit() {
        let mut state = conversion_state();
        state.v[1] = [0x0080_0000_7f7f_ffff, 0x3f80_0000_7f80_0001];
        let mut expected = state.clone();
        expected.v[1] = [0x3c00_7e00_0000_7c00, 0];
        expected.fpsr |= OVERFLOW | UNDERFLOW | INEXACT | INVALID;
        let operand = conversion::Operand::Precision(PrecisionOperand {
            destination: 1,
            source: 1,
            mode: PrecisionMode::Narrow {
                destination: Format::Half,
                upper: false,
                rounding: PrecisionRounding::Fpcr,
            },
        });
        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
        assert_eq!(state, expected);

        let mut state = conversion_state();
        state.v[1] = [0x3ff0_0000_1000_0000, 0x3ff0_0000_1000_0000];
        let mut expected = state.clone();
        expected.v[0] = [0x3f80_0001_3f80_0001, 0];
        expected.fpsr |= INEXACT;
        let operand = conversion::Operand::Precision(PrecisionOperand {
            destination: 0,
            source: 1,
            mode: PrecisionMode::Narrow {
                destination: Format::Single,
                upper: false,
                rounding: PrecisionRounding::ToOdd,
            },
        });
        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
        assert_eq!(state, expected);
    }

    #[test]
    fn general_integer_inputs_mask_w_sources_and_read_zero_without_touching_sp() {
        for (register, integer, bits, result) in [
            (
                Register::X(3),
                IntegerFormat {
                    width: IntegerWidth::Bits32,
                    signed: false,
                },
                0xdead_beef_0000_0003,
                0x4040_0000,
            ),
            (
                Register::X(3),
                IntegerFormat {
                    width: IntegerWidth::Bits64,
                    signed: true,
                },
                u64::MAX,
                0xbf80_0000,
            ),
            (
                Register::Zero,
                IntegerFormat {
                    width: IntegerWidth::Bits64,
                    signed: false,
                },
                0,
                0,
            ),
        ] {
            for nep in [false, true] {
                let mut state = conversion_state();
                state.fpcr |= if nep { FPCR_NEP } else { 0 };
                state.x[3] = bits;
                let mut expected = state.clone();
                let mut vector = if nep {
                    state.v[usize::from(LAST_VECTOR_REGISTER)]
                } else {
                    [0; VECTOR_LIMBS]
                };
                write_vector_lane(&mut vector, Format::Single, 0, result);
                expected.v[usize::from(LAST_VECTOR_REGISTER)] = vector;
                let operand = conversion::Operand::FromInteger(IntegerConversion {
                    integer: IntegerOperand::General {
                        register,
                        format: integer,
                    },
                    float: LAST_VECTOR_REGISTER,
                    format: Format::Single,
                    frac_bits: 0,
                });
                complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                assert_eq!(state, expected, "{operand:?}, NEP={nep}");
            }
        }
    }

    #[test]
    fn general_integer_results_zero_extend_w_and_discard_zr_with_sticky_status() {
        for destination in [Register::X(0), Register::X(30), Register::Zero] {
            let mut state = conversion_state();
            set_lane(
                &mut state,
                LAST_VECTOR_REGISTER,
                Format::Single,
                0x4060_0000,
            );
            let mut expected = state.clone();
            if let Register::X(index) = destination {
                expected.x[usize::from(index)] = 3;
            }
            expected.fpsr |= INEXACT;
            let operand = conversion::Operand::ToInteger {
                operand: IntegerConversion {
                    integer: IntegerOperand::General {
                        register: destination,
                        format: IntegerFormat {
                            width: IntegerWidth::Bits32,
                            signed: true,
                        },
                    },
                    float: LAST_VECTOR_REGISTER,
                    format: Format::Single,
                    frac_bits: 0,
                },
                rounding: IntegerRounding::TowardZero,
            };
            complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
            assert_eq!(state, expected, "{operand:?}");
        }
    }

    #[test]
    fn simd_integer_conversions_snapshot_aliases_respect_shape_and_forward_scaling() {
        let arrangements = [
            (Shape::Scalar, Format::Half),
            (Shape::Scalar, Format::Single),
            (Shape::Scalar, Format::Double),
        ]
        .into_iter()
        .chain(VECTOR_ARRANGEMENTS);
        for (shape, format) in arrangements {
            for signed in [false, true] {
                for nep in [false, true] {
                    for (destination, source) in CONVERSION_ALIASES {
                        let mut state = conversion_state();
                        state.fpcr |= if nep { FPCR_NEP } else { 0 };
                        let integer = integer_format(format, signed);
                        let value = if signed {
                            -3i64 as u64 & integer.width.mask()
                        } else {
                            3
                        };
                        for lane in 0..shape.lane_count(format) {
                            write_vector_lane(
                                &mut state.v[usize::from(source)],
                                format,
                                lane,
                                value,
                            );
                        }
                        let mut expected = state.clone();
                        let mut vector = if shape == Shape::Scalar && nep {
                            state.v[usize::from(destination)]
                        } else {
                            [0; VECTOR_LIMBS]
                        };
                        let (_, one, two, ..) =
                            FORMATS.into_iter().find(|row| row.0 == format).unwrap();
                        let result = (one + ((two - one) >> 1))
                            | if signed { 1 << (format.bits() - 1) } else { 0 };
                        for lane in 0..shape.lane_count(format) {
                            write_vector_lane(&mut vector, format, lane, result);
                        }
                        expected.v[usize::from(destination)] = vector;
                        let operand = conversion::Operand::FromInteger(IntegerConversion {
                            integer: IntegerOperand::Simd {
                                register: source,
                                format: integer,
                                shape,
                            },
                            float: destination,
                            format,
                            frac_bits: 1,
                        });
                        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                        assert_eq!(state, expected, "{operand:?}, NEP={nep}");

                        let mut state = conversion_state();
                        state.fpcr |= if nep { FPCR_NEP } else { 0 };
                        for lane in 0..shape.lane_count(format) {
                            write_vector_lane(
                                &mut state.v[usize::from(source)],
                                format,
                                lane,
                                result,
                            );
                        }
                        let mut expected = state.clone();
                        let mut vector = if shape == Shape::Scalar && nep {
                            state.v[usize::from(destination)]
                        } else {
                            [0; VECTOR_LIMBS]
                        };
                        for lane in 0..shape.lane_count(format) {
                            write_vector_lane(&mut vector, format, lane, value);
                        }
                        expected.v[usize::from(destination)] = vector;
                        let operand = conversion::Operand::ToInteger {
                            operand: IntegerConversion {
                                integer: IntegerOperand::Simd {
                                    register: destination,
                                    format: integer,
                                    shape,
                                },
                                float: source,
                                format,
                                frac_bits: 1,
                            },
                            rounding: IntegerRounding::TowardZero,
                        };
                        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                        assert_eq!(state, expected, "{operand:?}, NEP={nep}");
                    }
                }
            }
        }
    }

    #[test]
    fn integer_rounding_selection_and_vector_status_union_are_preserved() {
        for (rounding, positive, negative) in [
            (IntegerRounding::NearestEven, 2, -2i64),
            (IntegerRounding::NearestAway, 3, -3),
            (IntegerRounding::TowardPositive, 3, -2),
            (IntegerRounding::TowardNegative, 2, -3),
            (IntegerRounding::TowardZero, 2, -2),
        ] {
            for (source, result) in [
                (0x4004_0000_0000_0000, positive),
                (0xc004_0000_0000_0000, negative as u64),
            ] {
                let mut state = conversion_state();
                state.v[0][LOW_LIMB] = source;
                let mut expected = state.clone();
                expected.x[0] = result;
                expected.fpsr |= INEXACT;
                let operand = conversion::Operand::ToInteger {
                    operand: IntegerConversion {
                        integer: IntegerOperand::General {
                            register: Register::X(0),
                            format: IntegerFormat {
                                width: IntegerWidth::Bits64,
                                signed: true,
                            },
                        },
                        float: 0,
                        format: Format::Double,
                        frac_bits: 0,
                    },
                    rounding,
                };
                complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                assert_eq!(state, expected, "{operand:?}, input={source:#x}");
            }
        }
        let mut state = conversion_state();
        state.v[1] = [0x4f00_0000_4060_0000, 0x0000_0000_cf80_0000];
        let mut expected = state.clone();
        expected.v[1] = [0x7fff_ffff_0000_0003, 0x0000_0000_8000_0000];
        expected.fpsr |= INVALID | INEXACT;
        let operand = conversion::Operand::ToInteger {
            operand: IntegerConversion {
                integer: IntegerOperand::Simd {
                    register: 1,
                    format: IntegerFormat {
                        width: IntegerWidth::Bits32,
                        signed: true,
                    },
                    shape: Shape::Vector128,
                },
                float: 1,
                format: Format::Single,
                frac_bits: 0,
            },
            rounding: IntegerRounding::TowardZero,
        };
        complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
        assert_eq!(state, expected);
    }

    #[test]
    fn javascript_conversion_commits_w_destination_exact_flags_and_sticky_status() {
        const NZCV_ZERO: u32 = 1 << 30;
        for (source_bits, result, nzcv, exceptions) in [
            (0, 0, NZCV_ZERO, 0),
            (0x8000_0000_0000_0000, 0, 0, 0),
            (0x3ff0_0000_0000_0000, 1, NZCV_ZERO, 0),
            (0xbff0_0000_0000_0000, 0xffff_ffff, NZCV_ZERO, 0),
            (0x3ff8_0000_0000_0000, 1, 0, INEXACT),
            (0x41f0_0000_0010_0000, 1, 0, INVALID),
            (0x7ff8_0000_0000_0001, 0, 0, INVALID),
        ] {
            for destination in [Register::X(0), Register::X(30), Register::Zero] {
                let mut state = conversion_state();
                state.v[usize::from(LAST_VECTOR_REGISTER)][LOW_LIMB] = source_bits;
                let mut expected = state.clone();
                if let Register::X(index) = destination {
                    expected.x[usize::from(index)] = result;
                }
                expected.nzcv = nzcv;
                expected.fpsr |= exceptions;
                let operand = conversion::Operand::JavaScript {
                    destination,
                    source: LAST_VECTOR_REGISTER,
                };
                complete(&mut state, &FloatingPointOperation::Conversion(operand)).unwrap();
                assert_eq!(state, expected, "{operand:?}, input={source_bits:#x}");
            }
        }
    }

    #[test]
    fn unsupported_conversion_controls_preserve_every_register_flags_and_status() {
        let signed32 = IntegerFormat {
            width: IntegerWidth::Bits32,
            signed: true,
        };
        let general = IntegerConversion {
            integer: IntegerOperand::General {
                register: Register::X(30),
                format: signed32,
            },
            float: LAST_VECTOR_REGISTER,
            format: Format::Double,
            frac_bits: 0,
        };
        let vector = IntegerConversion {
            integer: IntegerOperand::Simd {
                register: LAST_VECTOR_REGISTER,
                format: signed32,
                shape: Shape::Vector128,
            },
            float: LAST_VECTOR_REGISTER,
            format: Format::Single,
            frac_bits: 1,
        };
        let operands = [
            conversion::Operand::Precision(PrecisionOperand {
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
                mode: PrecisionMode::Scalar {
                    source: Format::Double,
                    destination: Format::Half,
                    rounding: PrecisionRounding::Fpcr,
                },
            }),
            conversion::Operand::Precision(PrecisionOperand {
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
                mode: PrecisionMode::Widen {
                    source: Format::Half,
                    upper: true,
                },
            }),
            conversion::Operand::Precision(PrecisionOperand {
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
                mode: PrecisionMode::Narrow {
                    destination: Format::Half,
                    upper: true,
                    rounding: PrecisionRounding::Fpcr,
                },
            }),
            conversion::Operand::Precision(PrecisionOperand {
                destination: LAST_VECTOR_REGISTER,
                source: LAST_VECTOR_REGISTER,
                mode: PrecisionMode::Narrow {
                    destination: Format::Single,
                    upper: true,
                    rounding: PrecisionRounding::ToOdd,
                },
            }),
            conversion::Operand::FromInteger(general),
            conversion::Operand::FromInteger(vector),
            conversion::Operand::ToInteger {
                operand: general,
                rounding: IntegerRounding::TowardZero,
            },
            conversion::Operand::ToInteger {
                operand: vector,
                rounding: IntegerRounding::NearestAway,
            },
            conversion::Operand::JavaScript {
                destination: Register::Zero,
                source: LAST_VECTOR_REGISTER,
            },
        ];
        for enabled in [
            INVALID,
            DIVIDE_BY_ZERO,
            OVERFLOW,
            UNDERFLOW,
            INEXACT,
            INPUT_DENORMAL,
            EXCEPTIONS,
        ] {
            for operand in operands {
                let mut state = conversion_state();
                state.fpcr |= FPCR_NEP | (enabled << FPCR_EXCEPTION_ENABLE_SHIFT);
                let expected = state.clone();
                assert_eq!(
                    complete(&mut state, &FloatingPointOperation::Conversion(operand)),
                    Err(UnsupportedControl {
                        enabled_exceptions: enabled
                    })
                );
                assert_eq!(state, expected, "{operand:?}, enabled={enabled:#x}");
            }
        }
    }
}
