//! Transactional scalar/vector numerical completion over saved guest state.
use stela_compiler::{
    GuestState,
    aarch64::{
        FloatingPointOperation,
        floating::{FPCR_NEP, Format, UnsupportedControl, evaluate, fused},
        simd::arithmetic::Shape,
    },
};

const VECTOR_LIMBS: usize = 2;

fn read_lane(vector: &[u64; VECTOR_LIMBS], format: Format, lane: u32) -> u64 {
    let lane_bits = format.bits();
    let bit_offset = lane * lane_bits;
    let limb = (bit_offset / u64::BITS) as usize;
    let shift = bit_offset % u64::BITS;
    let lane_mask = u64::MAX >> (u64::BITS - lane_bits);
    (vector[limb] >> shift) & lane_mask
}

fn write_lane(vector: &mut [u64; VECTOR_LIMBS], format: Format, lane: u32, bits: u64) {
    let lane_bits = format.bits();
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
    let (destination, merge_register, left_register, right_register, right_lane) = match operation {
        FloatingPointOperation::Binary(operand) => (
            operand.destination,
            operand.left,
            operand.left,
            operand.right,
            None,
        ),
        FloatingPointOperation::Fused(operand) => (
            operand.destination,
            operand.addend,
            operand.left,
            operand.right,
            operand.right_lane,
        ),
    };
    // Snapshot every source before evaluating any lane, including an indexed
    // source outside a vector64 destination's active lanes.
    let merge = state.v[usize::from(merge_register)];
    let left = state.v[usize::from(left_register)];
    let right = state.v[usize::from(right_register)];
    let format = operation.format();
    let shape = operation.shape();
    let mut result = if shape == Shape::Scalar && state.fpcr & FPCR_NEP != 0 {
        merge
    } else {
        [0; VECTOR_LIMBS]
    };
    let mut exceptions = 0;
    for lane in 0..shape.lane_count(format) {
        let left = read_lane(&left, format, lane);
        let right = read_lane(&right, format, right_lane.map_or(lane, u32::from));
        let outcome = match operation {
            FloatingPointOperation::Binary(operand) => {
                evaluate(format, operand.operation, state.fpcr, left, right)?
            }
            FloatingPointOperation::Fused(operand) => fused::evaluate(
                format,
                operand.operation,
                state.fpcr,
                read_lane(&merge, format, lane),
                left,
                right,
            )?,
        };
        write_lane(&mut result, format, lane, outcome.bits);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(destination)] = result;
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
    use stela_compiler::aarch64::simd::{arithmetic::Operand, fused::Operand as FusedOperand};

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
                        left,
                        right,
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
                    left: 1,
                    right: 2,
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
                    left: 1,
                    right: 2,
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
                        left: LAST_VECTOR_REGISTER,
                        right: LAST_VECTOR_REGISTER,
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
                        left,
                        right,
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
                    left: 1,
                    right: 2,
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
                        left,
                        right,
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
}
