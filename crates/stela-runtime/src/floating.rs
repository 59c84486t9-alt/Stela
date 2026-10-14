//! Transactional scalar/vector numerical completion over saved guest state.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, UnsupportedControl, evaluate},
        simd::arithmetic::{Operand, Shape},
    },
};

const VECTOR_LIMBS: usize = 2;

pub(crate) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let lane_bits = operand.format.bits();
    let lane_mask = u64::MAX >> (u64::BITS - lane_bits);
    let mut result = if operand.shape == Shape::Scalar && state.fpcr & FPCR_NEP != 0 {
        left
    } else {
        [0; VECTOR_LIMBS]
    };
    let mut exceptions = 0;
    for lane in 0..operand.shape.lane_count(operand.format) {
        let bit_offset = lane * lane_bits;
        let limb = (bit_offset / u64::BITS) as usize;
        let shift = bit_offset % u64::BITS;
        let outcome = evaluate(
            operand.format,
            operand.operation,
            state.fpcr,
            (left[limb] >> shift) & lane_mask,
            (right[limb] >> shift) & lane_mask,
        )?;
        result[limb] =
            (result[limb] & !(lane_mask << shift)) | ((outcome.bits & lane_mask) << shift);
        exceptions |= outcome.exceptions;
    }
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::floating::{
        BinaryOperation, DIVIDE_BY_ZERO, EXCEPTIONS, FPCR_AHP, FPCR_EXCEPTION_ENABLE_SHIFT,
        FPSR_QC, Format, INEXACT, INPUT_DENORMAL, INVALID, OVERFLOW, UNDERFLOW,
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
                        left,
                        right,
                    };
                    complete(&mut state, &operand).unwrap();
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
                },
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
                complete(&mut state, &operand).unwrap();
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
                        complete(&mut state, &operand),
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
                    complete(&mut state, &operand).unwrap();
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
                },
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
                        complete(&mut state, &operand),
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
