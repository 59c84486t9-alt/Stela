//! Transactional scalar numerical completion over saved guest state.
use stela_compiler::{
    GuestState,
    aarch64::{
        floating::{FPCR_NEP, UnsupportedControl, evaluate},
        simd::arithmetic::Operand,
    },
};

const LOW_LIMB: usize = 0;
const VECTOR_LIMBS: usize = 2;

pub(crate) fn complete(
    state: &mut GuestState,
    operand: &Operand,
) -> Result<(), UnsupportedControl> {
    let left = state.v[usize::from(operand.left)];
    let right = state.v[usize::from(operand.right)];
    let outcome = evaluate(
        operand.format,
        operand.operation,
        state.fpcr,
        left[LOW_LIMB],
        right[LOW_LIMB],
    )?;
    let lane_mask = u64::MAX >> (u64::BITS - operand.format.bits());
    let mut result = if state.fpcr & FPCR_NEP != 0 {
        left
    } else {
        [0; VECTOR_LIMBS]
    };
    result[LOW_LIMB] = (result[LOW_LIMB] & !lane_mask) | (outcome.bits & lane_mask);
    state.v[usize::from(operand.destination)] = result;
    state.fpsr |= outcome.exceptions;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::floating::{
        BinaryOperation, DIVIDE_BY_ZERO, EXCEPTIONS, Format, INEXACT, INPUT_DENORMAL, INVALID,
        OVERFLOW, UNDERFLOW,
    };

    const VECTOR_REGISTER_COUNT: usize = 32;
    const LAST_VECTOR_REGISTER: u8 = (VECTOR_REGISTER_COUNT - 1) as u8;
    const FPCR_AHP: u32 = 1 << 26;
    const FPCR_EXCEPTION_ENABLE_SHIFT: u32 = 8;
    const FPSR_QC: u32 = 1 << 27;
    const RETAINED_FPSR_BITS: u32 = FPSR_QC | INEXACT | (1 << 31);
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

    #[test]
    fn scalar_add_merges_original_left_and_handles_every_alias_role() {
        let aliases = [
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
        for (format, one, two, three, _, _) in FORMATS {
            for nep in [false, true] {
                for (destination, left, right) in aliases {
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
}
