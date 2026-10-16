//! Conversions between FP and integers.
use super::numerical::{
    ArithmeticOpcode, Condition, INPUT_MINIMUM_EXPONENT, Rounding, branch, clear_scalar,
    commit_inexact, emit_opcode, environment_round, exponent_range, prepare_vector_input_range,
    read_numerical_vector, reject_other_status, resolve, restore_environment, test_control,
    vector_exponent_range,
};
use super::{Host, commit, packed, read_vector, vector_offset};
use crate::{
    GuestAddress,
    aarch64::{
        Register,
        floating::{
            FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, Format, INEXACT,
            integer::{IntegerFormat, IntegerRounding, IntegerWidth},
        },
        simd::{
            arithmetic::Shape,
            conversion::{IntegerConversion, IntegerOperand},
        },
    },
    block::ExitKind,
};
use alloc::vec::Vec;

const SINGLE_PREFIX: u8 = 0xf3;
const DOUBLE_PREFIX: u8 = 0xf2;
const SSE_ESCAPE: u8 = 0x0f;
const REX_W: u8 = 0x48;
const REGISTER_DIRECT: u8 = 0xc0;
const CVT_INTEGER_TO_FLOAT: u8 = 0x2a;
const CVT_FLOAT_TO_INTEGER: u8 = 0x2d;
const CVTT_FLOAT_TO_INTEGER: u8 = 0x2c;
const CVT_DWORDS_TO_SINGLE: &[u8] = &[0x0f, 0x5b, 0xc0];
const CVT_SINGLE_TO_DWORDS: &[u8] = &[0x66, 0x0f, 0x5b, 0xc0];
const CVTT_SINGLE_TO_DWORDS: &[u8] = &[0xf3, 0x0f, 0x5b, 0xc0];
const MOV_EAX_STATE: &[u8] = &[0x8b, 0x87];
const MOV_RAX_STATE: &[u8] = &[0x48, 0x8b, 0x87];
const MOVD_XMM0_STATE: &[u8] = &[0x66, 0x0f, 0x6e, 0x87];
const MOVQ_XMM0_STATE: &[u8] = &[0xf3, 0x0f, 0x7e, 0x87];
const MOV_EAX_EAX: &[u8] = &[0x89, 0xc0];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const SHR_RDX_32: &[u8] = &[0x48, 0xc1, 0xea, 32];
const TEST_EDX_EDX: &[u8] = &[0x85, 0xd2];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const SHR_RCX_63: &[u8] = &[0x48, 0xc1, 0xe9, 63];
const SHR_RAX_1: &[u8] = &[0x48, 0xd1, 0xe8];
const AND_ECX_1: &[u8] = &[0x83, 0xe1, 1];
const OR_RAX_RCX: &[u8] = &[0x48, 0x09, 0xc8];
const BT_RAX_63: &[u8] = &[0x48, 0x0f, 0xba, 0xe0, 63];
const BTS_RAX_63: &[u8] = &[0x48, 0x0f, 0xba, 0xe8, 63];
const MOVABS_RDX: &[u8] = &[0x48, 0xba];
const MOVQ_XMM1_RDX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xca];
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const MOVQ_RAX_XMM0: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xc0];
const MOVD_XMM1_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc8];
const MOVQ_XMM1_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xc8];
const MOVSS_XMM0_XMM1: &[u8] = &[0xf3, 0x0f, 0x10, 0xc1];
const MOVSD_XMM0_XMM1: &[u8] = &[0xf2, 0x0f, 0x10, 0xc1];
const PSLLDQ_XMM1: &[u8] = &[0x66, 0x0f, 0x73, 0xf9];
const SHUFPS_XMM1_BROADCAST: &[u8] = &[0x0f, 0xc6, 0xc9, 0];
const UNPCKLPD_XMM1_XMM1: &[u8] = &[0x66, 0x0f, 0x14, 0xc9];
const UCOMISS_XMM0_XMM1: &[u8] = &[0x0f, 0x2e, 0xc1];
const UCOMISD_XMM0_XMM1: &[u8] = &[0x66, 0x0f, 0x2e, 0xc1];
const JMP_REL32: u8 = 0xe9;
const RESULT_VECTOR: u8 = 0;
const TEMPORARY_VECTOR: u8 = 1;
const INTEGER_ACCUMULATOR: u8 = 6;
const BITS_PER_BYTE: u32 = u8::BITS;
const SINGLE_EXPONENT_BIAS: i16 = 127;
const DOUBLE_EXPONENT_BIAS: i16 = 1023;
const UNSIGNED_HIGH_EXPONENT: i16 = 63;

fn helper(code: &mut Vec<u8>, pc: GuestAddress) {
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
}

fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_REL32);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

fn scalar_conversion(code: &mut Vec<u8>, format: Format, opcode: u8, wide: bool) {
    code.push(match format {
        Format::Single => SINGLE_PREFIX,
        Format::Double => DOUBLE_PREFIX,
        Format::Half => unreachable!("half conversions use the exact core"),
    });
    if wide {
        code.push(REX_W);
    }
    code.extend([SSE_ESCAPE, opcode, REGISTER_DIRECT]);
}

fn rounding(rounding: IntegerRounding) -> Rounding {
    match rounding {
        IntegerRounding::NearestEven => Rounding::NearestEven,
        IntegerRounding::TowardPositive => Rounding::Positive,
        IntegerRounding::TowardNegative => Rounding::Negative,
        IntegerRounding::TowardZero => Rounding::Zero,
        IntegerRounding::NearestAway => unreachable!("ties-away conversions use the exact core"),
    }
}

fn integer_offset(integer: IntegerOperand, lane: u32) -> u32 {
    let IntegerOperand::Simd {
        register, format, ..
    } = integer
    else {
        unreachable!("general register operands have no SIMD offset")
    };
    vector_offset(register) + lane * (format.width.bits() / BITS_PER_BYTE)
}

fn read_integer(code: &mut Vec<u8>, integer: IntegerOperand, lane: u32) {
    let format = integer.format();
    match integer {
        IntegerOperand::General { register, .. } => super::super::load(code, register),
        IntegerOperand::Simd { .. } => {
            code.extend(if format.width == IntegerWidth::Bits64 {
                MOV_RAX_STATE
            } else {
                MOV_EAX_STATE
            });
            code.extend(integer_offset(integer, lane).to_le_bytes());
        }
    }
    if !format.signed && format.width == IntegerWidth::Bits32 {
        // The shared GPR load is 64-bit; unsigned W conversion reads only Wn.
        code.extend(MOV_EAX_EAX);
    }
}

fn float_constant(code: &mut Vec<u8>, format: Format, exponent: i16, shape: Shape) {
    let (bias, fraction_bits) = match format {
        Format::Single => (SINGLE_EXPONENT_BIAS, Format::Single.fraction_bits()),
        Format::Double => (DOUBLE_EXPONENT_BIAS, Format::Double.fraction_bits()),
        Format::Half => unreachable!("half conversions use the exact core"),
    };
    code.extend(MOVABS_RDX);
    code.extend(
        (u64::try_from(bias + exponent).expect("normal conversion scale") << fraction_bits)
            .to_le_bytes(),
    );
    code.extend(MOVQ_XMM1_RDX);
    if shape != Shape::Scalar {
        code.extend(if format == Format::Single {
            SHUFPS_XMM1_BROADCAST
        } else {
            UNPCKLPD_XMM1_XMM1
        });
    }
}

fn scale(code: &mut Vec<u8>, operand: &IntegerConversion, shape: Shape, direction: i16) {
    if operand.frac_bits != 0 {
        float_constant(
            code,
            operand.format,
            direction * i16::from(operand.frac_bits),
            shape,
        );
        emit_opcode(
            code,
            operand.format,
            shape,
            ArithmeticOpcode::Multiply,
            TEMPORARY_VECTOR,
        );
    }
}

fn convert_integer_lane(code: &mut Vec<u8>, operand: &IntegerConversion, lane: u32) {
    let integer = operand.integer.format();
    read_integer(code, operand.integer, lane);
    let wide = integer.width == IntegerWidth::Bits64 || !integer.signed;
    if integer.signed || integer.width != IntegerWidth::Bits64 {
        scalar_conversion(code, operand.format, CVT_INTEGER_TO_FLOAT, wide);
    } else {
        // High unsigned values do not fit CVTSI's signed input. Retaining a
        // sticky low bit before halving preserves all four rounding modes.
        code.extend(MOV_RCX_RAX);
        code.extend(SHR_RCX_63);
        let low = branch(code, Condition::Zero);
        code.extend(MOV_RCX_RAX);
        code.extend(AND_ECX_1);
        code.extend(SHR_RAX_1);
        code.extend(OR_RAX_RCX);
        scalar_conversion(code, operand.format, CVT_INTEGER_TO_FLOAT, true);
        emit_opcode(
            code,
            operand.format,
            Shape::Scalar,
            ArithmeticOpcode::Add,
            RESULT_VECTOR,
        );
        let done = jump(code);
        let low_start = code.len();
        resolve(code, low, low_start);
        scalar_conversion(code, operand.format, CVT_INTEGER_TO_FLOAT, true);
        let end = code.len();
        resolve(code, done, end);
    }
    // For S/D and fbits<=64, this power-of-two rescaling stays normal and exact.
    scale(code, operand, Shape::Scalar, -1);
}

fn pack_integer_lane(code: &mut Vec<u8>, width: IntegerWidth, lane: u32) {
    code.extend(if width == IntegerWidth::Bits64 {
        MOVQ_XMM1_RAX
    } else {
        MOVD_XMM1_EAX
    });
    if lane != 0 {
        code.extend(PSLLDQ_XMM1);
        code.push((lane * (width.bits() / BITS_PER_BYTE)) as u8);
    }
    packed(code, Host::Or, INTEGER_ACCUMULATOR, TEMPORARY_VECTOR);
}

fn finish_float(code: &mut Vec<u8>, operand: &IntegerConversion) {
    commit_inexact(code);
    if operand.integer.shape() == Shape::Scalar {
        test_control(code, FPCR_NEP);
        let merge = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, RESULT_VECTOR);
        let end = code.len();
        resolve(code, merge, end);
    }
    commit(code, operand.float, RESULT_VECTOR);
}

pub(in crate::x86_64) fn from_integer(
    code: &mut Vec<u8>,
    operand: &IntegerConversion,
    pc: GuestAddress,
) {
    if operand.format == Format::Half {
        // S->H after integer->S can double round; there is no baseline H CVT.
        helper(code, pc);
        return;
    }
    let shape = operand.integer.shape();
    let integer = operand.integer.format();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    let enabled = branch(code, Condition::NotZero);
    if shape == Shape::Scalar {
        read_vector(code, operand.float, RESULT_VECTOR);
    }
    environment_round(code, Rounding::Fpcr);
    if shape != Shape::Scalar && operand.format == Format::Single && integer.signed {
        let IntegerOperand::Simd { register, .. } = operand.integer else {
            unreachable!("vector integer source")
        };
        read_numerical_vector(code, shape, register, RESULT_VECTOR);
        code.extend(CVT_DWORDS_TO_SINGLE);
        scale(code, operand, shape, -1);
    } else if shape == Shape::Scalar {
        convert_integer_lane(code, operand, 0);
    } else {
        packed(code, Host::Xor, INTEGER_ACCUMULATOR, INTEGER_ACCUMULATOR);
        for lane in 0..shape.lane_count(operand.format) {
            convert_integer_lane(code, operand, lane);
            code.extend(if operand.format == Format::Single {
                MOVD_EAX_XMM0
            } else {
                MOVQ_RAX_XMM0
            });
            pack_integer_lane(code, integer.width, lane);
        }
        packed(code, Host::MoveAligned, RESULT_VECTOR, INTEGER_ACCUMULATOR);
    }
    restore_environment(code);
    let status = reject_other_status(code);
    let success = jump(code);
    let helper_start = code.len();
    resolve(code, enabled, helper_start);
    resolve(code, status, helper_start);
    helper(code, pc);
    let success_start = code.len();
    resolve(code, success, success_start);
    finish_float(code, operand);
}

fn guard_float_source(code: &mut Vec<u8>, operand: &IntegerConversion) -> usize {
    let shape = operand.integer.shape();
    read_numerical_vector(code, shape, operand.float, RESULT_VECTOR);
    if shape == Shape::Scalar {
        exponent_range(code, operand.format, RESULT_VECTOR, INPUT_MINIMUM_EXPONENT);
        branch(code, Condition::AboveOrEqual)
    } else {
        prepare_vector_input_range(code, operand.format);
        vector_exponent_range(code, operand.format, shape, RESULT_VECTOR);
        branch(code, Condition::NotZero)
    }
}

fn read_float_lane(code: &mut Vec<u8>, operand: &IntegerConversion, lane: u32) {
    code.extend(if operand.format == Format::Single {
        MOVD_XMM0_STATE
    } else {
        MOVQ_XMM0_STATE
    });
    code.extend(
        (vector_offset(operand.float) + lane * (operand.format.bits() / BITS_PER_BYTE))
            .to_le_bytes(),
    );
}

fn convert_float_lane(
    code: &mut Vec<u8>,
    operand: &IntegerConversion,
    mode: IntegerRounding,
    failures: &mut Vec<usize>,
) {
    let integer = operand.integer.format();
    let opcode = if mode == IntegerRounding::TowardZero {
        CVTT_FLOAT_TO_INTEGER
    } else {
        CVT_FLOAT_TO_INTEGER
    };
    if integer.signed {
        scalar_conversion(
            code,
            operand.format,
            opcode,
            integer.width == IntegerWidth::Bits64,
        );
    } else if integer.width == IntegerWidth::Bits32 {
        scalar_conversion(code, operand.format, opcode, true);
        code.extend(MOV_RDX_RAX);
        code.extend(SHR_RDX_32);
        code.extend(TEST_EDX_EDX);
        failures.push(branch(code, Condition::NotZero));
    } else {
        float_constant(code, operand.format, UNSIGNED_HIGH_EXPONENT, Shape::Scalar);
        code.extend(if operand.format == Format::Single {
            UCOMISS_XMM0_XMM1
        } else {
            UCOMISD_XMM0_XMM1
        });
        let low = branch(code, Condition::Below);
        // Subtraction is exact throughout [2^63,2^64) (Sterbenz). Anything
        // beyond that interval raises native invalid and is retried by the core.
        emit_opcode(
            code,
            operand.format,
            Shape::Scalar,
            ArithmeticOpcode::Subtract,
            TEMPORARY_VECTOR,
        );
        scalar_conversion(code, operand.format, opcode, true);
        code.extend(BTS_RAX_63);
        let done = jump(code);
        let low_start = code.len();
        resolve(code, low, low_start);
        scalar_conversion(code, operand.format, opcode, true);
        code.extend(BT_RAX_63);
        failures.push(branch(code, Condition::Below));
        let end = code.len();
        resolve(code, done, end);
    }
}

fn finish_integer(code: &mut Vec<u8>, operand: &IntegerConversion, packed_result: bool) {
    commit_inexact(code);
    match operand.integer {
        IntegerOperand::General { register, .. } => super::super::store(code, register),
        IntegerOperand::Simd {
            register,
            format,
            shape,
        } => {
            if shape != Shape::Scalar {
                if !packed_result {
                    packed(code, Host::MoveAligned, RESULT_VECTOR, INTEGER_ACCUMULATOR);
                }
            } else {
                read_vector(code, register, RESULT_VECTOR);
                code.extend(if format.width == IntegerWidth::Bits64 {
                    MOVQ_XMM1_RAX
                } else {
                    MOVD_XMM1_EAX
                });
                code.extend(if format.width == IntegerWidth::Bits64 {
                    MOVSD_XMM0_XMM1
                } else {
                    MOVSS_XMM0_XMM1
                });
                test_control(code, FPCR_NEP);
                let merge = branch(code, Condition::NotZero);
                clear_scalar(code, operand.format, RESULT_VECTOR);
                let end = code.len();
                resolve(code, merge, end);
            }
            commit(code, register, RESULT_VECTOR);
        }
    }
}

pub(in crate::x86_64) fn to_integer(
    code: &mut Vec<u8>,
    operand: &IntegerConversion,
    mode: IntegerRounding,
    pc: GuestAddress,
) {
    if operand.format == Format::Half || mode == IntegerRounding::NearestAway {
        // SSE2 has no ties-away control. Adding 0.5 before truncation double
        // rounds near half ties; keep the exact integer-core route instead.
        helper(code, pc);
        return;
    }
    let shape = operand.integer.shape();
    let integer = operand.integer.format();
    let packed_result =
        shape != Shape::Scalar && operand.format == Format::Single && integer.signed;
    let mut helper_patches = Vec::new();
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper_patches.push(branch(code, Condition::NotZero));
    helper_patches.push(guard_float_source(code, operand));
    environment_round(code, rounding(mode));
    let mut environment_failures = Vec::new();
    if packed_result {
        scale(code, operand, shape, 1);
        code.extend(if mode == IntegerRounding::TowardZero {
            CVTT_SINGLE_TO_DWORDS
        } else {
            CVT_SINGLE_TO_DWORDS
        });
    } else {
        if shape != Shape::Scalar {
            packed(code, Host::Xor, INTEGER_ACCUMULATOR, INTEGER_ACCUMULATOR);
        }
        for lane in 0..shape.lane_count(operand.format) {
            read_float_lane(code, operand, lane);
            scale(code, operand, Shape::Scalar, 1);
            convert_float_lane(code, operand, mode, &mut environment_failures);
            if shape != Shape::Scalar {
                pack_integer_lane(code, integer.width, lane);
            }
        }
    }
    restore_environment(code);
    helper_patches.push(reject_other_status(code));
    let success = jump(code);
    if !environment_failures.is_empty() {
        // Range failures occur before commit. Their cold path restores exactly
        // the same caller environment as the normal completion path.
        let restore_start = code.len();
        for patch in environment_failures {
            resolve(code, patch, restore_start);
        }
        restore_environment(code);
    }
    let helper_start = code.len();
    for patch in helper_patches {
        resolve(code, patch, helper_start);
    }
    helper(code, pc);
    let success_start = code.len();
    resolve(code, success, success_start);
    finish_integer(code, operand, packed_result);
}

pub(in crate::x86_64) fn javascript(
    code: &mut Vec<u8>,
    destination: Register,
    source: u8,
    pc: GuestAddress,
) {
    const XOR_ECX_IMMEDIATE: &[u8] = &[0x83, 0xf1];
    const SHL_ECX_IMMEDIATE: &[u8] = &[0xc1, 0xe1];
    const MOV_STATE_ECX: &[u8] = &[0x89, 0x8f];
    const NZCV_ZERO_SHIFT: u32 = 30;
    const INEXACT_TO_NZCV_SHIFT: u8 = (NZCV_ZERO_SHIFT - INEXACT.trailing_zeros()) as u8;
    let operand = IntegerConversion {
        integer: IntegerOperand::General {
            register: destination,
            format: IntegerFormat {
                width: IntegerWidth::Bits32,
                signed: true,
            },
        },
        float: source,
        format: Format::Double,
        frac_bits: 0,
    };
    // A normal input whose truncated integer fits signed32 agrees with JS
    // coercion. Other inputs exit unchanged at the original FJCVTZS word;
    // its exact core owns modulo, exceptional values and zero distinctions.
    to_integer(code, &operand, IntegerRounding::TowardZero, pc);
    // commit_inexact leaves only fresh IXC in ECX. Accumulated FPSR.IXC must
    // not clear Z for a later exact input, including a discarded WZR result.
    code.extend(XOR_ECX_IMMEDIATE);
    code.push(INEXACT as u8);
    code.extend(SHL_ECX_IMMEDIATE);
    code.push(INEXACT_TO_NZCV_SHIFT);
    code.extend(MOV_STATE_ECX);
    code.extend((core::mem::offset_of!(crate::GuestState, nzcv) as u32).to_le_bytes());
}
