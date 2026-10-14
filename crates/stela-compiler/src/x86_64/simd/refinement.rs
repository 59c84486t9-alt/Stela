//! Refinement steps: exact-product/widened SSE2, checked FMA3 and exact widened H.
use super::super::isa::ShiftOpcode;
use super::numerical::{
    ArithmeticOpcode, Condition, FusedOpcode, INPUT_MINIMUM_EXPONENT, MINIMUM_EXPONENT_VECTOR,
    RESULT_MINIMUM_EXPONENT, Rounding, branch, clear_scalar, commit_inexact, emit_fma,
    emit_opcode_to, environment, environment_round, exponent_range, prepare_vector_input_range,
    prepare_vector_result_range, read_numerical_vector, reject_other_status, reject_product_status,
    resolve, restore_environment, restore_environment_with_product, save_product_status,
    test_control, vector_exponent_range,
};
use super::{Host, commit, packed};
use crate::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::{
        floating::{
            FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, INEXACT,
        },
        simd::{
            arithmetic::Shape,
            refinement::{Kind, Operand},
        },
    },
    block::ExitKind,
};

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const ZERO: u8 = 2;
const SAVED_SINGLE_LEFT: u8 = 2;
const SAVED_SINGLE_RIGHT: u8 = 5;
const SAVED_SINGLE_CONSTANT: u8 = 2;
const FIRST_SINGLE_PAIR: u8 = 3;
const SPLIT_SINGLE_LEFT: u8 = 7;
const FIRST_LANE: u8 = 0;
const HALF_CONSTANT: u8 = 5;
const CONSTANT: u8 = 6;
const ORIGINAL_LEFT: u8 = 7;
const REGISTER_DIRECT: u8 = 0xc0;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SSE_ESCAPE: u8 = 0x0f;
const SINGLE_PREFIX: u8 = 0xf3;
const DOUBLE_PREFIX: u8 = 0xf2;
const MOV_SCALAR: u8 = 0x10;
const JMP_REL32: u8 = 0xe9;
const VZEROUPPER: &[u8] = &[0xc5, 0xf8, 0x77];
const SIGN_BITS: u32 = 1;
const FPCR_ROUNDING_LOW: u32 = 1 << FPCR_ROUNDING_SHIFT;
const FPCR_ROUNDING_HIGH: u32 = FPCR_ROUNDING_LOW << 1;
const MOVD_EAX_XMM0: &[u8] = &[0x66, 0x0f, 0x7e, 0xc0];
const MOVD_XMM0_EAX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc0];
const SUB_EAX_IMM32: u8 = 0x2d;

// Fixed registers for the cold Single-to-Double refinement path. The private
// environment uses the same four-slot scratch layout as numerical.rs.
const CVTSS2SD_XMM0_XMM0: &[u8] = &[0xf3, 0x0f, 0x5a, 0xc0];
const CVTSS2SD_XMM1_XMM1: &[u8] = &[0xf3, 0x0f, 0x5a, 0xc9];
const CVTSD2SS_XMM6_XMM6: &[u8] = &[0xf2, 0x0f, 0x5a, 0xf6];
const CVTPS2PD_XMM0_XMM0: &[u8] = &[0x0f, 0x5a, 0xc0];
const CVTPS2PD_XMM1_XMM1: &[u8] = &[0x0f, 0x5a, 0xc9];
const CVTPS2PD_XMM0_XMM7: &[u8] = &[0x0f, 0x5a, 0xc7];
const CVTPS2PD_XMM1_XMM5: &[u8] = &[0x0f, 0x5a, 0xcd];
const CVTPD2PS_XMM6_XMM6: &[u8] = &[0x66, 0x0f, 0x5a, 0xf6];
const MOVHLPS_XMM0_XMM7: &[u8] = &[0x0f, 0x12, 0xc7];
const MOVHLPS_XMM1_XMM5: &[u8] = &[0x0f, 0x12, 0xcd];
const MOVLHPS_XMM3_XMM6: &[u8] = &[0x0f, 0x16, 0xde];
const MXCSR_CONTROL_SLOT: u8 = 4;
const MXCSR_STATUS_SLOT: u8 = 8;
const MXCSR_PRODUCT_SLOT: u8 = 12;
const MXCSR_STACK_BYTES: u8 = 16;
const STMXCSR_STATUS: &[u8] = &[0x0f, 0xae, 0x5c, 0x24, MXCSR_STATUS_SLOT];
const LDMXCSR_SAVED: &[u8] = &[0x0f, 0xae, 0x14, 0x24];
const LDMXCSR_CONTROL: &[u8] = &[0x0f, 0xae, 0x54, 0x24, MXCSR_CONTROL_SLOT];
const MOV_R9D_PRODUCT: &[u8] = &[0x44, 0x8b, 0x4c, 0x24, MXCSR_PRODUCT_SLOT];
const MOV_R10D_STATUS: &[u8] = &[0x44, 0x8b, 0x54, 0x24, MXCSR_STATUS_SLOT];
const MOV_EAX_PRODUCT: &[u8] = &[0x8b, 0x44, 0x24, MXCSR_PRODUCT_SLOT];
const MOV_ECX_STATUS: &[u8] = &[0x8b, 0x4c, 0x24, MXCSR_STATUS_SLOT];
const MOV_PRODUCT_EAX: &[u8] = &[0x89, 0x44, 0x24, MXCSR_PRODUCT_SLOT];
const OR_EAX_R9D: &[u8] = &[0x44, 0x09, 0xc8];
const OR_ECX_R10D: &[u8] = &[0x44, 0x09, 0xd1];
const ADD_RSP_MXCSR: &[u8] = &[0x48, 0x83, 0xc4, MXCSR_STACK_BYTES];

// Half sources/results remain private until every active lane has passed.
// Only SysV caller-volatile GPRs are used; RSI remains untouched.
const HOST_VECTOR_BYTES: u8 = 16;
const HALF_RIGHT_SLOT: u8 = HOST_VECTOR_BYTES;
const HALF_RESULT_SLOT: u8 = HOST_VECTOR_BYTES * 2;
const HALF_STACK_BYTES: u8 = HALF_RESULT_SLOT + HOST_VECTOR_BYTES;
const SUB_RSP: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP: &[u8] = &[0x48, 0x83, 0xc4];
const SAVE_LEFT: &[u8] = &[0xf3, 0x0f, 0x7f, 0x04, 0x24];
const SAVE_RIGHT: &[u8] = &[0xf3, 0x0f, 0x7f, 0x4c, 0x24, HALF_RIGHT_SLOT];
const SAVE_ZERO_RESULT: &[u8] = &[0xf3, 0x0f, 0x7f, 0x54, 0x24, HALF_RESULT_SLOT];
const LOAD_RESULT: &[u8] = &[0xf3, 0x0f, 0x6f, 0x44, 0x24, HALF_RESULT_SLOT];
const LOAD_LEFT_HALF: &[u8] = &[0x42, 0x0f, 0xb7, 0x04, 0x5c];
const LOAD_RIGHT_HALF: &[u8] = &[0x42, 0x0f, 0xb7, 0x4c, 0x5c, HALF_RIGHT_SLOT];
const STORE_RESULT_HALF: &[u8] = &[0x66, 0x42, 0x89, 0x44, 0x5c, HALF_RESULT_SLOT];
const XOR_R10D_R10D: &[u8] = &[0x45, 0x31, 0xd2];
const XOR_R11D_R11D: &[u8] = &[0x45, 0x31, 0xdb];
const INC_R11D: &[u8] = &[0x41, 0xff, 0xc3];
const CMP_R11D: &[u8] = &[0x41, 0x83, 0xfb];
const MOVABS_R8: &[u8] = &[0x49, 0xb8];
const MOVABS_R9: &[u8] = &[0x49, 0xb9];
const MOVABS_RDX: &[u8] = &[0x48, 0xba];
const MOV_EDX_EAX: &[u8] = &[0x89, 0xc2];
const MOV_EDX_ECX: &[u8] = &[0x89, 0xca];
const AND_EAX_IMM32: u8 = 0x25;
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const AND_EDX_IMM32: &[u8] = &[0x81, 0xe2];
const SHL_RAX: &[u8] = &[0x48, 0xc1, 0xe0];
const SHL_RCX: &[u8] = &[0x48, 0xc1, 0xe1];
const SHL_RDX: &[u8] = &[0x48, 0xc1, 0xe2];
const SHR_RAX: &[u8] = &[0x48, 0xc1, 0xe8];
const SHR_RCX: &[u8] = &[0x48, 0xc1, 0xe9];
const SHR_RDX: &[u8] = &[0x48, 0xc1, 0xea];
const SHR_EDX: &[u8] = &[0xc1, 0xea];
const SHL_EDX: &[u8] = &[0xc1, 0xe2];
const SHL_ECX: &[u8] = &[0xc1, 0xe1];
const ADD_RAX_R8: &[u8] = &[0x4c, 0x01, 0xc0];
const ADD_RCX_R9: &[u8] = &[0x4c, 0x01, 0xc9];
const SUB_RAX_R9: &[u8] = &[0x4c, 0x29, 0xc8];
const OR_RAX_RDX: &[u8] = &[0x48, 0x09, 0xd0];
const OR_RCX_RDX: &[u8] = &[0x48, 0x09, 0xd1];
const OR_EAX_ECX: &[u8] = &[0x09, 0xc8];
const MOVQ_XMM0_RAX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xc0];
const MOVQ_XMM1_RCX: &[u8] = &[0x66, 0x48, 0x0f, 0x6e, 0xc9];
const MOVQ_RAX_XMM6: &[u8] = &[0x66, 0x48, 0x0f, 0x7e, 0xf0];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const MOV_RDX_RAX: &[u8] = &[0x48, 0x89, 0xc2];
const BTR_RAX: &[u8] = &[0x48, 0x0f, 0xba, 0xf0];
const BT_RAX: &[u8] = &[0x48, 0x0f, 0xba, 0xe0];
const SUB_EDX_IMM32: &[u8] = &[0x81, 0xea];
const SUB_EDX_IMM8: &[u8] = &[0x83, 0xea];
const CMP_EDX_IMM8: &[u8] = &[0x83, 0xfa];
const SETNE_DL: &[u8] = &[0x0f, 0x95, 0xc2];
const MOVZX_EDX_DL: &[u8] = &[0x0f, 0xb6, 0xd2];
const OR_R10D_EDX: &[u8] = &[0x41, 0x09, 0xd2];
const ADC_RAX_RDX: &[u8] = &[0x48, 0x11, 0xd0];
const ADD_RAX_RDX: &[u8] = &[0x48, 0x01, 0xd0];
const TEST_ECX_ECX: &[u8] = &[0x85, 0xc9];
const OR_STATE_R10D: &[u8] = &[0x44, 0x09, 0x97];
const PINSRW_XMM7_EAX: &[u8] = &[0x66, 0x0f, 0xc4, 0xf8, FIRST_LANE];
const HALF_TO_DOUBLE_SHIFT: u8 =
    (Format::Double.fraction_bits() - Format::Half.fraction_bits()) as u8;
const HALF_TO_DOUBLE_SIGN_SHIFT: u8 = (Format::Double.bits() - Format::Half.bits()) as u8;
const HALF_TO_DOUBLE_BIAS: u64 = ((Format::Double.exponent_bias() - Format::Half.exponent_bias())
    as u64)
    << Format::Double.fraction_bits();
const HALF_DISCARDED_MASK: u64 = (1u64 << HALF_TO_DOUBLE_SHIFT) - 1;
const HALF_NORMAL_EXPONENT_COUNT: u8 = ((Format::Half.exponent_mask()
    >> Format::Half.fraction_bits())
    - RESULT_MINIMUM_EXPONENT as u64) as u8;

fn jump(code: &mut Vec<u8>) -> usize {
    code.push(JMP_REL32);
    let patch = code.len();
    code.extend(0i32.to_le_bytes());
    patch
}

fn shift(code: &mut Vec<u8>, opcode: &[u8], amount: u8) {
    code.extend(opcode);
    code.push(amount);
}

fn immediate64(code: &mut Vec<u8>, opcode: &[u8], value: u64) {
    code.extend(opcode);
    code.extend(value.to_le_bytes());
}

fn exception_guard(code: &mut Vec<u8>, helper: &mut Vec<usize>) {
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
    helper.push(branch(code, Condition::NotZero));
    let enabled = code.len();
    resolve(code, suppressed, enabled);
}

fn effective_environment(code: &mut Vec<u8>) {
    test_control(code, FPCR_AH);
    let nearest = branch(code, Condition::NotZero);
    environment(code);
    let done = jump(code);
    let nearest_start = code.len();
    resolve(code, nearest, nearest_start);
    environment_round(code, Rounding::NearestEven);
    let end = code.len();
    resolve(code, done, end);
}

fn constant(code: &mut Vec<u8>, format: Format, kind: Kind, destination: u8) {
    packed(code, Host::EqualDword, destination, destination);
    let (right, left) = if format == Format::Single {
        (ShiftOpcode::RightDword, ShiftOpcode::LeftDword)
    } else {
        (ShiftOpcode::RightQword, ShiftOpcode::LeftQword)
    };
    let (right_bits, left_bits) = match kind {
        Kind::Reciprocal => (format.bits() - SIGN_BITS, format.bits() - SIGN_BITS * 2),
        Kind::ReciprocalSquareRoot => (
            format.fraction_bits() + SIGN_BITS,
            format.fraction_bits() - SIGN_BITS,
        ),
    };
    right.emit(code, destination, right_bits as u8);
    left.emit(code, destination, left_bits as u8);
}

fn normal_sources(code: &mut Vec<u8>, operand: &Operand, helper: &mut Vec<usize>) {
    let minimum = if operand.kind == Kind::ReciprocalSquareRoot {
        RESULT_MINIMUM_EXPONENT
    } else {
        INPUT_MINIMUM_EXPONENT
    };
    if operand.shape == Shape::Scalar {
        for (source, minimum) in [(RIGHT, INPUT_MINIMUM_EXPONENT), (LEFT, minimum)] {
            exponent_range(code, operand.format, source, minimum);
            helper.push(branch(code, Condition::AboveOrEqual));
        }
    } else {
        prepare_vector_input_range(code, operand.format);
        vector_exponent_range(code, operand.format, operand.shape, RIGHT);
        helper.push(branch(code, Condition::NotZero));
        if operand.kind == Kind::ReciprocalSquareRoot {
            prepare_vector_result_range(code);
        }
        vector_exponent_range(code, operand.format, operand.shape, LEFT);
        helper.push(branch(code, Condition::NotZero));
    }
}

fn prehalve(code: &mut Vec<u8>, operand: &Operand) {
    if operand.format == Format::Single && operand.shape == Shape::Scalar {
        code.extend(MOVD_EAX_XMM0);
        code.push(SUB_EAX_IMM32);
        code.extend((1u32 << operand.format.fraction_bits()).to_le_bytes());
        code.extend(MOVD_XMM0_EAX);
        return;
    }
    if operand.shape == Shape::Scalar {
        prepare_vector_result_range(code);
    }
    let (shift, subtract) = if operand.format == Format::Single {
        (ShiftOpcode::LeftDword, Host::SubDword)
    } else {
        (ShiftOpcode::LeftQword, Host::SubQword)
    };
    shift.emit(
        code,
        MINIMUM_EXPONENT_VECTOR,
        operand.format.fraction_bits() as u8,
    );
    packed(code, subtract, LEFT, MINIMUM_EXPONENT_VECTOR);
    if operand.shape == Shape::Vector64 {
        packed(code, Host::MoveQword, LEFT, LEFT);
    }
}

fn commit_host_status(code: &mut Vec<u8>) {
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    commit_inexact(code);
    let end = code.len();
    resolve(code, suppressed, end);
}

/// The first pair's target PE must not contaminate the second pair's exact
/// Double-affine status. R9D/R10D retain wide/target flags across the reset.
fn widen_single_pairs(code: &mut Vec<u8>) {
    packed(code, Host::MoveAligned, SPLIT_SINGLE_LEFT, LEFT);
    packed(code, Host::MoveAligned, SAVED_SINGLE_RIGHT, RIGHT);
    packed(code, Host::MoveAligned, SAVED_SINGLE_CONSTANT, CONSTANT);
    code.extend(CVTPS2PD_XMM0_XMM7);
    code.extend(CVTPS2PD_XMM1_XMM5);
    widened_product(code, Shape::Vector128);
    save_product_status(code);
    code.extend(MOV_R9D_PRODUCT);
    code.extend(CVTPD2PS_XMM6_XMM6);
    code.extend(STMXCSR_STATUS);
    code.extend(MOV_R10D_STATUS);
    code.extend(LDMXCSR_CONTROL);
    packed(code, Host::MoveAligned, FIRST_SINGLE_PAIR, CONSTANT);
    code.extend(MOVHLPS_XMM0_XMM7);
    code.extend(MOVHLPS_XMM1_XMM5);
    code.extend(CVTPS2PD_XMM0_XMM0);
    code.extend(CVTPS2PD_XMM1_XMM1);
    emit_opcode_to(
        code,
        Format::Double,
        Shape::Vector128,
        ArithmeticOpcode::Multiply,
        LEFT,
        RIGHT,
    );
    packed(code, Host::MoveAligned, CONSTANT, SAVED_SINGLE_CONSTANT);
    emit_opcode_to(
        code,
        Format::Double,
        Shape::Vector128,
        ArithmeticOpcode::Subtract,
        CONSTANT,
        LEFT,
    );
    save_product_status(code);
    code.extend(MOV_EAX_PRODUCT);
    code.extend(OR_EAX_R9D);
    code.extend(MOV_PRODUCT_EAX);
    code.extend(CVTPD2PS_XMM6_XMM6);
    code.extend(STMXCSR_STATUS);
    code.extend(LDMXCSR_SAVED);
    code.extend(MOV_EAX_PRODUCT);
    code.extend(MOV_ECX_STATUS);
    code.extend(OR_ECX_R10D);
    code.extend(ADD_RSP_MXCSR);
    code.extend(MOVLHPS_XMM3_XMM6);
    packed(code, Host::MoveAligned, CONSTANT, FIRST_SINGLE_PAIR);
}

fn widened_product(code: &mut Vec<u8>, shape: Shape) {
    emit_opcode_to(
        code,
        Format::Double,
        shape,
        ArithmeticOpcode::Multiply,
        LEFT,
        RIGHT,
    );
    emit_opcode_to(
        code,
        Format::Double,
        shape,
        ArithmeticOpcode::Subtract,
        CONSTANT,
        LEFT,
    );
}

/// Called only after the exact-product path has restored the caller environment.
/// Double multiplication of widened Singles is exact (at most 48 bits); the
/// affine operation must also be exact before the sole target-Single rounding.
fn widened_single_fallback(code: &mut Vec<u8>, operand: &Operand, helper_start: usize) {
    packed(code, Host::MoveAligned, LEFT, SAVED_SINGLE_LEFT);
    constant(code, Format::Double, operand.kind, CONSTANT);
    effective_environment(code);
    match operand.shape {
        Shape::Scalar => {
            code.extend(CVTSS2SD_XMM0_XMM0);
            code.extend(CVTSS2SD_XMM1_XMM1);
            widened_product(code, Shape::Scalar);
            save_product_status(code);
            code.extend(CVTSD2SS_XMM6_XMM6);
            restore_environment_with_product(code);
        }
        Shape::Vector64 => {
            code.extend(CVTPS2PD_XMM0_XMM0);
            code.extend(CVTPS2PD_XMM1_XMM1);
            widened_product(code, Shape::Vector128);
            save_product_status(code);
            code.extend(CVTPD2PS_XMM6_XMM6);
            restore_environment_with_product(code);
        }
        Shape::Vector128 => widen_single_pairs(code),
    }
    let wide_inexact = reject_product_status(code);
    resolve(code, wide_inexact, helper_start);
    let invalid_target = reject_other_status(code);
    resolve(code, invalid_target, helper_start);
}

fn emit_single_double(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress, target: TargetCpu) {
    let native_fma = target.supports(TargetCpu::Fma);
    if native_fma {
        code.extend(VZEROUPPER);
    }
    let mut helper = Vec::new();
    exception_guard(code, &mut helper);
    read_numerical_vector(code, operand.shape, operand.left, LEFT);
    read_numerical_vector(code, operand.shape, operand.right, RIGHT);
    let merge = if operand.shape == Shape::Scalar
        && (!native_fma || operand.kind == Kind::ReciprocalSquareRoot)
    {
        packed(code, Host::MoveAligned, ORIGINAL_LEFT, LEFT);
        ORIGINAL_LEFT
    } else {
        // VEX scalar FMA preserves the DEST upper XMM bits, not ADDEND
        // upper bits (Intel SDM VFNMADD132SS/SD). LEFT still holds original Vn.
        LEFT
    };
    normal_sources(code, operand, &mut helper);
    if operand.kind == Kind::ReciprocalSquareRoot {
        prehalve(code, operand);
    }
    constant(code, operand.format, operand.kind, CONSTANT);
    effective_environment(code);
    let mut widen_product = None;
    let result = if native_fma {
        emit_fma(
            code,
            operand.format,
            operand.shape,
            FusedOpcode::NegativeMultiplyAdd,
            target,
        );
        restore_environment(code);
        LEFT
    } else {
        if operand.format == Format::Single {
            packed(code, Host::MoveAligned, SAVED_SINGLE_LEFT, LEFT);
        }
        emit_opcode_to(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Multiply,
            LEFT,
            RIGHT,
        );
        save_product_status(code);
        emit_opcode_to(
            code,
            operand.format,
            operand.shape,
            ArithmeticOpcode::Subtract,
            CONSTANT,
            LEFT,
        );
        restore_environment_with_product(code);
        let inexact_product = reject_product_status(code);
        if operand.format == Format::Single {
            widen_product = Some(inexact_product);
        } else {
            helper.push(inexact_product);
        }
        CONSTANT
    };
    helper.push(reject_other_status(code));
    // A finite Single/Double refinement's nonzero exact result is normal.
    // Exact cancellation follows the installed Arm rounding mode's zero sign.
    // The retained status guards reject overflow and other exceptional results.
    let success = jump(code);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    if let Some(patch) = widen_product {
        let wide_start = code.len();
        resolve(code, patch, wide_start);
        widened_single_fallback(code, operand, helper_start);
    }
    let success_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    resolve(code, success, success_start);
    commit_host_status(code);
    if operand.shape == Shape::Scalar {
        if merge != result {
            code.extend([
                if operand.format == Format::Single {
                    SINGLE_PREFIX
                } else {
                    DOUBLE_PREFIX
                },
                SSE_ESCAPE,
                MOV_SCALAR,
                REGISTER_DIRECT | merge << MODRM_REGISTER_SHIFT | result,
            ]);
        }
        test_control(code, FPCR_NEP);
        let merging = branch(code, Condition::NotZero);
        clear_scalar(code, operand.format, merge);
        let end = code.len();
        resolve(code, merging, end);
        commit(code, operand.destination, merge);
    } else {
        if operand.shape == Shape::Vector64 {
            packed(code, Host::MoveQword, result, result);
        }
        commit(code, operand.destination, result);
    }
}

/// Normal Half field construction is exact and cannot raise host FP status.
fn widen_half_lane(code: &mut Vec<u8>) {
    code.extend(LOAD_LEFT_HALF);
    code.extend(MOV_EDX_EAX);
    code.push(AND_EAX_IMM32);
    code.extend((Format::Half.sign_mask() as u32 - 1).to_le_bytes());
    shift(code, SHL_RAX, HALF_TO_DOUBLE_SHIFT);
    code.extend(ADD_RAX_R8);
    code.extend(AND_EDX_IMM32);
    code.extend((Format::Half.sign_mask() as u32).to_le_bytes());
    shift(code, SHL_RDX, HALF_TO_DOUBLE_SIGN_SHIFT);
    code.extend(OR_RAX_RDX);
    code.extend(MOVQ_XMM0_RAX);
    code.extend(LOAD_RIGHT_HALF);
    code.extend(MOV_EDX_ECX);
    code.extend(AND_ECX_IMM32);
    code.extend((Format::Half.sign_mask() as u32 - 1).to_le_bytes());
    shift(code, SHL_RCX, HALF_TO_DOUBLE_SHIFT);
    code.extend(ADD_RCX_R9);
    code.extend(AND_EDX_IMM32);
    code.extend((Format::Half.sign_mask() as u32).to_le_bytes());
    shift(code, SHL_RDX, HALF_TO_DOUBLE_SIGN_SHIFT);
    code.extend(OR_RCX_RDX);
    code.extend(MOVQ_XMM1_RCX);
}

fn round_half_magnitude(code: &mut Vec<u8>) {
    // RAX holds positive rebased Double fields, RCX the original sign.
    test_control(code, FPCR_AH);
    let nearest_ah = branch(code, Condition::NotZero);
    test_control(code, FPCR_ROUNDING_HIGH);
    let high = branch(code, Condition::NotZero);
    test_control(code, FPCR_ROUNDING_LOW);
    let positive = branch(code, Condition::NotZero);
    let nearest = code.len();
    resolve(code, nearest_ah, nearest);
    immediate64(code, MOVABS_RDX, HALF_DISCARDED_MASK >> 1);
    shift(code, BT_RAX, HALF_TO_DOUBLE_SHIFT);
    code.extend(ADC_RAX_RDX);
    let nearest_done = jump(code);
    let high_start = code.len();
    resolve(code, high, high_start);
    test_control(code, FPCR_ROUNDING_LOW);
    let truncating = branch(code, Condition::NotZero);
    code.extend(TEST_ECX_ECX);
    let negative_unmatched = branch(code, Condition::Zero);
    let negative_bias = jump(code);
    let positive_start = code.len();
    resolve(code, positive, positive_start);
    code.extend(TEST_ECX_ECX);
    let positive_unmatched = branch(code, Condition::NotZero);
    let bias_start = code.len();
    resolve(code, negative_bias, bias_start);
    immediate64(code, MOVABS_RDX, HALF_DISCARDED_MASK);
    code.extend(ADD_RAX_RDX);
    let end = code.len();
    for patch in [
        nearest_done,
        truncating,
        negative_unmatched,
        positive_unmatched,
    ] {
        resolve(code, patch, end);
    }
    shift(code, SHR_RAX, HALF_TO_DOUBLE_SHIFT);
}

fn pack_half_lane(code: &mut Vec<u8>, rollback: &mut Vec<usize>) {
    code.extend(MOVQ_RAX_XMM6);
    code.extend(MOV_RCX_RAX);
    shift(code, SHR_RCX, (Format::Double.bits() - SIGN_BITS) as u8);
    shift(code, BTR_RAX, (Format::Double.bits() - SIGN_BITS) as u8);
    code.extend(MOV_RDX_RAX);
    shift(code, SHR_RDX, Format::Double.fraction_bits() as u8);
    code.extend(SUB_EDX_IMM32);
    code.extend(
        (Format::Double.exponent_bias() - Format::Half.exponent_bias()
            + u32::from(RESULT_MINIMUM_EXPONENT))
        .to_le_bytes(),
    );
    code.extend(CMP_EDX_IMM8);
    code.push(HALF_NORMAL_EXPONENT_COUNT);
    rollback.push(branch(code, Condition::AboveOrEqual));
    code.extend(SUB_RAX_R9);
    code.extend(MOV_RDX_RAX);
    shift(
        code,
        SHL_RDX,
        Format::Double.bits() as u8 - HALF_TO_DOUBLE_SHIFT,
    );
    code.extend(SETNE_DL);
    code.extend(MOVZX_EDX_DL);
    shift(code, SHL_EDX, INEXACT.trailing_zeros() as u8);
    code.extend(OR_R10D_EDX);
    round_half_magnitude(code);
    code.extend(MOV_EDX_EAX);
    shift(code, SHR_EDX, Format::Half.fraction_bits() as u8);
    code.extend(SUB_EDX_IMM8);
    code.push(RESULT_MINIMUM_EXPONENT);
    code.extend(CMP_EDX_IMM8);
    code.push(HALF_NORMAL_EXPONENT_COUNT);
    rollback.push(branch(code, Condition::AboveOrEqual));
    shift(code, SHL_ECX, (Format::Half.bits() - SIGN_BITS) as u8);
    code.extend(OR_EAX_ECX);
    code.extend(STORE_RESULT_HALF);
}

fn emit_half(code: &mut Vec<u8>, operand: &Operand, pc: GuestAddress) {
    let mut helper = Vec::new();
    let mut rollback = Vec::new();
    exception_guard(code, &mut helper);
    read_numerical_vector(code, operand.shape, operand.left, LEFT);
    read_numerical_vector(code, operand.shape, operand.right, RIGHT);
    if operand.shape == Shape::Scalar {
        packed(code, Host::MoveAligned, ORIGINAL_LEFT, LEFT);
    }
    prepare_vector_input_range(code, Format::Half);
    for source in [LEFT, RIGHT] {
        vector_exponent_range(code, Format::Half, operand.shape, source);
        helper.push(branch(code, Condition::NotZero));
    }
    code.extend(SUB_RSP);
    code.push(HALF_STACK_BYTES);
    code.extend(SAVE_LEFT);
    code.extend(SAVE_RIGHT);
    packed(code, Host::Xor, ZERO, ZERO);
    code.extend(SAVE_ZERO_RESULT);
    let left_bias = HALF_TO_DOUBLE_BIAS
        - if operand.kind == Kind::ReciprocalSquareRoot {
            1u64 << Format::Double.fraction_bits()
        } else {
            0
        };
    immediate64(code, MOVABS_R8, left_bias);
    immediate64(code, MOVABS_R9, HALF_TO_DOUBLE_BIAS);
    constant(code, Format::Double, operand.kind, HALF_CONSTANT);
    code.extend(XOR_R10D_R10D);
    code.extend(XOR_R11D_R11D);
    let loop_start = code.len();
    widen_half_lane(code);
    // A Half product uses at most 22 significant bits. FRSQRTS prehalves
    // the widened left operand exactly and subtracts its product from 1.5.
    // Both refinement expressions need at most 51 bits, so Double arithmetic
    // is exact under every caller environment. Only one active lane executes.
    emit_opcode_to(
        code,
        Format::Double,
        Shape::Scalar,
        ArithmeticOpcode::Multiply,
        LEFT,
        RIGHT,
    );
    packed(code, Host::MoveAligned, CONSTANT, HALF_CONSTANT);
    emit_opcode_to(
        code,
        Format::Double,
        Shape::Scalar,
        ArithmeticOpcode::Subtract,
        CONSTANT,
        LEFT,
    );
    pack_half_lane(code, &mut rollback);
    code.extend(INC_R11D);
    code.extend(CMP_R11D);
    code.push(operand.shape.lane_count(Format::Half) as u8);
    let more = branch(code, Condition::Below);
    resolve(code, more, loop_start);
    code.extend(LOAD_RESULT);
    code.extend(ADD_RSP);
    code.push(HALF_STACK_BYTES);
    let success = jump(code);
    let rollback_start = code.len();
    code.extend(ADD_RSP);
    code.push(HALF_STACK_BYTES);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let commit_start = code.len();
    for patch in helper {
        resolve(code, patch, helper_start);
    }
    for patch in rollback {
        resolve(code, patch, rollback_start);
    }
    resolve(code, success, commit_start);
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    code.extend(OR_STATE_R10D);
    code.extend((std::mem::offset_of!(GuestState, fpsr) as u32).to_le_bytes());
    let status_done = code.len();
    resolve(code, suppressed, status_done);
    if operand.shape == Shape::Scalar {
        test_control(code, FPCR_NEP);
        let clearing = branch(code, Condition::Zero);
        code.extend(PINSRW_XMM7_EAX);
        packed(code, Host::MoveAligned, LEFT, ORIGINAL_LEFT);
        let merged = code.len();
        resolve(code, clearing, merged);
    }
    commit(code, operand.destination, LEFT);
}

pub(in crate::x86_64) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    pc: GuestAddress,
    target: TargetCpu,
) {
    if operand.format == Format::Half {
        emit_half(code, operand, pc);
    } else {
        emit_single_double(code, operand, pc, target);
    }
}
