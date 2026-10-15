//! Selected BF16 fields with exact SSE2 products or independently checked FMA.
use super::{ADDEND, LEFT, RIGHT, shuffle, test_control};
use crate::{
    TargetCpu,
    aarch64::{
        floating::features::NumericalFeatures,
        floating::{
            FPCR_AH, FPCR_EXCEPTION_ENABLE_MASK, Format,
            bfloat16::{BFLOAT16_BITS, BFLOAT16_TO_SINGLE_SHIFT},
        },
        simd::arithmetic::Shape,
        sve::dot::VectorPart,
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::numerical::{self, Frame},
        simd::numerical::{
            ArithmeticOpcode, Condition, FusedOpcode, branch, emit_fma, emit_opcode_to,
            prepare_vector_input_range, prepare_vector_result_range, resolve, rounding_control,
            vector_exponent_range,
        },
    },
};

const SIGN_BITS: u8 = 1;
const SINGLE_SIGN_SHIFT: u8 = Format::Single.bits() as u8 - SIGN_BITS;
const BFLOAT_BYTES: u8 = (BFLOAT16_BITS / u8::BITS) as u8;
const SIGN_MASK: u8 = 7;
const FIRST_DWORD: u8 = 0;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_INEXACT_TO_FPSR_SHIFT: u8 = 1;
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const MOV_EAX_ECX: &[u8] = &[0x89, 0xc8];
const TEST_ECX_IMMEDIATE: &[u8] = &[0xf7, 0xc1];
const AND_EAX_IMMEDIATE: u8 = 0x25;
const JMP_REL32: u8 = 0xe9;
const VZEROUPPER: &[u8] = &[0xc5, 0xf8, 0x77];

pub(super) fn install_environment(
    code: &mut Vec<u8>,
    frame: &Frame,
    features: NumericalFeatures,
    failures: &mut Vec<usize>,
) {
    test_control(code, FPCR_AH);
    let alternative = branch(code, Condition::NotZero);
    if features.full_a64() {
        test_control(code, FPCR_EXCEPTION_ENABLE_MASK);
        failures.push(branch(code, Condition::NotZero));
    }
    // The sole generic RC encoder has no frame, MXCSR or guest-state effect.
    rounding_control(code);
    code.push(JMP_REL32);
    let installed = code.len();
    code.extend(0_i32.to_le_bytes());
    let alternative_start = code.len();
    resolve(code, alternative, alternative_start);
    code.extend(XOR_EAX_EAX);
    let install_start = code.len();
    resolve(code, installed, install_start);
    numerical::install_mxcsr(code, frame);
}

pub(super) fn prepare_sources(
    code: &mut Vec<u8>,
    part: VectorPart,
    index: Option<u8>,
    subtract: bool,
    target: TargetCpu,
) {
    if part == VectorPart::Top {
        ShiftOpcode::RightDword.emit(code, LEFT, BFLOAT16_BITS as u8);
    }
    ShiftOpcode::LeftDword.emit(code, LEFT, BFLOAT16_TO_SINGLE_SHIFT as u8);
    if let Some(index) = index {
        if index != FIRST_DWORD {
            ShiftOpcode::RightBytes.emit(code, RIGHT, index * BFLOAT_BYTES);
        }
        shuffle(code, RIGHT, FIRST_DWORD, target);
    } else if part == VectorPart::Top {
        ShiftOpcode::RightDword.emit(code, RIGHT, BFLOAT16_BITS as u8);
    }
    ShiftOpcode::LeftDword.emit(code, RIGHT, BFLOAT16_TO_SINGLE_SHIFT as u8);
    if subtract {
        // Exceptional/NaN lanes are rejected before arithmetic, so sign toggle
        // here equals the mature core's control-sensitive BF negate operation.
        Host::EqualDword.register(code, SIGN_MASK, SIGN_MASK, target);
        ShiftOpcode::LeftDword.emit(code, SIGN_MASK, SINGLE_SIGN_SHIFT);
        Host::Xor.register(code, LEFT, SIGN_MASK, target);
    }
}

fn guard_normal(code: &mut Vec<u8>, source: u8, failures: &mut Vec<usize>) {
    vector_exponent_range(code, Format::Single, Shape::Vector128, source);
    failures.push(branch(code, Condition::NotZero));
}

fn guard_status(code: &mut Vec<u8>, frame: &Frame, mask: u32, failures: &mut Vec<usize>) {
    numerical::capture_status(code, frame);
    code.extend(TEST_ECX_IMMEDIATE);
    code.extend(mask.to_le_bytes());
    failures.push(branch(code, Condition::NotZero));
}

pub(super) fn evaluate(
    code: &mut Vec<u8>,
    frame: &Frame,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    prepare_vector_input_range(code, Format::Single);
    for source in [LEFT, RIGHT, ADDEND] {
        guard_normal(code, source, failures);
    }
    numerical::clear_status(code, frame);
    if target.supports(TargetCpu::Fma) {
        emit_fma(
            code,
            Format::Single,
            Shape::Vector128,
            FusedOpcode::MultiplyAdd,
            target,
        );
        code.extend(VZEROUPPER);
    } else {
        emit_opcode_to(
            code,
            Format::Single,
            Shape::Vector128,
            ArithmeticOpcode::Multiply,
            LEFT,
            RIGHT,
        );
        // Normal BF products have at most16 significant bits. Require an exact,
        // nonexceptional Single product before split addition can equal FMA.
        guard_status(code, frame, MXCSR_INEXACT | MXCSR_OTHER_STATUS, failures);
        guard_normal(code, LEFT, failures);
        numerical::clear_status(code, frame);
        emit_opcode_to(
            code,
            Format::Single,
            Shape::Vector128,
            ArithmeticOpcode::Add,
            LEFT,
            ADDEND,
        );
    }
    guard_status(code, frame, MXCSR_OTHER_STATUS, failures);
    prepare_vector_result_range(code);
    guard_normal(code, LEFT, failures);
    test_control(code, FPCR_AH);
    let suppressed = branch(code, Condition::NotZero);
    code.extend(MOV_EAX_ECX);
    code.push(AND_EAX_IMMEDIATE);
    code.extend(MXCSR_INEXACT.to_le_bytes());
    // MXCSR status precision bit5 maps to the cumulative FPSR precision bit4.
    // Keep ECX live until capture_status after the next real arithmetic stage.
    const SHR_EAX_IMMEDIATE: &[u8] = &[0xc1, 0xe8];
    code.extend(SHR_EAX_IMMEDIATE);
    code.push(MXCSR_INEXACT_TO_FPSR_SHIFT);
    numerical::add_fpsr(code, frame);
    let status_complete = code.len();
    resolve(code, suppressed, status_complete);
    numerical::clear_status(code, frame);
}
