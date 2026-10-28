//! BFMLALB/BFMLALT with exact SSE2 products or FMA3.
use super::{ADDEND, LEFT, RIGHT, shuffle, test_control};
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, ShiftOp, Size};
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
use alloc::vec::Vec;

const SIGN_BITS: u8 = 1;
const SINGLE_SIGN_SHIFT: u8 = Format::Single.bits() as u8 - SIGN_BITS;
const BFLOAT_BYTES: u8 = (BFLOAT16_BITS / u8::BITS) as u8;
const SIGN_MASK: u8 = 7;
const FIRST_DWORD: u8 = 0;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_INEXACT_TO_FPSR_SHIFT: u8 = 1;

pub(super) fn install_environment(
    code: &mut Code,
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
    // The rounding-control encoder has no frame, MXCSR or guest-state effect.
    rounding_control(code);
    let installed = code.asm().jmp().offset();
    let alternative_start = code.len();
    resolve(code, alternative, alternative_start);
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    let install_start = code.len();
    resolve(code, installed, install_start);
    numerical::install_mxcsr(code, frame);
}

pub(super) fn prepare_sources(
    code: &mut Code,
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

fn guard_normal(code: &mut Code, source: u8, failures: &mut Vec<usize>) {
    vector_exponent_range(code, Format::Single, Shape::Vector128, source);
    failures.push(branch(code, Condition::NotZero));
}

fn guard_status(code: &mut Code, frame: &Frame, mask: u32, failures: &mut Vec<usize>) {
    numerical::capture_status(code, frame);
    code.asm().test_imm(Size::Dword, Rcx, mask as i32);
    failures.push(branch(code, Condition::NotZero));
}

pub(super) fn evaluate(
    code: &mut Code,
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
        code.asm().vzeroupper();
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
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rax, Rcx);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_INEXACT as i32);
    // MXCSR status precision bit5 maps to the cumulative FPSR precision bit4.
    // Keep ECX live until capture_status after the next real arithmetic stage.
    code.asm()
        .shift_imm(ShiftOp::Shr, Size::Dword, Rax, MXCSR_INEXACT_TO_FPSR_SHIFT);
    numerical::add_fpsr(code, frame);
    let status_complete = code.len();
    resolve(code, suppressed, status_complete);
    numerical::clear_status(code, frame);
}
