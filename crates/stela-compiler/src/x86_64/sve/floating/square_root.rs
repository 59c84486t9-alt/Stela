//! SVE FSQRT: SQRTPS/SQRTPD for positive normals, +0 and +infinity.
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::FloatOp;
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures},
        scalable::{ElementSize, VectorLength},
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape},
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::rounding_control,
        sve::floating::classify::{
            guard_active_exception_enables, guard_normal_zero_or_infinity, prepare_classification,
        },
    },
};
use alloc::vec::Vec;

const VALUE: u8 = 0;
const ACTIVE: u8 = 2;
const SCRATCH: [u8; 3] = [3, 4, 5];
const OLD_DESTINATION: u8 = SCRATCH[0];
const MASKS: [u8; 2] = [6, 7];
const OUTPUT_SLOT: usize = 0;
const DOUBLE_LOW_SIGN_DWORD: u32 = 1;
const DOUBLE_HIGH_SIGN_DWORD: u32 = 3;
const DOUBLE_SIGN_LANES: u32 = (1 << DOUBLE_LOW_SIGN_DWORD) | (1 << DOUBLE_HIGH_SIGN_DWORD);
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;

fn reject(code: &mut Code, failures: &mut Vec<usize>) {
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

fn guard_nonnegative(
    code: &mut Code,
    format: Format,
    failures: &mut Vec<usize>,
    target: TargetCpu,
) {
    code.asm()
        .simd_to_gpr(Host::DwordSignMask, Rax, VALUE, target);
    if format == Format::Double {
        // MOVMSKPS sees all four dwords. Only high dwords contain Double signs;
        // the low-dword fraction sign bits must not reject positive operands.
        code.asm()
            .test_accumulator_imm(Size::Dword, DOUBLE_SIGN_LANES as i32);
    } else {
        code.asm().test(Size::Dword, Rax, Rax);
    }
    reject(code, failures);
}

fn square_root(code: &mut Code, format: Format) {
    if format == Format::Double {
        code.asm().float(
            FloatOp::Sqrt,
            FloatLanes::PackedDouble,
            VALUE,
            Rm::Xmm(VALUE),
        );
    } else {
        code.asm().float(
            FloatOp::Sqrt,
            FloatLanes::PackedSingle,
            VALUE,
            Rm::Xmm(VALUE),
        );
    }
}

/// Predicated merging FSQRT over a positive exact/rounded IEEE domain. Shared
/// rounding_control maps raw guest RMode; AH does not force RNE for FPSqrt.
/// No architectural output/status commits before the final guard succeeds.
/// Clobbers volatile RAX/RCX/RDX, host flags and XMM0..7, preserving RDI/R15 and
/// caller MXCSR through both accepted and exceptional whole-instruction exits.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let element = match operand.format {
        Format::Single => ElementSize::Word,
        Format::Double => ElementSize::Doubleword,
        Format::Half => return Ok(false),
    };
    if operand.kind != Kind::SquareRoot || operand.shape != ResultShape::Vector {
        return Ok(false);
    }
    let (Inputs::Unary { source }, Some(predicate)) = (operand.inputs, operand.predicate) else {
        return Ok(false);
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    let classification = prepare_classification(code, operand.format, MASKS, target);
    let mut failures = Vec::new();
    for chunk in 0..length.chunks() {
        read_predicate_mask(
            code,
            predicate,
            chunk,
            element,
            ACTIVE,
            OLD_DESTINATION,
            length,
            target,
        );
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, source, chunk, VALUE, length, target);
        Host::And.register(code, VALUE, ACTIVE, target);
        guard_normal_zero_or_infinity(code, classification, VALUE, SCRATCH, &mut failures, target);
        guard_nonnegative(code, operand.format, &mut failures, target);
        square_root(code, operand.format);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            OLD_DESTINATION,
            length,
            target,
        );
        Host::And.register(code, VALUE, ACTIVE, target);
        Host::AndNot.register(code, ACTIVE, OLD_DESTINATION, target);
        Host::Or.register(code, VALUE, ACTIVE, target);
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, VALUE, target);
    }
    numerical::capture_status(code, &frame);
    code.asm()
        .test_imm(Size::Dword, Rcx, MXCSR_OTHER_STATUS as i32);
    reject(code, &mut failures);
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rax, Rcx);
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_INEXACT as i32);
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, MXCSR_TO_FPSR_INEXACT_SHIFT);
    numerical::add_fpsr(code, &frame);
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
