//! SVE fused multiply-add: AVX512-FP16 or FMA3, or an exact-product SSE2 path.
use super::arithmetic::{broadcast_bits, element, prepare_result_range, repeat_half_lane};
use crate::x86_64::asm::Gpr::{Rax, Rcx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size, vector_extensions};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, features::NumericalFeatures, fused::FusedOperation},
        scalable::{BITS_PER_BYTE, VECTOR_CHUNK_BYTES, VectorLength},
        simd::arithmetic::Shape,
        sve::floating::arithmetic::{Inputs, Kind, Operand, ResultShape, Source},
    },
    x86_64::{
        isa::{ShiftOpcode, SimdOpcode as Host},
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{
            ArithmeticOpcode, FusedOpcode, emit_fma, emit_opcode_to, prepare_vector_input_range,
            rounding_control, vector_exponent_range,
        },
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const LEFT: u8 = 0;
const RIGHT: u8 = 1;
const MASK_SCRATCH: u8 = 2;
const CONSTANT_SCRATCH: u8 = 3;
const ADDEND: u8 = 6;
const ACTIVE: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const SINGLE_BROADCAST_STRIDE: u8 = 0x55;
const DOUBLE_LOW_BROADCAST: u8 = 0x44;
const DOUBLE_HIGH_BROADCAST: u8 = 0xee;
const HALF_LANES_PER_CHUNK: u8 = 8;
const BENIGN_ADDEND_INCREMENT: u32 = 1;
const MXCSR_INEXACT: u32 = 1 << 5;
const MXCSR_OTHER_STATUS: u32 = MXCSR_INEXACT - 1;
const MXCSR_TO_FPSR_INEXACT_SHIFT: u8 = 1;

fn reject(code: &mut Code, failures: &mut Vec<usize>) {
    failures.push(code.asm().jcc(Cond::Ne).offset());
}

/// Inactive 2 + 1*1 and every signed variant are exact normal results.
fn benign_inactive(code: &mut Code, format: Format, input: u8, target: TargetCpu) {
    let increment = if input == ADDEND {
        BENIGN_ADDEND_INCREMENT
    } else {
        0
    };
    let bits = u64::from(format.exponent_bias() + increment) << format.fraction_bits();
    broadcast_bits(code, format, bits, CONSTANT_SCRATCH, target);
    Host::MoveAligned.register(code, MASK_SCRATCH, ACTIVE, target);
    Host::AndNot.register(code, MASK_SCRATCH, CONSTANT_SCRATCH, target);
    Host::And.register(code, input, ACTIVE, target);
    Host::Or.register(code, input, MASK_SCRATCH, target);
}

fn load_right(
    code: &mut Code,
    source: Source,
    format: Format,
    chunk: usize,
    length: VectorLength,
    target: TargetCpu,
) {
    let register = match source {
        Source::Vector(register) | Source::Indexed { register, .. } => register,
        Source::ImmediateBits(_) => unreachable!("validated fused register source"),
    };
    load_z_chunk(code, register, chunk, RIGHT, length, target);
    if let Source::Indexed { index, .. } = source {
        let order = match format {
            Format::Half => return repeat_half_lane(code, RIGHT, index, target),
            Format::Single => index * SINGLE_BROADCAST_STRIDE,
            Format::Double => {
                if index == 0 {
                    DOUBLE_LOW_BROADCAST
                } else {
                    DOUBLE_HIGH_BROADCAST
                }
            }
        };
        code.asm()
            .simd_imm(Host::ShuffleDword, RIGHT, Rm::Xmm(RIGHT), order, target);
    }
}

fn negate_baseline(code: &mut Code, operation: FusedOperation, format: Format, target: TargetCpu) {
    if !operation.negate_left() && !operation.negate_addend() {
        return;
    }
    Host::EqualDword.register(code, MASK_SCRATCH, MASK_SCRATCH, target);
    let shift = if format == Format::Single {
        ShiftOpcode::LeftDword
    } else {
        ShiftOpcode::LeftQword
    };
    shift.emit(code, MASK_SCRATCH, (format.bits() - 1) as u8);
    if operation.negate_left() {
        Host::Xor.register(code, LEFT, MASK_SCRATCH, target);
    }
    if operation.negate_addend() {
        Host::Xor.register(code, ADDEND, MASK_SCRATCH, target);
    }
}

/// Emit the fourteen fused forms, natively only for normal values, with Half
/// on its AVX512-FP16 instructions; software completion handles the rest.
/// RDI/R15 and the guest sources
/// survive; RAX/RCX/RDX, flags and XMM0-7 are clobbered. `TargetCpu::Fma`
/// implies OS-enabled AVX state; the baseline target never emits VEX.
pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Some(element) = element(operand.format, target) else {
        return Ok(false);
    };
    let (
        Kind::Fused(operation),
        Inputs::Fused {
            addend,
            left,
            right,
        },
        ResultShape::Vector,
    ) = (operand.kind, operand.inputs, operand.shape)
    else {
        return Ok(false);
    };
    match right {
        Source::Vector(_) => {}
        Source::Indexed { index, .. }
            if usize::from(index)
                < VECTOR_CHUNK_BYTES * BITS_PER_BYTE / operand.format.bits() as usize => {}
        _ => return Ok(false),
    }
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    rounding_control(code);
    numerical::install_mxcsr(code, &frame);
    let mut failures = Vec::new();
    let native_fma = target.supports(TargetCpu::Fma);
    for chunk in 0..length.chunks() {
        if let Some(predicate) = operand.predicate {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                element,
                crate::x86_64::scalable::MaskRegisters::new(ACTIVE, MASK_SCRATCH),
                length,
                target,
            );
        } else if features.full_a64() {
            Host::EqualDword.register(code, ACTIVE, ACTIVE, target);
        }
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(code, left, chunk, LEFT, length, target);
        load_right(code, right, operand.format, chunk, length, target);
        load_z_chunk(code, addend, chunk, ADDEND, length, target);
        if operand.predicate.is_some() {
            for input in [LEFT, RIGHT, ADDEND] {
                benign_inactive(code, operand.format, input, target);
            }
        }
        prepare_vector_input_range(code, operand.format);
        for input in [LEFT, RIGHT, ADDEND] {
            vector_exponent_range(code, operand.format, Shape::Vector128, input);
            reject(code, &mut failures);
        }
        numerical::clear_status(code, &frame);
        if operand.format == Format::Half {
            vector_extensions::half_writemask(code, HALF_LANES_PER_CHUNK);
            vector_extensions::half_fused(
                code,
                FusedOpcode::from(operation) as u8,
                LEFT,
                ADDEND,
                RIGHT,
            );
        } else if native_fma {
            emit_fma(
                code,
                operand.format,
                Shape::Vector128,
                FusedOpcode::from(operation),
                target,
            );
            // FMA has completed; clean upper AVX state before legacy guards or any exit.
            // Every host SIMD register is caller-volatile under this backend ABI.
            code.asm().vzeroupper();
        } else {
            negate_baseline(code, operation, operand.format, target);
            emit_opcode_to(
                code,
                operand.format,
                Shape::Vector128,
                ArithmeticOpcode::Multiply,
                LEFT,
                RIGHT,
            );
            // An exact normal product allows a separate ADD with one rounding;
            // any product status rejects the instruction.
            numerical::capture_status(code, &frame);
            code.asm().test(Size::Dword, Rcx, Rcx);
            reject(code, &mut failures);
            prepare_result_range(code, operand.format);
            vector_exponent_range(code, operand.format, Shape::Vector128, LEFT);
            reject(code, &mut failures);
            numerical::clear_status(code, &frame);
            emit_opcode_to(
                code,
                operand.format,
                Shape::Vector128,
                ArithmeticOpcode::Add,
                LEFT,
                ADDEND,
            );
        }
        prepare_result_range(code, operand.format);
        vector_exponent_range(code, operand.format, Shape::Vector128, LEFT);
        reject(code, &mut failures);
        numerical::capture_status(code, &frame);
        code.asm()
            .test_imm(Size::Dword, Rcx, MXCSR_OTHER_STATUS as i32);
        reject(code, &mut failures);
        let mut asm = code.asm();
        asm.mov(Size::Dword, Rax, Rcx);
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_INEXACT as i32);
        asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, MXCSR_TO_FPSR_INEXACT_SHIFT);
        numerical::add_fpsr(code, &frame);
        if operand.predicate.is_some() {
            load_z_chunk(code, operand.destination, chunk, RIGHT, length, target);
            Host::And.register(code, LEFT, ACTIVE, target);
            Host::AndNot.register(code, ACTIVE, RIGHT, target);
            Host::Or.register(code, LEFT, ACTIVE, target);
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, LEFT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
