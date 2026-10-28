//! BF16 fused multiply-add through exact double arithmetic. Close exponents make
//! the product and sum exact in double; round-to-odd then feeds BF16 rounding.
use crate::x86_64::asm::FloatLanes;
use crate::x86_64::asm::FloatOp;
use crate::x86_64::asm::Gpr::{R10, Rax, Rcx, Rdx};
use crate::x86_64::asm::{Alu, Code, Cond, Rm, ShiftOp, Size, Unary};
use crate::{
    CompileError, GuestAddress, TargetCpu,
    aarch64::{
        floating::{Format, INEXACT, features::NumericalFeatures},
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::{
            dot::RightOperand,
            floating::bfloat16::{Kind, Operand},
        },
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{
            load_z_chunk,
            numerical::{self, Environment, Output},
            read_predicate_mask,
        },
        simd::numerical::{integer_rounding_policy, quantize_bfloat_scalar_bits},
        sve::floating::classify::guard_active_exception_enables,
    },
};
use alloc::vec::Vec;

const RESULT: u8 = 0;
const ACCUMULATOR: u8 = 1;
const LEFT: u8 = 2;
const RIGHT: u8 = 3;
const DOUBLE_ACCUMULATOR: u8 = 4;
const ACTIVE: u8 = 5;
const DOUBLE_LEFT: u8 = 6;
const DOUBLE_RIGHT: u8 = 7;
const OUTPUT_SLOT: usize = 0;
const BFLOAT_BYTES: usize = size_of::<u16>();
const CHUNK_LANES: usize = VECTOR_CHUNK_BYTES / BFLOAT_BYTES;
const BFLOAT_FRACTION_BITS: u8 = 7;
const BFLOAT_EXPONENT_MASK: u32 = 255;
const BFLOAT_EXPONENT_BIAS: u32 = 127;
const BFLOAT_SIGN_MASK: u32 = 1 << 15;
const SINGLE_TO_BFLOAT_SHIFT: u8 = 16;
const DOUBLE_TO_SINGLE_SHIFT: u8 = 29;
const STICKY_MASK: u32 = (1 << DOUBLE_TO_SINGLE_SHIFT) - 1;
const SINGLE_SIGN_MASK: u32 = 1 << 31;
const SINGLE_EXPONENT_MASK: u32 = 255 << 23;
const EXPONENT_REBIAS: u64 = (1023 - 127) << 23;
const MINIMUM_DOUBLE_EXPONENT: u32 = 1023 - 127 + 1;
const NORMAL_EXPONENT_INTERVAL: u32 = 253;
const EXACT_EXPONENT_DISTANCE: u8 = 32;

fn extract(code: &mut Code, source: u8, lane: usize) {
    code.asm().pextrw(Rax, source, lane as u8);
}

/// Preserve raw BF16 in EAX and its biased exponent in ECX. Reject zeros,
/// subnormals and nonfinite values before any host floating-point instruction.
fn normal_input(code: &mut Code, failures: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rcx, Rax);
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rcx, BFLOAT_FRACTION_BITS);
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, BFLOAT_EXPONENT_MASK as i32);
    asm.mov(Size::Dword, Rdx, Rcx);
    asm.alu_imm8(Alu::Sub, Size::Dword, Rdx, 1);
    asm.alu_imm32(Alu::Cmp, Size::Dword, Rdx, NORMAL_EXPONENT_INTERVAL as i32);
    failures.push(asm.jcc(Cond::A).offset());
}

fn widen(code: &mut Code, destination: u8) {
    let mut asm = code.asm();
    asm.shift_imm(ShiftOp::Shl, Size::Dword, Rax, SINGLE_TO_BFLOAT_SHIFT);
    asm.movd_to_xmm(destination, Rax);
    asm.cvtss2sd(destination, Rm::Xmm(destination));
}

/// Product precision is at most16 bits. With |eL+eR-eA| <=32, aligning the
/// accumulator and product requires at most48 significant bits plus one carry,
/// fitting Double53 even before cancellation. Both Double operations are exact.
fn exact_exponent_guard(code: &mut Code, failures: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Sub, Size::Dword, R10, BFLOAT_EXPONENT_BIAS as i8);
    asm.alu_imm8(Alu::Add, Size::Dword, R10, EXACT_EXPONENT_DISTANCE as i8);
    asm.alu_imm8(
        Alu::Cmp,
        Size::Dword,
        R10,
        (EXACT_EXPONENT_DISTANCE * 2) as i8,
    );
    failures.push(asm.jcc(Cond::A).offset());
}

/// Compress an exact Double to a rebased Single-shaped integer representation.
/// The low29 discarded bits become one sticky bit. Sixteen retained guard bits
/// remain below BF precision, so every final BF rounding mode sees the same
/// below-half/equal-half/above-half and nonzero-remainder classification.
fn compress(code: &mut Code, failures: &mut Vec<usize>) {
    let mut asm = code.asm();
    asm.movq_from_xmm(Rax, 6);
    asm.mov(Size::Qword, Rcx, Rax);
    asm.shift_imm(
        ShiftOp::Shr,
        Size::Qword,
        Rcx,
        Format::Double.fraction_bits() as u8,
    );
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, 0x7ff);
    asm.alu_imm32(Alu::Sub, Size::Dword, Rcx, MINIMUM_DOUBLE_EXPONENT as i32);
    asm.alu_imm32(Alu::Cmp, Size::Dword, Rcx, NORMAL_EXPONENT_INTERVAL as i32);
    failures.push(asm.jcc(Cond::A).offset());
    asm.test_accumulator_imm(Size::Dword, STICKY_MASK as i32);
    asm.setcc(Cond::Ne, Rcx);
    asm.movzx(Size::Dword, R10, Size::Byte, Rcx);
    asm.mov(Size::Qword, Rdx, Rax);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Rdx, u32::BITS as u8);
    asm.alu_imm32(Alu::And, Size::Dword, Rdx, SINGLE_SIGN_MASK as i32);
    asm.shift_imm(ShiftOp::Shr, Size::Qword, Rax, DOUBLE_TO_SINGLE_SHIFT);
    asm.mov_imm64(Rcx, EXPONENT_REBIAS);
    asm.alu(Alu::Sub, Size::Qword, Rax, Rcx);
    asm.alu(Alu::Or, Size::Dword, Rax, R10);
    asm.alu(Alu::Or, Size::Dword, Rax, Rdx);
}

/// Shared R8D/R9D/R11D selectors own RC and nearest-even parity. Every discarded
/// bit records true-BF IXC, including AH1. Pending status commits only at finish.
fn quantize(code: &mut Code, frame: &numerical::Frame, failures: &mut Vec<usize>) {
    // R10D holds the compression sticky bit, which is already part of EAX.
    // The shared helper's OR-accumulation therefore records exactly low16.
    quantize_bfloat_scalar_bits(code);
    let mut asm = code.asm();
    asm.test(Size::Dword, R10, R10);
    let exact = asm.jcc(Cond::E);
    asm.mov(Size::Dword, R10, Rax);
    asm.mov_imm32(Rax, INEXACT);
    numerical::add_fpsr(code, frame);
    let mut asm = code.asm();
    asm.mov(Size::Dword, Rax, R10);
    asm.bind(exact);
    asm.mov(Size::Dword, Rcx, Rax);
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, SINGLE_EXPONENT_MASK as i32);
    asm.alu_imm32(Alu::Cmp, Size::Dword, Rcx, SINGLE_EXPONENT_MASK as i32);
    failures.push(asm.jcc(Cond::E).offset());
    asm.shift_imm(ShiftOp::Shr, Size::Dword, Rax, SINGLE_TO_BFLOAT_SHIFT);
}

pub(in crate::x86_64) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    features: NumericalFeatures,
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<bool, CompileError> {
    let Kind::MultiplyAdd { subtract } = operand.kind else {
        return Ok(false);
    };
    let (right, index) = match operand.right {
        RightOperand::Vector(register) => (register, None),
        RightOperand::Indexed { register, index } if index < CHUNK_LANES as u8 => {
            (register, Some(index))
        }
        RightOperand::Indexed { .. } => return Ok(false),
    };
    let frame = numerical::begin(
        code,
        length,
        &[Output::Z(operand.destination)],
        Environment::PrivateMxcsr,
    )?;
    let mut failures = Vec::new();
    // Exact admitted arithmetic is independent of host RC. Fixed RN also makes
    // the private environment auditable; final BF RC remains the shared policy.
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    numerical::install_mxcsr(code, &frame);
    integer_rounding_policy(code, SINGLE_TO_BFLOAT_SHIFT, false);
    for chunk in 0..length.chunks() {
        if let Some(predicate) = operand.predicate {
            read_predicate_mask(
                code,
                predicate,
                chunk,
                ElementSize::Halfword,
                crate::x86_64::scalable::MaskRegisters::new(ACTIVE, RESULT),
                length,
                target,
            );
        } else {
            Host::EqualWord.register(code, ACTIVE, ACTIVE, target);
        }
        guard_active_exception_enables(code, ACTIVE, features, &mut failures, target);
        load_z_chunk(
            code,
            operand.destination,
            chunk,
            ACCUMULATOR,
            length,
            target,
        );
        load_z_chunk(code, operand.left, chunk, LEFT, length, target);
        load_z_chunk(code, right, chunk, RIGHT, length, target);
        Host::MoveAligned.register(code, RESULT, ACCUMULATOR, target);
        for lane in 0..CHUNK_LANES {
            extract(code, ACTIVE, lane);
            let mut asm = code.asm();
            asm.test(Size::Dword, Rax, Rax);
            let inactive = asm.jcc(Cond::E);
            extract(code, ACCUMULATOR, lane);
            normal_input(code, &mut failures);
            let mut asm = code.asm();
            asm.mov(Size::Dword, R10, Rcx);
            asm.unary(Unary::Neg, Size::Dword, R10);
            widen(code, DOUBLE_ACCUMULATOR);
            extract(code, LEFT, lane);
            normal_input(code, &mut failures);
            code.asm().alu(Alu::Add, Size::Dword, R10, Rcx);
            if subtract {
                code.asm()
                    .alu_accumulator_imm32(Alu::Xor, Size::Dword, BFLOAT_SIGN_MASK as i32);
            }
            widen(code, DOUBLE_LEFT);
            extract(code, RIGHT, index.map_or(lane, usize::from));
            normal_input(code, &mut failures);
            code.asm().alu(Alu::Add, Size::Dword, R10, Rcx);
            exact_exponent_guard(code, &mut failures);
            widen(code, DOUBLE_RIGHT);
            let mut asm = code.asm();
            asm.float(
                FloatOp::Mul,
                FloatLanes::ScalarDouble,
                DOUBLE_LEFT,
                Rm::Xmm(DOUBLE_RIGHT),
            );
            asm.float(
                FloatOp::Add,
                FloatLanes::ScalarDouble,
                DOUBLE_LEFT,
                Rm::Xmm(DOUBLE_ACCUMULATOR),
            );
            compress(code, &mut failures);
            quantize(code, &frame, &mut failures);
            let mut asm = code.asm();
            asm.pinsrw(RESULT, Rax, lane as u8);
            asm.bind(inactive);
        }
        numerical::stage_vector_chunk(code, &frame, OUTPUT_SLOT, chunk, RESULT, target);
    }
    numerical::finish(code, &frame, &failures, pc, target);
    Ok(true)
}
