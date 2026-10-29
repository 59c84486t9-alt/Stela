//! Half-precision lane unpacking, rounding and packing for normal values.
use super::numerical::jump;
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::{Alu, Asm, Code, Gpr, Mem, Rm, ShiftOp, Size};
use crate::x86_64::simd::encode::guest;
use alloc::vec::Vec;
mod kernel;
use super::numerical::{Condition, RESULT_MINIMUM_EXPONENT, branch, resolve, test_control};
use super::{Host, packed};
use crate::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::floating::{FPCR_AH, FPCR_NEP, FPCR_ROUNDING_SHIFT, Format, INEXACT},
    block::ExitKind,
};

pub(super) const LEFT: u8 = 0;
pub(super) const RIGHT: u8 = 1;
pub(super) const RESULT: u8 = 6;
pub(super) const ORIGINAL_LEFT: u8 = 7;
const ZERO: u8 = 2;
const FIRST_LANE: u8 = 0;
const SIGN_BITS: u32 = 1;
const FPCR_ROUNDING_LOW: u32 = 1 << FPCR_ROUNDING_SHIFT;
const FPCR_ROUNDING_HIGH: u32 = FPCR_ROUNDING_LOW << 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::x86_64) enum RoundingPolicy {
    Fpcr,
    AhNearestEven,
}

#[derive(Clone, Copy)]
pub(super) enum LeftScale {
    Identity,
    Halved,
}

#[derive(Clone, Copy)]
pub(in crate::x86_64) enum ResultSign {
    Preserve,
    Negate,
    Absolute,
}

// Half sources/results remain private until every active lane has passed.
// Only SysV caller-volatile GPRs are used; RSI remains untouched.
const HOST_VECTOR_BYTES: u8 = 16;
const HALF_RIGHT_SLOT: u8 = HOST_VECTOR_BYTES;
const HALF_RESULT_SLOT: u8 = HOST_VECTOR_BYTES * 2;
const HALF_STACK_BYTES: u8 = HALF_RESULT_SLOT + HOST_VECTOR_BYTES;
/// R10D accumulates fresh IXC; R11D indexes the active lane.
const INEXACT_LANES: Gpr = Gpr::R10;
const LANE: Gpr = Gpr::R11;
/// R8 and R9 hold the left and unscaled Half-to-Double biases.
const LEFT_BIAS: Gpr = Gpr::R8;
const PACK_BIAS: Gpr = Gpr::R9;
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

/// `[rsp + slot]` in the private frame.
fn slot(offset: u8) -> Mem {
    Mem::base(Gpr::Rsp, offset.into())
}

/// `[rsp + r11*2 + slot]`: the active Half lane of a frame slot.
fn lane(offset: u8) -> Mem {
    Mem::indexed(Gpr::Rsp, LANE, 2, offset.into())
}

/// Reserve (`Alu::Sub`) or release (`Alu::Add`) the private frame.
fn frame(code: &mut Code, op: Alu) {
    code.asm()
        .alu_imm8(op, Size::Qword, Gpr::Rsp, HALF_STACK_BYTES as i8);
}

/// `and register32, imm32`, in the accumulator short form for EAX.
fn and_imm32(asm: &mut Asm, register: Gpr, value: u32) {
    if register == Gpr::Rax {
        asm.alu_accumulator_imm32(Alu::And, Size::Dword, value as i32);
    } else {
        asm.alu_imm32(Alu::And, Size::Dword, register, value as i32);
    }
}

/// Widen the normal raw Half in `value` to exact Double fields in `vector`,
/// rebasing its exponent by `bias`. EDX and flags are clobbered.
fn widen_fields(code: &mut Code, value: Gpr, bias: Gpr, vector: u8) {
    let sign = Format::Half.sign_mask() as u32;
    let mut asm = code.asm();
    asm.mov(Size::Dword, Gpr::Rdx, value);
    and_imm32(&mut asm, value, sign - 1);
    asm.shift_imm(ShiftOp::Shl, Size::Qword, value, HALF_TO_DOUBLE_SHIFT);
    asm.alu(Alu::Add, Size::Qword, value, bias);
    asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rdx, sign as i32);
    asm.shift_imm(
        ShiftOp::Shl,
        Size::Qword,
        Gpr::Rdx,
        HALF_TO_DOUBLE_SIGN_SHIFT,
    );
    asm.alu(Alu::Or, Size::Qword, value, Gpr::Rdx);
    asm.movq_to_xmm(vector, value);
}

/// Inputs XMM0/XMM1 are snapshotted before any widened lane overwrites them.
pub(super) fn allocate_frame(code: &mut Code) {
    let baseline = TargetCpu::Baseline;
    frame(code, Alu::Sub);
    Host::StoreUnaligned.emit(code, LEFT, slot(0), baseline);
    Host::StoreUnaligned.emit(code, RIGHT, slot(HALF_RIGHT_SLOT), baseline);
    packed(code, Host::Xor, ZERO, ZERO);
    Host::StoreUnaligned.emit(code, ZERO, slot(HALF_RESULT_SLOT), baseline);
}

pub(super) fn set_biases(code: &mut Code, scale: LeftScale) {
    let left_bias = HALF_TO_DOUBLE_BIAS
        - match scale {
            LeftScale::Identity => 0,
            LeftScale::Halved => 1u64 << Format::Double.fraction_bits(),
        };
    code.asm().mov_imm64(LEFT_BIAS, left_bias);
    set_pack_bias(code);
}

/// Checked hardware widening needs only the integer packer's unscaled bias.
pub(super) fn set_pack_bias(code: &mut Code) {
    code.asm().mov_imm64(PACK_BIAS, HALF_TO_DOUBLE_BIAS);
}

/// Family constants may be prepared after biases and before this loop label.
pub(super) fn start_lanes(code: &mut Code) -> usize {
    let mut asm = code.asm();
    asm.alu(Alu::Xor, Size::Dword, INEXACT_LANES, INEXACT_LANES);
    asm.alu(Alu::Xor, Size::Dword, LANE, LANE);
    code.len()
}

/// Normal Half field construction is exact and cannot raise host FP status.
pub(super) fn widen_lane(code: &mut Code) {
    code.asm().movzx(Size::Dword, Gpr::Rax, Size::Word, lane(0));
    widen_fields(code, Gpr::Rax, LEFT_BIAS, LEFT);
    code.asm()
        .movzx(Size::Dword, Gpr::Rcx, Size::Word, lane(HALF_RIGHT_SLOT));
    widen_fields(code, Gpr::Rcx, PACK_BIAS, RIGHT);
}

/// Normal Half to Single to Double is exact. MOVZX and MOVD zero all inactive
/// lanes before the packed hardware conversion, including poisoned scalar bits.
pub(super) fn widen_lane_checked(code: &mut Code, target: TargetCpu) {
    for (register, vector) in [(Gpr::Rax, LEFT), (Gpr::Rcx, RIGHT)] {
        let offset = if vector == LEFT { 0 } else { HALF_RIGHT_SLOT };
        let mut asm = code.asm();
        asm.movzx(Size::Dword, register, Size::Word, lane(offset));
        asm.movd_to_xmm(vector, register);
        Host::ConvertHalfToSingle.register(code, vector, vector, target);
        code.asm().cvtss2sd(vector, Rm::Xmm(vector));
    }
}

pub(super) fn pack_lane(
    code: &mut Code,
    rollback: &mut Vec<usize>,
    rounding: RoundingPolicy,
    sign: ResultSign,
) {
    kernel::emit_normal(code, rollback, rounding, sign);
    code.asm()
        .mov_store(Size::Word, lane(HALF_RESULT_SLOT), Gpr::Rax);
}

/// Every failed output guard drops private status/results and restores RSP.
/// Successful lanes return an assembled XMM0, final Half EAX and fresh IXC R10D.
pub(super) fn finish_lanes(
    code: &mut Code,
    lanes: u8,
    loop_start: usize,
    helper: &[usize],
    rollback: &[usize],
    pc: GuestAddress,
) {
    let mut asm = code.asm();
    asm.inc(Size::Dword, LANE);
    asm.alu_imm8(Alu::Cmp, Size::Dword, LANE, lanes as i8);
    let more = branch(code, Condition::Below);
    resolve(code, more, loop_start);
    Host::LoadUnaligned.emit(code, LEFT, slot(HALF_RESULT_SLOT), TargetCpu::Baseline);
    frame(code, Alu::Add);
    let success = jump(code);
    let rollback_start = code.len();
    frame(code, Alu::Add);
    let helper_start = code.len();
    super::super::block::direct_exit(code, pc, ExitKind::FloatingPoint);
    let commit_start = code.len();
    for &patch in helper {
        resolve(code, patch, helper_start);
    }
    for &patch in rollback {
        resolve(code, patch, rollback_start);
    }
    resolve(code, success, commit_start);
}

/// The caller applies instruction-specific AH status policy before this store.
pub(super) fn commit_inexact(code: &mut Code) {
    code.asm().alu(
        Alu::Or,
        Size::Dword,
        guest(core::mem::offset_of!(GuestState, fpsr) as u32),
        INEXACT_LANES,
    );
}

/// Original Vn is XMM7. Scalar-pair callers skip NEP merging entirely.
pub(super) fn merge_scalar(code: &mut Code) {
    test_control(code, FPCR_NEP);
    let clearing = branch(code, Condition::Zero);
    code.asm().pinsrw(ORIGINAL_LEFT, Gpr::Rax, FIRST_LANE);
    packed(code, Host::MoveAligned, LEFT, ORIGINAL_LEFT);
    let merged = code.len();
    resolve(code, clearing, merged);
}

/// Round one Double in XMM6 to IEEE Half fields in EAX, or preserve signed zero.
///
/// The caller clears R10D once; accepted lanes OR fresh IXC into it. Nonzero
/// inputs and rounded results keep the mature Half exponent 2..30 guards.
/// Callers own enabled-exception policy, finite-domain proofs, staging, fallback
/// cleanup and guest commit. No frame, host environment, store or CALL is emitted.
/// Clobbers RAX/RCX/RDX/R9/R10 and flags; every XMM and other GPR survives.
pub(in crate::x86_64) fn emit_normal_or_zero(code: &mut Code, failures: &mut Vec<usize>) {
    set_pack_bias(code);
    let mut asm = code.asm();
    asm.movq_from_xmm(Gpr::Rax, RESULT);
    asm.mov(Size::Qword, Gpr::Rdx, Gpr::Rax);
    asm.bit_imm(
        BitTest::Btr,
        Size::Qword,
        Gpr::Rdx,
        (Format::Double.bits() - SIGN_BITS) as u8,
    );
    asm.test(Size::Qword, Gpr::Rdx, Gpr::Rdx);
    let nonzero = branch(code, Condition::NotZero);
    code.asm().shift_imm(
        ShiftOp::Shr,
        Size::Qword,
        Gpr::Rax,
        HALF_TO_DOUBLE_SIGN_SHIFT,
    );
    let zero_done = jump(code);
    let normal_start = code.len();
    resolve(code, nonzero, normal_start);
    kernel::emit_normal(code, failures, RoundingPolicy::Fpcr, ResultSign::Preserve);
    let end = code.len();
    resolve(code, zero_done, end);
}

pub(in crate::x86_64) use kernel::emit_normal as pack_normal;

/// Widen one caller-guarded finite normal raw Half in EAX to exact Double
/// XMM6. R9 contains the unscaled Half-to-Double bias. Only RAX/RDX/flags and
/// XMM6 are clobbered; no frame or MXCSR change occurs. Checked F16C receives
/// an isolated Half with zero upper lanes, preserving the existing kernel.
pub(in crate::x86_64) fn widen_normal(code: &mut Code, target: TargetCpu) {
    if target.supports(TargetCpu::F16c) {
        // Isolate the selected Half before packed conversion: the next lane in
        // XMM7 may be an inactive sNaN. MOVD also zeros every higher Half lane.
        let mut asm = code.asm();
        asm.movzx(Size::Dword, Gpr::Rax, Size::Word, Gpr::Rax);
        asm.movd_to_xmm(RESULT, Gpr::Rax);
        Host::ConvertHalfToSingle.register(code, RESULT, RESULT, target);
        code.asm().cvtss2sd(RESULT, Rm::Xmm(RESULT));
        return;
    }
    widen_fields(code, Gpr::Rax, PACK_BIAS, RESULT);
}
