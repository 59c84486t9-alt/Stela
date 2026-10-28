//! Scalar element shifts and saturation.
use super::stack_vector;
use crate::aarch64::{
    scalable::ElementSize,
    sve::shifts::{Count, Kind},
};
use crate::x86_64::asm::Gpr::{R10, Rax, Rcx, Rdx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Mem, ShiftOp, Size, Unary};
use alloc::vec::Vec;

const CHUNK_BYTES: usize = 16;
const BITS_PER_BYTE: u8 = 8;
const HOST_BITS: u8 = 64;
const SOURCE_SLOT: u8 = 0;
const COUNT_SLOT: u8 = 16;
const RESULT_SLOT: u8 = 32;
pub(super) const STACK_BYTES: u8 = 48;

fn slot(offset: u8) -> Mem {
    Mem::base_disp8(Rsp, offset as i8)
}

fn load_lane(code: &mut Code, bytes: usize, signed: bool, offset: u8) {
    let source = slot(offset);
    let mut asm = code.asm();
    match (bytes, signed) {
        (1, false) => asm.movzx(Size::Dword, Rax, Size::Byte, source),
        (1, true) => asm.movsx(Size::Qword, Rax, Size::Byte, source),
        (2, false) => asm.movzx(Size::Dword, Rax, Size::Word, source),
        (2, true) => asm.movsx(Size::Qword, Rax, Size::Word, source),
        (4, false) => asm.mov_load(Size::Dword, Rax, source),
        (4, true) => asm.movsxd(Rax, source),
        (8, _) => asm.mov_load(Size::Qword, Rax, source),
        _ => unreachable!("integer element width"),
    }
}

fn store_lane(code: &mut Code, bytes: usize, offset: u8) {
    let size = match bytes {
        1 => Size::Byte,
        2 => Size::Word,
        4 => Size::Dword,
        8 => Size::Qword,
        _ => unreachable!("integer element width"),
    };
    code.asm().mov_store(size, slot(offset), Rax);
}

fn shift_count(code: &mut Code, op: ShiftOp, register: Gpr) {
    code.asm().shift_cl(op, Size::Qword, register);
}

fn shift_immediate(code: &mut Code, op: ShiftOp, amount: u8) {
    code.asm().shift_imm(op, Size::Qword, Rax, amount);
}

fn bound(code: &mut Code, value: u64, rdx: bool) {
    code.asm().mov_imm64(if rdx { Rdx } else { Rax }, value);
}
fn normalize(code: &mut Code, bits: u8, signed: bool) {
    if bits < HOST_BITS {
        shift_immediate(code, ShiftOp::Shl, HOST_BITS - bits);
        shift_immediate(
            code,
            if signed { ShiftOp::Sar } else { ShiftOp::Shr },
            HOST_BITS - bits,
        );
    }
}

/// Preloaded XMM0=data and XMM1=complete signed counts; result XMM0.
/// Preserves other XMMs and RDI/R15, clobbers RAX/RCX/RDX/R10, restores RSP.
/// Group instructions own source snapshots, group ordering and destination commit.
pub(crate) fn rounding_variable_chunk(code: &mut Code, element_size: ElementSize, signed: bool) {
    super::adjust_stack(code, STACK_BYTES, true);
    chunk(
        code,
        if signed {
            Kind::RoundingSigned
        } else {
            Kind::RoundingUnsigned
        },
        element_size,
        Count::Elements(0),
    );
    super::adjust_stack(code, STACK_BYTES, false);
}

pub(super) fn chunk(code: &mut Code, kind: Kind, element_size: ElementSize, count: Count) {
    stack_vector(code, 0, SOURCE_SLOT, true);
    if !matches!(count, Count::Immediate(_)) {
        stack_vector(code, 1, COUNT_SLOT, true);
    }
    let bytes = element_size.bytes();
    let bits = element_size.bits() as u8;
    let signed = matches!(
        kind,
        Kind::ArithmeticRight
            | Kind::DivideSigned
            | Kind::SaturatingSigned
            | Kind::SaturatingSignedToUnsigned
            | Kind::RoundingSigned
            | Kind::SaturatingRoundingSigned
    );
    for offset in (0..CHUNK_BYTES).step_by(bytes) {
        match count {
            Count::Immediate(amount) => {
                load_lane(code, bytes, signed, SOURCE_SLOT + offset as u8);
                if kind == Kind::DivideSigned {
                    divide_signed(code, bits, amount);
                } else {
                    code.asm().mov_imm32(Rcx, u32::from(amount));
                    left(code, bits, signed, kind != Kind::SaturatingSigned, true);
                }
            }
            Count::Elements(_) | Count::Doublewords(_) => {
                let bidirectional = !matches!(
                    kind,
                    Kind::ArithmeticRight | Kind::LogicalRight | Kind::LogicalLeft
                );
                let wide = matches!(count, Count::Doublewords(_));
                let count_bytes = if wide {
                    usize::from(HOST_BITS / BITS_PER_BYTE)
                } else {
                    bytes
                };
                let count_offset = if wide {
                    offset / count_bytes * count_bytes
                } else {
                    offset
                };
                load_lane(
                    code,
                    count_bytes,
                    bidirectional,
                    COUNT_SLOT + count_offset as u8,
                );
                code.asm().mov(Size::Qword, Rcx, Rax);
                if bidirectional {
                    clamp_signed_count(code, bits);
                }
                load_lane(code, bytes, signed, SOURCE_SLOT + offset as u8);
                if bidirectional {
                    let mut asm = code.asm();
                    asm.test(Size::Qword, Rcx, Rcx);
                    let positive = asm.jcc(Cond::Ns);
                    asm.unary(Unary::Neg, Size::Qword, Rcx);
                    right(
                        code,
                        signed,
                        matches!(
                            kind,
                            Kind::RoundingSigned
                                | Kind::RoundingUnsigned
                                | Kind::SaturatingRoundingSigned
                                | Kind::SaturatingRoundingUnsigned
                        ),
                    );
                    let mut asm = code.asm();
                    let done = asm.jmp();
                    asm.bind(positive);
                    left(
                        code,
                        bits,
                        signed,
                        !signed,
                        matches!(
                            kind,
                            Kind::SaturatingSigned
                                | Kind::SaturatingUnsigned
                                | Kind::SaturatingRoundingSigned
                                | Kind::SaturatingRoundingUnsigned
                        ),
                    );
                    code.asm().bind(done);
                } else if kind == Kind::LogicalLeft {
                    // Full unsigned counts must not truncate to ECX/CL first.
                    clamp_unsigned_count(code, bits);
                    left(code, bits, false, true, false);
                } else {
                    clamp_unsigned_count(code, bits);
                    right(code, signed, false);
                }
            }
        }
        store_lane(code, bytes, RESULT_SLOT + offset as u8);
    }
    stack_vector(code, 0, RESULT_SLOT, false);
}

fn clamp_unsigned_count(code: &mut Code, bits: u8) {
    // Compare the full count before x86 CL masking; source RAX remains intact.
    bound(code, u64::from(bits), true);
    let mut asm = code.asm();
    asm.alu(Alu::Cmp, Size::Qword, Rcx, Rdx);
    asm.cmov(Cond::A, Size::Qword, Rcx, Rdx);
}
fn clamp_signed_count(code: &mut Code, bits: u8) {
    let ceiling = i64::from(bits) + 1;
    bound(code, ceiling as u64, true);
    let mut asm = code.asm();
    asm.alu(Alu::Cmp, Size::Qword, Rcx, Rdx);
    asm.cmov(Cond::G, Size::Qword, Rcx, Rdx);
    bound(code, (-ceiling) as u64, true);
    let mut asm = code.asm();
    asm.alu(Alu::Cmp, Size::Qword, Rcx, Rdx);
    asm.cmov(Cond::L, Size::Qword, Rcx, Rdx);
}

fn divide_signed(code: &mut Code, bits: u8, amount: u8) {
    if amount == bits {
        code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
        return;
    }
    bound(code, (1_u64 << amount) - 1, true);
    let mut asm = code.asm();
    asm.alu(Alu::Xor, Size::Dword, Rcx, Rcx);
    asm.test(Size::Qword, Rax, Rax);
    asm.cmov(Cond::Ns, Size::Qword, Rdx, Rcx);
    asm.alu(Alu::Add, Size::Qword, Rax, Rdx);
    shift_immediate(code, ShiftOp::Sar, amount);
}

fn right(code: &mut Code, signed: bool, round: bool) {
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Cmp, Size::Dword, Rcx, HOST_BITS as i8);
    let large = asm.jcc(Cond::Ae);
    shift_count(code, if signed { ShiftOp::Sar } else { ShiftOp::Shr }, Rax);
    let mut asm = code.asm();
    if round {
        asm.alu_imm8(Alu::Adc, Size::Qword, Rax, 0);
    }
    let done = asm.jmp();
    asm.bind(large);
    if signed && !round {
        shift_immediate(code, ShiftOp::Sar, HOST_BITS - 1);
    } else if !signed && round {
        let beyond = asm.jcc(Cond::A);
        shift_immediate(code, ShiftOp::Shr, HOST_BITS - 1);
        let mut asm = code.asm();
        let end = asm.jmp();
        asm.bind(beyond);
        asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
        asm.bind(end);
    } else {
        asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
    }
    code.asm().bind(done);
}

fn left(code: &mut Code, bits: u8, signed: bool, unsigned_result: bool, saturating: bool) {
    let mut done = Vec::new();
    let mut negative = None;
    if saturating {
        code.asm().mov(Size::Qword, Rdx, Rax);
    }
    if signed && unsigned_result {
        let mut asm = code.asm();
        asm.test(Size::Qword, Rax, Rax);
        let nonnegative = asm.jcc(Cond::Ns);
        negative = Some(asm.jmp());
        asm.bind(nonnegative);
    }
    let mut asm = code.asm();
    asm.alu_imm8(Alu::Cmp, Size::Dword, Rcx, bits as i8);
    let large = asm.jcc(Cond::Ae);
    shift_count(code, ShiftOp::Shl, Rax);
    if saturating {
        normalize(code, bits, !unsigned_result);
        code.asm().mov(Size::Qword, R10, Rax);
        shift_count(
            code,
            if unsigned_result {
                ShiftOp::Shr
            } else {
                ShiftOp::Sar
            },
            R10,
        );
        let mut asm = code.asm();
        asm.alu(Alu::Cmp, Size::Qword, R10, Rdx);
        done.push(asm.jcc(Cond::E));
        let overflow = asm.jmp();
        asm.bind(large);
        asm.test(Size::Qword, Rax, Rax);
        done.push(asm.jcc(Cond::E));
        asm.bind(overflow);
        if let Some(patch) = negative {
            asm.bind(patch);
        }
        let maximum = if unsigned_result {
            u64::MAX >> (HOST_BITS - bits)
        } else {
            (1_u64 << (bits - 1)) - 1
        };
        bound(code, maximum, false);
        if signed {
            let mut asm = code.asm();
            asm.test(Size::Qword, Rdx, Rdx);
            let nonnegative = asm.jcc(Cond::Ns);
            bound(
                code,
                if unsigned_result {
                    0
                } else {
                    0_u64.wrapping_sub(1_u64 << (bits - 1))
                },
                false,
            );
            code.asm().bind(nonnegative);
        }
    } else {
        let mut asm = code.asm();
        done.push(asm.jmp());
        asm.bind(large);
        asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
    }
    let mut asm = code.asm();
    for patch in done {
        asm.bind(patch);
    }
}
