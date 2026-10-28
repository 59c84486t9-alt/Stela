//! FCSEL, FABS and FNEG by integer operations, without MXCSR effects.
use super::super::isa::ShiftOpcode;
use super::{Host, commit, packed, read_vector, vector_offset};
use crate::aarch64::floating::{FPCR_AH, FPCR_NEP};
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::{Alu, Code, Cond, Gpr, Size};
use crate::x86_64::simd::encode::guest;
use crate::{
    TargetCpu,
    aarch64::simd::floating::{Operand, SignOperation},
};

fn test_control(code: &mut Code, mask: u32) {
    code.asm().test_imm(
        Size::Dword,
        guest(core::mem::offset_of!(crate::GuestState, fpcr) as u32),
        mask as i32,
    );
}

fn jump(code: &mut Code, condition: Option<Cond>) -> usize {
    let mut asm = code.asm();
    match condition {
        Some(condition) => asm.jcc(condition),
        None => asm.jmp(),
    }
    .offset()
}

/// The operand size of a `bytes`-byte scalar lane.
fn size(bytes: u8) -> Size {
    match bytes {
        2 => Size::Word,
        4 => Size::Dword,
        8 => Size::Qword,
        _ => unreachable!("reviewed FP scalar size"),
    }
}

fn resolve(code: &mut [u8], patch: usize) {
    let delta = i32::try_from(code.len() - patch - 4).expect("bounded FP bit lowering");
    code[patch..patch + 4].copy_from_slice(&delta.to_le_bytes());
}

fn load_lane(code: &mut Code, vector: u8, bytes: u8, rcx: bool) {
    let register = if rcx { Gpr::Rcx } else { Gpr::Rax };
    let lane = guest(vector_offset(vector));
    if bytes == 2 {
        code.asm().movzx(Size::Dword, register, Size::Word, lane);
    } else {
        code.asm().mov_load(size(bytes), register, lane);
    }
}

fn zero_extended_commit(code: &mut Code, destination: u8) {
    packed(code, Host::MoveGprQword, 0, 0); // RAX was loaded at the exact scalar width.
    commit(code, destination, 0);
}

fn scalar_sign(code: &mut Code, operation: SignOperation, destination: u8, source: u8, bytes: u8) {
    load_lane(code, source, bytes, false);
    test_control(code, FPCR_AH);
    let ordinary = jump(code, Some(Cond::E)); // AH=0 skips all NaN classification.
    // Compare unsigned magnitude to positive infinity. Strictly greater means
    // NaN, including signaling payloads; no numerical host FP instruction runs.
    let mut asm = code.asm();
    asm.mov(Size::Qword, Gpr::Rcx, Gpr::Rax);
    if bytes == 8 {
        asm.bit_imm(BitTest::Btr, Size::Qword, Gpr::Rcx, 63);
        asm.mov_imm64(Gpr::Rdx, 0x7ff0_0000_0000_0000);
        asm.alu(Alu::Cmp, Size::Qword, Gpr::Rcx, Gpr::Rdx);
    } else {
        let magnitude: u32 = if bytes == 2 { 0x7fff } else { 0x7fff_ffff };
        let infinity: u32 = if bytes == 2 { 0x7c00 } else { 0x7f80_0000 };
        asm.alu_imm32(Alu::And, Size::Dword, Gpr::Rcx, magnitude as i32);
        asm.alu_imm32(Alu::Cmp, Size::Dword, Gpr::Rcx, infinity as i32);
    }
    let nan = jump(code, Some(Cond::A)); // AH=1 leaves every original NaN bit unchanged.
    resolve(code, ordinary);
    code.asm().bit_imm(
        if operation == SignOperation::Abs {
            BitTest::Btr
        } else {
            BitTest::Btc
        },
        if bytes == 8 { Size::Qword } else { Size::Dword },
        Gpr::Rax,
        bytes * 8 - 1,
    );
    resolve(code, nan);
    test_control(code, FPCR_NEP);
    let merging = jump(code, Some(Cond::Ne));
    zero_extended_commit(code, destination);
    let completed = jump(code, None);
    resolve(code, merging);
    // NEP merges with old Vd, not Vn. Exact-width store avoids a destination load.
    code.asm()
        .mov_store(size(bytes), guest(vector_offset(destination)), Gpr::Rax);
    resolve(code, completed);
}

fn splat(code: &mut Code, xmm: u8, lane: u64, lane_bytes: u8) {
    let mut low = 0;
    for index in 0..8 / lane_bytes {
        low |= lane << (index * lane_bytes * 8);
    }
    code.asm().mov_imm64(Gpr::Rcx, low);
    packed(code, Host::MoveGprQword, xmm, 1);
    packed(code, Host::UnpackLowQword, xmm, xmm);
}

fn vector_sign(
    code: &mut Code,
    operation: SignOperation,
    destination: u8,
    source: u8,
    lane_bytes: u8,
    bytes: u8,
    target: TargetCpu,
) {
    read_vector(code, source, 0);
    // Two SSE2 instructions, nine bytes: avoid MOVABS/MOVQ/PUNPCKLQDQ's
    // three instructions, nineteen bytes and integer-to-vector transfer.
    packed(code, Host::EqualDword, 1, 1);
    match lane_bytes {
        2 => ShiftOpcode::LeftWord,
        4 => ShiftOpcode::LeftDword,
        8 => ShiftOpcode::LeftQword,
        _ => unreachable!(),
    }
    .emit(code, 1, lane_bytes * 8 - 1);
    test_control(code, FPCR_AH);
    let ordinary = jump(code, Some(Cond::E));
    packed(code, Host::MoveAligned, 2, 1);
    packed(code, Host::AndNot, 2, 0); // XMM2 = unsigned magnitude.
    let infinity = match lane_bytes {
        2 => 0x7c00,
        4 => 0x7f80_0000,
        8 => 0x7ff0_0000_0000_0000,
        _ => unreachable!(),
    };
    splat(code, 3, infinity, lane_bytes);
    match lane_bytes {
        2 => packed(code, Host::GreaterWord, 2, 3),
        4 => packed(code, Host::GreaterDword, 2, 3),
        8 if target.supports(TargetCpu::Sse42) => Host::GreaterQword.register(code, 2, 3, target),
        8 => {
            // magnitude > infinity iff high>0x7ff00000, or equal high and low!=0.
            packed(code, Host::MoveAligned, 4, 2);
            packed(code, Host::GreaterDword, 4, 3);
            super::shuffle(code, 4, 4, 0xf5);
            packed(code, Host::EqualDword, 3, 2);
            super::shuffle(code, 3, 3, 0xf5);
            packed(code, Host::Xor, 5, 5);
            packed(code, Host::EqualDword, 2, 5);
            super::shuffle(code, 2, 2, 0xa0);
            packed(code, Host::AndNot, 2, 3);
            packed(code, Host::Or, 2, 4);
        }
        _ => unreachable!(),
    }
    packed(code, Host::AndNot, 2, 1); // Sign mask only for non-NaN lanes.
    packed(code, Host::MoveAligned, 1, 2);
    resolve(code, ordinary);
    let result = if operation == SignOperation::Abs {
        packed(code, Host::AndNot, 1, 0);
        1
    } else {
        packed(code, Host::Xor, 0, 1);
        0
    };
    if bytes == 8 {
        packed(code, Host::MoveQword, result, result);
    }
    commit(code, destination, result);
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    match *operand {
        Operand::Select {
            destination,
            left,
            right,
            lane_bytes,
            condition,
        } => {
            let predicate = super::super::condition_holds(code, condition, false);
            load_lane(code, left, lane_bytes, false);
            if let Some(holds) = predicate {
                load_lane(code, right, lane_bytes, true); // MOV loads preserve predicate flags.
                // CMOV on the false condition: RAX/EAX takes RCX/ECX.
                code.asm().cmov(
                    holds.negate(),
                    if lane_bytes == 8 {
                        Size::Qword
                    } else {
                        Size::Dword
                    },
                    Gpr::Rax,
                    Gpr::Rcx,
                );
            }
            zero_extended_commit(code, destination);
        }
        Operand::Sign {
            operation,
            destination,
            source,
            lane_bytes,
            scalar: true,
            ..
        } => {
            scalar_sign(code, operation, destination, source, lane_bytes);
        }
        Operand::Sign {
            operation,
            destination,
            source,
            lane_bytes,
            bytes,
            scalar: false,
        } => {
            vector_sign(
                code,
                operation,
                destination,
                source,
                lane_bytes,
                bytes,
                target,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_qword_classifier_and_no_numeric_host_fp() {
        let operation = Operand::Sign {
            operation: SignOperation::Neg,
            destination: 31,
            source: 31,
            lane_bytes: 8,
            bytes: 16,
            scalar: false,
        };
        let mut baseline = Code::new();
        emit(&mut baseline, &operation, TargetCpu::Baseline);
        let mut optimized = Code::new();
        emit(&mut optimized, &operation, TargetCpu::Sse42);
        assert!(
            !baseline
                .windows(4)
                .any(|bytes| bytes == Host::GreaterQword.encoding())
        );
        assert!(
            optimized
                .windows(4)
                .any(|bytes| bytes == Host::GreaterQword.encoding())
        );
        assert!(optimized.len() < baseline.len());
        for code in [baseline, optimized] {
            assert!(!code.windows(2).any(|bytes| bytes == [0x0f, 0xae])); // No MXCSR load/store.
        }
    }
}
