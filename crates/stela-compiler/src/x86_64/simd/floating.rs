//! FCSEL, FABS and FNEG by integer operations, without MXCSR effects.
use super::super::isa::ShiftOpcode;
use super::{Host, commit, packed, read_vector, vector_offset};
use crate::aarch64::floating::{FPCR_AH, FPCR_NEP};
use crate::x86_64::asm::Code;
use crate::{
    TargetCpu,
    aarch64::simd::floating::{Operand, SignOperation},
};

fn test_control(code: &mut Code, mask: u32) {
    code.extend([0xf7, 0x87]); // test dword [rdi+fpcr],mask
    code.extend((core::mem::offset_of!(crate::GuestState, fpcr) as u32).to_le_bytes());
    code.extend(mask.to_le_bytes());
}

fn jump(code: &mut Code, condition: Option<u8>) -> usize {
    if let Some(condition) = condition {
        code.extend([0x0f, condition]);
    } else {
        code.push(0xe9);
    }
    let patch = code.len();
    code.extend([0; 4]);
    patch
}

fn resolve(code: &mut [u8], patch: usize) {
    let delta = i32::try_from(code.len() - patch - 4).expect("bounded FP bit lowering");
    code[patch..patch + 4].copy_from_slice(&delta.to_le_bytes());
}

fn load_lane(code: &mut Code, vector: u8, bytes: u8, rcx: bool) {
    match bytes {
        2 => code.extend([0x0f, 0xb7]),
        4 => code.push(0x8b),
        8 => code.extend([0x48, 0x8b]),
        _ => unreachable!("reviewed FP scalar size"),
    }
    code.push(if rcx { 0x8f } else { 0x87 });
    code.extend(vector_offset(vector).to_le_bytes());
}

fn zero_extended_commit(code: &mut Code, destination: u8) {
    packed(code, Host::MoveGprQword, 0, 0); // RAX was loaded at the exact scalar width.
    commit(code, destination, 0);
}

fn scalar_sign(code: &mut Code, operation: SignOperation, destination: u8, source: u8, bytes: u8) {
    load_lane(code, source, bytes, false);
    test_control(code, FPCR_AH);
    let ordinary = jump(code, Some(0x84)); // AH=0 skips all NaN classification.
    // Compare unsigned magnitude to positive infinity. Strictly greater means
    // NaN, including signaling payloads; no numerical host FP instruction runs.
    code.extend([0x48, 0x89, 0xc1]); // mov rcx,rax
    if bytes == 8 {
        code.extend([0x48, 0x0f, 0xba, 0xf1, 63]); // btr rcx,63
        code.extend([0x48, 0xba]); // movabs rdx,+infinity
        code.extend(0x7ff0_0000_0000_0000u64.to_le_bytes());
        code.extend([0x48, 0x39, 0xd1]); // cmp rcx,rdx
    } else {
        code.extend([0x81, 0xe1]); // and ecx,magnitude_mask
        code.extend((if bytes == 2 { 0x7fffu32 } else { 0x7fff_ffff }).to_le_bytes());
        code.extend([0x81, 0xf9]); // cmp ecx,+infinity
        code.extend((if bytes == 2 { 0x7c00u32 } else { 0x7f80_0000 }).to_le_bytes());
    }
    let nan = jump(code, Some(0x87)); // AH=1 leaves every original NaN bit unchanged.
    resolve(code, ordinary);
    if bytes == 8 {
        code.push(0x48);
    }
    code.extend([
        0x0f,
        0xba,
        if operation == SignOperation::Abs {
            0xf0
        } else {
            0xf8
        },
        bytes * 8 - 1,
    ]); // BTR/BTC RAX/EAX,sign
    resolve(code, nan);
    test_control(code, FPCR_NEP);
    let merging = jump(code, Some(0x85));
    zero_extended_commit(code, destination);
    let completed = jump(code, None);
    resolve(code, merging);
    // NEP merges with old Vd, not Vn. Exact-width store avoids a destination load.
    match bytes {
        2 => code.extend([0x66, 0x89, 0x87]),
        4 => code.extend([0x89, 0x87]),
        8 => code.extend([0x48, 0x89, 0x87]),
        _ => unreachable!(),
    }
    code.extend(vector_offset(destination).to_le_bytes());
    resolve(code, completed);
}

fn splat(code: &mut Code, xmm: u8, lane: u64, lane_bytes: u8) {
    let mut low = 0;
    for index in 0..8 / lane_bytes {
        low |= lane << (index * lane_bytes * 8);
    }
    code.extend([0x48, 0xb9]);
    code.extend(low.to_le_bytes());
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
    let ordinary = jump(code, Some(0x84));
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
            let predicate = super::super::condition(code, condition);
            load_lane(code, left, lane_bytes, false);
            if let Some(jcc) = predicate {
                load_lane(code, right, lane_bytes, true); // MOV loads preserve predicate flags.
                if lane_bytes == 8 {
                    code.push(0x48);
                }
                code.extend([0x0f, (jcc ^ 1) - 0x40, 0xc1]); // CMOV false RAX/EAX,RCX/ECX
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
