//! SHA256: scalar rounds, SSE2 schedule, or Intel SHA when available. SHA256H and
//! SHA256H2 each run all four rounds and keep their own half.
use super::sha32::{
    DOUBLE_WORD_BYTES, HIGH_WORD_BYTE, RESULT, Rotate32, Scalar32, WORD_BITS, WORD_BYTES,
    WORDS_PER_VECTOR, pack_state,
};
use super::{Host, commit, packed, read_vector, shuffle};
use crate::x86_64::asm::Code;
use crate::x86_64::simd::encode::gpr;
use crate::{
    TargetCpu,
    aarch64::simd::sha256::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

const EAX: u8 = 0;
const ECX: u8 = 1;
const EDX: u8 = 2;
const EBX: u8 = 3;
const EBP: u8 = 5;
const ESI: u8 = 6;
const R8D: u8 = 8;
const R9D: u8 = 9;
const R10D: u8 = 10;
const R11D: u8 = 11;
const R12D: u8 = 12;
const LEFT: u8 = 1;
const RIGHT: u8 = 2;
const TEMPORARY: u8 = 3;
const SIGMA_TEMPORARY: u8 = 4;
const SAVED_RBX: u8 = 4;
const SAVED_RBP: u8 = 5;
const SAVED_R12: u8 = 6;
const REVERSE_DWORDS: u8 = 0x1b;
const REVERSE_DWORD_PAIRS: u8 = 0xb1;
const BIG_SIGMA0: [u8; 3] = [2, 13, 22];
const BIG_SIGMA1: [u8; 3] = [6, 11, 25];
const SMALL_SIGMA0: [u8; 3] = [7, 18, 3];
const SMALL_SIGMA1: [u8; 3] = [17, 19, 10];

fn preserve_scratch(code: &mut Code, restore: bool) {
    // Full host RBX/RBP/R12 values stay in SysV caller-saved XMM4..6.
    // No host stack or guest RAM is touched; these XMMs survive the scalar body.
    for (xmm, register) in [(SAVED_RBX, EBX), (SAVED_RBP, EBP), (SAVED_R12, R12D)] {
        let mut asm = code.asm();
        if restore {
            asm.movq_from_xmm(gpr(register), xmm);
        } else {
            asm.movq_to_xmm(xmm, gpr(register));
        }
    }
}
fn big_sigma(code: &mut Code, input: u8, result: u8, temporary: u8, amounts: [u8; 3]) {
    Scalar32::Move.register(code, result, input);
    Rotate32::Right.emit(code, result, amounts[0]);
    for amount in &amounts[1..] {
        Scalar32::Move.register(code, temporary, input);
        Rotate32::Right.emit(code, temporary, *amount);
        Scalar32::Xor.register(code, result, temporary);
    }
}
fn rounds_baseline(code: &mut Code, operand: &Operand) {
    use Scalar32::*;
    preserve_scratch(code, false);
    let (x, y) = if operand.kind == Kind::Hash {
        (operand.destination, operand.left)
    } else {
        (operand.left, operand.destination)
    };
    let mut state = [EAX, ECX, EDX, ESI, R8D, R9D, R10D, R11D];
    for (index, register) in state.iter().enumerate() {
        Move.state(
            code,
            *register,
            if index < WORDS_PER_VECTOR { x } else { y },
            (index % WORDS_PER_VECTOR) as u8,
        );
    }
    for lane in 0..WORDS_PER_VECTOR as u8 {
        let [a, b, c, d, e, f, g, h] = state;
        big_sigma(code, e, EBX, EBP, BIG_SIGMA1);
        Move.register(code, EBP, f);
        Xor.register(code, EBP, g);
        And.register(code, EBP, e);
        Xor.register(code, EBP, g);
        Add.register(code, EBX, EBP);
        Add.register(code, EBX, h);
        Add.state(code, EBX, operand.right, lane);
        Add.register(code, d, EBX); // new E; the original D is now consumed
        big_sigma(code, a, EBP, R12D, BIG_SIGMA0);
        Add.register(code, EBX, EBP);
        Move.register(code, R12D, a);
        And.register(code, R12D, b);
        Move.register(code, EBP, a);
        Or.register(code, EBP, b);
        And.register(code, EBP, c);
        Or.register(code, EBP, R12D);
        Add.register(code, EBX, EBP);
        Move.register(code, h, EBX); // new A; the original H is now consumed
        state = [h, a, b, c, d, e, f, g];
    }
    let part = if operand.kind == Kind::Hash {
        &state[..WORDS_PER_VECTOR]
    } else {
        &state[WORDS_PER_VECTOR..]
    };
    pack_state(code, [part[0], part[1], part[2], part[3]]);
    preserve_scratch(code, true);
}
fn rounds_sha(code: &mut Code, operand: &Operand, target: TargetCpu) {
    let (x, y) = if operand.kind == Kind::Hash {
        (operand.destination, operand.left)
    } else {
        (operand.left, operand.destination)
    };
    read_vector(code, x, LEFT);
    read_vector(code, y, RIGHT);
    read_vector(code, operand.right, RESULT); // RNDS2's implicit WK input
    shuffle(code, LEFT, LEFT, REVERSE_DWORDS); // [D,C,B,A]
    shuffle(code, RIGHT, RIGHT, REVERSE_DWORDS); // [H,G,F,E]
    packed(code, Host::MoveAligned, TEMPORARY, RIGHT);
    packed(code, Host::UnpackHighQword, TEMPORARY, LEFT); // [F,E,B,A]
    packed(code, Host::UnpackLowQword, RIGHT, LEFT); // [H,G,D,C]
    Host::Sha256Rounds2.register(code, RIGHT, TEMPORARY, target);
    Shift::RightBytes.emit(code, RESULT, DOUBLE_WORD_BYTES);
    Host::Sha256Rounds2.register(code, TEMPORARY, RIGHT, target);
    packed(
        code,
        if operand.kind == Kind::Hash {
            Host::UnpackHighQword
        } else {
            Host::UnpackLowQword
        },
        TEMPORARY,
        RIGHT,
    );
    shuffle(code, RESULT, TEMPORARY, REVERSE_DWORD_PAIRS);
}

fn small_sigma(code: &mut Code, input: u8, result: u8, temporary: u8, amounts: [u8; 3]) {
    // Two rotates and a logical shift are a linear XOR of five shifted copies.
    // Destructively consume input for the final shift, avoiding a sixth copy.
    packed(code, Host::MoveAligned, result, input);
    Shift::RightDword.emit(code, result, amounts[0]);
    packed(code, Host::MoveAligned, temporary, input);
    Shift::LeftDword.emit(code, temporary, WORD_BITS - amounts[0]);
    packed(code, Host::Xor, result, temporary);
    for (shift, amount) in [
        (Shift::RightDword, amounts[1]),
        (Shift::LeftDword, WORD_BITS - amounts[1]),
    ] {
        packed(code, Host::MoveAligned, temporary, input);
        shift.emit(code, temporary, amount);
        packed(code, Host::Xor, result, temporary);
    }
    Shift::RightDword.emit(code, input, amounts[2]);
    packed(code, Host::Xor, result, input);
}
fn schedule0(code: &mut Code, operand: &Operand, target: TargetCpu) {
    read_vector(code, operand.destination, RESULT);
    read_vector(code, operand.left, LEFT);
    if target.supports(TargetCpu::Sha) {
        Host::Sha256Message1.register(code, RESULT, LEFT, target);
    } else {
        if target.supports(TargetCpu::Ssse3) {
            packed(code, Host::MoveAligned, RIGHT, LEFT);
            Host::AlignBytes.register_imm(code, RIGHT, RESULT, WORD_BYTES, target); // [d1,d2,d3,n0]
        } else {
            packed(code, Host::MoveAligned, RIGHT, RESULT);
            Shift::RightBytes.emit(code, RIGHT, WORD_BYTES);
            Shift::LeftBytes.emit(code, LEFT, HIGH_WORD_BYTE);
            packed(code, Host::Or, RIGHT, LEFT);
        }
        small_sigma(code, RIGHT, TEMPORARY, SIGMA_TEMPORARY, SMALL_SIGMA0);
        packed(code, Host::AddDword, RESULT, TEMPORARY);
    }
}
fn schedule1(code: &mut Code, operand: &Operand, target: TargetCpu) {
    read_vector(code, operand.destination, RESULT);
    read_vector(code, operand.left, LEFT);
    read_vector(code, operand.right, RIGHT);
    if target.supports(TargetCpu::Ssse3) {
        // Keep the M vector for schedule feedback and SHA256MSG2.
        packed(code, Host::MoveAligned, TEMPORARY, RIGHT);
        Host::AlignBytes.register_imm(code, TEMPORARY, LEFT, WORD_BYTES, target); // [n1,n2,n3,m0]
        packed(code, Host::AddDword, RESULT, TEMPORARY);
    } else {
        Shift::RightBytes.emit(code, LEFT, WORD_BYTES);
        packed(code, Host::MoveAligned, TEMPORARY, RIGHT);
        Shift::LeftBytes.emit(code, TEMPORARY, HIGH_WORD_BYTE);
        packed(code, Host::Or, LEFT, TEMPORARY);
        packed(code, Host::AddDword, RESULT, LEFT);
    }
    if target.supports(TargetCpu::Sha) {
        Host::Sha256Message2.register(code, RESULT, RIGHT, target);
    } else {
        Shift::RightBytes.emit(code, RIGHT, DOUBLE_WORD_BYTES);
        small_sigma(code, RIGHT, TEMPORARY, SIGMA_TEMPORARY, SMALL_SIGMA1); // [sigma1(m2),sigma1(m3),0,0]
        packed(code, Host::AddDword, RESULT, TEMPORARY);
        packed(code, Host::MoveAligned, RIGHT, RESULT);
        Shift::LeftBytes.emit(code, RIGHT, DOUBLE_WORD_BYTES); // [0,0,result0,result1]
        small_sigma(code, RIGHT, TEMPORARY, SIGMA_TEMPORARY, SMALL_SIGMA1);
        packed(code, Host::AddDword, RESULT, TEMPORARY);
    }
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    match operand.kind {
        Kind::Hash | Kind::Hash2 => {
            if target.supports(TargetCpu::Sha) {
                rounds_sha(code, operand, target);
            } else {
                rounds_baseline(code, operand);
            }
        }
        Kind::Schedule0 => schedule0(code, operand, target),
        Kind::Schedule1 => schedule1(code, operand, target),
    }
    commit(code, operand.destination, RESULT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_gathers_require_ssse3_independently_of_sha() {
        for target in [
            TargetCpu::Baseline,
            TargetCpu::Ssse3,
            TargetCpu::Sha,
            TargetCpu::Ssse3.with_sha(),
        ] {
            for kind in [Kind::Schedule0, Kind::Schedule1] {
                let operand = Operand {
                    kind,
                    destination: 31,
                    left: 31,
                    right: 31,
                };
                let mut code = Code::new();
                emit(&mut code, &operand, target);
                let alignment = Host::AlignBytes.encoding();
                let used = code
                    .windows(alignment.len())
                    .any(|bytes| bytes == alignment);
                let expected = target.supports(TargetCpu::Ssse3)
                    && (kind == Kind::Schedule1 || !target.supports(TargetCpu::Sha));
                assert_eq!(used, expected);
            }
        }
    }

    #[test]
    fn checked_hash_uses_two_round_pairs_with_explicit_implicit_input_staging() {
        for kind in [Kind::Hash, Kind::Hash2] {
            let operand = Operand {
                kind,
                destination: 31,
                left: 31,
                right: 31,
            };
            let mut code = Code::new();
            emit(&mut code, &operand, TargetCpu::Sha);
            assert_eq!(
                code.windows(3).filter(|w| *w == [0x0f, 0x38, 0xcb]).count(),
                2
            );
            let mut baseline = Code::new();
            emit(&mut baseline, &operand, TargetCpu::Baseline);
            assert!(!baseline.windows(3).any(|w| w == [0x0f, 0x38, 0xcb]));
            // Full-width saves/restores cover every callee-saved GPR used.
            // movq xmm4/5/6, rbx/rbp/r12 and back.
            for expected in [
                [0x66, 0x48, 0x0f, 0x6e, 0xe3],
                [0x66, 0x48, 0x0f, 0x6e, 0xed],
                [0x66, 0x49, 0x0f, 0x6e, 0xf4],
                [0x66, 0x48, 0x0f, 0x7e, 0xe3],
                [0x66, 0x48, 0x0f, 0x7e, 0xed],
                [0x66, 0x49, 0x0f, 0x7e, 0xf4],
            ] {
                assert!(baseline.windows(expected.len()).any(|w| w == expected));
            }
        }
    }
}
