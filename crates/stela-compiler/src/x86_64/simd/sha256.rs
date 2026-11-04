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
    aarch64::{
        Instruction, Operation,
        simd::{
            IntegerOperation, Operand as Simd,
            sha256::{Kind, Operand},
        },
    },
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
const SAVED_RSI: u8 = 7;
const REVERSE_DWORDS: u8 = 0x1b;
const REVERSE_DWORD_PAIRS: u8 = 0xb1;
const BIG_SIGMA0: [u8; 3] = [2, 13, 22];
const BIG_SIGMA1: [u8; 3] = [6, 11, 25];
const SMALL_SIGMA0: [u8; 3] = [7, 18, 3];
const SMALL_SIGMA1: [u8; 3] = [17, 19, 10];

fn preserve_scratch(code: &mut Code, restore: bool) {
    // Full host RBX/RBP/R12/RSI values stay in SysV caller-saved XMM4..7.
    // No host stack or guest RAM is touched; these XMMs survive the scalar body.
    for (xmm, register) in [
        (SAVED_RBX, EBX),
        (SAVED_RBP, EBP),
        (SAVED_R12, R12D),
        (SAVED_RSI, ESI),
    ] {
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
fn rounds_baseline(code: &mut Code, x: u8, y: u8, schedule: u8) -> [u8; 8] {
    use Scalar32::*;
    preserve_scratch(code, false);
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
        Add.state(code, EBX, schedule, lane);
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
    state
}
/// Four rounds, with the caller's original ABCD already in LEFT.
fn rounds_sha(code: &mut Code, y: u8, schedule: u8, target: TargetCpu) {
    read_vector(code, y, RIGHT);
    read_vector(code, schedule, RESULT); // RNDS2's implicit WK input
    shuffle(code, LEFT, LEFT, REVERSE_DWORDS); // [D,C,B,A]
    shuffle(code, RIGHT, RIGHT, REVERSE_DWORDS); // [H,G,F,E]
    packed(code, Host::MoveAligned, TEMPORARY, RIGHT);
    packed(code, Host::UnpackHighQword, TEMPORARY, LEFT); // [F,E,B,A]
    packed(code, Host::UnpackLowQword, RIGHT, LEFT); // [H,G,D,C]
    Host::Sha256Rounds2.register(code, RIGHT, TEMPORARY, target);
    Shift::RightBytes.emit(code, RESULT, DOUBLE_WORD_BYTES);
    Host::Sha256Rounds2.register(code, TEMPORARY, RIGHT, target);
}

fn unpack_sha(code: &mut Code, state: u8, high: bool) {
    packed(
        code,
        if high {
            Host::UnpackHighQword
        } else {
            Host::UnpackLowQword
        },
        state,
        RIGHT,
    );
    shuffle(code, RESULT, state, REVERSE_DWORD_PAIRS);
}

/// The copy that keeps the original ABCD and the two projections of one
/// four-round hash update.
pub(in crate::x86_64) struct HashPair {
    copy: u8,
    abcd: u8,
    efgh: u8,
    schedule: u8,
}

impl HashPair {
    pub(in crate::x86_64) fn recognize(instructions: &[Instruction]) -> Option<Self> {
        let [copy, first, second, ..] = instructions else {
            return None;
        };
        let Operation::Simd(Simd::Integer {
            operation: IntegerOperation::Orr,
            destination: temporary,
            left,
            right,
            bytes: 16,
            ..
        }) = copy.operation
        else {
            return None;
        };
        let Operation::Simd(Simd::Sha256(Operand {
            kind: Kind::Hash,
            destination: abcd,
            left: efgh,
            right: schedule,
        })) = first.operation
        else {
            return None;
        };
        let second_half = Operation::Simd(Simd::Sha256(Operand {
            kind: Kind::Hash2,
            destination: efgh,
            left: temporary,
            right: schedule,
        }));
        if left != abcd || right != abcd
            || temporary == abcd || temporary == efgh || abcd == efgh
            // SHA256H2 must read the same WK as SHA256H, including when
            // WK aliases the unchanged EFGH or the original ABCD copy.
            || schedule == abcd
            || second.operation != second_half
            || copy.pc.0.checked_add(4) != Some(first.pc.0)
            || first.pc.0.checked_add(4) != Some(second.pc.0)
        {
            return None;
        }
        Some(Self {
            copy: temporary,
            abcd,
            efgh,
            schedule,
        })
    }

    /// Emit each architectural write in its own source row. All memory
    /// operands are in the native guest frame, so there is no guest fault
    /// or internal exit while the two halves are held in host registers.
    pub(in crate::x86_64) fn emit(self, code: &mut Code, target: TargetCpu) -> ([usize; 3], u8) {
        let copy = code.len();
        read_vector(code, self.abcd, LEFT);
        commit(code, self.copy, LEFT);
        let first = code.len();
        if target.supports(TargetCpu::Sha) {
            rounds_sha(code, self.efgh, self.schedule, target);
            packed(code, Host::MoveAligned, LEFT, TEMPORARY);
            unpack_sha(code, LEFT, true);
            commit(code, self.abcd, RESULT);
            unpack_sha(code, TEMPORARY, false);
        } else {
            let [a, b, c, d, e, f, g, h] =
                rounds_baseline(code, self.abcd, self.efgh, self.schedule);
            pack_state(code, [a, b, c, d]);
            commit(code, self.abcd, RESULT);
            pack_state(code, [e, f, g, h]);
            preserve_scratch(code, true);
        }
        let second = code.len();
        commit(code, self.efgh, RESULT);
        ([copy, first, second], self.efgh)
    }
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
            let high = operand.kind == Kind::Hash;
            let (x, y) = if high {
                (operand.destination, operand.left)
            } else {
                (operand.left, operand.destination)
            };
            if target.supports(TargetCpu::Sha) {
                read_vector(code, x, LEFT);
                rounds_sha(code, y, operand.right, target);
                unpack_sha(code, TEMPORARY, high);
            } else {
                let [a, b, c, d, e, f, g, h] = rounds_baseline(code, x, y, operand.right);
                pack_state(code, if high { [a, b, c, d] } else { [e, f, g, h] });
                preserve_scratch(code, true);
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
    use crate::{GuestAddress, Lifter, aarch64::Decoder};

    #[test]
    fn hash_pair_requires_the_unchanged_schedule_and_original_abcd_copy() {
        let instructions = |words: [u32; 3]| {
            core::array::from_fn::<_, 3, _>(|index| {
                Decoder
                    .lift(GuestAddress(0x1000 + index as u64 * 4), words[index])
                    .unwrap()
            })
        };
        let copy = 0x4ea0_1c02; // MOV V2.16B, V0.16B.
        let first = 0x5e00_4020; // SHA256H V0, V1, V0, before setting WK.
        let second = 0x5e00_5041; // SHA256H2 V1, V2, V0, before setting WK.
        for schedule in [1, 2, 16, 31] {
            let pair = instructions([copy, first | schedule << 16, second | schedule << 16]);
            assert!(HashPair::recognize(&pair).is_some());
            assert!(HashPair::recognize(&pair[..2]).is_none());
            assert!(HashPair::recognize(&pair[1..]).is_none());
        }
        for words in [
            [copy, first, second],                       // H changes the H2 schedule.
            [copy, first | 16 << 16, second | 17 << 16], // Different schedule.
            [copy ^ (1 << 30), first | 16 << 16, second | 16 << 16], // 64-bit copy.
            [copy ^ (1 << 16), first | 16 << 16, second | 16 << 16], // Not a copy.
            [copy ^ 2, first | 16 << 16, (second ^ (2 << 5)) | 16 << 16], // Temp=ABCD.
            [copy ^ 3, first | 16 << 16, (second ^ (3 << 5)) | 16 << 16], // Temp=EFGH.
        ] {
            assert!(HashPair::recognize(&instructions(words)).is_none());
        }
    }

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
