//! SHA1 instructions: scalar integer rounds, SSE2 schedule and checked Intel SHA.
//! All inputs are consumed before the single vector commit, including aliases.
use super::sha32::{
    HIGH_WORD_BYTE, RESULT, Rotate32, Scalar32, WORD_BITS, WORD_BYTES, WORDS_PER_VECTOR,
    move_to_vector, pack_state, read_scalar_vector,
};
use super::{Host, commit, packed, read_vector, shuffle};
use crate::{
    TargetCpu,
    aarch64::simd::sha1::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

const EAX: u8 = 0;
const ECX: u8 = 1;
const EDX: u8 = 2;
const ESI: u8 = 6;
const R8D: u8 = 8;
const R9D: u8 = 9;
const R10D: u8 = 10;
const R11D: u8 = 11;
const LEFT: u8 = 1;
const RIGHT: u8 = 2;
const TEMPORARY: u8 = 3;
const LOW_WORD: u8 = 0;
const HASH_E_INDEX: usize = WORDS_PER_VECTOR;
const HASH_A_ROTATE: u8 = 5;
const HASH_B_ROTATE: u8 = 30;
const HASH_E_ROTATE_RIGHT: u8 = 2;
const SCHEDULE_ROTATE: u8 = 1;
const SCHEDULE_FEEDBACK_ROTATE: u8 = 2;
const CHOOSE_FUNCTION: u8 = 0;
const PARITY_FUNCTION: u8 = 1;
const MAJORITY_FUNCTION: u8 = 2;
const REVERSE_DWORDS: u8 = 0x1b;
const SWAP_QWORDS: u8 = 0x4e;
const BROADCAST_LOW_DWORD: u8 = 0;
const MOV_EAX_IMM32: u8 = 0xb8;
// Intel SHA1RNDS4's immediate selects these FIPS 180-4 section 4.2.1 constants.
// Arm's message operand already contains whatever round constants it requires.
const CHOOSE_CONSTANT: u32 = 0x5a827999;
const PARITY_CONSTANT: u32 = 0x6ed9eba1;
const MAJORITY_CONSTANT: u32 = 0x8f1bbcdc;

fn rounds_baseline(code: &mut Vec<u8>, operand: &Operand) {
    use Scalar32::*;
    let mut state = [EAX, ECX, EDX, ESI, R8D];
    for (lane, register) in state[..WORDS_PER_VECTOR].iter().enumerate() {
        Move.state(code, *register, operand.destination, lane as u8);
    }
    Move.state(code, state[HASH_E_INDEX], operand.left, LOW_WORD);
    for lane in 0..WORDS_PER_VECTOR as u8 {
        let [a, b, c, d, e] = state;
        match operand.kind {
            Kind::Choose => {
                Move.register(code, R10D, c);
                Xor.register(code, R10D, d);
                And.register(code, R10D, b);
                Xor.register(code, R10D, d);
            }
            Kind::Parity => {
                Move.register(code, R10D, b);
                Xor.register(code, R10D, c);
                Xor.register(code, R10D, d);
            }
            Kind::Majority => {
                Move.register(code, R10D, b);
                And.register(code, R10D, c);
                Move.register(code, R11D, b);
                Or.register(code, R11D, c);
                And.register(code, R11D, d);
                Or.register(code, R10D, R11D);
            }
            _ => unreachable!("SHA1 hash update kind"),
        }
        Move.register(code, R9D, a);
        Rotate32::Left.emit(code, R9D, HASH_A_ROTATE);
        Add.register(code, e, R9D);
        Add.register(code, e, R10D);
        // No guest state is written until every original message lane is read.
        Add.state(code, e, operand.right, lane);
        Rotate32::Left.emit(code, b, HASH_B_ROTATE);
        state = [e, a, b, c, d];
    }
    pack_state(code, [state[0], state[1], state[2], state[3]]);
}

fn rounds_sha(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    let (function, constant) = match operand.kind {
        Kind::Choose => (CHOOSE_FUNCTION, CHOOSE_CONSTANT),
        Kind::Parity => (PARITY_FUNCTION, PARITY_CONSTANT),
        Kind::Majority => (MAJORITY_FUNCTION, MAJORITY_CONSTANT),
        _ => unreachable!("SHA1 hash update kind"),
    };
    read_vector(code, operand.destination, RESULT);
    read_vector(code, operand.right, RIGHT);
    // MOVD reads only Sn[31:0], zeros its upper lanes, and adds E to W0 only.
    read_scalar_vector(code, LEFT, operand.left);
    packed(code, Host::AddDword, RIGHT, LEFT);
    code.push(MOV_EAX_IMM32);
    code.extend(constant.to_le_bytes());
    move_to_vector(code, TEMPORARY, EAX);
    shuffle(code, TEMPORARY, TEMPORARY, BROADCAST_LOW_DWORD);
    packed(code, Host::SubDword, RIGHT, TEMPORARY); // cancel Intel's built-in K in all rounds
    shuffle(code, RESULT, RESULT, REVERSE_DWORDS);
    shuffle(code, RIGHT, RIGHT, REVERSE_DWORDS);
    Host::Sha1Rounds4.register(code, RESULT, RIGHT, target);
    code.push(function);
    shuffle(code, RESULT, RESULT, REVERSE_DWORDS);
}

fn schedule0(code: &mut Vec<u8>, operand: &Operand) {
    read_vector(code, operand.destination, RESULT);
    read_vector(code, operand.left, LEFT);
    read_vector(code, operand.right, RIGHT);
    // [d2,d3,n0,n1] XOR d XOR m, low lane first.
    shuffle(code, TEMPORARY, RESULT, SWAP_QWORDS);
    packed(code, Host::UnpackLowQword, TEMPORARY, LEFT);
    packed(code, Host::Xor, RESULT, TEMPORARY);
    packed(code, Host::Xor, RESULT, RIGHT);
}
fn rotate_lanes(code: &mut Vec<u8>, vector: u8, temporary: u8, amount: u8) {
    packed(code, Host::MoveAligned, temporary, vector);
    Shift::LeftDword.emit(code, vector, amount);
    Shift::RightDword.emit(code, temporary, WORD_BITS - amount);
    packed(code, Host::Or, vector, temporary);
}
fn schedule1(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    read_vector(code, operand.destination, RESULT);
    read_vector(code, operand.left, LEFT);
    if target.supports(TargetCpu::Sha) {
        shuffle(code, RESULT, RESULT, REVERSE_DWORDS);
        shuffle(code, LEFT, LEFT, REVERSE_DWORDS);
        Host::Sha1Message2.register(code, RESULT, LEFT, target);
        shuffle(code, RESULT, RESULT, REVERSE_DWORDS);
    } else {
        Shift::RightBytes.emit(code, LEFT, WORD_BYTES);
        packed(code, Host::Xor, RESULT, LEFT);
        packed(code, Host::MoveAligned, RIGHT, RESULT);
        Shift::LeftBytes.emit(code, RIGHT, HIGH_WORD_BYTE); // T0 only, in the high result lane
        rotate_lanes(code, RIGHT, TEMPORARY, SCHEDULE_FEEDBACK_ROTATE);
        rotate_lanes(code, RESULT, LEFT, SCHEDULE_ROTATE);
        packed(code, Host::Xor, RESULT, RIGHT);
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand, target: TargetCpu) {
    match operand.kind {
        Kind::Choose | Kind::Parity | Kind::Majority => {
            if target.supports(TargetCpu::Sha) {
                rounds_sha(code, operand, target);
            } else {
                rounds_baseline(code, operand);
            }
        }
        Kind::Rotate => {
            Scalar32::Move.state(code, EAX, operand.left, LOW_WORD);
            Rotate32::Right.emit(code, EAX, HASH_E_ROTATE_RIGHT);
            move_to_vector(code, RESULT, EAX); // clears destination bits 127:32
        }
        Kind::Schedule0 => schedule0(code, operand),
        Kind::Schedule1 => schedule1(code, operand, target),
    }
    commit(code, operand.destination, RESULT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_has_no_sha_and_checked_rounds_cancel_the_selected_constant() {
        for (kind, constant) in [
            (Kind::Choose, CHOOSE_CONSTANT),
            (Kind::Parity, PARITY_CONSTANT),
            (Kind::Majority, MAJORITY_CONSTANT),
        ] {
            let operand = Operand {
                kind,
                destination: 31,
                left: 31,
                right: 31,
            };
            let mut baseline = Vec::new();
            emit(&mut baseline, &operand, TargetCpu::Baseline);
            assert!(!baseline.windows(3).any(|w| w == [0x0f, 0x3a, 0xcc]));
            let mut checked = Vec::new();
            emit(&mut checked, &operand, TargetCpu::Sha);
            assert!(checked.windows(3).any(|w| w == [0x0f, 0x3a, 0xcc]));
            assert!(checked.windows(4).any(|w| w == constant.to_le_bytes()));
            assert!(checked.windows(3).any(|w| w == Host::SubDword.encoding()));
        }
    }
}
