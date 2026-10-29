//! SM3 baseline recipes: wrapping 32-bit arithmetic, no host SM3 requirement.
use super::commit;
use super::sha32::{RESULT, Rotate32, Scalar32, pack_state};
use crate::aarch64::simd::sm3::{Kind, Operand};
use crate::x86_64::asm::Code;

// Caller-saved words only; RDI remains the real GuestState pointer.
const WORDS: [u8; 4] = [0, 1, 2, 6];
const VALUE: u8 = 8;
const TEMP: u8 = 9;
const OTHER: u8 = 10;
const EXTRA: u8 = 11;

/// x XOR ROL(x,a) XOR ROL(x,b), keeping the original x in scratch.
fn permutation(code: &mut Code, value: u8, scratch: [u8; 2], rotations: [u8; 2]) {
    use Scalar32::*;
    for (register, rotation) in scratch.into_iter().zip(rotations) {
        Move.register(code, register, value);
        Rotate32::Left.emit(code, register, rotation);
    }
    for register in scratch {
        Xor.register(code, value, register);
    }
}

fn schedule(code: &mut Code, operand: &Operand, first: bool) {
    use Scalar32::*;
    // No destination store occurs until every possibly aliased source is read.
    for (lane, register) in WORDS.into_iter().enumerate() {
        Move.state(code, register, operand.destination, lane as u8);
        Xor.state(code, register, operand.left, lane as u8);
        if first && lane == 3 {
            Move.register(code, VALUE, WORDS[0]);
            Rotate32::Left.emit(code, VALUE, 15);
        } else {
            Move.state(
                code,
                VALUE,
                operand.right,
                (lane + usize::from(first)) as u8,
            );
            Rotate32::Left.emit(code, VALUE, if first { 15 } else { 7 });
        }
        Xor.register(code, register, VALUE);
        if first {
            permutation(code, register, [TEMP, OTHER], [15, 23]);
        } else if lane == 0 {
            // Keep n0 XOR ROL(m0,7), not the old destination contribution.
            Move.register(code, EXTRA, VALUE);
            Xor.state(code, EXTRA, operand.left, 0);
        }
    }
    if !first {
        Rotate32::Left.emit(code, EXTRA, 15);
        permutation(code, EXTRA, [TEMP, OTHER], [15, 23]);
        Xor.register(code, WORDS[3], EXTRA);
    }
    pack_state(code, WORDS);
}

fn sum(code: &mut Code, operand: &Operand, third: u8) {
    use Scalar32::*;
    Move.state(code, VALUE, operand.left, 3);
    Rotate32::Left.emit(code, VALUE, 12);
    Add.state(code, VALUE, operand.right, 3);
    Add.state(code, VALUE, third, 3);
    Rotate32::Left.emit(code, VALUE, 7);
    // The three low words are architectural zero, not kept destination data.
    Xor.register(code, WORDS[0], WORDS[0]);
    pack_state(code, [WORDS[0], WORDS[0], WORDS[0], VALUE]);
}

fn round(code: &mut Code, operand: &Operand, second: bool, nonlinear: bool, lane: u8) {
    use Scalar32::*;
    for (lane, register) in WORDS.into_iter().enumerate() {
        Move.state(code, register, operand.destination, lane as u8);
    }
    let [low, middle, high, top] = WORDS;
    Move.register(code, VALUE, top);
    if !nonlinear {
        Xor.register(code, VALUE, high);
        Xor.register(code, VALUE, middle);
    } else if second {
        // choose(top, high, middle) = middle XOR (top AND (high XOR middle)).
        Move.register(code, TEMP, high);
        Xor.register(code, TEMP, middle);
        And.register(code, VALUE, TEMP);
        Xor.register(code, VALUE, middle);
    } else {
        And.register(code, VALUE, middle);
        Move.register(code, TEMP, top);
        Or.register(code, TEMP, middle);
        And.register(code, TEMP, high);
        Or.register(code, VALUE, TEMP);
    }
    Add.register(code, VALUE, low);
    Add.state(code, VALUE, operand.right, lane);
    Move.state(code, TEMP, operand.left, 3);
    if !second {
        Move.register(code, OTHER, top);
        Rotate32::Left.emit(code, OTHER, 12);
        Xor.register(code, TEMP, OTHER);
    }
    Add.register(code, VALUE, TEMP);
    if second {
        permutation(code, VALUE, [TEMP, OTHER], [9, 17]);
    }
    Rotate32::Left.emit(code, high, if second { 19 } else { 9 });
    pack_state(code, [middle, high, top, VALUE]);
}

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    match operand.kind {
        Kind::Schedule1 => schedule(code, operand, true),
        Kind::Schedule2 => schedule(code, operand, false),
        Kind::Sum { third } => sum(code, operand, third),
        Kind::Round {
            second,
            nonlinear,
            lane,
        } => round(code, operand, second, nonlinear, lane),
    }
    commit(code, operand.destination, RESULT);
}

#[cfg(all(test, target_arch = "x86_64", target_os = "linux"))]
mod tests;
