//! SHA512: scalar large sigmas and packed small sigmas.
use super::{Host, commit, packed, read_vector, shuffle, vector_offset};
use crate::x86_64::asm::{Alu, Code, Gpr, ShiftOp, Size};
use crate::x86_64::simd::encode::guest;
use crate::{
    TargetCpu,
    aarch64::simd::sha512::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

const QWORD_BITS: u8 = 64;
const QWORD_BYTES: u32 = 8;
const LOW: u32 = 0;
const HIGH: u32 = 1;
const SWAP_QWORDS: u8 = 0x4e;
const OLD_DESTINATION_XMM: u8 = 0;
const SECOND_SOURCE_XMM: u8 = 1;
const SIGMA_INPUT_XMM: u8 = 2;
const SIGMA_OUTPUT_XMM: u8 = 3;
const ROTATE_SCRATCH_XMM: u8 = 4;
const SECOND_ROTATE_XMM: u8 = 5;
const SMALL_SIGMA0_ROTATIONS: [u8; 2] = [1, 8];
const SMALL_SIGMA0_SHIFT: u8 = 7;
const SMALL_SIGMA1_ROTATIONS: [u8; 2] = [19, 61];
const SMALL_SIGMA1_SHIFT: u8 = 6;
const LARGE_SIGMA0_ROTATIONS: [u8; 3] = [28, 34, 39];
const LARGE_SIGMA1_ROTATIONS: [u8; 3] = [14, 18, 41];

// Only caller-saved registers; RDI remains the GuestState pointer.
const W0: Gpr = Gpr::Rax;
const W1: Gpr = Gpr::Rcx;
const X0: Gpr = Gpr::Rdx;
const X1: Gpr = Gpr::Rsi;
const Y0: Gpr = Gpr::R8;
const Y1: Gpr = Gpr::R9;
const VALUE: Gpr = Gpr::R10;
const SIGMA: Gpr = Gpr::R11;

/// Baseline 64-bit register/register instructions.
#[derive(Clone, Copy)]
enum QwordOpcode {
    Add,
    Or,
    And,
    Xor,
    Move,
}

impl QwordOpcode {
    fn emit(self, code: &mut Code, destination: Gpr, source: Gpr) {
        let mut asm = code.asm();
        let op = match self {
            Self::Add => Alu::Add,
            Self::Or => Alu::Or,
            Self::And => Alu::And,
            Self::Xor => Alu::Xor,
            Self::Move => return asm.mov(Size::Qword, destination, source),
        };
        asm.alu(op, Size::Qword, destination, source);
    }
}

fn state_qword(code: &mut Code, vector: u8, lane: u32, register: Gpr, load: bool) {
    let memory = guest(vector_offset(vector) + lane * QWORD_BYTES);
    if load {
        code.asm().mov_load(Size::Qword, register, memory);
    } else {
        code.asm().mov_store(Size::Qword, memory, register);
    }
}

fn rotate(code: &mut Code, destination: Gpr, amount: u8) {
    code.asm()
        .shift_imm(ShiftOp::Ror, Size::Qword, destination, amount);
}

fn large_sigma(
    code: &mut Code,
    destination: Gpr,
    source: Gpr,
    scratch: [Gpr; 2],
    rotations: [u8; 3],
) {
    // Independent rotates expose parallelism. Callers reuse dead inputs as
    // scratch, avoiding spills and extra CPU features.
    let [first, second] = scratch;
    let [low, middle, high] = rotations;
    QwordOpcode::Move.emit(code, destination, source);
    QwordOpcode::Move.emit(code, first, source);
    QwordOpcode::Move.emit(code, second, source);
    rotate(code, destination, low);
    rotate(code, first, middle);
    rotate(code, second, high);
    QwordOpcode::Xor.emit(code, destination, first);
    QwordOpcode::Xor.emit(code, destination, second);
}

fn choose(code: &mut Code, destination: Gpr, selector: Gpr, yes: Gpr, no: Gpr) {
    QwordOpcode::Move.emit(code, destination, yes);
    QwordOpcode::Xor.emit(code, destination, no);
    QwordOpcode::And.emit(code, destination, selector);
    QwordOpcode::Xor.emit(code, destination, no);
}

fn majority(code: &mut Code, destination: Gpr, scratch: Gpr, x: Gpr, y: Gpr, z: Gpr) {
    QwordOpcode::Move.emit(code, destination, x);
    QwordOpcode::And.emit(code, destination, y);
    QwordOpcode::Move.emit(code, scratch, x);
    QwordOpcode::Or.emit(code, scratch, y);
    QwordOpcode::And.emit(code, scratch, z);
    QwordOpcode::Or.emit(code, destination, scratch);
}

fn hash(code: &mut Code, operand: &Operand, second: bool) {
    let right = operand.right.expect("three-register SHA512 hash form");
    // Stage every needed qword before either destination store, so the high
    // result can be stored before the low one is computed even when all three
    // registers alias.
    for (vector, lane, register) in [
        (operand.destination, LOW, W0),
        (operand.destination, HIGH, W1),
        (operand.left, LOW, X0),
        (right, LOW, Y0),
        (right, HIGH, Y1),
    ] {
        state_qword(code, vector, lane, register, true);
    }
    if second {
        majority(code, VALUE, SIGMA, X0, Y1, Y0);
        // X0 is dead after majority; X1 is unused by the guest H2 form.
        large_sigma(code, SIGMA, Y0, [X0, X1], LARGE_SIGMA0_ROTATIONS);
    } else {
        state_qword(code, operand.left, HIGH, X1, true);
        choose(code, VALUE, Y1, X0, X1);
        // Use the old W1 before sigma so that its register and the dead X1 can
        // hold independent rotations.
        QwordOpcode::Add.emit(code, VALUE, W1);
        large_sigma(code, SIGMA, Y1, [X1, W1], LARGE_SIGMA1_ROTATIONS);
    }
    QwordOpcode::Add.emit(code, VALUE, SIGMA);
    if second {
        QwordOpcode::Add.emit(code, VALUE, W1);
    }
    state_qword(code, operand.destination, HIGH, VALUE, false);

    if second {
        large_sigma(code, SIGMA, VALUE, [X0, X1], LARGE_SIGMA0_ROTATIONS);
        // W1 and X0 are dead inputs. VALUE stays the sigma source until sigma
        // completes, then becomes the first majority operand.
        majority(code, W1, X0, VALUE, Y0, Y1);
        QwordOpcode::Add.emit(code, W1, SIGMA);
        QwordOpcode::Add.emit(code, W1, W0);
        state_qword(code, operand.destination, LOW, W1, false);
    } else {
        QwordOpcode::Add.emit(code, VALUE, Y0);
        choose(code, SIGMA, VALUE, Y1, X0);
        // Y0 is dead after forming VALUE, and X1 was consumed by the first Ch.
        large_sigma(code, W1, VALUE, [X1, Y0], LARGE_SIGMA1_ROTATIONS);
        QwordOpcode::Add.emit(code, SIGMA, W1);
        QwordOpcode::Add.emit(code, SIGMA, W0);
        state_qword(code, operand.destination, LOW, SIGMA, false);
    }
}

fn packed_rotate(code: &mut Code, destination: u8, scratch: u8, source: u8, amount: u8) {
    packed(code, Host::MoveAligned, destination, source);
    Shift::RightQword.emit(code, destination, amount);
    packed(code, Host::MoveAligned, scratch, source);
    Shift::LeftQword.emit(code, scratch, QWORD_BITS - amount);
    packed(code, Host::Or, destination, scratch);
}

fn small_sigma(code: &mut Code, rotations: [u8; 2], shift: u8) {
    // XMM2 holds both independent sigma inputs. XMM0/1 keep old W/Y.
    packed_rotate(
        code,
        SIGMA_OUTPUT_XMM,
        ROTATE_SCRATCH_XMM,
        SIGMA_INPUT_XMM,
        rotations[0],
    );
    packed_rotate(
        code,
        SECOND_ROTATE_XMM,
        ROTATE_SCRATCH_XMM,
        SIGMA_INPUT_XMM,
        rotations[1],
    );
    packed(code, Host::Xor, SIGMA_OUTPUT_XMM, SECOND_ROTATE_XMM);
    Shift::RightQword.emit(code, SIGMA_INPUT_XMM, shift);
    packed(code, Host::Xor, SIGMA_OUTPUT_XMM, SIGMA_INPUT_XMM);
}

pub(super) fn emit(code: &mut Code, operand: &Operand, _target: TargetCpu) {
    match operand.kind {
        Kind::Hash | Kind::Hash2 => hash(code, operand, operand.kind == Kind::Hash2),
        Kind::Schedule0 => {
            read_vector(code, operand.destination, OLD_DESTINATION_XMM);
            read_vector(code, operand.left, SECOND_SOURCE_XMM);
            shuffle(code, SIGMA_INPUT_XMM, OLD_DESTINATION_XMM, SWAP_QWORDS);
            packed(
                code,
                Host::UnpackLowQword,
                SIGMA_INPUT_XMM,
                SECOND_SOURCE_XMM,
            ); // [old W1, old X0]
            small_sigma(code, SMALL_SIGMA0_ROTATIONS, SMALL_SIGMA0_SHIFT);
            packed(code, Host::AddQword, OLD_DESTINATION_XMM, SIGMA_OUTPUT_XMM);
            commit(code, operand.destination, OLD_DESTINATION_XMM);
        }
        Kind::Schedule1 => {
            read_vector(code, operand.destination, OLD_DESTINATION_XMM);
            read_vector(
                code,
                operand.right.expect("three-register SHA512SU1 form"),
                SECOND_SOURCE_XMM,
            );
            read_vector(code, operand.left, SIGMA_INPUT_XMM);
            small_sigma(code, SMALL_SIGMA1_ROTATIONS, SMALL_SIGMA1_SHIFT);
            packed(code, Host::AddQword, OLD_DESTINATION_XMM, SECOND_SOURCE_XMM);
            packed(code, Host::AddQword, OLD_DESTINATION_XMM, SIGMA_OUTPUT_XMM);
            commit(code, operand.destination, OLD_DESTINATION_XMM);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_qword_encodings_keep_rex_operand_roles_and_state_base() {
        let mut code = Code::new();
        QwordOpcode::Move.emit(&mut code, Gpr::R10, Gpr::Rdx);
        QwordOpcode::And.emit(&mut code, Gpr::R10, Gpr::R9);
        rotate(&mut code, Gpr::R11, 23);
        state_qword(&mut code, 31, HIGH, Gpr::R9, true);
        state_qword(&mut code, 31, LOW, Gpr::R10, false);
        let high = (vector_offset(31) + QWORD_BYTES).to_le_bytes();
        let low = vector_offset(31).to_le_bytes();
        assert_eq!(
            code,
            [
                &[0x49, 0x89, 0xd2][..], // mov r10,rdx
                &[0x4d, 0x21, 0xca],     // and r10,r9
                &[0x49, 0xc1, 0xcb, 23], // ror r11,23
                &[0x4c, 0x8b, 0x8f],
                &high,
                &[0x4c, 0x89, 0x97],
                &low,
            ]
            .concat()
        );
    }
}
