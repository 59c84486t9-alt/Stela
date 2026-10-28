//! 32-bit lane encodings shared by the SHA1 and SHA256 recipes.
use super::{Host, packed, vector_offset};
use crate::x86_64::asm::{Alu, Code, Rm, ShiftOp, Size};
use crate::x86_64::simd::encode::{gpr, guest};

pub(super) const WORD_BITS: u8 = 32;
pub(super) const WORD_BYTES: u8 = WORD_BITS / 8;
pub(super) const WORDS_PER_VECTOR: usize = 4;
pub(super) const DOUBLE_WORD_BYTES: u8 = WORD_BYTES * 2;
pub(super) const HIGH_WORD_BYTE: u8 = WORD_BYTES * 3;
pub(super) const RESULT: u8 = 0;
const PACK_PAIR: u8 = 1;
const PACK_LAST: u8 = 2;

#[derive(Clone, Copy)]
pub(super) enum Scalar32 {
    Move,
    Add,
    Xor,
    And,
    Or,
}
impl Scalar32 {
    /// `op destination, rm` in the load direction.
    fn emit(self, code: &mut Code, destination: u8, rm: Rm) {
        let mut asm = code.asm();
        let op = match self {
            Self::Move => return asm.mov_load(Size::Dword, gpr(destination), rm),
            Self::Add => Alu::Add,
            Self::Xor => Alu::Xor,
            Self::And => Alu::And,
            Self::Or => Alu::Or,
        };
        asm.alu_load(op, Size::Dword, gpr(destination), rm);
    }
    pub(super) fn register(self, code: &mut Code, destination: u8, source: u8) {
        self.emit(code, destination, Rm::Reg(gpr(source)));
    }
    pub(super) fn state(self, code: &mut Code, destination: u8, vector: u8, lane: u8) {
        let offset = vector_offset(vector) + u32::from(lane) * u32::from(WORD_BYTES);
        self.emit(code, destination, Rm::Mem(guest(offset)));
    }
}

pub(super) enum Rotate32 {
    Left,
    Right,
}
impl Rotate32 {
    pub(super) fn emit(self, code: &mut Code, register: u8, amount: u8) {
        let op = match self {
            Self::Left => ShiftOp::Rol,
            Self::Right => ShiftOp::Ror,
        };
        code.asm().shift_imm(op, Size::Dword, gpr(register), amount);
    }
}
pub(super) fn move_to_vector(code: &mut Code, xmm: u8, register: u8) {
    code.asm().movd_to_xmm(xmm, gpr(register));
}
pub(super) fn read_scalar_vector(code: &mut Code, xmm: u8, vector: u8) {
    code.asm().movd_to_xmm(xmm, guest(vector_offset(vector)));
}
/// Pack four zero-extended words into RESULT; PACK_PAIR/PACK_LAST are scratch.
pub(super) fn pack_state(code: &mut Code, words: [u8; WORDS_PER_VECTOR]) {
    move_to_vector(code, RESULT, words[0]);
    move_to_vector(code, PACK_PAIR, words[1]);
    packed(code, Host::UnpackLowDword, RESULT, PACK_PAIR);
    move_to_vector(code, PACK_PAIR, words[2]);
    move_to_vector(code, PACK_LAST, words[3]);
    packed(code, Host::UnpackLowDword, PACK_PAIR, PACK_LAST);
    packed(code, Host::UnpackLowQword, RESULT, PACK_PAIR);
}
