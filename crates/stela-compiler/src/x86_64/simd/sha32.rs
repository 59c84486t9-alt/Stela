//! Exact 32-bit encoders shared by the classic SHA1/SHA256 recipes.
//! This is a fixed GuestState/legacy-XMM boundary, not a general assembler.
use super::{Host, packed, vector_offset};
use alloc::vec::Vec;

pub(super) const WORD_BITS: u8 = 32;
pub(super) const WORD_BYTES: u8 = WORD_BITS / 8;
pub(super) const WORDS_PER_VECTOR: usize = 4;
pub(super) const DOUBLE_WORD_BYTES: u8 = WORD_BYTES * 2;
pub(super) const HIGH_WORD_BYTE: u8 = WORD_BYTES * 3;
pub(super) const RESULT: u8 = 0;
const PACK_PAIR: u8 = 1;
const PACK_LAST: u8 = 2;
const LOW_REGISTER_MASK: u8 = 7;
const EXTENDED_REGISTER_SHIFT: u8 = 3;
const MODRM_REGISTER_SHIFT: u8 = 3;
const MODRM_REGISTER: u8 = 0xc0;
const MODRM_STATE_DISPLACEMENT: u8 = 0x87; // [rdi+disp32]
const REX_BASE: u8 = 0x40;
const REX_REGISTER_SHIFT: u8 = 2;
const NO_EXTENDED_OPERAND: u8 = 0;
const PACKED_PREFIX: u8 = 0x66;
const MOVD_XMM_RM32: [u8; 2] = [0x0f, 0x6e];
const ROTATE_IMMEDIATE: u8 = 0xc1;
const ROL_GROUP: u8 = 0;
const ROR_GROUP: u8 = 1;

#[derive(Clone, Copy)]
pub(super) enum Scalar32 {
    Move,
    Add,
    Xor,
    And,
    Or,
}
impl Scalar32 {
    fn opcode(self) -> u8 {
        match self {
            Self::Move => 0x8b,
            Self::Add => 0x03,
            Self::Xor => 0x33,
            Self::And => 0x23,
            Self::Or => 0x0b,
        }
    }
    pub(super) fn register(self, code: &mut Vec<u8>, destination: u8, source: u8) {
        rex(code, destination, source);
        code.extend([
            self.opcode(),
            MODRM_REGISTER
                | ((destination & LOW_REGISTER_MASK) << MODRM_REGISTER_SHIFT)
                | (source & LOW_REGISTER_MASK),
        ]);
    }
    pub(super) fn state(self, code: &mut Vec<u8>, destination: u8, vector: u8, lane: u8) {
        rex(code, destination, NO_EXTENDED_OPERAND);
        code.extend([
            self.opcode(),
            MODRM_STATE_DISPLACEMENT | ((destination & LOW_REGISTER_MASK) << MODRM_REGISTER_SHIFT),
        ]);
        code.extend(
            (vector_offset(vector) + u32::from(lane) * u32::from(WORD_BYTES)).to_le_bytes(),
        );
    }
}
fn rex(code: &mut Vec<u8>, destination: u8, source: u8) {
    let prefix = REX_BASE
        | ((destination >> EXTENDED_REGISTER_SHIFT) << REX_REGISTER_SHIFT)
        | (source >> EXTENDED_REGISTER_SHIFT);
    if prefix != REX_BASE {
        code.push(prefix);
    }
}

pub(super) enum Rotate32 {
    Left,
    Right,
}
impl Rotate32 {
    pub(super) fn emit(self, code: &mut Vec<u8>, register: u8, amount: u8) {
        rex(code, NO_EXTENDED_OPERAND, register);
        let group = match self {
            Self::Left => ROL_GROUP,
            Self::Right => ROR_GROUP,
        };
        code.extend([
            ROTATE_IMMEDIATE,
            MODRM_REGISTER | (group << MODRM_REGISTER_SHIFT) | (register & LOW_REGISTER_MASK),
            amount,
        ]);
    }
}
pub(super) fn move_to_vector(code: &mut Vec<u8>, xmm: u8, register: u8) {
    code.push(PACKED_PREFIX);
    rex(code, xmm, register);
    code.extend(MOVD_XMM_RM32);
    code.push(MODRM_REGISTER | (xmm << MODRM_REGISTER_SHIFT) | (register & LOW_REGISTER_MASK));
}
pub(super) fn read_scalar_vector(code: &mut Vec<u8>, xmm: u8, vector: u8) {
    code.push(PACKED_PREFIX);
    rex(code, xmm, NO_EXTENDED_OPERAND);
    code.extend(MOVD_XMM_RM32);
    code.push(MODRM_STATE_DISPLACEMENT | (xmm << MODRM_REGISTER_SHIFT));
    code.extend(vector_offset(vector).to_le_bytes());
}
/// Pack four zero-extended words into RESULT; PACK_PAIR/PACK_LAST are scratch.
pub(super) fn pack_state(code: &mut Vec<u8>, words: [u8; WORDS_PER_VECTOR]) {
    move_to_vector(code, RESULT, words[0]);
    move_to_vector(code, PACK_PAIR, words[1]);
    packed(code, Host::UnpackLowDword, RESULT, PACK_PAIR);
    move_to_vector(code, PACK_PAIR, words[2]);
    move_to_vector(code, PACK_LAST, words[3]);
    packed(code, Host::UnpackLowDword, PACK_PAIR, PACK_LAST);
    packed(code, Host::UnpackLowQword, RESULT, PACK_PAIR);
}
