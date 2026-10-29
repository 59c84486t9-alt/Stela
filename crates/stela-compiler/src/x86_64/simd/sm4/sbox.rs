//! SM4 field arithmetic with fixed work and no secret-indexed memory.
use super::super::{Host, packed, shuffle};
use crate::x86_64::{
    asm::{Code, Gpr, Rm},
    isa::ShiftOpcode as Shift,
};
const VALUE: Gpr = Gpr::R8;

fn byte_constant(code: &mut Code, xmm: u8, value: u8) {
    code.asm().mov_imm32(VALUE, u32::from(value) * 0x01010101);
    code.asm().movd_to_xmm(xmm, VALUE);
    shuffle(code, xmm, xmm, 0);
}

/// Per-byte GF(2^8) multiply modulo x8+x7+x6+x5+x4+x2+1.
/// Inputs/outputs live in XMM8..15; XMM0..7 are explicit scratch.
fn multiply(code: &mut Code, destination: u8, left: u8, right: u8) {
    packed(code, Host::MoveAligned, 0, left);
    packed(code, Host::MoveAligned, 1, right);
    packed(code, Host::Xor, 2, 2);
    byte_constant(code, 5, 1);
    byte_constant(code, 6, 0xf5);
    byte_constant(code, 7, 0x7f);
    for _ in 0..8 {
        packed(code, Host::MoveAligned, 3, 1);
        packed(code, Host::And, 3, 5);
        packed(code, Host::Xor, 4, 4);
        packed(code, Host::SubByte, 4, 3);
        packed(code, Host::And, 4, 0);
        packed(code, Host::Xor, 2, 4);
        // Signed byte comparison against zero is the carry mask for bit7.
        packed(code, Host::Xor, 3, 3);
        packed(code, Host::GreaterByte, 3, 0);
        packed(code, Host::And, 3, 6);
        packed(code, Host::AddByte, 0, 0);
        packed(code, Host::Xor, 0, 3);
        Shift::RightWord.emit(code, 1, 1);
        packed(code, Host::And, 1, 7);
    }
    packed(code, Host::MoveAligned, destination, 2);
}

/// The circulant SM4 affine map is x XOR ROL8(x,1,3,6,7), then XOR0xd3.
/// This exact algebra is exhaustively checked against the Arm Sbox table.
fn affine(code: &mut Code, value: u8) {
    packed(code, Host::MoveAligned, 0, value);
    packed(code, Host::MoveAligned, 1, value);
    for rotation in [1, 3, 6, 7] {
        packed(code, Host::MoveAligned, 2, 0);
        packed(code, Host::MoveAligned, 3, 0);
        Shift::LeftWord.emit(code, 2, rotation);
        byte_constant(code, 4, 0xff_u8 << rotation);
        packed(code, Host::And, 2, 4);
        Shift::RightWord.emit(code, 3, 8 - rotation);
        byte_constant(code, 4, (1_u8 << rotation) - 1);
        packed(code, Host::And, 3, 4);
        packed(code, Host::Or, 2, 3);
        packed(code, Host::Xor, 1, 2);
    }
    byte_constant(code, 4, 0xd3);
    packed(code, Host::Xor, 1, 4);
    packed(code, Host::MoveAligned, value, 1);
}

fn baseline(code: &mut Code) {
    code.asm().movd_to_xmm(8, VALUE);
    affine(code, 8);
    // Addition chain: 2,3,6,12,15,30,60,120,240,252,254. Zero stays zero.
    multiply(code, 9, 8, 8); // x2
    multiply(code, 10, 9, 8); // x3
    multiply(code, 11, 10, 10); // x6
    multiply(code, 11, 11, 11); // x12, retained until the final product
    multiply(code, 8, 11, 10); // x15
    for _ in 0..4 {
        multiply(code, 8, 8, 8);
    } // x30,x60,x120,x240
    multiply(code, 8, 8, 11); // x252
    multiply(code, 8, 8, 9); // x254
    affine(code, 8);
    code.asm().movd_from_xmm(VALUE, 8);
}

fn matrix(code: &mut Code, xmm: u8, value: u64) {
    code.asm().mov_imm64(VALUE, value);
    code.asm().movq_to_xmm(xmm, VALUE);
    packed(code, Host::UnpackLowQword, xmm, xmm);
}
fn native(code: &mut Code) {
    code.asm().movd_to_xmm(0, VALUE);
    // Derive the isomorphism T by mapping the SM4 field generator to the
    // smallest root0x23 of its polynomial in the AES field. Pre=T*A,
    // post=A*T^-1; GFNI's row order is reversed within each qword.
    matrix(code, 1, 0x4c287db91a22505d);
    code.asm().gf2p8affineqb(0, Rm::Xmm(1), 0x3e);
    matrix(code, 1, 0xf3ab34a974a6b589);
    code.asm().gf2p8affineinvqb(0, Rm::Xmm(1), 0xd3);
    code.asm().movd_from_xmm(VALUE, 0);
}
pub(super) fn emit(code: &mut Code, gfni: bool) {
    if gfni {
        native(code);
    } else {
        baseline(code);
    }
}
