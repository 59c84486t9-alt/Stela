//! Exact-width ordinary-RAM literal loads; commit only after a successful access.
use super::{simd, store};
use crate::aarch64::{
    Width,
    literal::{Operand, Transfer},
};
use alloc::vec::Vec;

/// Family-local baseline opcodes; address/state displacements follow separately.
#[derive(Clone, Copy)]
enum Opcode {
    MoveAddress,
    LoadWord,
    LoadDoubleword,
    LoadSignedWord,
}

impl Opcode {
    fn emit(self, code: &mut Vec<u8>) {
        code.extend(match self {
            Self::MoveAddress => &[0x48, 0xb8][..], // movabs rax,imm64
            Self::LoadWord => &[0x8b, 0x00],        // mov eax,[rax], zeroextends RAX
            Self::LoadDoubleword => &[0x48, 0x8b, 0x00], // mov rax,[rax]
            Self::LoadSignedWord => &[0x48, 0x63, 0x00], // movsxd rax,[rax]
        });
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    Opcode::MoveAddress.emit(code);
    code.extend(operand.address.to_le_bytes());
    match operand.transfer {
        Transfer::Integer {
            destination,
            width,
            signed,
        } => {
            match (width, signed) {
                (Width::W32, false) => Opcode::LoadWord,
                (Width::X64, false) => Opcode::LoadDoubleword,
                (Width::X64, true) => Opcode::LoadSignedWord,
                (Width::W32, true) => unreachable!("literal signed load writes X register"),
            }
            .emit(code);
            // ZR discards only the result; its access and possible fault remain.
            store(code, destination);
        }
        Transfer::Simd { destination, bytes } => {
            simd::memory::transfer(code, true, bytes, destination, false);
        }
    }
}

#[cfg(test)]
mod tests;
