//! Exact-width ordinary-RAM literal loads; commit only after a successful access.
use super::{simd, store};
use crate::aarch64::{
    Width,
    literal::{Operand, Transfer},
};

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
mod tests {
    use super::*;
    use crate::{GuestState, aarch64::Register};

    #[test]
    fn integer_discard_still_loads_and_signed_load_has_exact_width() {
        for (width, signed, expected) in [
            (Width::W32, false, &[0x8b, 0x00][..]),
            (Width::X64, false, &[0x48, 0x8b, 0x00][..]),
            (Width::X64, true, &[0x48, 0x63, 0x00][..]),
        ] {
            let mut code = vec![];
            emit(
                &mut code,
                &Operand {
                    address: u64::MAX,
                    transfer: Transfer::Integer {
                        destination: Register::Zero,
                        width,
                        signed,
                    },
                },
            );
            assert_eq!(&code[..2], &[0x48, 0xb8]);
            assert_eq!(&code[2..10], &u64::MAX.to_le_bytes());
            assert_eq!(&code[10..], expected);
        }
    }

    #[test]
    fn vector31_load_stages_exact_width_before_full_state_commit() {
        for (bytes, expected) in [
            (4, [0x66, 0x0f, 0x6e, 0x00]),
            (8, [0xf3, 0x0f, 0x7e, 0x00]),
            (16, [0xf3, 0x0f, 0x6f, 0x00]),
        ] {
            let mut code = vec![];
            emit(
                &mut code,
                &Operand {
                    address: 0x123456789abc,
                    transfer: Transfer::Simd {
                        destination: 31,
                        bytes,
                    },
                },
            );
            assert_eq!(&code[10..14], &expected);
            assert_eq!(&code[14..18], &[0xf3, 0x0f, 0x7f, 0x87]);
            let vector31 = (std::mem::offset_of!(GuestState, v) + 31 * 16) as u32;
            assert_eq!(&code[18..], &vector31.to_le_bytes());
        }
    }
}
