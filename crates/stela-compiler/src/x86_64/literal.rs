//! Literal loads. The destination is written only after the access succeeds.
use super::{simd, store};
use crate::aarch64::{
    Width,
    literal::{Operand, Transfer},
};
use crate::x86_64::asm::{Code, Gpr, Mem, Size};

pub(super) fn emit(code: &mut Code, operand: &Operand, checks: super::MemoryChecks) {
    code.asm().mov_imm64(Gpr::Rax, operand.address);
    let bytes = match operand.transfer {
        Transfer::Integer {
            width: Width::X64,
            signed: false,
            ..
        } => 8,
        Transfer::Integer { .. } => 4,
        Transfer::Simd { bytes, .. } => bytes,
    };
    super::address_checks(code, checks, bytes, super::Access::read(bytes.into()));
    match operand.transfer {
        Transfer::Integer {
            destination,
            width,
            signed,
        } => {
            let address = Mem::base(Gpr::Rax, 0);
            let mut asm = code.asm();
            asm.guest_access(|asm| {
                match (width, signed) {
                    // MOV EAX zero-extends RAX.
                    (Width::W32, false) => asm.mov_load(Size::Dword, Gpr::Rax, address),
                    (Width::X64, false) => asm.mov_load(Size::Qword, Gpr::Rax, address),
                    (Width::X64, true) => asm.movsxd(Gpr::Rax, address),
                    (Width::W32, true) => unreachable!("literal signed load writes X register"),
                }
            });
            // ZR discards only the result; its access and possible fault remain.
            store(code, destination);
        }
        Transfer::Simd { destination, bytes } => {
            simd::memory::transfer(code, true, bytes, destination, false, false);
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
            let mut code = Code::new();
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
                crate::x86_64::MemoryChecks::DEFAULT,
            );
            assert_eq!(&code[..2], &[0x48, 0xb8]);
            assert_eq!(&code[2..10], &u64::MAX.to_le_bytes());
            assert_eq!(&code[10..], expected);
        }
    }

    #[test]
    fn sctlr_a_checks_the_literal_address_against_the_access_size() {
        for (width, signed, unit) in [
            (Width::W32, false, 4),
            (Width::X64, false, 8),
            (Width::X64, true, 4),
        ] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand {
                    address: 0x1004,
                    transfer: Transfer::Integer {
                        destination: Register::X(0),
                        width,
                        signed,
                    },
                },
                crate::x86_64::MemoryChecks {
                    alignment: true,
                    ..crate::x86_64::MemoryChecks::DEFAULT
                },
            );
            assert_eq!(&code[10..16], &[0xa8, unit - 1, 0x74, 2, 0x0f, 0x0b]);
        }
    }

    #[test]
    fn vector31_load_stages_exact_width_before_full_state_commit() {
        for (bytes, expected) in [
            (4, [0x66, 0x0f, 0x6e, 0x00]),
            (8, [0xf3, 0x0f, 0x7e, 0x00]),
            (16, [0xf3, 0x0f, 0x6f, 0x00]),
        ] {
            let mut code = Code::new();
            emit(
                &mut code,
                &Operand {
                    address: 0x123456789abc,
                    transfer: Transfer::Simd {
                        destination: 31,
                        bytes,
                    },
                },
                crate::x86_64::MemoryChecks::DEFAULT,
            );
            assert_eq!(&code[10..14], &expected);
            assert_eq!(&code[14..18], &[0xf3, 0x0f, 0x7f, 0x87]);
            let vector31 = (core::mem::offset_of!(GuestState, v) + 31 * 16) as u32;
            assert_eq!(&code[18..], &vector31.to_le_bytes());
        }
    }
}
