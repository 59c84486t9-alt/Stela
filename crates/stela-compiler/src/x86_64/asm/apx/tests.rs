//! Independent encoding vectors and architectural NF/zero-extension checks.
use super::*;
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
use crate::x86_64::asm::Mem;
use crate::x86_64::asm::{Code, Gpr::*};

#[test]
fn ndd_nf_encodings_match_gnu_assembler() {
    for (operation, preserve_flags, expected) in [
        (Alu::Add, false, [0x62, 0xec, 0xe4, 0x10, 0x01, 0xca]),
        (Alu::Add, true, [0x62, 0xec, 0xe4, 0x14, 0x01, 0xca]),
        (Alu::And, true, [0x62, 0xec, 0xe4, 0x14, 0x21, 0xca]),
    ] {
        let mut code = Code::new();
        code.asm().apx_alu(AluOperands {
            operation,
            size: Size::Qword,
            destination: R19,
            left: R18,
            right: R17,
            preserve_flags,
        });
        assert_eq!(code.as_slice(), expected);
        assert_eq!(code.instructions(), 1);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn nf_preserves_every_flag_and_ndd_zero_extends_dword_results() {
    if !crate::TargetCpu::detect().supports(crate::TargetCpu::Apx.with_apx_ndd()) {
        std::eprintln!("APX NDD/NF execution unavailable on this host");
        return;
    }
    for size in [Size::Dword, Size::Qword] {
        for operation in [Alu::Add, Alu::Or, Alu::And, Alu::Sub, Alu::Xor] {
            for (left, right) in [
                (u64::MAX, 1),
                (0x7fff_ffff_ffff_ffff, 3),
                (0x8000_0000_8000_0000, 0x80ff_00ff_aa55_aa55),
            ] {
                let mut code = Code::new();
                let mut a = code.asm();
                a.mov_imm64(R8, left);
                a.mov_imm64(R9, right);
                a.mov_imm64(R16, u64::MAX);
                a.alu(Alu::Cmp, size, R8, R9);
                a.fixed(&[0x9c]);
                a.pop(Rax);
                a.mov_store(Size::Qword, Mem::base(Rdi, 0), Rax);
                a.apx_alu(AluOperands {
                    operation,
                    size,
                    destination: R16,
                    left: R8,
                    right: R9,
                    preserve_flags: true,
                });
                a.fixed(&[0x9c]);
                a.pop(Rax);
                a.mov_store(Size::Qword, Mem::base(Rdi, 8), Rax);
                a.mov_store(Size::Qword, Mem::base(Rdi, 16), R16);
                let mut state = crate::GuestState::default();
                crate::x86_64::native::run(&code, &mut state);
                assert_eq!(state.x[0], state.x[1], "NF changed flags for {operation:?}");
                let expected = match operation {
                    Alu::Add => left.wrapping_add(right),
                    Alu::Or => left | right,
                    Alu::And => left & right,
                    Alu::Sub => left.wrapping_sub(right),
                    Alu::Xor => left ^ right,
                    _ => unreachable!(),
                };
                assert_eq!(
                    state.x[2],
                    if size == Size::Dword {
                        expected & 0xffff_ffff
                    } else {
                        expected
                    }
                );
            }
        }
    }
    std::eprintln!("APX NDD/NF arithmetic, flags and dword zero extension executed");
}
