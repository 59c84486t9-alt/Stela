//! GNU-assembled APX boundaries and execution of emitted extended-bank forms.
use super::*;
use crate::x86_64::asm::{Alu, Code, Gpr::*, Pp, ShiftOp};

fn one(build: impl FnOnce(&mut Asm)) -> Code {
    let mut code = Code::new();
    build(&mut code.asm());
    assert_eq!(code.instructions(), 1);
    code
}

#[test]
fn rex2_forms_match_independent_gnu_encodings() {
    use Size::*;
    for (expected, code) in [
        (
            &[0xd5, 0x59, 0x89, 0xc7][..],
            one(|a| a.mov(Qword, R31, R16)),
        ),
        (&[0xd5, 0x54, 0x89, 0xf8], one(|a| a.mov(Dword, R16, R31))),
        (
            &[
                0xd5, 0x19, 0xbf, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            ],
            one(|a| a.mov_imm64(R31, 0x1122334455667788)),
        ),
        (
            &[0xd5, 0x79, 0x89, 0x84, 0xe7, 0x34, 0x12, 0, 0],
            one(|a| a.mov_store(Qword, Mem::indexed(R31, R20, 8, 0x1234), R16)),
        ),
        (
            &[0xd5, 0x79, 0x8b, 0x84, 0xe7, 0x34, 0x12, 0, 0],
            one(|a| a.mov_load(Qword, R16, Mem::indexed(R31, R20, 8, 0x1234))),
        ),
        (
            &[0xd5, 0x58, 0x01, 0xca],
            one(|a| a.alu(Alu::Add, Qword, R18, R17)),
        ),
        (
            &[0xd5, 0x79, 0x8d, 0x44, 0xe7, 0x20],
            one(|a| a.lea(Qword, R16, Mem::indexed(R31, R20, 8, 0x20))),
        ),
        (
            &[0xd5, 0x18, 0xc1, 0xe0, 9],
            one(|a| a.shift_imm(ShiftOp::Shl, Qword, R16, 9)),
        ),
        (
            &[0xd5, 0x19, 0xd3, 0xe7],
            one(|a| a.shift_cl(ShiftOp::Shl, Qword, R31)),
        ),
        (
            &[0xf3, 0xd5, 0xdc, 0xbd, 0xf8],
            one(|a| a.lzcnt(Qword, R31, R16)),
        ),
        (
            &[0xf3, 0xd5, 0xdc, 0xb8, 0xf8],
            one(|a| a.popcnt(Qword, R31, R16)),
        ),
        (&[0xd5, 0x10, 0x50], one(|a| a.push(R16))),
        (&[0xd5, 0x11, 0x5f], one(|a| a.pop(R31))),
    ] {
        assert_eq!(code.as_slice(), expected);
    }
}

#[test]
#[should_panic(expected = "REX2 supports only legacy maps zero and one")]
fn rex2_refuses_map_two_instead_of_reinterpreting_the_opcode() {
    one(|a| {
        a.legacy(
            Size::Qword,
            None,
            &[0x0f, 0x38, 0xf0],
            16,
            false,
            Rax.into(),
        )
    });
}

#[test]
#[should_panic(expected = "VEX cannot encode APX registers")]
fn vex_refuses_an_extended_memory_base() {
    one(|a| {
        a.vex(
            Vex {
                map: Map::M0f,
                pp: Pp::None,
                w: false,
                l: false,
            },
            0x10,
            0,
            0,
            Mem::base(R16, 0).into(),
        )
    });
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn rex2_executes_every_extended_register_and_zero_extending_dword_write() {
    if !crate::TargetCpu::detect().supports(crate::TargetCpu::Apx) {
        std::eprintln!("APX execution unavailable on this host");
        return;
    }
    let mut code = Code::new();
    let mut a = code.asm();
    for number in 16_u8..32 {
        let register = Gpr::from_encoding(number);
        a.mov_imm64(register, u64::MAX);
        a.mov_imm32(register, 0x80000000 | u32::from(number));
    }
    for number in 16_u8..32 {
        a.mov_store(
            Size::Qword,
            Mem::base(Rdi, i32::from(number - 16) * 8),
            Gpr::from_encoding(number),
        );
    }
    let mut state = crate::GuestState::default();
    crate::x86_64::native::run(&code, &mut state);
    for number in 16_u8..32 {
        assert_eq!(
            state.x[usize::from(number - 16)],
            0x80000000 | u64::from(number)
        );
    }
    std::eprintln!("APX execution completed for R16 through R31");
}
