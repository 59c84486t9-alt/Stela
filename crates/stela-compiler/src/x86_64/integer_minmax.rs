//! FEAT_CSSC min/max through CMP and CMOV.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::aarch64::integer_minmax::{Kind, Operand, Right};
use crate::x86_64::asm::{
    Alu, Code, Cond,
    Gpr::{Rax, Rcx},
    Size,
};

pub(super) fn emit(code: &mut Code, operand: &Operand) {
    if operand.destination == Register::Zero {
        code.asm().nop();
        return;
    }
    load(code, operand.left);
    match operand.right {
        Right::Register(register) => right_operand(code, register, Width::X64, Shift::Lsl, 0),
        Right::Immediate(value) if operand.kind.signed() => {
            let immediate = i32::from(value as i8);
            if operand.width == Width::X64 && immediate < 0 {
                // Sign-extended to 64 bits.
                code.asm().mov_rm_imm32(Size::Qword, Rcx, immediate);
            } else {
                code.asm().mov_imm32(Rcx, immediate as u32);
            }
        }
        Right::Immediate(value) => code.asm().mov_imm32(Rcx, u32::from(value)),
    }
    // All flag-changing source preparation precedes CMP, including ZR loads.
    let size = Size::of(operand.width == Width::X64);
    let mut asm = code.asm();
    asm.alu(Alu::Cmp, size, Rax, Rcx);
    // A false 32-bit CMOV also clears the destination's high half.
    let replace = match operand.kind {
        Kind::SignedMinimum => Cond::G,
        Kind::SignedMaximum => Cond::L,
        Kind::UnsignedMinimum => Cond::A,
        Kind::UnsignedMaximum => Cond::B,
    };
    asm.cmov(replace, size, Rax, Rcx);
    store(code, operand.destination);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const REX_W: u8 = 0x48;
    const NOP: u8 = 0x90;
    const MOV_ECX_IMM32: u8 = 0xb9;
    const MOV_RCX_IMM32: &[u8] = &[REX_W, 0xc7, 0xc1];
    const OPCODE_ESCAPE: u8 = 0x0f;
    const MODRM_EAX_ECX: u8 = 0xc1;
    const CMOVG: u8 = 0x4f;
    const CMOVL: u8 = 0x4c;
    const CMOVA: u8 = 0x47;
    const CMOVB: u8 = 0x42;

    #[test]
    fn signed_x_immediates_sign_extend_but_unsigned_do_not() {
        for value in [0, 1, 0x7f, 0x80, 0xff] {
            for width in [Width::W32, Width::X64] {
                for kind in [
                    Kind::SignedMinimum,
                    Kind::SignedMaximum,
                    Kind::UnsignedMinimum,
                    Kind::UnsignedMaximum,
                ] {
                    let mut code = Code::new();
                    emit(
                        &mut code,
                        &Operand {
                            kind,
                            width,
                            destination: Register::X(0),
                            left: Register::X(1),
                            right: Right::Immediate(value),
                        },
                    );
                    let mut prefix = Code::new();
                    load(&mut prefix, Register::X(1));
                    let signed_negative_x = width == Width::X64 && kind.signed() && value >= 0x80;
                    let materialization = if signed_negative_x {
                        MOV_RCX_IMM32
                    } else {
                        &[MOV_ECX_IMM32]
                    };
                    assert_eq!(
                        &code[prefix.len()..prefix.len() + materialization.len()],
                        materialization
                    );
                    let immediate_start = prefix.len() + materialization.len();
                    let expected = if kind.signed() {
                        i32::from(value as i8) as u32
                    } else {
                        u32::from(value)
                    };
                    assert_eq!(
                        &code[immediate_start..immediate_start + size_of::<u32>()],
                        &expected.to_le_bytes()
                    );
                }
            }
        }
    }

    #[test]
    fn every_predicate_follows_compare_directly_at_guest_width() {
        for (kind, condition) in [
            (Kind::SignedMinimum, CMOVG),
            (Kind::SignedMaximum, CMOVL),
            (Kind::UnsignedMinimum, CMOVA),
            (Kind::UnsignedMaximum, CMOVB),
        ] {
            for width in [Width::W32, Width::X64] {
                let mut code = Code::new();
                emit(
                    &mut code,
                    &Operand {
                        kind,
                        width,
                        destination: Register::X(1),
                        left: Register::X(1),
                        right: Right::Register(Register::Zero),
                    },
                );
                let mut prefix = Code::new();
                load(&mut prefix, Register::X(1));
                right_operand(&mut prefix, Register::Zero, Width::X64, Shift::Lsl, 0);
                let expected = if width == Width::X64 {
                    vec![
                        REX_W,
                        0x39,
                        0xc8,
                        REX_W,
                        OPCODE_ESCAPE,
                        condition,
                        MODRM_EAX_ECX,
                    ]
                } else {
                    vec![0x39, 0xc8, OPCODE_ESCAPE, condition, MODRM_EAX_ECX]
                };
                let mut suffix = Code::new();
                store(&mut suffix, Register::X(1));
                assert_eq!(code, [&prefix[..], &expected[..], &suffix[..]].concat());
            }
        }
    }

    #[test]
    fn discarded_result_preserves_a_nonempty_interval() {
        let mut code = Code::new();
        emit(
            &mut code,
            &Operand {
                kind: Kind::SignedMinimum,
                width: Width::W32,
                destination: Register::Zero,
                left: Register::X(1),
                right: Right::Register(Register::X(2)),
            },
        );
        assert_eq!(code, [NOP]);
    }
}
