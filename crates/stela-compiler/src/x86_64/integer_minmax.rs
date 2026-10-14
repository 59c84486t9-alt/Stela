//! Scalar min/max selection without guest condition-flag changes.
use super::{Register, Shift, Width, load, right_operand, store};
use crate::aarch64::integer_minmax::{Kind, Operand, Right};

const REX_W: u8 = 0x48;
const NOP: u8 = 0x90;
const MOV_ECX_IMM32: u8 = 0xb9; // MOV ECX,imm32
const MOV_RCX_IMM32: &[u8] = &[REX_W, 0xc7, 0xc1];
const CMP_EAX_ECX: &[u8] = &[0x39, 0xc8];
const OPCODE_ESCAPE: u8 = 0x0f;
const MODRM_EAX_ECX: u8 = 0xc1;
const CMOVG: u8 = 0x4f;
const CMOVL: u8 = 0x4c;
const CMOVA: u8 = 0x47;
const CMOVB: u8 = 0x42;

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    if operand.destination == Register::Zero {
        code.push(NOP);
        return;
    }
    load(code, operand.left);
    match operand.right {
        Right::Register(register) => right_operand(code, register, Width::X64, Shift::Lsl, 0),
        Right::Immediate(value) => {
            let immediate = if operand.kind.signed() {
                i32::from(value as i8) as u32
            } else {
                u32::from(value)
            };
            if operand.width == Width::X64 && operand.kind.signed() && (value as i8) < 0 {
                code.extend(MOV_RCX_IMM32);
            } else {
                code.push(MOV_ECX_IMM32);
            }
            code.extend(immediate.to_le_bytes());
        }
    }
    // All flag-changing source preparation precedes CMP, including ZR loads.
    if operand.width == Width::X64 {
        code.push(REX_W);
    }
    code.extend(CMP_EAX_ECX);
    if operand.width == Width::X64 {
        code.push(REX_W);
    }
    // A false 32-bit CMOV also clears the destination's high half.
    code.extend([
        OPCODE_ESCAPE,
        match operand.kind {
            Kind::SignedMinimum => CMOVG,
            Kind::SignedMaximum => CMOVL,
            Kind::UnsignedMinimum => CMOVA,
            Kind::UnsignedMaximum => CMOVB,
        },
        MODRM_EAX_ECX,
    ]);
    store(code, operand.destination);
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    let mut code = Vec::new();
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
                    let mut prefix = Vec::new();
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
                let mut code = Vec::new();
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
                let mut prefix = Vec::new();
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
                let mut suffix = Vec::new();
                store(&mut suffix, Register::X(1));
                assert_eq!(code, [prefix, expected, suffix].concat());
            }
        }
    }

    #[test]
    fn discarded_result_preserves_a_nonempty_interval() {
        let mut code = Vec::new();
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
