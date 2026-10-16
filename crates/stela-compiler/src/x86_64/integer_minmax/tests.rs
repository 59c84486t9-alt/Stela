use super::*;
use alloc::vec;
use alloc::vec::Vec;

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
