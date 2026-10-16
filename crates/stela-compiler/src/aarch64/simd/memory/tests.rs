use super::*;

const UXTW: u32 = 2;
const LSL: u32 = 3;
const SXTW: u32 = 6;
const SXTX: u32 = 7;

fn word(size: u32, opcode: u32, option: u32, scaled: bool) -> u32 {
    REGISTER_OFFSET_CLASS
        | (size << SIZE_SHIFT)
        | (opcode << OPCODE_SHIFT)
        | (option << EXTENSION_SHIFT)
        | if scaled { SCALED_OFFSET_BIT } else { 0 }
        | (REGISTER_MASK << INDEX_SHIFT)
        | (REGISTER_MASK << BASE_SHIFT)
        | REGISTER_MASK
}

#[test]
fn all_widths_extensions_and_register_roles_are_explicit() {
    for size in 0..4 {
        for opcode in 0..4 {
            for option in 0..8 {
                for scaled in [false, true] {
                    let decoded = decode(word(size, opcode, option, scaled)).unwrap();
                    if (opcode & Q_OPCODE_BIT != 0 && size != 0)
                        || ![UXTW, LSL, SXTW, SXTX].contains(&option)
                    {
                        assert!(decoded.is_err());
                        continue;
                    }
                    let operand = decoded.unwrap();
                    let scale = if opcode & Q_OPCODE_BIT != 0 {
                        u32::from(Q_SCALE)
                    } else {
                        size
                    };
                    assert_eq!(operand.bytes, 1 << scale);
                    assert_eq!(operand.shift, if scaled { scale as u8 } else { 0 });
                    assert_eq!(operand.load, opcode & LOAD_OPCODE_BIT != 0);
                    assert_eq!(
                        operand.extend,
                        match option {
                            UXTW => IndexExtend::Uxtw,
                            LSL => IndexExtend::Lsl,
                            SXTW => IndexExtend::Sxtw,
                            SXTX => IndexExtend::Sxtx,
                            _ => unreachable!("reserved options checked above"),
                        }
                    );
                    assert_eq!(operand.vector, REGISTER_MASK as u8);
                    assert_eq!(operand.base, Register::Sp);
                    assert_eq!(operand.index, Register::Zero);
                }
            }
        }
    }
}

#[test]
fn immediate_integer_pair_and_atomic_classes_do_not_match() {
    let original = word(0, 1, LSL, false);
    for changed in [
        original ^ (1 << 26),
        original ^ (1 << 21),
        original ^ (1 << 10),
        original ^ (1 << 11),
        0x3dc0_0000,
        0xad40_0000,
        0xc85f_7c00,
    ] {
        assert!(decode(changed).is_none());
    }
}
