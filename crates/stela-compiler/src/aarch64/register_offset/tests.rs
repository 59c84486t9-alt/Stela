use super::*;

fn word(size: u32, opcode: u32, option: u32, scaled: bool) -> u32 {
    (size << 30)
        | 0x38200800
        | (opcode << 22)
        | (31 << 16)
        | (option << 13)
        | (u32::from(scaled) << 12)
        | (31 << 5)
        | 31
}

#[test]
fn sizes_extensions_and_zero_sp_roles_are_explicit() {
    for size in 0..4 {
        for opcode in 0..4 {
            for option in 0..8 {
                for scaled in [false, true] {
                    let decoded = decode(word(size, opcode, option, scaled)).unwrap();
                    let valid_opcode =
                        opcode < 2 || (opcode == 2 && size < 3) || (opcode == 3 && size < 2);
                    if !valid_opcode || option & 2 == 0 {
                        assert!(decoded.is_err());
                        continue;
                    }
                    let operand = decoded.unwrap();
                    assert_eq!(operand.bytes, 1 << size);
                    assert_eq!(operand.shift, if scaled { size as u8 } else { 0 });
                    assert_eq!(operand.base, Register::Sp);
                    assert_eq!(operand.data, Register::Zero);
                    assert_eq!(operand.index, Register::Zero);
                }
            }
        }
    }
}

#[test]
fn other_memory_classes_do_not_match() {
    let original = word(3, 1, 3, false);
    for changed in [
        original ^ (1 << 26),
        original ^ (1 << 21),
        original ^ (1 << 10),
        original ^ (1 << 11),
        0xf9800000,
        0xc85f7c00,
        0xf8200400,
    ] {
        assert!(decode(changed).is_none());
    }
}
