use super::*;

fn word(size: u32, opcode: u32, data: u32, base: u32, immediate: u32) -> u32 {
    UNPRIVILEGED_CLASS
        | (size << SIZE_SHIFT)
        | (opcode << OPCODE_SHIFT)
        | (immediate << IMMEDIATE_SHIFT)
        | (base << BASE_SHIFT)
        | data
}

#[test]
fn all_thirteen_forms_and_reserved_sizes_are_explicit() {
    let mut allocated = 0;
    for size in 0..=DOUBLEWORD_SIZE {
        for opcode in 0..=OPCODE_MASK {
            let operand = decode(word(size, opcode, 0, 1, 0)).unwrap();
            let expected = match (size, opcode) {
                (_, STORE_OPCODE) => MemoryTransfer::Store,
                (DOUBLEWORD_SIZE, UNSIGNED_LOAD_OPCODE) => MemoryTransfer::Load {
                    signed: false,
                    width: Width::X64,
                },
                (_, UNSIGNED_LOAD_OPCODE) => MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                (0..=WORD_SIZE, SIGNED_LOAD_X_OPCODE) => MemoryTransfer::Load {
                    signed: true,
                    width: Width::X64,
                },
                (size, SIGNED_LOAD_W_OPCODE) if size < WORD_SIZE => MemoryTransfer::Load {
                    signed: true,
                    width: Width::W32,
                },
                _ => {
                    assert!(operand.is_err());
                    continue;
                }
            };
            let operand = operand.unwrap();
            assert_eq!(operand.transfer, expected);
            assert_eq!(operand.bytes, 1 << size);
            allocated += 1;
        }
    }
    assert_eq!(allocated, 13);
}

#[test]
fn registers_include_zero_sp_and_all_aliases_without_writeback() {
    for data in 0..=REGISTER_MASK {
        for base in 0..=REGISTER_MASK {
            let operand = decode(word(WORD_SIZE, UNSIGNED_LOAD_OPCODE, data, base, 0))
                .unwrap()
                .unwrap();
            assert_eq!(operand.data, register(data, false));
            assert_eq!(operand.base, register(base, true));
        }
    }
    for immediate in 0..=IMMEDIATE_MASK {
        let operand = decode(word(
            WORD_SIZE,
            UNSIGNED_LOAD_OPCODE,
            REGISTER_MASK,
            REGISTER_MASK,
            immediate,
        ))
        .unwrap()
        .unwrap();
        let expected = if immediate < (1 << (IMMEDIATE_BITS - 1)) {
            immediate as i32
        } else {
            immediate as i32 - (1 << IMMEDIATE_BITS)
        };
        assert_eq!(operand.displacement, expected);
        assert_eq!(operand.data, Register::Zero);
        assert_eq!(operand.base, Register::Sp);
    }
}

#[test]
fn adjacent_memory_classes_are_not_claimed() {
    let original = word(DOUBLEWORD_SIZE, UNSIGNED_LOAD_OPCODE, 0, 1, 0);
    for bit in [10, 11, 21, 24, 25, 26, 27, 28, 29] {
        assert!(decode(original ^ (1 << bit)).is_none());
    }
    // Unscaled, pre/post-indexed, unsigned, register-offset and atomic.
    for neighbor in [
        0xf840_0000,
        0xf840_0400,
        0xf840_0c00,
        0xf940_0000,
        0xf860_6800,
        0xc85f_7c00,
    ] {
        assert!(decode(neighbor).is_none());
    }
}
