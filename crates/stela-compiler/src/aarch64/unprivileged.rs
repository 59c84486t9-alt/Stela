//! Unprivileged loads and stores (LDTR*, STTR*). Native code supports EL0 on
//! directly mapped RAM only.
use super::{MemoryTransfer, Register, Width, register};
use crate::aarch64::Unsupported;

const CLASS_MASK: u32 = 0x3f20_0c00;
const UNPRIVILEGED_CLASS: u32 = 0x3800_0800;
const SIZE_SHIFT: u32 = 30;
const OPCODE_SHIFT: u32 = 22;
const OPCODE_MASK: u32 = 3;
const STORE_OPCODE: u32 = 0;
const UNSIGNED_LOAD_OPCODE: u32 = 1;
const SIGNED_LOAD_X_OPCODE: u32 = 2;
const SIGNED_LOAD_W_OPCODE: u32 = 3;
const DOUBLEWORD_SIZE: u32 = 3;
const WORD_SIZE: u32 = 2;
const IMMEDIATE_SHIFT: u32 = 12;
const IMMEDIATE_BITS: u32 = 9;
const IMMEDIATE_MASK: u32 = (1 << IMMEDIATE_BITS) - 1;
const SIGN_EXTENSION_SHIFT: u32 = i32::BITS - IMMEDIATE_BITS;
const BASE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub transfer: MemoryTransfer,
    pub bytes: u8,
    pub data: Register,
    pub base: Register,
    pub displacement: i32,
}

/// None denotes another encoding class; Err denotes a reserved size/opcode.
/// This class has neither writeback nor register-overlap restrictions.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    if word & CLASS_MASK != UNPRIVILEGED_CLASS {
        return None;
    }
    let size = word >> SIZE_SHIFT;
    let transfer = match (word >> OPCODE_SHIFT) & OPCODE_MASK {
        STORE_OPCODE => MemoryTransfer::Store,
        UNSIGNED_LOAD_OPCODE => MemoryTransfer::Load {
            signed: false,
            width: if size == DOUBLEWORD_SIZE {
                Width::X64
            } else {
                Width::W32
            },
        },
        SIGNED_LOAD_X_OPCODE if size < DOUBLEWORD_SIZE => MemoryTransfer::Load {
            signed: true,
            width: Width::X64,
        },
        SIGNED_LOAD_W_OPCODE if size < WORD_SIZE => MemoryTransfer::Load {
            signed: true,
            width: Width::W32,
        },
        _ => return Some(Err(Unsupported)),
    };
    let immediate = ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as i32;
    Some(Ok(Operand {
        transfer,
        bytes: 1 << size,
        data: register(word & REGISTER_MASK, false),
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        displacement: (immediate << SIGN_EXTENSION_SHIFT) >> SIGN_EXTENSION_SHIFT,
    }))
}

#[cfg(test)]
mod tests {
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
}
