//! SIMD/FP register-offset loads and stores.
use super::super::{Register, register, register_offset::IndexExtend};
use crate::aarch64::Unsupported;

const REGISTER_OFFSET_MASK: u32 = 0x3f20_0c00;
const REGISTER_OFFSET_CLASS: u32 = 0x3c20_0800;
const SIZE_SHIFT: u32 = 30;
const OPCODE_SHIFT: u32 = 22;
const OPCODE_MASK: u32 = 3;
const Q_OPCODE_BIT: u32 = 2;
const LOAD_OPCODE_BIT: u32 = 1;
const Q_SCALE: u8 = 4;
const EXTENSION_SHIFT: u32 = 13;
const EXTENSION_MASK: u32 = 7;
const SCALED_OFFSET_BIT: u32 = 1 << 12;
const REGISTER_MASK: u32 = 31;
const BASE_SHIFT: u32 = 5;
const INDEX_SHIFT: u32 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub load: bool,
    pub bytes: u8,
    pub vector: u8,
    pub base: Register,
    pub index: Register,
    pub extend: IndexExtend,
    pub shift: u8,
}

/// None is a different class; Err is an undefined size or index extension.
pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    if word & REGISTER_OFFSET_MASK != REGISTER_OFFSET_CLASS {
        return None;
    }
    let size = (word >> SIZE_SHIFT) as u8;
    let opcode = (word >> OPCODE_SHIFT) & OPCODE_MASK;
    let scale = if opcode & Q_OPCODE_BIT != 0 {
        if size != 0 {
            return Some(Err(Unsupported));
        }
        Q_SCALE
    } else {
        size
    };
    let Some(extend) = IndexExtend::decode((word >> EXTENSION_SHIFT) & EXTENSION_MASK) else {
        return Some(Err(Unsupported));
    };
    Some(Ok(Operand {
        load: opcode & LOAD_OPCODE_BIT != 0,
        bytes: 1 << scale,
        vector: (word & REGISTER_MASK) as u8,
        base: register((word >> BASE_SHIFT) & REGISTER_MASK, true),
        index: register((word >> INDEX_SHIFT) & REGISTER_MASK, false),
        extend,
        shift: if word & SCALED_OFFSET_BIT == 0 {
            0
        } else {
            scale
        },
    }))
}

#[cfg(test)]
mod tests {
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
}
