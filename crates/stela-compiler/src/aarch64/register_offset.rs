//! Scalar integer load/store register-offset addressing.
//!
//! Arm instruction reference: https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85
//! The ordinary-RAM profile disables tags/PAC; base SP alignment is checked.
use super::{MemoryTransfer, Register, Width, register};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexExtend {
    Uxtw,
    Lsl,
    Sxtw,
    Sxtx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub transfer: MemoryTransfer,
    pub bytes: u8,
    pub data: Register,
    pub base: Register,
    pub index: Register,
    pub extend: IndexExtend,
    pub shift: u8,
}

/// None means another encoding class; Err means a reserved/unsupported form
/// within the scalar register-offset class. SIMD and atomics never match.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if word & 0x3f200c00 != 0x38200800 {
        return None;
    }
    let size = word >> 30;
    let transfer = match (word >> 22) & 3 {
        0 => MemoryTransfer::Store,
        1 => MemoryTransfer::Load {
            signed: false,
            width: if size == 3 { Width::X64 } else { Width::W32 },
        },
        2 if size < 3 => MemoryTransfer::Load {
            signed: true,
            width: Width::X64,
        },
        3 if size < 2 => MemoryTransfer::Load {
            signed: true,
            width: Width::W32,
        },
        _ => return Some(Err(())), // PRFM and reserved signed sizes
    };
    let extend = match (word >> 13) & 7 {
        2 => IndexExtend::Uxtw,
        3 => IndexExtend::Lsl,
        6 => IndexExtend::Sxtw,
        7 => IndexExtend::Sxtx,
        _ => return Some(Err(())), // sub-word index extensions are undefined
    };
    Some(Ok(Operand {
        transfer,
        bytes: 1 << size,
        data: register(word & 31, false),
        base: register((word >> 5) & 31, true),
        index: register((word >> 16) & 31, false),
        extend,
        shift: if word & (1 << 12) == 0 { 0 } else { size as u8 },
    }))
}

#[cfg(test)]
mod tests {
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
}
