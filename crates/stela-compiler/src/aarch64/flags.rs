//! Scalar FlagM/FlagM2 encodings from the pinned Arm 2026-06 reference.
use super::{Register, register};

const PSTATE_MASK: u32 = 0xfffff0ff;
const CFINV: u32 = 0xd500401f;
const AXFLAG: u32 = 0xd500405f;
const XAFLAG: u32 = 0xd500403f;
const RMIF_MASK: u32 = 0xffe07c10;
const RMIF: u32 = 0xba000400;
const SETF_MASK: u32 = 0xfffffc1f;
const SETF8: u32 = 0x3a00080d;
const SETF16: u32 = 0x3a00480d;
const SOURCE_SHIFT: u32 = 5;
const REGISTER_MASK: u32 = 31;
const ROTATION_SHIFT: u32 = 15;
const ROTATION_MASK: u32 = 63;
const FLAG_MASK: u32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetWidth {
    Byte,
    Halfword,
}
impl SetWidth {
    pub(crate) fn bits(self) -> u8 {
        match self {
            Self::Byte => 8,
            Self::Halfword => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    InvertCarry,
    RotateMask {
        source: Register,
        rotation: u8,
        mask: u8,
    },
    Set {
        source: Register,
        width: SetWidth,
    },
    ArmToExternal,
    ExternalToArm,
}

/// CRm's parenthesized zero bits in CFINV/AXFLAG/XAFLAG are ignored.
/// RMIF reads Xn and SETF reads Wn; register 31 is ZR, never SP.
pub fn decode(word: u32) -> Option<Operand> {
    match word & PSTATE_MASK {
        CFINV => return Some(Operand::InvertCarry),
        AXFLAG => return Some(Operand::ArmToExternal),
        XAFLAG => return Some(Operand::ExternalToArm),
        _ => {}
    }
    let source = register((word >> SOURCE_SHIFT) & REGISTER_MASK, false);
    if word & RMIF_MASK == RMIF {
        return Some(Operand::RotateMask {
            source,
            rotation: ((word >> ROTATION_SHIFT) & ROTATION_MASK) as u8,
            mask: (word & FLAG_MASK) as u8,
        });
    }
    match word & SETF_MASK {
        SETF8 => Some(Operand::Set {
            source,
            width: SetWidth::Byte,
        }),
        SETF16 => Some(Operand::Set {
            source,
            width: SetWidth::Halfword,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignored_crm_bits_and_all_rotate_operands_decode() {
        for crm in 0..=FLAG_MASK {
            for (base, expected) in [
                (CFINV, Operand::InvertCarry),
                (AXFLAG, Operand::ArmToExternal),
                (XAFLAG, Operand::ExternalToArm),
            ] {
                assert_eq!(decode(base | (crm << 8)), Some(expected));
            }
        }
        for source in 0..=REGISTER_MASK {
            for rotation in 0..=ROTATION_MASK {
                for mask in 0..=FLAG_MASK {
                    assert_eq!(
                        decode(
                            RMIF | (source << SOURCE_SHIFT) | (rotation << ROTATION_SHIFT) | mask
                        ),
                        Some(Operand::RotateMask {
                            source: register(source, false),
                            rotation: rotation as u8,
                            mask: mask as u8,
                        })
                    );
                }
            }
            for (base, width) in [(SETF8, SetWidth::Byte), (SETF16, SetWidth::Halfword)] {
                assert_eq!(
                    decode(base | (source << SOURCE_SHIFT)),
                    Some(Operand::Set {
                        source: register(source, false),
                        width,
                    })
                );
            }
        }
    }

    #[test]
    fn fixed_bits_do_not_alias_another_flag_operation() {
        for (base, mask) in [
            (CFINV, PSTATE_MASK),
            (AXFLAG, PSTATE_MASK),
            (XAFLAG, PSTATE_MASK),
            (RMIF, RMIF_MASK),
            (SETF8, SETF_MASK),
            (SETF16, SETF_MASK),
        ] {
            for bit in 0..u32::BITS {
                if mask & (1 << bit) != 0 {
                    assert_ne!(decode(base ^ (1 << bit)), decode(base));
                }
            }
        }
    }
}
