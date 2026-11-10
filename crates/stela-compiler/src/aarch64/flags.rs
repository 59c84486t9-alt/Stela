//! NZCV condition evaluation and FlagM/FlagM2: CFINV, RMIF, SETF8/16, XAFLAG, AXFLAG.
use super::{Register, register};

pub const NZCV_N: u32 = 1 << 31;
pub const NZCV_Z: u32 = 1 << 30;
pub const NZCV_C: u32 = 1 << 29;
pub const NZCV_V: u32 = 1 << 28;
pub const NZCV_SHIFT: u32 = 28;

/// AArch64 ConditionHolds, including the unconditional AL and NV encodings.
pub fn condition_holds(condition: u8, nzcv: u32) -> bool {
    assert!(condition < 16, "decoded four-bit condition");
    let n = nzcv & NZCV_N != 0;
    let z = nzcv & NZCV_Z != 0;
    let c = nzcv & NZCV_C != 0;
    let v = nzcv & NZCV_V != 0;
    let positive = match condition >> 1 {
        0 => z,
        1 => c,
        2 => n,
        3 => v,
        4 => c && !z,
        5 => n == v,
        6 => n == v && !z,
        7 => true,
        _ => unreachable!("four-bit condition"),
    };
    positive ^ (condition & 1 != 0 && condition != 15)
}

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
    /// MRS Xt, NZCV: the flags in bits 31:28, the rest zero.
    Read {
        destination: Register,
    },
    /// MSR NZCV, Xt: bits 31:28 of Xt; the rest are RES0 and ignored.
    Write {
        source: Register,
    },
}

/// MRS Xt, NZCV and MSR NZCV, Xt, with Rt 0.
const MRS_NZCV: u32 = 0xd53b_4200;
const MSR_NZCV: u32 = 0xd51b_4200;

/// Whether `word` is MRS or MSR of NZCV. NZCV is plain PSTATE at every EL:
/// no control traps or redirects it (Arm `NZCV` accessibility), so these
/// complete inline rather than as System register accesses.
pub fn accesses_nzcv(word: u32) -> bool {
    matches!(word & !REGISTER_MASK, MRS_NZCV | MSR_NZCV)
}

/// CRm's parenthesized zero bits in CFINV/AXFLAG/XAFLAG are ignored.
/// RMIF reads Xn and SETF reads Wn; register 31 is ZR, never SP. MRS and
/// MSR of NZCV take Xt, register 31 XZR.
pub fn decode(word: u32) -> Option<Operand> {
    let rt = register(word & REGISTER_MASK, false);
    match word & !REGISTER_MASK {
        MRS_NZCV => return Some(Operand::Read { destination: rt }),
        MSR_NZCV => return Some(Operand::Write { source: rt }),
        _ => {}
    }
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
    fn nzcv_register_accesses_decode_for_every_register_and_nothing_near() {
        for rt in 0..=REGISTER_MASK {
            let expected = register(rt, false);
            assert_eq!(
                decode(MRS_NZCV | rt),
                Some(Operand::Read {
                    destination: expected
                })
            );
            assert_eq!(
                decode(MSR_NZCV | rt),
                Some(Operand::Write { source: expected })
            );
            assert!(accesses_nzcv(MRS_NZCV | rt) && accesses_nzcv(MSR_NZCV | rt));
        }
        assert_eq!(
            decode(MRS_NZCV | 31),
            Some(Operand::Read {
                destination: Register::Zero
            })
        );
        // DAIF, FPCR, FPSR, SYS and MSR (immediate) neighbors stay out.
        for word in [
            0xd53b_4220,
            0xd53b_4400,
            0xd51b_4420,
            0xd50b_4200,
            0xd503_421f,
        ] {
            assert_eq!(decode(word), None, "{word:#010x}");
            assert!(!accesses_nzcv(word), "{word:#010x}");
        }
        let system = crate::block::decode_system_mode_instruction;
        for word in [MRS_NZCV | 7, MSR_NZCV | 7] {
            assert_eq!(system(crate::GuestAddress(0x1000), word).unwrap(), None);
        }
        assert!(
            system(crate::GuestAddress(0x1000), 0xd53b_4227)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn every_condition_matches_the_architectural_truth_table() {
        // Bit k describes the condition at NZCV nibble k, independently of the
        // implementation's predicate expressions. AL and NV are unconditional.
        const TRUTH: [u16; 16] = [
            0xf0f0, 0x0f0f, 0xcccc, 0x3333, 0xff00, 0x00ff, 0xaaaa, 0x5555, 0x0c0c, 0xf3f3, 0xaa55,
            0x55aa, 0x0a05, 0xf5fa, 0xffff, 0xffff,
        ];
        for (condition, expected) in TRUTH.into_iter().enumerate() {
            for nibble in 0..16 {
                let nzcv = (nibble << NZCV_SHIFT) | ((1 << NZCV_SHIFT) - 1);
                assert_eq!(
                    condition_holds(condition as u8, nzcv),
                    expected & (1 << nibble) != 0,
                    "condition={condition}, NZCV={nibble:x}"
                );
            }
        }
    }

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
