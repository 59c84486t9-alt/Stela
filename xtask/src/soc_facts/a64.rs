//! The few A64 encodings the SoC fact extractor follows, decoded from the Arm
//! A64 reference's encoding tables (`ISA_A64_xml_A_profile-2026-06`): the
//! address, constant and pointer arithmetic SPTM uses to reach a CPU
//! implementation block, its loads and stores, calls, and System register
//! accesses. Every other word is [`Insn::Other`].

/// The zero register or stack pointer number.
pub const ZR: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveKind {
    /// MOVN: the inverted shifted immediate.
    Inverted,
    /// MOVZ: the shifted immediate.
    Zeroed,
    /// MOVK: the immediate replaces one 16-bit field.
    Kept,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Select {
    Csel,
    Csinc,
    Csinv,
    Csneg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logical {
    And,
    Orr,
    Eor,
    Ands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insn {
    /// ADRP: `rd` = the 4 KiB page at `page`.
    Adrp {
        rd: u8,
        page: u64,
    },
    /// ADD or SUB (immediate), `imm` already negated for SUB.
    AddImmediate {
        rd: u8,
        rn: u8,
        imm: i64,
        wide: bool,
    },
    /// ADD (shifted register) with LSL #`shift`.
    AddRegister {
        rd: u8,
        rn: u8,
        rm: u8,
        shift: u8,
    },
    /// MOVN, MOVZ or MOVK of `imm16` at bit `16 * hw`.
    Move {
        rd: u8,
        kind: MoveKind,
        imm16: u16,
        hw: u8,
        wide: bool,
    },
    /// A logical operation with a bitmask immediate.
    LogicalImmediate {
        rd: u8,
        rn: u8,
        op: Logical,
        imm: u64,
        wide: bool,
    },
    /// A logical operation with an unshifted register, `inverted` for
    /// BIC, ORN, EON and BICS.
    LogicalRegister {
        rd: u8,
        rn: u8,
        rm: u8,
        op: Logical,
        inverted: bool,
        shifted: bool,
    },
    /// LDR or LDRS* (immediate, unsigned or unscaled offset) of `bytes`.
    Load {
        rt: u8,
        rn: u8,
        offset: i64,
        bytes: u8,
    },
    /// STR (immediate, unsigned or unscaled offset) of `bytes`.
    Store {
        rt: u8,
        rn: u8,
        offset: i64,
        bytes: u8,
    },
    /// CSEL, CSINC, CSINV or CSNEG.
    Select {
        rd: u8,
        rn: u8,
        rm: u8,
        op: Select,
    },
    Call {
        target: u64,
    },
    /// MRS (`read`) or MSR (register) with the full op0..op2 encoding.
    System {
        read: bool,
        op0: u8,
        op1: u8,
        crn: u8,
        crm: u8,
        op2: u8,
        rt: u8,
    },
    /// SYS (`read` false) or SYSL.
    SystemInstruction {
        read: bool,
        op1: u8,
        crn: u8,
        crm: u8,
        op2: u8,
        rt: u8,
    },
    Other,
}

fn field(word: u32, low: u32, bits: u32) -> u32 {
    word >> low & ((1 << bits) - 1)
}

fn register(word: u32, low: u32) -> u8 {
    field(word, low, 5) as u8
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// Arm `DecodeBitMasks` for a logical immediate (`immediate` true), the
/// `wmask` element replicated across the register.
pub fn bit_mask(n: u32, imms: u32, immr: u32, width: u32) -> Option<u64> {
    let combined = n << 6 | (!imms & 0x3f);
    let length = 31 - combined.leading_zeros();
    if combined == 0 || length < 1 {
        return None;
    }
    let size = 1u32 << length;
    let levels = size - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let ones = if s + 1 == 64 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };
    let element_mask = if size == 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    };
    let element = if r == 0 {
        ones
    } else {
        (ones >> r | ones << (size - r)) & element_mask
    };
    let mut value = 0u64;
    let mut position = 0;
    while position < width {
        value |= element << position;
        position += size;
    }
    Some(if width == 64 {
        value
    } else {
        value & u64::from(u32::MAX)
    })
}

/// Decode `word` at `pc`.
pub fn decode(pc: u64, word: u32) -> Insn {
    let wide = word >> 31 == 1;
    let rd = register(word, 0);
    let rn = register(word, 5);
    let rm = register(word, 16);
    if word & 0x9f00_0000 == 0x9000_0000 {
        let immediate = u64::from(field(word, 5, 19) << 2 | field(word, 29, 2));
        let page = (pc & !0xfff).wrapping_add_signed(sign_extend(immediate, 21) << 12);
        return Insn::Adrp { rd, page };
    }
    if word & 0x1f80_0000 == 0x1100_0000 && field(word, 29, 1) == 0 {
        let imm = i64::from(field(word, 10, 12)) << (12 * field(word, 22, 1));
        let subtract = field(word, 30, 1) == 1;
        return Insn::AddImmediate {
            rd,
            rn,
            imm: if subtract { -imm } else { imm },
            wide,
        };
    }
    if word & 0x7f20_0000 == 0x0b00_0000 && field(word, 22, 2) == 0 {
        return Insn::AddRegister {
            rd,
            rn,
            rm,
            shift: field(word, 10, 6) as u8,
        };
    }
    if word & 0x1f80_0000 == 0x1280_0000 {
        let kind = match field(word, 29, 2) {
            0 => MoveKind::Inverted,
            2 => MoveKind::Zeroed,
            3 => MoveKind::Kept,
            _ => return Insn::Other,
        };
        return Insn::Move {
            rd,
            kind,
            imm16: field(word, 5, 16) as u16,
            hw: field(word, 21, 2) as u8,
            wide,
        };
    }
    let logical = |opc| match opc {
        0 => Logical::And,
        1 => Logical::Orr,
        2 => Logical::Eor,
        _ => Logical::Ands,
    };
    if word & 0x1f80_0000 == 0x1200_0000 {
        let width = if wide { 64 } else { 32 };
        return bit_mask(
            field(word, 22, 1),
            field(word, 10, 6),
            field(word, 16, 6),
            width,
        )
        .map_or(Insn::Other, |imm| Insn::LogicalImmediate {
            rd,
            rn,
            op: logical(field(word, 29, 2)),
            imm,
            wide,
        });
    }
    if word & 0x1f00_0000 == 0x0a00_0000 {
        return Insn::LogicalRegister {
            rd,
            rn,
            rm,
            op: logical(field(word, 29, 2)),
            inverted: field(word, 21, 1) == 1,
            shifted: field(word, 10, 6) != 0,
        };
    }
    // Load/store register (unsigned immediate), general registers.
    if word & 0x3b00_0000 == 0x3900_0000 {
        let size = field(word, 30, 2);
        let offset = i64::from(field(word, 10, 12)) << size;
        return transfer(word, size, rn, offset);
    }
    // Load/store register (unscaled immediate), general registers.
    if word & 0x3b20_0c00 == 0x3800_0000 {
        let offset = sign_extend(u64::from(field(word, 12, 9)), 9);
        return transfer(word, field(word, 30, 2), rn, offset);
    }
    if word & 0x1fe0_0800 == 0x1a80_0000 {
        let op = match (field(word, 30, 1), field(word, 10, 1)) {
            (0, 0) => Select::Csel,
            (0, _) => Select::Csinc,
            (_, 0) => Select::Csinv,
            _ => Select::Csneg,
        };
        return Insn::Select { rd, rn, rm, op };
    }
    if word & 0xfc00_0000 == 0x9400_0000 {
        let target = pc.wrapping_add_signed(sign_extend(u64::from(field(word, 0, 26)), 26) << 2);
        return Insn::Call { target };
    }
    if word & 0xffd0_0000 == 0xd510_0000 {
        return Insn::System {
            read: field(word, 21, 1) == 1,
            op0: 2 + field(word, 19, 1) as u8,
            op1: field(word, 16, 3) as u8,
            crn: field(word, 12, 4) as u8,
            crm: field(word, 8, 4) as u8,
            op2: field(word, 5, 3) as u8,
            rt: rd,
        };
    }
    if word & 0xffd8_0000 == 0xd508_0000 {
        return Insn::SystemInstruction {
            read: field(word, 21, 1) == 1,
            op1: field(word, 16, 3) as u8,
            crn: field(word, 12, 4) as u8,
            crm: field(word, 8, 4) as u8,
            op2: field(word, 5, 3) as u8,
            rt: rd,
        };
    }
    Insn::Other
}

fn transfer(word: u32, size: u32, rn: u8, offset: i64) -> Insn {
    let rt = register(word, 0);
    let bytes = 1u8 << size;
    match field(word, 22, 2) {
        0 => Insn::Store {
            rt,
            rn,
            offset,
            bytes,
        },
        // LDR, or LDRS* (opc 2 with size 3 is PRFM, not a load).
        1 => Insn::Load {
            rt,
            rn,
            offset,
            bytes,
        },
        2 if size != 3 => Insn::Load {
            rt,
            rn,
            offset,
            bytes,
        },
        3 if size < 2 => Insn::Load {
            rt,
            rn,
            offset,
            bytes,
        },
        _ => Insn::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_t8112_lockdown_words() {
        // The words of SPTM 26A434 (T8112) `__text+0x1b0d8..0x1b144`, as
        // llvm-objdump prints them.
        // ldr x10, [x20, #0x14c8]
        assert_eq!(
            decode(0, 0xf94a668a),
            Insn::Load {
                rt: 10,
                rn: 20,
                offset: 0x14c8,
                bytes: 8
            }
        );
        // orr x11, x11, #0xffbfffffffffffff
        assert_eq!(
            decode(0, 0xb249f96b),
            Insn::LogicalImmediate {
                rd: 11,
                rn: 11,
                op: Logical::Orr,
                imm: 0xffbf_ffff_ffff_ffff,
                wide: true
            }
        );
        // str x11, [x10, #0x5008]
        assert_eq!(
            decode(0, 0xf928054b),
            Insn::Store {
                rt: 11,
                rn: 10,
                offset: 0x5008,
                bytes: 8
            }
        );
        // mov x9, #-0xa0000000000001 (MOVN x9, #0xa0, lsl #48)
        assert_eq!(
            decode(0, 0x92e01409),
            Insn::Move {
                rd: 9,
                kind: MoveKind::Inverted,
                imm16: 0xa0,
                hw: 3,
                wide: true
            }
        );
        // add x8, x8, #0x9, lsl #12
        assert_eq!(
            decode(0, 0x91402508),
            Insn::AddImmediate {
                rd: 8,
                rn: 8,
                imm: 0x9000,
                wide: true
            }
        );
    }

    #[test]
    fn decodes_pages_calls_selects_and_system_accesses() {
        // adrp x1, +0x1000 from 0x4010
        assert_eq!(
            decode(0x4010, 0xb0000001),
            Insn::Adrp {
                rd: 1,
                page: 0x5000
            }
        );
        // bl -4
        assert_eq!(decode(0x1000, 0x97ffffff), Insn::Call { target: 0xffc });
        // csinv x13, x13, xzr, eq
        assert_eq!(
            decode(0, 0xda9f01ad),
            Insn::Select {
                rd: 13,
                rn: 13,
                rm: ZR,
                op: Select::Csinv
            }
        );
        // msr S3_4_C15_C0_5, x8
        assert_eq!(
            decode(0, 0xd51cf0a8),
            Insn::System {
                read: false,
                op0: 3,
                op1: 4,
                crn: 15,
                crm: 0,
                op2: 5,
                rt: 8
            }
        );
        // mrs x8, MPIDR_EL1 (S3_0_C0_C0_5)
        assert_eq!(
            decode(0, 0xd53800a8),
            Insn::System {
                read: true,
                op0: 3,
                op1: 0,
                crn: 0,
                crm: 0,
                op2: 5,
                rt: 8
            }
        );
        // ldr xzr, [x14, #0x5008]
        assert_eq!(
            decode(0, 0xf96805df),
            Insn::Load {
                rt: ZR,
                rn: 14,
                offset: 0x5008,
                bytes: 8
            }
        );
    }

    #[test]
    fn bit_masks_follow_decode_bit_masks() {
        // orr x11, x11, #0x1: N 1, immr 0, imms 0.
        assert_eq!(bit_mask(1, 0, 0, 64), Some(1));
        // 0x5555...: N 0, immr 0, imms 0b111100.
        assert_eq!(bit_mask(0, 0b11_1100, 0, 64), Some(0x5555_5555_5555_5555));
        // All ones is reserved.
        assert_eq!(bit_mask(1, 0b11_1111, 0, 64), None);
        // A 32-bit element: 0xffff0000.
        assert_eq!(bit_mask(0, 0b00_1111, 16, 32), Some(0xffff_0000));
    }
}
