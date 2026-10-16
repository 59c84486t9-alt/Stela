//! System register encodings for MRS, MSR and MSR (immediate).

const OP0_MASK: u8 = 0b11;
const OP1_MASK: u8 = 0b111;
const CRN_MASK: u8 = 0b1111;
const CRM_MASK: u8 = 0b1111;
const OP2_MASK: u8 = 0b111;
const OP0_SELECTOR_SHIFT: u32 = 14;
const OP1_SELECTOR_SHIFT: u32 = 11;
const CRN_SELECTOR_SHIFT: u32 = 7;
const CRM_SELECTOR_SHIFT: u32 = 3;
#[cfg(test)]
const SELECTOR_COUNT: usize = 1 << u16::BITS;

/// Checked operand fields. This identifies an encoding, not its allocation,
/// availability, access permission or architectural effect in any CPU profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encoding {
    op0: u8,
    op1: u8,
    crn: u8,
    crm: u8,
    op2: u8,
}
impl Encoding {
    pub const fn new(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> Self {
        assert!(
            op0 <= OP0_MASK
                && op1 <= OP1_MASK
                && crn <= CRN_MASK
                && crm <= CRM_MASK
                && op2 <= OP2_MASK,
            "system encoding fields must fit their architectural widths"
        );
        Self {
            op0,
            op1,
            crn,
            crm,
            op2,
        }
    }

    pub const fn op0(self) -> u8 {
        self.op0
    }
    pub const fn op1(self) -> u8 {
        self.op1
    }
    pub const fn crn(self) -> u8 {
        self.crn
    }
    pub const fn crm(self) -> u8 {
        self.crm
    }
    pub const fn op2(self) -> u8 {
        self.op2
    }

    pub const fn selector(self) -> u16 {
        ((self.op0 as u16) << OP0_SELECTOR_SHIFT)
            | ((self.op1 as u16) << OP1_SELECTOR_SHIFT)
            | ((self.crn as u16) << CRN_SELECTOR_SHIFT)
            | ((self.crm as u16) << CRM_SELECTOR_SHIFT)
            | self.op2 as u16
    }
}

/// EL1 translation-control register encodings.
pub const SCTLR_EL1: Encoding = Encoding::new(3, 0, 1, 0, 0);
pub const TCR_EL1: Encoding = Encoding::new(3, 0, 2, 0, 2);
pub const TTBR0_EL1: Encoding = Encoding::new(3, 0, 2, 0, 0);
pub const TTBR1_EL1: Encoding = Encoding::new(3, 0, 2, 0, 1);
pub const MAIR_EL1: Encoding = Encoding::new(3, 0, 10, 2, 0);

pub fn is_translation_control(encoding: Encoding) -> bool {
    [SCTLR_EL1, TCR_EL1, TTBR0_EL1, TTBR1_EL1, MAIR_EL1].contains(&encoding)
}

const REGISTER_INSTRUCTION_MASK: u32 = 0xfff0_0000;
const MRS_REGISTER_INSTRUCTION: u32 = 0xd530_0000;
const MSR_REGISTER_INSTRUCTION: u32 = 0xd510_0000;
const WORD_OP0_LOW_SHIFT: u32 = 19;
const WORD_OP1_SHIFT: u32 = 16;
const WORD_CRN_SHIFT: u32 = 12;
const WORD_CRM_SHIFT: u32 = 8;
const WORD_OP2_SHIFT: u32 = 5;
const WORD_REGISTER_MASK: u32 = 0b1_1111;
const REGISTER_OP0_HIGH_BIT: u8 = 0b10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterAccess {
    direction: Direction,
    encoding: Encoding,
    rt: u8,
}

impl RegisterAccess {
    pub const fn direction(self) -> Direction {
        self.direction
    }

    pub const fn encoding(self) -> Encoding {
        self.encoding
    }

    pub const fn rt(self) -> u8 {
        self.rt
    }
}

/// Structure only: register allocation, feature gates, controls and effects are
/// evaluated by the authoritative runtime. Rt31 denotes XZR, never SP.
pub fn decode(word: u32) -> Option<RegisterAccess> {
    let direction = match word & REGISTER_INSTRUCTION_MASK {
        MRS_REGISTER_INSTRUCTION => Direction::Read,
        MSR_REGISTER_INSTRUCTION => Direction::Write,
        _ => return None,
    };
    let encoding = Encoding::new(
        REGISTER_OP0_HIGH_BIT | ((word >> WORD_OP0_LOW_SHIFT) & 1) as u8,
        ((word >> WORD_OP1_SHIFT) & u32::from(OP1_MASK)) as u8,
        ((word >> WORD_CRN_SHIFT) & u32::from(CRN_MASK)) as u8,
        ((word >> WORD_CRM_SHIFT) & u32::from(CRM_MASK)) as u8,
        ((word >> WORD_OP2_SHIFT) & u32::from(OP2_MASK)) as u8,
    );
    Some(RegisterAccess {
        direction,
        encoding,
        rt: (word & WORD_REGISTER_MASK) as u8,
    })
}

const PSTATE_IMMEDIATE_MASK: u32 = 0xfff8_f01f;
const PSTATE_IMMEDIATE_CLASS: u32 = 0xd500_401f;
const PSTATE_OP1_SHIFT: u32 = 16;
const PSTATE_CRM_SHIFT: u32 = 8;
const PSTATE_OP2_SHIFT: u32 = 5;
const PSTATE_IMMEDIATE_OP0: u8 = 0;
const PSTATE_IMMEDIATE_CRN: u8 = 4;
const FLAGS_ALIAS_OP1: u8 = 0;
const LAST_FLAGS_ALIAS_OP2: u8 = 2;

/// Preserve exact CRm; high bits are ignored only by specified field semantics.
/// Rt31 is fixed encoding here, not a read of XZR as the immediate operand.
pub fn decode_pstate_immediate(word: u32) -> Option<Encoding> {
    if word & PSTATE_IMMEDIATE_MASK != PSTATE_IMMEDIATE_CLASS {
        return None;
    }
    let op1 = ((word >> PSTATE_OP1_SHIFT) & u32::from(OP1_MASK)) as u8;
    let op2 = ((word >> PSTATE_OP2_SHIFT) & u32::from(OP2_MASK)) as u8;
    if op1 == FLAGS_ALIAS_OP1 && op2 <= LAST_FLAGS_ALIAS_OP2 {
        return None;
    }
    Some(Encoding::new(
        PSTATE_IMMEDIATE_OP0,
        op1,
        PSTATE_IMMEDIATE_CRN,
        ((word >> PSTATE_CRM_SHIFT) & u32::from(CRM_MASK)) as u8,
        op2,
    ))
}

#[cfg(test)]
mod tests;
