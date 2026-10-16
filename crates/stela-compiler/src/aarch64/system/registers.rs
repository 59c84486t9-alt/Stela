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

/// Timer register selectors; availability and access are decided at run time.
pub const CNTFRQ_EL0: Encoding = Encoding::new(3, 3, 14, 0, 0);
pub const CNTPCT_EL0: Encoding = Encoding::new(3, 3, 14, 0, 1);
pub const CNTVCT_EL0: Encoding = Encoding::new(3, 3, 14, 0, 2);

#[cfg(test)]
mod tests {
    use super::*;

    mod pstate_immediate {
        use super::*;

        const REGISTER_WRITE_NZCV: u32 = 0xd51b_4200;
        const REGISTER_READ_NZCV: u32 = 0xd53b_4200;
        const NOP: u32 = 0xd503_201f;
        const SYS: u32 = 0xd508_0000;
        const IMMEDIATE_OPERAND_MAX: u8 = 15;
        const SPSEL_SELECTOR: (u8, u8) = (0, 5);
        const DAIF_SET_SELECTOR: (u8, u8) = (3, 6);
        const DAIF_CLEAR_SELECTOR: (u8, u8) = (3, 7);

        #[test]
        fn all_base_immediate_operands_preserve_the_original_fields() {
            for (op1, op2) in [SPSEL_SELECTOR, DAIF_SET_SELECTOR, DAIF_CLEAR_SELECTOR] {
                for operand in 0..=IMMEDIATE_OPERAND_MAX {
                    let word = PSTATE_IMMEDIATE_CLASS
                        | (u32::from(op1) << PSTATE_OP1_SHIFT)
                        | (u32::from(operand) << PSTATE_CRM_SHIFT)
                        | (u32::from(op2) << PSTATE_OP2_SHIFT);
                    assert_eq!(
                        decode_pstate_immediate(word),
                        Some(Encoding::new(
                            PSTATE_IMMEDIATE_OP0,
                            op1,
                            PSTATE_IMMEDIATE_CRN,
                            operand,
                            op2,
                        ))
                    );
                    assert_eq!(decode_pstate_immediate(word ^ 1), None);
                    assert_eq!(
                        decode_pstate_immediate(word ^ (1 << PSTATE_CRN_TEST_SHIFT)),
                        None
                    );
                }
            }
        }

        const PSTATE_CRN_TEST_SHIFT: u32 = 12;

        #[test]
        fn delegated_flags_aliases_and_other_system_classes_miss() {
            for op2 in 0..=LAST_FLAGS_ALIAS_OP2 {
                for operand in 0..=IMMEDIATE_OPERAND_MAX {
                    let word = PSTATE_IMMEDIATE_CLASS
                        | (u32::from(operand) << PSTATE_CRM_SHIFT)
                        | (u32::from(op2) << PSTATE_OP2_SHIFT);
                    assert_eq!(decode_pstate_immediate(word), None);
                }
            }
            for word in [NOP, REGISTER_WRITE_NZCV, REGISTER_READ_NZCV, SYS] {
                assert_eq!(decode_pstate_immediate(word), None);
            }
        }
    }
    mod register_access {
        use super::*;

        const MRS_NZCV: u32 = 0xd53b_4200;
        const MSR_NZCV: u32 = 0xd51b_4200;
        const SYS: u32 = 0xd508_0000;
        const SYSL: u32 = 0xd528_0000;
        const MSR_IMMEDIATE: u32 = 0xd503_40df;
        const ISB: u32 = 0xd503_3fdf;
        const NOP: u32 = 0xd503_201f;

        #[test]
        fn every_structural_register_operand_round_trips_exactly() {
            for (base, direction) in [
                (MRS_REGISTER_INSTRUCTION, Direction::Read),
                (MSR_REGISTER_INSTRUCTION, Direction::Write),
            ] {
                for op0_low in 0..=1 {
                    for op1 in 0..=u32::from(OP1_MASK) {
                        for crn in 0..=u32::from(CRN_MASK) {
                            for crm in 0..=u32::from(CRM_MASK) {
                                for op2 in 0..=u32::from(OP2_MASK) {
                                    for rt in 0..=WORD_REGISTER_MASK {
                                        let word = base
                                            | (op0_low << WORD_OP0_LOW_SHIFT)
                                            | (op1 << WORD_OP1_SHIFT)
                                            | (crn << WORD_CRN_SHIFT)
                                            | (crm << WORD_CRM_SHIFT)
                                            | (op2 << WORD_OP2_SHIFT)
                                            | rt;
                                        let access = decode(word).unwrap();
                                        assert_eq!(access.direction(), direction);
                                        assert_eq!(access.rt(), rt as u8);
                                        assert_eq!(
                                            access.encoding(),
                                            Encoding::new(
                                                REGISTER_OP0_HIGH_BIT | op0_low as u8,
                                                op1 as u8,
                                                crn as u8,
                                                crm as u8,
                                                op2 as u8,
                                            )
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[test]
        fn fixed_class_bits_and_neighbor_families_are_not_guessed() {
            for word in [SYS, SYSL, MSR_IMMEDIATE, ISB, NOP, u32::MAX] {
                assert!(decode(word).is_none());
            }
            for bit in 0..u32::BITS {
                let mask = 1 << bit;
                if mask & REGISTER_INSTRUCTION_MASK != 0 {
                    for word in [MRS_NZCV, MSR_NZCV] {
                        let changed = word ^ mask;
                        if !matches!(
                            changed & REGISTER_INSTRUCTION_MASK,
                            MRS_REGISTER_INSTRUCTION | MSR_REGISTER_INSTRUCTION
                        ) {
                            assert!(decode(changed).is_none());
                        }
                    }
                }
            }
        }

        #[test]
        fn zero_register_keeps_its_encoded_role_in_both_directions() {
            for word in [MRS_NZCV, MSR_NZCV] {
                let access = decode(word | WORD_REGISTER_MASK).unwrap();
                assert_eq!(access.rt(), WORD_REGISTER_MASK as u8);
                assert_eq!(access.encoding(), Encoding::new(3, 3, 4, 2, 0));
            }
        }
    }

    #[test]
    fn every_checked_field_tuple_has_a_unique_selector() {
        let mut seen = [false; SELECTOR_COUNT];
        for op0 in 0..=OP0_MASK {
            for op1 in 0..=OP1_MASK {
                for crn in 0..=CRN_MASK {
                    for crm in 0..=CRM_MASK {
                        for op2 in 0..=OP2_MASK {
                            let selector = Encoding::new(op0, op1, crn, crm, op2).selector();
                            assert!(!core::mem::replace(&mut seen[usize::from(selector)], true));
                        }
                    }
                }
            }
        }
        assert!(seen.into_iter().all(|present| present));
    }

    #[test]
    fn overwide_fields_fail_instead_of_aliasing_another_encoding() {
        for fields in [
            (4, 0, 0, 0, 0),
            (0, 8, 0, 0, 0),
            (0, 0, 16, 0, 0),
            (0, 0, 0, 16, 0),
            (0, 0, 0, 0, 8),
        ] {
            assert!(
                std::panic::catch_unwind(|| Encoding::new(
                    fields.0, fields.1, fields.2, fields.3, fields.4
                ))
                .is_err()
            );
        }
    }
}
