//! Canonical encoding fields shared by system-register access boundaries.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_checked_field_tuple_has_a_unique_selector() {
        let mut seen = [false; SELECTOR_COUNT];
        for op0 in 0..=OP0_MASK {
            for op1 in 0..=OP1_MASK {
                for crn in 0..=CRN_MASK {
                    for crm in 0..=CRM_MASK {
                        for op2 in 0..=OP2_MASK {
                            let selector = Encoding::new(op0, op1, crn, crm, op2).selector();
                            assert!(!std::mem::replace(&mut seen[usize::from(selector)], true));
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
