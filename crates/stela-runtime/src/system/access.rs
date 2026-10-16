//! System-register access requests and decisions, before any effect.
pub use stela_compiler::aarch64::system::registers::Encoding;

const ZERO_REGISTER: u8 = 31;
const ESR_EXCEPTION_CLASS_SHIFT: u32 = 26;
const ESR_AARCH64_INSTRUCTION_LENGTH: u32 = 1 << 25;
const SYSTEM_ACCESS_EXCEPTION_CLASS: u8 = 0x18;
const ISS_OP0_SHIFT: u32 = 20;
const ISS_OP2_SHIFT: u32 = 17;
const ISS_OP1_SHIFT: u32 = 14;
const ISS_CRN_SHIFT: u32 = 10;
const ISS_RT_SHIFT: u32 = 5;
const ISS_CRM_SHIFT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    El0,
    El1,
    El2,
    El3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    NonSecure,
    Secure,
    Realm,
}

/// Explicit architectural inputs, independent of application or host identity.
/// Family Context types own their additional typed features and control readbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub current_el: ExceptionLevel,
    pub security: SecurityState,
    pub el2_enabled: bool,
    pub el3_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write { value: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub encoding: Encoding,
    pub kind: AccessKind,
    pub rt: u8,
}
impl Request {
    pub fn read(encoding: Encoding, rt: u8) -> Self {
        assert!(rt <= ZERO_REGISTER, "architectural five-bit Rt");
        Self {
            encoding,
            kind: AccessKind::Read,
            rt,
        }
    }
    pub fn write(encoding: Encoding, rt: u8, value: u64) -> Self {
        assert!(rt <= ZERO_REGISTER, "architectural five-bit Rt");
        Self {
            encoding,
            kind: AccessKind::Write {
                value: if rt == ZERO_REGISTER { 0 } else { value },
            },
            rt,
        }
    }
    pub fn write_value(self) -> Option<u64> {
        match self.kind {
            AccessKind::Read => None,
            AccessKind::Write { value } => Some(if self.rt == ZERO_REGISTER { 0 } else { value }),
        }
    }
    /// Exact June AArch64_SystemAccessTrapSyndrome EC0x18 field packing.
    pub fn system_access_iss(self) -> u32 {
        (u32::from(self.encoding.op0()) << ISS_OP0_SHIFT)
            | (u32::from(self.encoding.op2()) << ISS_OP2_SHIFT)
            | (u32::from(self.encoding.op1()) << ISS_OP1_SHIFT)
            | (u32::from(self.encoding.crn()) << ISS_CRN_SHIFT)
            | (u32::from(self.rt) << ISS_RT_SHIFT)
            | (u32::from(self.encoding.crm()) << ISS_CRM_SHIFT)
            | u32::from(matches!(self.kind, AccessKind::Read))
    }
    pub fn system_access_esr(self) -> u32 {
        (u32::from(SYSTEM_ACCESS_EXCEPTION_CLASS) << ESR_EXCEPTION_CLASS_SHIFT)
            | ESR_AARCH64_INSTRUCTION_LENGTH
            | self.system_access_iss()
    }
}

/// A direct architectural-state replacement, not an MMU/IRQ/device register bank.
/// Families with externally visible effects must instead request their backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateWrite {
    pub encoding: Encoding,
    pub value: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trap {
    pub target: ExceptionLevel,
    pub exception_class: u8,
}
impl Trap {
    pub const fn system_access(target: ExceptionLevel) -> Self {
        Self {
            target,
            exception_class: SYSTEM_ACCESS_EXCEPTION_CLASS,
        }
    }
}

/// Distinct architecture, platform and implementation outcomes. No effects applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<B> {
    /// This leaf does not own the requested direction/selector.
    NotHandled,
    /// The complete CPU-profile allocation owner found no allocated operation.
    Unallocated,
    Undefined,
    Trap(Trap),
    Read(u64),
    Write(StateWrite),
    BackendRequired(B),
    Unsupported(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_register_writes_are_normalized_even_for_literal_requests() {
        let encoding = Encoding::new(3, 3, 4, 2, 0);
        let constructor = Request::write(encoding, ZERO_REGISTER, u64::MAX);
        assert_eq!(constructor.write_value(), Some(0));
        let literal = Request {
            encoding,
            kind: AccessKind::Write { value: u64::MAX },
            rt: ZERO_REGISTER,
        };
        assert_eq!(literal.write_value(), Some(0));
        assert_eq!(Request::read(encoding, ZERO_REGISTER).write_value(), None);
    }

    #[test]
    fn every_register_selector_and_rt_packs_the_original_word_syndrome() {
        const MRS_BASE: u32 = 0xd5200000;
        const READ_DIRECTION_BIT: u32 = 1 << 21;
        const OP0_WORD_SHIFT: u32 = 19;
        const OP1_WORD_SHIFT: u32 = 16;
        const CRN_WORD_SHIFT: u32 = 12;
        const CRM_WORD_SHIFT: u32 = 8;
        const OP2_WORD_SHIFT: u32 = 5;
        for op0 in 2..=3 {
            for op1 in 0..=7 {
                for crn in 0..=15 {
                    for crm in 0..=15 {
                        for op2 in 0..=7 {
                            let encoding = Encoding::new(op0, op1, crn, crm, op2);
                            for rt in 0..=ZERO_REGISTER {
                                for read in [false, true] {
                                    let request = if read {
                                        Request::read(encoding, rt)
                                    } else {
                                        Request::write(encoding, rt, 0)
                                    };
                                    let word = (MRS_BASE & !READ_DIRECTION_BIT)
                                        | (u32::from(read) << 21)
                                        | (u32::from(op0) << OP0_WORD_SHIFT)
                                        | (u32::from(op1) << OP1_WORD_SHIFT)
                                        | (u32::from(crn) << CRN_WORD_SHIFT)
                                        | (u32::from(crm) << CRM_WORD_SHIFT)
                                        | (u32::from(op2) << OP2_WORD_SHIFT)
                                        | u32::from(rt);
                                    let source_iss = (((word >> 19) & 3) << 20)
                                        | (((word >> 5) & 7) << 17)
                                        | (((word >> 16) & 7) << 14)
                                        | (((word >> 12) & 15) << 10)
                                        | ((word & 31) << 5)
                                        | (((word >> 8) & 15) << 1)
                                        | ((word >> 21) & 1);
                                    assert_eq!(request.system_access_iss(), source_iss);
                                    assert_eq!(
                                        request.system_access_esr(),
                                        0x62000000 | source_iss
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
