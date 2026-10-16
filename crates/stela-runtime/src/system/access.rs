//! Pure system-access requests and decisions, before context/backend mutation.
//! The caller owns instruction PCs, exception entry and atomic effect commitment.
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
mod tests;
