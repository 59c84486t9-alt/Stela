//! Optional EL2/EL3 register banks.
use super::{El1Registers, StateError};
use crate::system::{
    access::{ExceptionLevel, SecurityState},
    identification::Register,
    identification_snapshot::{Snapshot, Unsupported as IdentificationUnsupported},
    profile::EntryProfile,
};
use alloc::sync::Arc;

const ID_FIELD_MASK: u64 = 0xf;
const EL0_SHIFT: u32 = 0;
const EL1_SHIFT: u32 = 4;
const EL2_SHIFT: u32 = 8;
const EL3_SHIFT: u32 = 12;
const SEL2_SHIFT: u32 = 36;
const RME_SHIFT: u32 = 52;
const NV_SHIFT: u32 = 24;
const NV_FRAC_SHIFT: u32 = 20;
const A64_ONLY: u64 = 1;
const A64_AND_A32: u64 = 2;
const FEATURE_ABSENT: u64 = 0;
const HCR_RW: u64 = 1 << 31;
const SCR_NS: u64 = 1;
const SCR_RW: u64 = 1 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitializationError {
    Identification(IdentificationUnsupported),
    Field {
        register: Register,
        name: &'static str,
        value: u64,
    },
    BankPresence(ExceptionLevel),
    ExecutionState {
        register: &'static str,
        value: u64,
    },
    LowerSecurity,
}

/// Actual initialized EL2 storage. Common fields own ELR/SPSR/ESR/FAR/VBAR once;
/// this is not another EL1 bank or a cached view of another control owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct El2Initialization {
    pub exception: El1Registers,
    pub stack_pointer: u64,
    pub hcr: u64,
    pub sctlr: u64,
    pub tcr: u64,
    pub hpfar: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct El3Initialization {
    pub exception: El1Registers,
    pub stack_pointer: u64,
    pub scr: u64,
    pub sctlr: u64,
    pub tcr: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initialization {
    pub el2: Option<El2Initialization>,
    pub el3: Option<El3Initialization>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct El2Bank {
    exception: El1Registers,
    hcr: u64,
    sctlr: u64,
    tcr: u64,
    hpfar: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct El3Bank {
    exception: El1Registers,
    scr: u64,
    sctlr: u64,
    tcr: u64,
}

/// Banks owned by the system state. Cloning them makes a diagnostic copy only.
#[derive(Debug, Clone)]
pub struct HigherElState {
    snapshot: Arc<Snapshot>,
    entry: EntryProfile,
    el2: Option<El2Bank>,
    el3: Option<El3Bank>,
}
impl PartialEq for HigherElState {
    fn eq(&self, other: &Self) -> bool {
        self.snapshot.same_snapshot(&other.snapshot)
            && self.entry == other.entry
            && self.el2 == other.el2
            && self.el3 == other.el3
    }
}
impl Eq for HigherElState {}

fn field(
    snapshot: &Snapshot,
    register: Register,
    name: &'static str,
    shift: u32,
    allowed: &[u64],
) -> Result<u64, InitializationError> {
    let value = (snapshot
        .read(register)
        .map_err(InitializationError::Identification)?
        >> shift)
        & ID_FIELD_MASK;
    if allowed.contains(&value) {
        Ok(value)
    } else {
        Err(InitializationError::Field {
            register,
            name,
            value,
        })
    }
}

impl HigherElState {
    /// The first supported scope: non-secure lower ELs, all ELs AArch64, no
    /// SEL2, RME or NV, and no base optional entry effects. The identification
    /// snapshot and the initialized banks must agree exactly.
    pub(super) fn initialized(
        snapshot: Arc<Snapshot>,
        initial: Initialization,
    ) -> Result<(Self, Option<u64>, Option<u64>), InitializationError> {
        let pfr0 = Register::IdAa64Pfr0El1;
        let el1 = field(&snapshot, pfr0, "EL1", EL1_SHIFT, &[A64_ONLY, A64_AND_A32])?;
        field(&snapshot, pfr0, "EL0", EL0_SHIFT, &[A64_ONLY, A64_AND_A32])?;
        let el2 = field(
            &snapshot,
            pfr0,
            "EL2",
            EL2_SHIFT,
            &[FEATURE_ABSENT, A64_ONLY, A64_AND_A32],
        )?;
        let el3 = field(
            &snapshot,
            pfr0,
            "EL3",
            EL3_SHIFT,
            &[FEATURE_ABSENT, A64_ONLY, A64_AND_A32],
        )?;
        for (register, name, shift) in [
            (pfr0, "SEL2", SEL2_SHIFT),
            (pfr0, "RME", RME_SHIFT),
            (Register::IdAa64Mmfr2El1, "NV", NV_SHIFT),
            (Register::IdAa64Mmfr4El1, "NV_frac", NV_FRAC_SHIFT),
        ] {
            field(&snapshot, register, name, shift, &[FEATURE_ABSENT])?;
        }
        if (el2 != FEATURE_ABSENT) != initial.el2.is_some() {
            return Err(InitializationError::BankPresence(ExceptionLevel::El2));
        }
        if (el3 != FEATURE_ABSENT) != initial.el3.is_some() {
            return Err(InitializationError::BankPresence(ExceptionLevel::El3));
        }
        if let Some(bank) = initial.el3 {
            if bank.scr & SCR_NS == 0 {
                return Err(InitializationError::LowerSecurity);
            }
            if (el2 == A64_AND_A32 || el2 == FEATURE_ABSENT && el1 == A64_AND_A32)
                && bank.scr & SCR_RW == 0
            {
                return Err(InitializationError::ExecutionState {
                    register: "SCR_EL3.RW",
                    value: bank.scr,
                });
            }
        }
        if el1 == A64_AND_A32
            && let Some(bank) = initial.el2
            && bank.hcr & HCR_RW == 0
        {
            return Err(InitializationError::ExecutionState {
                register: "HCR_EL2.RW",
                value: bank.hcr,
            });
        }
        let entry = snapshot
            .base_entry_effect_profile()
            .map_err(InitializationError::Identification)?;
        let sp2 = initial.el2.map(|value| value.stack_pointer);
        let sp3 = initial.el3.map(|value| value.stack_pointer);
        Ok((
            Self {
                snapshot,
                entry,
                el2: initial.el2.map(|value| El2Bank {
                    exception: value.exception,
                    hcr: value.hcr,
                    sctlr: value.sctlr,
                    tcr: value.tcr,
                    hpfar: value.hpfar,
                }),
                el3: initial.el3.map(|value| El3Bank {
                    exception: value.exception,
                    scr: value.scr,
                    sctlr: value.sctlr,
                    tcr: value.tcr,
                }),
            },
            sp2,
            sp3,
        ))
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn same_snapshot(&self, snapshot: &Snapshot) -> bool {
        self.snapshot.same_snapshot(snapshot)
    }
    pub const fn entry_profile(&self) -> EntryProfile {
        self.entry
    }
    pub fn present(&self, level: ExceptionLevel) -> bool {
        match level {
            ExceptionLevel::El0 | ExceptionLevel::El1 => true,
            ExceptionLevel::El2 => self.el2.is_some(),
            ExceptionLevel::El3 => self.el3.is_some(),
        }
    }
    pub fn hcr(&self) -> Option<&u64> {
        self.el2.as_ref().map(|bank| &bank.hcr)
    }
    pub fn scr(&self) -> Option<&u64> {
        self.el3.as_ref().map(|bank| &bank.scr)
    }
    pub fn sctlr(&self, level: ExceptionLevel) -> Result<u64, StateError> {
        match level {
            ExceptionLevel::El2 => self.el2.as_ref().map(|bank| bank.sctlr),
            ExceptionLevel::El3 => self.el3.as_ref().map(|bank| bank.sctlr),
            _ => None,
        }
        .ok_or(StateError::UnavailableExceptionLevel(level))
    }
    pub fn tcr(&self, level: ExceptionLevel) -> Result<u64, StateError> {
        match level {
            ExceptionLevel::El2 => self.el2.as_ref().map(|bank| bank.tcr),
            ExceptionLevel::El3 => self.el3.as_ref().map(|bank| bank.tcr),
            _ => None,
        }
        .ok_or(StateError::UnavailableExceptionLevel(level))
    }
    pub fn security(&self, level: ExceptionLevel) -> SecurityState {
        // Constructor proves NonSecure lower ELs and absent SEL2/RME. EL3 itself
        // is Secure, regardless of SCR.NS governing the lower level on return.
        if level == ExceptionLevel::El3 {
            SecurityState::Secure
        } else {
            SecurityState::NonSecure
        }
    }
    pub(super) fn exception(&self, level: ExceptionLevel) -> Result<&El1Registers, StateError> {
        match level {
            ExceptionLevel::El2 => self.el2.as_ref().map(|bank| &bank.exception),
            ExceptionLevel::El3 => self.el3.as_ref().map(|bank| &bank.exception),
            _ => None,
        }
        .ok_or(StateError::UnavailableExceptionLevel(level))
    }
    pub(super) fn exception_mut(
        &mut self,
        level: ExceptionLevel,
    ) -> Result<&mut El1Registers, StateError> {
        match level {
            ExceptionLevel::El2 => self.el2.as_mut().map(|bank| &mut bank.exception),
            ExceptionLevel::El3 => self.el3.as_mut().map(|bank| &mut bank.exception),
            _ => None,
        }
        .ok_or(StateError::UnavailableExceptionLevel(level))
    }
}

#[cfg(test)]
mod tests;
