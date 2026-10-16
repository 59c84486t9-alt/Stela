//! FEAT_CPA effects resolved from the identification, control and debug state.

#[cfg(feature = "std")]
use super::extended_controls::{
    ExtendedControlLoan, SCTLR2_CPTA, SCTLR2_CPTA0, SCTLR2_CPTM, SCTLR2_CPTM0,
};
#[cfg(feature = "std")]
use crate::system::debug::DebugControls;
use crate::system::{
    identification::Register,
    identification_snapshot::{Snapshot, Unsupported},
};
use stela_compiler::context::{
    memory::address::{AccessEl, AddressAddChecks, EffectiveAddressChecks},
    pointer::EffectivePointerChecks,
};

const FIELD_MASK: u64 = 0xf;
const ISAR3_CPA_SHIFT: u32 = 0;
const CPA_ABSENT: u8 = 0;
const CPA_ARITHMETIC: u8 = 1;
const CPA_CHECKED: u8 = 2;
#[cfg(feature = "std")]
const MMFR3_SCTLRX_SHIFT: u32 = 4;
#[cfg(feature = "std")]
const SCTLR2_ABSENT: u8 = 0;
#[cfg(feature = "std")]
const SCTLR2_PRESENT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Identification(Unsupported),
    ActualDebugRequired,
    ActualExtendedControlsRequired,
    DifferentSnapshot,
    UnsupportedProfile,
    ExtendedControlUnavailable,
}

/// The declared feature subset; checking the effects alone does not prove
/// FEAT_CPA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CpaFeature {
    Absent,
    Arithmetic,
    Checked,
}

impl CpaFeature {
    pub(crate) fn from_raw(raw: u64) -> Result<Self, Error> {
        match ((raw >> ISAR3_CPA_SHIFT) & FIELD_MASK) as u8 {
            CPA_ABSENT => Ok(Self::Absent),
            CPA_ARITHMETIC => Ok(Self::Arithmetic),
            CPA_CHECKED => Ok(Self::Checked),
            value => Err(unsupported(Register::IdAa64Isar3El1, "CPA", value)),
        }
    }
    pub(crate) fn from_snapshot(snapshot: &Snapshot) -> Result<Self, Error> {
        Self::from_raw(
            snapshot
                .read(Register::IdAa64Isar3El1)
                .map_err(Error::Identification)?,
        )
    }
    pub(crate) const fn has_arithmetic(self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// Resolved effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedPointerChecks {
    feature: CpaFeature,
    el0: EffectivePointerChecks,
    el1: EffectivePointerChecks,
}

impl ResolvedPointerChecks {
    #[cfg(feature = "std")]
    const fn unchecked(feature: CpaFeature) -> Self {
        Self {
            feature,
            el0: EffectivePointerChecks::Unchecked,
            el1: EffectivePointerChecks::Unchecked,
        }
    }
    pub(crate) const fn feature(self) -> CpaFeature {
        self.feature
    }

    pub(crate) const fn arithmetic_at(self, access_el: AccessEl) -> EffectivePointerChecks {
        match access_el {
            AccessEl::El0 => self.el0,
            AccessEl::El1 => self.el1,
        }
    }

    pub(crate) fn address_checks(self) -> EffectiveAddressChecks {
        let addition = |checks| match checks {
            EffectivePointerChecks::Unchecked => AddressAddChecks::Disabled,
            EffectivePointerChecks::Addition
            | EffectivePointerChecks::AdditionAndMultiplication => AddressAddChecks::Enabled,
        };
        EffectiveAddressChecks::new(addition(self.el0), addition(self.el1))
    }
}

#[cfg(feature = "std")]
fn field(snapshot: &Snapshot, register: Register, shift: u32) -> Result<u8, Error> {
    let raw = snapshot.read(register).map_err(Error::Identification)?;
    Ok(((raw >> shift) & FIELD_MASK) as u8)
}

fn unsupported(register: Register, name: &'static str, value: u8) -> Error {
    Error::Identification(Unsupported::Field {
        register,
        field: name,
        value,
    })
}

/// Resolve both EL10 effects without collapsing a block's distinct access ELs.
/// CPA0/1 returns before debug/regime/SCTLR2 lookup as the source helpers require.
/// This does not select source AccessDescriptor.el or validate PSTATE legality.
#[cfg(feature = "std")]
pub(crate) fn resolve(
    snapshot: &Snapshot,
    actual_debug: Option<&DebugControls>,
    extended: Option<&ExtendedControlLoan<'_>>,
) -> Result<ResolvedPointerChecks, Error> {
    let feature = CpaFeature::from_snapshot(snapshot)?;
    if feature != CpaFeature::Checked {
        return Ok(ResolvedPointerChecks::unchecked(feature));
    }
    let debug = actual_debug.ok_or(Error::ActualDebugRequired)?;
    if debug.halted {
        return Ok(ResolvedPointerChecks::unchecked(CpaFeature::Checked));
    }
    // Reuse the shared exact EL implementation/regime qualifier. A fresh
    // compiler profile or absent optional bank cannot invent higher-EL state.
    snapshot
        .check_el10_regime()
        .map_err(Error::Identification)?;
    match field(snapshot, Register::IdAa64Mmfr3El1, MMFR3_SCTLRX_SHIFT)? {
        SCTLR2_ABSENT => return Ok(ResolvedPointerChecks::unchecked(CpaFeature::Checked)),
        SCTLR2_PRESENT => {}
        value => return Err(unsupported(Register::IdAa64Mmfr3El1, "SCTLRX", value)),
    }
    let controls = extended.ok_or(Error::ActualExtendedControlsRequired)?;
    if !controls.snapshot().same_snapshot(snapshot) {
        return Err(Error::DifferentSnapshot);
    }
    let raw = controls.sctlr2_el1();
    let checks = |addition, multiplication| {
        let cpta = raw & addition != 0;
        // EffectiveCPTM is zero unless effective CPTA at the same EL is one.
        EffectivePointerChecks::from_effective(cpta, cpta && raw & multiplication != 0)
            .expect("multiplication is explicitly gated by addition")
    };
    Ok(ResolvedPointerChecks {
        feature,
        el0: checks(SCTLR2_CPTA0, SCTLR2_CPTM0),
        el1: checks(SCTLR2_CPTA, SCTLR2_CPTM),
    })
}

#[cfg(test)]
mod tests;
