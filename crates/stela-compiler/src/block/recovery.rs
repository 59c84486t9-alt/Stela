//! Typed register/spill recovery and atomic guest retirement settlement.
mod packed;
mod qualification;
mod retirement;
mod sites;
mod spills;
use super::HostGprSnapshot;
use crate::GuestAddress;
pub use packed::PackedRecovery;
pub use qualification::{RecoveryQualificationError, RecoveryTemplate, UnqualifiedFaultRecovery};
pub use retirement::{RecoveredPosition, RetirementPhase, RetirementPoint};
pub use sites::{RecoverySettlement, RecoverySite, RecoverySiteKind, TranslatedAccess};
pub use spills::{HostSpillSnapshot, InvalidSpillOffset, NATIVE_SPILL_WORDS, SpillOffset};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySource {
    HostRegister(u8),
    NativeSpill(SpillOffset),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryBinding {
    pub guest: u8,
    pub source: RecoverySource,
}
impl RecoveryBinding {
    pub const fn gpr(guest: u8, register: u8) -> Self {
        Self {
            guest,
            source: RecoverySource::HostRegister(register),
        }
    }
    pub const fn spill(guest: u8, offset: SpillOffset) -> Self {
        Self {
            guest,
            source: RecoverySource::NativeSpill(offset),
        }
    }
}

/// Capture data from one pinned invocation and its matching code/plan epoch.
/// Native-stack permission remains with the platform capture owner.
#[derive(Debug, Clone, Copy)]
pub struct HostFaultSnapshot<'a> {
    pub gprs: &'a HostGprSnapshot,
    pub spills: &'a HostSpillSnapshot,
}

/// Native interval with a single complete guest retirement boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultRecovery {
    pub start: usize,
    pub end: usize,
    pub bindings: alloc::vec::Vec<RecoveryBinding>,
    pub retirement: RetirementPoint,
    pub site: RecoverySite,
}
impl FaultRecovery {
    /// Classify before attempting architectural settlement. An absent row is a
    /// host-internal fault. Ordinary frame/commit intervals do not authorize
    /// guest projection because their location metadata says Before.
    pub fn site_at(table: &[Self], offset: usize) -> Result<RecoverySite, FaultRecoveryError> {
        let mut site = None;
        for entry in table {
            if entry.start >= entry.end {
                return Err(FaultRecoveryError::InvalidNativeRange {
                    start: entry.start,
                    end: entry.end,
                });
            }
            if !(entry.start..entry.end).contains(&offset) {
                continue;
            }
            if entry.site.kind() != RecoverySiteKind::NativeInternal
                && entry.retirement.phase() != RetirementPhase::Before
            {
                return Err(FaultRecoveryError::InvalidGuestSitePhase {
                    site: entry.site.kind(),
                    phase: entry.retirement.phase(),
                });
            }
            if site.is_some_and(|site| site != entry.site) {
                return Err(FaultRecoveryError::ConflictingRecoverySite);
            }
            site = Some(entry.site);
        }
        Ok(site.unwrap_or(RecoverySite::native_internal()))
    }
    /// Required initialized spill words at this native offset. The capture
    /// owner validates each address against its mapped invocation lease.
    pub fn required_spills(
        table: &[Self],
        offset: usize,
    ) -> impl Iterator<Item = SpillOffset> + '_ {
        table
            .iter()
            .filter(move |entry| (entry.start..entry.end).contains(&offset))
            .flat_map(|entry| entry.bindings.iter())
            .filter_map(|binding| match binding.source {
                RecoverySource::NativeSpill(offset) => Some(offset),
                _ => None,
            })
    }
    /// Validate the entire active settlement before changing any guest value.
    /// PC and retirement count are returned together, never inferred from a
    /// partially executed native recipe or an unavailable capture.
    pub fn apply(
        table: &[Self],
        offset: usize,
        capture: HostFaultSnapshot<'_>,
        state: &mut crate::GuestState,
    ) -> Result<Option<RecoverySettlement>, FaultRecoveryError> {
        let mut settlement: Option<RecoverySettlement> = None;
        let mut values = [0; 32];
        let mut present = 0u32;
        for entry in table {
            if entry.start >= entry.end {
                return Err(FaultRecoveryError::InvalidNativeRange {
                    start: entry.start,
                    end: entry.end,
                });
            }
            if !(entry.start..entry.end).contains(&offset) {
                continue;
            }
            let at = entry.retirement.position()?;
            let phase = entry.retirement.phase();
            if entry.site.kind() != RecoverySiteKind::NativeInternal
                && phase != RetirementPhase::Before
            {
                return Err(FaultRecoveryError::InvalidGuestSitePhase {
                    site: entry.site.kind(),
                    phase,
                });
            }
            if let Some(previous) = settlement {
                if previous.position != at || previous.phase != phase {
                    return Err(FaultRecoveryError::InconsistentRetirement);
                }
                if previous.site != entry.site {
                    return Err(FaultRecoveryError::ConflictingRecoverySite);
                }
            }
            settlement = Some(RecoverySettlement {
                position: at,
                site: entry.site,
                phase,
            });
            for binding in &entry.bindings {
                if binding.guest > 31 {
                    return Err(FaultRecoveryError::InvalidGuestRegister {
                        register: binding.guest,
                    });
                }
                let value = match binding.source {
                    RecoverySource::HostRegister(register) => {
                        if register >= 32 {
                            return Err(FaultRecoveryError::InvalidHostRegister { register });
                        }
                        capture
                            .gprs
                            .get(register)
                            .ok_or(FaultRecoveryError::ExtendedStateUnavailable { register })?
                    }
                    RecoverySource::NativeSpill(offset) => capture
                        .spills
                        .get(offset)
                        .ok_or(FaultRecoveryError::NativeSpillUnavailable { offset })?,
                };
                let slot = &mut values[usize::from(binding.guest)];
                let bit = 1 << binding.guest;
                if present & bit != 0 && *slot != value {
                    return Err(FaultRecoveryError::ConflictingGuestBinding {
                        register: binding.guest,
                    });
                }
                *slot = value;
                present |= bit;
            }
        }
        while present != 0 {
            let guest = present.trailing_zeros() as usize;
            present &= present - 1;
            if guest == 31 {
                state.sp = values[guest];
            } else {
                state.x[guest] = values[guest];
            }
        }
        Ok(settlement)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultRecoveryError {
    InvalidGuestRegister {
        register: u8,
    },
    InvalidHostRegister {
        register: u8,
    },
    ExtendedStateUnavailable {
        register: u8,
    },
    NativeSpillUnavailable {
        offset: SpillOffset,
    },
    InvalidNativeRange {
        start: usize,
        end: usize,
    },
    InvalidInstructionAddress {
        pc: GuestAddress,
    },
    RetirementOverflow {
        pc: GuestAddress,
    },
    UnprovenFallthrough {
        pc: GuestAddress,
    },
    InvalidRetiredCount {
        count: u16,
    },
    InconsistentRetirement,
    UnknownRecoverySite {
        tag: u8,
    },
    InvalidGuestSitePhase {
        site: RecoverySiteKind,
        phase: RetirementPhase,
    },
    ConflictingRecoverySite,
    ConflictingGuestBinding {
        register: u8,
    },
}
impl core::fmt::Display for FaultRecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidGuestRegister { register } => {
                write!(f, "fault recovery names invalid guest register {register}")
            }
            Self::InvalidHostRegister { register } => {
                write!(f, "fault recovery names invalid host register {register}")
            }
            Self::ExtendedStateUnavailable { register } => write!(
                f,
                "fault recovery needs host R{register}, but its extended bank was not captured"
            ),
            Self::NativeSpillUnavailable { offset } => write!(
                f,
                "fault recovery needs unavailable native spill at RSP+{}",
                offset.bytes()
            ),
            Self::InvalidNativeRange { start, end } => {
                write!(f, "invalid native recovery range {start}..{end}")
            }
            Self::InvalidInstructionAddress { pc } => {
                write!(f, "unaligned recovery instruction PC {:#x}", pc.0)
            }
            Self::RetirementOverflow { pc } => {
                write!(f, "recovery retirement overflows at PC {:#x}", pc.0)
            }
            Self::UnprovenFallthrough { pc } => write!(
                f,
                "instruction at PC {:#x} has no proven fallthrough recovery",
                pc.0
            ),
            Self::InvalidRetiredCount { count } => {
                write!(f, "recovery retired count {count} exceeds the block bound")
            }
            Self::InconsistentRetirement => {
                f.write_str("overlapping recovery entries disagree on retirement")
            }
            Self::UnknownRecoverySite { tag } => {
                write!(f, "unknown native recovery site tag {tag}")
            }
            Self::InvalidGuestSitePhase { site, phase } => write!(
                f,
                "guest recovery site {site:?} cannot have phase {phase:?}"
            ),
            Self::ConflictingRecoverySite => {
                f.write_str("overlapping recovery entries disagree on native fault site")
            }
            Self::ConflictingGuestBinding { register } => {
                write!(f, "recovery entries disagree on guest register {register}")
            }
        }
    }
}
impl core::error::Error for FaultRecoveryError {}

#[cfg(test)]
mod tests;
