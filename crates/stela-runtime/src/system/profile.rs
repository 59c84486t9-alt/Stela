//! Checked capability subsets for fixed EL0/EL1 execution and exception entry.
//!
//! This is not a complete guest CPU model. The caller retains feature/control
//! provenance and separately validates the EL/security/debug regime and state.
//! Numerical and scalable capability owners remain authoritative for their
//! domains; an empty bounded scalable set cannot prove base SVE absence.

const ID_FIELD_MASK: u64 = 0xf;
const PFR0_SVE_SHIFT: u32 = 32;
const PFR1_SME_SHIFT: u32 = 24;
const ARCHITECTURAL_STATE_ABSENT: u64 = 0;
const DFR0_PMS_VERSION_SHIFT: u32 = 32;
const SPE_NOT_IMPLEMENTED: u64 = 0;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const TCR_TOP_BYTE_IGNORE_MASK: u64 = TCR_TBI0 | TCR_TBI1;
const MDSCR_SOFTWARE_STEP: u64 = 1;
const MDSCR_KERNEL_DEBUG_ENABLE: u64 = 1 << 13;
const MDSCR_MONITOR_DEBUG_ENABLE: u64 = 1 << 15;
const MDSCR_ACTIVE_DEBUG_MASK: u64 =
    MDSCR_SOFTWARE_STEP | MDSCR_KERNEL_DEBUG_ENABLE | MDSCR_MONITOR_DEBUG_ENABLE;

/// Raw base-SPE version which this fixed profile cannot implement.
/// Present and reserved values both decline; neither proves feature absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedSpe {
    pub pms_version: u8,
}

/// Explicit base FEAT_SPE absence, independent from FEAT_SPE_EXC absence.
///
/// Construct from this software machine's actual declared ID field or retained
/// hardware readback. Disabled profiling does not suffice: branch helpers can
/// still change previous-branch history. This is a feature fact, not a CPU bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseSpeAbsence(());

impl BaseSpeAbsence {
    pub const fn from_id_aa64dfr0_el1(value: u64) -> Result<Self, UnsupportedSpe> {
        let version = (value >> DFR0_PMS_VERSION_SHIFT) & ID_FIELD_MASK;
        if version == SPE_NOT_IMPLEMENTED {
            Ok(Self(()))
        } else {
            Err(UnsupportedSpe {
                pms_version: version as u8,
            })
        }
    }
}

/// Optional effects reachable in the reviewed A64 entry/return helpers.
/// EL2/EL3 routing and debug enablement are separate execution-state checks.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEntryFeature {
    Brbe,
    Bti,
    Dit,
    DoubleFault,
    Ebep,
    Exs,
    Gcs,
    Iesb,
    Mops,
    Mte,
    Nmi,
    Pan,
    PauthLr,
    SpeExc,
    Ssbs,
    TrbeExc,
    Uao,
    Uinj,
    /// ReportException can write PFAR even with an invalid physical address.
    Pfar,
}

const SYSTEM_ENTRY_FEATURES: &[SystemEntryFeature] = &[
    SystemEntryFeature::Brbe,
    SystemEntryFeature::Bti,
    SystemEntryFeature::Dit,
    SystemEntryFeature::DoubleFault,
    SystemEntryFeature::Ebep,
    SystemEntryFeature::Exs,
    SystemEntryFeature::Gcs,
    SystemEntryFeature::Iesb,
    SystemEntryFeature::Mops,
    SystemEntryFeature::Mte,
    SystemEntryFeature::Nmi,
    SystemEntryFeature::Pan,
    SystemEntryFeature::PauthLr,
    SystemEntryFeature::SpeExc,
    SystemEntryFeature::Ssbs,
    SystemEntryFeature::TrbeExc,
    SystemEntryFeature::Uao,
    SystemEntryFeature::Uinj,
    SystemEntryFeature::Pfar,
];

impl SystemEntryFeature {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Brbe => "FEAT_BRBE",
            Self::Bti => "FEAT_BTI",
            Self::Dit => "FEAT_DIT",
            Self::DoubleFault => "FEAT_DoubleFault",
            Self::Ebep => "FEAT_EBEP",
            Self::Exs => "FEAT_ExS",
            Self::Gcs => "FEAT_GCS",
            Self::Iesb => "FEAT_IESB",
            Self::Mops => "FEAT_MOPS",
            Self::Mte => "FEAT_MTE",
            Self::Nmi => "FEAT_NMI",
            Self::Pan => "FEAT_PAN",
            Self::PauthLr => "FEAT_PAuth_LR",
            Self::SpeExc => "FEAT_SPE_EXC",
            Self::Ssbs => "FEAT_SSBS",
            Self::TrbeExc => "FEAT_TRBE_EXC",
            Self::Uao => "FEAT_UAO",
            Self::Uinj => "FEAT_UINJ",
            Self::Pfar => "FEAT_PFAR",
        }
    }

    const fn mask(self) -> u32 {
        1 << self as u8
    }
}

/// Complete explicit declaration for this bounded entry-effect subset.
/// There is deliberately no Default, host detection or unknown-ID fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemEntryFeatures(u32);

impl SystemEntryFeatures {
    /// Declare every reviewed optional entry effect absent in a software profile.
    /// This does not infer absence on hardware or establish readback provenance.
    pub const fn declared_absent() -> Self {
        Self(0)
    }

    pub const fn with(self, feature: SystemEntryFeature) -> Self {
        Self(self.0 | feature.mask())
    }

    pub const fn contains(self, feature: SystemEntryFeature) -> bool {
        self.0 & feature.mask() != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryProfileError {
    UnsupportedSystemFeature(SystemEntryFeature),
    /// A nonzero reviewed ID field means present or unreviewed, never absent.
    UnsupportedScalableState {
        feature: &'static str,
        id_value: u8,
    },
    UnsupportedControl {
        register: &'static str,
        value: u64,
    },
}

/// Narrow source-fact witness, not a copy of scalable features or mutable state.
/// The complete machine profile owns the original ID/control evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalableEntryAbsence {
    _private: (),
}

impl ScalableEntryAbsence {
    /// Exact June PFR0.SVE and PFR1.SME zero values declare their architectural
    /// state absent. Present and reserved values explicitly decline this subset.
    pub const fn from_id_registers(
        id_aa64pfr0_el1: u64,
        id_aa64pfr1_el1: u64,
    ) -> Result<Self, EntryProfileError> {
        let sve = (id_aa64pfr0_el1 >> PFR0_SVE_SHIFT) & ID_FIELD_MASK;
        if sve != ARCHITECTURAL_STATE_ABSENT {
            return Err(EntryProfileError::UnsupportedScalableState {
                feature: "FEAT_SVE",
                id_value: sve as u8,
            });
        }
        let sme = (id_aa64pfr1_el1 >> PFR1_SME_SHIFT) & ID_FIELD_MASK;
        if sme != ARCHITECTURAL_STATE_ABSENT {
            return Err(EntryProfileError::UnsupportedScalableState {
                feature: "FEAT_SME",
                id_value: sme as u8,
            });
        }
        Ok(Self { _private: () })
    }
}

/// Checked capability token for base entry/return effects.
/// It does not validate current PSTATE, saved modes, debug controls or backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryProfile {
    features: SystemEntryFeatures,
}

impl EntryProfile {
    pub fn base(
        features: SystemEntryFeatures,
        _scalable: ScalableEntryAbsence,
    ) -> Result<Self, EntryProfileError> {
        for &feature in SYSTEM_ENTRY_FEATURES {
            if features.contains(feature) {
                return Err(EntryProfileError::UnsupportedSystemFeature(feature));
            }
        }
        Ok(Self { features })
    }

    pub const fn features(self) -> SystemEntryFeatures {
        self.features
    }

    /// Check current owning-backend readbacks before preparing entry/return.
    /// EL/security, halted/halting eligibility and source PSTATE remain separate
    /// checks; feature absence cannot establish those execution-state facts.
    pub const fn check_controls(
        self,
        tcr_el1: u64,
        mdscr_el1: u64,
    ) -> Result<(), EntryProfileError> {
        if tcr_el1 & TCR_TOP_BYTE_IGNORE_MASK != 0 {
            return Err(EntryProfileError::UnsupportedControl {
                register: "TCR_EL1",
                value: tcr_el1,
            });
        }
        if mdscr_el1 & MDSCR_ACTIVE_DEBUG_MASK != 0 {
            return Err(EntryProfileError::UnsupportedControl {
                register: "MDSCR_EL1",
                value: mdscr_el1,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
