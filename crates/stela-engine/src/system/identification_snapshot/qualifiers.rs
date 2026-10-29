//! Feature checks derived from identification-register fields.
use super::{Register, Snapshot, Unsupported};
use crate::system::profile::{
    BaseSpeAbsence, EntryProfile, ScalableEntryAbsence, SystemEntryFeatures,
};

const FIELD_MASK: u64 = 0xf;
const FEATURE_ABSENT: u8 = 0;
const A64_ONLY: u8 = 1;
const A64_AND_A32: u8 = 2;
const APA_SHIFT: u32 = 4;
const API_SHIFT: u32 = 8;
const APA3_SHIFT: u32 = 12;
const APA_QARMA5_CLASSIC: u8 = 1;
const APA_QARMA5_FAULTING_COMBINED: u8 = 5;
const RAS_BASE_VERSION: u8 = 1;
const TGRAN4_SHIFT: u32 = 28;
const D128_SHIFT: u32 = 32;
const EL0_SHIFT: u32 = 0;
const EL1_SHIFT: u32 = 4;
const EL2_SHIFT: u32 = 8;
const EL3_SHIFT: u32 = 12;
const RAS_SHIFT: u32 = 28;

#[derive(Debug, Clone, Copy)]
struct Field {
    register: Register,
    name: &'static str,
    shift: u32,
}
const REQUIRED_ABSENCES: &[Field] = &[
    Field {
        register: Register::IdAa64Dfr0El1,
        name: "BRBE",
        shift: 52,
    },
    Field {
        register: Register::IdAa64Dfr0El1,
        name: "TraceBuffer",
        shift: 44,
    },
    Field {
        register: Register::IdAa64Dfr0El1,
        name: "PMSVer",
        shift: 32,
    },
    Field {
        register: Register::IdAa64Dfr1El1,
        name: "EBEP",
        shift: 48,
    },
    Field {
        register: Register::IdAa64Pfr0El1,
        name: "DIT",
        shift: 48,
    },
    Field {
        register: Register::IdAa64Pfr1El1,
        name: "BT",
        shift: 0,
    },
    Field {
        register: Register::IdAa64Pfr1El1,
        name: "PFAR",
        shift: 60,
    },
    Field {
        register: Register::IdAa64Pfr1El1,
        name: "DF2",
        shift: 56,
    },
    Field {
        register: Register::IdAa64Pfr1El1,
        name: "GCS",
        shift: 44,
    },
    Field {
        register: Register::IdAa64Pfr1El1,
        name: "NMI",
        shift: 36,
    },
    Field {
        register: Register::IdAa64Pfr1El1,
        name: "MTE",
        shift: 8,
    },
    Field {
        register: Register::IdAa64Pfr1El1,
        name: "SSBS",
        shift: 4,
    },
    Field {
        register: Register::IdAa64Pfr2El1,
        name: "UINJ",
        shift: 16,
    },
    Field {
        register: Register::IdAa64Mmfr0El1,
        name: "ExS",
        shift: 44,
    },
    Field {
        register: Register::IdAa64Mmfr1El1,
        name: "PAN",
        shift: 20,
    },
    Field {
        register: Register::IdAa64Mmfr2El1,
        name: "IESB",
        shift: 12,
    },
    Field {
        register: Register::IdAa64Mmfr2El1,
        name: "UAO",
        shift: 4,
    },
    Field {
        register: Register::IdAa64Isar2El1,
        name: "MOPS",
        shift: 16,
    },
];

impl Snapshot {
    fn field(&self, field: Field) -> Result<u8, Unsupported> {
        Ok(((self.read(field.register)? >> field.shift) & FIELD_MASK) as u8)
    }
    fn require_zero(&self, field: Field) -> Result<(), Unsupported> {
        let value = self.field(field)?;
        if value != FEATURE_ABSENT {
            return Err(Unsupported::Field {
                register: field.register,
                field: field.name,
                value,
            });
        }
        Ok(())
    }
    fn check_fixed_exception_levels(&self) -> Result<(), Unsupported> {
        for (name, shift) in [("EL0", EL0_SHIFT), ("EL1", EL1_SHIFT)] {
            let value = self.field(Field {
                register: Register::IdAa64Pfr0El1,
                name,
                shift,
            })?;
            if !matches!(value, A64_ONLY | A64_AND_A32) {
                return Err(Unsupported::Field {
                    register: Register::IdAa64Pfr0El1,
                    field: name,
                    value,
                });
            }
        }
        // With no EL3, an implemented EL2 is enabled by the exact EL2Enabled
        // helper. The fixed no-EL2/no-EL3 owner therefore requires both absent.
        for (name, shift) in [("EL2", EL2_SHIFT), ("EL3", EL3_SHIFT)] {
            self.require_zero(Field {
                register: Register::IdAa64Pfr0El1,
                name,
                shift,
            })?;
        }
        Ok(())
    }

    /// Require implemented AArch64 EL0/EL1 and absent EL2/EL3 from these IDs.
    /// This checks implementation/regime facts, not dynamic CurrentEL or PSTATE.
    pub fn check_el10_regime(&self) -> Result<(), Unsupported> {
        self.check_fixed_exception_levels()
    }

    /// The optional-effect facts for the fixed EL, except FEAT_PAuth_LR.
    pub(crate) fn non_pauth_entry_absence(&self) -> Result<ScalableEntryAbsence, Unsupported> {
        self.check_fixed_exception_levels()?;
        for &field in REQUIRED_ABSENCES {
            self.require_zero(field)?;
        }
        // DF2=0 does not establish DoubleFault absence: PFR0.RAS>=2 identifies it.
        let ras = self.field(Field {
            register: Register::IdAa64Pfr0El1,
            name: "RAS",
            shift: RAS_SHIFT,
        })?;
        if ras > RAS_BASE_VERSION {
            return Err(Unsupported::Field {
                register: Register::IdAa64Pfr0El1,
                field: "RAS",
                value: ras,
            });
        }
        ScalableEntryAbsence::from_id_registers(
            self.read(Register::IdAa64Pfr0El1)?,
            self.read(Register::IdAa64Pfr1El1)?,
        )
        .map_err(Unsupported::EntryProfile)
    }

    /// The exception entry profile, including the absence of FEAT_PAuth_LR.
    pub fn entry_profile(&self) -> Result<EntryProfile, Unsupported> {
        let scalable = self.non_pauth_entry_absence()?;
        let isar1 = self.read(Register::IdAa64Isar1El1)?;
        let isar2 = self.read(Register::IdAa64Isar2El1)?;
        let apa = ((isar1 >> APA_SHIFT) & FIELD_MASK) as u8;
        let api = ((isar1 >> API_SHIFT) & FIELD_MASK) as u8;
        let apa3 = ((isar2 >> APA3_SHIFT) & FIELD_MASK) as u8;
        // Supports the classic and PAuth2 algorithm tuples, or no algorithm;
        // other tuples are refused. FEAT_PAuth_LR absence is never mistaken for
        // PAuth absence.
        if !matches!(
            (apa, api, apa3),
            (FEATURE_ABSENT, FEATURE_ABSENT, FEATURE_ABSENT)
                | (APA_QARMA5_CLASSIC, FEATURE_ABSENT, FEATURE_ABSENT)
                | (APA_QARMA5_FAULTING_COMBINED, FEATURE_ABSENT, FEATURE_ABSENT)
        ) {
            return Err(Unsupported::PauthLrTuple { apa, api, apa3 });
        }
        // MTE = 0 means MTE is absent; MTE_frac and MTEX are invalid in that
        // case and are not read.
        EntryProfile::base(SystemEntryFeatures::declared_absent(), scalable)
            .map_err(Unsupported::EntryProfile)
    }

    /// The same optional-effect facts, independent of EL availability.
    /// Higher-EL owners must also validate their EL, security and
    /// execution-state controls.
    pub(crate) fn base_entry_effect_profile(&self) -> Result<EntryProfile, Unsupported> {
        self.check_base_optional_entry_effects()?;
        let scalable = ScalableEntryAbsence::from_id_registers(
            self.read(Register::IdAa64Pfr0El1)?,
            self.read(Register::IdAa64Pfr1El1)?,
        )
        .map_err(Unsupported::EntryProfile)?;
        EntryProfile::base(SystemEntryFeatures::declared_absent(), scalable)
            .map_err(Unsupported::EntryProfile)
    }

    /// The same optional-state checks, for a debug lifecycle that may keep SME
    /// storage.
    pub(crate) fn check_base_optional_entry_effects(&self) -> Result<(), Unsupported> {
        for &field in REQUIRED_ABSENCES {
            self.require_zero(field)?;
        }
        // DF2=0 does not establish DoubleFault absence: PFR0.RAS>=2 identifies it.
        let ras = self.field(Field {
            register: Register::IdAa64Pfr0El1,
            name: "RAS",
            shift: RAS_SHIFT,
        })?;
        if ras > RAS_BASE_VERSION {
            return Err(Unsupported::Field {
                register: Register::IdAa64Pfr0El1,
                field: "RAS",
                value: ras,
            });
        }
        let isar1 = self.read(Register::IdAa64Isar1El1)?;
        let isar2 = self.read(Register::IdAa64Isar2El1)?;
        let apa = ((isar1 >> APA_SHIFT) & FIELD_MASK) as u8;
        let api = ((isar1 >> API_SHIFT) & FIELD_MASK) as u8;
        let apa3 = ((isar2 >> APA3_SHIFT) & FIELD_MASK) as u8;
        // Supports the classic and PAuth2 algorithm tuples, or no algorithm;
        // other tuples are refused. FEAT_PAuth_LR absence is never mistaken for
        // PAuth absence.
        if !matches!(
            (apa, api, apa3),
            (FEATURE_ABSENT, FEATURE_ABSENT, FEATURE_ABSENT)
                | (APA_QARMA5_CLASSIC, FEATURE_ABSENT, FEATURE_ABSENT)
                | (APA_QARMA5_FAULTING_COMBINED, FEATURE_ABSENT, FEATURE_ABSENT)
        ) {
            return Err(Unsupported::PauthLrTuple { apa, api, apa3 });
        }
        Ok(())
    }

    pub fn check_entry_profile(&self, profile: EntryProfile) -> Result<(), Unsupported> {
        if self.entry_profile()? != profile {
            return Err(Unsupported::EntryProfileMismatch);
        }
        Ok(())
    }

    pub fn base_spe_absence(&self) -> Result<BaseSpeAbsence, Unsupported> {
        BaseSpeAbsence::from_id_aa64dfr0_el1(self.read(Register::IdAa64Dfr0El1)?)
            .map_err(Unsupported::BaseSpe)
    }

    /// Actual feature facts only: ordinary 4KB stage1 and FEAT_D128 absent. TCR,
    /// TCR2, effective sizes/TBI/TBID/MTX and current control generation remain
    /// the existing mutable control owner's responsibility.
    pub fn check_base_el10_4k(&self) -> Result<(), Unsupported> {
        self.check_fixed_exception_levels()?;
        self.require_zero(Field {
            register: Register::IdAa64Mmfr0El1,
            name: "TGran4",
            shift: TGRAN4_SHIFT,
        })?;
        self.require_zero(Field {
            register: Register::IdAa64Mmfr3El1,
            name: "D128",
            shift: D128_SHIFT,
        })
    }
}
