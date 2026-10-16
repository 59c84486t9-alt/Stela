//! Actual immutable facts and implementation choice of the fresh software PE.
//! This owns no mutable architectural/control bank and authenticates no hardware.
use crate::system::{
    access::{ExceptionLevel, Profile, SecurityState},
    identification::Register,
    identification_snapshot::Snapshot,
    profile::{EntryProfile, SystemEntryFeature},
    registers::el1::{Context, Controls, FineGrainedTraps},
    state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
};
use anyhow::{Result, ensure};

const ID_FIELD_MASK: u64 = 0xf;
const RME_SHIFT: u32 = 52;
const CPA_SHIFT: u32 = 0;
const LSE2_SHIFT: u32 = 32;
const A64_EL0_EL1: u64 = 0x11;
const FP_ABSENT_SHIFT: u32 = 16;
const ASIMD_ABSENT_SHIFT: u32 = 20;
const DECLARED_PFR0: u64 =
    A64_EL0_EL1 | (ID_FIELD_MASK << FP_ABSENT_SHIFT) | (ID_FIELD_MASK << ASIMD_ABSENT_SHIFT);
const PA_40: u64 = 2;
const TGRAN16_SUPPORTED_SHIFT: u32 = 20;
const TGRAN64_ABSENT_SHIFT: u32 = 24;
const DECLARED_MMFR0: u64 =
    PA_40 | (1 << TGRAN16_SUPPORTED_SHIFT) | (ID_FIELD_MASK << TGRAN64_ABSENT_SHIFT);

enum SecurityImplementation {
    NonSecureOnly,
}

/// Created once by the genuine fresh software factory. Missing unrelated IDs
/// stay missing; these explicit values are declared implementation facts.
pub(in crate::blocks::retirement::checked) struct El1PlatformControls {
    identification: Snapshot,
    security: SecurityImplementation,
    entry: EntryProfile,
}
impl El1PlatformControls {
    pub(in crate::blocks::retirement::checked) fn declared_base() -> Result<Self> {
        let identification = Snapshot::declared(
            "stela-owned-base-el1-platform-v1",
            &[
                (Register::IdAa64Pfr0El1, DECLARED_PFR0),
                (Register::IdAa64Pfr1El1, 0),
                (Register::IdAa64Pfr2El1, 0),
                (Register::IdAa64Dfr0El1, 0),
                (Register::IdAa64Dfr1El1, 0),
                (Register::IdAa64Mmfr0El1, DECLARED_MMFR0),
                (Register::IdAa64Mmfr1El1, 0),
                (Register::IdAa64Mmfr2El1, 0),
                (Register::IdAa64Isar1El1, 0),
                (Register::IdAa64Isar2El1, 0),
                (Register::IdAa64Isar3El1, 0),
            ],
        )?;
        let entry = identification.entry_profile()?;
        let result = Self {
            identification,
            security: SecurityImplementation::NonSecureOnly,
            entry,
        };
        result.check()?;
        Ok(result)
    }
    pub(in crate::blocks::retirement::checked) fn entry_profile(&self) -> EntryProfile {
        self.entry
    }
    pub(in crate::blocks::retirement::checked) fn identification(&self) -> &Snapshot {
        &self.identification
    }
    pub(in crate::blocks::retirement::checked) fn check(&self) -> Result<()> {
        self.identification.check_el10_regime()?;
        self.identification.check_entry_profile(self.entry)?;
        ensure!(
            (self.identification.read(Register::IdAa64Isar3El1)? >> CPA_SHIFT) & ID_FIELD_MASK == 0,
            "actual fresh EL1 base address arithmetic requires CPA absence"
        );
        let pfr0 = self.identification.read(Register::IdAa64Pfr0El1)?;
        ensure!(
            (pfr0 >> RME_SHIFT) & ID_FIELD_MASK == 0,
            "actual fresh EL1 identification does not exclude RME"
        );
        ensure!(
            !self.entry.features().contains(SystemEntryFeature::Gcs),
            "actual fresh EL1 entry profile requires GCS ownership"
        );
        Ok(())
    }
    /// The actual retained immutable declaration must positively exclude LSE2.
    /// Missing ID values are not absence; this grants no source/outer/read loan.
    pub(in crate::blocks::retirement::checked) fn check_pair_read_profile(
        &self,
        system: &SystemState,
    ) -> Result<()> {
        // Same checks as the original pair source producer, in original order.
        self.context(system)?;
        let value = self.identification.read(Register::IdAa64Mmfr2El1)?;
        ensure!(
            (value >> LSE2_SHIFT) & ID_FIELD_MASK == 0,
            "actual same-PE pair read requires positively observed LSE2 absence"
        );
        Ok(())
    }
    pub(in crate::blocks::retirement::checked) fn context(
        &self,
        system: &SystemState,
    ) -> Result<Context> {
        self.check()?;
        system.check_lower_el_storage().map_err(|error| {
            anyhow::anyhow!("actual EL1 profile does not own higher-EL storage: {error:?}")
        })?;
        ensure!(
            system.current_el() == ExceptionLevel::El1
                && system.pstate_misc() & (PSTATE_IL_MASK | PSTATE_SS_MASK) == 0,
            "actual EL1 state requires another execution owner"
        );
        let security = match self.security {
            SecurityImplementation::NonSecureOnly => SecurityState::NonSecure,
        };
        // The same Snapshot proves EL2/EL3 absent and A64 EL1 implemented;
        // the same EntryProfile proves GCS absent. NVx/FGT/HCR/SCR and EXLOCK
        // predicates are consequently inapplicable, not invented readbacks.
        let traps = FineGrainedTraps {
            esr: false,
            far: false,
            vbar: false,
        };
        Ok(Context {
            profile: Profile {
                current_el: system.current_el(),
                security,
                el2_enabled: false,
                el3_present: false,
            },
            aa64: true,
            gcs: false,
            fine_grained_traps: false,
            controls: Some(Controls {
                effective_nvx: 0,
                hcr_trvm: false,
                hcr_tvm: false,
                scr_fgt_enabled: false,
                read_traps: traps,
                write_traps: traps,
                current_exlock_enabled: false,
                halted: false,
                pstate_exlock: false,
            }),
        })
    }
}

#[cfg(test)]
mod tests;
