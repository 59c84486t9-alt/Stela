//! The fixed identification and implementation choices of a software PE.
mod fixed_profile;

use super::super::software_el1::{SoftwareEl1Declaration, SoftwareEl1Security};
use crate::system::{
    access::{ExceptionLevel, Profile, SecurityState},
    identification::Register,
    identification_snapshot::Snapshot,
    profile::{EntryProfile, SystemEntryFeature},
    registers::el1::{Context, Controls, FineGrainedTraps},
    state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
};
use alloc::sync::Arc;
use anyhow::{Result, ensure};

const ID_FIELD_MASK: u64 = 0xf;
const RME_SHIFT: u32 = 52;
const CPA_SHIFT: u32 = 0;
const LSE2_SHIFT: u32 = 32;
const ECV_SHIFT: u32 = 60;
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

enum WfxtDeclaration {
    Absent,
    RegisterSyndrome,
}

impl WfxtDeclaration {
    const fn encoded(&self) -> u64 {
        match self {
            Self::Absent => 0,
            Self::RegisterSyndrome => 2,
        }
    }
}

/// Created once with the software PE. Missing IDs stay missing; the values
/// given are declared implementation facts.
pub(in crate::blocks::retirement::checked) struct El1PlatformControls {
    identification: Arc<Snapshot>,
    security: SoftwareEl1Security,
    entry: EntryProfile,
}
impl El1PlatformControls {
    pub(in crate::blocks::retirement::checked) fn declared_base() -> Result<Self> {
        Self::declared("stela-owned-base-el1-platform-v1", WfxtDeclaration::Absent)
    }
    /// The hosted-wait profile, used before the PE exists. Its factory must
    /// also install the counter, IRQ, deadline and event resources; the profile
    /// alone does not enable waits.
    pub(in crate::blocks::retirement::checked) fn declared_hosted_wait() -> Result<Self> {
        Self::declared(
            "stela-owned-hosted-el1-wfxt-monotonic-ns-v1",
            WfxtDeclaration::RegisterSyndrome,
        )
    }
    fn declared(identity: &'static str, wfxt: WfxtDeclaration) -> Result<Self> {
        let identification = Snapshot::declared(
            identity,
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
                (Register::IdAa64Isar2El1, wfxt.encoded()),
                (Register::IdAa64Isar3El1, 0),
            ],
        )?;
        Self::from_declaration(SoftwareEl1Declaration::new(
            Arc::new(identification),
            SoftwareEl1Security::NonSecureOnly,
        )?)
    }
    pub(in crate::blocks::retirement::checked) fn from_declaration(
        declaration: SoftwareEl1Declaration,
    ) -> Result<Self> {
        let (identification, security) = declaration.into_parts();
        let entry = identification.entry_profile()?;
        let result = Self {
            identification,
            security,
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
        fixed_profile::check(&self.identification)?;
        ensure!(
            (self.identification.read(Register::IdAa64Isar3El1)? >> CPA_SHIFT) & ID_FIELD_MASK == 0,
            "fresh EL1 base address arithmetic requires CPA absence"
        );
        let pfr0 = self.identification.read(Register::IdAa64Pfr0El1)?;
        ensure!(
            (pfr0 >> RME_SHIFT) & ID_FIELD_MASK == 0,
            "fresh EL1 identification does not exclude RME"
        );
        ensure!(
            !self.entry.features().contains(SystemEntryFeature::Gcs),
            "fresh EL1 entry profile requires GCS ownership"
        );
        Ok(())
    }
    /// The PE's declaration must positively exclude FEAT_LSE2; a missing ID
    /// value does not count as absent.
    pub(in crate::blocks::retirement::checked) fn check_pair_read_profile(
        &self,
        system: &SystemState,
    ) -> Result<()> {
        // The same checks, in the same order, as the pair-read producer.
        self.context(system)?;
        let value = self.identification.read(Register::IdAa64Mmfr2El1)?;
        ensure!(
            (value >> LSE2_SHIFT) & ID_FIELD_MASK == 0,
            "same-PE pair read requires positively observed LSE2 absence"
        );
        Ok(())
    }
    pub(in crate::blocks::retirement::checked) fn timer_context(
        &self,
        system: &SystemState,
    ) -> Result<crate::system::timer::Context> {
        use crate::system::timer::{Context, HypervisorControl, KernelControl};
        let profile = self.context(system)?.profile;
        ensure!(
            (self.identification.read(Register::IdAa64Mmfr0El1)? >> ECV_SHIFT) & ID_FIELD_MASK == 0,
            "hosted ordinary-counter profile requires ECV absence"
        );
        // With only EL1 and no EL2/EL3, the EL0 and hypervisor controls do not
        // apply, and there is no writable CNTKCTL, HCR or SCR.
        Ok(Context {
            aa64: true,
            ecv: false,
            ecv_physical_offset: false,
            secure_el2: false,
            profile,
            highest_el: ExceptionLevel::El1,
            have_el2: false,
            el2_aarch64: false,
            el2_in_host: false,
            el0_in_host: false,
            effective_tge: false,
            scr_ecv_enable: false,
            nested_all: false,
            kernel: KernelControl {
                el0_physical_count: false,
                el0_virtual_count: false,
                el0_physical_timer: false,
                el0_virtual_timer: false,
            },
            hypervisor: HypervisorControl {
                el0_physical_count: false,
                el0_virtual_count: false,
                el1_physical_count: false,
                el1_virtual_count_trap: false,
                el0_physical_timer: false,
                el0_virtual_timer: false,
                el1_physical_timer: false,
                el1_physical_timer_host: false,
                el1_virtual_timer_trap: false,
                ecv: false,
            },
        })
    }

    pub(in crate::blocks::retirement::checked) fn context(
        &self,
        system: &SystemState,
    ) -> Result<Context> {
        self.check()?;
        system.check_lower_el_storage().map_err(|error| {
            anyhow::anyhow!("EL1 profile does not own higher-EL storage: {error:?}")
        })?;
        ensure!(
            system.current_el() == ExceptionLevel::El1
                && system.pstate_misc() & (PSTATE_IL_MASK | PSTATE_SS_MASK) == 0,
            "EL1 state requires another execution owner"
        );
        let security = match self.security {
            SoftwareEl1Security::NonSecureOnly => SecurityState::NonSecure,
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
