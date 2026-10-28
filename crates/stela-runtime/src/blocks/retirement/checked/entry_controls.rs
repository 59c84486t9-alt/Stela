//! Debug controls of a software PE and the execution scopes derived from them.
#[cfg(feature = "std")]
use crate::pauth::features::LinkRegisterPauthCapability;
use crate::system::{
    debug::DebugControls,
    identification_snapshot::Snapshot,
    profile::{BaseSpeAbsence, EntryProfile},
    state::{PacmStateFeature, SystemState},
};
#[cfg(feature = "std")]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use anyhow::Context;
use anyhow::{Result, ensure};
const MDSCR_SOFTWARE_STEP: u64 = 1;
const MDSCR_KERNEL_DEBUG_ENABLE: u64 = 1 << 13;
const MDSCR_MONITOR_DEBUG_ENABLE: u64 = 1 << 15;
const MDSCR_ACTIVE_DEBUG: u64 =
    MDSCR_SOFTWARE_STEP | MDSCR_KERNEL_DEBUG_ENABLE | MDSCR_MONITOR_DEBUG_ENABLE;
enum FeatureScope {
    Base(EntryProfile),
    #[cfg(feature = "std")]
    LinkRegister(Arc<Snapshot>),
}
pub(crate) struct ProcessEntryControls {
    features: FeatureScope,
    _spe: BaseSpeAbsence,
    mdscr_el1: u64,
    debug: DebugControls,
}
impl ProcessEntryControls {
    /// # Safety
    /// These are this software PE's declared controls; keep them for as long as
    /// the PE runs.
    pub(crate) unsafe fn fresh_software(
        features: EntryProfile,
        spe: BaseSpeAbsence,
        mdscr_el1: u64,
        debug: DebugControls,
    ) -> Result<Self> {
        let owner = Self {
            features: FeatureScope::Base(features),
            _spe: spe,
            mdscr_el1,
            debug,
        };
        owner.check()?;
        Ok(owner)
    }
    /// # Safety
    /// The Arc is the same snapshot allocation as this PE's fixed controls.
    /// Otherwise as for `fresh_software`.
    #[cfg(feature = "std")]
    pub(crate) unsafe fn fresh_software_link_register_pauth(
        snapshot: &Arc<Snapshot>,
        spe: BaseSpeAbsence,
        mdscr_el1: u64,
        debug: DebugControls,
    ) -> Result<Self> {
        snapshot.non_pauth_entry_absence()?;
        LinkRegisterPauthCapability::from_profile(snapshot)
            .map_err(|error| anyhow::anyhow!("LR profile: {error:?}"))?;
        let owner = Self {
            features: FeatureScope::LinkRegister(Arc::clone(snapshot)),
            _spe: spe,
            mdscr_el1,
            debug,
        };
        owner.check()?;
        Ok(owner)
    }
    #[cfg(feature = "std")]
    pub(super) fn link_register(&self) -> bool {
        matches!(self.features, FeatureScope::LinkRegister(_))
    }

    pub(crate) fn debug_controls(&self) -> &DebugControls {
        &self.debug
    }
    pub(super) fn check(&self) -> Result<()> {
        let debug = self.debug_controls();
        ensure!(
            self.mdscr_el1 & MDSCR_ACTIVE_DEBUG == 0
                && !debug.halted
                && !debug.ignore_traps_in_debug
                && !debug.halting_allowed
                && !debug.edscr_tda
                && debug.breakpoint_count == 0
                && debug.watchpoint_count == 0
                && debug.raw_bank == 0
                && debug.effective_bank == 0,
            "unsupported debug/step producer state"
        );
        Ok(())
    }
    pub(super) fn check_snapshot(
        &self,
        identification: Option<&Snapshot>,
        system: &SystemState,
    ) -> Result<()> {
        match &self.features {
            FeatureScope::Base(profile) => {
                if let Some(ids) = identification {
                    ids.check_entry_profile(*profile)?;
                }
                ensure!(
                    system.pacm_state_feature() == PacmStateFeature::Absent,
                    "base entry scope has unqualified PACM storage"
                );
            }
            #[cfg(feature = "std")]
            FeatureScope::LinkRegister(snapshot) => {
                let ids = identification.context("LR identification owner unavailable")?;
                ensure!(
                    snapshot.same_snapshot(ids),
                    "LR feature and memory bank snapshots differ"
                );
                snapshot.non_pauth_entry_absence()?;
                LinkRegisterPauthCapability::from_profile(snapshot)
                    .map_err(|error| anyhow::anyhow!("LR profile: {error:?}"))?;
                ensure!(
                    system.pacm_state_feature() == PacmStateFeature::Full,
                    "full PACM storage unavailable"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{identification::Register, state::El1Registers};
    const A64_EL0_EL1: u64 = 0x11;
    const APA_SHIFT: u32 = 4;
    const APA_LR: u64 = 6;
    const PACM_FULL: u64 = 2 << 12;

    fn snapshot() -> Arc<Snapshot> {
        Arc::new(
            Snapshot::declared(
                "actual-lr-entry-tests",
                &[
                    (Register::IdAa64Isar1El1, APA_LR << APA_SHIFT),
                    (Register::IdAa64Isar2El1, 0),
                    (Register::IdAa64Isar3El1, PACM_FULL),
                    (Register::IdAa64Pfr0El1, A64_EL0_EL1),
                    (Register::IdAa64Pfr1El1, 0),
                    (Register::IdAa64Pfr2El1, 0),
                    (Register::IdAa64Dfr0El1, 0),
                    (Register::IdAa64Dfr1El1, 0),
                    (Register::IdAa64Mmfr0El1, 0),
                    (Register::IdAa64Mmfr1El1, 0),
                    (Register::IdAa64Mmfr2El1, 0),
                    (Register::IdAa64Mmfr3El1, 0),
                ],
            )
            .unwrap(),
        )
    }
    fn controls(ids: &Arc<Snapshot>) -> ProcessEntryControls {
        // SAFETY: locally declared test controls.
        unsafe {
            ProcessEntryControls::fresh_software_link_register_pauth(
                ids,
                ids.base_spe_absence().unwrap(),
                0,
                DebugControls::default(),
            )
        }
        .unwrap()
    }
    fn system(feature: PacmStateFeature) -> SystemState {
        SystemState::new_with_pacm(0, 0, El1Registers::new(0, 0, 0, 0, 0), feature).unwrap()
    }

    #[test]
    fn lr_scope_requires_original_snapshot_allocation_and_full_storage() {
        let ids = snapshot();
        let owner = controls(&ids);
        assert!(
            owner
                .check_snapshot(Some(&ids), &system(PacmStateFeature::Full))
                .is_ok()
        );
        assert!(
            owner
                .check_snapshot(Some(&snapshot()), &system(PacmStateFeature::Full))
                .is_err()
        );
        assert!(
            owner
                .check_snapshot(None, &system(PacmStateFeature::Full))
                .is_err()
        );
        assert!(
            owner
                .check_snapshot(Some(&ids), &system(PacmStateFeature::Absent))
                .is_err()
        );
    }

    #[test]
    fn lr_scope_does_not_manufacture_lr_absent_entry_profile() {
        let ids = snapshot();
        assert!(ids.non_pauth_entry_absence().is_ok());
        assert!(ids.entry_profile().is_err());
        assert!(controls(&ids).link_register());
    }

    #[test]
    fn fresh_lr_scope_rejects_actual_halted_or_step_controls() {
        let ids = snapshot();
        for (mdscr, debug) in [
            (MDSCR_SOFTWARE_STEP, DebugControls::default()),
            (
                0,
                DebugControls {
                    halted: true,
                    ..DebugControls::default()
                },
            ),
        ] {
            // SAFETY: locally declared test controls, which the constructor must
            // refuse.
            assert!(
                unsafe {
                    ProcessEntryControls::fresh_software_link_register_pauth(
                        &ids,
                        ids.base_spe_absence().unwrap(),
                        mdscr,
                        debug,
                    )
                }
                .is_err()
            );
        }
    }
}
