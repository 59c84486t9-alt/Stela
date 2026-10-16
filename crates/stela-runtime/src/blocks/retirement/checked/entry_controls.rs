//! Actual fresh-software debug controls and distinct retained execution scopes.
//! LR execution does not manufacture an LR-absent exception-entry token.
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
    /// These are this fresh software PE's sole actual declared controls. Retain
    /// them through the sole execution owner and complete producer registry.
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
    /// The Arc is the SAME immutable Snapshot allocation as the actual fixed
    /// control bank of this fresh PE; no hardware/diagnostic adoption occurs.
    /// Other owner/producer obligations are identical to fresh_software.
    #[cfg(feature = "std")]
    pub(crate) unsafe fn fresh_software_link_register_pauth(
        snapshot: &Arc<Snapshot>,
        spe: BaseSpeAbsence,
        mdscr_el1: u64,
        debug: DebugControls,
    ) -> Result<Self> {
        snapshot.non_pauth_entry_absence()?;
        LinkRegisterPauthCapability::from_profile(snapshot)
            .map_err(|error| anyhow::anyhow!("actual LR profile: {error:?}"))?;
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
    pub(super) fn exception_controls(
        &self,
        controls: &crate::system::translation_controls::TranslationControls,
    ) -> Result<crate::system::exception::EntryControls> {
        self.check()?;
        let snapshot = controls
            .snapshot()
            .map_err(|error| anyhow::anyhow!("original exception controls: {error:?}"))?;
        Ok(crate::system::exception::EntryControls {
            tcr_el1: snapshot.consumer_inputs().tcr_el1,
            mdscr_el1: self.mdscr_el1,
            debug: self.debug,
        })
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
            "unsupported actual debug/step producer state"
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
                let ids = identification.context("actual LR identification owner unavailable")?;
                ensure!(
                    snapshot.same_snapshot(ids),
                    "actual LR feature and memory bank snapshots differ"
                );
                snapshot.non_pauth_entry_absence()?;
                LinkRegisterPauthCapability::from_profile(snapshot)
                    .map_err(|error| anyhow::anyhow!("actual LR profile: {error:?}"))?;
                ensure!(
                    system.pacm_state_feature() == PacmStateFeature::Full,
                    "actual full PACM storage unavailable"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "entry_controls/tests.rs"]
mod tests;
