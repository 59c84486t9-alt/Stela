//! Fresh original source/controls envelope for the typed EL1 register and literal plans.
//! Source creation only: no PE, native invocation or replacement boot firmware.
use super::{BlockRuntime, InstalledCodeSources, InstalledEl1Sources};
use crate::{
    memory::domain::physical::{ImmutableCodeBacking, PhysicalAddressSpace},
    system::{
        profile::EntryProfile,
        state::SystemState,
        translation_controls::{ControlProfile, RegisterValues, TranslationControls},
    },
};
use anyhow::{Result, ensure};
use stela_compiler::{GuestAddress, block::BlockProfile};
pub(in crate::blocks) struct InstalledEl1Owner {
    runtime: BlockRuntime,
    sources: InstalledEl1Sources,
    controls: TranslationControls,
}
impl InstalledEl1Owner {
    /// # Safety
    /// Same original fresh-machine/physical/source ownership contract as
    /// InstalledM0Owner::new: all resources belong to ONE declared CPU/PE/System;
    /// sole actual publication/retirement and immutable storage rights cover ALL
    /// aliases/participants through the executable scope. No external writer,
    /// firmware/DMA/debugger/NMI/other PE or hidden producer bypasses that owner.
    /// This does not adopt a hardware PE or claim an Apple firmware handoff.
    /// The canonical original PE/outer/ThreadState/System/closed-producer/native
    /// finalization and neutral retirement path remains mandatory after creation.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::blocks) unsafe fn new(
        mut runtime: BlockRuntime,
        physical: PhysicalAddressSpace,
        immutable_sources: Vec<ImmutableCodeBacking>,
        entry_profile: EntryProfile,
        readbacks: RegisterValues,
        control_profile: ControlProfile,
        system: &SystemState,
        source_pc: GuestAddress,
    ) -> Result<Self> {
        ensure!(
            matches!(
                runtime.profile(),
                BlockProfile::El1DirectBranchV1
                    | BlockProfile::El1M0IntegerV1
                    | BlockProfile::El1PlatformV1
            ),
            "fresh EL1 source owner requires actual typed EL1 direct-B compiler profile"
        );
        ensure!(
            runtime.regions.is_empty() && runtime.loaded.is_empty(),
            "fresh EL1 source owner requires an unbound actual runtime"
        );
        // SAFETY: this one actual fresh owner transfers the complete ORIGINAL
        // source/physical/publication ownership described above to shared Initial.
        let (sources, controls) = unsafe {
            InstalledCodeSources::install(
                &mut runtime,
                physical,
                immutable_sources,
                entry_profile,
                readbacks,
                control_profile,
                system,
            )
        }?;
        let mut owner = Self {
            runtime,
            sources,
            controls,
        };
        let scope = owner.sources.el1_scope().map_err(anyhow::Error::msg)?;
        scope
            .check_installed(&owner.controls, system)
            .map_err(anyhow::Error::msg)?;
        let execution = scope
            .physical_space()
            .initial_source_execution_loan()
            .map_err(|error| anyhow::anyhow!("EL1 initial source execution loan: {error:?}"))?;
        let reached = scope
            .physical_space()
            .fetch_el1_instruction(&execution, &owner.controls, &scope, system, source_pc.0)
            .map_err(|error| anyhow::anyhow!("genuine EL1 initial source fetch: {error:?}"))?;
        owner
            .runtime
            .bind_physical_instruction(scope.installed_snapshot(), reached)?;
        drop(execution);
        Ok(owner)
    }
    /// One consuming executable lifetime, sealed by the ORIGINAL consumer key.
    /// Stable outer slots avoid self-reference; no resource tuple/public adoption
    /// escapes and no PE is recreated per run. System is captured by canonical
    /// constructor so it can own the SAME actual mutable System throughout.
    pub(in crate::blocks) fn into_executable_scope<R>(
        mut self,
        _key: &crate::blocks::retirement::ConsumerKey,
        operation: impl for<'run> FnOnce(
            &'run mut BlockRuntime,
            &'run mut InstalledEl1Sources,
            &'run mut TranslationControls,
        ) -> R,
    ) -> Result<R> {
        let scope = self.sources.el1_scope().map_err(anyhow::Error::msg)?;
        self.controls
            .validate_installed_el1_source(&scope)
            .map_err(anyhow::Error::msg)?;
        scope
            .physical_space()
            .check_fetch_execution()
            .map_err(anyhow::Error::msg)?;
        Ok(operation(
            &mut self.runtime,
            &mut self.sources,
            &mut self.controls,
        ))
    }
}
