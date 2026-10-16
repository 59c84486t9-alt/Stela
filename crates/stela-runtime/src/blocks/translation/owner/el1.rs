//! Installing EL1 source and controls for register and literal blocks.
use super::{BlockRuntime, InstalledCodeSources, InstalledEl1Sources};
use crate::{
    memory::domain::physical::{ImmutableCodeBacking, PhysicalAddressSpace},
    system::{
        profile::EntryProfile,
        state::SystemState,
        translation_controls::{ControlProfile, RegisterValues, TranslationControls},
    },
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use anyhow::{Result, ensure};
use stela_compiler::{GuestAddress, block::BlockProfile};
pub(in crate::blocks) struct InstalledEl1Owner {
    runtime: BlockRuntime,
    sources: InstalledEl1Sources,
    controls: TranslationControls,
}
impl InstalledEl1Owner {
    /// # Safety
    /// As for `InstalledM0Owner::new`: every resource belongs to one declared
    /// CPU, and this owner alone publishes, retires and holds the storage for
    /// every alias while the machine runs. The PE, thread, system state,
    /// producers and native finalization checks remain mandatory after
    /// creation.
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
            "fresh EL1 source owner requires typed EL1 direct-B compiler profile"
        );
        ensure!(
            runtime.regions.is_empty() && runtime.loaded.is_empty(),
            "fresh EL1 source owner requires an unbound runtime"
        );
        // SAFETY: this owner hands its source, physical and publication
        // resources to initial publication as described above.
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
            .map_err(|error| anyhow::anyhow!("EL1 initial source fetch: {error:?}"))?;
        owner
            .runtime
            .bind_physical_instruction(scope.installed_snapshot(), reached)?;
        drop(execution);
        Ok(owner)
    }
    pub(in crate::blocks) fn reload_ram_file_prefixes(
        &mut self,
        system: &SystemState,
        pc: GuestAddress,
    ) -> Result<()> {
        self.sources.reload_region_prefixes(&mut self.runtime)?;
        let scope = self.sources.el1_scope().map_err(anyhow::Error::msg)?;
        let execution = scope.physical_space().initial_source_execution_loan()?;
        let reached = scope
            .physical_space()
            .fetch_el1_instruction(&execution, &self.controls, &scope, system, pc.0)
            .map_err(|error| anyhow::anyhow!("RAM reload original source fetch: {error:?}"))?;
        self.runtime
            .bind_physical_instruction(scope.installed_snapshot(), reached)?;
        Ok(())
    }
    /// Consume this owner once for the machine's whole run. The callback
    /// captures the system state so the execution owner can hold it mutably
    /// throughout.
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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;
