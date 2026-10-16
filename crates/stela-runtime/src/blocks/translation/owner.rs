//! The owner of code execution and physical memory changes on a PE.

use super::{
    BlockRuntime, profile,
    scope::{ContextState, ControlCodeScope, InstalledContext},
    source_lease::InstalledM0SourceScope,
};
use crate::{
    memory::domain::physical::{ImmutableCodeBacking, PhysicalAddressSpace},
    system::{
        profile::EntryProfile,
        state::SystemState,
        translation_controls::{ControlProfile, RegisterValues, TranslationControls},
    },
};
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use anyhow::{Result, ensure};
use stela_compiler::{
    GuestAddress,
    block::{BlockProfile, CheckedMemoryProfile},
};

/// The installed source resources, produced once by initial publication over
/// this machine's M0 runtime.
pub(in crate::blocks) struct InstalledCodeSources {
    context: ContextState,
    runtime_identity: Arc<()>,
    compiler_profile: BlockProfile,
    physical: PhysicalAddressSpace,
    immutable_sources: Vec<ImmutableCodeBacking>,
    entry_profile: EntryProfile,
}

// Name kept for the LDR-only source API.
pub(in crate::blocks) type InstalledM0Sources = InstalledCodeSources;
pub(in crate::blocks) type InstalledEl1Sources = InstalledCodeSources;

mod el1;
pub(in crate::blocks) use el1::InstalledEl1Owner;

impl InstalledCodeSources {
    /// Reuse the initial installation. Profile admission, PE construction and
    /// the control bank are the caller's: it checks the runtime profile,
    /// fetches and registers the source, and keeps this storage with the
    /// returned controls while it runs.
    ///
    /// # Safety
    /// As for `InstalledM0Owner::new`. Nothing else may publish initial state.
    /// No native code runs here.
    #[allow(clippy::too_many_arguments)]
    unsafe fn install(
        runtime: &mut BlockRuntime,
        physical: PhysicalAddressSpace,
        immutable_sources: Vec<ImmutableCodeBacking>,
        entry_profile: EntryProfile,
        readbacks: RegisterValues,
        control_profile: ControlProfile,
        system: &SystemState,
    ) -> Result<(Self, TranslationControls)> {
        ensure!(
            !immutable_sources.is_empty() || physical.owns_mutable_instruction_sources(),
            "fresh source owner requires actual immutable or factory-owned mutable instruction owners"
        );
        super::super::platform::ensure_supported()?;
        physical
            .check_fetch_execution()
            .map_err(anyhow::Error::msg)?;
        let mut context = ContextState::Unbound;
        // The initial preparation and commit: one context allocation on the
        // same physical memory system, leaving the runtime profile unchanged.
        let controls = {
            let memory = Arc::clone(physical.memory_system());
            let mut initial = ControlCodeScope {
                runtime,
                physical: &physical,
                immutable_sources: &immutable_sources,
                entry_profile,
                context: &mut context,
                _outer: None,
            };
            TranslationControls::install(readbacks, control_profile, memory, system, &mut initial)
                .map_err(|error| anyhow::anyhow!("genuine M0 Initial installation: {error:?}"))?
        };
        ensure!(
            matches!(context, ContextState::Installed(_)),
            "genuine M0 Initial publication did not install its context"
        );
        Ok((
            Self {
                context,
                runtime_identity: Arc::clone(&runtime.identity),
                compiler_profile: runtime.profile(),
                physical,
                immutable_sources,
                entry_profile,
            },
            controls,
        ))
    }

    fn reload_region_prefixes(&mut self, runtime: &mut BlockRuntime) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&runtime.identity, &self.runtime_identity),
            "RAM reload cache is not the original installed runtime"
        );
        // Every native and source borrow has ended; release the dependent
        // native code first.
        runtime.retire_translation_sources();
        self.physical
            .reload_original_region_prefixes()
            .map_err(|error| anyhow::anyhow!("RAM file-prefix reload: {error:?}"))?;
        Ok(())
    }

    pub(in crate::blocks) fn el1_scope(
        &self,
    ) -> Result<super::el1_source_lease::InstalledEl1SourceScope<'_>, &'static str> {
        super::el1_source_lease::InstalledEl1SourceScope::borrow(self)
    }

    pub(in crate::blocks) fn source_scope(
        &self,
    ) -> Result<InstalledM0SourceScope<'_>, &'static str> {
        InstalledM0SourceScope::borrow(self)
    }
    pub(super) fn compiler_profile(&self) -> BlockProfile {
        self.compiler_profile
    }

    pub(super) fn installed(&self) -> Result<&InstalledContext, &'static str> {
        match &self.context {
            ContextState::Installed(current) => Ok(current),
            ContextState::Unbound => Err("original source context is unbound"),
            ContextState::Failed => Err("original source publication has failed"),
        }
    }

    /// Hold the RAM and source participants while the EL1 owner completes a
    /// DSB. The source and runtime borrows exclude other publication or cache
    /// and context changes. The machine owns every physical alias and excludes
    /// external memory masters; arbitrary MMIO or DMA completion is not
    /// covered.
    pub(in crate::blocks) fn ram_completion_scope<'run>(
        &'run self,
        runtime: &'run BlockRuntime,
        controls: &TranslationControls,
        system: &SystemState,
        outer: &crate::memory::domain::MemoryExecutionLoan,
    ) -> Result<super::el1_source_lease::InstalledEl1SourceScope<'run>, &'static str> {
        if !Arc::ptr_eq(&runtime.identity, &self.runtime_identity)
            || runtime.profile() != self.compiler_profile
            || self.compiler_profile != BlockProfile::El1PlatformV1
        {
            return Err("RAM completion requires the original installed platform/cache");
        }
        self.physical
            .check_execution_loan(outer)
            .map_err(|_| "RAM completion original physical/outer differs")?;
        // Installed excludes Unbound and Failed. Every context publication
        // finishes before returning to the PE, and this factory has no deferred
        // maintenance.
        let scope = self.el1_scope()?;
        scope.check_installed(controls, system)?;
        Ok(scope)
    }

    /// Lend the installed context, physical memory and code after native
    /// return. The consumer binds the returned source and keeps its PE, outer
    /// and control borrows through publication.
    pub(in crate::blocks) fn publication_scope<'run>(
        &'run mut self,
        runtime: &'run mut BlockRuntime,
        controls: &TranslationControls,
        system: &SystemState,
        outer: &'run crate::memory::domain::MemoryExecutionLoan,
    ) -> Result<ControlCodeScope<'run>, &'static str> {
        if !Arc::ptr_eq(&runtime.identity, &self.runtime_identity) {
            return Err("publication runtime is not the original installed source cache");
        }
        if runtime.profile() != self.compiler_profile {
            return Err("publication runtime profile differs from original installed source");
        }
        self.physical
            .check_execution_loan(outer)
            .map_err(|_| "publication uses a different/unavailable original outer")?;
        let source = self.el1_scope()?;
        controls.validate_installed_el1_source(&source)?;
        profile::check_entry(system)?;
        profile::check_features(self.entry_profile, source.installed_snapshot())?;
        self.physical.check_fetch_execution()?;
        Ok(ControlCodeScope {
            runtime,
            physical: &self.physical,
            immutable_sources: &self.immutable_sources,
            entry_profile: self.entry_profile,
            context: &mut self.context,
            _outer: Some(outer),
        })
    }
    pub(super) fn physical_space(&self) -> &PhysicalAddressSpace {
        &self.physical
    }
    pub(super) fn immutable_sources(&self) -> &[ImmutableCodeBacking] {
        &self.immutable_sources
    }
    pub(super) fn entry_profile(&self) -> EntryProfile {
        self.entry_profile
    }
}

/// Private owner of the M0 runtime, its installed source and its translation
/// controls. A PE factory consumes it once.
pub(in crate::blocks) struct InstalledM0Owner {
    runtime: BlockRuntime,
    sources: InstalledM0Sources,
    controls: TranslationControls,
}

impl InstalledM0Owner {
    /// Install the control bank over the M0 runtime.
    ///
    /// # Safety
    /// The caller owns the new machine and its source RAM. The runtime,
    /// physical domain, source storage, entry profile, readbacks and control
    /// profile all belong to the same declared CPU. Until this owner and every
    /// borrow split from it are dropped, it alone may retire physical views and
    /// publish descriptors and source for every alias: no memory-domain or
    /// system writer, raw pointer, DMA, firmware, debugger, NMI, asynchronous
    /// work or other PE may bypass it. The source storage meets the read-only,
    /// coherence and lifetime contract of `ImmutableCodeBacking`, with no
    /// writable alias or Rust reference surviving. No debug, IRQ, timer,
    /// cache-maintenance or trace producer can observe skipped effects. The PE
    /// checks and PC settlement are still required before any native call; this
    /// constructor only installs and registers the instructions.
    #[allow(clippy::too_many_arguments)] // Explicit actual resource/control inputs at the unsafe boundary.
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
            runtime.profile()
                == BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged),
            "fresh M0 source owner requires the actual staged M0 compiler profile"
        );
        ensure!(
            runtime.regions.is_empty() && runtime.loaded.is_empty(),
            "fresh M0 source owner requires an unbound actual runtime"
        );
        // SAFETY: this owner hands its physical and source resources to initial
        // publication under the contract above, after the profile and
        // empty-runtime checks.
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
        let scope = owner.sources.source_scope().map_err(anyhow::Error::msg)?;
        scope
            .check_installed(&owner.controls, system)
            .map_err(anyhow::Error::msg)?;
        // One short construction borrow before any PE exists, held across both
        // the instruction read and its registration.
        let source_execution = scope
            .physical_space()
            .initial_source_execution_loan()
            .map_err(|error| anyhow::anyhow!("M0 initial source execution loan: {error:?}"))?;
        let reached = scope
            .physical_space()
            .fetch_m0_instruction(
                &source_execution,
                &owner.controls,
                &scope,
                system,
                source_pc.0,
            )
            .map_err(|error| anyhow::anyhow!("genuine M0 initial source fetch: {error:?}"))?;
        owner
            .runtime
            .bind_physical_instruction(scope.installed_snapshot(), reached)?;
        drop(source_execution);
        Ok(owner)
    }

    pub(in crate::blocks) fn reload_ram_file_prefixes(
        &mut self,
        system: &SystemState,
        pc: GuestAddress,
    ) -> Result<()> {
        self.sources.reload_region_prefixes(&mut self.runtime)?;
        let scope = self.sources.source_scope().map_err(anyhow::Error::msg)?;
        let execution = scope.physical_space().initial_source_execution_loan()?;
        let reached = scope
            .physical_space()
            .fetch_m0_instruction(&execution, &self.controls, &scope, system, pc.0)
            .map_err(|error| anyhow::anyhow!("RAM reload original source fetch: {error:?}"))?;
        self.runtime
            .bind_physical_instruction(scope.installed_snapshot(), reached)?;
        Ok(())
    }

    /// Consume this owner once for the machine's whole run. The callback builds
    /// the execution owner and keeps the thread state, system state and backend
    /// until shutdown; no borrow or owner escapes.
    pub(in crate::blocks) fn into_executable_scope<R>(
        mut self,
        _key: &crate::blocks::retirement::ConsumerKey,
        operation: impl for<'run> FnOnce(
            &'run mut BlockRuntime,
            &'run mut InstalledM0Sources,
            &'run mut TranslationControls,
        ) -> R,
    ) -> Result<R> {
        let scope = self.sources.source_scope().map_err(anyhow::Error::msg)?;
        self.controls
            .validate_installed_m0_source(&scope)
            .map_err(anyhow::Error::msg)?;
        scope
            .physical_space()
            .check_fetch_execution()
            .map_err(anyhow::Error::msg)?;
        // Do not borrow the system state here: the callback captures it mutably
        // for the execution owner. Construction checked it, and each M0 input
        // re-checks it.
        Ok(operation(
            &mut self.runtime,
            &mut self.sources,
            &mut self.controls,
        ))
    }
}
