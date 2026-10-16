//! Sole-PE owner of actual code execution and physical mutation authority.

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
use anyhow::{Result, ensure};
use std::sync::Arc;
use stela_compiler::{
    GuestAddress,
    block::{BlockProfile, CheckedMemoryProfile},
};

/// Original installed source resources produced once by actual Initial
/// publication over this machine's M0-profile runtime. No legacy raw owner is
/// constructed, and no copied snapshot/config can create these private fields.
pub(in crate::blocks) struct InstalledCodeSources {
    context: ContextState,
    runtime_identity: Arc<()>,
    compiler_profile: BlockProfile,
    physical: PhysicalAddressSpace,
    immutable_sources: Vec<ImmutableCodeBacking>,
    entry_profile: EntryProfile,
}

// Preserve the existing LDR-only source API. The alias itself grants nothing;
// InstalledM0SourceScope still performs its exact existing source qualification.
pub(in crate::blocks) type InstalledM0Sources = InstalledCodeSources;
pub(in crate::blocks) type InstalledEl1Sources = InstalledCodeSources;

#[path = "owner/el1.rs"]
mod el1;
pub(in crate::blocks) use el1::InstalledEl1Owner;

impl InstalledCodeSources {
    /// Reuse the ORIGINAL Initial installation/storage producer. This is not
    /// profile/source admission, a PE constructor or a mutable control-bank copy.
    /// The typed cohort's fresh owner must separately check its actual runtime
    /// profile, perform genuine source fetch/registration and retain this storage
    /// with the sole returned controls through its one executable scope.
    ///
    /// # Safety
    /// InstalledM0Owner::new's actual same-machine physical/source retirement,
    /// immutable backing, complete producer and no-alias ownership obligations
    /// apply to these original resources. No external participant may bypass
    /// this sole Initial publisher. No native entry occurs here.
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
            !immutable_sources.is_empty(),
            "fresh M0 source owner requires actual immutable instruction owners"
        );
        super::super::platform::ensure_supported()?;
        physical
            .check_fetch_execution()
            .map_err(anyhow::Error::msg)?;
        let mut context = ContextState::Unbound;
        // This is the original concrete Initial preparation/commit service:
        // one context allocation and the SAME physical MemorySystem. It never
        // constructs the legacy System-only owner or changes runtime.profile.
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

    /// Loan the SAME installed context/physical/code owners after native return.
    /// The canonical consumer separately binds the exact returned source and
    /// retains its original PE, outer and control loans through publication.
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

/// Fresh private owner of the ONE actual M0 runtime, installed source resources
/// and sole TranslationControls bank returned by real Initial publication.
/// There is no legacy step method, profile transition, public tuple or raw-parts
/// extraction. A canonical PE factory consumes this envelope once.
pub(in crate::blocks) struct InstalledM0Owner {
    runtime: BlockRuntime,
    sources: InstalledM0Sources,
    controls: TranslationControls,
}

impl InstalledM0Owner {
    /// Install the sole live control bank directly over the actual M0 runtime.
    ///
    /// # Safety
    /// The caller is the actual fresh machine/source-RAM owner. The runtime,
    /// genuine physical role/domain, immutable source storage, EntryProfile,
    /// readbacks and ControlProfile belong to the SAME declared CPU/PE/System.
    /// It transfers sole physical-view retirement and descriptor/source
    /// publication authority for ALL aliases and participants until this
    /// envelope and every synchronous field-split loan are dropped. No retained
    /// MemoryDomain/System writer, raw pointer, DMA, firmware, debugger, NMI,
    /// async work or other PE can bypass that authority. Source storage satisfies
    /// the actual native RO/coherence/lifetime contract of ImmutableCodeBacking;
    /// no guest/host writable alias or Rust reference to it survives. No active
    /// debug/IRQ/timer/cache-maintenance/trace producer can observe omitted
    /// effects. The genuine root physical factory must establish these facts;
    /// labels, Configs, snapshots or arbitrary domain constructors cannot.
    /// Canonical actual PE ownership, exact outer/thread/domain/source/RX checks,
    /// the no-read prepared session and once-only state/PC settlement are
    /// independently required before any native invocation. This constructor
    /// performs real Initial installation and original instruction registration,
    /// but no native invocation or guest data transaction.
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
        // SAFETY: this same fresh owner transfers its original physical/source
        // resources under the complete contract above, to the sole Initial
        // producer. The original typed profile/empty-runtime checks precede it.
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
        // Exactly one short construction loan, before any PE exists. Retain
        // it through BOTH the original instruction read and its registration;
        // current NativeActive revalidation instead borrows its exact outer.
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

    /// Consume this fresh envelope ONCE for the complete executable lifetime.
    /// The sole canonical consumer key seals its disjoint field split. The
    /// canonical fresh-machine callback constructs its one SystemExecutionOwner
    /// and retains original ThreadState/System/backend resources until shutdown;
    /// it cannot recreate PE authority for repeated per-run callbacks. All loans
    /// stay inside this one callback and no public tuple or owner escapes.
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
        // Do not borrow System here: the canonical callback must capture its
        // ORIGINAL System mutably for the sole actual execution owner. Initial
        // construction checked it; each actual M0 input rechecks that same PE
        // System through the retained scope/control/source authority.
        Ok(operation(
            &mut self.runtime,
            &mut self.sources,
            &mut self.controls,
        ))
    }
}
