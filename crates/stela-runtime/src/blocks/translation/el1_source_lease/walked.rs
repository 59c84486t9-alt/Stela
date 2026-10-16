//! EL1 instruction fetch with the MMU enabled.
use super::{INSTRUCTION_BYTES, InstalledEl1SourceScope, SCTLR_M, profile, stage1};
use crate::{
    memory::domain::{
        MemoryExecutionLoan,
        physical::{ImmutableCodeBacking, PhysicalAddressSpace},
    },
    system::{
        state::SystemState,
        translation_controls::{FetchFailure, TranslationControls},
    },
};

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "enabled-source component remains unmounted")
)]
pub(crate) struct InstalledWalkedSource<'loan, 'run> {
    scope: &'loan InstalledEl1SourceScope<'run>,
    controls: &'loan TranslationControls,
    state: &'loan SystemState,
    execution: &'loan MemoryExecutionLoan,
    config: stage1::Config,
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "enabled-source component remains unmounted")
)]
impl<'loan, 'run> InstalledWalkedSource<'loan, 'run> {
    pub(super) fn borrow(
        scope: &'loan InstalledEl1SourceScope<'run>,
        controls: &'loan TranslationControls,
        state: &'loan SystemState,
        execution: &'loan MemoryExecutionLoan,
    ) -> Result<Self, FetchFailure> {
        let config = stage1::Config::from_controls_for_cpu(
            scope
                .installed_snapshot()
                .consumer_inputs()
                .stage1_controls(),
            scope.installed_cpu(),
        )
        .map_err(|_| FetchFailure::Unavailable("enabled installed configuration unavailable"))?;
        let session = Self {
            scope,
            controls,
            state,
            execution,
            config,
        };
        session.check_current()?;
        Ok(session)
    }
    pub(crate) fn check_current(&self) -> Result<(), FetchFailure> {
        self.controls
            .validate_installed_el1_source(self.scope)
            .map_err(FetchFailure::Unavailable)?;
        profile::check_entry(self.state).map_err(FetchFailure::Unavailable)?;
        profile::check_features(
            self.scope.sources.entry_profile(),
            self.scope.installed_snapshot(),
        )
        .map_err(FetchFailure::Unavailable)?;
        if self.scope.installed_snapshot().consumer_inputs().sctlr_el1 & SCTLR_M == 0 {
            return Err(FetchFailure::Unavailable(
                "walked source requires actual enabled MMU",
            ));
        }
        self.physical_space()
            .check_execution_loan(self.execution)
            .map_err(|_| FetchFailure::Unavailable("walked source original outer unavailable"))
    }
    pub(crate) fn physical_space(&self) -> &PhysicalAddressSpace {
        self.scope.physical_space()
    }
    pub(crate) fn execution(&self) -> &MemoryExecutionLoan {
        self.execution
    }
    pub(crate) fn source_cache_controls(&self) -> u64 {
        self.scope.installed_snapshot().consumer_inputs().sctlr_el1
    }
    pub(crate) fn immutable_sources(&self) -> &[ImmutableCodeBacking] {
        self.scope.immutable_sources()
    }
    pub(crate) fn canonical_fetch(&self, raw_pc: u64) -> Result<stage1::Translation, FetchFailure> {
        self.check_current()?;
        if !raw_pc.is_multiple_of(INSTRUCTION_BYTES) {
            return Err(FetchFailure::InstructionAlignment {
                raw_pc,
                exception_level: self.state.current_el(),
            });
        }
        let result = self.scope.installed.cache.translate(
            &self.config,
            self.physical_space(),
            self.execution,
            stage1::Access {
                kind: stage1::AccessKind::Fetch,
                exception_level: stage1::ExceptionLevel::El1,
                raw_virtual_address: raw_pc,
                source_pc: raw_pc,
                pan: false,
                uao: false,
                aligned: true,
            },
        );
        // Health is re-checked even after an architectural failure, so a failed
        // platform cannot look like a guest exception.
        self.check_current()?;
        result.map_err(|error| match error {
            stage1::TranslationError::Fault(fault) => FetchFailure::Architectural(fault),
            stage1::TranslationError::Unsupported(stage1::Unsupported::PhysicalPlatform(
                reason,
            )) => FetchFailure::Platform(reason),
            stage1::TranslationError::Unsupported(_) => {
                FetchFailure::Unavailable("enabled instruction translation unsupported")
            }
        })
    }
    pub(crate) fn check_fetch_policy(
        &self,
        reached: &stage1::Translation,
        raw_pc: u64,
    ) -> Result<(), FetchFailure> {
        self.scope
            .check_fetch_policy(reached, raw_pc, self.state)
            .map_err(FetchFailure::Unavailable)
    }
    pub(crate) fn check_source_word(&self, raw_pc: u64, word: u32) -> Result<(), FetchFailure> {
        self.scope
            .check_source_word(raw_pc, word)
            .map_err(FetchFailure::Unavailable)
    }
}
