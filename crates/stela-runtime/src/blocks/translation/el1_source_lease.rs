//! Readonly ORIGINAL installed source lease for typed EL1 register and literal plans.
//! This retains actual Initial allocation/physical/code storage, never copied
//! descriptors, and grants no PE/native/retirement capability.
use super::{owner::InstalledEl1Sources, profile};
use crate::{
    memory::{
        domain::physical::{ImmutableCodeBacking, PhysicalAddressSpace},
        stage1,
    },
    system::{
        state::SystemState,
        translation_controls::{ControlSnapshot, FetchFailure, TranslationControls},
    },
};
use stela_compiler::{
    GuestAddress,
    block::{BlockProfile, analyze_with_profile},
};
const SCTLR_M: u64 = 1;
const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
pub(crate) struct InstalledEl1SourceScope<'run> {
    sources: &'run InstalledEl1Sources,
    installed: &'run super::scope::InstalledContext,
}
impl<'run> InstalledEl1SourceScope<'run> {
    pub(super) fn borrow(sources: &'run InstalledEl1Sources) -> Result<Self, &'static str> {
        Ok(Self {
            sources,
            installed: sources.installed()?,
        })
    }
    pub(crate) fn physical_space(&self) -> &PhysicalAddressSpace {
        self.sources.physical_space()
    }
    pub(crate) fn installed_snapshot(&self) -> &ControlSnapshot {
        &self.installed.snapshot
    }
    pub(crate) fn installed_cpu(&self) -> stage1::CpuProfile {
        self.installed.cpu
    }
    pub(crate) fn immutable_sources(&self) -> &[ImmutableCodeBacking] {
        self.sources.immutable_sources()
    }
    pub(crate) fn check_installed(
        &self,
        owner: &TranslationControls,
        state: &SystemState,
    ) -> Result<(), &'static str> {
        owner.validate_installed_el1_source(self)?;
        profile::check_entry(state)?;
        profile::check_features(self.sources.entry_profile(), self.installed_snapshot())?;
        if self.installed_snapshot().consumer_inputs().sctlr_el1 & SCTLR_M != 0 {
            return Err("EL1 installed source context is not MMU-disabled");
        }
        self.physical_space().check_fetch_execution()
    }
    pub(crate) fn canonical_fetch(
        &self,
        owner: &TranslationControls,
        state: &SystemState,
        pc: u64,
    ) -> Result<stage1::Translation, FetchFailure> {
        self.check_installed(owner, state)
            .map_err(FetchFailure::Unavailable)?;
        if !pc.is_multiple_of(INSTRUCTION_BYTES) {
            return Err(FetchFailure::InstructionAlignment {
                raw_pc: pc,
                exception_level: state.current_el(),
            });
        }
        let config = stage1::Config::from_controls_for_cpu(
            self.installed_snapshot()
                .consumer_inputs()
                .stage1_controls(),
            self.installed_cpu(),
        )
        .map_err(|_| FetchFailure::Unavailable("installed EL1 source configuration unavailable"))?;
        stage1::translate(
            &config,
            self.physical_space(),
            stage1::Access {
                kind: stage1::AccessKind::Fetch,
                exception_level: stage1::ExceptionLevel::El1,
                raw_virtual_address: pc,
                source_pc: pc,
                pan: false,
                uao: false,
                aligned: true,
            },
        )
        .map_err(|error| match error {
            stage1::TranslationError::Fault(fault) => FetchFailure::Architectural(fault),
            stage1::TranslationError::Unsupported(stage1::Unsupported::PhysicalPlatform(
                reason,
            )) => FetchFailure::Platform(reason),
            stage1::TranslationError::Unsupported(_) => {
                FetchFailure::Unavailable("installed EL1 instruction translation unavailable")
            }
        })
    }
    pub(crate) fn check_fetch_policy(
        &self,
        translation: &stage1::Translation,
        raw_pc: u64,
        state: &SystemState,
    ) -> Result<(), &'static str> {
        profile::check_immutable_fetch(translation, raw_pc, state)
    }
    pub(crate) fn check_source_word(&self, pc: u64, word: u32) -> Result<(), &'static str> {
        // The actual immutable compiler profile decodes one reached word.
        // No descriptive bitmask or legacy whitelist supplies admission.
        if !matches!(
            self.sources.compiler_profile(),
            BlockProfile::El1DirectBranchV1
                | BlockProfile::El1M0IntegerV1
                | BlockProfile::El1PlatformV1
        ) {
            return Err("installed integer source profile differs");
        }
        let analysis = analyze_with_profile(
            &word.to_le_bytes(),
            GuestAddress(pc),
            self.sources.compiler_profile(),
        )
        .map_err(|_| "installed EL1 source is outside the actual typed EL1 plan")?;
        if analysis.source_bytes != INSTRUCTION_BYTES as usize {
            return Err("installed EL1 analysis extent differs");
        }
        Ok(())
    }
}

pub(super) mod walked;
impl<'run> InstalledEl1SourceScope<'run> {
    /// Readonly enabled fetch/refill loan. Existing MMU-off admission is intact.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "enabled-source component remains unmounted")
    )]
    pub(crate) fn walked<'loan>(
        &'loan self,
        controls: &'loan TranslationControls,
        state: &'loan SystemState,
        execution: &'loan crate::memory::domain::MemoryExecutionLoan,
    ) -> Result<walked::InstalledWalkedSource<'loan, 'run>, FetchFailure> {
        walked::InstalledWalkedSource::borrow(self, controls, state, execution)
    }
}
