//! Genuine installed-context/source lease for bounded M0 data cohorts.
//!
//! Construction accepts only the original private resources created by real
//! Initial publication over the actual fresh M0 runtime. No Config, copied
//! snapshot, Arc label or source descriptor can create this lease. The runtime
//! and its original CodeRegion registry are separate disjoint owner fields.

use super::{owner::InstalledM0Sources, profile};
use crate::{
    blocks::retirement::M0SourceInput,
    memory::{
        domain::{
            m0_read::{M0ScalarReadSource, pair::M0ReadPairSource},
            m0_write::M0WriteSource,
            physical::{BoundPhysicalInstruction, ImmutableCodeBacking, PhysicalAddressSpace},
        },
        stage1,
    },
    system::{
        state::SystemState,
        translation_controls::{ControlSnapshot, FetchFailure, TranslationControls},
    },
};
use stela_compiler::{GuestAddress, Lifter, aarch64::Decoder};

const SCTLR_M: u64 = 1;
const SCTLR_EE: u64 = 1 << 25;
const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;

/// Non-Clone, non-Copy, externally unconstructible and read-only. It retains the
/// ORIGINAL installed context allocation, physical authority and immutable code
/// owners. It borrows neither the whole runtime nor its mutable native cache.
pub(crate) struct InstalledM0SourceScope<'run> {
    sources: &'run InstalledM0Sources,
    installed: &'run super::scope::InstalledContext,
}

impl<'run> InstalledM0SourceScope<'run> {
    pub(super) fn borrow(sources: &'run InstalledM0Sources) -> Result<Self, &'static str> {
        Ok(Self {
            sources,
            installed: sources.installed()?,
        })
    }

    pub(crate) fn physical_space(&self) -> &PhysicalAddressSpace {
        self.sources.physical_space()
    }

    /// Read the original installed slot, never a reconstructed control bank.
    pub(crate) fn installed_snapshot(&self) -> &ControlSnapshot {
        &self.installed.snapshot
    }

    pub(crate) fn installed_cpu(&self) -> stage1::CpuProfile {
        self.installed.cpu
    }

    pub(crate) fn immutable_sources(&self) -> &[ImmutableCodeBacking] {
        self.sources.immutable_sources()
    }

    /// Actual live owner identity/generation/CPU/memory checks precede fetch.
    /// The real TranslationControls implementation owns those comparisons;
    /// accepting this concrete opaque scope does not add any bank field.
    pub(crate) fn check_installed(
        &self,
        owner: &TranslationControls,
        state: &SystemState,
    ) -> Result<(), &'static str> {
        owner.validate_installed_m0_source(self)?;
        profile::check_entry(state)?;
        profile::check_features(self.sources.entry_profile(), self.installed_snapshot())?;
        if self.installed_snapshot().consumer_inputs().sctlr_el1 & SCTLR_M != 0 {
            return Err("installed source context is not MMU-disabled");
        }
        if self.installed_snapshot().consumer_inputs().sctlr_el1 & SCTLR_EE != 0 {
            return Err("installed M0 data cohort is not little-endian");
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
        .map_err(|_| FetchFailure::Unavailable("installed M0 source configuration unavailable"))?;
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
                FetchFailure::Unavailable("installed M0 instruction translation unavailable")
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

    /// Exact canonical read/write source shapes under the installed immutable
    /// cohort. Shape classification alone grants no data or control authority;
    /// the separate typed System/ISB source lane retains its own qualifier.
    pub(crate) fn check_source_word(&self, pc: u64, word: u32) -> Result<(), &'static str> {
        check_data_source_word(self.sources.compiler_profile(), pc, word)
    }

    /// Re-fetch actual original bytes/Execute rights using the original installed
    /// context and physical owner, then compare the SINGLE original CodeRegion
    /// physical binding through the canonical input's actual BoundSource.
    /// Logical RX/plan checks alone never establish installed source currency.
    pub(crate) fn qualify_source(
        &self,
        owner: &TranslationControls,
        input: &M0SourceInput<'_, '_>,
    ) -> Result<(), FetchFailure> {
        self.pin_source(owner, input).map(|_| ())
    }

    /// Retain the original actual fetch for an in-flight modifying instruction.
    pub(crate) fn pin_source(
        &self,
        owner: &TranslationControls,
        input: &M0SourceInput<'_, '_>,
    ) -> Result<BoundPhysicalInstruction, FetchFailure> {
        input.validate_source_current().map_err(|_| {
            FetchFailure::Unavailable("M0 logical source/RX/plan association changed")
        })?;
        self.check_installed(owner, input.actual_system())
            .map_err(FetchFailure::Unavailable)?;
        self.physical_space()
            .check_execution_loan(input.outer_execution())
            .map_err(|_| {
                FetchFailure::Unavailable(
                    "M0 source uses a different/unavailable outer execution loan",
                )
            })?;

        // This is the ORIGINAL retained NativeActive outer object. The
        // physical reader must borrow it and must not mint a nested loan.
        let reached: BoundPhysicalInstruction = self.physical_space().fetch_m0_instruction(
            input.outer_execution(),
            owner,
            self,
            input.actual_system(),
            input.source_pc().0,
        )?;
        if reached.raw_pc() != input.source_pc().0
            || reached.word() != input.source_word()
            || input.source_bytes() != reached.word().to_le_bytes()
        {
            return Err(FetchFailure::Unavailable(
                "installed M0 original word differs from actual source input",
            ));
        }
        input
            .validate_installed_fetch(self, &reached)
            .map_err(|_| {
                FetchFailure::Unavailable(
                    "installed M0 physical source differs from actual registered source/RX",
                )
            })?;
        self.check_installed(owner, input.actual_system())
            .map_err(FetchFailure::Unavailable)?;
        Ok(reached)
    }

    /// Postmint currency only. The initial factory uses qualify_source so an
    /// original instruction-fetch architectural/alignment fault remains typed
    /// and precedes data-address faults. Under the retained immutable bank and
    /// source/physical/outer loans, later failure is an authority/platform loss,
    /// never a newly synthesized guest exception or successful continuation.
    pub(crate) fn validate_current(
        &self,
        owner: &TranslationControls,
        input: &M0SourceInput<'_, '_>,
    ) -> Result<(), &'static str> {
        self.qualify_source(owner, input)
            .map_err(|_| "installed M0 source/control/physical currency was lost")
    }
}

/// Pure source-shape classification only; the opaque installed scope supplies
/// the immutable profile. This confers no source/CPU/control/outer/read grant.
fn check_data_source_word(
    profile: stela_compiler::block::BlockProfile,
    pc: u64,
    word: u32,
) -> Result<(), &'static str> {
    let instruction = Decoder
        .lift(GuestAddress(pc), word)
        .map_err(|_| "installed M0 source decode unavailable")?;
    if profile == stela_compiler::block::BlockProfile::El1PlatformV1
        && (M0WriteSource::from_source(&instruction, word).is_ok()
            || M0ReadPairSource::from_source(&instruction, word).is_ok())
    {
        return Ok(());
    }
    M0ScalarReadSource::from_profile(profile, &instruction, word)
        .map(|_| ())
        .map_err(|_| "installed M0 source is outside the exact LDR64 shape")
}

#[cfg(test)]
mod tests;
