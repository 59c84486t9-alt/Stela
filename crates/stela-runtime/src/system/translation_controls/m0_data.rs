//! Actual-bank MMU-disabled ordinary aligned Device read8 qualification.
//!
//! Private source component. This is not a PA backing constructor, physical
//! read, host serialization permit, source mint, PE entry or retirement hook.

use super::{PanFeatures, Presence, TranslationControls};
use crate::{
    blocks::{InstalledM0SourceScope, retirement::M0SourceInput},
    memory::{
        domain::{MemoryExecutionLoan, m0_read::M0Read64Intent, physical::PhysicalAddressSpace},
        stage1,
    },
    system::{
        access::ExceptionLevel,
        state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
    },
};

const SCTLR_M: u64 = 1;
const SCTLR_EE: u64 = 1 << 25;
const READ_BYTES: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum M0ControlError {
    Poisoned,
    Source(String),
    Domain(stela_compiler::context::memory::MemoryStatus),
    WrongMemorySystem,
    DifferentExecutionLoan,
    NotEl1,
    UnsupportedState,
    MmuEnabled,
    BigEndian,
    UnsupportedProfile,
    Configuration(stage1::Unsupported),
    SourceFetch(super::FetchFailure),
    /// Only initial qualification may return the canonical source fault or
    /// unsupported translation. Currency checks never manufacture guest faults.
    Translation(stage1::TranslationError),
    UnexpectedAttributes,
}

impl TranslationControls {
    /// Internal calculation only; no externally supplied Config/snapshot/flags
    /// are accepted. The caller must first validate the actual same-PE source
    /// and installed context under the canonical source/memory owner loan.
    fn current_m0_config(
        &self,
        system: &SystemState,
        actual_pstate: u64,
    ) -> Result<stage1::Config, M0ControlError> {
        if self.poisoned {
            return Err(M0ControlError::Poisoned);
        }
        if system.current_el() != ExceptionLevel::El1 {
            return Err(M0ControlError::NotEl1);
        }
        if actual_pstate & (PSTATE_IL_MASK | PSTATE_SS_MASK) != 0 || system.mte().is_some() {
            return Err(M0ControlError::UnsupportedState);
        }
        // Keep the reviewed base entry-effect subset. The bounded SystemState
        // rejects UAO state; ordinary LDR uses uao=false independently of PAN.
        if self.profile.facts.pan != PanFeatures::Absent
            || self.profile.facts.ssbs != Presence::Absent
            || self.profile.facts.exs != Presence::Absent
        {
            return Err(M0ControlError::UnsupportedProfile);
        }
        let effective = self.profile.consumers(self.readbacks);
        if effective.sctlr_el1 & SCTLR_M != 0 {
            return Err(M0ControlError::MmuEnabled);
        }
        // Retained Config deliberately leaves EE dormant for M0; EL1 data
        // byte order therefore needs this actual live-bank check explicitly.
        if effective.sctlr_el1 & SCTLR_EE != 0 {
            return Err(M0ControlError::BigEndian);
        }
        let config =
            stage1::Config::from_controls_for_cpu(effective.stage1_controls(), self.profile.cpu)
                .map_err(M0ControlError::Configuration)?;
        if config.mode() != stage1::Mode::Disabled {
            return Err(M0ControlError::MmuEnabled);
        }
        Ok(config)
    }

    /// Derive only after actual instruction-source fetch qualification. Config
    /// is private output of the live bank above, never a caller's permission.
    fn derive_m0_read8(
        config: &stage1::Config,
        physical: &PhysicalAddressSpace,
        source_pc: u64,
        raw_address: u64,
    ) -> Result<stage1::Translation, M0ControlError> {
        // Canonical disabled translation applies region/TBI/PAMax address-size
        // priority before the aligned-Device support check. Do not preempt it
        // with a made-up Alignment fault or use TCR.IPS as CPU PAMax.
        let translation = stage1::translate(
            config,
            physical,
            stage1::Access {
                kind: stage1::AccessKind::Read,
                exception_level: stage1::ExceptionLevel::El1,
                raw_virtual_address: raw_address,
                source_pc,
                pan: false,
                uao: false,
                aligned: raw_address.is_multiple_of(READ_BYTES),
            },
        )
        .map_err(M0ControlError::Translation)?;
        let attributes = translation.attributes();
        if attributes.memory_type != stage1::MemoryType::DeviceNgnrne
            || attributes.origin != stage1::AttributeOrigin::MmuDisabled
            || attributes.shareability != stage1::Shareability::Outer
            || attributes.mair.is_some()
            || attributes.tagged
            || !attributes.xs
            || attributes.not_global
            || attributes.guarded_page
            || translation.permissions().is_some()
            || translation.walk().is_some()
            || translation.contiguous_bytes() < READ_BYTES
        {
            return Err(M0ControlError::UnexpectedAttributes);
        }
        Ok(translation)
    }
}

/// Private type erasure retains the REAL opaque input with all its original
/// source/System/outer/scope references. No caller implementation or callback is
/// accepted. This avoids leaking the input's nested source lifetime into the
/// writer's one-lifetime loan and holds no GuestState/actual-PC/authority borrow.
trait InputCurrency {
    fn validate(&self, owner: &TranslationControls) -> Result<(), M0ControlError>;
    fn physical(&self) -> &PhysicalAddressSpace;
}
impl InputCurrency for M0SourceInput<'_, '_> {
    fn validate(&self, owner: &TranslationControls) -> Result<(), M0ControlError> {
        self.validate_source_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        self.validate_thread_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        self.installed_source_scope()
            .validate_current(owner, self)
            .map_err(|reason| M0ControlError::Source(reason.into()))
    }
    fn physical(&self) -> &PhysicalAddressSpace {
        self.installed_source_scope().physical_space()
    }
}

/// Live CPU/source qualification only. Non-Clone/non-Copy, private fields and no
/// constructor except the actual bank method below. RAM/host ordering/physical
/// read pins remain the separate Device producer's obligations. The SAME outer
/// execution loan stays borrowed through the writer's staging and PC commit.
pub(crate) struct M0DataReadLoan<'cpu> {
    owner: &'cpu TranslationControls,
    source: &'cpu dyn InputCurrency,
    outer: &'cpu MemoryExecutionLoan,
    generation: u64,
    intent: M0Read64Intent,
    translation: stage1::Translation,
}
impl M0DataReadLoan<'_> {
    /// Post-mint failures are source/control/domain currency refusals, never a
    /// newly synthesized architectural translation fault or read completion.
    pub(crate) fn validate_current(
        &self,
        execution: &MemoryExecutionLoan,
    ) -> Result<(), M0ControlError> {
        if !std::ptr::eq(execution, self.outer) {
            return Err(M0ControlError::DifferentExecutionLoan);
        }
        execution
            .check_memory_system(&self.owner.memory)
            .map_err(M0ControlError::Domain)?;
        if self.owner.poisoned {
            return Err(M0ControlError::Poisoned);
        }
        if self.owner.generation != self.generation {
            return Err(M0ControlError::Source(
                "M0 control generation differs".into(),
            ));
        }
        self.source.validate(self.owner)
    }
    pub(crate) fn intent(&self) -> M0Read64Intent {
        self.intent
    }
    pub(crate) fn derived_translation(&self) -> &stage1::Translation {
        &self.translation
    }
    pub(crate) fn physical_space(&self) -> &PhysicalAddressSpace {
        self.source.physical()
    }
}

impl TranslationControls {
    /// Compare the actual current bank against the ORIGINAL installed context
    /// under its genuine, private-constructed source/physical lease. A caller's
    /// independent snapshot, CPU profile or hash cannot invoke this interface.
    pub(crate) fn validate_installed_m0_source(
        &self,
        scope: &InstalledM0SourceScope<'_>,
    ) -> Result<(), &'static str> {
        if self.poisoned {
            return Err("M0 control owner is poisoned");
        }
        let installed = scope.installed_snapshot();
        if !std::sync::Arc::ptr_eq(&self.memory, scope.physical_space().memory_system()) {
            return Err("M0 controls and physical source have different MemorySystem owners");
        }
        if !std::sync::Arc::ptr_eq(&self.identity, &installed.identity)
            || self.generation != installed.generation()
            || self.profile.cpu != scope.installed_cpu()
            || self.readbacks != installed.readbacks()
            || self.profile.consumers(self.readbacks) != installed.consumer_inputs()
            || self.profile.facts != installed.feature_facts()
            || self.profile.provenance != installed.policy_provenance()
        {
            return Err("M0 installed context differs from the actual control owner");
        }
        Ok(())
    }

    pub(crate) fn loan_m0_read8<'cpu>(
        &'cpu self,
        input: &'cpu M0SourceInput<'_, '_>,
    ) -> Result<M0DataReadLoan<'cpu>, M0ControlError> {
        input
            .validate_source_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        // Only admission checks here: do not raise a data address fault before
        // the genuine installed context qualifies the source instruction fetch.
        let config = self.current_m0_config(input.actual_system(), input.actual_pstate())?;
        let outer = input.outer_execution();
        input
            .validate_thread_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        outer
            .check_memory_system(&self.memory)
            .map_err(M0ControlError::Domain)?;
        let scope = input.installed_source_scope();
        if !std::sync::Arc::ptr_eq(&self.memory, scope.physical_space().memory_system()) {
            return Err(M0ControlError::WrongMemorySystem);
        }
        // The real scope checks exact physical-domain/outer membership as well
        // as original source/RX/installed-context currency. It performs no data
        // transaction. Initial source fetch faults remain typed; source/RX/owner
        // mismatches are unavailable/platform failures, never fake data aborts.
        scope
            .qualify_source(self, input)
            .map_err(M0ControlError::SourceFetch)?;
        let intent = input.intent();
        let translation = Self::derive_m0_read8(
            &config,
            scope.physical_space(),
            intent.source_pc.0,
            intent.raw_address,
        )?;
        Ok(M0DataReadLoan {
            owner: self,
            source: input,
            outer,
            generation: self.generation,
            intent,
            translation,
        })
    }
}
