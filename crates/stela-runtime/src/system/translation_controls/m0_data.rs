//! Aligned Device reads with the MMU off (M0).

use super::{PanFeatures, Presence, TranslationControls};
use crate::{
    blocks::{
        InstalledM0SourceScope,
        retirement::{M0PairReadSourceInput, M0SourceInput, M0WriteSourceInput},
    },
    memory::{
        domain::{
            MemoryExecutionLoan,
            m0_read::{
                M0ScalarReadIntent,
                pair::{M0ReadMember, M0ReadPairIntent},
            },
            m0_write::{M0WriteIntent, M0WriteMember},
            physical::PhysicalAddressSpace,
        },
        stage1,
    },
    system::{
        access::ExceptionLevel,
        state::{PSTATE_IL_MASK, PSTATE_SS_MASK, SystemState},
    },
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};

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
    StackAlignment {
        source_pc: u64,
        original_sp: u64,
    },
    UnsupportedProfile,
    Configuration(stage1::Unsupported),
    SourceFetch(super::FetchFailure),
    /// Only the initial check may return the source fault or an unsupported
    /// translation; later checks never create guest faults.
    Translation(stage1::TranslationError),
    UnexpectedAttributes,
    WrongSourceKind,
    MissingWriteMember,
}

impl TranslationControls {
    /// Compute the current M0 configuration from the live bank. The caller
    /// first validates the source and installed context under the source and
    /// memory borrow.
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
        // Keep the base entry-effect subset. SystemState rejects UAO, and an
        // ordinary LDR uses uao = false regardless of PAN.
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
        // The configuration leaves EE unused for M0, so EL1 data byte order
        // needs this explicit check of the live bank.
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

    /// Derive only after the instruction fetch is validated; the configuration
    /// comes from the live bank above.
    fn derive_m0_read8(
        config: &stage1::Config,
        physical: &PhysicalAddressSpace,
        source_pc: u64,
        raw_address: u64,
    ) -> Result<stage1::Translation, M0ControlError> {
        Self::derive_m0_scalar_read(config, physical, source_pc, raw_address, READ_BYTES as u8)
    }
    fn derive_m0_scalar_read(
        config: &stage1::Config,
        physical: &PhysicalAddressSpace,
        source_pc: u64,
        raw_address: u64,
        bytes: u8,
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
                aligned: raw_address.is_multiple_of(u64::from(bytes)),
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
            || translation.contiguous_bytes() < u64::from(bytes)
        {
            return Err(M0ControlError::UnexpectedAttributes);
        }
        Ok(translation)
    }
}

/// Erases the input's type while keeping all its source, system, outer and
/// scope references, so its nested lifetime does not leak into the writer's
/// borrow. Holds no guest state or PC borrow.
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

/// CPU and source validation for an M0 read. Not Clone or Copy, and constructed
/// only by the bank method below. RAM ordering and physical pins are the Device
/// producer's job; the outer execution borrow stays held through staging and
/// the PC commit.
pub(crate) struct M0DataReadLoan<'cpu> {
    owner: &'cpu TranslationControls,
    source: &'cpu dyn InputCurrency,
    outer: &'cpu MemoryExecutionLoan,
    generation: u64,
    intent: M0ScalarReadIntent,
    translation: stage1::Translation,
}
impl M0DataReadLoan<'_> {
    /// Later failures are currency refusals, never new translation faults or
    /// read completions.
    pub(crate) fn validate_current(
        &self,
        execution: &MemoryExecutionLoan,
    ) -> Result<(), M0ControlError> {
        if !core::ptr::eq(execution, self.outer) {
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
    pub(crate) fn intent(&self) -> M0ScalarReadIntent {
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
    /// Compare the current bank with the installed context under its source and
    /// physical lease.
    pub(crate) fn validate_installed_m0_source(
        &self,
        scope: &InstalledM0SourceScope<'_>,
    ) -> Result<(), &'static str> {
        if self.poisoned {
            return Err("M0 control owner is poisoned");
        }
        let installed = scope.installed_snapshot();
        if !alloc::sync::Arc::ptr_eq(&self.memory, scope.physical_space().memory_system()) {
            return Err("M0 controls and physical source have different MemorySystem owners");
        }
        if !alloc::sync::Arc::ptr_eq(&self.identity, &installed.identity)
            || self.generation != installed.generation()
            || self.profile.cpu != scope.installed_cpu()
            || self.readbacks != installed.readbacks()
            || self.profile.consumers(self.readbacks) != installed.consumer_inputs()
            || self.profile.facts != installed.feature_facts()
            || self.profile.provenance != installed.policy_provenance()
        {
            return Err("M0 installed context differs from the control owner");
        }
        Ok(())
    }

    pub(crate) fn loan_m0_scalar_read<'cpu>(
        &'cpu self,
        input: &'cpu M0SourceInput<'_, '_>,
    ) -> Result<M0DataReadLoan<'cpu>, M0ControlError> {
        input
            .validate_source_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        // Admission checks only: a data address fault must not be raised before
        // the installed context validates the instruction fetch.
        let config = self.current_m0_config(input.actual_system(), input.actual_pstate())?;
        let outer = input.outer_execution();
        input
            .validate_thread_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        outer
            .check_memory_system(&self.memory)
            .map_err(M0ControlError::Domain)?;
        let scope = input.installed_source_scope();
        if !alloc::sync::Arc::ptr_eq(&self.memory, scope.physical_space().memory_system()) {
            return Err(M0ControlError::WrongMemorySystem);
        }
        // The scope checks physical-domain and outer membership and source,
        // native-code and installed-context currency, without any data access.
        // Initial fetch faults stay typed; mismatches are platform failures,
        // never data aborts.
        scope
            .qualify_source(self, input)
            .map_err(M0ControlError::SourceFetch)?;
        let intent = input.read_intent().ok_or(M0ControlError::WrongSourceKind)?;
        if !matches!(intent.bytes, 1 | 2 | 4 | 8) {
            return Err(M0ControlError::WrongSourceKind);
        }
        // SP is checked before any offset-derived address, following the
        // effective SCTLR.SA.
        if self.profile.consumers(self.readbacks).sctlr_el1 & super::fields::SCTLR_SA_MASK != 0
            && let Some(original_sp) = intent.stack_pointer
            && original_sp & 15 != 0
        {
            return Err(M0ControlError::StackAlignment {
                source_pc: intent.source_pc.0,
                original_sp,
            });
        }
        let translation = Self::derive_m0_scalar_read(
            &config,
            scope.physical_space(),
            intent.source_pc.0,
            intent.raw_address,
            intent.bytes,
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

impl InputCurrency for M0WriteSourceInput<'_, '_> {
    fn validate(&self, owner: &TranslationControls) -> Result<(), M0ControlError> {
        self.original().validate(owner)
    }
    fn physical(&self) -> &PhysicalAddressSpace {
        self.original().physical()
    }
}
trait WriteCurrency: InputCurrency {
    fn validate_inflight(&self, owner: &TranslationControls) -> Result<(), M0ControlError>;
    fn actual_system(&self) -> &SystemState;
    fn actual_pstate(&self) -> u64;
}
impl WriteCurrency for M0WriteSourceInput<'_, '_> {
    fn validate_inflight(&self, owner: &TranslationControls) -> Result<(), M0ControlError> {
        let original = self.original();
        original
            .validate_source_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        original
            .validate_thread_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        original
            .installed_source_scope()
            .check_installed(owner, original.actual_system())
            .map_err(|reason| M0ControlError::Source(reason.into()))
    }
    fn actual_system(&self) -> &SystemState {
        self.original().actual_system()
    }
    fn actual_pstate(&self) -> u64 {
        self.original().actual_pstate()
    }
}

/// The bank, source and outer borrow for an M0 write; not a writable physical
/// pin. Each member's translation comes from the live bank, and only the
/// physical owner resolves storage and publishes.
pub(crate) struct M0DataWriteLoan<'cpu> {
    owner: &'cpu TranslationControls,
    source: &'cpu dyn WriteCurrency,
    outer: &'cpu MemoryExecutionLoan,
    generation: u64,
    intent: M0WriteIntent,
    source_pin: crate::memory::domain::physical::BoundPhysicalInstruction,
}
impl M0DataWriteLoan<'_> {
    pub(crate) fn validate_current(
        &self,
        execution: &MemoryExecutionLoan,
    ) -> Result<(), M0ControlError> {
        self.validate_current_with_writes(execution, &[])
    }
    pub(crate) fn validate_current_with_writes(
        &self,
        execution: &MemoryExecutionLoan,
        writes: &[crate::memory::domain::SourceWriteReceipt],
    ) -> Result<(), M0ControlError> {
        if !core::ptr::eq(execution, self.outer) {
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
                "M0 write control generation differs".into(),
            ));
        }
        self.source.validate_inflight(self.owner)?;
        self.source_pin
            .validate_owned_writes(&self.owner.memory, writes)
            .map_err(|reason| M0ControlError::Source(reason.into()))
    }
    pub(crate) fn physical_space(&self) -> &PhysicalAddressSpace {
        self.source.physical()
    }
    pub(crate) fn intent(&self) -> M0WriteIntent {
        self.intent
    }
    pub(crate) fn qualify_member(
        &self,
        execution: &MemoryExecutionLoan,
        member: M0WriteMember,
    ) -> Result<stage1::Translation, M0ControlError> {
        self.qualify_member_after_writes(execution, member, &[])
    }
    pub(crate) fn qualify_member_after_writes(
        &self,
        execution: &MemoryExecutionLoan,
        member: M0WriteMember,
        writes: &[crate::memory::domain::SourceWriteReceipt],
    ) -> Result<stage1::Translation, M0ControlError> {
        self.validate_current_with_writes(execution, writes)?;
        let (raw_address, _) = self
            .intent
            .member(member)
            .ok_or(M0ControlError::MissingWriteMember)?;
        let config = self
            .owner
            .current_m0_config(self.source.actual_system(), self.source.actual_pstate())?;
        let translation = stage1::translate(
            &config,
            self.physical_space(),
            stage1::Access {
                kind: stage1::AccessKind::Write,
                exception_level: stage1::ExceptionLevel::El1,
                raw_virtual_address: raw_address,
                source_pc: self.intent.source_pc.0,
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
            || !translation.physical_address().is_multiple_of(READ_BYTES)
        {
            return Err(M0ControlError::UnexpectedAttributes);
        }
        Ok(translation)
    }
}
impl TranslationControls {
    /// Validates the instruction first, without translating or accessing the
    /// target. The physical session prepares the first member; the second is
    /// validated only after the first 8 bytes complete.
    pub(crate) fn loan_m0_write8_or_pair<'cpu>(
        &'cpu self,
        input: &'cpu M0WriteSourceInput<'_, '_>,
    ) -> Result<M0DataWriteLoan<'cpu>, M0ControlError> {
        let original = input.original();
        original
            .validate_source_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        self.current_m0_config(original.actual_system(), original.actual_pstate())?;
        original
            .validate_thread_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        let outer = original.outer_execution();
        outer
            .check_memory_system(&self.memory)
            .map_err(M0ControlError::Domain)?;
        let scope = original.installed_source_scope();
        if !alloc::sync::Arc::ptr_eq(&self.memory, scope.physical_space().memory_system()) {
            return Err(M0ControlError::WrongMemorySystem);
        }
        let source_pin = scope
            .pin_source(self, original)
            .map_err(M0ControlError::SourceFetch)?;
        Ok(M0DataWriteLoan {
            owner: self,
            source: input,
            outer,
            generation: self.generation,
            intent: input.intent(),
            source_pin,
        })
    }
}

impl InputCurrency for M0PairReadSourceInput<'_, '_> {
    fn validate(&self, owner: &TranslationControls) -> Result<(), M0ControlError> {
        self.original().validate(owner)?;
        self.validate_pair_profile()
            .map_err(|error| M0ControlError::Source(error.to_string()))
    }
    fn physical(&self) -> &PhysicalAddressSpace {
        self.original().physical()
    }
}
trait PairReadCurrency: InputCurrency {
    fn actual_system(&self) -> &SystemState;
    fn actual_pstate(&self) -> u64;
}
impl PairReadCurrency for M0PairReadSourceInput<'_, '_> {
    fn actual_system(&self) -> &SystemState {
        self.original().actual_system()
    }
    fn actual_pstate(&self) -> u64 {
        self.original().actual_pstate()
    }
}
/// The same borrows for an M0 pair read. Nothing is translated or read at
/// creation; each member is validated when reached.
pub(crate) struct M0DataPairReadLoan<'cpu> {
    owner: &'cpu TranslationControls,
    source: &'cpu dyn PairReadCurrency,
    outer: &'cpu MemoryExecutionLoan,
    generation: u64,
    intent: M0ReadPairIntent,
}
impl M0DataPairReadLoan<'_> {
    pub(crate) fn validate_current(
        &self,
        execution: &MemoryExecutionLoan,
    ) -> Result<(), M0ControlError> {
        if !core::ptr::eq(execution, self.outer) {
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
                "M0 pair control generation differs".into(),
            ));
        }
        self.source.validate(self.owner)
    }
    pub(crate) fn physical_space(&self) -> &PhysicalAddressSpace {
        self.source.physical()
    }
    pub(crate) fn intent(&self) -> M0ReadPairIntent {
        self.intent
    }
    pub(crate) fn qualify_member(
        &self,
        execution: &MemoryExecutionLoan,
        member: M0ReadMember,
    ) -> Result<stage1::Translation, M0ControlError> {
        self.validate_current(execution)?;
        let config = self
            .owner
            .current_m0_config(self.source.actual_system(), self.source.actual_pstate())?;
        TranslationControls::derive_m0_read8(
            &config,
            self.physical_space(),
            self.intent.source_pc.0,
            self.intent.member(member),
        )
    }
}
impl TranslationControls {
    pub(crate) fn loan_m0_read8_pair<'cpu>(
        &'cpu self,
        input: &'cpu M0PairReadSourceInput<'_, '_>,
    ) -> Result<M0DataPairReadLoan<'cpu>, M0ControlError> {
        let original = input.original();
        original
            .validate_source_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        input
            .validate_pair_profile()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        self.current_m0_config(original.actual_system(), original.actual_pstate())?;
        original
            .validate_thread_current()
            .map_err(|error| M0ControlError::Source(error.to_string()))?;
        let outer = original.outer_execution();
        outer
            .check_memory_system(&self.memory)
            .map_err(M0ControlError::Domain)?;
        let scope = original.installed_source_scope();
        if !alloc::sync::Arc::ptr_eq(&self.memory, scope.physical_space().memory_system()) {
            return Err(M0ControlError::WrongMemorySystem);
        }
        scope
            .qualify_source(self, original)
            .map_err(M0ControlError::SourceFetch)?;
        Ok(M0DataPairReadLoan {
            owner: self,
            source: input,
            outer,
            generation: self.generation,
            intent: input.intent(),
        })
    }
}
