//! FEAT_CPA2 controls for checked memory.

use super::{FixedProcessMemoryControls, ResolvedPointerChecks, SystemState};
use crate::system::debug::DebugControls;

// Preparation is reached only by the hosted EL0 process owner.
#[cfg(feature = "std")]
use super::pointer_checks::{self};
#[cfg(feature = "std")]
use super::{
    EntryBoundary, EventEndpoint, GuestState, MemoryControls, MemoryExecutionLoan,
    MemoryRequirements, MemoryThread, PointerChecksError, PreparedProcessMemory,
    ProcessMemoryError, flags,
};
#[cfg(feature = "std")]
use stela_compiler::{
    block::CheckedMemoryProfile,
    context::memory::{
        SpAlignmentRequirement,
        address::{AccessEl, IncrementChoice},
    },
};

pub(crate) struct PointerMemoryAuthorization<'run> {
    _controls: &'run FixedProcessMemoryControls,
    _system: &'run SystemState,
    _debug: &'run DebugControls,
    checks: ResolvedPointerChecks,
}
impl PointerMemoryAuthorization<'_> {
    pub(crate) const fn checks(&self) -> ResolvedPointerChecks {
        self.checks
    }
}

impl FixedProcessMemoryControls {
    #[cfg(feature = "std")]
    pub(super) fn qualify_pointer<'run>(
        &'run self,
        profile: CheckedMemoryProfile,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        debug: &'run DebugControls,
        thread: &MemoryThread<MemoryControls>,
        execution: &MemoryExecutionLoan,
    ) -> Result<PointerMemoryAuthorization<'run>, ProcessMemoryError> {
        let fail = || ProcessMemoryError::PointerChecks(PointerChecksError::UnsupportedProfile);
        let snapshot = self.identification_snapshot().ok_or_else(fail)?;
        if debug.halted {
            return Err(fail());
        }
        // A missing SCTLR2 is not zero; the lookup may be skipped only when the
        // feature facts make it inapplicable.
        let extended = if self.extended.is_some() {
            Some(
                self.extended_controls(snapshot, thread, execution)
                    .map_err(|_| {
                        ProcessMemoryError::PointerChecks(
                            PointerChecksError::ExtendedControlUnavailable,
                        )
                    })?,
            )
        } else {
            None
        };
        let checks = pointer_checks::resolve(snapshot, Some(debug), extended.as_ref())
            .map_err(ProcessMemoryError::PointerChecks)?;
        let base = if self.sctlr_el1 & super::SCTLR_SP_ALIGNMENT_EL0 != 0 {
            CheckedMemoryProfile::SpAlignmentEnabled
        } else {
            CheckedMemoryProfile::SpAlignmentDisabled
        };
        // `acquire_source_loan` proved EL0t, so both normal and unprivileged
        // accesses use EL0 here. Compare the whole profile, not the combined EL
        // requirements.
        let expected =
            base.with_address_checks(AccessEl::El0, AccessEl::El0, checks.address_checks());
        let arithmetic = if checks.feature().has_arithmetic() {
            expected.with_pointer_arithmetic(checks.arithmetic_at(AccessEl::El0))
        } else {
            None
        };
        if profile != expected && Some(profile) != arithmetic {
            return Err(fail());
        }
        if !requirements
            .required_address_checks
            .matches(checks.address_checks(), IncrementChoice::Unchecked)
        {
            return Err(fail());
        }
        if let Some(required) = requirements.required_pointer_arithmetic
            && (!checks.feature().has_arithmetic()
                || Some(profile) != arithmetic
                || required.access_el() != AccessEl::El0
                || required.checks() != checks.arithmetic_at(AccessEl::El0))
        {
            return Err(fail());
        }
        if requirements.required_sp_alignment != SpAlignmentRequirement::Any
            && requirements.required_sp_alignment != base.sp_requirement()
        {
            return Err(fail());
        }
        Ok(PointerMemoryAuthorization {
            _controls: self,
            _system: system,
            _debug: debug,
            checks,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "std")]
    pub(crate) fn prepare_profile<'run>(
        &'run self,
        boundary: &EntryBoundary,
        profile: CheckedMemoryProfile,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        debug: &'run DebugControls,
        registers: &GuestState,
        thread: &'run mut MemoryThread<MemoryControls>,
        endpoint: Option<&'run EventEndpoint>,
    ) -> Result<PreparedProcessMemory<'run>, ProcessMemoryError> {
        if matches!(profile, CheckedMemoryProfile::AddressChecks(_)) {
            self.prepare_pointer(
                boundary,
                profile,
                requirements,
                system,
                debug,
                registers,
                thread,
                endpoint,
            )
        } else {
            self.prepare(boundary, requirements, system, registers, thread, endpoint)
        }
    }

    /// Private entry for the provider, which holds its debug owner, PE, source,
    /// outer object and runtime profile.
    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "std")]
    pub(crate) fn prepare_pointer<'run>(
        &'run self,
        boundary: &EntryBoundary,
        profile: CheckedMemoryProfile,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        debug: &'run DebugControls,
        registers: &GuestState,
        thread: &'run mut MemoryThread<MemoryControls>,
        endpoint: Option<&'run EventEndpoint>,
    ) -> Result<PreparedProcessMemory<'run>, ProcessMemoryError> {
        let execution = self.acquire_source_loan(boundary, system, registers, thread)?;
        let pointer =
            self.qualify_pointer(profile, requirements, system, debug, thread, &execution)?;
        let unavailable =
            flags::ATOMIC | flags::ORDERED | flags::ASIMD | flags::SME | flags::SVE_PREDICATED;
        if requirements.required_flags & unavailable != 0 {
            return Err(ProcessMemoryError::Memory(super::MemoryStatus::Unsupported));
        }
        let mut prepared =
            self.finish_prepare(requirements, system, thread, endpoint, execution)?;
        prepared.pointer = Some(pointer);
        Ok(prepared)
    }
}

#[cfg(test)]
mod tests;
