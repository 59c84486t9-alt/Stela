//! CPA2 specialization admitted by the original fixed process/control owner.
//!
//! The canonical provider supplies its retained immutable debug owner and exact
//! bound compiler profile. The token retains those borrows and the original
//! SystemState; its parent prepared token owns the same-domain execution pin.

use super::pointer_checks::{self};
use super::{
    EntryBoundary, EventEndpoint, FixedProcessMemoryControls, GuestState, MemoryControls,
    MemoryExecutionLoan, MemoryRequirements, MemoryThread, PointerChecksError,
    PreparedProcessMemory, ProcessMemoryError, ResolvedPointerChecks, SystemState, flags,
};
use crate::system::debug::DebugControls;
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
        // Missing SCTLR2 is not a zero value. The helper may bypass the lookup
        // only after actual feature/SCTLRX facts have made it inapplicable.
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
        // acquire_source_loan already proves actual EL0t. Both normal and
        // unprivileged access descriptors therefore use EL0 in this owner.
        // Compare the complete profile, not aggregate used-EL requirements.
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

    /// Private source-bound entry. The canonical provider must retain its actual
    /// debug owner, PE/source/outer and exact immutable runtime profile. This is
    /// not a public loose-control or permission-boolean constructor.
    #[allow(clippy::too_many_arguments)]
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
#[path = "pointer/tests.rs"]
mod tests;
