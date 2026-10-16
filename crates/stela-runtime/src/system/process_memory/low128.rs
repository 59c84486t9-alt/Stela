//! FP/AdvSIMD access combined with checked memory.

use super::{
    EntryBoundary, EventEndpoint, FixedProcessMemoryControls, GuestState, MemoryContextView,
    MemoryControls, MemoryRequirements, MemoryStatus, MemoryThread, PreparedProcessMemory,
    ProcessMemoryError, SystemState, flags,
};
use crate::system::fp_access::Low128FpContext;

/// Borrows from the owners themselves, not a snapshot of CPACR or PSTATE.
/// Cannot be constructed outside this module.
pub(crate) struct Low128ProcessMemoryAuthorization<'run, 'loan, 'id> {
    boundary: &'run EntryBoundary,
    context: &'run Low128FpContext<'loan, 'id>,
    system: &'run SystemState,
    controls: &'run FixedProcessMemoryControls,
}

impl Low128ProcessMemoryAuthorization<'_, '_, '_> {
    pub(crate) fn memory_controls(&self) -> MemoryControls {
        self.controls.memory_controls(self.system)
    }

    fn check_state(&self, registers: &GuestState) -> Result<(), ProcessMemoryError> {
        self.context
            .check_system(self.system)
            .map_err(ProcessMemoryError::Low128)?;
        self.context
            .check_guest(registers)
            .map_err(ProcessMemoryError::Low128)
    }
}

/// Keeps the FP context and the entry descriptor alongside the prepared memory
/// borrow. The descriptor does not authenticate the fetched bytes or native
/// code; the provider does. The guest state stays mutable inside the split
/// callback.
pub struct PreparedLow128ProcessMemory<'run, 'loan, 'id> {
    authorization: Low128ProcessMemoryAuthorization<'run, 'loan, 'id>,
    prepared: PreparedProcessMemory<'run>,
}

impl FixedProcessMemoryControls {
    /// Admit the unchanged AdvSIMD requirements using the shared FP owner.
    /// Register-only SIMD keeps its AdvSIMD requirement even without
    /// NATIVE_ACCESS, and no memory requirement is dropped. Exclusive, ordered,
    /// atomic and scalable classes are refused in this little-endian ordinary
    /// scope.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_low128<'run, 'loan, 'id>(
        &'run self,
        boundary: &'run EntryBoundary,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        context: &'run Low128FpContext<'loan, 'id>,
        registers: &GuestState,
        thread: &'run mut MemoryThread<MemoryControls>,
        endpoint: Option<&'run EventEndpoint>,
    ) -> Result<PreparedLow128ProcessMemory<'run, 'loan, 'id>, ProcessMemoryError> {
        self.prepare_low128_profile(
            boundary,
            requirements,
            system,
            context,
            registers,
            thread,
            endpoint,
            None,
        )
    }

    /// The same owner with the FEAT_CPA specialization from the source.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_profile_with_low128<'run, 'loan, 'id>(
        &'run self,
        boundary: &'run EntryBoundary,
        profile: stela_compiler::block::CheckedMemoryProfile,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        debug: &'run crate::system::debug::DebugControls,
        context: &'run Low128FpContext<'loan, 'id>,
        registers: &GuestState,
        thread: &'run mut MemoryThread<MemoryControls>,
        endpoint: Option<&'run EventEndpoint>,
    ) -> Result<PreparedLow128ProcessMemory<'run, 'loan, 'id>, ProcessMemoryError> {
        self.prepare_low128_profile(
            boundary,
            requirements,
            system,
            context,
            registers,
            thread,
            endpoint,
            if matches!(
                profile,
                stela_compiler::block::CheckedMemoryProfile::AddressChecks(_)
            ) {
                Some((profile, debug))
            } else {
                None
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_low128_profile<'run, 'loan, 'id>(
        &'run self,
        boundary: &'run EntryBoundary,
        requirements: MemoryRequirements,
        system: &'run SystemState,
        context: &'run Low128FpContext<'loan, 'id>,
        registers: &GuestState,
        thread: &'run mut MemoryThread<MemoryControls>,
        endpoint: Option<&'run EventEndpoint>,
        pointer_profile: Option<(
            stela_compiler::block::CheckedMemoryProfile,
            &'run crate::system::debug::DebugControls,
        )>,
    ) -> Result<PreparedLow128ProcessMemory<'run, 'loan, 'id>, ProcessMemoryError> {
        let execution_loan = self.acquire_source_loan(boundary, system, registers, thread)?;
        let pointer = match pointer_profile {
            Some((profile, debug)) => Some(self.qualify_pointer(
                profile,
                requirements,
                system,
                debug,
                thread,
                &execution_loan,
            )?),
            None if self.features.cpa == super::pointer_checks::CpaFeature::Checked => {
                return Err(ProcessMemoryError::PointerChecks(
                    super::PointerChecksError::UnsupportedProfile,
                ));
            }
            None => None,
        };

        let authorization = Low128ProcessMemoryAuthorization {
            boundary,
            context,
            system,
            controls: self,
        };
        authorization.check_state(registers)?;
        if requirements.required_flags & !flags::KNOWN != 0 {
            return Err(ProcessMemoryError::Memory(MemoryStatus::InvalidRequest));
        }
        let unavailable =
            flags::ATOMIC | flags::ORDERED | flags::EXCLUSIVE | flags::SME | flags::SVE_PREDICATED;
        if requirements.required_flags & flags::ASIMD == 0
            || requirements.required_flags & unavailable != 0
        {
            return Err(ProcessMemoryError::Memory(MemoryStatus::Unsupported));
        }
        let mut prepared =
            self.finish_prepare(requirements, system, thread, endpoint, execution_loan)?;
        prepared.pointer = pointer;
        Ok(PreparedLow128ProcessMemory {
            authorization,
            prepared,
        })
    }
}

impl PreparedLow128ProcessMemory<'_, '_, '_> {
    pub const fn profile_id(&self) -> &'static str {
        self.prepared.profile_id()
    }

    pub(crate) const fn requirements(&self) -> MemoryRequirements {
        self.prepared.requirements()
    }

    /// Re-check the bound guest and system state at the call and immediately
    /// before the native callback, keeping the context throughout.
    ///
    /// # Safety
    /// The provider binds this token to its source plan, requirements and
    /// native body, and calls that body with `registers`. The checked-view and
    /// backing contracts apply, and the provider's outer PE, source and domain
    /// borrow must last through PC settlement. The callback must not substitute
    /// another bank, keep raw pointers, re-enter or change mappings. On CPUs
    /// with SVE, V writes still need the scalable writer for the upper Z bytes.
    pub(crate) unsafe fn with_view<R>(
        self,
        registers: &mut GuestState,
        callback: impl FnOnce(&EntryBoundary, &mut GuestState, &mut MemoryContextView) -> R,
    ) -> Result<R, ProcessMemoryError> {
        self.authorization.check_state(registers)?;
        let policy = MemoryControls::for_low128_authority(&self.authorization);
        // SAFETY: the caller binds the exact checked body and inherits all
        // native contracts. The private policy originates only from this live
        // typed authorization; finalization restores the same thread's policy.
        unsafe {
            self.prepared.with_policy(policy, |view| {
                self.authorization.check_state(registers)?;
                Ok(callback(self.authorization.boundary, registers, view))
            })
        }
        .map_err(ProcessMemoryError::Memory)?
    }
}
