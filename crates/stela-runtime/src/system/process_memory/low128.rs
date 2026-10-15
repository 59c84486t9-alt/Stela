//! Ordinary low128 FP/AdvSIMD access joined to existing process-memory owners.
//!
//! Construct inside Low128FpAccess::with_guest. The actual invocation provider
//! retains the same PE/source/RX/retirement loan and outer domain execution loan;
//! this adapter adds no register bank, opcode decoder or permission boolean.

use super::{
    EntryBoundary, EventEndpoint, FixedProcessMemoryControls, GuestState, MemoryContextView,
    MemoryControls, MemoryRequirements, MemoryStatus, MemoryThread, PreparedProcessMemory,
    ProcessMemoryError, SystemState, flags,
};
use crate::system::fp_access::Low128FpContext;

/// Externally unconstructible, non-Clone/non-Copy. These are actual owner loans,
/// not a CPACR/PSTATE snapshot or a copied low128 feature/grant bit.
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

/// The actual FP context and exact borrowed entry descriptor survive alongside
/// the existing prepared memory loan. The descriptor does not itself authenticate
/// fetched bytes or an RX mapping; the actual provider retains those authorities.
/// The bound guest remains mutable inside the original split callback; no shared
/// GuestState borrow or detached pointer capability is substituted for it.
pub struct PreparedLow128ProcessMemory<'run, 'loan, 'id> {
    authorization: Low128ProcessMemoryAuthorization<'run, 'loan, 'id>,
    prepared: PreparedProcessMemory<'run>,
}

impl FixedProcessMemoryControls {
    /// Qualify unchanged ASIMD requirements using the actual common FP owner.
    /// Register-only SIMD retains ASIMD even without NATIVE_ACCESS; no memory
    /// requirement is removed to make the base factory accept an instruction.
    /// Mixed exclusive/ordered/atomic/scalable classes require their own reviewed
    /// composition and decline explicitly in this bounded ordinary LE scope.
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
        let execution_loan = self.acquire_source_loan(boundary, system, registers, thread)?;
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
        let prepared =
            self.finish_prepare(requirements, system, thread, endpoint, execution_loan)?;
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

    /// Recheck the actual bound guest/system at invocation and immediately
    /// before the native callback, retaining the original context throughout.
    ///
    /// # Safety
    /// The actual provider binds this token to its exact consumed source plan,
    /// compiler requirements and native RX body, and invokes that body with the
    /// supplied `registers`. Existing checked-view/backing contracts apply. Its
    /// outer actual PE/source/domain loan must survive once-only PC settlement.
    /// This callback must not substitute another bank, retain raw pointers,
    /// reenter or change mappings. SVE-present V writes/upper-Z effects still
    /// require the canonical scalable writer; this token cannot enable them.
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
