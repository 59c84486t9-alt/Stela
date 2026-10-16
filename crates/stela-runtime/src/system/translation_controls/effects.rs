//! Hooks the translation-control owner needs from the memory system.

use super::{ControlSnapshot, Register};
use crate::memory::{domain::MemorySystem, stage1};
use crate::system::state::SystemState;
use alloc::sync::Arc;
use stela_compiler::{GuestState, aarch64::system::synchronization::Operation};

/// A real fetch, not a request to trust a copied buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalFetch {
    pub pc: u64,
    pub word: u32,
    pub physical_address: u64,
    pub source_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchFailure {
    /// Pre-translation PC alignment fault; the exception owner derives its
    /// architectural syndrome directly from this provenance.
    InstructionAlignment {
        raw_pc: u64,
        exception_level: crate::system::access::ExceptionLevel,
    },
    /// Canonical source-derived fault: raw VA, access kind/EL/level, walk and
    /// external-abort provenance remain available to the exception owner.
    Architectural(stage1::Fault),
    Unavailable(&'static str),
    Platform(&'static str),
}

#[derive(Debug, Clone)]
pub struct ControlChange {
    pub before: ControlSnapshot,
    pub after: ControlSnapshot,
    pub register: Register,
    pub operand: u64,
    pub source: PhysicalFetch,
    pub next_pc: u64,
}

/// Owning snapshot data removes any borrow of temporary copied controls. Actual
/// SystemState/GuestState remain borrowed while the real service gates are held.
pub enum PublicationRequest<'a> {
    Initial {
        snapshot: ControlSnapshot,
        cpu: stage1::CpuProfile,
        state: &'a SystemState,
    },
    Read {
        snapshot: ControlSnapshot,
        source: PhysicalFetch,
        cpu: stage1::CpuProfile,
        state: &'a SystemState,
    },
    Write {
        change: ControlChange,
        cpu: stage1::CpuProfile,
        state: &'a SystemState,
        registers: &'a GuestState,
    },
    Isb {
        before: ControlSnapshot,
        after: ControlSnapshot,
        source: PhysicalFetch,
        operation: Operation,
        cpu: stage1::CpuProfile,
        state: &'a SystemState,
        registers: &'a GuestState,
    },
}

/// Context synchronization for an exception, distinct from an ISB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSynchronizationCause {
    ExceptionEntry,
    ExceptionReturn,
    /// IRQ entry after a retired instruction, selected only by the pending-
    /// receipt consumer.
    InterruptEntry,
}
impl ContextSynchronizationCause {
    pub(crate) fn matches_source(self, word: u32) -> bool {
        use stela_compiler::aarch64::system::exception::{Operation, decode};
        matches!(
            (self, decode(word)),
            (
                Self::ExceptionEntry,
                Some(
                    Operation::Undefined { .. }
                        | Operation::SupervisorCall { .. }
                        | Operation::SoftwareBreakpoint { .. }
                )
            ) | (
                Self::ExceptionReturn,
                Some(Operation::ExceptionReturn { key: None })
            )
        )
    }
}

/// The state borrow is checked during preparation. The consumer keeps its state
/// exclusively until the service commits, and the service keeps the source,
/// control and publication resources instead of borrowing the bank the
/// exception must change next.
pub struct ContextSynchronizationRequest<'state> {
    pub before: ControlSnapshot,
    pub after: ControlSnapshot,
    pub source: PhysicalFetch,
    pub cpu: stage1::CpuProfile,
    pub state: &'state SystemState,
    pub cause: ContextSynchronizationCause,
    /// The retired source, present only for asynchronous entry. The installed
    /// publisher borrows its pre-effect physical pin.
    pub(crate) retired_source:
        Option<&'state crate::blocks::retirement::checked::RetiredInstructionSource<'state>>,
}

/// How far the backend got; the control owner reports a committed MSR
/// separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationProgress {
    None,
    TranslationDependenciesRetired,
    CodeDependenciesRetired,
    CurrentContextInstalled,
    InstructionExecutionSerialized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationFailure {
    pub progress: PublicationProgress,
    pub reason: &'static str,
}

/// A prepared service holding memory, source and code gates. Commit should not
/// fail after preparation; when it does, it reports the reached prefix and the
/// control owner is marked failed rather than exposing stale views or retrying
/// a committed MSR. A failing adapter must also make its derived state unusable
/// until recovered, and a dropped failed initial install must not leave
/// reusable partial state.
pub trait PreparedPublication {
    fn commit(self) -> Result<(), PublicationFailure>;
}

/// The memory and publication services behind the translation controls.
/// Implementations belong to the returned MemorySystem, and nothing succeeds by
/// default.
///
/// `prepare` checks the source word and generation, the PE and controls, and
/// the backing, view and code generations, under gates held until commit. It
/// has no guest-visible effect and reserves every service needed:
///
/// - Initial installs the per-PE policy or refuses.
/// - Read re-validates the fetched source, the access and the owner binding; it does not act as a context synchronization, TLBI, DSB or code serialization.
/// - Write derives from every applicable consumer input, including zero controls. It retires or rebinds the affected views, translations and source and native code, so that later fetches and accesses cannot reuse stale state. Intermediate states may be dormant or faulting, but preparation must not raise a future fetch fault or invent a valid final MMU state. The next fetch uses the new controls, and any deferred fault is raised by `fetch` after the MSR.
/// - Isb completes context synchronization, instruction-fetch publication and any BRBE effect, keeping the raw option. It adds no data barrier and does not invalidate every TLB. The ISB itself was fetched under the post-MSR policy.
///
/// MMU-off Device data and WT/NC fetch need their own adapters. Unsupported
/// effects or configurations return Unavailable. EL2/EL3, devices, other PEs,
/// instruction traps, keys, PSTATE defaults and optional features need their
/// own owners. Fetch faults are architectural faults, never converted from host
/// MemoryStatus. Physical byte publication and reservation invalidation alone
/// satisfy none of these obligations.
pub trait TranslationServices {
    /// Reserve the exception's context publication without holding a state
    /// borrow across the exception's bank effects. Services without it refuse.
    fn prepare_context_synchronization<'a>(
        &'a mut self,
        _request: ContextSynchronizationRequest<'_>,
    ) -> Result<Self::Prepared<'a>, &'static str> {
        Err("exception context publication is unavailable")
    }

    type Prepared<'a>: PreparedPublication
    where
        Self: 'a;

    fn memory_system(&self) -> &Arc<MemorySystem>;

    fn prepare<'a>(
        &'a mut self,
        request: PublicationRequest<'a>,
    ) -> Result<Self::Prepared<'a>, &'static str>;

    /// Revalidate real physical/source identity before interpreting a source
    /// word or returning a guest-visible access outcome. The subsequent prepare
    /// revalidates again under gates it retains until commit. This method does
    /// not publish controls, retire mappings, serialize, or deliver an exception.
    fn validate_source(
        &mut self,
        snapshot: &ControlSnapshot,
        source: PhysicalFetch,
        state: &SystemState,
    ) -> Result<(), &'static str>;

    fn fetch(
        &mut self,
        snapshot: &ControlSnapshot,
        cpu: &stage1::CpuProfile,
        state: &SystemState,
        pc: u64,
    ) -> Result<PhysicalFetch, FetchFailure>;
}
