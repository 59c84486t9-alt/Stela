//! Required hooks for the real same-machine translation/fetch/publication owner.
//!
//! This leaf deliberately supplies no successful implementation. MemorySystem's
//! existing NormalWB byte-publication API alone is insufficient. The concrete
//! adapter composes canonical stage1, physical views, source/RX dependencies,
//! active invocations and the existing code-publication authority.

use super::{ControlSnapshot, Register};
use crate::memory::{domain::MemorySystem, stage1};
use crate::system::state::SystemState;
use std::sync::Arc;
use stela_compiler::{GuestState, aarch64::system::synchronization::Operation};

/// An actual fetch, not a request to trust a copied virtual byte buffer.
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

/// Source-qualified synchronization for an exception, distinct from an ISB.
/// This describes a required effect; it grants no exception or native authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSynchronizationCause {
    ExceptionEntry,
    ExceptionReturn,
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

/// The state borrow is checked during preparation. The canonical consumer keeps
/// its ORIGINAL state exclusively owned until the prepared service commits;
/// the service retains the genuine source/control/publication resources instead
/// of immutably borrowing the bank that exception execution must mutate next.
pub struct ContextSynchronizationRequest<'state> {
    pub before: ControlSnapshot,
    pub after: ControlSnapshot,
    pub source: PhysicalFetch,
    pub cpu: stage1::CpuProfile,
    pub state: &'state SystemState,
    pub cause: ContextSynchronizationCause,
}

/// Exact internal backend prefix, not a claim of architectural instruction
/// completion. The control owner separately reports a committed MSR register.
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

/// Noncloneable service preparation, holding actual memory/source/code gates.
/// Commit should be infallible after preparation wherever possible. Any real
/// failure reports the exact reached prefix; the control authority is poisoned
/// rather than exposing mismatched old views or retrying a committed MSR. A
/// failing concrete adapter must likewise make its derived execution/source
/// state unusable until explicit recovery; dropping a failed Initial authority
/// must not leave partially installed state reusable by another constructor.
pub trait PreparedPublication {
    fn commit(self) -> Result<(), PublicationFailure>;
}

/// Concrete implementations MUST belong to the returned real MemorySystem.
/// There are no default successful methods or scalar stand-ins for maintenance.
///
/// `prepare` must check the original source word/generation and actual PE/control,
/// backing/view/code generations under gates retained through commit. It performs
/// no guest-visible effect. It reserves all required services before accepting:
///
/// - Initial installs the authentic per-PE policy, or declines; a register bank
///   without a usable/explicitly unavailable current context is not admission.
/// - Read revalidates fetched source, access and current owner binding; it does
///   not act as CSE, TLBI, DSB or code serialization.
/// - Write derives from ALL applicable consumer inputs, including zero controls.
///   It must retire/rebind affected virtual views, translations and source/RX
///   dependencies and ensure future fetch/access cannot reuse stale validity.
///   Dormant/faulting intermediate states are legal. It must not deliver a future
///   architectural fetch fault during preparation or invent a valid final MMU.
///   The serial implementation uses the new current controls for the next actual
///   fetch. Any deferred architectural fault is delivered by `fetch` after MSR.
/// - Isb completes real CSE/instruction-fetch publication/serialization and any
///   present BRBE effect, preserving the original raw option. It neither invents
///   a data barrier nor silently invalidates all TLBs. The ISB itself was fetched
///   under the current post-MSR policy before this request can be produced.
///
/// MMU-off Device data and WT/NC fetch need their genuine attribute/backing
/// adapters. Unsupported effects/profile/configuration paths return Unavailable;
/// register storage is never a substitute. EL2/3, devices, other PEs, instruction
/// traps, keys, PSTATE defaults and optional features need their actual owners.
/// Returned fetch faults are canonical faults, never conversions from generic
/// host MemoryStatus. Pending in-scope work must be drained by real participants.
/// Physical byte publication and reservation invalidation alone prove none of
/// the translation/code/TLBI/DSB obligations above.
pub trait TranslationServices {
    /// Reserve real exception context publication without retaining a state
    /// borrow across the subsequent original-bank exception effects. Services
    /// without this actual producer explicitly refuse; no successful fallback.
    fn prepare_context_synchronization<'a>(
        &'a mut self,
        _request: ContextSynchronizationRequest<'_>,
    ) -> Result<Self::Prepared<'a>, &'static str> {
        Err("actual exception context publication is unavailable")
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
