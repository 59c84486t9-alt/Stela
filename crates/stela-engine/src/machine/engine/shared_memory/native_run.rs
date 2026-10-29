//! A borrowed architectural frame; no Cpu or Host crosses a core.
mod access;
mod epoch;
pub(super) use epoch::Limits;
pub use epoch::{
    MAX_NATIVE_EPOCH_BODIES, NativeEpochDeadline, NativeEpochEnd, NativeEpochStatistics,
};
mod preparation;
use preparation::PreparationFailure;
use stela_compiler::block::Features;
pub(super) mod source;
#[cfg(feature = "native-profile")]
use super::super::NativeTimingWork as Work;
use super::super::{NativeExit, publication};
use super::*;
use crate::{execution::context::ContextLoan, platform::cpu::system::NativeSystemTarget};
pub(in crate::machine::engine) use access::{
    RecoveredAccess, RecoveredDeviceAccess, RecoveredRead, RecoveredWrite,
};
use alloc::boxed::Box;
use alloc::string::ToString;
use stela_compiler::{
    GuestState,
    block::ExitKind,
    context::{
        ExecutionContext,
        memory::{FaultAccess, MemoryRequirements, MemoryStatus},
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub pe: usize,
    pub pc: u64,
    pub source_sha256: alloc::string::String,
    pub native_sha256: alloc::string::String,
    pub controls_sha256: alloc::string::String,
    pub compiler_source_sha256: &'static str,
    pub abi: alloc::string::String,
    pub target: stela_compiler::TargetCpu,
    pub requirements: MemoryRequirements,
}
/// Per-PE compiler-artifact resource policy, independent of guest/application.
/// No persistent cache or installed Host arena is charged to this separate
/// in-memory artifact budget. Every PE has its own independent bound.
const ARTIFACT_CACHE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactCacheStats {
    pub compiled: u64,
    pub reused: u64,
    /// Rust allocation capacities and metadata; allocator headers are
    /// outside this accounting. Artifacts, slot capacity and one
    /// effective-control declaration share the same per-PE byte limit.
    pub retained_bytes: usize,
    pub entries: usize,
}

/// Every input to the immutable per-word admission decision. The table's
/// private lookup data is derived solely from its chip and withheld features;
/// the profile chip independently selects access checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmissionPolicy {
    profile_chip: stela_contracts::Chip,
    table_chip: stela_contracts::Chip,
    withheld: u64,
    asimd: bool,
}

/// Source-independent identity, captured anew while the PE is owned.
/// The cache itself lives in exactly that PE's canonical-memory owner.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactKey {
    pe: usize,
    pc: u64,
    worker: publication::WorkerId,
    profile: &'static str,
    admission: AdmissionPolicy,
    controls_sha256: Arc<str>,
    compiler_source_sha256: &'static str,
    abi: alloc::string::String,
    target: stela_compiler::TargetCpu,
    guarded: bool,
}
struct CacheEntry {
    artifact: Arc<Artifact>,
    recency: u64,
}
pub(super) struct ArtifactCache {
    // PC is only an index hint; every candidate still needs the complete key
    // and a fresh executable-source check before it can be promoted or entered.
    entries: Vec<CacheEntry>,
    recency_clock: u64,
    // One exact effective declaration, charged against the same byte budget.
    // Reset owners start empty and tightening can discard it independently.
    controls: Option<Controls>,
    retained_payload: usize,
    compiled: u64,
    reused: u64,
    byte_budget: usize,
    #[cfg(test)]
    fail_next_growth: bool,
}
impl Default for ArtifactCache {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            recency_clock: 0,
            controls: None,
            retained_payload: 0,
            compiled: 0,
            reused: 0,
            byte_budget: ARTIFACT_CACHE_BYTES,
            #[cfg(test)]
            fail_next_growth: false,
        }
    }
}
impl ArtifactCache {
    pub(super) fn controls(&self) -> Option<&Controls> {
        self.controls.as_ref()
    }
    fn controls_bytes(&self) -> usize {
        self.controls.as_ref().map_or(0, Controls::retained_bytes)
    }
    fn remember_controls(&mut self, controls: &Controls) {
        self.controls = None;
        let bytes = controls.retained_bytes();
        if bytes > self.byte_budget {
            return;
        }
        while !self.entries.is_empty() && !self.fits(bytes) {
            self.evict_oldest();
        }
        if !self.fits(bytes) {
            // An empty high-water slot allocation must not prevent a smaller
            // declaration (or a later artifact) from fitting the same bound.
            self.entries = Vec::new();
        }
        self.controls = Some(controls.clone());
    }
    fn find(&self, key: &ArtifactKey) -> Option<usize> {
        let first = self
            .entries
            .partition_point(|entry| entry.artifact.key.pc < key.pc);
        self.entries[first..]
            .iter()
            .take_while(|entry| entry.artifact.key.pc == key.pc)
            .position(|entry| entry.artifact.key == *key)
            .map(|offset| first + offset)
    }
    fn candidate(&self, key: &ArtifactKey) -> Option<(usize, Arc<Artifact>)> {
        self.find(key)
            .map(|index| (index, Arc::clone(&self.entries[index].artifact)))
    }
    fn next_recency(&mut self) -> u64 {
        if self.recency_clock == u64::MAX {
            // Unique positive tickets can be ranked in place without moving
            // entries or allocating. Each assigned rank is <= its old ticket,
            // so rewritten entries cannot pass the next >last_old filter.
            let mut last_old = 0;
            for rank in 1..=self.entries.len() {
                let index = self
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.recency > last_old)
                    .min_by_key(|(_, entry)| entry.recency)
                    .map(|(index, _)| index)
                    .expect("unique positive cache recency");
                last_old = self.entries[index].recency;
                self.entries[index].recency = rank as u64;
            }
            self.recency_clock = self.entries.len() as u64;
        }
        self.recency_clock += 1;
        self.recency_clock
    }
    /// Promote only after exact, freshly fetched executable source validation.
    /// Ordinary hits allocate nothing and move no entries. Only ticket wrap
    /// requires the allocation-free recency renumbering above.
    fn reuse(&mut self, index: usize) {
        let ticket = self.next_recency();
        self.entries[index].recency = ticket;
        self.reused = self.reused.saturating_add(1);
    }
    fn evict_oldest(&mut self) {
        let index = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.recency)
            .map(|(index, _)| index)
            .expect("nonempty cache eviction");
        self.remove(index);
    }
    #[cfg(test)]
    fn recency_order(&self) -> Vec<&Arc<Artifact>> {
        let mut ordered: Vec<_> = self.entries.iter().collect();
        ordered.sort_by_key(|entry| entry.recency);
        ordered.into_iter().map(|entry| &entry.artifact).collect()
    }
    pub(super) fn stats(&self) -> ArtifactCacheStats {
        ArtifactCacheStats {
            compiled: self.compiled,
            reused: self.reused,
            retained_bytes: self.retained_payload + self.slot_bytes() + self.controls_bytes(),
            entries: self.entries.len(),
        }
    }
    fn slot_bytes(&self) -> usize {
        self.entries.capacity() * core::mem::size_of::<CacheEntry>()
    }
    pub(super) fn tighten(&mut self, bytes: usize) {
        self.byte_budget = self.byte_budget.min(bytes);
        if self.stats().retained_bytes > self.byte_budget {
            self.controls = None;
        }
        while !self.entries.is_empty() && self.stats().retained_bytes > self.byte_budget {
            self.evict_oldest();
        }
        if self.slot_bytes() > self.byte_budget {
            self.entries = Vec::new();
        }
    }
    pub(super) fn empty_like(&self) -> Self {
        let mut empty = Self::default();
        empty.tighten(self.byte_budget);
        empty
    }
    fn remove(&mut self, index: usize) {
        self.retained_payload -= self.entries.remove(index).artifact.retained_bytes();
    }
    /// Whether the allocation plus additional payload fits.
    fn fits(&self, additional: usize) -> bool {
        self.retained_payload
            .checked_add(self.slot_bytes())
            .and_then(|bytes| bytes.checked_add(self.controls_bytes()))
            .and_then(|bytes| bytes.checked_add(additional))
            .is_some_and(|bytes| bytes <= self.byte_budget)
    }
    /// Required and geometric growth are both clipped by *remaining* bytes;
    /// speculative slots never cause otherwise unnecessary payload eviction.
    fn growth_capacity(&self, incoming: usize) -> Option<usize> {
        let required = self.entries.len().checked_add(1)?;
        let available = self
            .byte_budget
            .checked_sub(self.controls_bytes())?
            .checked_sub(self.retained_payload)?
            .checked_sub(incoming)?
            / core::mem::size_of::<CacheEntry>();
        if required > available {
            return None;
        }
        let geometric = self.entries.capacity().checked_mul(2).unwrap_or(available);
        Some(geometric.max(required).min(available))
    }
    fn reserve_slots(&mut self, capacity: usize) -> Option<()> {
        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_growth) {
            return None;
        }
        // Vec's additional count is relative to length, not current capacity.
        let additional = capacity.checked_sub(self.entries.len())?;
        self.entries.try_reserve_exact(additional).ok()
    }
    fn insert(&mut self, artifact: Arc<Artifact>) {
        self.compiled = self.compiled.saturating_add(1);
        let Some(bytes) = artifact.checked_retained_bytes() else {
            return;
        };
        let minimum = bytes
            .checked_add(core::mem::size_of::<CacheEntry>())
            .and_then(|bytes| bytes.checked_add(self.controls_bytes()));
        if minimum.is_none_or(|bytes| bytes > self.byte_budget) {
            return; // Valid one-shot compilation; never raises the owner bound.
        }
        if let Some(index) = self.find(&artifact.key) {
            self.remove(index);
        }
        loop {
            if self.entries.len() < self.entries.capacity() && self.fits(bytes) {
                break;
            }
            // Existing capacity remains charged after eviction. Release an
            // empty buffer if that high-water allocation alone prevents reuse.
            if self.entries.is_empty() && !self.fits(bytes) {
                self.entries = Vec::new();
            }
            if self.entries.len() == self.entries.capacity()
                && let Some(capacity) = self.growth_capacity(bytes)
            {
                if self.reserve_slots(capacity).is_none() {
                    return; // Cache decline only: the caller still owns/runs it.
                }
                // Allocators may supply more capacity than requested. The
                // observed allocation, rather than the growth target, rules.
                while !self.entries.is_empty() && !self.fits(bytes) {
                    self.evict_oldest();
                }
                if !self.fits(bytes) {
                    self.entries = Vec::new();
                    return;
                }
                break;
            }
            self.evict_oldest();
        }
        // fits() checked this addition as well as the full charge.
        self.retained_payload += bytes;
        let index = self
            .entries
            .partition_point(|entry| entry.artifact.key.pc <= artifact.key.pc);
        let recency = self.next_recency();
        self.entries.insert(index, CacheEntry { artifact, recency });
    }
}

struct Artifact {
    key: ArtifactKey,
    identity: Arc<Identity>,
    code: Arc<Vec<u8>>,
    source_map: Vec<(stela_compiler::GuestAddress, usize)>,
    source: Vec<u8>,
    requirements: MemoryRequirements,
    branch_type: u8,
    #[cfg(feature = "native-profile")]
    profile: stela_compiler::block::profile::CompileProfile,
}

impl Artifact {
    fn retained_bytes(&self) -> usize {
        // Only admitted entries call this infallible accounting accessor.
        self.checked_retained_bytes()
            .expect("retained artifact charge")
    }
    fn checked_retained_bytes(&self) -> Option<usize> {
        let bytes = [
            core::mem::size_of::<Self>(),
            2 * core::mem::size_of::<usize>(),
            core::mem::size_of::<Identity>(),
            2 * core::mem::size_of::<usize>(),
            crate::machine::engine::installed_code::ARC_VEC_METADATA_BYTES,
            self.code.capacity(),
            self.source.capacity(),
            self.source_map
                .capacity()
                .checked_mul(core::mem::size_of::<(stela_compiler::GuestAddress, usize)>())?,
            self.key.controls_sha256.len(),
            2 * core::mem::size_of::<usize>(),
            self.identity.source_sha256.capacity(),
            self.identity.native_sha256.capacity(),
            self.identity.controls_sha256.capacity(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add);
        #[cfg(feature = "native-profile")]
        let bytes = bytes?.checked_add(self.profile.retained_bytes()?);
        bytes
    }
}

/// Created only from Machine's mutable frame and effective controls.
/// Native code, context and memory services are installed/borrowed on its fixed
/// owner's Host. The original CPU borrow survives the returned payload.
pub struct NativeRun<'a> {
    pub(super) memory: &'a mut SharedMemory,
    state: &'a mut GuestState,
    pc: &'a mut u64,
    retired: &'a mut u64,
    btype: &'a mut u8,
    worker: publication::WorkerId,
    artifact: Arc<Artifact>,
    pub(super) limits: Limits,
    executed_bodies: u64,
    epoch_retired: u64,
}
impl NativeRun<'_> {
    pub fn identity(&self) -> &Identity {
        &self.artifact.identity
    }
}
/// Full native observation plus the original exclusively borrowed frame. The
/// latter cannot be replaced by a parked snapshot or an acknowledgement count.
pub struct ReturnedRun<'a> {
    run: NativeRun<'a>,
    observation: Option<Observation>,
}
#[derive(Debug)]
pub struct Observation {
    /// Immutable provenance shared with the exact artifact that executed.
    /// Cloning an observation's provenance keeps its bytes without copying
    /// three digest allocations on every warm native return.
    pub identity: Arc<Identity>,
    pub artifact_cache: ArtifactCacheStats,
    pub native: Option<NativeExit>,
    pub memory_fault: Option<crate::memory::domain::MemoryFault>,
    pub source_failure: Option<policy::Failure>,
    pub status: Result<(), MemoryStatus>,
    /// Last checked materialized boundary. A native Host fault leaves the
    /// current frame unchecked; this field is then diagnostic history only.
    pub settled_pc: u64,
    /// Retired source prefix in the final executed body (fault indexing).
    pub retired: u64,
    pub epoch_retired: u64,
    pub executed_bodies: u64,
    pub epoch_end: NativeEpochEnd,
    pub physical_processor: Option<u32>,
    pub(super) settlement: Option<Settlement>,
}
/// Sealed permission from this exact recovered frame, separate from the public
/// diagnostic fields. It is consumed once by stopped source settlement.
#[derive(Debug)]
pub(super) struct Settlement {
    pub(super) machine: Arc<ExecutionDomain>,
    pub(super) binding: publication::WorkerBinding,
    pub(super) generation: u64,
    pub(super) pc: u64,
    pub(super) retired: u64,
    pub(super) executed_bodies: u64,
    pub(super) terminal: u32,
    pub(super) fault_word: Option<u32>,
    pub(super) native: Option<NativeExit>,
    pub(super) memory_fault: Option<crate::memory::domain::MemoryFault>,
    pub(super) source_failure: Option<policy::Failure>,
    pub(super) status: Result<(), MemoryStatus>,
    controls_sha256: Option<alloc::string::String>,
}

impl publication::sealed::NativeFrame for NativeRun<'_> {}
impl<'a> publication::NativeFrame for NativeRun<'a> {
    type Returned = ReturnedRun<'a>;
    fn execute(mut self, host: &mut dyn Host) -> Self::Returned {
        let mut observation = Observation {
            identity: Arc::clone(&self.artifact.identity),
            artifact_cache: self.memory.artifacts.stats(),
            native: None,
            memory_fault: None,
            source_failure: None,
            status: Err(MemoryStatus::Unsupported),
            settled_pc: *self.pc,
            retired: 0,
            epoch_retired: 0,
            executed_bodies: 0,
            epoch_end: NativeEpochEnd::Failure,
            physical_processor: None,
            settlement: None,
        };
        observation.status = self.enter(host, &mut observation);
        observation.source_failure = self.memory.memory.policy_mut().failure;
        observation.executed_bodies = self.executed_bodies;
        observation.epoch_retired = self.epoch_retired;
        observation.artifact_cache = self.memory.artifacts.stats();
        #[cfg(feature = "native-profile")]
        self.memory.epochs.record(self.limits, &observation);
        ReturnedRun {
            run: self,
            observation: Some(observation),
        }
    }
}
impl NativeRun<'_> {
    fn enter(
        &mut self,
        host: &mut dyn Host,
        observation: &mut Observation,
    ) -> Result<(), MemoryStatus> {
        if self.memory.machine.quarantined() {
            return Err(MemoryStatus::Domain);
        }
        if host.native_worker() != Some(self.worker) {
            return Err(MemoryStatus::Unsupported);
        }
        let authority = NativeSystemTarget::capture_for(self.worker, host.native_cpu_lease())
            .map_err(|_| MemoryStatus::Unsupported)?;
        #[cfg(feature = "native-profile")]
        host.native_timing(super::super::NativeTimingPhase::CpuVerified);
        observation.physical_processor = Some(authority.physical_processor());
        if !authority.target().supports(self.artifact.identity.target) {
            return Err(MemoryStatus::Unsupported);
        }
        // A service/publication loan outlives both callback finalization and PC
        // settlement. This Host borrow pins the installed arena throughout them.
        #[cfg(feature = "native-profile")]
        let measured = host.native_timing_work_start(Work::PinnedStorage);
        let execution = self.memory.memory.execution_session();
        #[cfg(feature = "native-profile")]
        if let Some(started) = measured {
            host.native_timing_work_end(Work::PinnedStorage, started);
        }
        let execution = execution?;
        let result = self.enter_epoch(host, &authority, &execution, observation);
        #[cfg(feature = "native-profile")]
        host.native_timing(super::super::NativeTimingPhase::BodyReturned);
        result
    }

    fn enter_body(
        &mut self,
        host: &mut dyn Host,
        authority: &NativeSystemTarget,
        execution: &crate::memory::domain::MemoryExecutionSession,
        artifact: Arc<Artifact>,
        observation: &mut Observation,
    ) -> Result<bool, MemoryStatus> {
        if self.memory.machine.quarantined() {
            return Err(MemoryStatus::Domain);
        }
        #[cfg(feature = "native-profile")]
        let measured = host.native_timing_work_start(Work::CodeInstallation);
        let installed = match host.install_immutable(&artifact.code) {
            Ok(code) => Ok(code),
            Err(crate::machine::InstallError::Full) => {
                // This fixed owner has returned/recovered its preceding frame.
                // Installed reuse pointers remain inside this Host;
                // discard invalidates its reuse metadata before the retry. The
                // shared lane never uses legacy cached block addresses.
                host.discard_code();
                host.install_immutable(&artifact.code)
                    .map_err(|_| MemoryStatus::Unsupported)
            }
        };
        #[cfg(feature = "native-profile")]
        if let Some(started) = measured {
            host.native_timing_work_end(Work::CodeInstallation, started);
        }
        let code = installed?;
        #[cfg(feature = "native-profile")]
        if self.executed_bodies == 0 {
            host.native_timing(super::super::NativeTimingPhase::CodeInstalled);
        }
        #[cfg(feature = "native-profile")]
        let measured = host.native_timing_work_start(Work::MemoryPreparation);
        let entry = self.memory.memory.prepare_native_system_in(
            artifact.requirements,
            authority,
            execution,
        );
        #[cfg(feature = "native-profile")]
        if let Some(started) = measured {
            host.native_timing_work_end(Work::MemoryPreparation, started);
        }
        let entry = entry?;
        #[cfg(feature = "native-profile")]
        if self.executed_bodies == 0 {
            host.native_timing(super::super::NativeTimingPhase::MemoryPrepared);
        }
        // Installation and checked preparation are synchronous and can consume
        // the remaining quantum. Do not begin another body after they do.
        if self.executed_bodies != 0 && self.limits.expired(host) {
            observation.epoch_end = NativeEpochEnd::Deadline;
            return Ok(false);
        }
        let artifact_slot = &mut self.artifact;
        let executed_bodies = &mut self.executed_bodies;
        let mut context = ExecutionContext::default();
        let mut raw = None;
        let mut malformed = false;
        #[cfg(feature = "native-profile")]
        let measured = host.native_timing_work_start(Work::CheckedBody);
        // SAFETY: the source-bound artifact, real frame, effective policy, canonical RAM,
        // current physical target and local installed arena all stay exclusively borrowed through
        // native return, fault and settlement.
        let entered = unsafe {
            entry.with_checked_view(|view| {
                let mut context_loan = ContextLoan::memory(&mut context, view);
                let result = host.execute_context(code, self.state, context_loan.context());
                if let Some(NativeExit::Fault(fault)) = result {
                    self.memory.machine.record(super::terminal::FailureCapture {
                        pe: artifact_slot.identity.pe,
                        pc: *self.pc,
                        retired: *self.retired,
                        code,
                        fault,
                    });
                }
                // Permission/domain admission can fail before the callback, and
                // Host None explicitly refuses before native effects. Only an
                // Some exit/fault replaces the preceding body's identity.
                if result.is_some() {
                    *artifact_slot = artifact;
                    observation.identity = Arc::clone(&artifact_slot.identity);
                    observation.retired = 0;
                    observation.native = result;
                    observation.memory_fault = None;
                    *executed_bodies += 1;
                }
                malformed = !context_loan.context().has_supported_header()
                    || context_loan.context().memory != core::ptr::from_mut(view).cast();
                raw = Some((
                    view.fault_kind,
                    view.fault_access,
                    view.fault_address,
                    view.fault_pc,
                    view.completed_bytes,
                ));
                result
            })
        };
        #[cfg(feature = "native-profile")]
        if let Some(started) = measured {
            host.native_timing_work_end(Work::CheckedBody, started);
        }
        if malformed {
            return Err(MemoryStatus::Domain);
        }
        let (status, access, address, pc, completed_bytes) = raw.ok_or(MemoryStatus::Domain)?;
        let status = MemoryStatus::from_code(status).ok_or(MemoryStatus::Domain)?;
        let access = FaultAccess::from_code(access).ok_or(MemoryStatus::Domain)?;
        if status != MemoryStatus::Success {
            observation.memory_fault = Some(crate::memory::domain::MemoryFault {
                status,
                access,
                address,
                pc,
                completed_bytes,
            });
        }
        let result = entered?;
        let native = result.ok_or(MemoryStatus::Unsupported)?;
        if matches!(native, NativeExit::Fault(_)) {
            // The checked body dereferences no direct guest VA. A native fault
            // can occur during frame/helper/commit bookkeeping, so source-map
            // indexing proves no resumable register, PC or retirement boundary.
            observation.memory_fault = None;
            observation.epoch_end = NativeEpochEnd::Failure;
            return Err(MemoryStatus::Domain);
        }
        let (settled_pc, retired) = if status != MemoryStatus::Success {
            observation.memory_fault = Some(crate::memory::domain::MemoryFault {
                status,
                access,
                address,
                pc,
                completed_bytes,
            });
            let index = self
                .artifact
                .source_map
                .iter()
                .position(|(source, _)| source.0 == pc)
                .ok_or(MemoryStatus::Domain)?;
            (pc, index as u64)
        } else {
            match native {
                NativeExit::Fault(_) => return Err(MemoryStatus::Domain),
                NativeExit::Exit { next_pc, kind } => {
                    let kind = ExitKind::try_from(kind).map_err(|_| MemoryStatus::Domain)?;
                    let count = self.artifact.source.len() as u64 / 4;
                    let service = matches!(
                        kind,
                        ExitKind::System
                            | ExitKind::PointerAuthentication
                            | ExitKind::Amx
                            | ExitKind::FloatingPoint
                            | ExitKind::Trap
                    );
                    let terminal_pc =
                        self.artifact.identity.pc + self.artifact.source.len() as u64 - 4;
                    if service && kind != ExitKind::Trap && next_pc != terminal_pc {
                        return Err(MemoryStatus::Domain);
                    }
                    // Checked callbacks use System as their failed exit. With
                    // Success, the unexecuted terminal is the final source word.
                    (
                        if service { terminal_pc } else { next_pc },
                        count - u64::from(service),
                    )
                }
            }
        };
        let next_btype = match native {
            NativeExit::Exit { kind, .. }
                if status == MemoryStatus::Success
                    && matches!(
                        ExitKind::try_from(kind),
                        Ok(ExitKind::Fallthrough
                            | ExitKind::Direct
                            | ExitKind::Indirect
                            | ExitKind::Call
                            | ExitKind::Return)
                    ) =>
            {
                self.artifact.branch_type
            }
            _ if retired == 0 => *self.btype,
            _ => 0,
        };
        *self.btype = next_btype;
        *self.pc = settled_pc;
        *self.retired = self.retired.wrapping_add(retired);
        observation.settled_pc = settled_pc;
        observation.retired = retired;
        self.epoch_retired = self.epoch_retired.wrapping_add(retired);
        #[cfg(feature = "native-profile")]
        host.native_instruction_sample(super::super::NativeInstructionSample {
            source: &self.artifact.source,
            source_map: &self.artifact.source_map,
            native_bytes: self.artifact.code.len(),
            register_spans: &self.artifact.profile.register_spans,
            retired,
            faulting: status != MemoryStatus::Success,
            deferred_terminal: status == MemoryStatus::Success
                && retired < self.artifact.source.len() as u64 / 4,
        });
        // This happens while the owner-local Host/code arena, RAM and
        // current target proof are still borrowed, before Release publication.
        Ok(true)
    }
}

/// Machine-only frame creation and source fetch. The outer scheduler still
/// owns interrupt/debug/PMU boundaries and the complete stopped-worker cohort.
impl<H: Host, D: Devices> Machine<H, D> {
    /// Prepare this current PE, leaving the ordinary serial engine off
    /// while its mutable GuestState/PC/retirement fields are lent.
    ///
    /// # Safety
    /// `binding` names this PE's source-checked, exclusively assigned physical
    /// worker and matches the publication inventory. All code/MMU/control
    /// publications and unjoined DMA/host writers are stopped; RAM registration
    /// and event ownership remain live. Interrupts, timers, debug, PMU and every
    /// BSP System/PAC/AMX service are settled before dispatch/after recovery by
    /// the scheduler. The Cpu owns the persistent canonical memory/event
    /// service; its inactive legacy fields cannot authorize serial fallback.
    /// Stopped services must use that same owner and held-generation protocol.
    /// Direct `SYSTEM_MODE` data writers remain excluded, including between calls.
    /// This bounded frame alone is not full machine SMP admission.
    pub unsafe fn shared_native_run<'a>(
        &'a mut self,
        binding: publication::WorkerBinding,
    ) -> Result<NativeRun<'a>, MemoryStatus> {
        if self.native_failure.is_some() || self.native_memory_identity.quarantined() {
            return Err(MemoryStatus::Domain);
        }
        let memory = self
            .cpu
            .canonical_memory
            .as_ref()
            .ok_or(MemoryStatus::Unsupported)?;
        if !Arc::ptr_eq(&memory.machine, &self.native_memory_identity) {
            return Err(MemoryStatus::Unsupported);
        }
        if self.pending_native_device_access().is_some() {
            return Err(MemoryStatus::Unsupported);
        }
        let bytes = source_window(self.cpu.pc, &self.breakpoints, &self.traces);
        prepare(
            &mut self.cpu,
            binding,
            self.current,
            &self.profile,
            &self.profile_missing,
            &self.admit_table,
            PreparationBoundary {
                source_bytes: bytes,
                translation_generation: self.translation_generation,
            },
        )
        .map_err(|failure| failure.status)
    }
}

/// A host observation is a source boundary, even when a longer immutable
/// artifact was compiled before the observation was installed. The two point
/// lists are sorted by Machine's setters; unaligned PCs cannot be reached.
fn source_window(pc: u64, breakpoints: &[u64], traces: &[u64]) -> usize {
    let mut bytes = super::super::window(pc);
    for points in [breakpoints, traces] {
        let next = points.partition_point(|point| *point <= pc);
        if let Some(point) = points[next..].iter().find(|point| point.is_multiple_of(4)) {
            bytes = bytes.min(usize::try_from(*point - pc).unwrap_or(usize::MAX));
        }
    }
    bytes
}

struct PreparationBoundary {
    source_bytes: usize,
    translation_generation: u64,
}

fn prepare<'a>(
    cpu: &'a mut crate::machine::Cpu,
    binding: publication::WorkerBinding,
    pe: usize,
    cpu_profile: &crate::machine::CpuProfile,
    missing: &[crate::machine::system::Register],
    admit: &stela_contracts::chip::AdmitTable,
    boundary: PreparationBoundary,
) -> Result<NativeRun<'a>, PreparationFailure> {
    let PreparationBoundary {
        source_bytes,
        translation_generation,
    } = boundary;
    if cpu
        .canonical_memory
        .as_ref()
        .is_some_and(|memory| memory.machine.quarantined())
    {
        return Err(PreparationFailure::at(
            "terminal canonical execution domain",
            MemoryStatus::Domain,
            (pe, cpu.pc, cpu.pstate.el),
            None,
        ));
    }
    let location = (pe, cpu.pc, cpu.pstate.el);
    let at = |stage, status| PreparationFailure::at(stage, status, location, None);
    if binding.pe != pe || cpu.monitor.is_some() {
        return Err(at("worker/frame ownership", MemoryStatus::Unsupported));
    }
    if !cpu.pc.is_multiple_of(4) {
        return Err(at("source PC alignment", MemoryStatus::Alignment));
    }
    let controls = Controls::capture(cpu, cpu_profile.name, missing)
        .map_err(|status| at("control capture", status))?;
    let pc = cpu.pc;
    let entry_sctlr = cpu.regime_sctlr();
    let asimd = controls.asimd;
    let btype = &mut cpu.pstate.btype;
    let state = &mut cpu.state;
    let retired = &mut cpu.retired;
    let frame_pc = &mut cpu.pc;
    let memory = cpu
        .canonical_memory
        .as_mut()
        .ok_or_else(|| at("canonical memory ownership", MemoryStatus::Unsupported))?;
    if memory.pe != pe {
        return Err(at("canonical PE ownership", MemoryStatus::Unsupported));
    }
    let execution = memory
        .memory
        .execution_loan()
        .map_err(|status| at("source mapping pin", status))?;
    let artifact = {
        // SAFETY: prepare is reached only under shared_native_run's held cohort
        // and no-code/MMU/control/unjoined-writer contract. No guest or Host service
        // runs until this witness is dropped below; compilation is private work.
        let source = unsafe {
            source::ExecuteTranslation::first(
                &memory.ram,
                &controls,
                &execution,
                pc,
                #[cfg(feature = "native-profile")]
                &memory.source,
            )
        }
        .map_err(|failure| {
            let status = match failure {
                source::FetchFailure::Fault(_) => MemoryStatus::Unsupported,
                source::FetchFailure::Refused(status) => status,
            };
            at("first instruction fetch", status).detail(alloc::format!("{failure:?}"))
        })?;
        let first = source.first_word();
        let guarded = source.guarded();
        let at = |stage, status| PreparationFailure::at(stage, status, location, Some(first));
        if *btype != 0 && guarded && !source::target_accepts(first, *btype, entry_sctlr, location.2)
        {
            return Err(at("branch target compatibility", MemoryStatus::Unsupported));
        }
        let profile = stela_compiler::block::BlockProfile::new(Features::SYSTEM_MODE)
            .with_checked_memory(controls.sp);
        let target = memory.ram.target();
        let key = ArtifactKey {
            pe,
            pc,
            worker: binding.worker,
            profile: cpu_profile.name,
            admission: AdmissionPolicy {
                profile_chip: cpu_profile.chip,
                table_chip: admit.chip(),
                withheld: admit.withheld(),
                asimd,
            },
            controls_sha256: controls.shared_identity(),
            compiler_source_sha256: stela_compiler::SOURCE_SHA256,
            abi: profile.abi(),
            target,
            guarded,
        };
        let admitted = |word| {
            admit.admit(word) == word
                && (!super::super::is_floating_point(word) || asimd)
                && cpu_profile.chip.checks(word).iter().all(|check| {
                    matches!(
                        check,
                        stela_contracts::chip::Check::Fp | stela_contracts::chip::Check::FpAdvSimd
                    )
                })
        };
        let candidate = memory
            .artifacts
            .candidate(&key)
            .filter(|(_, artifact)| artifact.source.len() <= source_bytes);
        let artifact = if let Some((index, artifact)) = candidate {
            // A hit is immutable compilation reuse. Rewalk executable source
            // and read canonical bytes for its exact prefix every
            // time. A shorter compiled prefix remains a valid scheduling boundary;
            // words after it cannot grant or revoke its instruction effects.
            let bytes = artifact.source.len();
            if bytes == 0 || !bytes.is_multiple_of(4) || bytes > super::super::window(pc) {
                return Err(at("cached source extent", MemoryStatus::Domain));
            }
            // The existing compiler block bound also bounds private revalidation
            // staging. Every hit still walks source permissions and copies
            // canonical bytes; only the per-round heap allocation disappears.
            let mut staging = [0; super::super::MAX_BLOCK_BYTES as usize];
            let input = staging
                .get_mut(..bytes)
                .ok_or_else(|| at("cached source staging", MemoryStatus::Domain))?;
            source
                .read_into(input)
                .map_err(|status| at("cached executable source fetch", status))?;
            // The immutable artifact was admitted in full before construction.
            // Exact bytes and the fresh key above bind every pure decoder input:
            // both chips, withheld features and effective ASIMD permission.
            // Reuse only that decoder result; the source walk, BTYPE entry check,
            // current controls and physical execution permission remain separate.
            (input == artifact.source.as_slice()).then_some((index, artifact))
        } else {
            None
        };
        match artifact {
            Some((index, artifact)) => {
                memory.artifacts.reuse(index);
                artifact
            }
            None => {
                let mut input = alloc::vec![0; source_bytes];
                // Instruction walks use the same source controls, canonical descriptor
                // owner and original physical bytes. No direct identity-frame shortcut.
                source
                    .read_into(&mut input)
                    .map_err(|status| at("cold executable source fetch", status))?;
                // A denied later access check must not erase an already reached GPR
                // prefix. End before it; the held scheduler checks that exact next word.
                if let Some(boundary) = input
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .position(|raw| !admitted(u32::from_le_bytes(*raw)))
                {
                    if boundary == 0 {
                        return Err(at("instruction admission", MemoryStatus::Unsupported));
                    }
                    input.truncate(boundary * 4);
                }
                let plan = stela_compiler::block::CompilationPlan::new(
                    &input,
                    stela_compiler::GuestAddress(pc),
                    &stela_compiler::Options::new(profile, target),
                )
                .map_err(|error| {
                    at("compilation planning", MemoryStatus::Unsupported).detail(error.to_string())
                })?;
                let bytes = plan.source_bytes();
                input.truncate(bytes);
                if !input
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .all(|raw| admitted(u32::from_le_bytes(*raw)))
                {
                    return Err(at("compiled prefix admission", MemoryStatus::Unsupported));
                }
                let requirements = plan
                    .memory_requirements()
                    .ok_or_else(|| at("checked memory requirements", MemoryStatus::Unsupported))?;
                let (compiled, _profile) = {
                    #[cfg(feature = "native-profile")]
                    {
                        plan.compile_profiled()
                    }
                    #[cfg(not(feature = "native-profile"))]
                    {
                        plan.compile().map(|block| (block, ()))
                    }
                }
                .map_err(|error| {
                    at("native emission", MemoryStatus::Unsupported).detail(error.to_string())
                })?;
                if !compiled.fault_recovery.is_empty() {
                    return Err(at(
                        "checked fault recovery contract",
                        MemoryStatus::Unsupported,
                    ));
                }
                let identity = Identity {
                    pe,
                    pc,
                    source_sha256: stela_formats::sha256(&input),
                    native_sha256: stela_formats::sha256(&compiled.native.x86_64_code),
                    controls_sha256: key.controls_sha256.as_ref().into(),
                    compiler_source_sha256: stela_compiler::SOURCE_SHA256,
                    abi: profile.abi(),
                    target,
                    requirements,
                };
                let artifact =
                    Arc::new(Artifact {
                        key,
                        identity: Arc::new(identity),
                        code: Arc::new(compiled.native.x86_64_code),
                        source_map: compiled.native.source_map,
                        branch_type: source::branch_type(
                            u32::from_le_bytes(input.last_chunk().copied().ok_or_else(|| {
                                at("compiled source extent", MemoryStatus::Domain)
                            })?),
                            guarded,
                        ),
                        source: input,
                        requirements,
                        #[cfg(feature = "native-profile")]
                        profile: _profile,
                    });
                memory.artifacts.insert(Arc::clone(&artifact));
                artifact
            }
        }
    };
    drop(execution);
    memory.artifacts.remember_controls(&controls);
    memory
        .memory
        .policy_mut()
        .refresh(controls, translation_generation);
    Ok(NativeRun {
        memory,
        state,
        pc: frame_pc,
        retired,
        btype,
        worker: binding.worker,
        artifact,
        limits: Limits::single(),
        executed_bodies: 0,
        epoch_retired: 0,
    })
}

/// Disjoint PE frames and the one owning Machine's publication state.
/// The BSP may use its own Host while fixed APs execute the other frames.
pub struct Cohort<'a, H: Host> {
    pub host: &'a mut H,
    pub inventory: &'a mut publication::WorkerPublications,
    pub frames: Vec<NativeRun<'a>>,
}
impl<H: Host, D: Devices> Machine<H, D> {
    /// Bind the intended fixed workers; each physical Host must still publish
    /// its source-checked identity before any frame dispatch.
    pub fn bind_native_workers(
        &mut self,
        bindings: &[publication::WorkerBinding],
    ) -> Result<Vec<publication::WorkerOwner>, publication::PublicationError> {
        if self.native_publication.is_some() {
            return Err(publication::PublicationError::AlreadyInitialized);
        }
        if bindings.len() != self.peers.len()
            || (0..self.peers.len()).any(|pe| !bindings.iter().any(|binding| binding.pe == pe))
        {
            return Err(publication::PublicationError::ProcessorCount {
                expected: self.peers.len(),
                actual: bindings.len(),
            });
        }
        let (inventory, owners) = publication::WorkerPublications::new(bindings)?;
        self.native_publication = Some(inventory);
        Ok(owners)
    }
    /// Bind exactly all instantiated canonical Cpu owners; Off slots carry no
    /// worker permission. The roster cannot grow through an unjoined CPU start.
    pub fn bind_active_native_workers(
        &mut self,
        bindings: &[publication::WorkerBinding],
    ) -> Result<Vec<publication::WorkerOwner>, publication::PublicationError> {
        if !matches!(
            self.peers.get(self.current),
            Some(super::super::processors::Peer::Running)
        ) {
            return Err(publication::PublicationError::UnknownPe(self.current));
        }
        if self.native_publication.is_some() {
            return Err(publication::PublicationError::AlreadyInitialized);
        }
        let active: Vec<_> = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(pe, peer)| {
                (!matches!(peer, super::super::processors::Peer::Off)).then_some(pe)
            })
            .collect();
        if bindings.len() != active.len()
            || active
                .iter()
                .any(|pe| !bindings.iter().any(|binding| binding.pe == *pe))
            || bindings.iter().any(|binding| !active.contains(&binding.pe))
        {
            return Err(publication::PublicationError::ProcessorCount {
                expected: active.len(),
                actual: bindings.len(),
            });
        }
        for &pe in &active {
            let cpu = match &self.peers[pe] {
                super::super::processors::Peer::Running if pe == self.current => &self.cpu,
                super::super::processors::Peer::Parked(parked) => parked.cpu(),
                _ => return Err(publication::PublicationError::UnknownPe(pe)),
            };
            if !cpu.canonical_memory.as_ref().is_some_and(|memory| {
                memory.pe == pe && Arc::ptr_eq(&memory.machine, &self.native_memory_identity)
            }) {
                return Err(publication::PublicationError::UnknownPe(pe));
            }
        }
        let (inventory, owners) = publication::WorkerPublications::new(bindings)?;
        self.native_publication = Some(inventory);
        Ok(owners)
    }

    pub fn native_worker_publications(&mut self) -> Option<&mut publication::WorkerPublications> {
        self.native_publication.as_mut()
    }

    /// Borrow every active PE and the publication inventory together.
    ///
    /// # Safety
    /// The shared_native_run scheduler/owner preconditions apply to every member.
    /// No frame may be dropped or bypassed as a substitute for recovery.
    /// System/PAC/AMX/IRQ/PMU settlement requires all affected frames returned and
    /// the exact held stopped-cohort lease before changing controls or ACKing.
    pub unsafe fn shared_native_cohort<'a>(
        &'a mut self,
        bindings: &[publication::WorkerBinding],
    ) -> Result<Cohort<'a, H>, MemoryStatus> {
        if self.pending_native_device_access().is_some() {
            return Err(MemoryStatus::Unsupported);
        }
        self.native_cohort(bindings, false)
            .map_err(|failure| failure.status)
    }

    pub(super) fn native_cohort<'a>(
        &'a mut self,
        bindings: &[publication::WorkerBinding],
        runnable_only: bool,
    ) -> Result<Cohort<'a, H>, PreparationFailure> {
        if self.native_failure.is_some() || self.native_memory_identity.quarantined() {
            return Err(MemoryStatus::Domain.into());
        }
        if bindings.len() != self.peers.len() || (!runnable_only && self.waiting.is_some()) {
            return Err(MemoryStatus::Unsupported.into());
        }
        let mut services = Vec::new();
        for (pe, peer) in self.peers.iter().enumerate() {
            let cpu = match peer {
                super::super::processors::Peer::Running if pe == self.current => &self.cpu,
                super::super::processors::Peer::Parked(parked)
                    if runnable_only || parked.native_ready() =>
                {
                    parked.cpu()
                }
                super::super::processors::Peer::Off => continue,
                _ => return Err(MemoryStatus::Unsupported.into()),
            };
            let memory = cpu
                .canonical_memory
                .as_ref()
                .ok_or(MemoryStatus::Unsupported)?;
            if memory.pe != pe || !Arc::ptr_eq(&memory.machine, &self.native_memory_identity) {
                return Err(MemoryStatus::Unsupported.into());
            }
            services.push(memory);
        }
        let first = services.first().ok_or(MemoryStatus::Unsupported)?;
        if services.iter().any(|candidate| {
            !Arc::ptr_eq(&candidate.ram, &first.ram) || !candidate.event.same_domain(&first.event)
        }) {
            return Err(MemoryStatus::Unsupported.into());
        }
        drop(services);
        let mut current = Some(&mut self.cpu);
        let mut frames = Vec::with_capacity(self.peers.len());
        for (pe, peer) in self.peers.iter_mut().enumerate() {
            if matches!(peer, super::super::processors::Peer::Off) {
                continue;
            }
            if runnable_only && self.processor_power.paused(pe) == Some(true) {
                continue;
            }
            let binding = bindings
                .iter()
                .find(|binding| binding.pe == pe)
                .copied()
                .ok_or(MemoryStatus::Unsupported)?;
            let cpu = match peer {
                super::super::processors::Peer::Running if pe == self.current => {
                    if runnable_only && self.waiting.is_some() {
                        continue;
                    }
                    current.take().ok_or(MemoryStatus::Domain)?
                }
                super::super::processors::Peer::Parked(parked)
                    if runnable_only && !parked.native_ready() =>
                {
                    continue;
                }
                super::super::processors::Peer::Parked(parked) if parked.native_ready() => {
                    parked.cpu_mut()
                }
                _ => return Err(MemoryStatus::Unsupported.into()),
            };
            let bytes = source_window(cpu.pc, &self.breakpoints, &self.traces);
            frames.push(prepare(
                cpu,
                binding,
                pe,
                &self.profile,
                &self.profile_missing,
                &self.admit_table,
                PreparationBoundary {
                    source_bytes: bytes,
                    translation_generation: self.translation_generation,
                },
            )?);
        }
        Ok(Cohort {
            host: &mut self.host,
            inventory: self
                .native_publication
                .as_mut()
                .ok_or(MemoryStatus::Unsupported)?,
            frames,
        })
    }
}

/// Dispatch/recover consume the lifetime-bound frame payload, using the
/// same generation protocol as stopped-worker ProcessorWrite publication.
pub fn dispatch<'a>(
    inventory: &mut publication::WorkerPublications,
    run: NativeRun<'a>,
) -> Result<publication::NativeLoan<NativeRun<'a>>, Box<publication::WithPayload<NativeRun<'a>>>> {
    inventory
        .dispatch(run.artifact.identity.pe, run)
        .map_err(Box::new)
}
pub type RecoveryFailure<'a> = Box<
    publication::WithPayload<
        publication::NativeReturned<ReturnedRun<'a>>,
        publication::RecoveryError<MemoryStatus>,
    >,
>;
pub fn recover<'a>(
    inventory: &mut publication::WorkerPublications,
    returned: publication::NativeReturned<ReturnedRun<'a>>,
) -> Result<Observation, RecoveryFailure<'a>> {
    let mut observation = None;
    let generation = returned.generation();
    let binding = returned.binding();
    inventory
        .recover(returned, |actual| {
            // PC/retirement were settled through this original loan before the
            // owner's code borrow ended. Preserve terminal failures for BSP handling.
            let observed = actual.observation.as_ref().ok_or(MemoryStatus::Domain)?;
            if *actual.run.pc != observed.settled_pc {
                return Err(MemoryStatus::Domain);
            }
            let terminal = u32::from_le_bytes(
                actual
                    .run
                    .artifact
                    .source
                    .last_chunk()
                    .copied()
                    .ok_or(MemoryStatus::Domain)?,
            );
            let fault_word = observed
                .memory_fault
                .map(|fault| {
                    let offset = fault
                        .pc
                        .checked_sub(actual.run.artifact.identity.pc)
                        .ok_or(MemoryStatus::Domain)?;
                    if !offset.is_multiple_of(4) {
                        return Err(MemoryStatus::Domain);
                    }
                    let offset = usize::try_from(offset).map_err(|_| MemoryStatus::Domain)?;
                    let word = actual
                        .run
                        .artifact
                        .source
                        .get(offset..offset.checked_add(4).ok_or(MemoryStatus::Domain)?)
                        .ok_or(MemoryStatus::Domain)?;
                    Ok(u32::from_le_bytes(
                        word.try_into().map_err(|_| MemoryStatus::Domain)?,
                    ))
                })
                .transpose()?;
            let mut observed = actual.observation.take().ok_or(MemoryStatus::Domain)?;
            observed.settlement = Some(Settlement {
                machine: Arc::clone(&actual.run.memory.machine),
                binding,
                generation,
                pc: *actual.run.pc,
                retired: *actual.run.retired,
                executed_bodies: actual.run.executed_bodies,
                terminal,
                fault_word,
                native: observed.native,
                memory_fault: observed.memory_fault,
                source_failure: observed.source_failure,
                status: observed.status,
                controls_sha256: matches!(
                    observed.source_failure,
                    Some(policy::Failure::DeviceRead { .. } | policy::Failure::DeviceWrite { .. })
                )
                .then(|| actual.run.artifact.identity.controls_sha256.clone()),
            });
            observation = Some(observed);
            Ok(())
        })
        .map_err(Box::new)?;
    Ok(observation.expect("successful recovery consumed actual returned payload"))
}

#[cfg(test)]
mod tests;
