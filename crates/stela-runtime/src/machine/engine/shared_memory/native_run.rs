//! An actual borrowed architectural frame; no Cpu or Host crosses a core.
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
/// in-memory artifact budget. Every actual PE has its own independent bound.
const ARTIFACT_CACHE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactCacheStats {
    pub compiled: u64,
    pub reused: u64,
    /// Retained Rust allocation capacities and metadata; allocator headers are
    /// outside this accounting. Artifacts, actual slot capacity and one
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

/// Source-independent identity, captured anew while the actual PE is owned.
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
    /// Whether the actual retained allocation plus additional payload fits.
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
    fn reserve_slots(&mut self, capacity: usize) -> Result<(), ()> {
        #[cfg(test)]
        if core::mem::take(&mut self.fail_next_growth) {
            return Err(());
        }
        // Vec's additional count is relative to length, not current capacity.
        let additional = capacity.checked_sub(self.entries.len()).ok_or(())?;
        self.entries.try_reserve_exact(additional).map_err(|_| ())
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
                if self.reserve_slots(capacity).is_err() {
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
        // fits() checked this addition as well as the full retained charge.
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

/// Created only from Machine's actual mutable frame and effective controls.
/// Native code, context and memory services are installed/borrowed on its fixed
/// owner's Host. The original CPU borrow survives the actual returned payload.
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
    /// Cloning an observation's provenance retains its bytes without copying
    /// three digest allocations on every warm native return.
    pub identity: Arc<Identity>,
    pub artifact_cache: ArtifactCacheStats,
    pub native: Option<NativeExit>,
    pub memory_fault: Option<crate::memory::domain::MemoryFault>,
    pub source_failure: Option<policy::Failure>,
    pub status: Result<(), MemoryStatus>,
    pub settled_pc: u64,
    /// Retired source prefix in the final executed body (fault indexing).
    pub retired: u64,
    pub epoch_retired: u64,
    pub executed_bodies: u64,
    pub epoch_end: NativeEpochEnd,
    pub physical_processor: Option<u32>,
    pub(super) settlement: Option<Settlement>,
}
/// Sealed authority from this exact recovered frame, separate from the public
/// diagnostic fields. It is consumed once by stopped source settlement.
#[derive(Debug)]
pub(super) struct Settlement {
    pub(super) machine: Arc<()>,
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
        #[cfg(feature = "native-profile")]
        let measured = host.native_timing_work_start(Work::CodeInstallation);
        let installed = match host.install_immutable(&artifact.code) {
            Ok(code) => Ok(code),
            Err(crate::machine::InstallError::Full) => {
                // This fixed owner has returned/recovered its preceding frame.
                // Installed reuse pointers remain inside this actual Host;
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
        // SAFETY: the source-bound artifact, exact real frame, effective policy,
        // canonical RAM, current physical target and local installed arena all
        // stay exclusively borrowed through native return, fault and settlement.
        #[cfg(feature = "native-profile")]
        let measured = host.native_timing_work_start(Work::CheckedBody);
        let entered = unsafe {
            entry.with_checked_view(|view| {
                let mut context_loan = ContextLoan::memory(&mut context, view);
                let result = host.execute_context(code, self.state, context_loan.context());
                // Authority/domain admission can fail before the callback, and
                // Host None explicitly refuses before native effects. Only an
                // actual Some exit/fault replaces the preceding body's identity.
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
                NativeExit::Fault(fault) => {
                    // No direct guest VA is dereferenced by a checked body.
                    // Retain its exact reached source prefix for diagnostics,
                    // but a host bug/fault is terminal, never an ARM data abort.
                    if fault.offset >= self.artifact.code.len() {
                        return Err(MemoryStatus::Domain);
                    }
                    let index = self
                        .artifact
                        .source_map
                        .partition_point(|(_, offset)| *offset <= fault.offset)
                        .checked_sub(1)
                        .ok_or(MemoryStatus::Domain)?;
                    let source_pc = self.artifact.source_map[index].0.0;
                    *self.pc = source_pc;
                    *self.retired = self.retired.wrapping_add(index as u64);
                    if index != 0 {
                        *self.btype = 0;
                    }
                    observation.settled_pc = source_pc;
                    observation.retired = index as u64;
                    self.epoch_retired = self.epoch_retired.wrapping_add(index as u64);
                    return Err(MemoryStatus::Domain);
                }
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
        // This happens while the actual owner-local Host/code arena, RAM and
        // current target proof are still borrowed, before Release publication.
        Ok(true)
    }
}

/// Machine-only frame creation and source fetch. The outer scheduler still
/// owns interrupt/debug/PMU boundaries and the complete stopped-worker cohort.
impl<H: Host, D: Devices> Machine<H, D> {
    /// Prepare this actual current PE, leaving the ordinary serial engine off
    /// while its mutable GuestState/PC/retirement fields are lent.
    ///
    /// # Safety
    /// `binding` names this PE's source-qualified, exclusively assigned physical
    /// worker and matches the retained publication inventory. All code/MMU/control
    /// publications and unjoined DMA/host writers are stopped; RAM registration
    /// and event ownership remain live. Interrupts, timers, debug, PMU and every
    /// BSP System/PAC/AMX service are settled before dispatch/after recovery by
    /// the scheduler. The actual Cpu owns the persistent canonical memory/event
    /// service; its inactive legacy fields cannot authorize serial fallback.
    /// Stopped services must use that same owner and held-generation protocol.
    /// Direct `SYSTEM_MODE` data writers remain excluded, including between calls.
    /// This bounded frame alone is not full machine SMP admission.
    pub unsafe fn shared_native_run<'a>(
        &'a mut self,
        binding: publication::WorkerBinding,
    ) -> Result<NativeRun<'a>, MemoryStatus> {
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

/// A host observation is an exact source boundary, even when a longer immutable
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
            // A hit is merely immutable compilation reuse. Rewalk executable source
            // and read actual canonical bytes for its exact retained prefix every
            // time. A shorter compiled prefix remains a valid scheduling boundary;
            // words after it cannot grant or revoke its instruction effects.
            let bytes = artifact.source.len();
            if bytes == 0 || !bytes.is_multiple_of(4) || bytes > super::super::window(pc) {
                return Err(at("cached source extent", MemoryStatus::Domain));
            }
            // The existing compiler block bound also bounds private revalidation
            // staging. Every hit still walks source permissions and copies actual
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
            // both actual chips, withheld features and effective ASIMD permission.
            // Reuse only that decoder result; the source walk, BTYPE entry check,
            // current controls and physical execution authority remain separate.
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

/// Disjoint actual PE frames and the one owning Machine's publication state.
/// The BSP may use its own Host while fixed APs execute the other frames.
pub struct Cohort<'a, H: Host> {
    pub host: &'a mut H,
    pub inventory: &'a mut publication::WorkerPublications,
    pub frames: Vec<NativeRun<'a>>,
}
impl<H: Host, D: Devices> Machine<H, D> {
    /// Bind the intended fixed workers; each physical Host must still publish
    /// its source-qualified actual identity before any frame dispatch.
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
    /// worker authority. The roster cannot grow through an unjoined CPU start.
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

    /// Borrow every actual active PE and the publication inventory together.
    ///
    /// # Safety
    /// The shared_native_run scheduler/owner preconditions apply to every member.
    /// No frame may be dropped or bypassed as a substitute for actual recovery.
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

/// Dispatch/recover consume the actual lifetime-bound frame payload, using the
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
mod artifact_tests {
    use super::*;
    use crate::machine::{
        engine::{NoDevices, tests::FakeHost},
        system::Register,
    };
    const PC: u64 = 0x4000;
    const DATA: u64 = 0x14000;
    const LEAF: u64 = 0x13020;
    const BINDING: publication::WorkerBinding = publication::WorkerBinding {
        pe: 0,
        worker: publication::WorkerId(0),
    };
    fn fixture() -> (Machine<FakeHost, NoDevices>, Arc<RegisteredSystemRam>) {
        let (mut machine, ram, events) = super::super::tests::machine();
        machine
            .install_shared_memory_for_processors(Arc::clone(&ram), &events)
            .unwrap();
        machine.cpu.pc = PC;
        let source: Vec<_> = [0x91000400u32, 0x17ffffff]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        unsafe { ram.publish_physical(DATA, &source) }.unwrap();
        (machine, ram)
    }
    fn prepare_artifact(
        machine: &mut Machine<FakeHost, NoDevices>,
        binding: publication::WorkerBinding,
    ) -> Result<Arc<Artifact>, MemoryStatus> {
        // Preparation only: no hosted fixture enters a physical native frame.
        let bytes = source_window(machine.cpu.pc, &machine.breakpoints, &machine.traces);
        let run = prepare(
            &mut machine.cpu,
            binding,
            machine.current,
            &machine.profile,
            &machine.profile_missing,
            &machine.admit_table,
            PreparationBoundary {
                source_bytes: bytes,
                translation_generation: machine.translation_generation,
            },
        )
        .map_err(|failure| failure.status)?;
        Ok(Arc::clone(&run.artifact))
    }
    fn capture_controls(machine: &Machine<FakeHost, NoDevices>) -> Result<Controls, MemoryStatus> {
        Controls::capture(&machine.cpu, machine.profile.name, &machine.profile_missing)
    }

    fn prepare_failure(
        machine: &mut Machine<FakeHost, NoDevices>,
        binding: publication::WorkerBinding,
    ) -> PreparationFailure {
        let bytes = source_window(machine.cpu.pc, &machine.breakpoints, &machine.traces);
        match prepare(
            &mut machine.cpu,
            binding,
            machine.current,
            &machine.profile,
            &machine.profile_missing,
            &machine.admit_table,
            PreparationBoundary {
                source_bytes: bytes,
                translation_generation: machine.translation_generation,
            },
        ) {
            Ok(_) => panic!("preparation unexpectedly succeeded"),
            Err(failure) => failure,
        }
    }

    #[test]
    fn preparation_refusal_preserves_source_and_owner_reason_without_execution() {
        use crate::machine::engine::{RequirementKind, Stop};
        let (mut machine, ram) = fixture();
        let state = machine.cpu.state.clone();
        let retired = machine.cpu.retired;
        let el = machine.cpu.pstate.el;
        let failure = prepare_failure(
            &mut machine,
            publication::WorkerBinding { pe: 1, ..BINDING },
        );
        assert_eq!(failure.status, MemoryStatus::Unsupported);
        let Stop::Unsupported(requirement) = failure.into_stop(0, 3) else {
            panic!()
        };
        assert_eq!((requirement.pc, requirement.el), (PC, el));
        let RequirementKind::NativePreparation(detail) = requirement.kind else {
            panic!()
        };
        assert!(detail.contains("worker/frame ownership"));
        assert!(detail.contains("PE=0"));
        assert!(!detail.contains("first_word="));

        // A genuine failed executable walk must retain the original MMU cause.
        unsafe { ram.publish_physical(LEAF, &0u64.to_le_bytes()) }.unwrap();
        let failure = prepare_failure(&mut machine, BINDING);
        let rendered = match failure.into_stop(0, 3) {
            Stop::Unsupported(requirement) => alloc::format!("{requirement}"),
            _ => panic!(),
        };
        assert!(rendered.contains("first instruction fetch"));
        assert!(rendered.contains("Fault("));
        assert_eq!(machine.cpu.state, state);
        assert_eq!(machine.cpu.pc, PC);
        assert_eq!(machine.cpu.retired, retired);
        assert_eq!(
            machine
                .cpu
                .canonical_memory
                .as_ref()
                .unwrap()
                .native_artifact_stats()
                .compiled,
            0
        );
    }

    #[test]
    fn warm_controls_reuse_digest_but_observe_every_actual_id_profile_and_missing_input() {
        let (mut machine, _) = fixture();
        prepare_artifact(&mut machine, BINDING).unwrap();
        let original = capture_controls(&machine).unwrap();
        let repeated = capture_controls(&machine).unwrap();
        assert!(Arc::ptr_eq(
            &original.shared_identity(),
            &repeated.shared_identity()
        ));
        for register in [
            Register::ID_AA64DFR0_EL1,
            Register::ID_AA64DFR1_EL1,
            Register::ID_AA64DFR2_EL1,
            Register::ID_AA64ISAR0_EL1,
            Register::ID_AA64ISAR1_EL1,
            Register::ID_AA64ISAR3_EL1,
            Register::ID_AA64MMFR0_EL1,
            Register::ID_AA64MMFR2_EL1,
            Register::ID_AA64PFR1_EL1,
        ] {
            let value = machine.cpu.read(register);
            machine.cpu.registers.set_raw(register, 0, value ^ 1);
            if let Ok(changed) = capture_controls(&machine) {
                assert_ne!(original.identity(), changed.identity(), "{register:?}");
                assert!(!Arc::ptr_eq(
                    &original.shared_identity(),
                    &changed.shared_identity()
                ));
            }
            machine.cpu.registers.set_raw(register, 0, value);
            machine.profile_missing.push(register);
            assert!(capture_controls(&machine).is_err(), "{register:?}");
            machine.profile_missing.pop();
        }
        let changed = Controls::capture(
            &machine.cpu,
            "another-declared-machine",
            &machine.profile_missing,
        )
        .unwrap();
        assert_ne!(original.identity(), changed.identity());
        // Even an unrelated missing declaration changes the exact reuse key,
        // although it does not alter the established effective-control digest.
        machine.profile_missing.push(Register::TTBR0_EL1);
        let changed = capture_controls(&machine).unwrap();
        assert_eq!(original.identity(), changed.identity());
        assert!(!Arc::ptr_eq(
            &original.shared_identity(),
            &changed.shared_identity()
        ));
        machine.profile_missing.pop();
        assert!(Arc::ptr_eq(
            &original.shared_identity(),
            &capture_controls(&machine).unwrap().shared_identity()
        ));
    }

    #[test]
    fn warm_controls_recheck_translation_requester_sp_permissions_and_debug_state() {
        let (mut machine, _) = fixture();
        prepare_artifact(&mut machine, BINDING).unwrap();
        let original = capture_controls(&machine).unwrap();
        for register in [Register::TTBR0_EL1, Register::TCR_EL1, Register::MAIR_EL1] {
            let value = machine.cpu.read(register);
            machine.cpu.registers.set_raw(register, 0, value ^ 0x1000);
            let changed = capture_controls(&machine).unwrap();
            assert_ne!(original.identity(), changed.identity(), "{register:?}");
            machine.cpu.registers.set_raw(register, 0, value);
        }
        let sctlr = machine.cpu.read(Register::SCTLR_EL1);
        machine
            .cpu
            .registers
            .set_raw(Register::SCTLR_EL1, 0, sctlr ^ (1 << 3));
        let changed = capture_controls(&machine).unwrap();
        assert_ne!(original.sp, changed.sp);
        assert_ne!(original.identity(), changed.identity());
        machine.cpu.registers.set_raw(Register::SCTLR_EL1, 0, sctlr);
        machine.cpu.pstate.pan = !machine.cpu.pstate.pan;
        let changed = capture_controls(&machine).unwrap();
        assert_ne!(original.requester, changed.requester);
        assert_ne!(original.identity(), changed.identity());
        machine.cpu.pstate.pan = !machine.cpu.pstate.pan;
        machine
            .cpu
            .registers
            .set_raw(Register::CPACR_EL1, 0, 3 << 20);
        machine
            .cpu
            .registers
            .set_raw(Register::CPTR_EL2, 0, 3 << 20);
        let enabled = capture_controls(&machine).unwrap();
        assert!(enabled.asimd);
        machine.cpu.registers.set_raw(Register::CPTR_EL2, 0, 0);
        let disabled = capture_controls(&machine).unwrap();
        assert!(!disabled.asimd);
        assert_ne!(enabled.identity(), disabled.identity());
        machine.cpu.pstate.ss = true;
        assert!(capture_controls(&machine).is_err());
    }

    #[test]
    fn cached_controls_are_charged_at_exact_budget_and_tightening_or_reset_clears_them() {
        let (mut machine, _) = fixture();
        prepare_artifact(&mut machine, BINDING).unwrap();
        let controls = capture_controls(&machine).unwrap();
        let mut exact = ArtifactCache::default();
        let bytes = controls.retained_bytes() + exact.slot_bytes();
        exact.tighten(bytes);
        exact.remember_controls(&controls);
        assert_eq!(exact.stats().retained_bytes, bytes);
        assert!(exact.controls().is_some());
        assert!(exact.empty_like().controls().is_none());
        let mut denied = ArtifactCache::default();
        denied.tighten(bytes - 1);
        denied.remember_controls(&controls);
        assert!(denied.controls().is_none());
        exact.tighten(0);
        assert_eq!(exact.stats().retained_bytes, 0);
        assert!(exact.controls().is_none());
        exact.remember_controls(&controls);
        assert!(exact.controls().is_none());
        machine.tighten_native_artifact_cache_budget(0).unwrap();
        let uncached = capture_controls(&machine).unwrap();
        assert!(!Arc::ptr_eq(
            &controls.shared_identity(),
            &uncached.shared_identity()
        ));
    }

    #[test]
    fn repeated_preparation_reuses_only_immutable_artifact_and_refetches_changed_source() {
        let (mut machine, ram) = fixture();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        let second = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.source.len(), 8);
        // No frame was cached: each attempt still borrows current CPU state.
        machine.cpu.state.x[0] = 0x1234;
        let third = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(Arc::ptr_eq(&first, &third));
        assert_eq!(machine.cpu.state.x[0], 0x1234);
        unsafe { ram.publish_physical(DATA, &0x91000800u32.to_le_bytes()) }.unwrap();
        let changed = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &changed));
        assert_ne!(first.identity.source_sha256, changed.identity.source_sha256);
        assert_eq!(
            u32::from_le_bytes(changed.source[..4].try_into().unwrap()),
            0x91000800
        );
        let stats = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .native_artifact_stats();
        assert_eq!((stats.compiled, stats.reused, stats.entries), (2, 2, 1));
        assert!(stats.retained_bytes <= ARTIFACT_CACHE_BYTES);
    }

    #[test]
    fn actual_return_shares_immutable_provenance_after_artifact_replacement() {
        let (mut machine, ram) = fixture();
        let bytes = source_window(machine.cpu.pc, &machine.breakpoints, &machine.traces);
        let run = prepare(
            &mut machine.cpu,
            BINDING,
            machine.current,
            &machine.profile,
            &machine.profile_missing,
            &machine.admit_table,
            PreparationBoundary {
                source_bytes: bytes,
                translation_generation: machine.translation_generation,
            },
        )
        .unwrap();
        let identity = Arc::clone(&run.artifact.identity);
        let returned = publication::NativeFrame::execute(run, &mut machine.host);
        let observation = returned.observation.as_ref().unwrap();
        // The unassigned test Host refuses entry, while the real frame path
        // constructs its observation from this exact prepared artifact.
        assert_eq!(observation.status, Err(MemoryStatus::Unsupported));
        assert!(Arc::ptr_eq(&identity, &observation.identity));
        let retained = Arc::clone(&observation.identity);
        drop(returned);
        unsafe { ram.publish_physical(DATA, &0x91000800u32.to_le_bytes()) }.unwrap();
        let changed = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&retained, &changed.identity));
        assert_ne!(retained.source_sha256, changed.identity.source_sha256);
        assert_eq!(retained, identity);
        machine.tighten_native_artifact_cache_budget(0).unwrap();
        assert_eq!(retained, identity);
    }

    #[test]
    fn warm_revalidation_reads_the_entire_maximum_compiler_window() {
        let (mut machine, ram) = fixture();
        let mut words = [0xd503201fu32; stela_compiler::block::MAX_BLOCK_INSTRUCTIONS];
        *words.last_mut().unwrap() = 0x14000000;
        let source: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        unsafe { ram.publish_physical(DATA, &source) }.unwrap();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        assert_eq!(
            first.source.len(),
            super::super::super::MAX_BLOCK_BYTES as usize
        );
        assert!(Arc::ptr_eq(
            &first,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
        let changed_offset = source.len() - 8;
        unsafe { ram.publish_physical(DATA + changed_offset as u64, &0x91000400u32.to_le_bytes()) }
            .unwrap();
        let changed = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &changed));
        assert_ne!(first.identity.source_sha256, changed.identity.source_sha256);
        assert_eq!(
            &changed.source[changed_offset..changed_offset + 4],
            &0x91000400u32.to_le_bytes()
        );
    }

    #[test]
    fn unchanged_source_requires_both_actual_chip_policies_and_withheld_features() {
        let (mut machine, _) = fixture();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        let chip = machine.profile.chip;
        let table = Arc::clone(&machine.admit_table);
        machine.profile.chip = stela_contracts::Chip::AppleM2;
        let profile = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &profile));
        assert_ne!(
            first.key.admission.profile_chip,
            profile.key.admission.profile_chip
        );
        assert_eq!(
            first.identity.controls_sha256,
            profile.identity.controls_sha256
        );
        assert_eq!(first.source, profile.source);
        machine.profile.chip = chip;
        machine.admit_table = Arc::new(
            stela_contracts::Chip::AppleM2
                .admit_table(table.withheld())
                .unwrap(),
        );
        let table_chip = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &table_chip));
        assert_ne!(
            first.key.admission.table_chip,
            table_chip.key.admission.table_chip
        );
        assert_eq!(first.source, table_chip.source);
        let withheld = table.withheld() ^ (1 << stela_contracts::Feature::FEAT_WFxT as u64);
        machine.admit_table = Arc::new(table.chip().admit_table(withheld).unwrap());
        let features = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &features));
        assert_ne!(
            first.key.admission.withheld,
            features.key.admission.withheld
        );
        assert_eq!(first.source, features.source);
        machine.admit_table = table;
        assert!(Arc::ptr_eq(
            &first,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
    }

    #[test]
    fn unchanged_fp_source_cannot_reuse_admission_after_permission_is_revoked() {
        for word in [0x9e670000, 0x9e630100] {
            // FMOV D0,X0; UCVTF D0,X8
            let (mut machine, ram) = fixture();
            machine
                .cpu
                .registers
                .set_raw(Register::CPACR_EL1, 0, 3 << 20);
            machine
                .cpu
                .registers
                .set_raw(Register::CPTR_EL2, 0, 3 << 20);
            let source: Vec<_> = [0x91000400u32, word, 0x14000000]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            unsafe { ram.publish_physical(DATA, &source) }.unwrap();
            let enabled = prepare_artifact(&mut machine, BINDING).unwrap();
            assert!(enabled.key.admission.asimd);
            let expected_bytes = if word == 0x9e630100 { 8 } else { 12 };
            assert_eq!(enabled.source, source[..expected_bytes]);
            assert!(Arc::ptr_eq(
                &enabled,
                &prepare_artifact(&mut machine, BINDING).unwrap()
            ));
            machine.cpu.registers.set_raw(Register::CPTR_EL2, 0, 0);
            let denied = prepare_artifact(&mut machine, BINDING).unwrap();
            assert!(!denied.key.admission.asimd);
            assert!(!Arc::ptr_eq(&enabled, &denied));
            // Current access controls cut the real GPR prefix before FP,
            // even when the exact canonical source was previously admitted.
            assert_eq!(denied.source, source[..4]);
            machine.cpu.pc = PC + 4;
            let state = machine.cpu.state.clone();
            assert_eq!(
                prepare_artifact(&mut machine, BINDING).err(),
                Some(MemoryStatus::Unsupported)
            );
            assert_eq!(machine.cpu.state, state);
        }
    }

    #[test]
    fn changed_later_source_is_readmitted_before_any_cached_decoder_proof_is_reused() {
        let (mut machine, ram) = fixture();
        let source: Vec<_> = [0x91000400u32, 0x91000421, 0x14000000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        unsafe { ram.publish_physical(DATA, &source) }.unwrap();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(Arc::ptr_eq(
            &first,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
        // An unallocated nonzero top-level group is denied by AdmitTable,
        // rather than being mistaken for the existing artifact's admitted word.
        unsafe { ram.publish_physical(DATA + 4, &0x02000000u32.to_le_bytes()) }.unwrap();
        let changed = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &changed));
        assert_eq!(changed.source, source[..4]);
    }
    #[test]
    fn new_host_points_cut_a_warm_artifact_before_the_observed_instruction() {
        for breakpoint in [false, true] {
            let (mut machine, _) = fixture();
            let full = prepare_artifact(&mut machine, BINDING).unwrap();
            assert_eq!(full.source.len(), 8);
            if breakpoint {
                machine.set_breakpoints(&[PC + 4]);
            } else {
                machine.set_traces(&[PC, PC + 1, PC + 4, PC + 8]);
            }
            let prefix = prepare_artifact(&mut machine, BINDING).unwrap();
            assert!(!Arc::ptr_eq(&full, &prefix));
            assert_eq!(prefix.source, full.source[..4]);
            assert_eq!(prefix.source_map.len(), 1);
            assert!(Arc::ptr_eq(
                &prefix,
                &prepare_artifact(&mut machine, BINDING).unwrap()
            ));
            machine.set_breakpoints(&[]);
            machine.set_traces(&[]);
            // Removing a point may retain the shorter, still valid boundary.
            assert!(Arc::ptr_eq(
                &prefix,
                &prepare_artifact(&mut machine, BINDING).unwrap()
            ));
        }
    }
    #[test]
    fn controls_worker_and_guarded_leaf_are_actual_cache_identity() {
        let (mut machine, ram) = fixture();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        let worker = prepare_artifact(
            &mut machine,
            publication::WorkerBinding {
                worker: publication::WorkerId(7),
                ..BINDING
            },
        )
        .unwrap();
        assert!(!Arc::ptr_eq(&first, &worker));
        let sctlr = machine.cpu.read(Register::SCTLR_EL1);
        machine
            .cpu
            .registers
            .set_raw(Register::SCTLR_EL1, 0, sctlr | (1 << 3));
        let controls = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &controls));
        assert_ne!(
            first.identity.controls_sha256,
            controls.identity.controls_sha256
        );
        machine.cpu.registers.set_raw(Register::SCTLR_EL1, 0, sctlr);
        let mut bytes = [0; 8];
        unsafe { ram.read_physical(LEAF, &mut bytes) }.unwrap();
        let descriptor = u64::from_le_bytes(bytes);
        unsafe { ram.publish_physical(LEAF, &(descriptor | (1 << 50)).to_le_bytes()) }.unwrap();
        let guarded = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &guarded));
        assert_eq!(
            first.identity.controls_sha256,
            guarded.identity.controls_sha256
        );
        assert!(guarded.key.guarded);
        // Entry BTI validation is fresh even when a guarded artifact exists.
        machine.cpu.pstate.btype = 1;
        assert!(matches!(
            prepare_artifact(&mut machine, BINDING),
            Err(MemoryStatus::Unsupported)
        ));
    }
    #[test]
    fn cached_code_never_bypasses_current_fetch_translation_or_execute_permission() {
        let (mut machine, ram) = fixture();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        let mut bytes = [0; 8];
        unsafe { ram.read_physical(LEAF, &mut bytes) }.unwrap();
        let descriptor = u64::from_le_bytes(bytes);
        for denied in [0, descriptor | (1 << 53) | (1 << 54)] {
            unsafe { ram.publish_physical(LEAF, &denied.to_le_bytes()) }.unwrap();
            assert!(matches!(
                prepare_artifact(&mut machine, BINDING),
                Err(MemoryStatus::Unsupported)
            ));
        }
        unsafe { ram.publish_physical(LEAF, &descriptor.to_le_bytes()) }.unwrap();
        assert!(Arc::ptr_eq(
            &first,
            &prepare_artifact(&mut machine, BINDING).unwrap()
        ));
    }
    #[test]
    fn retained_capacities_are_bounded_and_owner_budget_can_only_tighten() {
        let (mut machine, _) = fixture();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        let mut cache = ArtifactCache::default();
        for index in 0..4 {
            let mut key = first.key.clone();
            key.pc += index * 4;
            cache.insert(Arc::new(Artifact {
                key, identity: first.identity.clone(),
                code: Arc::new(alloc::vec![0; if index == 3 { ARTIFACT_CACHE_BYTES } else { ARTIFACT_CACHE_BYTES / 2 }]),
                source_map: Vec::new(), source: first.source.clone(),
                requirements: first.requirements, branch_type: first.branch_type,
                #[cfg(feature = "native-profile")]
                profile: first.profile.clone(),
            }));
            assert!(cache.stats().retained_bytes <= ARTIFACT_CACHE_BYTES);
            assert_eq!(cache.stats().entries, 1);
        }
        assert_eq!(cache.stats().compiled, 4);
        machine.tighten_native_artifact_cache_budget(0).unwrap();
        let stats = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .native_artifact_stats();
        assert_eq!((stats.entries, stats.retained_bytes), (0, 0));
        // A later larger request cannot restore a limit already tightened.
        machine
            .tighten_native_artifact_cache_budget(ARTIFACT_CACHE_BYTES)
            .unwrap();
        let uncached = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&first, &uncached));
        assert_eq!(
            machine
                .cpu
                .canonical_memory
                .as_ref()
                .unwrap()
                .artifacts
                .byte_budget,
            0
        );
        let (cpu, profile, missing, _) = super::super::policy::tests::fixture();
        let reset = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .prepare_reset_peer(&cpu, 1, profile.name, &missing)
            .unwrap();
        assert_eq!(
            (
                reset.artifacts.byte_budget,
                reset.artifacts.stats().retained_bytes
            ),
            (0, 0)
        );
    }

    fn branch_artifacts(
        count: usize,
    ) -> (
        Machine<FakeHost, NoDevices>,
        Arc<RegisteredSystemRam>,
        Vec<Arc<Artifact>>,
    ) {
        let (mut machine, ram) = fixture();
        let source: Vec<_> = core::iter::repeat_n(0x14000000u32, count + 1)
            .flat_map(u32::to_le_bytes)
            .collect();
        unsafe { ram.publish_physical(DATA, &source) }.unwrap();
        let artifacts = (0..count)
            .map(|index| {
                machine.cpu.pc = PC + index as u64 * 4;
                prepare_artifact(&mut machine, BINDING).unwrap()
            })
            .collect();
        (machine, ram, artifacts)
    }

    #[test]
    fn validated_hot_source_survives_byte_budget_eviction() {
        for count in [3, 80] {
            let (mut machine, _, artifacts) = branch_artifacts(count);
            let initial = machine
                .cpu
                .canonical_memory
                .as_ref()
                .unwrap()
                .native_artifact_stats();
            machine
                .tighten_native_artifact_cache_budget(initial.retained_bytes)
                .unwrap();
            machine.cpu.pc = PC;
            assert!(Arc::ptr_eq(
                &artifacts[0],
                &prepare_artifact(&mut machine, BINDING).unwrap()
            ));
            let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
            assert!(Arc::ptr_eq(
                cache.recency_order().last().unwrap(),
                &artifacts[0]
            ));
            assert_eq!(cache.stats().retained_bytes, initial.retained_bytes);
            assert_eq!(cache.stats().reused, initial.reused + 1);
            assert_eq!(cache.stats().compiled, initial.compiled);

            machine.cpu.pc = PC + count as u64 * 4;
            let cold = prepare_artifact(&mut machine, BINDING).unwrap();
            let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
            assert_eq!(cache.entries.len(), count);
            assert!(cache.candidate(&artifacts[1].key).is_none());
            let (_, hot) = cache.candidate(&artifacts[0].key).unwrap();
            assert!(Arc::ptr_eq(&hot, &artifacts[0]));
            assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &cold));
            assert!(cache.stats().retained_bytes <= cache.byte_budget);
        }
    }

    #[test]
    fn cache_lookup_and_refused_source_do_not_refresh_recency() {
        let (mut machine, ram, artifacts) = branch_artifacts(3);
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        let initial = cache.stats();
        assert!(cache.candidate(&artifacts[0].key).is_some());
        assert!(Arc::ptr_eq(cache.recency_order()[0], &artifacts[0]));
        machine.cpu.pc = PC;
        let mut descriptor = [0; 8];
        unsafe { ram.read_physical(LEAF, &mut descriptor) }.unwrap();
        unsafe { ram.publish_physical(LEAF, &0u64.to_le_bytes()) }.unwrap();
        assert_eq!(
            prepare_artifact(&mut machine, BINDING).err(),
            Some(MemoryStatus::Unsupported)
        );
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert_eq!(cache.stats(), initial);
        for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
            assert!(Arc::ptr_eq(entry, artifact));
        }
        // The first fetch now succeeds and finds the old key, but exact bytes
        // differ and the newly fetched instruction cannot pass admission.
        unsafe { ram.publish_physical(LEAF, &descriptor) }.unwrap();
        unsafe { ram.publish_physical(DATA, &0x02000000u32.to_le_bytes()) }.unwrap();
        assert_eq!(
            prepare_artifact(&mut machine, BINDING).err(),
            Some(MemoryStatus::Unsupported)
        );
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert_eq!(cache.stats(), initial);
        for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
            assert!(Arc::ptr_eq(entry, artifact));
        }
    }

    #[test]
    fn changed_source_replaces_without_crediting_or_promoting_a_hit() {
        let (mut machine, ram, artifacts) = branch_artifacts(3);
        let initial = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .native_artifact_stats();
        machine.cpu.pc = PC;
        unsafe { ram.publish_physical(DATA, &0x91000400u32.to_le_bytes()) }.unwrap();
        let changed = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&changed, &artifacts[0]));
        assert_eq!(&changed.source[..4], &0x91000400u32.to_le_bytes());
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert_eq!(cache.stats().compiled, initial.compiled + 1);
        assert_eq!(cache.stats().reused, initial.reused);
        assert!(Arc::ptr_eq(cache.recency_order()[0], &artifacts[1]));
        assert!(Arc::ptr_eq(cache.recency_order()[1], &artifacts[2]));
        assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &changed));
    }

    #[test]
    fn changed_admission_key_does_not_refresh_an_older_artifact() {
        let (mut machine, _, artifacts) = branch_artifacts(3);
        let initial = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .native_artifact_stats();
        machine.cpu.pc = PC;
        machine.profile.chip = stela_contracts::Chip::AppleM2;
        let changed = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&changed, &artifacts[0]));
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert_eq!(cache.stats().compiled, initial.compiled + 1);
        assert_eq!(cache.stats().reused, initial.reused);
        for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
            assert!(Arc::ptr_eq(entry, artifact));
        }
        assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &changed));
        // Equal-PC entries retain independent full keys. Revisit both variants
        // and a missing variant after insertion, without refreshing recency.
        let tickets: Vec<_> = cache.entries.iter().map(|entry| entry.recency).collect();
        assert!(Arc::ptr_eq(
            &cache.candidate(&artifacts[0].key).unwrap().1,
            &artifacts[0]
        ));
        assert!(Arc::ptr_eq(
            &cache.candidate(&changed.key).unwrap().1,
            &changed
        ));
        let mut missing = changed.key.clone();
        missing.worker = publication::WorkerId(1);
        assert!(cache.candidate(&missing).is_none());
        assert_eq!(
            cache
                .entries
                .iter()
                .map(|entry| entry.recency)
                .collect::<Vec<_>>(),
            tickets
        );
    }

    #[test]
    fn shortened_observation_window_replaces_without_crediting_a_hit() {
        let (mut machine, _) = fixture();
        let full = prepare_artifact(&mut machine, BINDING).unwrap();
        machine.cpu.pc = PC + 4;
        let following = prepare_artifact(&mut machine, BINDING).unwrap();
        let initial = machine
            .cpu
            .canonical_memory
            .as_ref()
            .unwrap()
            .native_artifact_stats();
        machine.set_breakpoints(&[PC + 4]);
        machine.cpu.pc = PC;
        let prefix = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&prefix, &full));
        assert_eq!(prefix.source, full.source[..4]);
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert_eq!(cache.stats().compiled, initial.compiled + 1);
        assert_eq!(cache.stats().reused, initial.reused);
        assert!(Arc::ptr_eq(cache.recency_order()[0], &following));
        assert!(Arc::ptr_eq(cache.recency_order().last().unwrap(), &prefix));
    }

    fn assert_accounting(cache: &ArtifactCache) {
        let payload: usize = cache
            .entries
            .iter()
            .map(|entry| entry.artifact.retained_bytes())
            .sum();
        assert_eq!(cache.retained_payload, payload);
        assert_eq!(
            cache.stats().retained_bytes,
            payload
                + cache.entries.capacity() * core::mem::size_of::<CacheEntry>()
                + cache.controls_bytes()
        );
        assert!(cache.stats().retained_bytes <= cache.byte_budget);
        assert!(
            cache
                .entries
                .windows(2)
                .all(|pair| pair[0].artifact.key.pc <= pair[1].artifact.key.pc)
        );
    }

    #[test]
    fn indexed_cache_matches_reference_lru_without_moving_hits() {
        let (_, _, artifacts) = branch_artifacts(8);
        let mut cache = ArtifactCache::default();
        let mut reference: Vec<Arc<Artifact>> = Vec::new();
        for step in 0..200 {
            let artifact = &artifacts[(step * 5 + step / 7) % artifacts.len()];
            if let Some((index, candidate)) = cache.candidate(&artifact.key) {
                let positions: Vec<_> = cache
                    .entries
                    .iter()
                    .map(|entry| entry.artifact.key.pc)
                    .collect();
                let bytes = cache.stats().retained_bytes;
                assert!(Arc::ptr_eq(&candidate, artifact));
                cache.reuse(index);
                assert_eq!(
                    cache
                        .entries
                        .iter()
                        .map(|entry| entry.artifact.key.pc)
                        .collect::<Vec<_>>(),
                    positions
                );
                assert_eq!(cache.stats().retained_bytes, bytes);
                reference.retain(|entry| !Arc::ptr_eq(entry, artifact));
            } else {
                cache.insert(Arc::clone(artifact));
            }
            reference.push(Arc::clone(artifact));
            if step % 11 == 10 {
                cache.evict_oldest();
                reference.remove(0);
            }
            assert_eq!(cache.entries.len(), reference.len());
            for (actual, expected) in cache.recency_order().into_iter().zip(&reference) {
                assert!(Arc::ptr_eq(actual, expected));
            }
            assert_accounting(&cache);
        }
    }

    #[test]
    fn recency_wrap_preserves_indices_order_and_eviction_after_counter_saturation() {
        let (_, _, artifacts) = branch_artifacts(4);
        let mut cache = ArtifactCache::default();
        for index in [2, 0, 3, 1] {
            cache.insert(Arc::clone(&artifacts[index]));
        }
        let (index, _) = cache.candidate(&artifacts[0].key).unwrap();
        let bytes = cache.stats().retained_bytes;
        cache.recency_clock = u64::MAX;
        cache.reused = u64::MAX;
        cache.reuse(index);
        assert_eq!(cache.reused, u64::MAX);
        assert_eq!(cache.candidate(&artifacts[0].key).unwrap().0, index);
        assert_eq!(cache.stats().retained_bytes, bytes);
        for (actual, expected) in cache.recency_order().into_iter().zip([2, 3, 1, 0]) {
            assert!(Arc::ptr_eq(actual, &artifacts[expected]));
        }
        cache.evict_oldest();
        assert!(cache.candidate(&artifacts[2].key).is_none());
        assert!(cache.candidate(&artifacts[0].key).is_some());
        assert_accounting(&cache);
    }

    #[test]
    fn more_than_the_old_entry_limit_reuses_real_prepared_artifacts_and_reset_is_empty() {
        let (mut machine, _, artifacts) = branch_artifacts(129);
        let owner = machine.cpu.canonical_memory.as_ref().unwrap();
        assert_eq!(owner.artifacts.entries.len(), artifacts.len());
        assert_accounting(&owner.artifacts);
        let initial = owner.artifacts.stats();
        for (index, artifact) in artifacts.iter().enumerate() {
            machine.cpu.pc = PC + index as u64 * 4;
            assert!(Arc::ptr_eq(
                artifact,
                &prepare_artifact(&mut machine, BINDING).unwrap()
            ));
        }
        let owner = machine.cpu.canonical_memory.as_ref().unwrap();
        assert_eq!(owner.artifacts.stats().compiled, initial.compiled);
        assert_eq!(
            owner.artifacts.stats().reused,
            initial.reused + artifacts.len() as u64
        );
        assert_accounting(&owner.artifacts);
        let (cpu, profile, missing, _) = super::super::policy::tests::fixture();
        let reset = owner
            .prepare_reset_peer(&cpu, 1, profile.name, &missing)
            .unwrap();
        assert!(reset.artifacts.entries.is_empty());
        assert_eq!(reset.artifacts.entries.capacity(), 0);
        assert_eq!(reset.artifacts.byte_budget, owner.artifacts.byte_budget);
        assert!(Arc::ptr_eq(&owner.ram, &reset.ram));
    }

    #[test]
    fn adaptive_growth_uses_spare_bytes_without_evicting_for_speculative_slots() {
        let (machine, _, artifacts) = branch_artifacts(5);
        let controls = capture_controls(&machine).unwrap();
        let mut cache = ArtifactCache::default();
        cache.remember_controls(&controls);
        for artifact in &artifacts[..4] {
            cache.insert(Arc::clone(artifact));
            assert_accounting(&cache);
        }
        let slots = core::mem::size_of::<CacheEntry>();
        assert_eq!(cache.entries.capacity(), 4);
        let budget = cache.retained_payload
            + controls.retained_bytes()
            + artifacts[4].retained_bytes()
            + 5 * slots;
        cache.tighten(budget);
        cache.insert(Arc::clone(&artifacts[4]));
        assert_eq!(cache.entries.capacity(), 5);
        assert_eq!(cache.entries.len(), 5);
        assert_eq!(cache.stats().retained_bytes, budget);
        assert_accounting(&cache);
        for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
            assert!(Arc::ptr_eq(entry, artifact));
        }
    }

    #[test]
    fn high_water_slots_release_for_tiny_artifact_and_zero_budget() {
        let (machine, _, artifacts) = branch_artifacts(129);
        let controls = capture_controls(&machine).unwrap();
        let slots = core::mem::size_of::<CacheEntry>();
        let mut cache = ArtifactCache::default();
        for artifact in &artifacts {
            cache.insert(Arc::clone(artifact));
        }
        assert!(cache.entries.capacity() >= artifacts.len());
        // Source/code capacities can make one artifact larger than the slot
        // allocation for this roster. Derive sufficient metadata pressure from
        // its actual charge rather than assuming a particular compiled size.
        let required = (artifacts[0].retained_bytes() + slots).div_ceil(slots);
        cache
            .reserve_slots(required.max(cache.entries.len()))
            .unwrap();
        assert_accounting(&cache);
        // Retaining only the old slot allocation fits exactly, but leaves no
        // payload room. Insertion must release it and regrow a smaller buffer.
        let high_water = cache.slot_bytes();
        assert!(high_water >= artifacts[0].retained_bytes() + slots);
        cache.tighten(high_water);
        assert!(cache.entries.is_empty());
        assert_eq!(cache.slot_bytes(), high_water);
        cache.insert(Arc::clone(&artifacts[0]));
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.entries.capacity(), 1);
        assert_accounting(&cache);
        let tiny = artifacts[0].retained_bytes() + slots;
        cache.tighten(tiny);
        assert_eq!(cache.stats().retained_bytes, tiny);
        cache.tighten(0);
        cache.remember_controls(&controls);
        cache.insert(Arc::clone(&artifacts[0]));
        assert_eq!(cache.stats().retained_bytes, 0);
        assert_eq!(cache.entries.capacity(), 0);
        assert!(cache.controls.is_none());
        assert_eq!(cache.empty_like().byte_budget, 0);
    }

    #[test]
    fn oversized_slot_buffer_does_not_prevent_retaining_controls_after_eviction() {
        let (machine, _, _) = branch_artifacts(1);
        let controls = capture_controls(&machine).unwrap();
        let mut cache = ArtifactCache::default();
        let slots = controls
            .retained_bytes()
            .div_ceil(core::mem::size_of::<CacheEntry>());
        cache.reserve_slots(slots).unwrap();
        let budget = cache.slot_bytes();
        cache.tighten(budget);
        assert_eq!(cache.slot_bytes(), budget);
        cache.remember_controls(&controls);
        assert!(cache.controls.is_some());
        assert!(cache.entries.is_empty());
        assert_eq!(cache.entries.capacity(), 0);
        assert_eq!(cache.stats().retained_bytes, controls.retained_bytes());
        assert_accounting(&cache);
    }

    #[test]
    fn varied_payload_capacity_replacement_and_controls_changes_charge_actual_storage() {
        let (mut machine, _, artifacts) = branch_artifacts(3);
        let original_controls = capture_controls(&machine).unwrap();
        let mut cache = ArtifactCache::default();
        cache.remember_controls(&original_controls);
        for (index, artifact) in artifacts.iter().enumerate() {
            // Vec::clone may discard spare capacity. Grow beyond the real
            // original charge so replacing this entry cannot require eviction.
            let mut code = artifact.code.as_ref().clone();
            code.reserve_exact(artifact.code.capacity() + (index + 1) * 37 - code.len());
            let mut source = artifact.source.clone();
            source.reserve_exact(artifact.source.capacity() + (index + 1) * 11 - source.len());
            let mut source_map = artifact.source_map.clone();
            source_map
                .reserve_exact(artifact.source_map.capacity() + (index + 1) * 3 - source_map.len());
            #[cfg(feature = "native-profile")]
            let profile = {
                let mut profile = artifact.profile.clone();
                // Metadata is another retained Vec: cloning can shrink its
                // spare capacity, so grow beyond its actual original charge too.
                profile.register_spans.reserve_exact(
                    artifact.profile.register_spans.capacity() + index + 1
                        - profile.register_spans.len(),
                );
                profile
            };
            let enlarged = Arc::new(Artifact {
                key: artifact.key.clone(),
                identity: Arc::clone(&artifact.identity),
                code: Arc::new(code),
                source_map,
                source,
                requirements: artifact.requirements,
                branch_type: artifact.branch_type,
                #[cfg(feature = "native-profile")]
                profile,
            });
            assert!(enlarged.retained_bytes() > artifact.retained_bytes());
            cache.insert(enlarged);
            assert_accounting(&cache);
        }
        let initial_count = cache.entries.len();
        cache.tighten(cache.stats().retained_bytes);
        // Same-key replacement removes the old capacity charge exactly once.
        cache.insert(Arc::clone(&artifacts[1]));
        assert_eq!(cache.entries.len(), initial_count);
        assert!(Arc::ptr_eq(
            cache.recency_order().last().unwrap(),
            &artifacts[1]
        ));
        assert_accounting(&cache);
        cache.tighten(cache.stats().retained_bytes);
        // The retained missing-register slice is charged at host-word
        // alignment. One additional register may fit within its old charge.
        machine.profile_missing.extend([
            Register::TTBR0_EL1,
            Register::TTBR1_EL1,
            Register::TCR_EL1,
            Register::SCTLR_EL1,
        ]);
        let changed = capture_controls(&machine).unwrap();
        assert!(changed.retained_bytes() > original_controls.retained_bytes());
        cache.remember_controls(&changed);
        assert_eq!(cache.entries.len(), initial_count - 1);
        assert_eq!(cache.controls_bytes(), changed.retained_bytes());
        assert_accounting(&cache);
    }

    #[test]
    fn growth_failure_returns_prepared_uncached_code_without_losing_valid_entries() {
        let (mut machine, _, artifacts) = branch_artifacts(4);
        let cache = &mut machine.cpu.canonical_memory.as_mut().unwrap().artifacts;
        assert_eq!(cache.entries.len(), cache.entries.capacity());
        let initial = cache.stats();
        cache.fail_next_growth = true;
        machine.cpu.pc = PC + artifacts.len() as u64 * 4;
        let uncached = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!uncached.code.is_empty());
        assert_eq!(uncached.source, 0x14000000u32.to_le_bytes());
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        assert_eq!(cache.stats().compiled, initial.compiled + 1);
        assert_eq!(cache.stats().retained_bytes, initial.retained_bytes);
        assert_eq!(cache.stats().entries, initial.entries);
        assert!(cache.candidate(&uncached.key).is_none());
        for (entry, artifact) in cache.recency_order().into_iter().zip(&artifacts) {
            assert!(Arc::ptr_eq(entry, artifact));
        }
        assert_accounting(cache);
        let retry = prepare_artifact(&mut machine, BINDING).unwrap();
        assert!(!Arc::ptr_eq(&retry, &uncached));
        assert_accounting(&machine.cpu.canonical_memory.as_ref().unwrap().artifacts);
    }

    #[test]
    fn growth_arithmetic_overflow_declines_without_mutating_retained_cache() {
        let (machine, _, _) = branch_artifacts(3);
        let cache = &machine.cpu.canonical_memory.as_ref().unwrap().artifacts;
        let initial = cache.stats();
        assert_eq!(cache.growth_capacity(usize::MAX), None);
        assert!(!cache.fits(usize::MAX));
        assert_eq!(cache.stats(), initial);
        assert_accounting(cache);
    }

    #[test]
    fn immutable_code_arc_metadata_is_charged_at_the_exact_artifact_budget_boundary() {
        let (mut machine, _) = fixture();
        let artifact = prepare_artifact(&mut machine, BINDING).unwrap();
        let expected = core::mem::size_of::<Artifact>()
            + 2 * core::mem::size_of::<usize>()
            + core::mem::size_of::<Identity>()
            + 2 * core::mem::size_of::<usize>()
            + crate::machine::engine::installed_code::ARC_VEC_METADATA_BYTES
            + artifact.code.capacity()
            + artifact.source.capacity()
            + artifact.source_map.capacity()
                * core::mem::size_of::<(stela_compiler::GuestAddress, usize)>()
            + artifact.key.controls_sha256.len()
            + 2 * core::mem::size_of::<usize>()
            + artifact.identity.source_sha256.capacity()
            + artifact.identity.native_sha256.capacity()
            + artifact.identity.controls_sha256.capacity();
        #[cfg(feature = "native-profile")]
        let expected = expected + artifact.profile.retained_bytes().unwrap();
        assert_eq!(artifact.retained_bytes(), expected);
        let mut denied = ArtifactCache::default();
        let slots = core::mem::size_of::<CacheEntry>();
        denied.tighten(expected + slots - 1);
        denied.insert(Arc::clone(&artifact));
        assert!(denied.entries.is_empty());
        let mut exact = ArtifactCache::default();
        exact.tighten(expected + slots);
        exact.insert(artifact);
        assert_eq!(exact.stats().entries, 1);
        assert_eq!(exact.stats().retained_bytes, expected + slots);
    }
    #[test]
    fn warm_epoch_probe_checks_reached_source_without_compiling_or_changing_identity() {
        let (mut machine, ram, artifacts) = branch_artifacts(3);
        machine.cpu.pc = PC;
        let run = unsafe { machine.shared_native_run(BINDING) }.unwrap();
        let before = run.memory.artifacts.stats();
        let execution = run.memory.memory.execution_session().unwrap();
        *run.pc = PC + 4;
        let (_, candidate) = run.warm_successor(&execution).unwrap().unwrap();
        assert!(Arc::ptr_eq(&candidate, &artifacts[1]));
        assert!(Arc::ptr_eq(&run.artifact, &artifacts[0]));
        // A valid but cold reached target yields; it never compiles on worker.
        *run.pc = PC + 12;
        assert!(matches!(
            run.warm_successor(&execution),
            Ok(Err(NativeEpochEnd::Cold))
        ));
        assert_eq!(run.memory.artifacts.stats(), before);
        // Source bytes can change through the real shared publication owner.
        unsafe { ram.publish_physical(DATA + 4, &0x14000001u32.to_le_bytes()) }.unwrap();
        *run.pc = PC + 4;
        assert!(matches!(
            run.warm_successor(&execution),
            Ok(Err(NativeEpochEnd::Source))
        ));
        assert_eq!(run.memory.artifacts.stats(), before);
        assert!(Arc::ptr_eq(&run.artifact, &artifacts[0]));
        assert_eq!(run.executed_bodies, 0);
    }

    #[test]
    fn warm_epoch_probe_rewalks_permissions_mapping_and_guarded_entry() {
        let (mut machine, ram, _) = branch_artifacts(2);
        machine.cpu.pc = PC;
        let run = unsafe { machine.shared_native_run(BINDING) }.unwrap();
        let execution = run.memory.memory.execution_session().unwrap();
        let mut descriptor = [0; 8];
        unsafe { ram.read_physical(LEAF, &mut descriptor) }.unwrap();
        let descriptor = u64::from_le_bytes(descriptor);
        // Guarded BR target requires a compatible actual landing instruction.
        *run.btype = 3;
        unsafe { ram.publish_physical(LEAF, &(descriptor | (1 << 50)).to_le_bytes()) }.unwrap();
        assert!(matches!(
            run.warm_successor(&execution),
            Ok(Err(NativeEpochEnd::Source))
        ));
        *run.btype = 0;
        // Same virtual PC and old cached bytes cannot confer execute rights.
        unsafe { ram.publish_physical(LEAF, &0u64.to_le_bytes()) }.unwrap();
        assert!(matches!(
            run.warm_successor(&execution),
            Ok(Err(NativeEpochEnd::Source))
        ));
        unsafe { ram.publish_physical(LEAF, &descriptor.to_le_bytes()) }.unwrap();
        assert!(matches!(run.warm_successor(&execution), Ok(Ok(_))));
    }
}
