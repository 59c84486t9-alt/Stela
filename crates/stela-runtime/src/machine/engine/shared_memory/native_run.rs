//! An actual borrowed architectural frame; no Cpu or Host crosses a core.
mod access;
pub(super) mod source;
use super::super::{NativeExit, publication};
use super::*;
use crate::{execution::context::ContextLoan, platform::cpu::system::NativeSystemTarget};
pub(in crate::machine::engine) use access::{
    RecoveredAccess, RecoveredDeviceAccess, RecoveredRead, RecoveredWrite,
};
use alloc::boxed::Box;
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
    pub abi: &'static str,
    pub target: stela_compiler::TargetCpu,
    pub requirements: MemoryRequirements,
}
const ARTIFACT_CACHE_ENTRIES: usize = 64;
/// Per-PE compiler-artifact resource policy, independent of guest/application.
/// No persistent cache or installed Host arena is charged to this separate
/// in-memory artifact budget. Every actual PE has its own independent bound.
const ARTIFACT_CACHE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactCacheStats {
    pub compiled: u64,
    pub reused: u64,
    /// Retained Rust allocation capacities and metadata; allocator headers are
    /// outside this accounting, with at most 64 bounded allocation groups.
    pub retained_bytes: usize,
    pub entries: usize,
}

/// Source-independent identity, captured anew while the actual PE is owned.
/// The cache itself lives in exactly that PE's canonical-memory owner.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactKey {
    pe: usize,
    pc: u64,
    worker: publication::WorkerId,
    profile: &'static str,
    controls_sha256: alloc::string::String,
    compiler_source_sha256: &'static str,
    abi: &'static str,
    target: stela_compiler::TargetCpu,
    guarded: bool,
}
pub(super) struct ArtifactCache {
    entries: Vec<Arc<Artifact>>,
    retained_payload: usize,
    compiled: u64,
    reused: u64,
    byte_budget: usize,
}
impl Default for ArtifactCache {
    fn default() -> Self {
        Self {
            entries: Vec::with_capacity(ARTIFACT_CACHE_ENTRIES),
            retained_payload: 0,
            compiled: 0,
            reused: 0,
            byte_budget: ARTIFACT_CACHE_BYTES,
        }
    }
}
impl ArtifactCache {
    fn candidate(&self, key: &ArtifactKey) -> Option<Arc<Artifact>> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.key == *key)
            .map(Arc::clone)
    }
    pub(super) fn stats(&self) -> ArtifactCacheStats {
        ArtifactCacheStats {
            compiled: self.compiled,
            reused: self.reused,
            retained_bytes: self.retained_payload + self.slot_bytes(),
            entries: self.entries.len(),
        }
    }
    fn slot_bytes(&self) -> usize {
        self.entries.capacity() * core::mem::size_of::<Arc<Artifact>>()
    }
    pub(super) fn tighten(&mut self, bytes: usize) {
        self.byte_budget = self.byte_budget.min(bytes);
        while !self.entries.is_empty() && self.stats().retained_bytes > self.byte_budget {
            self.remove(0);
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
        self.retained_payload -= self.entries.remove(index).retained_bytes();
    }
    fn insert(&mut self, artifact: Arc<Artifact>) {
        self.compiled = self.compiled.saturating_add(1);
        let bytes = artifact.retained_bytes();
        if self.entries.capacity() == 0 {
            let slots = ARTIFACT_CACHE_ENTRIES * core::mem::size_of::<Arc<Artifact>>();
            if bytes > self.byte_budget.saturating_sub(slots) || slots > self.byte_budget {
                return;
            }
            self.entries.reserve_exact(ARTIFACT_CACHE_ENTRIES);
        }
        if bytes > self.byte_budget.saturating_sub(self.slot_bytes()) {
            return; // Valid one-shot compilation, without retaining oversize code.
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.key == artifact.key)
        {
            self.remove(index);
        }
        while self.entries.len() >= ARTIFACT_CACHE_ENTRIES
            || self.retained_payload + self.slot_bytes() + bytes > self.byte_budget
        {
            self.remove(0);
        }
        self.retained_payload += bytes;
        self.entries.push(artifact);
    }
}

struct Artifact {
    key: ArtifactKey,
    identity: Identity,
    code: Vec<u8>,
    source_map: Vec<(stela_compiler::GuestAddress, usize)>,
    source: Vec<u8>,
    requirements: MemoryRequirements,
    branch_type: u8,
}

impl Artifact {
    fn retained_bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + 2 * core::mem::size_of::<usize>()
            + self.code.capacity()
            + self.source.capacity()
            + self.source_map.capacity()
                * core::mem::size_of::<(stela_compiler::GuestAddress, usize)>()
            + self.key.controls_sha256.capacity()
            + self.identity.source_sha256.capacity()
            + self.identity.native_sha256.capacity()
            + self.identity.controls_sha256.capacity()
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
    pub identity: Identity,
    pub artifact_cache: ArtifactCacheStats,
    pub native: Option<NativeExit>,
    pub memory_fault: Option<crate::memory::domain::MemoryFault>,
    pub source_failure: Option<policy::Failure>,
    pub status: Result<(), MemoryStatus>,
    pub settled_pc: u64,
    pub retired: u64,
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
            identity: self.artifact.identity.clone(),
            artifact_cache: self.memory.artifacts.stats(),
            native: None,
            memory_fault: None,
            source_failure: None,
            status: Err(MemoryStatus::Unsupported),
            settled_pc: *self.pc,
            retired: 0,
            physical_processor: None,
            settlement: None,
        };
        observation.status = self.enter(host, &mut observation);
        observation.source_failure = self.memory.memory.policy_mut().failure;
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
        let authority = NativeSystemTarget::capture().map_err(|_| MemoryStatus::Unsupported)?;
        observation.physical_processor = Some(authority.physical_processor());
        if !authority.target().supports(self.artifact.identity.target) {
            return Err(MemoryStatus::Unsupported);
        }
        // A service/publication loan outlives both callback finalization and PC
        // settlement. This Host borrow pins the installed arena throughout them.
        let _publication = self.memory.memory.execution_loan()?;
        let code = match host.install(&self.artifact.code) {
            Ok(code) => code,
            Err(crate::machine::InstallError::Full) => {
                // This fixed owner has returned/recovered its preceding frame;
                // no installed pointer escapes a NativeRun. The shared lane
                // never falls back to legacy cached block addresses.
                host.discard_code();
                host.install(&self.artifact.code)
                    .map_err(|_| MemoryStatus::Unsupported)?
            }
        };
        let entry = self
            .memory
            .memory
            .prepare_native_system(self.artifact.requirements, &authority)?;
        let mut context = ExecutionContext::default();
        let mut raw = None;
        let mut malformed = false;
        // SAFETY: the source-bound artifact, exact real frame, effective policy,
        // canonical RAM, current physical target and local installed arena all
        // stay exclusively borrowed through native return, fault and settlement.
        let entered = unsafe {
            entry.with_checked_view(|view| {
                let mut context_loan = ContextLoan::memory(&mut context, view);
                let result = host.execute_context(code, self.state, context_loan.context());
                observation.native = result;
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
        // This happens while the actual owner-local Host/code arena, RAM and
        // current target proof are still borrowed, before Release publication.
        Ok(())
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
    /// Direct SystemModeV1 data writers remain excluded, including between calls.
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
        prepare(
            &mut self.cpu,
            binding,
            self.current,
            &self.profile,
            &self.profile_missing,
            &self.admit_table,
        )
    }
}

fn prepare<'a>(
    cpu: &'a mut crate::machine::Cpu,
    binding: publication::WorkerBinding,
    pe: usize,
    cpu_profile: &crate::machine::CpuProfile,
    missing: &[crate::machine::system::Register],
    admit: &crate::machine::chip::AdmitTable,
) -> Result<NativeRun<'a>, MemoryStatus> {
    if binding.pe != pe || cpu.monitor.is_some() {
        return Err(MemoryStatus::Unsupported);
    }
    if !cpu.pc.is_multiple_of(4) {
        return Err(MemoryStatus::Alignment);
    }
    let controls = Controls::capture(cpu, cpu_profile.name, missing)?;
    let pc = cpu.pc;
    let memory = cpu
        .canonical_memory
        .as_ref()
        .ok_or(MemoryStatus::Unsupported)?;
    let (first, guarded) =
        source::instruction(memory, &controls, pc).map_err(|failure| match failure {
            source::FetchFailure::Fault(_) => MemoryStatus::Unsupported,
            source::FetchFailure::Refused(status) => status,
        })?;
    if cpu.pstate.btype != 0
        && guarded
        && !source::target_accepts(first, cpu.pstate.btype, cpu.regime_sctlr(), cpu.pstate.el)
    {
        return Err(MemoryStatus::Unsupported);
    }
    let asimd = controls.asimd;
    let btype = &mut cpu.pstate.btype;
    let state = &mut cpu.state;
    let retired = &mut cpu.retired;
    let frame_pc = &mut cpu.pc;
    let memory = cpu
        .canonical_memory
        .as_mut()
        .ok_or(MemoryStatus::Unsupported)?;
    if memory.pe != pe {
        return Err(MemoryStatus::Unsupported);
    }
    let profile = stela_compiler::block::BlockProfile::SystemModeSharedV1(controls.sp);
    let target = memory.ram.target();
    let key = ArtifactKey {
        pe,
        pc,
        worker: binding.worker,
        profile: cpu_profile.name,
        controls_sha256: controls.identity(),
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
                    crate::machine::chip::Check::Fp | crate::machine::chip::Check::FpAdvSimd
                )
            })
    };
    let artifact = if let Some(artifact) = memory.artifacts.candidate(&key) {
        // A hit is merely immutable compilation reuse. Rewalk executable source
        // and read actual canonical bytes for its exact retained prefix every
        // time. A shorter compiled prefix remains a valid scheduling boundary;
        // words after it cannot grant or revoke its instruction effects.
        let bytes = artifact.source.len();
        if bytes == 0 || !bytes.is_multiple_of(4) || bytes > super::super::window(pc) {
            return Err(MemoryStatus::Domain);
        }
        let mut input = alloc::vec![0; bytes];
        memory.fetch(&controls, pc, &mut input)?;
        (input == artifact.source
            && input
                .as_chunks::<4>()
                .0
                .iter()
                .all(|raw| admitted(u32::from_le_bytes(*raw))))
        .then_some(artifact)
    } else {
        None
    };
    let artifact = match artifact {
        Some(artifact) => {
            memory.artifacts.reused = memory.artifacts.reused.saturating_add(1);
            artifact
        }
        None => {
            let mut input = alloc::vec![0; super::super::window(pc)];
            // Instruction walks use the same source controls, canonical descriptor
            // owner and original physical bytes. No direct identity-frame shortcut.
            memory.fetch(&controls, pc, &mut input)?;
            // A denied later access check must not erase an already reached GPR
            // prefix. End before it; the held scheduler checks that exact next word.
            if let Some(boundary) = input
                .as_chunks::<4>()
                .0
                .iter()
                .position(|raw| !admitted(u32::from_le_bytes(*raw)))
            {
                if boundary == 0 {
                    return Err(MemoryStatus::Unsupported);
                }
                input.truncate(boundary * 4);
            }
            let plan = stela_compiler::block::CompilationPlan::new(
                &input,
                stela_compiler::GuestAddress(pc),
                profile,
                target,
            )
            .map_err(|_| MemoryStatus::Unsupported)?;
            let bytes = plan.source_bytes();
            input.truncate(bytes);
            if !input
                .as_chunks::<4>()
                .0
                .iter()
                .all(|raw| admitted(u32::from_le_bytes(*raw)))
            {
                return Err(MemoryStatus::Unsupported);
            }
            let requirements = plan
                .memory_requirements()
                .ok_or(MemoryStatus::Unsupported)?;
            let compiled = plan.compile().map_err(|_| MemoryStatus::Unsupported)?;
            if !compiled.fault_recovery.is_empty() {
                return Err(MemoryStatus::Unsupported);
            }
            let identity = Identity {
                pe,
                pc,
                source_sha256: crate::sha256(&input),
                native_sha256: crate::sha256(&compiled.native.x86_64_code),
                controls_sha256: key.controls_sha256.clone(),
                compiler_source_sha256: stela_compiler::SOURCE_SHA256,
                abi: profile.abi(),
                target,
                requirements,
            };
            let artifact = Arc::new(Artifact {
                key,
                identity,
                code: compiled.native.x86_64_code,
                source_map: compiled.native.source_map,
                branch_type: source::branch_type(
                    u32::from_le_bytes(input.last_chunk().copied().ok_or(MemoryStatus::Domain)?),
                    guarded,
                ),
                source: input,
                requirements,
            });
            memory.artifacts.insert(Arc::clone(&artifact));
            artifact
        }
    };
    memory.memory.policy_mut().controls = controls;
    memory.memory.policy_mut().failure = None;
    Ok(NativeRun {
        memory,
        state,
        pc: frame_pc,
        retired,
        btype,
        worker: binding.worker,
        artifact,
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
    }

    pub(super) fn native_cohort<'a>(
        &'a mut self,
        bindings: &[publication::WorkerBinding],
        runnable_only: bool,
    ) -> Result<Cohort<'a, H>, MemoryStatus> {
        if bindings.len() != self.peers.len() || (!runnable_only && self.waiting.is_some()) {
            return Err(MemoryStatus::Unsupported);
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
                _ => return Err(MemoryStatus::Unsupported),
            };
            let memory = cpu
                .canonical_memory
                .as_ref()
                .ok_or(MemoryStatus::Unsupported)?;
            if memory.pe != pe || !Arc::ptr_eq(&memory.machine, &self.native_memory_identity) {
                return Err(MemoryStatus::Unsupported);
            }
            services.push(memory);
        }
        let first = services.first().ok_or(MemoryStatus::Unsupported)?;
        if services.iter().any(|candidate| {
            !Arc::ptr_eq(&candidate.ram, &first.ram) || !candidate.event.same_domain(&first.event)
        }) {
            return Err(MemoryStatus::Unsupported);
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
                _ => return Err(MemoryStatus::Unsupported),
            };
            frames.push(prepare(
                cpu,
                binding,
                pe,
                &self.profile,
                &self.profile_missing,
                &self.admit_table,
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
        let run = prepare(
            &mut machine.cpu,
            binding,
            machine.current,
            &machine.profile,
            &machine.profile_missing,
            &machine.admit_table,
        )?;
        Ok(Arc::clone(&run.artifact))
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
                code: alloc::vec![0; if index == 3 { ARTIFACT_CACHE_BYTES } else { ARTIFACT_CACHE_BYTES / 2 }],
                source_map: Vec::new(), source: first.source.clone(),
                requirements: first.requirements, branch_type: first.branch_type,
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

    #[test]
    fn immutable_cache_is_bounded_and_reset_memory_starts_empty() {
        let (mut machine, _) = fixture();
        let first = prepare_artifact(&mut machine, BINDING).unwrap();
        let mut cache = ArtifactCache::default();
        for index in 0..=ARTIFACT_CACHE_ENTRIES {
            let mut key = first.key.clone();
            key.pc += index as u64 * 4;
            cache.insert(Arc::new(Artifact {
                key,
                identity: first.identity.clone(),
                code: Vec::new(),
                source_map: Vec::new(),
                source: first.source.clone(),
                requirements: first.requirements,
                branch_type: first.branch_type,
            }));
        }
        assert_eq!(cache.entries.len(), ARTIFACT_CACHE_ENTRIES);
        assert!(cache.candidate(&first.key).is_none());
        let (cpu, profile, missing, _) = super::super::policy::tests::fixture();
        let owner = machine.cpu.canonical_memory.as_ref().unwrap();
        let reset = owner
            .prepare_reset_peer(&cpu, 1, profile.name, &missing)
            .unwrap();
        assert!(reset.artifacts.entries.is_empty());
        assert_eq!(owner.artifacts.entries.len(), 1);
        assert!(Arc::ptr_eq(&owner.ram, &reset.ram));
    }
}
