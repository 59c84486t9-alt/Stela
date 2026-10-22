//! An actual borrowed architectural frame; no Cpu or Host crosses a core.
use super::super::{NativeExit, publication};
use super::*;
use crate::{execution::context::ContextLoan, platform::cpu::system::NativeSystemTarget};
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
struct Artifact {
    identity: Identity,
    code: Vec<u8>,
    source_map: Vec<(stela_compiler::GuestAddress, usize)>,
    source: Vec<u8>,
    requirements: MemoryRequirements,
}

/// Created only from Machine's actual mutable frame and effective controls.
/// Native code, context and memory services are installed/borrowed on its fixed
/// owner's Host. The original CPU borrow survives the actual returned payload.
pub struct NativeRun<'a> {
    pub(super) memory: &'a mut SharedMemory,
    state: &'a mut GuestState,
    pc: &'a mut u64,
    retired: &'a mut u64,
    worker: publication::WorkerId,
    artifact: Artifact,
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

/// Non-Clone authority obtained only by consuming a real recovered settlement.
/// Public request diagnostics cannot construct or replace this owner.
#[derive(Debug)]
pub(in crate::machine::engine) struct RecoveredRead {
    source: Settlement,
}
impl Settlement {
    pub(super) fn into_read(self) -> RecoveredRead {
        RecoveredRead { source: self }
    }
}
impl RecoveredRead {
    pub(in crate::machine::engine) fn source(&self) -> (publication::WorkerBinding, u64, u64, u64) {
        (
            self.source.binding,
            self.source.generation,
            self.source.pc,
            self.source.retired,
        )
    }
    pub(in crate::machine::engine) fn machine_matches(&self, identity: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.source.machine, identity)
    }
    pub(in crate::machine::engine) fn controls(&self) -> Option<&str> {
        self.source.controls_sha256.as_deref()
    }
    pub(in crate::machine::engine) fn access(
        &self,
    ) -> Option<(u32, crate::memory::domain::DataRequest, u64, u64, usize)> {
        let fault = self.source.memory_fault?;
        let policy::Failure::DeviceRead {
            request,
            address,
            physical,
            bytes,
        } = self.source.source_failure?
        else {
            return None;
        };
        if self.source.status.is_err()
            || fault.status != MemoryStatus::Unsupported
            || fault.completed_bytes != 0
            || fault.pc != self.source.pc
            || fault.address != address
            || fault.access == FaultAccess::Write
            || request.operation != crate::memory::domain::DataOperation::Ordinary
            || request.flags & stela_compiler::context::memory::flags::WRITE != 0
            || request.pc != Some(self.source.pc)
            || request.address != address
        {
            return None;
        }
        Some((self.source.fault_word?, request, address, physical, bytes))
    }
}
impl publication::sealed::NativeFrame for NativeRun<'_> {}
impl<'a> publication::NativeFrame for NativeRun<'a> {
    type Returned = ReturnedRun<'a>;
    fn execute(mut self, host: &mut dyn Host) -> Self::Returned {
        let mut observation = Observation {
            identity: self.artifact.identity.clone(),
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
                NativeExit::Fault(_) => {
                    // A checked body never dereferences a guest VA directly.
                    // A host fault is retained intact and terminal; it is not
                    // invented into an ARM data abort or a completed source op.
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
    let controls = Controls::capture(cpu, cpu_profile.name, missing)?;
    let pc = cpu.pc;
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
    if !pc.is_multiple_of(4) {
        return Err(MemoryStatus::Alignment);
    }
    let mut input = alloc::vec![0; super::super::window(pc)];
    // Instruction walks use the same source controls, canonical descriptor
    // owner and original physical bytes. No direct identity-frame shortcut.
    memory.fetch(&controls, pc, &mut input)?;
    let profile = stela_compiler::block::BlockProfile::SystemModeSharedV1(controls.sp);
    let target = memory.ram.target();
    let plan = stela_compiler::block::CompilationPlan::new(
        &input,
        stela_compiler::GuestAddress(pc),
        profile,
        target,
    )
    .map_err(|_| MemoryStatus::Unsupported)?;
    let bytes = plan.source_bytes();
    input.truncate(bytes);
    for word in input.as_chunks::<4>().0 {
        let word = u32::from_le_bytes(*word);
        // BR/BLR need source guarded-page BTypeNext settlement. They stay
        // explicit boundaries until the complete branch-control owner joins.
        const REGISTER_BRANCH: u32 = 0xffff_fc1f;
        const BR: u32 = 0xd61f_0000;
        const BLR: u32 = 0xd63f_0000;
        if admit.admit(word) != word
            || matches!(word & REGISTER_BRANCH, BR | BLR)
            || super::super::is_floating_point(word)
            || !cpu_profile.chip.checks(word).is_empty()
        {
            return Err(MemoryStatus::Unsupported);
        }
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
        controls_sha256: controls.identity(),
        compiler_source_sha256: stela_compiler::SOURCE_SHA256,
        abi: profile.abi(),
        target,
        requirements,
    };
    memory.memory.policy_mut().controls = controls;
    memory.memory.policy_mut().failure = None;
    Ok(NativeRun {
        memory,
        state,
        pc: frame_pc,
        retired,
        worker: binding.worker,
        artifact: Artifact {
            identity,
            code: compiled.native.x86_64_code,
            source_map: compiled.native.source_map,
            source: input,
            requirements,
        },
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
        let services: Vec<_> = self
            .peers
            .iter()
            .enumerate()
            .map(|(pe, peer)| {
                let cpu = match peer {
                    super::super::processors::Peer::Running if pe == self.current => &self.cpu,
                    super::super::processors::Peer::Parked(parked)
                        if runnable_only || parked.native_ready() =>
                    {
                        parked.cpu()
                    }
                    _ => return Err(MemoryStatus::Unsupported),
                };
                let memory = cpu
                    .canonical_memory
                    .as_ref()
                    .ok_or(MemoryStatus::Unsupported)?;
                if memory.pe != pe || !Arc::ptr_eq(&memory.machine, &self.native_memory_identity) {
                    return Err(MemoryStatus::Unsupported);
                }
                Ok(memory)
            })
            .collect::<Result<_, _>>()?;
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
                    Some(policy::Failure::DeviceRead { .. })
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
mod read_continuation_tests {
    use super::super::host::tests::{Local, OneWorker};
    use super::*;
    use crate::machine::{DeviceError, Lines, Stop, exception::Pstate};
    use crate::memory::domain::{DataOperation, DataRequest};
    use stela_compiler::context::memory::FaultAccess;
    const PC: u64 = 0x14000;
    const DEVICE: u64 = 0x90000;
    const LDR: u32 = 0xf9400020; // LDR X0,[X1]
    const LDP_POST: u32 = 0xa8c10440; // LDP X0,X1,[X2],#16
    struct Device {
        reads: usize,
        fail: bool,
        shape: Option<super::super::super::DeviceReadShape>,
    }
    impl Devices for Device {
        fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
            panic!("raw/replayed read")
        }
        fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
            Err(DeviceError::NoDevice)
        }
        fn lines(&mut self, _: usize, _: u64) -> Lines {
            Lines::default()
        }
        fn read_canonical(
            &mut self,
            _: usize,
            physical: u64,
            bytes: u8,
            _: u64,
            memory: &mut dyn super::super::super::CanonicalDeviceMemory,
        ) -> Result<super::super::super::ConsumedScalar, DeviceError> {
            assert_eq!(physical, DEVICE);
            assert!(matches!(bytes, 1 | 2 | 4 | 8));
            memory.fence_cpu_memory();
            memory.memory().validate_current().unwrap();
            self.reads += 1;
            self.shape = Some(super::super::super::DeviceReadShape::Scalar { bytes });
            Ok(super::super::super::ConsumedScalar {
                value: 0x8877665544332211,
                settlement: self.settlement(),
            })
        }
        fn read_pair_canonical(
            &mut self,
            _: usize,
            physical: u64,
            bytes: u8,
            _: u64,
            memory: &mut dyn super::super::super::CanonicalDeviceMemory,
        ) -> Result<super::super::super::ConsumedPair, DeviceError> {
            assert_eq!(physical, DEVICE);
            assert!(matches!(bytes, 1 | 2 | 4 | 8));
            memory.fence_cpu_memory();
            memory.memory().validate_current().unwrap();
            self.reads += 1;
            self.shape = Some(super::super::super::DeviceReadShape::Pair { bytes });
            Ok(super::super::super::ConsumedPair {
                values: [0x8877665544332211, 0xffeeddccbbaa0099],
                settlement: self.settlement(),
            })
        }
    }
    impl Device {
        fn settlement(&self) -> Result<(), DeviceError> {
            if self.fail {
                Err(DeviceError::TransferRefused(
                    "model post-consume failure".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
    type TestMachine = Machine<ServiceHost<Local, OneWorker>, Device>;
    /// Protocol model only: the real publication loan is actually returned
    /// after CPL0 refusal on this hosted runner. Its failure diagnostics are
    /// replaced ONLY here to drive continuation adversaries. No native memory
    /// callback/CPL0 execution is claimed by these tests.
    fn pending(word: u32, fail: bool) -> (TestMachine, Arc<RegisteredSystemRam>) {
        pending_at(word, fail, DEVICE)
    }
    fn pending_at(word: u32, fail: bool, base: u64) -> (TestMachine, Arc<RegisteredSystemRam>) {
        let (mut cpu, profile, missing, ram) = super::super::policy::tests::fixture();
        cpu.pstate = Pstate::reset(2);
        cpu.registers
            .set_raw(crate::machine::system::Register::SCTLR_EL2, 0, 0);
        cpu.pc = PC;
        cpu.state.x[1] = base;
        cpu.state.x[2] = base;
        let mut source = word.to_le_bytes().to_vec();
        source.extend_from_slice(&0x14000000u32.to_le_bytes());
        unsafe { ram.publish_physical(PC, &source) }.unwrap();
        let native_host = ServiceHost::new(Local, OneWorker(None), Arc::clone(&ram));
        let mut machine = Machine::new(
            cpu,
            native_host,
            Device {
                reads: 0,
                fail,
                shape: None,
            },
            profile,
            ram.target(),
        );
        machine.profile_missing = missing;
        machine
            .install_shared_memory_for_active_processors(
                Arc::clone(&ram),
                &crate::system::events::EventDomain::new(),
            )
            .unwrap();
        let binding = publication::WorkerBinding {
            pe: 0,
            worker: publication::WorkerId(17),
        };
        let owners = machine.bind_active_native_workers(&[binding]).unwrap();
        machine.initialize_native_transport(owners);
        let cohort = machine.native_cohort(&[binding], true).unwrap();
        let controls = cohort.frames[0].identity().controls_sha256.clone();
        let mut reports =
            cohort
                .host
                .transport
                .execute(&mut cohort.host.local, cohort.inventory, cohort.frames);
        let mut settlement = reports.pop().unwrap().settlement.take().unwrap();
        assert!(settlement.status.is_err()); // actual CPL0 refusal, never a success substitute
        let instruction = stela_compiler::Lifter::lift(
            &stela_compiler::aarch64::Decoder,
            stela_compiler::GuestAddress(PC),
            word,
        )
        .unwrap();
        let (pair, bytes) = match instruction.operation {
            stela_compiler::aarch64::Operation::MemoryPair { bytes, .. } => {
                (true, usize::from(bytes) * 2)
            }
            _ => (
                false,
                usize::from(
                    stela_compiler::block::el1_platform::ScalarLoad::from_instruction(&instruction)
                        .unwrap()
                        .bytes(),
                ),
            ),
        };
        let request = DataRequest {
            address: DEVICE,
            bytes,
            flags: if pair {
                stela_compiler::context::memory::flags::PAIR
            } else {
                0
            },
            pc: Some(PC),
            operation: DataOperation::Ordinary,
        };
        settlement.status = Ok(());
        settlement.fault_word = Some(word);
        settlement.controls_sha256 = Some(controls);
        settlement.memory_fault = Some(crate::memory::domain::MemoryFault {
            status: MemoryStatus::Unsupported,
            address: DEVICE,
            pc: PC,
            completed_bytes: 0,
            access: FaultAccess::Read,
        });
        settlement.source_failure = Some(policy::Failure::DeviceRead {
            request,
            address: DEVICE,
            physical: DEVICE,
            bytes,
        });
        let held = machine.hold_native_services().unwrap();
        assert!(matches!(
            machine.queue_device_read(settlement.into_read(), held),
            Stop::DeviceRead(_)
        ));
        (machine, ram)
    }
    #[test]
    fn scalar_and_pair_retire_once_and_preserve_consumed_data_on_settlement_failure() {
        for word in [LDR, LDP_POST] {
            for fail in [false, true] {
                let (mut machine, ram) = pending(word, fail);
                let before = machine.cpu.state.clone();
                let retired = machine.cpu.retired;
                let result = unsafe { machine.complete_device_read() };
                assert_eq!(result.is_err(), fail);
                assert_eq!(machine.devices.reads, 1);
                assert_eq!(machine.cpu.pc, PC + 4);
                assert_eq!(machine.cpu.retired, retired + 1);
                let mut expected = before;
                expected.x[0] = 0x8877665544332211;
                if word == LDP_POST {
                    expected.x[1] = 0xffeeddccbbaa0099;
                    expected.x[2] = DEVICE + 16;
                }
                assert_eq!(machine.cpu.state, expected);
                assert!(unsafe { machine.complete_device_read() }.is_err());
                assert_eq!(machine.devices.reads, 1);
                assert!(matches!(machine.run(1), Stop::Unsupported(_)));
                assert_eq!(ram.check_physical(PC, 4).is_err(), fail);
            }
        }
    }
    #[test]
    fn original_scalar_pair_address_and_sign_modes_retain_full_state_and_exact_writeback() {
        // Unchanged source encodings through the shared decoder; closed model
        // only. The QEMU cold fixture separately executes the real pair path.
        for (word, base, first, second, writeback) in [
            (
                0xf8408420,
                DEVICE,
                0x8877665544332211,
                None,
                Some((1, DEVICE + 8)),
            ), // LDR X0,[X1],#8
            (0xb89fcc20, DEVICE + 4, 0x44332211, None, Some((1, DEVICE))), // LDRSW X0,[X1,#-4]!
            (
                0x29ff0440,
                DEVICE + 8,
                0x44332211,
                Some(0xbbaa0099),
                Some((2, DEVICE)),
            ), // LDP W0,W1,[X2,#-8]!
            (
                0x68c10440,
                DEVICE,
                0x44332211,
                Some(0xffffffffbbaa0099),
                Some((2, DEVICE + 8)),
            ), // LDPSW X0,X1,[X2],#8
            (0xf8636820, DEVICE, 0x8877665544332211, None, None),          // LDR X0,[X1,X3]
            (0x583e0000, DEVICE, 0x8877665544332211, None, None),          // LDR X0,literal(Device)
        ] {
            let (mut machine, _) = pending_at(word, false, base);
            let mut expected = machine.cpu.state.clone();
            expected.x[0] = first;
            if let Some(value) = second {
                expected.x[1] = value;
            }
            if let Some((register, value)) = writeback {
                expected.x[register] = value;
            }
            unsafe { machine.complete_device_read() }.unwrap();
            assert_eq!(machine.cpu.state, expected, "word={word:#x}");
            assert_eq!(machine.cpu.pc, PC + 4);
            assert_eq!(machine.cpu.retired, 1);
            assert_eq!(machine.devices.reads, 1);
        }
    }
    #[test]
    fn changed_actual_frame_controls_or_source_refuses_before_device_consumption() {
        for tamper in 0..5 {
            let (mut machine, ram) = pending(LDR, false);
            match tamper {
                0 => machine.cpu.state.x[3] ^= 1,
                1 => machine.cpu.pc += 4,
                2 => machine.cpu.pstate.daif ^= 1,
                3 => {
                    machine
                        .cpu
                        .registers
                        .set_raw(crate::machine::system::Register::SCTLR_EL2, 0, 1)
                }
                _ => {
                    unsafe { ram.publish_physical(PC, &0xd503201fu32.to_le_bytes()) }.unwrap();
                }
            }
            let before = (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.retired,
            );
            assert!(unsafe { machine.complete_device_read() }.is_err());
            assert_eq!(machine.devices.reads, 0);
            assert_eq!(
                (
                    machine.cpu.state.clone(),
                    machine.cpu.pc,
                    machine.cpu.retired
                ),
                before
            );
            assert!(unsafe { machine.native_round() }.is_err());
            assert_eq!(machine.devices.reads, 0);
        }
    }
}
