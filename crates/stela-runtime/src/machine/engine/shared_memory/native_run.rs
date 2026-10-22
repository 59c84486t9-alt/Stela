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
            });
            observation = Some(observed);
            Ok(())
        })
        .map_err(Box::new)?;
    Ok(observation.expect("successful recovery consumed actual returned payload"))
}
