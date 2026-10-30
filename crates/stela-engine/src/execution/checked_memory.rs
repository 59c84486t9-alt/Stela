//! Immutable checked GPR blocks with a private native mapping per worker.
//!
//! This is a bounded execution boundary, not a native machine SMP
//! scheduler. Every memory access uses the shared memory service;
//! direct-RAM blocks and caller-supplied native artifacts are excluded.

use super::{context::ContextLoan, floating_environment::HostFloatingEnvironment, platform};
use crate::Result;
use crate::{
    blocks::ThreadState,
    system::{
        debug::DebugControls,
        execution::EntryBoundary,
        fp_access::{Low128FpAccess, Low128FpContext},
        process_memory::{FixedProcessMemoryControls, Low128Entry, PeThread},
        state::SystemState,
    },
};
use std::{marker::PhantomData, rc::Rc};
use stela_compiler::{
    GuestAddress, Lifter, TargetCpu,
    aarch64::{Decoder, Operation},
    block::{BlockExit, BlockProfile, CheckedMemoryProfile, CompilationPlan},
    context::{ExecutionContext, memory::MemoryRequirements},
};
use stela_contracts::{refuse, require};

pub use crate::memory::domain::MemoryFault;

/// Source-bound identity. It never authorizes loading external native bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Identity {
    pub address_space: u64,
    pub entry: GuestAddress,
    pub source_sha256: String,
    pub native_sha256: String,
    pub native_bytes: usize,
    pub compiler_source_sha256: &'static str,
    pub target: TargetCpu,
    pub abi: String,
    /// Distinguishes this all-writer checked contract from direct-RAM profiles.
    pub memory_model: &'static str,
}

/// One native block and its exact compiler-derived entry requirements. Create
/// this inside each worker: mappings, CPU state and contexts are not shared.
pub struct CheckedMemoryBlock {
    identity: Identity,
    source: Vec<u8>,
    source_map: Vec<(GuestAddress, usize)>,
    requirements: MemoryRequirements,
    profile: CheckedMemoryProfile,
    mapping: platform::Mapping,
    _worker: PhantomData<Rc<()>>,
}

#[derive(Debug)]
pub struct Observation {
    pub exit: BlockExit,
    pub fault: Option<MemoryFault>,
}

/// A finalization failure keeps the native observation available for diagnosis;
/// returning from native code alone does not establish successful retirement.
#[derive(Debug, Clone, Copy)]
pub struct RawMemoryObservation {
    pub version: u32,
    pub bytes: u32,
    pub status_code: u32,
    pub access_code: u32,
    pub address: u64,
    pub pc: u64,
    pub completed_bytes: u64,
}

#[derive(Debug)]
pub struct FinalizationFailure {
    pub cause: crate::system::process_memory::ProcessMemoryError,
    pub observation: Option<Observation>,
    pub raw_memory: Option<RawMemoryObservation>,
}
impl core::fmt::Display for FinalizationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "checked block finalization failed: {}; observation: {:?}; raw memory: {:?}",
            self.cause, self.observation, self.raw_memory
        )
    }
}
impl core::error::Error for FinalizationFailure {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl CheckedMemoryBlock {
    /// Compile one complete source block. Trailing unconsumed bytes are refused
    /// so the identity always describes exactly what may execute.
    pub fn compile(
        address_space: u64,
        entry: GuestAddress,
        source: Vec<u8>,
        profile: CheckedMemoryProfile,
        target: TargetCpu,
    ) -> Result<Self> {
        require!(
            matches!(
                profile,
                CheckedMemoryProfile::SpAlignmentEnabled
                    | CheckedMemoryProfile::SpAlignmentDisabled
            ),
            "this boundary requires the fixed checked GPR memory profile"
        );
        require!(
            !target.data_independent_timing(),
            "shared memory does not admit the single-agent DIT target"
        );
        require!(
            crate::platform::cpu::admitted(target),
            "host lacks native target requirements"
        );
        require!(
            !source.is_empty() && source.len() <= 4096,
            "source must be one bounded nonempty block"
        );
        require!(
            entry.0.checked_add(source.len() as u64).is_some(),
            "source address overflow"
        );
        let plan = CompilationPlan::new(
            &source,
            entry,
            &stela_compiler::Options::new(
                BlockProfile::ORDINARY.with_checked_memory(profile),
                target,
            ),
        )?;
        require!(
            plan.source_bytes() == source.len(),
            "source contains unconsumed trailing bytes"
        );
        // The fixed memory permission establishes LSE2/EL0 memory controls, not
        // arbitrary guest instruction extensions. The typed structure-memory
        // adapter requires the separate low128 FP entry permission at execution;
        // compiling it does not authorize the ordinary GPR entry.
        for (index, bytes) in source.as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_le_bytes(*bytes);
            let instruction = Decoder
                .lift(GuestAddress(entry.0 + (index * 4) as u64), word)
                .map_err(stela_compiler::CompileError::from)?;
            require!(
                baseline_register_operation(word, &instruction.operation)
                    || matches!(
                        instruction.operation,
                        Operation::Exclusive(_)
                        // The checked emitter chooses the architecturally
                        // permitted ignored hint, with no guest memory access.
                        | Operation::Prefetch(_)
                        | Operation::Atomic(_)
                        | Operation::Ordered(_)
                        | Operation::Literal(_)
                        | Operation::Simd(stela_compiler::aarch64::simd::Operand::StructureMemory(
                            _
                        ))
                        | Operation::MemoryRegisterOffset(_)
                        | Operation::MemoryNonTemporal(_)
                        | Operation::MemoryUnprivileged(_)
                        | Operation::Memory { .. }
                        | Operation::MemoryPair { .. }
                    ),
                "instruction requires a separate guest CPU authority"
            );
        }
        let requirements = plan.memory_requirements().expect("checked memory plan");
        let compiled = plan.compile()?;
        let identity = Identity {
            address_space,
            entry,
            source_sha256: stela_formats::sha256(&source),
            native_sha256: stela_formats::sha256(&compiled.native.x86_64_code),
            native_bytes: compiled.native.x86_64_code.len(),
            compiler_source_sha256: stela_compiler::SOURCE_SHA256,
            target,
            abi: stela_compiler::block::BlockProfile::ORDINARY
                .with_checked_memory(profile)
                .abi(),
            memory_model: "checked-normal-wb-all-writers-reservations-lse-ordered-memory-v2",
        };
        let mapping = platform::Mapping::new(&compiled.native.x86_64_code)?;
        Ok(Self {
            identity,
            source,
            source_map: compiled.native.source_map,
            requirements,
            profile,
            mapping,
            _worker: PhantomData,
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Enter with the existing typed CPU permission. Its controls, PE event
    /// attachment, domain and effective policy remain borrowed until the memory
    /// service finalizes. Distinct workers may hold execution loans together;
    /// mapping/protection publication still requires an exclusive service loan.
    ///
    /// # Safety
    /// The outer execution owner must check instruction fetch of this exact
    /// immutable source at its original PC, the guest's baseline instruction
    /// availability and source attributes, and debug/step/interrupt admission.
    /// Its CPU state and memory controls must describe this same PE and machine.
    /// All guest storage and writers must obey the domain's binding
    /// contract, with no external/direct-RAM writers or concurrent host rights
    /// changes. Source, state, native code, host stacks and runtime metadata
    /// must be disjoint from writable guest RAM. This method supplies checked
    /// memory invocation and PC settlement, not full PE execution permission.
    pub unsafe fn run(
        &self,
        controls: &FixedProcessMemoryControls,
        system: &SystemState,
        thread: PeThread<'_>,
        state: &mut ThreadState,
    ) -> Result<Observation> {
        // SAFETY: forwards the unchanged caller contract with no FP permission.
        unsafe {
            self.run_registers(
                controls,
                system,
                thread,
                &mut state.registers,
                &mut state.pc,
                None,
            )
        }
    }

    /// Enter the exact checked block with the same live low128 FP bank and
    /// controls held by `access`. The ordinary entry keeps refusing ASIMD.
    /// `pc` is settled only after the memory service finalizes.
    ///
    /// # Safety
    /// The source, debug/interrupt, memory-domain and all-writer contracts of
    /// `run` apply. `debug` describes this PE's current effective debug state;
    /// it must remain unchanged throughout this synchronous invocation. The
    /// caller obtains `access` through `with_nonstreaming_low128`, keeping
    /// that permission and the original register bank through PC settlement.
    pub unsafe fn run_with_low128(
        &self,
        controls: &FixedProcessMemoryControls,
        system: &SystemState,
        debug: &DebugControls,
        thread: PeThread<'_>,
        pc: &mut GuestAddress,
        access: &mut Low128FpAccess<'_, '_>,
    ) -> Result<Observation> {
        access.with_guest(|context, registers| {
            // SAFETY: the context and mutable bank are split by their
            // owner. The same source/domain contracts apply to both entries.
            unsafe {
                self.run_registers(
                    controls,
                    system,
                    thread,
                    registers,
                    pc,
                    Some((debug, context)),
                )
            }
        })
    }

    unsafe fn run_registers(
        &self,
        controls: &FixedProcessMemoryControls,
        system: &SystemState,
        thread: PeThread<'_>,
        registers: &mut stela_compiler::GuestState,
        pc: &mut GuestAddress,
        low128: Option<(&DebugControls, &Low128FpContext<'_, '_>)>,
    ) -> Result<Observation> {
        require!(
            *pc == self.identity.entry,
            "thread PC differs from checked source entry"
        );
        // Keep this outer loan through exact architectural PC settlement.
        let _publication = thread.memory.execution_loan().map_err(|status| {
            refuse!("checked publication loan refused", status = status.name())
        })?;
        let boundary = EntryBoundary::new(
            self.identity.address_space,
            1,
            self.identity.entry,
            self.identity.entry,
            self.source.len(),
            u32::from_le_bytes(self.source[..4].try_into().expect("complete instruction")),
        );
        let mut observation = None;
        let mut raw_memory = None;
        let finalized = if let Some((debug, context)) = low128 {
            let entry = controls.prepare_profile_with_low128(
                Low128Entry {
                    boundary: &boundary,
                    system,
                    context,
                },
                self.profile,
                self.requirements,
                debug,
                registers,
                thread,
            )?;
            require!(
                entry.requirements() == self.requirements
                    && entry.profile_id() == self.profile.process_memory_profile_id(),
                "checked body/authority mismatch"
            );
            let _floating = HostFloatingEnvironment::capture();
            // SAFETY: the context stays borrowed through the checked
            // callback; only the same split register bank enters native code.
            let result = unsafe {
                entry.with_view(registers, |_, registers, view| {
                    self.invoke_native(registers, view, &mut observation, &mut raw_memory)
                })
            };
            result.map_err(|cause| FinalizationFailure {
                cause,
                observation: observation.take(),
                raw_memory: raw_memory.take(),
            })
        } else {
            let entry = controls.prepare(
                &boundary,
                self.requirements,
                system,
                registers,
                thread.memory,
                thread.events,
            )?;
            require!(
                entry.requirements() == self.requirements
                    && entry.profile_id() == self.profile.process_memory_profile_id(),
                "checked body/authority mismatch"
            );
            let _floating = HostFloatingEnvironment::capture();
            // SAFETY: this is the unchanged ordinary typed memory entry.
            unsafe {
                entry.with_view(|view| {
                    self.invoke_native(registers, view, &mut observation, &mut raw_memory)
                })
            }
            .map_err(|status| FinalizationFailure {
                cause: crate::system::process_memory::ProcessMemoryError::Memory(status),
                observation: observation.take(),
                raw_memory: raw_memory.take(),
            })
        };
        finalized??;
        let observation =
            observation.ok_or(refuse!("checked entry returned without an observation"))?;
        *pc = GuestAddress(
            observation
                .fault
                .map_or(observation.exit.next_pc, |fault| fault.pc),
        );
        Ok(observation)
    }

    unsafe fn invoke_native(
        &self,
        registers: &mut stela_compiler::GuestState,
        view: &mut stela_compiler::context::memory::MemoryContextView,
        observation: &mut Option<Observation>,
        raw_memory: &mut Option<RawMemoryObservation>,
    ) -> Result<()> {
        let mut context = ExecutionContext::default();
        let mut loan = ContextLoan::memory(&mut context, view);
        // SAFETY: the invoking entry keeps source, CPU/context and
        // all-writer memory permission through this synchronous call.
        let exit = unsafe { self.mapping.call_context_block(registers, loan.context()) }?;
        *raw_memory = Some(RawMemoryObservation {
            version: view.version,
            bytes: view.bytes,
            status_code: view.fault_kind,
            access_code: view.fault_access,
            address: view.fault_address,
            pc: view.fault_pc,
            completed_bytes: view.completed_bytes,
        });
        require!(
            loan.context().has_supported_header()
                && loan.context().memory == core::ptr::from_mut(view).cast(),
            "checked context association changed during native call"
        );
        let status =
            stela_compiler::context::memory::MemoryStatus::from_code(view.fault_kind).ok_or(
                refuse!("unknown checked memory status", status = view.fault_kind),
            )?;
        let access = stela_compiler::context::memory::FaultAccess::from_code(view.fault_access)
            .ok_or_else(|| {
                refuse!(
                    "unknown checked memory fault access",
                    access = view.fault_access
                )
            })?;
        let fault = (status != stela_compiler::context::memory::MemoryStatus::Success).then_some(
            MemoryFault {
                access,
                status,
                address: view.fault_address,
                pc: view.fault_pc,
                completed_bytes: view.completed_bytes,
            },
        );
        *observation = Some(Observation { exit, fault });
        if let Some(fault) = observation.as_ref().and_then(|value| value.fault) {
            require!(
                self.source_map.iter().any(|(pc, _)| pc.0 == fault.pc),
                "fault outside consumed source"
            );
        }
        Ok(())
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests;

const NOP_WORD: u32 = 0xd503_201f;
const CONDITIONAL_BRANCH_MASK: u32 = 0xff00_0000;
const CONDITIONAL_BRANCH_CLASS: u32 = 0x5400_0000;
const CONSISTENT_BRANCH_HINT: u32 = 1 << 4;

fn baseline_register_operation(word: u32, operation: &Operation) -> bool {
    // The shared decoder turns some constrained memory forms into NOPs and
    // erases BC's HBC origin. This profile supports neither, so the word
    // itself is checked.
    match operation {
        Operation::Nop => return word == NOP_WORD,
        Operation::BranchCondition { .. } => {
            return word & CONDITIONAL_BRANCH_MASK == CONDITIONAL_BRANCH_CLASS
                && word & CONSISTENT_BRANCH_HINT == 0;
        }
        _ => {}
    }
    matches!(
        operation,
        Operation::Bitfield(_)
            | Operation::PcRelative(_)
            | Operation::ConditionalSelect(_)
            | Operation::ConditionalCompare(_)
            | Operation::IntegerMath(_)
            | Operation::AddSubRegister { .. }
            | Operation::AddSubCarry { .. }
            | Operation::AddSubExtended { .. }
            | Operation::LogicalRegister { .. }
            | Operation::LogicalImmediate { .. }
            | Operation::Branch { .. }
            | Operation::BranchZero { .. }
            | Operation::BranchBit { .. }
            | Operation::MoveWide { .. }
            | Operation::AddSub { .. }
            | Operation::Return
    )
}
