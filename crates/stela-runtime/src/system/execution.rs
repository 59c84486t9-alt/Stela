//! Completing system-instruction exits after native return.

#[cfg(not(feature = "std"))]
use alloc::string::String;
pub(crate) mod authority;
pub(crate) mod owner;

use super::{
    access::{ExceptionLevel, Profile, SecurityState},
    events::{DomainError, SendAttachment},
    exception::{self, EntryControls, EntryEvent, ExceptionServices, ExecuteError, PrepareError},
    profile::EntryProfile,
    state::{PSTATE_IL_MASK, SystemState},
};
use crate::memory::{
    domain::MemoryThread,
    policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    tag_execution::{self, RandomTagFault},
    tag_transfer,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use stela_compiler::{
    GuestAddress, GuestState,
    aarch64::{system::exception::Operation, tag_memory::Operand},
    block::system::{SystemInstruction, SystemOperation},
    context::memory::{MemoryRequirements, MemoryStatus},
};

/// Immutable source identity at the next native entry. The runtime validates
/// registered generation and fetch bounds before constructing this value.
/// Compiled consumed extent and source map are checked separately before effects.
#[derive(Debug)]
pub struct EntryBoundary {
    address_space: u64,
    generation: u64,
    entry: GuestAddress,
    region_base: GuestAddress,
    source_bytes: usize,
    word: u32,
}

impl EntryBoundary {
    pub(crate) fn new(
        address_space: u64,
        generation: u64,
        entry: GuestAddress,
        region_base: GuestAddress,
        source_bytes: usize,
        word: u32,
    ) -> Self {
        Self {
            address_space,
            generation,
            entry,
            region_base,
            source_bytes,
            word,
        }
    }
    pub const fn address_space(&self) -> u64 {
        self.address_space
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn entry(&self) -> GuestAddress {
        self.entry
    }
    pub const fn region_base(&self) -> GuestAddress {
        self.region_base
    }
    /// Registered immutable region extent, not the compiled consumed prefix.
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }
    pub const fn word(&self) -> u32 {
        self.word
    }
}

/// A terminal instruction validated by the runtime. Callers cannot construct
/// one from artifact metadata.
#[derive(Debug)]
pub struct Boundary {
    source: EntryBoundary,
    consumed_bytes: usize,
    instruction: SystemInstruction,
}

impl Boundary {
    /// The block owner checked this descriptor against the final immutable word
    /// of the same source identity validated before native entry.
    pub(crate) fn new(
        source: EntryBoundary,
        consumed_bytes: usize,
        instruction: SystemInstruction,
    ) -> Self {
        Self {
            source,
            consumed_bytes,
            instruction,
        }
    }
    pub const fn consumed_bytes(&self) -> usize {
        self.consumed_bytes
    }
    pub const fn source(&self) -> &EntryBoundary {
        &self.source
    }
    pub const fn instruction(&self) -> SystemInstruction {
        self.instruction
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    WrongAddressSpace,
    IllegalExecutionState,
    Backend(String),
    Event(DomainError),
    Unsupported(&'static str),
    ExceptionPrepare(PrepareError),
    ExceptionExecute(ExecuteError<String>),
    RandomTag(RandomTagFault),
    TagMemory {
        fault: tag_transfer::Fault<MemoryStatus>,
        settlement_error: Option<MemoryStatus>,
    },
}

impl Serialize for Failure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let kind = match self {
            Self::WrongAddressSpace => "wrong_address_space",
            Self::IllegalExecutionState => "illegal_execution_state",
            Self::Backend(_) => "backend",
            Self::Event(_) => "event",
            Self::Unsupported(_) => "unsupported",
            Self::ExceptionPrepare(_) => "exception_prepare",
            Self::ExceptionExecute(_) => "exception_execute",
            Self::RandomTag(_) => "random_tag",
            Self::TagMemory { .. } => "tag_memory",
        };
        if let Self::TagMemory {
            fault,
            settlement_error,
        } = self
        {
            let mut record = serializer.serialize_struct("SystemFailure", 4)?;
            record.serialize_field("kind", kind)?;
            record.serialize_field("cause", &tag_cause_report(&fault.cause))?;
            record.serialize_field(
                "completed",
                &serde_json::json!({
                    "tag_reads": fault.completed.tag_reads,
                    "tag_writes": fault.completed.tag_writes,
                    "data_granules": fault.completed.data_granules,
                }),
            )?;
            record.serialize_field(
                "settlement_error",
                &settlement_error.map(|status| status as u32),
            )?;
            record.end()
        } else {
            let mut record = serializer.serialize_struct("SystemFailure", 2)?;
            record.serialize_field("kind", kind)?;
            record.serialize_field("detail", &format!("{self:?}"))?;
            record.end()
        }
    }
}

fn tag_cause_report(cause: &tag_transfer::Cause<MemoryStatus>) -> serde_json::Value {
    use tag_transfer::{AccessKind, Cause};
    match cause {
        Cause::NotMemoryInstruction => serde_json::json!({ "kind": "not_memory_instruction" }),
        Cause::UndefinedPrivilege => serde_json::json!({ "kind": "undefined_privilege" }),
        Cause::StackAlignment { stack_pointer } => serde_json::json!({
            "kind": "stack_alignment", "stack_pointer": stack_pointer,
        }),
        Cause::DataAlignment { address } => serde_json::json!({
            "kind": "data_alignment", "address": address,
        }),
        Cause::Access { access, error } => serde_json::json!({
            "kind": "access", "status": *error as u32,
            "access": {
                "address": access.address,
                "kind": match access.kind {
                    AccessKind::TagRead => "tag_read",
                    AccessKind::TagWrite => "tag_write",
                    AccessKind::DataWrite => "data_write",
                },
                "privileged": access.privileged,
                "required_alignment": access.required_alignment,
                "pair": access.pair,
                "zero_bulk": access.zero_bulk,
                "data_registers": access.data_registers,
                "tag_checked": access.tag_checked,
            },
        }),
        Cause::Platform(status) => serde_json::json!({
            "kind": "platform", "status": *status as u32,
        }),
        Cause::InvalidOperands => serde_json::json!({ "kind": "invalid_operands" }),
    }
}

/// Synchronous dispatch from the block runtime, which sets PC only after
/// successful completion. A failure keeps its source PC and records any
/// committed effects.
pub trait Dispatcher {
    fn address_space(&self) -> u64;
    /// Validate authoritative PSTATE/control state before any native prefix.
    /// Failure occurs at boundary.entry(), before guest instruction effects.
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        registers: &GuestState,
    ) -> Result<(), Failure>;
    /// Source-derived memory eligibility under the same CPU/backend owner.
    fn prepare_memory_entry<'run>(
        &'run mut self,
        _boundary: &EntryBoundary,
        _source: &[u8],
        _requirements: MemoryRequirements,
        _registers: &GuestState,
    ) -> Result<super::process_memory::PreparedProcessMemory<'run>, Failure> {
        Err(Failure::Unsupported(
            "checked process memory authority unavailable",
        ))
    }
    fn complete(
        &mut self,
        boundary: Boundary,
        registers: &mut GuestState,
    ) -> Result<GuestAddress, Failure>;
    /// Borrowed after native return; the default certifies no new synchronization.
    fn complete_with_code_scope(
        &mut self,
        boundary: Boundary,
        registers: &mut GuestState,
        _code: &mut crate::blocks::CodePublicationScope<'_>,
    ) -> Result<GuestAddress, Failure> {
        self.complete(boundary, registers)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EntrySnapshot {
    pub profile: Profile,
    pub features: EntryProfile,
    pub controls: EntryControls,
}

#[derive(Debug, Clone, Copy)]
pub struct TagMemorySnapshot {
    pub lower_address: LowerAddressProfile,
    pub fault_mode: TagCheckFaultMode,
    pub tag_check_mask: bool,
    pub transfer: tag_transfer::Profile,
}

/// Ephemeral effective controls, not persistent feature/register state. IRG needs
/// no memory snapshot; a dedicated tag transfer does require one.
#[derive(Debug, Clone, Copy)]
pub struct TagSnapshot {
    pub allocation_access_enabled: bool,
    pub memory: Option<TagMemorySnapshot>,
}

/// Fresh CPU profile and a borrow of the authoritative PE event owner. This is
/// a synchronous Rust service attachment, never a persistent control snapshot.
pub struct SendEventServices<'a> {
    pub profile: Profile,
    pub attachment: SendAttachment<'a>,
}

/// The CPU/platform owner supplies current source-bound snapshots and real
/// effect services. Snapshot creation performs feature/access checks but no
/// guest architectural effect. An unavailable optional service must decline.
///
/// Tag snapshot authorization checks only source-required feature/access gates.
/// It must not require memory attachment or block geometry before an EL0 bulk
/// instruction's Undefined privilege outcome, and IRG needs no memory controls.
/// Only reached dedicated memory operations require a supported MMU/storage
/// snapshot; LowerAddressProfile does not implement an ARM page-table walk.
/// The thread is the same physical writer/tag/reservation domain used by other
/// guest memory accesses.
pub trait Backend: ExceptionServices<Error = String> {
    /// Check against the same CPU and control identity used by completion.
    /// `source` is the immutable window starting at `boundary.entry()`. Use the
    /// shared parser to find the prefix and check every feature it needs (the
    /// context-free classifier does not prove availability). The borrow ends
    /// with this call. No architectural effect. Context-backed memory must also
    /// refresh and validate its policy from the system state here.
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<(), String>;
    /// One scoped borrow from the controls, the system state and this thread.
    fn prepare_process_memory<'run>(
        &'run mut self,
        _boundary: &EntryBoundary,
        _source: &[u8],
        _requirements: MemoryRequirements,
        _system: &'run SystemState,
        _registers: &GuestState,
    ) -> Result<super::process_memory::PreparedProcessMemory<'run>, String> {
        Err("checked process memory authority unavailable".into())
    }
    fn entry_snapshot(
        &mut self,
        boundary: &Boundary,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<EntrySnapshot, String>;
    fn tag_snapshot(
        &mut self,
        boundary: &Boundary,
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<TagSnapshot, String>;
    fn tag_memory(&mut self) -> Result<&mut MemoryThread<MemoryControls>, String>;

    /// The event services, with the profile from the same owner as
    /// `validate_entry`. The endpoint is shared with exception-return event
    /// publication and the local monitor binding. By default events are
    /// unavailable.
    fn send_event_services(
        &mut self,
        _boundary: &Boundary,
        _system: &SystemState,
        _registers: &GuestState,
    ) -> Result<SendEventServices<'_>, String> {
        Err("event publication services are unavailable".into())
    }
}

/// Exclusive borrows of the existing state and backend; this owner stores no
/// architectural copies and does not dereference ExecutionContext's system slot.
pub struct Execution<'a, B> {
    address_space: u64,
    system: &'a mut SystemState,
    backend: &'a mut B,
}

impl<'a, B: Backend> Execution<'a, B> {
    pub fn new(address_space: u64, system: &'a mut SystemState, backend: &'a mut B) -> Self {
        Self {
            address_space,
            system,
            backend,
        }
    }

    fn exception(
        &mut self,
        boundary: &Boundary,
        registers: &mut GuestState,
        operation: Operation,
    ) -> Result<GuestAddress, Failure> {
        let event = match operation {
            Operation::Undefined { .. } => Some(EntryEvent::Undefined {
                instruction_pc: boundary.instruction.instruction_pc.0,
            }),
            Operation::SupervisorCall { immediate } => Some(EntryEvent::SupervisorCall {
                instruction_pc: boundary.instruction.instruction_pc.0,
                immediate,
            }),
            Operation::ExceptionReturn { key: None } => None,
            _ => {
                return Err(Failure::Unsupported(
                    "exception operation requires additional effects",
                ));
            }
        };
        let snapshot = self
            .backend
            .entry_snapshot(boundary, self.system, registers)
            .map_err(Failure::Backend)?;
        let next = if let Some(event) = event {
            exception::prepare_entry(
                &snapshot.features,
                snapshot.profile,
                snapshot.controls,
                self.system,
                registers,
                event,
            )
            .map_err(Failure::ExceptionPrepare)?
            .execute(self.system, registers, self.backend)
        } else {
            exception::prepare_return(
                boundary.instruction.instruction_pc.0,
                &snapshot.features,
                snapshot.profile,
                snapshot.controls,
                self.system,
                registers,
            )
            .map_err(Failure::ExceptionPrepare)?
            .execute(self.system, registers, self.backend)
        };
        next.map(GuestAddress).map_err(Failure::ExceptionExecute)
    }

    fn send_event(
        &mut self,
        boundary: &Boundary,
        registers: &GuestState,
        local: bool,
    ) -> Result<GuestAddress, Failure> {
        let mut services = self
            .backend
            .send_event_services(boundary, self.system, registers)
            .map_err(Failure::Backend)?;
        let profile = services.profile;
        if profile.current_el != self.system.current_el() {
            return Err(Failure::Unsupported("event profile differs from PSTATE"));
        }
        if profile.security != SecurityState::NonSecure
            || !matches!(
                profile.current_el,
                ExceptionLevel::El0 | ExceptionLevel::El1
            )
            || profile.el2_enabled
            || profile.el3_present
        {
            return Err(Failure::Unsupported(
                "event execution profile is unsupported",
            ));
        }
        services.attachment.send(local).map_err(Failure::Event)?;
        Ok(boundary.instruction.next_pc)
    }

    fn tag(
        &mut self,
        boundary: &Boundary,
        registers: &mut GuestState,
        operand: Operand,
    ) -> Result<GuestAddress, Failure> {
        if self.system.mte().is_none() {
            return Err(Failure::Unsupported("allocation-tag state is unavailable"));
        }
        let snapshot = self
            .backend
            .tag_snapshot(boundary, self.system, registers)
            .map_err(Failure::Backend)?;
        if self.system.current_el() == ExceptionLevel::El0 && operand.requires_privilege() {
            return Err(Failure::TagMemory {
                fault: tag_transfer::Fault {
                    cause: tag_transfer::Cause::UndefinedPrivilege,
                    completed: tag_transfer::Progress::default(),
                },
                settlement_error: None,
            });
        }
        if matches!(operand, Operand::RandomTag { .. }) {
            let mte = self
                .system
                .mte_mut()
                .expect("MTE state checked before snapshot");
            let controls = mte.generation_controls(snapshot.allocation_access_enabled);
            tag_execution::complete_random_tag(operand, registers, controls, mte.generation_mut())
                .map_err(Failure::RandomTag)?;
        } else {
            let snapshot_memory = snapshot.memory.ok_or(Failure::Unsupported(
                "allocation-tag memory backend is unavailable",
            ))?;
            let privileged = self.system.current_el() == ExceptionLevel::El1;
            if snapshot_memory.transfer.privileged() != privileged {
                return Err(Failure::Unsupported(
                    "allocation-tag privilege snapshot differs from PSTATE",
                ));
            }
            let memory = self.backend.tag_memory().map_err(Failure::Backend)?;
            if memory.address_space() != Some(self.address_space) {
                return Err(Failure::WrongAddressSpace);
            }
            *memory.policy_mut() = MemoryControls::new(
                snapshot_memory.lower_address,
                privileged,
                snapshot.allocation_access_enabled,
                self.system.tag_check_override(),
                snapshot_memory.fault_mode,
                snapshot_memory.tag_check_mask,
            );
            if let Err(fault) =
                tag_execution::complete_memory(operand, registers, snapshot_memory.transfer, memory)
            {
                // The selected reservation policy (not a TakeException effect).
                // Keep the fault even if settlement fails.
                let status = match &fault.cause {
                    tag_transfer::Cause::StackAlignment { .. }
                    | tag_transfer::Cause::DataAlignment { .. } => Some(MemoryStatus::Alignment),
                    tag_transfer::Cause::Access { error, .. } => Some(*error),
                    _ => None,
                };
                let settlement_error = status.and_then(|status| memory.settle_fault(status).err());
                return Err(Failure::TagMemory {
                    fault,
                    settlement_error,
                });
            }
        }
        Ok(boundary.instruction.next_pc)
    }
}

impl<B: Backend> Dispatcher for Execution<'_, B> {
    fn address_space(&self) -> u64 {
        self.address_space
    }

    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        registers: &GuestState,
    ) -> Result<(), Failure> {
        if boundary.address_space != self.address_space {
            return Err(Failure::WrongAddressSpace);
        }
        if self.system.pstate(registers) & PSTATE_IL_MASK != 0 {
            return Err(Failure::IllegalExecutionState);
        }
        self.backend
            .validate_entry(boundary, source, self.system, registers)
            .map_err(Failure::Backend)
    }

    fn prepare_memory_entry<'run>(
        &'run mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        requirements: MemoryRequirements,
        registers: &GuestState,
    ) -> Result<super::process_memory::PreparedProcessMemory<'run>, Failure> {
        if boundary.address_space != self.address_space {
            return Err(Failure::WrongAddressSpace);
        }
        if self.system.pstate(registers) & PSTATE_IL_MASK != 0 {
            return Err(Failure::IllegalExecutionState);
        }
        self.backend
            .prepare_process_memory(boundary, source, requirements, self.system, registers)
            .map_err(Failure::Backend)
    }
    fn complete(
        &mut self,
        boundary: Boundary,
        registers: &mut GuestState,
    ) -> Result<GuestAddress, Failure> {
        if boundary.source.address_space != self.address_space {
            return Err(Failure::WrongAddressSpace);
        }
        if self.system.pstate(registers) & PSTATE_IL_MASK != 0 {
            return Err(Failure::IllegalExecutionState);
        }
        match boundary.instruction.operation {
            SystemOperation::Exception(operation) => {
                self.exception(&boundary, registers, operation)
            }
            SystemOperation::TagMemory(operand) => self.tag(&boundary, registers, operand),
            SystemOperation::SendEvent { local } => self.send_event(&boundary, registers, local),
            SystemOperation::Register(_) | SystemOperation::PstateImmediate(_) => Err(
                Failure::Unsupported("register operation requires retained authoritative owners"),
            ),
            SystemOperation::InstructionSynchronization { .. } => Err(Failure::Unsupported(
                "instruction synchronization requires the actual source publication owner",
            )),
            SystemOperation::Synchronization(_) => Err(Failure::Unsupported(
                "synchronization requires the retained resource-specific System owner",
            )),
        }
    }
}

#[cfg(test)]
mod tests;
