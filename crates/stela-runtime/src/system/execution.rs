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
            SystemOperation::Maintenance(_)
            | SystemOperation::Guarded(_)
            | SystemOperation::DebugStateOnly(_)
            | SystemOperation::Unprivileged(_)
            | SystemOperation::Exclusive(_)
            | SystemOperation::CheckedPointer(_)
            | SystemOperation::TagOffset(_) => Err(Failure::Unsupported(
                "SYS maintenance, GXF, Debug-state-only, unprivileged, exclusive, CPA and \
                 ADDG/SUBG forms belong to the system-mode engine",
            )),
            SystemOperation::Wait { .. } => Err(Failure::Unsupported(
                "wait requires the retained hosted wait owner",
            )),
            SystemOperation::InstructionSynchronization { .. } => Err(Failure::Unsupported(
                "instruction synchronization requires the source publication owner",
            )),
            SystemOperation::Synchronization(_) => Err(Failure::Unsupported(
                "synchronization requires the retained resource-specific System owner",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{
        domain::{AllocationTagPolicy, MemoryDomain, MemorySystem},
        tags::{AllocationTag, TagGenerationState, TagRandomization},
    };
    use crate::system::{
        access::SecurityState,
        debug::DebugControls,
        exception::{CommittedPrefix, Completion, EffectFailure, EffectStage, ServiceRequest},
        profile::{ScalableEntryAbsence, SystemEntryFeatures},
        pstate::{MteFeature, TCO_MASK},
        state::{El1Registers, MteState, PSTATE_EL1H},
    };
    use stela_compiler::{
        TargetCpu, block::system::decode_system_instruction, context::memory::flags,
    };

    const ADDRESS_SPACE: u64 = 7;
    const SOURCE_PC: GuestAddress = GuestAddress(0x1000);
    const DATA_ADDRESS: u64 = 0x4000;
    const ADDRESS_BITS: u8 = 48;
    const SEV: u32 = 0xd503_209f;
    const SEVL: u32 = 0xd503_20bf;
    const SVC: u32 = 0xd400_0001;
    const IRG: u32 = 0x9ac0_1000;
    const LDG: u32 = 0xd960_0000;
    const VECTOR_BASE: u64 = 0x8000;
    const ERG_BYTES: u64 = 16;
    const STRIPES: usize = 4;
    const GENERATION: u64 = 3;
    const REGISTER_FLAGS: u32 = 0xa000_0000;

    fn entry(word: u32) -> EntryBoundary {
        EntryBoundary::new(
            ADDRESS_SPACE,
            GENERATION,
            SOURCE_PC,
            SOURCE_PC,
            size_of::<u32>(),
            word,
        )
    }

    fn boundary(word: u32) -> Boundary {
        Boundary::new(
            entry(word),
            size_of::<u32>(),
            decode_system_instruction(SOURCE_PC, word).unwrap().unwrap(),
        )
    }

    fn state(mte: bool, tco: bool) -> SystemState {
        let registers = El1Registers::new(0, 0, 0, 0, VECTOR_BASE);
        if mte {
            SystemState::new_with_mte(
                PSTATE_EL1H | if tco { TCO_MASK } else { 0 },
                0x2000,
                registers,
                MteFeature::TwoOrLater,
                MteState::new(
                    0,
                    TagRandomization::ArchitecturalLfsr,
                    TagGenerationState {
                        seed: 1,
                        tag: AllocationTag::new(0).unwrap(),
                    },
                ),
            )
            .unwrap()
        } else {
            SystemState::new(PSTATE_EL1H, 0x2000, registers).unwrap()
        }
    }

    fn registers() -> GuestState {
        let mut registers = GuestState {
            sp: 0x3000,
            nzcv: REGISTER_FLAGS,
            ..GuestState::default()
        };
        registers.x[0] = DATA_ADDRESS;
        registers
    }

    struct BackendFixture {
        event_domain: Option<std::sync::Arc<super::super::events::EventDomain>>,
        event_endpoint: Option<super::super::events::EventEndpoint>,
        event_profile: Option<Profile>,
        entry: Option<EntrySnapshot>,
        tags: Option<TagSnapshot>,
        memory: Option<MemoryThread<MemoryControls>>,
        fail_synchronize: bool,
        deny_cssc: bool,
        expected_source_pc: u64,
        calls: Vec<&'static str>,
    }

    impl BackendFixture {
        fn new() -> Self {
            Self {
                event_domain: None,
                event_endpoint: None,
                event_profile: None,
                entry: Some(EntrySnapshot {
                    profile: Profile {
                        current_el: ExceptionLevel::El1,
                        security: SecurityState::NonSecure,
                        el2_enabled: false,
                        el3_present: false,
                    },
                    features: EntryProfile::base(
                        SystemEntryFeatures::declared_absent(),
                        ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
                    )
                    .unwrap(),
                    controls: EntryControls {
                        tcr_el1: 0,
                        mdscr_el1: 0,
                        debug: DebugControls::default(),
                    },
                }),
                tags: None,
                memory: None,
                fail_synchronize: false,
                deny_cssc: false,
                expected_source_pc: SOURCE_PC.0,
                calls: Vec::new(),
            }
        }
    }

    // Records ordering and failures only.
    impl ExceptionServices for BackendFixture {
        type Permit = ();
        type Error = String;

        fn preflight(&mut self, request: ServiceRequest) -> Result<(), String> {
            assert_eq!(request.source_pc, self.expected_source_pc);
            self.calls.push("preflight");
            Ok(())
        }
        fn synchronize_context(
            &mut self,
            _: &mut (),
            _: ExceptionLevel,
        ) -> Result<(), EffectFailure<String>> {
            self.calls.push("synchronize");
            if self.fail_synchronize {
                Err(EffectFailure {
                    error: "unavailable synchronization".into(),
                    completion: Completion::None,
                })
            } else {
                Ok(())
            }
        }
        fn clear_exclusive_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<String>> {
            self.calls.push("clear_exclusive");
            Ok(())
        }
        fn send_event_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<String>> {
            self.calls.push("send_event");
            Ok(())
        }
        fn branch_address(
            &mut self,
            _: &mut (),
            target: u64,
            _: ExceptionLevel,
        ) -> Result<u64, EffectFailure<String>> {
            self.calls.push("branch_address");
            Ok(target)
        }
    }

    impl Backend for BackendFixture {
        fn validate_entry(
            &mut self,
            boundary: &EntryBoundary,
            source: &[u8],
            _: &SystemState,
            _: &GuestState,
        ) -> Result<(), String> {
            self.calls.push("validate_entry");
            let analysis = stela_compiler::block::analyze_with_profile(
                source,
                boundary.entry(),
                stela_compiler::block::BlockProfile::SystemV1,
            )
            .map_err(|error| error.to_string())?;
            if self.deny_cssc
                && source[..analysis.source_bytes]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .any(|bytes| {
                        stela_compiler::aarch64::integer_unary::decode(u32::from_le_bytes(*bytes))
                            .is_some()
                    })
            {
                return Err("FEAT_CSSC is absent in this source-authorized fixture profile".into());
            }
            Ok(())
        }
        fn entry_snapshot(
            &mut self,
            _: &Boundary,
            _: &SystemState,
            _: &GuestState,
        ) -> Result<EntrySnapshot, String> {
            self.calls.push("entry_snapshot");
            self.entry.ok_or_else(|| "entry backend unavailable".into())
        }
        fn tag_snapshot(
            &mut self,
            _: &Boundary,
            _: &SystemState,
            _: &GuestState,
        ) -> Result<TagSnapshot, String> {
            self.calls.push("tag_snapshot");
            self.tags.ok_or_else(|| "tag backend unavailable".into())
        }
        fn send_event_services(
            &mut self,
            boundary: &Boundary,
            _: &SystemState,
            _: &GuestState,
        ) -> Result<SendEventServices<'_>, String> {
            assert_eq!(
                boundary.instruction().instruction_pc.0,
                self.expected_source_pc
            );
            self.calls.push("send_event_services");
            let profile = self.event_profile.ok_or("event profile unavailable")?;
            let domain = self
                .event_domain
                .as_ref()
                .ok_or("event domain unavailable")?;
            let endpoint = self
                .event_endpoint
                .as_mut()
                .ok_or("event endpoint unavailable")?;
            let attachment =
                SendAttachment::new(domain, endpoint).map_err(|error| format!("{error:?}"))?;
            Ok(SendEventServices {
                profile,
                attachment,
            })
        }
        fn tag_memory(&mut self) -> Result<&mut MemoryThread<MemoryControls>, String> {
            self.calls.push("tag_memory");
            self.memory
                .as_mut()
                .ok_or_else(|| "memory backend unavailable".into())
        }
    }

    #[test]
    fn wrong_space_and_il_decline_before_backend_or_register_effects() {
        let mut system = state(false, false);
        let mut registers = registers();
        let original = registers.clone();
        let mut backend = BackendFixture::new();
        let mut wrong = entry(SVC);
        wrong.address_space += 1;
        assert_eq!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend).validate_entry(
                &wrong,
                &SVC.to_le_bytes(),
                &registers
            ),
            Err(Failure::WrongAddressSpace)
        );
        system
            .transition_pstate(
                &mut registers,
                PSTATE_EL1H | PSTATE_IL_MASK | u64::from(REGISTER_FLAGS),
            )
            .unwrap();
        assert_eq!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend).validate_entry(
                &entry(SVC),
                &SVC.to_le_bytes(),
                &registers
            ),
            Err(Failure::IllegalExecutionState)
        );
        assert_eq!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                .complete(boundary(IRG), &mut registers),
            Err(Failure::IllegalExecutionState)
        );
        assert_eq!(registers, original);
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn absent_or_failed_exception_backend_preserves_architectural_state() {
        let mut system = state(false, false);
        let mut registers = registers();
        let original_system = system.clone();
        let original_registers = registers.clone();
        let mut backend = BackendFixture::new();
        backend.entry = None;
        assert!(matches!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                .complete(boundary(SVC), &mut registers),
            Err(Failure::Backend(_))
        ));
        backend = BackendFixture::new();
        backend.fail_synchronize = true;
        assert!(matches!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                .complete(boundary(SVC), &mut registers),
            Err(Failure::ExceptionExecute(ExecuteError::Effect {
                stage: EffectStage::Synchronize,
                committed: CommittedPrefix::None,
                failure: EffectFailure {
                    completion: Completion::None,
                    ..
                },
            }))
        ));
        assert_eq!(system, original_system);
        assert_eq!(registers, original_registers);
        assert_eq!(
            backend.calls,
            ["entry_snapshot", "preflight", "synchronize"]
        );
    }

    #[test]
    fn random_tag_completes_without_any_memory_backend() {
        let mut system = state(true, false);
        let mut registers = registers();
        let mut backend = BackendFixture::new();
        backend.tags = Some(TagSnapshot {
            allocation_access_enabled: true,
            memory: None,
        });
        assert_eq!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                .complete(boundary(IRG), &mut registers),
            Ok(GuestAddress(SOURCE_PC.0 + size_of::<u32>() as u64))
        );
        assert_eq!(backend.calls, ["tag_snapshot"]);
        assert_eq!(registers.nzcv, REGISTER_FLAGS);
    }

    fn tag_snapshot(privileged: bool) -> TagSnapshot {
        TagSnapshot {
            allocation_access_enabled: true,
            memory: Some(TagMemorySnapshot {
                lower_address: LowerAddressProfile::new(ADDRESS_BITS, true).unwrap(),
                fault_mode: TagCheckFaultMode::Asynchronous,
                tag_check_mask: false,
                transfer: tag_transfer::Profile::new(privileged, true, 16, 64).unwrap(),
            }),
        }
    }

    #[test]
    fn tag_privilege_mismatch_is_rejected_before_memory_or_state_effects() {
        let mut system = state(true, false);
        let mut registers = registers();
        let original = registers.clone();
        let mut backend = BackendFixture::new();
        backend.tags = Some(tag_snapshot(false));
        assert!(matches!(
            Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                .complete(boundary(LDG), &mut registers),
            Err(Failure::Unsupported(_))
        ));
        assert_eq!(backend.calls, ["tag_snapshot"]);
        assert_eq!(registers, original);
    }

    #[test]
    fn tag_entry_refreshes_actual_policy_from_authoritative_el_and_tco() {
        for tco in [false, true] {
            let mut system = state(true, tco);
            let mut registers = registers();
            let mut backend = BackendFixture::new();
            backend.tags = Some(tag_snapshot(true));
            let stale = MemoryControls::new(
                LowerAddressProfile::new(ADDRESS_BITS, true).unwrap(),
                false,
                true,
                !tco,
                TagCheckFaultMode::Asynchronous,
                false,
            );
            backend.memory = Some(
                MemoryDomain::new_for_address_space(
                    ADDRESS_SPACE,
                    MemorySystem::new(ERG_BYTES, STRIPES).unwrap(),
                    Vec::new(),
                    TargetCpu::detect(),
                )
                .unwrap()
                .thread(stale),
            );
            let result = Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                .complete(boundary(LDG), &mut registers);
            assert!(matches!(
                result,
                Err(Failure::TagMemory {
                    fault: tag_transfer::Fault {
                        cause: tag_transfer::Cause::Access {
                            error: MemoryStatus::Translation,
                            ..
                        },
                        ..
                    },
                    settlement_error: None,
                })
            ));
            let memory = backend.memory.as_mut().unwrap();
            assert_eq!(memory.policy_mut().validate_privilege(true), Ok(()));
            assert_eq!(
                memory.validate_execution(flags::TAG_CHECKED),
                if tco {
                    Ok(())
                } else {
                    Err(MemoryStatus::Unsupported)
                }
            );
        }
    }

    #[test]
    fn tag_failure_report_retains_structured_access_prefix_and_settlement_error() {
        let failure = Failure::TagMemory {
            fault: tag_transfer::Fault {
                cause: tag_transfer::Cause::Access {
                    access: tag_transfer::Access {
                        address: DATA_ADDRESS,
                        kind: tag_transfer::AccessKind::TagWrite,
                        privileged: true,
                        required_alignment: 16,
                        pair: true,
                        zero_bulk: false,
                        data_registers: [Some(0), None],
                        tag_checked: false,
                    },
                    error: MemoryStatus::Permission,
                },
                completed: tag_transfer::Progress {
                    tag_reads: 0,
                    tag_writes: 1,
                    data_granules: 0,
                },
            },
            settlement_error: Some(MemoryStatus::Domain),
        };
        let report = serde_json::to_value(failure).unwrap();
        assert_eq!(report["cause"]["access"]["address"], DATA_ADDRESS);
        assert_eq!(report["cause"]["status"], MemoryStatus::Permission as u32);
        assert_eq!(report["completed"]["tag_writes"], 1);
        assert_eq!(report["settlement_error"], MemoryStatus::Domain as u32);
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn actual_block_runtime_preserves_failed_exception_pc_and_completed_prefix()
    -> anyhow::Result<()> {
        use crate::blocks::{BlockRuntime, StopReason, ThreadState};
        use stela_compiler::block::BlockProfile;
        const ADD: u32 = 0x9100_0400;
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::SystemV1,
        );
        runtime.register_code(
            SOURCE_PC,
            [ADD, SVC].into_iter().flat_map(u32::to_le_bytes).collect(),
        )?;
        let mut thread = ThreadState {
            registers: registers(),
            pc: SOURCE_PC,
        };
        let original_x0 = thread.registers.x[0];
        let mut system = state(false, false);
        let original_system = system.clone();
        let mut backend = BackendFixture::new();
        backend.fail_synchronize = true;
        backend.expected_source_pc = SOURCE_PC.0 + size_of::<u32>() as u64;
        let mut execution = Execution::new(ADDRESS_SPACE, &mut system, &mut backend);
        // SAFETY: a trusted ADD followed by a checked system boundary; the fixture
        // fails synchronization before any exception effect.
        let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut execution)? };
        assert!(matches!(
            outcome.reason,
            StopReason::SystemFailure {
                failure: Failure::ExceptionExecute(ExecuteError::Effect {
                    committed: CommittedPrefix::None,
                    ..
                }),
                ..
            }
        ));
        assert_eq!(thread.pc, GuestAddress(backend.expected_source_pc));
        assert_eq!(thread.registers.x[0], original_x0 + 1);
        assert_eq!(system, original_system);
        Ok(())
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn illegal_state_stops_before_decode_and_any_native_prefix() -> anyhow::Result<()> {
        use crate::blocks::{BlockRuntime, StopReason, ThreadState};
        use stela_compiler::block::BlockProfile;
        const ADD: u32 = 0x9100_0400;
        const UNALLOCATED: u32 = u32::MAX;
        for words in [[ADD, SVC], [IRG, SVC], [UNALLOCATED, SVC]] {
            let cache = tempfile::tempdir()?;
            let mut runtime = BlockRuntime::new_with_profile(
                ADDRESS_SPACE,
                cache.path().into(),
                BlockProfile::SystemV1,
            );
            runtime.register_code(
                SOURCE_PC,
                words.into_iter().flat_map(u32::to_le_bytes).collect(),
            )?;
            let mut thread = ThreadState {
                registers: registers(),
                pc: SOURCE_PC,
            };
            let original = thread.registers.clone();
            let mut system = state(false, false);
            system
                .transition_pstate(
                    &mut thread.registers,
                    PSTATE_EL1H | PSTATE_IL_MASK | u64::from(REGISTER_FLAGS),
                )
                .unwrap();
            let mut backend = BackendFixture::new();
            let mut execution = Execution::new(ADDRESS_SPACE, &mut system, &mut backend);
            // SAFETY: entry must reject IL before any decoding, mapping or invocation.
            let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut execution)? };
            assert!(matches!(
                outcome.reason,
                StopReason::SystemEntryFailure {
                    instruction_pc: SOURCE_PC,
                    failure: Failure::IllegalExecutionState,
                    ..
                }
            ));
            assert_eq!(outcome.blocks_executed, 0);
            assert_eq!(outcome.compiled_blocks, 0);
            assert_eq!(thread.pc, SOURCE_PC);
            assert_eq!(thread.registers, original);
            assert!(backend.calls.is_empty());
        }
        Ok(())
    }

    #[test]
    fn authorized_el0_bulk_is_undefined_without_memory_attachment_or_geometry() {
        use crate::system::state::PSTATE_EL0T;
        const LDGM: u32 = 0xd9e0_0000;
        const STGM: u32 = 0xd9a0_0000;
        const STZGM: u32 = 0xd920_0000;
        for word in [LDGM, STGM, STZGM] {
            let mut system = state(true, false);
            let mut registers = registers();
            system
                .transition_pstate(&mut registers, PSTATE_EL0T | u64::from(REGISTER_FLAGS))
                .unwrap();
            let original_registers = registers.clone();
            let original_system = system.clone();
            let mut backend = BackendFixture::new();
            backend.tags = Some(TagSnapshot {
                allocation_access_enabled: true,
                memory: None,
            });
            assert_eq!(
                Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                    .complete(boundary(word), &mut registers),
                Err(Failure::TagMemory {
                    fault: tag_transfer::Fault {
                        cause: tag_transfer::Cause::UndefinedPrivilege,
                        completed: tag_transfer::Progress::default()
                    },
                    settlement_error: None,
                })
            );
            assert_eq!(backend.calls, ["tag_snapshot"]);
            assert_eq!(registers, original_registers);
            assert_eq!(system, original_system);
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn unavailable_optional_feature_beyond_first_word_prevents_all_prefix_effects()
    -> anyhow::Result<()> {
        use crate::blocks::{BlockRuntime, StopReason, ThreadState};
        use stela_compiler::block::BlockProfile;
        const ADD: u32 = 0x9100_0400;
        const CSSC_ABS: u32 = 0xdac0_2000;
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::SystemV1,
        );
        runtime.register_code(
            SOURCE_PC,
            [ADD, CSSC_ABS, SVC]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )?;
        let mut thread = ThreadState {
            registers: registers(),
            pc: SOURCE_PC,
        };
        let original = thread.registers.clone();
        let mut system = state(false, false);
        let mut backend = BackendFixture::new();
        backend.deny_cssc = true;
        let mut execution = Execution::new(ADDRESS_SPACE, &mut system, &mut backend);
        // SAFETY: authoritative feature rejection must happen before any native prefix.
        let outcome = unsafe { runtime.run_with_system(&mut thread, None, 1, &mut execution)? };
        assert!(matches!(
            outcome.reason,
            StopReason::SystemEntryFailure {
                failure: Failure::Backend(_),
                ..
            }
        ));
        assert_eq!(thread.registers, original);
        assert_eq!(thread.pc, SOURCE_PC);
        assert_eq!(outcome.blocks_executed, 0);
        assert_eq!(outcome.compiled_blocks, 0);
        assert_eq!(backend.calls, ["validate_entry"]);
        // The parser stops authorization at the first terminator.
        let source: Vec<_> = [SVC, CSSC_ABS]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        assert_eq!(
            backend.validate_entry(&entry(SVC), &source, &system, &thread.registers),
            Ok(())
        );
        Ok(())
    }

    fn event_backend() -> BackendFixture {
        let mut backend = BackendFixture::new();
        let domain = std::sync::Arc::new(super::super::events::EventDomain::new());
        backend.event_endpoint = Some(domain.register(false, None).unwrap());
        backend.event_domain = Some(domain);
        backend.event_profile = backend.entry.map(|entry| entry.profile);
        backend
    }

    #[test]
    fn real_event_dispatch_publishes_local_or_global_without_register_effects() {
        for word in [SEVL, SEV] {
            let mut backend = event_backend();
            let peer = backend
                .event_domain
                .as_ref()
                .unwrap()
                .register(false, None)
                .unwrap();
            let mut system = state(false, false);
            let mut registers = registers();
            let before = registers.clone();
            let pstate = system.pstate(&registers);
            assert_eq!(
                Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                    .complete(boundary(word), &mut registers),
                Ok(GuestAddress(SOURCE_PC.0 + size_of::<u32>() as u64))
            );
            assert_eq!(registers, before);
            assert_eq!(system.pstate(&registers), pstate);
            assert!(backend.event_endpoint.as_ref().unwrap().is_set());
            assert_eq!(peer.is_set(), word == SEV);
            assert_eq!(backend.calls, ["send_event_services"]);
        }
    }

    #[test]
    fn event_profile_and_domain_fail_before_publication() {
        let base = event_backend().event_profile.unwrap();
        for profile in [
            Profile {
                current_el: ExceptionLevel::El0,
                ..base
            },
            Profile {
                current_el: ExceptionLevel::El2,
                ..base
            },
            Profile {
                security: SecurityState::Secure,
                ..base
            },
            Profile {
                security: SecurityState::Realm,
                ..base
            },
            Profile {
                el2_enabled: true,
                ..base
            },
            Profile {
                el3_present: true,
                ..base
            },
        ] {
            let mut backend = event_backend();
            backend.event_profile = Some(profile);
            let mut system = state(false, false);
            let mut registers = registers();
            let before = registers.clone();
            assert!(matches!(
                Execution::new(ADDRESS_SPACE, &mut system, &mut backend)
                    .complete(boundary(SEV), &mut registers),
                Err(Failure::Unsupported(_))
            ));
            assert_eq!(registers, before);
            assert!(!backend.event_endpoint.as_ref().unwrap().is_set());
        }
        let mut backend = event_backend();
        backend.event_domain = Some(std::sync::Arc::new(super::super::events::EventDomain::new()));
        assert!(matches!(
            Execution::new(ADDRESS_SPACE, &mut state(false, false), &mut backend)
                .complete(boundary(SEV), &mut registers()),
            Err(Failure::Backend(_))
        ));
        assert!(!backend.event_endpoint.as_ref().unwrap().is_set());
    }

    #[test]
    fn missing_event_service_is_explicit_failure_without_register_effects() {
        let mut backend = BackendFixture::new();
        let mut registers = registers();
        let before = registers.clone();
        assert!(matches!(
            Execution::new(ADDRESS_SPACE, &mut state(false, false), &mut backend)
                .complete(boundary(SEVL), &mut registers),
            Err(Failure::Backend(_))
        ));
        assert_eq!(registers, before);
    }

    #[test]
    fn native_event_blocks_share_real_two_pe_domain_and_exact_source_maps() -> anyhow::Result<()> {
        use crate::blocks::{BlockRuntime, StopReason, ThreadState};
        use stela_compiler::block::{BlockProfile, ExitKind};
        const MOV_RAX_IMMEDIATE: [u8; 2] = [0x48, 0xb8];
        const MOV_EDX_IMMEDIATE: u8 = 0xba;
        const RETURN: u8 = 0xc3;
        const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
        for word in [SEVL, SEV] {
            for sender_pe in 0..2 {
                let cache = tempfile::tempdir()?;
                let mut runtime = BlockRuntime::new_with_profile(
                    ADDRESS_SPACE,
                    cache.path().into(),
                    BlockProfile::SystemV1,
                );
                runtime.register_code(SOURCE_PC, word.to_le_bytes().to_vec())?;
                let prepared = runtime.prepare(SOURCE_PC)?;
                let map = &prepared.prepared.manifest.source_map;
                assert_eq!(map.len(), 1);
                assert_eq!(map[0].0, SOURCE_PC);
                let native = std::fs::read(prepared.prepared.directory.join("native.bin"))?;
                let mut expected = MOV_RAX_IMMEDIATE.to_vec();
                expected.extend(SOURCE_PC.0.to_le_bytes());
                expected.push(MOV_EDX_IMMEDIATE);
                expected.extend((ExitKind::System as u32).to_le_bytes());
                expected.push(RETURN);
                assert_eq!(&native[map[0].1..], expected);
                let domain = std::sync::Arc::new(super::super::events::EventDomain::new());
                let mut backends = [event_backend(), event_backend()];
                for backend in &mut backends {
                    backend.event_endpoint = Some(domain.register(false, None).unwrap());
                    backend.event_domain = Some(std::sync::Arc::clone(&domain));
                }
                let mut system = state(false, false);
                let mut thread = ThreadState {
                    registers: registers(),
                    pc: SOURCE_PC,
                };
                let before = thread.registers.clone();
                // SAFETY: one trusted event instruction; the dispatcher performs no
                // guest RAM access.
                let outcome = unsafe {
                    runtime.run_with_system(
                        &mut thread,
                        Some(GuestAddress(SOURCE_PC.0 + INSTRUCTION_BYTES)),
                        1,
                        &mut Execution::new(ADDRESS_SPACE, &mut system, &mut backends[sender_pe]),
                    )?
                };
                assert_eq!(outcome.reason, StopReason::StopAddress);
                assert_eq!(
                    outcome.last_exit,
                    Some((SOURCE_PC.0, ExitKind::System as u64))
                );
                assert_eq!(thread.registers, before);
                assert_eq!(thread.pc, GuestAddress(SOURCE_PC.0 + INSTRUCTION_BYTES));
                for (pe, backend) in backends.iter().enumerate() {
                    assert_eq!(
                        backend.event_endpoint.as_ref().unwrap().is_set(),
                        word == SEV || pe == sender_pe
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_event_failure_preserves_original_terminal_and_completed_prefix() -> anyhow::Result<()>
    {
        use crate::blocks::{BlockRuntime, StopReason, ThreadState};
        use stela_compiler::block::BlockProfile;
        const ADD_X0_X0_ONE: u32 = 0x9100_0400;
        const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            cache.path().into(),
            BlockProfile::SystemV1,
        );
        runtime.register_code(
            SOURCE_PC,
            [ADD_X0_X0_ONE, SEVL]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        )?;
        let mut backend = BackendFixture::new();
        backend.expected_source_pc = SOURCE_PC.0 + INSTRUCTION_BYTES;
        let mut system = state(false, false);
        let mut thread = ThreadState {
            registers: registers(),
            pc: SOURCE_PC,
        };
        let mut expected = thread.registers.clone();
        expected.x[0] += 1;
        // SAFETY: trusted pure ADD prefix and event terminal, no guest RAM accesses.
        let outcome = unsafe {
            runtime.run_with_system(
                &mut thread,
                None,
                1,
                &mut Execution::new(ADDRESS_SPACE, &mut system, &mut backend),
            )?
        };
        let StopReason::SystemFailure {
            instruction,
            failure,
        } = outcome.reason
        else {
            panic!("expected exact System failure")
        };
        assert_eq!(instruction.word, SEVL);
        assert_eq!(
            instruction.instruction_pc,
            GuestAddress(SOURCE_PC.0 + INSTRUCTION_BYTES)
        );
        assert!(matches!(failure, Failure::Backend(_)));
        assert_eq!(thread.pc, instruction.instruction_pc);
        assert_eq!(thread.registers, expected);
        Ok(())
    }

    mod event_corpus {
        //! SEV/SEVL event delivery.
        mod backend {
            //! Test backend for event delivery.
            use crate::memory::{domain::MemoryThread, policy::MemoryControls};
            use crate::system::{
                access::{ExceptionLevel, Profile, SecurityState},
                events::{EventDomain, EventEndpoint, SendAttachment},
                exception::{Completion, EffectFailure, ExceptionServices, ServiceRequest},
                execution::{
                    Backend, Boundary, EntryBoundary, EntrySnapshot, SendEventServices, TagSnapshot,
                },
                state::{PSTATE_SS_MASK, SystemState},
            };
            use std::sync::Arc;
            use stela_compiler::{
                GuestAddress, GuestState,
                block::{BlockProfile, analyze_with_profile},
            };

            const INSTRUCTION_BYTES: usize = size_of::<u32>();

            pub(super) const NOP: u32 = 0xd503_201f;
            pub(super) const SEV: u32 = 0xd503_209f;
            pub(super) const SEVL: u32 = 0xd503_20bf;
            pub(super) const ADD_X0: u32 = 0x9100_0400;

            pub(super) struct EventBackend {
                pub domain: Arc<EventDomain>,
                pub endpoint: EventEndpoint,
                pub service_available: bool,
                expected_pc: GuestAddress,
                expected_word: u32,
                admitted_source: Option<(u64, u64, GuestAddress, GuestAddress, usize)>,
            }

            impl EventBackend {
                pub fn new(domain: Arc<EventDomain>, endpoint: EventEndpoint) -> Self {
                    Self {
                        domain,
                        endpoint,
                        service_available: true,
                        expected_pc: GuestAddress(0),
                        expected_word: 0,
                        admitted_source: None,
                    }
                }
                pub fn expect(&mut self, pc: GuestAddress, word: u32) {
                    self.expected_pc = pc;
                    self.expected_word = word;
                }
            }

            fn unavailable() -> EffectFailure<String> {
                EffectFailure {
                    error: "event corpus has no exception service".into(),
                    completion: Completion::None,
                }
            }

            impl ExceptionServices for EventBackend {
                type Permit = ();
                type Error = String;
                fn preflight(&mut self, _: ServiceRequest) -> Result<(), String> {
                    Err("event corpus has no exception service".into())
                }
                fn synchronize_context(
                    &mut self,
                    _: &mut (),
                    _: ExceptionLevel,
                ) -> Result<(), EffectFailure<String>> {
                    Err(unavailable())
                }
                fn clear_exclusive_local(
                    &mut self,
                    _: &mut (),
                ) -> Result<(), EffectFailure<String>> {
                    Err(unavailable())
                }
                fn send_event_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<String>> {
                    Err(unavailable())
                }
                fn branch_address(
                    &mut self,
                    _: &mut (),
                    _: u64,
                    _: ExceptionLevel,
                ) -> Result<u64, EffectFailure<String>> {
                    Err(unavailable())
                }
            }

            impl Backend for EventBackend {
                fn validate_entry(
                    &mut self,
                    boundary: &EntryBoundary,
                    source: &[u8],
                    system: &SystemState,
                    registers: &GuestState,
                ) -> Result<(), String> {
                    if system.current_el() != ExceptionLevel::El0 {
                        return Err("event corpus source profile requires own EL0".into());
                    }
                    if system.pstate(registers) & PSTATE_SS_MASK != 0 {
                        return Err("event corpus fixture does not support PSTATE.SS=1".into());
                    }
                    if source
                        .first_chunk::<INSTRUCTION_BYTES>()
                        .map(|x| u32::from_le_bytes(*x))
                        != Some(boundary.word())
                    {
                        return Err("entry source word mismatch".into());
                    }
                    let analysis =
                        analyze_with_profile(source, boundary.entry(), BlockProfile::SystemV1)
                            .map_err(|error| error.to_string())?;
                    let consumed = source
                        .get(..analysis.source_bytes)
                        .ok_or("invalid consumed extent")?;
                    for (index, bytes) in consumed
                        .as_chunks::<INSTRUCTION_BYTES>()
                        .0
                        .iter()
                        .enumerate()
                    {
                        let word = u32::from_le_bytes(*bytes);
                        if !matches!(word, NOP | ADD_X0 | SEV | SEVL) {
                            return Err("outside event corpus register/send source profile".into());
                        }
                        if matches!(word, SEV | SEVL)
                            && (index + 1) * INSTRUCTION_BYTES != consumed.len()
                        {
                            return Err("send must be the terminal".into());
                        }
                    }
                    self.admitted_source = Some((
                        boundary.address_space(),
                        boundary.generation(),
                        boundary.entry(),
                        boundary.region_base(),
                        boundary.source_bytes(),
                    ));
                    Ok(())
                }
                fn entry_snapshot(
                    &mut self,
                    _: &Boundary,
                    _: &SystemState,
                    _: &GuestState,
                ) -> Result<EntrySnapshot, String> {
                    Err("event corpus has no exception entry snapshot".into())
                }
                fn tag_snapshot(
                    &mut self,
                    _: &Boundary,
                    _: &SystemState,
                    _: &GuestState,
                ) -> Result<TagSnapshot, String> {
                    Err("event corpus has no tag service".into())
                }
                fn tag_memory(&mut self) -> Result<&mut MemoryThread<MemoryControls>, String> {
                    Err("event corpus has no memory service".into())
                }
                fn send_event_services(
                    &mut self,
                    boundary: &Boundary,
                    system: &SystemState,
                    _: &GuestState,
                ) -> Result<SendEventServices<'_>, String> {
                    let source = boundary.source();
                    let identity = (
                        source.address_space(),
                        source.generation(),
                        source.entry(),
                        source.region_base(),
                        source.source_bytes(),
                    );
                    let instruction = boundary.instruction();
                    if self.admitted_source != Some(identity)
                        || instruction.instruction_pc != self.expected_pc
                        || !instruction.matches_source(self.expected_pc, self.expected_word)
                    {
                        return Err("post-prefix event source identity differs".into());
                    }
                    if !self.service_available {
                        return Err(
                "event publication service explicitly unavailable after source validation".into(),
            );
                    }
                    if system.current_el() != ExceptionLevel::El0 {
                        return Err("current event source level differs".into());
                    }
                    let attachment = SendAttachment::new(&self.domain, &mut self.endpoint)
                        .map_err(|error| format!("{error:?}"))?;
                    Ok(SendEventServices {
                        profile: Profile {
                            current_el: ExceptionLevel::El0,
                            security: SecurityState::NonSecure,
                            el2_enabled: false,
                            el3_present: false,
                        },
                        attachment,
                    })
                }
            }
        }

        use crate::{
            blocks::{BlockRuntime, StopReason, ThreadState},
            system::{
                events::EventDomain,
                execution::{Execution, Failure},
            },
        };
        use anyhow::Result;
        use backend::{ADD_X0, EventBackend, SEVL};
        use std::sync::Arc;
        use stela_compiler::{GuestAddress, TargetCpu, block::BlockProfile};

        const ADDRESS_SPACE: u64 = 7;
        const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
        const TEST_PREFIX_PC: GuestAddress = GuestAddress(0x1000);

        fn backends() -> Result<[EventBackend; 2]> {
            let domain = Arc::new(EventDomain::new());
            let first = domain
                .register(false, None)
                .map_err(|e| anyhow::anyhow!("event register: {e:?}"))?;
            let second = domain
                .register(false, None)
                .map_err(|e| anyhow::anyhow!("event register: {e:?}"))?;
            Ok([
                EventBackend::new(Arc::clone(&domain), first),
                EventBackend::new(domain, second),
            ])
        }

        #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
        #[test]
        fn fixture_single_step_refusal_precedes_native_prefix_and_publication() -> Result<()> {
            use crate::system::state::{El1Registers, PSTATE_EL0T, PSTATE_SS_MASK, SystemState};
            use stela_compiler::GuestState;

            let cache = tempfile::tempdir()?;
            let mut runtime = BlockRuntime::new_for_target(
                ADDRESS_SPACE,
                cache.path().into(),
                BlockProfile::SystemV1,
                TargetCpu::Baseline,
            );
            runtime.register_code(
                TEST_PREFIX_PC,
                [ADD_X0, SEVL]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            )?;
            let mut owners = backends()?;
            owners[0].expect(GuestAddress(TEST_PREFIX_PC.0 + INSTRUCTION_BYTES), SEVL);
            let mut thread = ThreadState {
                registers: GuestState {
                    x: std::array::from_fn(|index| 0x1000 + index as u64),
                    sp: 0x4000,
                    nzcv: 0xa000_0000,
                    reserved: 0x1234_5678,
                    v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
                    fpcr: 0,
                    fpsr: 0x0800_0001,
                },
                pc: TEST_PREFIX_PC,
            };
            let mut system = SystemState::new(
                PSTATE_EL0T | PSTATE_SS_MASK,
                0x5000,
                El1Registers::new(0x2000, PSTATE_EL0T, 0, 0, 0x8000),
            )
            .map_err(|error| anyhow::anyhow!("single-step fixture state: {error:?}"))?;
            assert_ne!(system.pstate(&thread.registers) & PSTATE_SS_MASK, 0);
            assert!(owners[0].service_available);
            let original_registers = thread.registers.clone();
            let original_system = system.clone();
            let original_pc = thread.pc;
            let original_events = [owners[0].endpoint.is_set(), owners[1].endpoint.is_set()];
            // SAFETY: the fixture's SS check refuses before this code runs; no guest
            // RAM access is possible.
            let outcome = unsafe {
                runtime.run_with_system(
                    &mut thread,
                    None,
                    1,
                    &mut Execution::new(ADDRESS_SPACE, &mut system, &mut owners[0]),
                )?
            };
            assert!(matches!(
                outcome.reason,
                StopReason::SystemEntryFailure {
                    instruction_pc: TEST_PREFIX_PC,
                    word: ADD_X0,
                    failure: Failure::Backend(_),
                }
            ));
            assert_eq!(outcome.blocks_executed, 0);
            assert_eq!(thread.registers, original_registers);
            assert_eq!(system, original_system);
            assert_eq!(thread.pc, original_pc);
            assert_eq!(
                [owners[0].endpoint.is_set(), owners[1].endpoint.is_set()],
                original_events
            );
            assert_eq!(original_events, [false, false]);
            Ok(())
        }
    }
}
