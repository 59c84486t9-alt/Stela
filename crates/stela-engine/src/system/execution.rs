//! Completing system-instruction exits after native return.

#[cfg(not(feature = "std"))]
use alloc::string::String;

use super::events::DomainError;
use crate::memory::{tag_execution::RandomTagFault, tag_transfer};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use stela_compiler::{
    GuestAddress, GuestState, block::system::SystemInstruction, context::memory::MemoryStatus,
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
    #[cfg(feature = "std")]
    fn prepare_memory_entry<'run>(
        &'run mut self,
        _boundary: &EntryBoundary,
        _source: &[u8],
        _requirements: stela_compiler::context::memory::MemoryRequirements,
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
}
