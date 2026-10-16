//! Exact source-bound requests at the shared system runtime boundary.
//!
//! These Rust descriptors never cross the native ABI. Native blocks return only
//! the original instruction PC and System exit kind. Reports retain the source
//! word and operation family; runtime recovery must revalidate both typed operands
//! and source identity before applying architectural effects. Immutable source
//! extent and generation validation belongs to the registered runtime owner.

use crate::{
    CompileError, GuestAddress,
    aarch64::{
        system::{exception, registers, synchronization},
        tag_memory,
    },
};
use serde::{Serialize, Serializer};

const INSTRUCTION_BYTES: u64 = core::mem::size_of::<u32>() as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemOperation {
    Exception(exception::Operation),
    /// Canonical effect description; the actual retained owner grants admission.
    Synchronization(synchronization::Operation),
    TagMemory(tag_memory::Operand),
    Register(registers::RegisterAccess),
    PstateImmediate(registers::Encoding),
    SendEvent {
        local: bool,
    },
    InstructionSynchronization {
        option: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SystemInstruction {
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
    pub word: u32,
    #[serde(rename = "family", serialize_with = "serialize_family")]
    pub operation: SystemOperation,
}

fn serialize_family<S: Serializer>(
    operation: &SystemOperation,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(match operation {
        SystemOperation::Exception(_) => "exception",
        SystemOperation::Synchronization(_) => "synchronization",
        SystemOperation::TagMemory(_) => "tag_memory",
        SystemOperation::Register(_) => "system_register",
        SystemOperation::PstateImmediate(_) => "pstate_immediate",
        SystemOperation::SendEvent { .. } => "event",
        SystemOperation::InstructionSynchronization { .. } => "instruction_synchronization",
    })
}

pub fn decode_system_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<SystemInstruction>, CompileError> {
    if !pc.0.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(CompileError(
            "system instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    let event = match synchronization::decode(word) {
        Some(synchronization::Operation::SendEvent { local }) => Some(local),
        _ => None,
    };
    let instruction_synchronization = match synchronization::decode(word) {
        Some(synchronization::Operation::InstructionSynchronization { option }) => {
            Some(SystemOperation::InstructionSynchronization { option })
        }
        _ => None,
    };
    let mut operations = [
        exception::decode(word).map(SystemOperation::Exception),
        tag_memory::decode(word).map(SystemOperation::TagMemory),
        event.map(|local| SystemOperation::SendEvent { local }),
        instruction_synchronization,
        registers::decode(word).map(SystemOperation::Register),
        registers::decode_pstate_immediate(word).map(SystemOperation::PstateImmediate),
    ]
    .into_iter()
    .flatten();
    let Some(operation) = operations.next() else {
        return Ok(None);
    };
    if operations.next().is_some() {
        return Err(CompileError("ambiguous system instruction family".into()));
    }
    let next_pc = GuestAddress(pc.0.checked_add(INSTRUCTION_BYTES).ok_or_else(|| {
        CompileError("system continuation PC overflows guest address range".into())
    })?);
    Ok(Some(SystemInstruction {
        instruction_pc: pc,
        next_pc,
        word,
        operation,
    }))
}

/// Extend the fixed EL1 cohort only for its actual mounted RAM completion.
/// Existing NOP, PAuth aliases and unmounted hints keep their original selection.
pub(super) fn decode_el1_system_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<SystemInstruction>, CompileError> {
    if let Some(instruction) = decode_system_instruction(pc, word)? {
        return Ok(Some(instruction));
    }
    let Some(operation @ synchronization::Operation::DataCompletion { nxs: false, .. }) =
        synchronization::decode(word)
    else {
        return Ok(None);
    };
    let next_pc = GuestAddress(pc.0.checked_add(INSTRUCTION_BYTES).ok_or_else(|| {
        CompileError("system continuation PC overflows guest address range".into())
    })?);
    Ok(Some(SystemInstruction {
        instruction_pc: pc,
        next_pc,
        word,
        operation: SystemOperation::Synchronization(operation),
    }))
}

impl SystemInstruction {
    pub fn is_el1_ram_completion(self) -> bool {
        matches!(
            self.operation,
            SystemOperation::Synchronization(synchronization::Operation::DataCompletion {
                nxs: false,
                ..
            })
        )
    }

    /// Source classification only. This grants no PE/control/publication loan.
    /// The actual lifetime-fixed platform must mount the corresponding owner.
    pub fn is_el1_context_operation(self) -> bool {
        match self.operation {
            SystemOperation::Register(access) => {
                registers::is_translation_control(access.encoding())
            }
            SystemOperation::InstructionSynchronization { .. } => true,
            SystemOperation::Exception(
                exception::Operation::SupervisorCall { .. }
                | exception::Operation::SoftwareBreakpoint { .. }
                | exception::Operation::Undefined { .. }
                | exception::Operation::ExceptionReturn { key: None },
            ) => true,
            _ => false,
        }
    }

    /// The runtime supplies a word fetched from its immutable registered region.
    /// A public descriptor cannot substitute different typed operands or a PC.
    pub fn matches_source(self, pc: GuestAddress, word: u32) -> bool {
        self.instruction_pc == pc
            && self.word == word
            && decode_el1_system_instruction(pc, word).ok().flatten() == Some(self)
    }
}

#[cfg(test)]
mod tests;
