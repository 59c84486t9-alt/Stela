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

const INSTRUCTION_BYTES: u64 = std::mem::size_of::<u32>() as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemOperation {
    Exception(exception::Operation),
    TagMemory(tag_memory::Operand),
    Register(registers::RegisterAccess),
    PstateImmediate(registers::Encoding),
    SendEvent { local: bool },
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
        SystemOperation::TagMemory(_) => "tag_memory",
        SystemOperation::Register(_) => "system_register",
        SystemOperation::PstateImmediate(_) => "pstate_immediate",
        SystemOperation::SendEvent { .. } => "event",
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
    let mut operations = [
        exception::decode(word).map(SystemOperation::Exception),
        tag_memory::decode(word).map(SystemOperation::TagMemory),
        event.map(|local| SystemOperation::SendEvent { local }),
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

impl SystemInstruction {
    /// The runtime supplies a word fetched from its immutable registered region.
    /// A public descriptor cannot substitute different typed operands or a PC.
    pub fn matches_source(self, pc: GuestAddress, word: u32) -> bool {
        self.instruction_pc == pc
            && self.word == word
            && decode_system_instruction(pc, word).ok().flatten() == Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVC: u32 = 0xd400_0001;
    const ERET: u32 = 0xd69f_03e0;
    const IRG: u32 = 0x9ac0_1000;
    const LDG: u32 = 0xd960_0000;
    const STG: u32 = 0xd920_0800;
    const STGP: u32 = 0x6900_0000;
    const SEV: u32 = 0xd503_209f;
    const SEVL: u32 = 0xd503_20bf;
    const WFE: u32 = 0xd503_205f;
    const WFI: u32 = 0xd503_207f;
    const WFET: u32 = 0xd503_1000;
    const WFIT: u32 = 0xd503_1020;
    const NOP: u32 = 0xd503_201f;
    const ADD_IMMEDIATE: u32 = 0x9100_0000;
    const RET: u32 = 0xd65f_03c0;
    const UNALLOCATED: u32 = 0xffff_ffff;

    #[test]
    fn system_requests_preserve_exact_instruction_identity() {
        let pc = GuestAddress(0x1000);
        for word in [SVC, ERET, IRG, LDG, STG, STGP, SEV, SEVL] {
            let instruction = decode_system_instruction(pc, word).unwrap().unwrap();
            assert_eq!(instruction.instruction_pc, pc);
            assert_eq!(instruction.next_pc, GuestAddress(pc.0 + INSTRUCTION_BYTES));
            assert!(instruction.matches_source(pc, word));
            assert!(!instruction.matches_source(GuestAddress(pc.0 + INSTRUCTION_BYTES), word));
            assert!(!instruction.matches_source(pc, word ^ 1));
            let mut forged = instruction;
            forged.next_pc = pc;
            assert!(!forged.matches_source(pc, word));
        }
    }

    #[test]
    fn unrelated_words_do_not_become_runtime_system_requests() {
        for word in [NOP, ADD_IMMEDIATE, RET, UNALLOCATED, WFE, WFI, WFET, WFIT] {
            assert!(
                decode_system_instruction(GuestAddress(0x1000), word)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(decode_system_instruction(GuestAddress(0x1001), IRG).is_err());
        assert!(decode_system_instruction(GuestAddress(u64::MAX - 3), IRG).is_err());
    }
}
