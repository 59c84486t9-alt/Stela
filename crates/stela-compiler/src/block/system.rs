//! System instruction requests returned to the runtime.
//!
//! Native blocks return only the instruction's PC and exit kind; the runtime
//! re-decodes the source word before applying the effect.

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
    /// The effect to apply; the runtime decides whether it is admitted.
    Synchronization(synchronization::Operation),
    TagMemory(tag_memory::Operand),
    Register(registers::RegisterAccess),
    /// SYS/SYSL (op0=1): address translation, cache and TLB maintenance.
    /// Only the system-mode profile produces it.
    Maintenance(registers::RegisterAccess),
    /// Apple GXF guarded-level transitions. Only the system-mode profile
    /// produces it.
    Guarded(GuardedOperation),
    PstateImmediate(registers::Encoding),
    SendEvent {
        local: bool,
    },
    InstructionSynchronization {
        option: u8,
    },
    Wait {
        kind: synchronization::WaitKind,
        timeout_register: Option<u8>,
    },
}

/// Apple GXF instructions, exact words from Asahi Linux "SPRR and GXF" and
/// m1n1 `gxf_asm.S` (`#define genter .long 0x00201420`, `gexit .long
/// 0x00201400`). They sit in the A64 reserved space, so no other decoder
/// claims them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedOperation {
    /// GENTER: enter the guarded level at GXF_ENTER_EL1.
    Enter,
    /// GEXIT: return through ELR/SPSR/ASPSR of the guarded level.
    Exit,
}

pub const GENTER: u32 = 0x0020_1420;
pub const GEXIT: u32 = 0x0020_1400;

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
        SystemOperation::Maintenance(_) => "maintenance",
        SystemOperation::Guarded(_) => "guarded",
        SystemOperation::PstateImmediate(_) => "pstate_immediate",
        SystemOperation::SendEvent { .. } => "event",
        SystemOperation::InstructionSynchronization { .. } => "instruction_synchronization",
        SystemOperation::Wait { .. } => "wait",
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
    let wait = match synchronization::decode(word) {
        Some(synchronization::Operation::Wait {
            kind,
            timeout_register,
        }) => Some(SystemOperation::Wait {
            kind,
            timeout_register,
        }),
        _ => None,
    };
    let mut operations = [
        exception::decode(word).map(SystemOperation::Exception),
        tag_memory::decode(word).map(SystemOperation::TagMemory),
        event.map(|local| SystemOperation::SendEvent { local }),
        instruction_synchronization,
        wait,
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

/// Decode the EL1 system instructions the platform completes. NOP, PAuth
/// aliases and other hints keep their existing decoding.
pub(super) fn decode_el1_system_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<SystemInstruction>, CompileError> {
    if let Some(instruction) = decode_system_instruction(pc, word)? {
        return Ok(Some(instruction));
    }
    let Some(operation @ synchronization::Operation::DataCompletion { .. }) =
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

/// Decode every instruction the system-mode profile hands to the runtime: the
/// [`decode_el1_system_instruction`] families, SYS/SYSL, and the barriers and
/// hints that the ordinary decoder does not own (DSB, SSBB/PSSBB, BTI, ESB,
/// TSB and unallocated hints). YIELD, CSDB, SB and DMB stay ordinary; PAuth
/// hints belong to the PAuth decoder, which the profile consults first.
pub fn decode_system_mode_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<SystemInstruction>, CompileError> {
    if let Some(instruction) = decode_system_instruction(pc, word)? {
        return Ok(Some(instruction));
    }
    let operation = if word == GENTER {
        SystemOperation::Guarded(GuardedOperation::Enter)
    } else if word == GEXIT {
        SystemOperation::Guarded(GuardedOperation::Exit)
    } else if let Some(access) = registers::decode_sys(word) {
        SystemOperation::Maintenance(access)
    } else {
        match synchronization::decode(word) {
            Some(
                operation @ (synchronization::Operation::DataCompletion { .. }
                | synchronization::Operation::StoreBypassBarrier { .. }
                | synchronization::Operation::BranchTarget { .. }
                | synchronization::Operation::ErrorSynchronization
                | synchronization::Operation::TraceSynchronization
                | synchronization::Operation::OtherHint { .. }),
            ) if word != NOP => SystemOperation::Synchronization(operation),
            _ => return Ok(None),
        }
    };
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

const NOP: u32 = 0xd503_201f;

impl SystemInstruction {
    pub fn is_el1_ram_completion(self) -> bool {
        matches!(
            self.operation,
            SystemOperation::Synchronization(synchronization::Operation::DataCompletion { .. })
        )
    }

    /// Whether this operation needs the EL1 platform context.
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
    fn context_carriers_preserve_exact_operands_without_granting_other_families() {
        let pc = GuestAddress(0x1000);
        let isb = 0xd5033fdf;
        let instruction = decode_system_instruction(pc, isb).unwrap().unwrap();
        assert_eq!(
            instruction.operation,
            SystemOperation::InstructionSynchronization { option: 15 }
        );
        assert!(instruction.matches_source(pc, isb));
        assert!(!instruction.matches_source(pc, isb ^ (1 << 8)));
        assert!(instruction.is_el1_context_operation());
        for encoding in [
            registers::SCTLR_EL1,
            registers::TCR_EL1,
            registers::TTBR0_EL1,
            registers::TTBR1_EL1,
            registers::MAIR_EL1,
        ] {
            for base in [0xd5200000u32, 0xd5000000] {
                for rt in [0, 30, 31] {
                    let word = base | (u32::from(encoding.selector()) << 5) | rt;
                    let instruction = decode_system_instruction(pc, word).unwrap().unwrap();
                    assert!(instruction.matches_source(pc, word));
                    assert!(instruction.is_el1_context_operation());
                    let SystemOperation::Register(access) = instruction.operation else {
                        panic!("register carrier")
                    };
                    assert_eq!(access.encoding(), encoding);
                    assert_eq!(access.rt(), rt as u8);
                }
            }
        }
        for word in [SVC, ERET, 0xd4202460, 0x00001234] {
            assert!(
                decode_system_instruction(pc, word)
                    .unwrap()
                    .unwrap()
                    .is_el1_context_operation()
            );
        }
        for word in [
            0xd69f0bff, 0xd69f0fff, 0xd4000002, 0xd4000003, SEV, SEVL, IRG,
        ] {
            assert!(
                !decode_system_instruction(pc, word)
                    .unwrap()
                    .unwrap()
                    .is_el1_context_operation()
            );
        }
    }

    #[test]
    fn wait_carriers_retain_kind_and_timeout_register_from_decoder() {
        use synchronization::WaitKind;
        for (word, kind, timeout_register) in [
            (WFE, WaitKind::Event, None),
            (WFI, WaitKind::Interrupt, None),
            (WFET | 30, WaitKind::Event, Some(30)),
            (WFIT | 31, WaitKind::Interrupt, Some(31)),
        ] {
            let pc = GuestAddress(0x1000);
            let instruction = decode_system_instruction(pc, word).unwrap().unwrap();
            assert_eq!(
                instruction.operation,
                SystemOperation::Wait {
                    kind,
                    timeout_register
                }
            );
            assert!(instruction.matches_source(pc, word));
            assert!(!instruction.is_el1_context_operation());
            let analysis = super::super::analyze_with_profile(
                &word.to_le_bytes(),
                pc,
                super::super::BlockProfile::El1PlatformV1,
            )
            .unwrap();
            assert_eq!(
                analysis.static_successors,
                alloc::vec![super::super::StaticSuccessor {
                    kind: super::super::SuccessorKind::Fallthrough,
                    target: instruction.next_pc,
                }]
            );
        }
    }

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
        for word in [NOP, ADD_IMMEDIATE, RET, UNALLOCATED] {
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
