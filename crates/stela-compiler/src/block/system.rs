//! System instruction requests returned to the runtime.
//!
//! Native blocks return only the instruction's PC and exit kind; the runtime
//! re-decodes the source word before applying the effect.

use crate::{
    CompileError, GuestAddress,
    aarch64::{
        system::{exception, registers, synchronization},
        tag_arithmetic, tag_memory,
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
    /// ADDG and SUBG, whose tag depends on GCR_EL1.Exclude and Allocation
    /// Tag access, which the runtime holds. Only the system-mode profile
    /// produces it.
    TagOffset(tag_arithmetic::Operand),
    Register(registers::RegisterAccess),
    /// SYS/SYSL (op0=1): address translation, cache and TLB maintenance.
    /// Only the system-mode profile produces it.
    Maintenance(registers::RegisterAccess),
    /// Apple GXF guarded-level transitions. Only the system-mode profile
    /// produces it.
    Guarded(GuardedOperation),
    /// An instruction that exists only in Debug state, which a PE without
    /// halting debug never enters: UNDEFINED. Only the system-mode profile
    /// produces it.
    DebugStateOnly(DebugStateOperation),
    /// LDTR*/STTR*, which the runtime checks with EL0 permissions unless the
    /// access is privileged (Arm `AArch64_IsUnprivAccessPriv`). Only the
    /// system-mode profile produces it.
    Unprivileged(crate::aarch64::unprivileged::Operand),
    /// LDXR/STXR, their acquire/release and pair forms, and CLREX, which the
    /// runtime performs against the Exclusives monitors; the CONSTRAINED
    /// UNPREDICTABLE register overlaps take their UNDEFINED choice. Only the
    /// system-mode profile produces it.
    Exclusive(
        Result<crate::aarch64::exclusive::Operand, crate::aarch64::exclusive::ConstrainedUndefined>,
    ),
    /// ADDPT, SUBPT, MADDPT and MSUBPT (FEAT_CPA), which the runtime
    /// completes once it has admitted the form for its CPU. Only the
    /// system-mode profile produces it.
    CheckedPointer(crate::aarch64::checked_pointer::Operand),
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

/// Debug-state-only instructions outside the exception-generation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugStateOperation {
    /// MOVT Xt, ZT0[offs] (SME2), `0xc04c03e0` under `0xffff8fe0`.
    TableToGeneral,
    /// MOVT ZT0[offs], Xt (SME2), `0xc04e03e0` under `0xffff8fe0`.
    GeneralToTable,
}

const MOVT_GPR_MASK: u32 = 0xffff_8fe0;
const MOVT_TABLE_TO_GPR: u32 = 0xc04c_03e0;
const MOVT_GPR_TO_TABLE: u32 = 0xc04e_03e0;

impl DebugStateOperation {
    pub const fn decode(word: u32) -> Option<Self> {
        match word & MOVT_GPR_MASK {
            MOVT_TABLE_TO_GPR => Some(Self::TableToGeneral),
            MOVT_GPR_TO_TABLE => Some(Self::GeneralToTable),
            _ => None,
        }
    }
}

pub const GENTER: u32 = 0x0020_1420;
pub const GEXIT: u32 = 0x0020_1400;

/// Apple SDSB OSH, NSH, ISH and SY: `0x00201460` plus the domain (Asahi Linux
/// "Apple Proprietary Instructions"; iBoot and SPTM use SDSB ISH). How it
/// differs from DSB is not documented, so it decodes as the DSB of its
/// domain, whose completion it at least provides (inference).
const SDSB: u32 = 0x0020_1460;
/// DSB with CRm OSH, NSH, ISH and SY, in SDSB's domain order.
const SDSB_AS_DSB: [u32; 4] = [0xd503_339f, 0xd503_379f, 0xd503_3b9f, 0xd503_3f9f];

fn decode_sdsb(word: u32) -> Option<synchronization::Operation> {
    let domain = word.checked_sub(SDSB)? as usize;
    synchronization::decode(*SDSB_AS_DSB.get(domain)?)
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
        SystemOperation::TagOffset(_) => "tag_offset",
        SystemOperation::Register(_) => "system_register",
        SystemOperation::Maintenance(_) => "maintenance",
        SystemOperation::Guarded(_) => "guarded",
        SystemOperation::DebugStateOnly(_) => "debug_state_only",
        SystemOperation::Unprivileged(_) => "unprivileged",
        SystemOperation::Exclusive(_) => "exclusive",
        SystemOperation::CheckedPointer(_) => "checked_pointer",
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
/// hints that the ordinary decoder does not own (DSB, SSBB/PSSBB, ESB,
/// TSB and unallocated hints), Apple's SDSB, the Debug-state-only MOVT
/// GPR/ZT0 forms, and
/// the FEAT_CPA pointer arithmetic.
/// YIELD, CSDB, SB and DMB stay ordinary and BTI compiles as NOP; PAuth hints belong to the PAuth
/// decoder, which the profile consults first.
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
    } else if let Some(operation) = decode_sdsb(word) {
        SystemOperation::Synchronization(operation)
    } else if let Some(operation) = DebugStateOperation::decode(word) {
        SystemOperation::DebugStateOnly(operation)
    } else if let Some(decoded) = crate::aarch64::exclusive::decode(word) {
        SystemOperation::Exclusive(decoded)
    } else if let Some(operand) = crate::aarch64::checked_pointer::decode(word) {
        SystemOperation::CheckedPointer(operand)
    } else if let Some(
        operand @ tag_arithmetic::Operand {
            kind: tag_arithmetic::Kind::Offset { .. },
            ..
        },
    ) = tag_arithmetic::decode(word)
    {
        SystemOperation::TagOffset(operand)
    } else if let Some(decoded) = crate::aarch64::unprivileged::decode(word) {
        // Reserved sizes and opcodes stay with the ordinary decoder.
        match decoded {
            Ok(operand) => SystemOperation::Unprivileged(operand),
            Err(()) => return Ok(None),
        }
    } else if let Some(access) = registers::decode_sys(word) {
        SystemOperation::Maintenance(access)
    } else {
        match synchronization::decode(word) {
            Some(
                operation @ (synchronization::Operation::DataCompletion { .. }
                | synchronization::Operation::StoreBypassBarrier { .. }
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
    fn system_mode_decodes_apple_sdsb_as_the_dsb_of_its_domain() {
        let pc = GuestAddress(0x1000);
        for (domain, dsb) in SDSB_AS_DSB.into_iter().enumerate() {
            let instruction = decode_system_mode_instruction(pc, SDSB + domain as u32)
                .unwrap()
                .unwrap();
            assert_eq!(
                instruction.operation,
                SystemOperation::Synchronization(synchronization::decode(dsb).unwrap())
            );
        }
        assert!(
            decode_system_mode_instruction(pc, SDSB + 4)
                .unwrap()
                .is_none()
        );
        assert!(
            decode_system_mode_instruction(pc, SDSB - 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn system_mode_claims_debug_state_only_movt_and_nothing_beside_it() {
        let pc = GuestAddress(0x1000);
        for (word, operation) in [
            (0xc04c_03e0, DebugStateOperation::TableToGeneral),
            (0xc04c_73fe, DebugStateOperation::TableToGeneral),
            (0xc04e_03e0, DebugStateOperation::GeneralToTable),
            (0xc04e_73ff, DebugStateOperation::GeneralToTable),
        ] {
            let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
            assert_eq!(
                instruction.operation,
                SystemOperation::DebugStateOnly(operation)
            );
            assert!(decode_system_instruction(pc, word).unwrap().is_none());
        }
        // MOVT (vector to table), and the fixed bits 15 and 9..5, are not it.
        for word in [0xc04f_03e0, 0xc04c_83e0, 0xc04c_03c0, 0xc04d_03e0] {
            assert!(decode_system_mode_instruction(pc, word).unwrap().is_none());
        }
    }

    #[test]
    fn system_mode_claims_cpa_arithmetic_with_its_operands() {
        use crate::aarch64::{
            Register,
            checked_pointer::{Kind, Operand},
        };
        let pc = GuestAddress(0x1000);
        // ADDPT X0, X1, X2, LSL #3; SUBPT SP, SP, X2; MADDPT; MSUBPT.
        for word in [0x9a02_2c20, 0xda02_23ff, 0x9b62_1023, 0x9b62_9025] {
            let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
            assert!(
                matches!(instruction.operation, SystemOperation::CheckedPointer(_)),
                "{word:#x}"
            );
            assert_eq!(instruction.next_pc, GuestAddress(0x1004));
        }
        assert_eq!(
            decode_system_mode_instruction(pc, 0xda02_23ff)
                .unwrap()
                .unwrap()
                .operation,
            SystemOperation::CheckedPointer(Operand {
                destination: Register::Sp,
                kind: Kind::Offset {
                    base: Register::Sp,
                    offset: Register::X(2),
                    amount: 0,
                    subtract: true,
                },
            })
        );
        // Ordinary ADD (shifted register) is not claimed.
        assert!(
            decode_system_mode_instruction(pc, 0x8b02_0c20)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn system_mode_claims_exclusives_and_their_undefined_overlaps() {
        use crate::aarch64::exclusive::{ConstrainedUndefined, Operand};
        let pc = GuestAddress(0x1000);
        // LDXR X1, [X2]; STXR W3, X1, [X2]; LDAXP X1, X4, [X2]; CLREX.
        for word in [0xc85f_7c41, 0xc803_7c41, 0xc87f_9041, 0xd503_305f] {
            let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
            assert!(
                matches!(instruction.operation, SystemOperation::Exclusive(Ok(_))),
                "{word:#x}"
            );
        }
        assert!(matches!(
            decode_system_mode_instruction(pc, 0xd503_305f)
                .unwrap()
                .unwrap()
                .operation,
            SystemOperation::Exclusive(Ok(Operand::Clear))
        ));
        // STXR W1, X1, [X2]: the status register overlaps the data.
        assert_eq!(
            decode_system_mode_instruction(pc, 0xc801_7c41)
                .unwrap()
                .unwrap()
                .operation,
            SystemOperation::Exclusive(Err(ConstrainedUndefined::StoreStatusData))
        );
    }

    #[test]
    fn system_mode_claims_unprivileged_transfers_but_not_reserved_forms() {
        let pc = GuestAddress(0x1000);
        // LDTR X1, [X2, #8]; STTR W1, [X2]; LDTRSB W3, [X2].
        for word in [0xf840_8841, 0xb800_0841, 0x38c0_0843] {
            let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
            assert!(
                matches!(instruction.operation, SystemOperation::Unprivileged(_)),
                "{word:#x}"
            );
            assert!(decode_system_instruction(pc, word).unwrap().is_none());
        }
        // LDTRSW into W and LDTRSB/H/W into X from a doubleword are reserved.
        for word in [0xb8c0_0843, 0xf880_0843] {
            assert!(decode_system_mode_instruction(pc, word).unwrap().is_none());
        }
    }

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
    fn system_mode_claims_completion_barriers_and_unallocated_hints_only() {
        let pc = GuestAddress(0x1000);
        // DSB SY, DSB ISHST, ISB, SSBB, PSSBB and the unallocated HINT #0x54
        // and #0x7f exit to the engine.
        for word in [
            0xd503_3f9f,
            0xd503_3a9f,
            0xd503_3fdf,
            0xd503_309f,
            0xd503_349f,
            0xd503_2a9f,
            0xd503_2fff,
        ] {
            assert!(
                decode_system_mode_instruction(pc, word).unwrap().is_some(),
                "{word:#x}"
            );
        }
        // DMB ISH, NOP, YIELD, CSDB and SB stay with the ordinary decoder.
        for word in [0xd503_3bbf, NOP, 0xd503_203f, 0xd503_229f, 0xd503_30ff] {
            assert!(
                decode_system_mode_instruction(pc, word).unwrap().is_none(),
                "{word:#x}"
            );
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
