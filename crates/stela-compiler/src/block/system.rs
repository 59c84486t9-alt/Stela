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
    /// Apple WKDMC and WKDMD, which compress and decompress a 16 KiB page
    /// through translated memory (`crate::wkdm`). Only the system-mode
    /// profile produces it.
    Compression(crate::wkdm::Instruction),
    /// Apple's M4 and later maintenance words. Only the system-mode profile
    /// produces it.
    AppleMaintenance(AppleMaintenance),
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

/// Apple GXF instructions, from Asahi Linux "SPRR and GXF" and "Apple
/// Proprietary Instructions" and m1n1 `gxf_asm.S` (`#define genter .long
/// 0x00201420`, `gexit .long 0x00201400`). They sit in the A64 reserved
/// space, so no other decoder claims them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedOperation {
    /// GENTER: enter the guarded level at GXF_ENTER_EL1. The immediate,
    /// bits 4:0 ("imm5 stored in ESR_GLx"), reaches ESR_GLx.
    Enter { immediate: u8 },
    /// GEXIT: return through ELR/SPSR/ASPSR of the guarded level.
    Exit,
}

pub const GENTER: u32 = 0x0020_1420;
pub const GEXIT: u32 = 0x0020_1400;
/// GENTER's immediate, bits 4:0.
const GENTER_IMMEDIATE: u32 = 0x1f;

impl GuardedOperation {
    pub const fn decode(word: u32) -> Option<Self> {
        if word & !GENTER_IMMEDIATE == GENTER {
            Some(Self::Enter {
                immediate: (word & GENTER_IMMEDIATE) as u8,
            })
        } else if word == GEXIT {
            Some(Self::Exit)
        } else {
            None
        }
    }
}

/// Apple maintenance words that the M4 and later 26A434 SPTMs execute at GL2
/// and no M1 to M3 SPTM, TXM or kernel holds. Operations 24 to 26 overlay
/// AMX's unallocated operations (`0x00201000 | op << 5 | Rt`), which the
/// runtime keeps for the chips without them. Only DC INCPA4K is named by a
/// public source; m1n1's SPTM emulator (`proxyclient/m1n1/hv/sprr.py`
/// `GXF_TLBI_ALL`, `GXF_TLBI_WITH_ARG`) flushes the TLB for `0x00201401` and
/// all of `0x00201300..0x0020133f`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleMaintenance {
    /// Operation 24, DC INCPA4K Xt: "Enable coprocessor cache flush" (XNU
    /// `H16.h`/`H17.h` `HAS_DC_INCPA`); `pmap_flush_noncoherent_page` issues
    /// `.long 0x201308` with x8 the physical address of each 4 KiB of a
    /// page, then DSB OSH (`osfmk/arm/pmap/pmap_data.c`), as SPTM does.
    CoprocessorCacheFlush { register: u8 },
    /// Operation 25: Rt holds a physical page number, `PA >> 12` with bits
    /// 1:0 clear, once per 16 KiB frame between DSB OSHNXS barriers after
    /// SPTM changes the frame's `/arm-io/sapt` entry.
    PhysicalPage { register: u8 },
    /// Operation 26 (from the M5): Rt holds the 16-bit address-space word
    /// of a pmap (ASID byte, generation byte), issued when the CPU's
    /// recorded generation for that ASID is stale.
    AddressSpace { register: u8 },
    /// `0x00201401`, without an operand: SPTM's choice in place of
    /// operation 25 when the page is 0 or a batch exceeds 63 pages.
    All,
}

const APPLE_MAINTENANCE_ALL: u32 = 0x0020_1401;
/// Operations 24, 25 and 26 with Rt 0; bits 4:0 are Rt.
const DC_INCPA4K: u32 = 0x0020_1300;
const APPLE_MAINTENANCE_PAGE: u32 = 0x0020_1320;
const APPLE_MAINTENANCE_ADDRESS_SPACE: u32 = 0x0020_1340;
const APPLE_MAINTENANCE_RT: u32 = 0x1f;

impl AppleMaintenance {
    pub const fn decode(word: u32) -> Option<Self> {
        if word == APPLE_MAINTENANCE_ALL {
            return Some(Self::All);
        }
        let register = (word & APPLE_MAINTENANCE_RT) as u8;
        match word & !APPLE_MAINTENANCE_RT {
            DC_INCPA4K => Some(Self::CoprocessorCacheFlush { register }),
            APPLE_MAINTENANCE_PAGE => Some(Self::PhysicalPage { register }),
            APPLE_MAINTENANCE_ADDRESS_SPACE => Some(Self::AddressSpace { register }),
            _ => None,
        }
    }
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
        SystemOperation::Compression(_) => "compression",
        SystemOperation::AppleMaintenance(_) => "apple_maintenance",
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
    decode_instruction(pc, word, synchronization::decode(word), false)
}

/// Decode the EL1 system instructions the platform completes. NOP, PAuth
/// aliases and other hints keep their existing decoding.
pub(super) fn decode_el1_system_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<SystemInstruction>, CompileError> {
    let sync = synchronization::decode(word);
    if let Some(instruction) = decode_instruction(pc, word, sync, false)? {
        return Ok(Some(instruction));
    }
    let Some(operation @ synchronization::Operation::DataCompletion { .. }) = sync else {
        return Ok(None);
    };
    request(pc, word, SystemOperation::Synchronization(operation)).map(Some)
}

/// Decode every instruction the system-mode profile hands to the runtime: the
/// [`decode_el1_system_instruction`] families, SYS/SYSL, and the barriers and
/// hints that the ordinary decoder does not own (DSB, SSBB/PSSBB, ESB,
/// TSB and unallocated hints), Apple's GXF instructions, SDSB, WKDMC and
/// WKDMD, the Debug-state-only MOVT GPR/ZT0 forms, and the FEAT_CPA pointer
/// arithmetic. YIELD, CSDB, SB and DMB stay ordinary and BTI compiles as NOP;
/// PAuth hints belong to the PAuth decoder, which the profile consults first.
pub fn decode_system_mode_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<SystemInstruction>, CompileError> {
    decode_system_mode_with_sync(pc, word, synchronization::decode(word))
}

pub(super) fn decode_system_mode_with_sync(
    pc: GuestAddress,
    word: u32,
    sync: Option<synchronization::Operation>,
) -> Result<Option<SystemInstruction>, CompileError> {
    decode_instruction(pc, word, sync, true)
}

fn decode_instruction(
    pc: GuestAddress,
    word: u32,
    sync: Option<synchronization::Operation>,
    system_mode: bool,
) -> Result<Option<SystemInstruction>, CompileError> {
    if !pc.0.is_multiple_of(INSTRUCTION_BYTES) {
        return Err(
            CompileError::new(crate::CompileErrorKind::MisalignedInstructionAddress)
                .at_instruction(pc, word),
        );
    }
    // Route by the fixed high byte of the encoding classes. Ordinary ALU,
    // branch and memory words outside these classes need no family probes.
    // The family decoders still own every fixed bit and operand check.
    let operation = match word >> 24 {
        0x00 => exception::decode(word)
            .map(SystemOperation::Exception)
            .or_else(|| {
                if !system_mode {
                    return None;
                }
                GuardedOperation::decode(word)
                    .map(SystemOperation::Guarded)
                    .or_else(|| {
                        AppleMaintenance::decode(word).map(SystemOperation::AppleMaintenance)
                    })
                    .or_else(|| decode_sdsb(word).map(SystemOperation::Synchronization))
                    .or_else(|| crate::wkdm::decode(word).map(SystemOperation::Compression))
            }),
        0x08 | 0x48 | 0x88 | 0xc8 if system_mode => {
            crate::aarch64::exclusive::decode(word).map(SystemOperation::Exclusive)
        }
        0x38 | 0x78 | 0xb8 | 0xf8 if system_mode => {
            // Reserved sizes and opcodes stay with the ordinary decoder.
            crate::aarch64::unprivileged::decode(word)
                .and_then(Result::ok)
                .map(SystemOperation::Unprivileged)
        }
        0x68 | 0x69 | 0xd9 => tag_memory::decode(word).map(SystemOperation::TagMemory),
        0x91 | 0xd1 if system_mode => match tag_arithmetic::decode(word) {
            Some(
                operand @ tag_arithmetic::Operand {
                    kind: tag_arithmetic::Kind::Offset { .. },
                    ..
                },
            ) => Some(SystemOperation::TagOffset(operand)),
            _ => None,
        },
        0x9a => tag_memory::decode(word)
            .map(SystemOperation::TagMemory)
            .or_else(|| {
                if system_mode {
                    decode_checked_pointer(word)
                } else {
                    None
                }
            }),
        0x9b | 0xda if system_mode => decode_checked_pointer(word),
        0xc0 if system_mode => {
            DebugStateOperation::decode(word).map(SystemOperation::DebugStateOnly)
        }
        0xd4 | 0xd6 => exception::decode(word).map(SystemOperation::Exception),
        0xd5 => decode_system_class(word, sync, system_mode)?,
        _ => None,
    };
    operation
        .map(|operation| request(pc, word, operation))
        .transpose()
}

fn decode_checked_pointer(word: u32) -> Option<SystemOperation> {
    crate::aarch64::checked_pointer::decode(word).map(SystemOperation::CheckedPointer)
}

/// Hints, barriers, CLREX, system registers, PSTATE and SYS/SYSL share 0xd5.
fn decode_system_class(
    word: u32,
    sync: Option<synchronization::Operation>,
    system_mode: bool,
) -> Result<Option<SystemOperation>, CompileError> {
    let terminal_sync = match sync {
        Some(synchronization::Operation::SendEvent { local }) => {
            Some(SystemOperation::SendEvent { local })
        }
        Some(synchronization::Operation::InstructionSynchronization { option }) => {
            Some(SystemOperation::InstructionSynchronization { option })
        }
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
        terminal_sync,
        registers::decode(word).map(SystemOperation::Register),
        registers::decode_pstate_immediate(word).map(SystemOperation::PstateImmediate),
    ]
    .into_iter()
    .flatten();
    if let Some(operation) = operations.next() {
        if operations.next().is_some() {
            return Err(CompileError::new(
                crate::CompileErrorKind::AmbiguousSystemInstruction,
            ));
        }
        return Ok(Some(operation));
    }
    if !system_mode {
        return Ok(None);
    }
    Ok(crate::aarch64::exclusive::decode(word)
        .map(SystemOperation::Exclusive)
        .or_else(|| registers::decode_sys(word).map(SystemOperation::Maintenance))
        .or(match sync {
            Some(
                operation @ (synchronization::Operation::DataCompletion { .. }
                | synchronization::Operation::StoreBypassBarrier { .. }
                | synchronization::Operation::ErrorSynchronization
                | synchronization::Operation::TraceSynchronization
                | synchronization::Operation::OtherHint { .. }),
            ) if word != NOP => Some(SystemOperation::Synchronization(operation)),
            _ => None,
        }))
}

fn request(
    pc: GuestAddress,
    word: u32,
    operation: SystemOperation,
) -> Result<SystemInstruction, CompileError> {
    let next_pc = GuestAddress(
        pc.0.checked_add(INSTRUCTION_BYTES)
            .ok_or_else(|| CompileError::new(crate::CompileErrorKind::GuestAddressOverflow))?,
    );
    Ok(SystemInstruction {
        instruction_pc: pc,
        next_pc,
        word,
        operation,
    })
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
mod tests;
