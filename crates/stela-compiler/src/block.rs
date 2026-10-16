//! Basic-block translation.
//!
//! Native entry is System V `BlockExit function(GuestState *state)`. Emitted code
//! never jumps to a guest PC: every control-flow change exits to the dispatcher.
//! SVC and BRK exit at a synchronous-trap boundary. PAC instructions call a
//! runtime helper when software PAuth is enabled.

use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock,
    aarch64::{Decoder, Instruction, Operation, Register},
};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use serde::Serialize;

pub mod el1_m0;
pub mod el1_platform;
pub mod loop_budget;
pub mod memory;
pub mod pauth_lr;
pub mod pauth_memory;
pub use memory::{
    CHECKED_POINTER_PROCESS_MEMORY_PROFILE_ID, CheckedMemoryProfile,
    ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
};
pub mod system;
pub use system::{SystemInstruction, decode_system_instruction};
pub mod scalable;
mod thread;
pub use thread::{ThreadRegisterInstruction, decode_thread_register_instruction};

const NOP_ENCODING: u32 = 0xd503_201f;

/// Separate from the leaf ABI: RAX/RDX return the next guest PC and exit kind.
pub const BLOCK_ABI: &str = "x86_64-sysv-guest-state-v2-block-exit-direct-ram";
/// The block ABI with software PAuth helper exits. Keys and the PAuth version
/// are chosen at run time, so cached code contains neither.
pub const PAUTH_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-v1";
pub const CLOCK_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-clock-v1";

pub const THREAD_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-darwin-arm64-thread-v1";
pub const PAUTH_THREAD_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-thread-v1";
pub const CLOCK_THREAD_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-clock-thread-v1";

/// Restricted context-independent prefixes and checked System runtime exits.
/// This identifies a service boundary, not CPU feature availability.
pub const SYSTEM_BLOCK_ABI: &str = "x86_64-sysv-guest-state-v2-block-exit-system-v1";
pub const SYSTEM_REGISTER_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-system-registers-v1";
pub const EL1_PLATFORM_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v3-context-block-exit-el1-platform-v1";

/// Blocks of exactly one B (immediate) at EL1.
pub const EL1_DIRECT_BRANCH_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-el1-direct-branch-v1";
/// Context ABI for EL1 integer blocks with the MMU off. Literal reads go
/// through a staged RAM callback.
pub const EL1_M0_INTEGER_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v3-context-block-exit-el1-m0-integer-v1";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockProfile {
    #[default]
    Ordinary,
    /// Direct RAM, with non-faulting self-loops kept resident.
    OrdinaryResidentV1,
    El1DirectBranchV1,
    El1M0IntegerV1,
    El1PlatformV1,
    CheckedMemory(CheckedMemoryProfile),
    /// Checked memory plus the existing serialized PAC/clock/thread helpers.
    /// The immutable ABI keeps every cache entry distinct from direct RAM.
    CheckedMemoryPauthClockThread(CheckedMemoryProfile),
    SystemV1,
    SystemRegistersV1,
    AppleArm64eSoftwarePauthV1,
    AppleArm64eSoftwarePauthClockV1,
    DarwinArm64ThreadV1,
    AppleArm64eSoftwarePauthThreadV1,
    AppleArm64eSoftwarePauthClockThreadV1,
}

impl BlockProfile {
    pub const fn abi(self) -> &'static str {
        match self {
            Self::Ordinary => BLOCK_ABI,
            Self::OrdinaryResidentV1 => loop_budget::RESIDENT_BLOCK_ABI,
            Self::El1DirectBranchV1 => EL1_DIRECT_BRANCH_BLOCK_ABI,
            Self::El1M0IntegerV1 => EL1_M0_INTEGER_BLOCK_ABI,
            Self::El1PlatformV1 => EL1_PLATFORM_BLOCK_ABI,
            Self::CheckedMemory(profile) => profile.abi(),
            Self::CheckedMemoryPauthClockThread(profile) => profile.process_helpers_abi(),
            Self::SystemV1 => SYSTEM_BLOCK_ABI,
            Self::SystemRegistersV1 => SYSTEM_REGISTER_BLOCK_ABI,
            Self::AppleArm64eSoftwarePauthV1 => PAUTH_BLOCK_ABI,
            Self::AppleArm64eSoftwarePauthClockV1 => CLOCK_BLOCK_ABI,
            Self::DarwinArm64ThreadV1 => THREAD_BLOCK_ABI,
            Self::AppleArm64eSoftwarePauthThreadV1 => PAUTH_THREAD_BLOCK_ABI,
            Self::AppleArm64eSoftwarePauthClockThreadV1 => CLOCK_THREAD_BLOCK_ABI,
        }
    }

    pub const fn supports_resident_loops(self) -> bool {
        matches!(self, Self::OrdinaryResidentV1)
    }

    pub const fn checked_memory(self) -> Option<CheckedMemoryProfile> {
        match self {
            Self::CheckedMemory(profile) | Self::CheckedMemoryPauthClockThread(profile) => {
                Some(profile)
            }
            _ => None,
        }
    }

    pub const fn supports_checked_process_helpers(self) -> bool {
        matches!(self, Self::CheckedMemoryPauthClockThread(_))
    }

    pub const fn supports_system(self) -> bool {
        matches!(
            self,
            Self::SystemV1 | Self::SystemRegistersV1 | Self::El1PlatformV1
        )
    }

    pub const fn supports_system_registers(self) -> bool {
        matches!(self, Self::SystemRegistersV1 | Self::El1PlatformV1)
    }

    pub const fn supports_pointer_authentication(self) -> bool {
        matches!(
            self,
            Self::AppleArm64eSoftwarePauthV1
                | Self::AppleArm64eSoftwarePauthClockV1
                | Self::AppleArm64eSoftwarePauthThreadV1
                | Self::AppleArm64eSoftwarePauthClockThreadV1
                | Self::CheckedMemoryPauthClockThread(_)
        )
    }

    pub const fn supports_clock(self) -> bool {
        matches!(
            self,
            Self::AppleArm64eSoftwarePauthClockV1
                | Self::AppleArm64eSoftwarePauthClockThreadV1
                | Self::CheckedMemoryPauthClockThread(_)
        )
    }

    pub const fn supports_thread_registers(self) -> bool {
        matches!(
            self,
            Self::DarwinArm64ThreadV1
                | Self::AppleArm64eSoftwarePauthThreadV1
                | Self::AppleArm64eSoftwarePauthClockThreadV1
                | Self::CheckedMemoryPauthClockThread(_)
        )
    }
}
/// Maximum input window; a terminator can consume a shorter prefix.
pub const MAX_BLOCK_INSTRUCTIONS: usize = 256;

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    Fallthrough = 0,
    Direct = 1,
    Indirect = 2,
    Call = 3,
    Return = 4,
    Trap = 5,
    PointerAuthentication = 6,
    Clock = 7,
    ThreadRegister = 8,
    FloatingPoint = 9,
    ScalableNumerical = 10,
    System = 11,
}

impl TryFrom<u64> for ExitKind {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Fallthrough),
            1 => Ok(Self::Direct),
            2 => Ok(Self::Indirect),
            3 => Ok(Self::Call),
            4 => Ok(Self::Return),
            5 => Ok(Self::Trap),
            6 => Ok(Self::PointerAuthentication),
            7 => Ok(Self::Clock),
            8 => Ok(Self::ThreadRegister),
            9 => Ok(Self::FloatingPoint),
            10 => Ok(Self::ScalableNumerical),
            11 => Ok(Self::System),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClockOperation {
    ReadVirtualCounter { destination: u8 },
    InstructionSynchronization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClockInstruction {
    pub operation: ClockOperation,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

/// Only ISB SY and MRS CNTVCT_EL0 (X31 discards). Other counter registers and
/// barrier options are refused; both need the clock service.
pub fn decode_clock_instruction(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<ClockInstruction>, CompileError> {
    if !pc.0.is_multiple_of(4) {
        return Err(CompileError(
            "clock instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    let operation = if word == 0xd5033fdf {
        ClockOperation::InstructionSynchronization
    } else if word & 0xffffffe0 == 0xd53be040 {
        ClockOperation::ReadVirtualCounter {
            destination: (word & 31) as u8,
        }
    } else {
        return Ok(None);
    };
    Ok(Some(ClockInstruction {
        operation,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0.checked_add(4).ok_or_else(|| {
            CompileError("clock continuation PC overflows guest address range".into())
        })?),
    }))
}

/// Separate compiler-side key selector; never contains process key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PointerAuthenticationKey {
    Ia,
    Ib,
    Da,
    Db,
}

/// Register31 is SP only in the two-operand modifier field. The distinct Z
/// encoding denotes zero, while destination31 always denotes the discard XZR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerAuthenticationModifier {
    Register(u8),
    StackPointer,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerAuthenticationOperation {
    // Keep the existing descriptor representation.
    /// Exact HINT source identity: general PACIA X17,X16 remains distinct.
    Sign1716 {
        key: PointerAuthenticationKey,
    },
    Authenticate1716 {
        key: PointerAuthenticationKey,
    },
    LinkRegister(pauth_lr::Instruction),
    SignIbSp,
    AuthenticateIbSp,
    ReturnIbSp,
    Sign {
        key: PointerAuthenticationKey,
        destination: u8,
        modifier: PointerAuthenticationModifier,
    },
    Authenticate {
        key: PointerAuthenticationKey,
        destination: u8,
        modifier: PointerAuthenticationModifier,
    },
    Strip {
        data: bool,
        destination: u8,
    },
    ReturnIaSp,
    GenericCode(pauth_memory::GenericCode),
    Load(pauth_memory::Load),
    Branch {
        key: PointerAuthenticationKey,
        target: u8,
        modifier: PointerAuthenticationModifier,
        link: bool,
    },
}

impl PointerAuthenticationOperation {
    pub const fn is_return(self) -> bool {
        matches!(self, Self::ReturnIbSp | Self::ReturnIaSp)
            || matches!(self, Self::LinkRegister(instruction) if instruction.is_return())
    }

    pub const fn is_transfer(self) -> bool {
        self.is_return() || matches!(self, Self::Branch { .. })
    }

    pub const fn required_key(self) -> Option<PointerAuthenticationKey> {
        match self {
            Self::SignIbSp | Self::AuthenticateIbSp | Self::ReturnIbSp => {
                Some(PointerAuthenticationKey::Ib)
            }
            Self::ReturnIaSp => Some(PointerAuthenticationKey::Ia),
            Self::Sign { key, .. }
            | Self::Authenticate { key, .. }
            | Self::Sign1716 { key }
            | Self::Authenticate1716 { key }
            | Self::Branch { key, .. } => Some(key),
            Self::LinkRegister(instruction) => match instruction.key() {
                Some(pauth_lr::Key::Ia) => Some(PointerAuthenticationKey::Ia),
                Some(pauth_lr::Key::Ib) => Some(PointerAuthenticationKey::Ib),
                None => None,
            },
            Self::Load(load) => Some(match load.key {
                pauth_memory::DataKey::A => PointerAuthenticationKey::Da,
                pauth_memory::DataKey::B => PointerAuthenticationKey::Db,
            }),
            Self::Strip { .. } | Self::GenericCode(_) => None,
        }
    }
}

/// A helper request at an instruction that has not executed. The block commits
/// the instructions before it but performs no PAC operation or transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PointerAuthentication {
    pub operation: PointerAuthenticationOperation,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

/// PAC/AUT (integer and HINT forms), XPAC, PACGA and authenticated loads. Keys
/// and the PAuth1/PAuth2/FPAC policy come from the runtime context.
/// FEAT_PAuth_LR forms need LR and PACM state, so key-only consumers refuse
/// them. GCS and dynamic controls are unsupported. Consumers re-validate the
/// descriptor against the source bytes.
pub fn decode_pointer_authentication(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<PointerAuthentication>, CompileError> {
    use PointerAuthenticationKey::{Da, Db, Ia, Ib};
    use PointerAuthenticationModifier::{Register, StackPointer, Zero};
    use PointerAuthenticationOperation::{Authenticate, Sign, Strip};
    if !pc.0.is_multiple_of(4) {
        return Err(CompileError(
            "PAC instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    let operation = if let Some(instruction) = pauth_lr::decode(word) {
        PointerAuthenticationOperation::LinkRegister(instruction)
    } else {
        match word {
            0xd503237f => PointerAuthenticationOperation::SignIbSp,
            0xd50323ff => PointerAuthenticationOperation::AuthenticateIbSp,
            0xd65f0fff => PointerAuthenticationOperation::ReturnIbSp,
            0xd65f0bff => PointerAuthenticationOperation::ReturnIaSp,
            0xd503211f => PointerAuthenticationOperation::Sign1716 { key: Ia },
            0xd503215f => PointerAuthenticationOperation::Sign1716 { key: Ib },
            0xd503219f => PointerAuthenticationOperation::Authenticate1716 { key: Ia },
            0xd50321df => PointerAuthenticationOperation::Authenticate1716 { key: Ib },
            0xd503233f => Sign {
                key: Ia,
                destination: 30,
                modifier: StackPointer,
            },
            0xd50323bf => Authenticate {
                key: Ia,
                destination: 30,
                modifier: StackPointer,
            },
            0xd503231f => Sign {
                key: Ia,
                destination: 30,
                modifier: Zero,
            },
            0xd503235f => Sign {
                key: Ib,
                destination: 30,
                modifier: Zero,
            },
            0xd503239f => Authenticate {
                key: Ia,
                destination: 30,
                modifier: Zero,
            },
            0xd50323df => Authenticate {
                key: Ib,
                destination: 30,
                modifier: Zero,
            },
            0xd50320ff => Strip {
                data: false,
                destination: 30,
            },
            _ if word & 0xffffc000 == 0xdac10000 => {
                let rn = ((word >> 5) & 31) as u8;
                let modifier = if word & (1 << 13) != 0 {
                    // The Z forms fix Rn=11111. Do not admit unallocated neighbors.
                    if rn != 31 {
                        return Ok(None);
                    }
                    Zero
                } else if rn == 31 {
                    StackPointer
                } else {
                    Register(rn)
                };
                let key = match (word >> 10) & 3 {
                    0 => Ia,
                    1 => Ib,
                    2 => Da,
                    _ => Db,
                };
                let destination = (word & 31) as u8;
                if word & (1 << 12) == 0 {
                    Sign {
                        key,
                        destination,
                        modifier,
                    }
                } else {
                    Authenticate {
                        key,
                        destination,
                        modifier,
                    }
                }
            }
            _ if word & 0xfffffbe0 == 0xdac143e0 => Strip {
                data: word & (1 << 10) != 0,
                destination: (word & 31) as u8,
            },
            _ if word & 0xfedff800 == 0xd61f0800 => {
                let rm = (word & 31) as u8;
                let modifier = if word & (1 << 24) == 0 {
                    if rm != 31 {
                        return Ok(None);
                    }
                    Zero
                } else if rm == 31 {
                    StackPointer
                } else {
                    Register(rm)
                };
                PointerAuthenticationOperation::Branch {
                    key: if word & (1 << 10) == 0 { Ia } else { Ib },
                    target: ((word >> 5) & 31) as u8,
                    modifier,
                    link: word & (1 << 21) != 0,
                }
            }
            _ => match pauth_memory::decode(word) {
                Some(pauth_memory::Instruction::GenericCode(code)) => {
                    PointerAuthenticationOperation::GenericCode(code)
                }
                Some(pauth_memory::Instruction::Load(load)) => {
                    PointerAuthenticationOperation::Load(load)
                }
                None => return Ok(None),
            },
        }
    };
    Ok(Some(PointerAuthentication {
        operation,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0.checked_add(4).ok_or_else(|| {
            CompileError("PAC continuation PC overflows guest address range".into())
        })?),
    }))
}

/// Identifies the instruction; the exception itself is raised elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapKind {
    SupervisorCall,
    SoftwareBreakpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SynchronousTrap {
    pub kind: TrapKind,
    pub immediate: u16,
    pub instruction_pc: GuestAddress,
    /// Architectural preferred return address; the dispatcher still stops at
    /// instruction_pc. This metadata does not advance or resume guest state.
    pub exception_return_pc: GuestAddress,
}

/// Decode only exact SVC/BRK encodings at an aligned guest instruction address.
/// HVC/SMC/HLT/DCPS and neighboring reserved encodings remain unsupported.
pub fn decode_trap(pc: GuestAddress, word: u32) -> Result<Option<SynchronousTrap>, CompileError> {
    if !pc.0.is_multiple_of(4) {
        return Err(CompileError(
            "trap instruction PC must be aligned to 4 bytes".into(),
        ));
    }
    // June 2026 official SVC_EX_exception / BRK_EX_exception encodings:
    // only imm16 at bits 20:5 varies.
    let kind = match word & 0xffe0001f {
        0xd4000001 => TrapKind::SupervisorCall,
        0xd4200000 => TrapKind::SoftwareBreakpoint,
        _ => return Ok(None),
    };
    let exception_return_pc = match kind {
        TrapKind::SupervisorCall => GuestAddress(pc.0.checked_add(4).ok_or_else(|| {
            CompileError("SVC exception return PC overflows guest address range".into())
        })?),
        TrapKind::SoftwareBreakpoint => pc,
    };
    Ok(Some(SynchronousTrap {
        kind,
        immediate: ((word >> 5) & 0xffff) as u16,
        instruction_pc: pc,
        exception_return_pc,
    }))
}

/// The raw kind, validated before the result is converted.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockExit {
    pub next_pc: u64,
    pub kind: u64,
}

#[derive(Debug)]
pub struct CompiledBlock {
    pub native: NativeBlock,
    /// Exact consumed prefix, including the terminator when present.
    pub source_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Terminator {
    Branch(Operation),
    DirectCall(GuestAddress),
    Register {
        source: Register,
        kind: ExitKind,
    },
    Trap(SynchronousTrap),
    System(SystemInstruction),
    PointerAuthentication(PointerAuthentication),
    Clock(ClockInstruction),
    ThreadRegister(ThreadRegisterInstruction),
    /// Scalar mapping that unconditionally returns to numerical completion.
    FloatingPoint(crate::aarch64::FloatingPointOperation),
}

fn decode_terminator(pc: GuestAddress, word: u32) -> Result<Option<Terminator>, CompileError> {
    if let Some(trap) = decode_trap(pc, word)? {
        return Ok(Some(Terminator::Trap(trap)));
    }
    if word & 0xfc000000 == 0x94000000 {
        let displacement = ((i64::from(word & 0x03ffffff) << 38) >> 38) * 4;
        let target =
            pc.0.checked_add_signed(displacement)
                .map(GuestAddress)
                .ok_or_else(|| CompileError("direct call guest address overflow".into()))?;
        return Ok(Some(Terminator::DirectCall(target)));
    }
    let kind = match word & 0xfffffc1f {
        0xd61f0000 => Some(ExitKind::Indirect),
        0xd63f0000 => Some(ExitKind::Call),
        0xd65f0000 => Some(ExitKind::Return),
        _ => None,
    };
    Ok(kind.map(|kind| {
        let index = ((word >> 5) & 31) as u8;
        Terminator::Register {
            // Arm X(n) reads register 31 as Zero, including BR/BLR/RET.
            source: if index == 31 {
                Register::Zero
            } else {
                Register::X(index)
            },
            kind,
        }
    }))
}

struct ParsedBlock {
    instructions: Vec<Instruction>,
    terminal: Option<(GuestAddress, Terminator)>,
    next_pc: GuestAddress,
    source_bytes: usize,
}

/// An analysis failure at the instruction that caused it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockAnalysisError {
    pub pc: GuestAddress,
    pub detail: String,
}
impl core::fmt::Display for BlockAnalysisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at {:#x}", self.detail, self.pc.0)
    }
}
impl core::error::Error for BlockAnalysisError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessorKind {
    Direct,
    ConditionalTarget,
    ConditionalFallthrough,
    CallTarget,
    CallContinuation,
    Fallthrough,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticSuccessor {
    pub kind: SuccessorKind,
    pub target: GuestAddress,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicEdgeKind {
    Branch,
    Call,
    Return,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DynamicEdge {
    pub kind: DynamicEdgeKind,
    /// Architectural Xn source; index31 denotes Zero, never SP.
    pub register: u8,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockAnalysis {
    pub source_bytes: usize,
    pub terminator_pc: Option<GuestAddress>,
    pub static_successors: Vec<StaticSuccessor>,
    pub dynamic_edge: Option<DynamicEdge>,
    pub trap: Option<SynchronousTrap>,
    pub system_instruction: Option<SystemInstruction>,
    pub pointer_authentication: Option<PointerAuthentication>,
    pub clock_instruction: Option<ClockInstruction>,
    pub thread_register_instruction: Option<ThreadRegisterInstruction>,
}
/// Find block boundaries and edges with the parser shared by AOT and JIT. Call
/// continuations are candidates, since the callee may not return; dynamic
/// targets and trap resumption are resolved at run time.
pub fn analyze(source: &[u8], base: GuestAddress) -> Result<BlockAnalysis, BlockAnalysisError> {
    analyze_with_profile(source, base, BlockProfile::Ordinary)
}

pub fn analyze_with_profile(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
) -> Result<BlockAnalysis, BlockAnalysisError> {
    let parsed = parse(source, base, profile)?;
    let mut successors = Vec::new();
    let mut dynamic_edge = None;
    let mut trap = None;
    let mut system_instruction = None;
    let mut pointer_authentication = None;
    let mut clock_instruction = None;
    let mut thread_register_instruction = None;
    let mut add = |kind, target| successors.push(StaticSuccessor { kind, target });
    match parsed.terminal.as_ref().map(|(_, terminal)| terminal) {
        None => add(SuccessorKind::Fallthrough, parsed.next_pc),
        Some(Terminator::Branch(Operation::Branch { target })) => {
            add(SuccessorKind::Direct, *target)
        }
        Some(Terminator::Branch(
            Operation::BranchCondition { target, .. }
            | Operation::BranchZero { target, .. }
            | Operation::BranchBit { target, .. },
        )) => {
            add(SuccessorKind::ConditionalTarget, *target);
            add(SuccessorKind::ConditionalFallthrough, parsed.next_pc);
        }
        Some(Terminator::DirectCall(target)) => {
            add(SuccessorKind::CallTarget, *target);
            add(SuccessorKind::CallContinuation, parsed.next_pc);
        }
        Some(Terminator::Register { source, kind }) => {
            let edge = match kind {
                ExitKind::Indirect => DynamicEdgeKind::Branch,
                ExitKind::Call => DynamicEdgeKind::Call,
                ExitKind::Return => DynamicEdgeKind::Return,
                _ => unreachable!("private parser only constructs ordinary register transfers"),
            };
            let register = match source {
                Register::X(index) => *index,
                Register::Zero => 31,
                Register::Sp => unreachable!("transfer source never SP"),
            };
            dynamic_edge = Some(DynamicEdge {
                kind: edge,
                register,
            });
            if *kind == ExitKind::Call {
                add(SuccessorKind::CallContinuation, parsed.next_pc);
            }
        }
        Some(Terminator::Trap(value)) => trap = Some(*value),
        Some(Terminator::System(value)) => {
            system_instruction = Some(*value);
            if matches!(
                value.operation,
                system::SystemOperation::TagMemory(_)
                    | system::SystemOperation::SendEvent { .. }
                    | system::SystemOperation::Register(_)
                    | system::SystemOperation::PstateImmediate(_)
            ) {
                add(SuccessorKind::Fallthrough, value.next_pc);
            }
        }
        Some(Terminator::PointerAuthentication(value)) => {
            pointer_authentication = Some(*value);
            if value.operation.is_return() {
                // Signed LR is only a candidate: the service authenticates it.
                dynamic_edge = Some(DynamicEdge {
                    kind: DynamicEdgeKind::Return,
                    register: 30,
                });
            } else if let PointerAuthenticationOperation::Branch { target, link, .. } =
                value.operation
            {
                dynamic_edge = Some(DynamicEdge {
                    kind: if link {
                        DynamicEdgeKind::Call
                    } else {
                        DynamicEdgeKind::Branch
                    },
                    register: target,
                });
                if link {
                    add(SuccessorKind::CallContinuation, value.next_pc);
                }
            } else {
                add(SuccessorKind::Fallthrough, value.next_pc);
            }
        }
        Some(Terminator::Clock(value)) => {
            clock_instruction = Some(*value);
            add(SuccessorKind::Fallthrough, value.next_pc);
        }
        Some(Terminator::ThreadRegister(value)) => {
            thread_register_instruction = Some(*value);
            add(SuccessorKind::Fallthrough, value.next_pc);
        }
        Some(Terminator::FloatingPoint(_)) => {
            add(SuccessorKind::Fallthrough, parsed.next_pc);
        }
        Some(Terminator::Branch(_)) => {
            unreachable!("private parser only stores branch operations as terminators")
        }
    }
    Ok(BlockAnalysis {
        source_bytes: parsed.source_bytes,
        terminator_pc: parsed.terminal.map(|(pc, _)| pc),
        static_successors: successors,
        dynamic_edge,
        trap,
        system_instruction,
        pointer_authentication,
        clock_instruction,
        thread_register_instruction,
    })
}

fn parse(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
) -> Result<ParsedBlock, BlockAnalysisError> {
    if source.is_empty() || !source.len().is_multiple_of(4) || !base.0.is_multiple_of(4) {
        return Err(BlockAnalysisError {
            pc: base,
            detail: "block input and guest base must be nonempty/aligned to 4 bytes".into(),
        });
    }
    if profile == BlockProfile::El1DirectBranchV1 {
        if source.len() != size_of::<u32>() {
            return Err(BlockAnalysisError {
                pc: base,
                detail: "EL1 direct-branch profile requires exactly one complete instruction"
                    .into(),
            });
        }
        let word = u32::from_le_bytes(source.try_into().expect("exact instruction extent"));
        let direct = Decoder
            .lift(base, word)
            .is_ok_and(|instruction| matches!(instruction.operation, Operation::Branch { .. }));
        if !direct {
            return Err(BlockAnalysisError {
                pc: base,
                detail: "EL1 direct-branch profile admits only ordinary B immediate".into(),
            });
        }
    }
    if source.len() / 4 > MAX_BLOCK_INSTRUCTIONS {
        return Err(BlockAnalysisError {
            pc: base,
            detail: format!("block input exceeds {MAX_BLOCK_INSTRUCTIONS} instructions"),
        });
    }
    let mut instructions = vec![];
    let mut terminal = None;
    let mut source_bytes = 0;
    let mut next_pc = base;
    for bytes in source.as_chunks::<4>().0 {
        let pc = next_pc;
        next_pc = GuestAddress(pc.0.checked_add(4).ok_or_else(|| BlockAnalysisError {
            pc,
            detail: "block guest address overflow".into(),
        })?);
        source_bytes += 4;
        let word = u32::from_le_bytes(*bytes);
        if profile.supports_system()
            && let Some(decoded) = (if profile == BlockProfile::El1PlatformV1 {
                system::decode_el1_system_instruction(pc, word)
            } else {
                decode_system_instruction(pc, word)
            })
            .map_err(|error| BlockAnalysisError {
                pc,
                detail: error.0,
            })?
            && (profile.supports_system_registers()
                || !matches!(
                    decoded.operation,
                    system::SystemOperation::Register(_)
                        | system::SystemOperation::PstateImmediate(_)
                ))
        {
            if profile == BlockProfile::El1PlatformV1 {
                el1_platform::validate_system(decoded).map_err(|error| BlockAnalysisError {
                    pc,
                    detail: error.0,
                })?;
                if !instructions.is_empty() {
                    source_bytes -= size_of::<u32>();
                    next_pc = pc;
                    break;
                }
            }
            terminal = Some((pc, Terminator::System(decoded)));
            break;
        }
        if profile.supports_pointer_authentication()
            && let Some(decoded) =
                decode_pointer_authentication(pc, word).map_err(|error| BlockAnalysisError {
                    pc,
                    detail: error.0,
                })?
        {
            terminal = Some((pc, Terminator::PointerAuthentication(decoded)));
            break;
        }
        if profile.supports_clock()
            && let Some(decoded) =
                decode_clock_instruction(pc, word).map_err(|error| BlockAnalysisError {
                    pc,
                    detail: error.0,
                })?
        {
            terminal = Some((pc, Terminator::Clock(decoded)));
            break;
        }
        if profile.supports_thread_registers()
            && let Some(decoded) =
                decode_thread_register_instruction(pc, word).map_err(|error| {
                    BlockAnalysisError {
                        pc,
                        detail: error.0,
                    }
                })?
        {
            terminal = Some((pc, Terminator::ThreadRegister(decoded)));
            break;
        }
        if let Some(decoded) = decode_terminator(pc, word).map_err(|error| BlockAnalysisError {
            pc,
            detail: error.0,
        })? {
            if profile == BlockProfile::El1M0IntegerV1 {
                el1_m0::validate_terminal(&decoded).map_err(|error| BlockAnalysisError {
                    pc,
                    detail: error.0,
                })?;
            }
            if profile == BlockProfile::El1PlatformV1 {
                el1_platform::validate_terminal(&decoded).map_err(|error| BlockAnalysisError {
                    pc,
                    detail: error.0,
                })?;
            }
            terminal = Some((pc, decoded));
            break;
        }
        let instruction = Decoder.lift(pc, word).map_err(|error| BlockAnalysisError {
            pc,
            detail: format!("unsupported ARM64 semantics: {error:?}"),
        })?;
        if profile == BlockProfile::El1PlatformV1 {
            el1_platform::validate_operation(&instruction.operation).map_err(|error| {
                BlockAnalysisError {
                    pc,
                    detail: error.0,
                }
            })?;
            if matches!(instruction.operation, Operation::Literal(_))
                || el1_platform::Write64Pair::from_instruction(&instruction).is_some()
                || el1_platform::Read64Pair::from_instruction(&instruction).is_some()
                || el1_platform::ScalarLoad::from_instruction(&instruction).is_some()
            {
                if !instructions.is_empty() {
                    source_bytes -= size_of::<u32>();
                    next_pc = pc;
                } else {
                    instructions.push(instruction);
                }
                break;
            }
        }
        if profile == BlockProfile::El1M0IntegerV1 {
            el1_m0::validate_operation(&instruction.operation).map_err(|error| {
                BlockAnalysisError {
                    pc,
                    detail: error.0,
                }
            })?;
            if matches!(instruction.operation, Operation::Literal(_)) {
                // Retire a real register-only prefix before acquiring a read
                // session. The literal belongs to the following attempt.
                if !instructions.is_empty() {
                    source_bytes -= size_of::<u32>();
                    next_pc = pc;
                } else {
                    instructions.push(instruction);
                }
                break;
            }
        }
        if (profile.checked_memory().is_some() || profile == BlockProfile::El1PlatformV1)
            && instruction.operation == Operation::Nop
            && word != NOP_ENCODING
        {
            return Err(BlockAnalysisError {
                pc,
                detail: "unadmitted original NOP provenance in checked memory profile".into(),
            });
        }
        if profile.supports_system() && !crate::extended::ordinary_permitted(&instruction.operation)
        {
            return Err(BlockAnalysisError {
                pc,
                detail: "operation outside restricted System prefix profile".into(),
            });
        }
        if let Operation::FloatingPoint(operand) = &instruction.operation
            && crate::x86_64::numerical_always_exits(operand)
        {
            terminal = Some((pc, Terminator::FloatingPoint(*operand)));
            break;
        }
        if matches!(
            instruction.operation,
            Operation::Branch { .. }
                | Operation::BranchCondition { .. }
                | Operation::BranchZero { .. }
                | Operation::BranchBit { .. }
        ) {
            terminal = Some((pc, Terminator::Branch(instruction.operation)));
            break;
        }
        instructions.push(instruction);
    }
    Ok(ParsedBlock {
        instructions,
        terminal,
        next_pc,
        source_bytes,
    })
}

/// Validate and identify the consumed prefix without generating native code.
/// Uses the same semantic lift and transfer boundaries as [`compile`].
pub fn source_bytes(source: &[u8], base: GuestAddress) -> Result<usize, CompileError> {
    source_bytes_with_profile(source, base, BlockProfile::Ordinary)
}

pub fn source_bytes_with_profile(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
) -> Result<usize, CompileError> {
    let parsed = parse(source, base, profile).map_err(|error| CompileError(error.detail))?;
    if let Some(selected) = profile.checked_memory() {
        memory::CheckedPlan::new(
            &parsed.instructions,
            parsed.terminal.as_ref(),
            selected,
            profile.supports_checked_process_helpers(),
        )?;
    }
    Ok(parsed.source_bytes)
}

/// Compile through the first transfer, trap or unconditional runtime helper,
/// or exit at the input boundary.
/// Unknown semantics before that boundary are rejected. Bytes following a
/// terminator are unconsumed and do not participate in the returned source map.
pub fn compile(source: &[u8], base: GuestAddress) -> Result<CompiledBlock, CompileError> {
    compile_with_profile(source, base, BlockProfile::Ordinary)
}

pub fn compile_with_profile(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
) -> Result<CompiledBlock, CompileError> {
    compile_for_target(source, base, profile, crate::TargetCpu::Baseline)
}
pub fn compile_for_target(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
    target: crate::TargetCpu,
) -> Result<CompiledBlock, CompileError> {
    CompilationPlan::new(source, base, profile, target)?.compile()
}

/// One immutable parsed consumed vector shared by cache requirements and emission.
/// A cache hit may avoid emission; it still derives exact requirements from source.
pub struct CompilationPlan {
    parsed: ParsedBlock,
    checked: Option<memory::CheckedPlan>,
    el1_m0: Option<el1_m0::Plan>,
    el1_platform: Option<el1_platform::Plan>,
    target: crate::TargetCpu,
    profile: BlockProfile,
    resident: Option<crate::x86_64::block::ResidentLoopPlan>,
}
impl CompilationPlan {
    pub fn new(
        source: &[u8],
        base: GuestAddress,
        profile: BlockProfile,
        target: crate::TargetCpu,
    ) -> Result<Self, CompileError> {
        let parsed = parse(source, base, profile).map_err(|error| CompileError(error.detail))?;
        for instruction in &parsed.instructions {
            if !matches!(
                instruction.operation,
                Operation::Exclusive(_) | Operation::CheckedPointer(_)
            ) || profile.checked_memory().is_none()
            {
                crate::x86_64::validate_target(instruction, target)
                    .map_err(|error| CompileError(format!("{error:?}")))?;
            }
        }
        let checked = profile
            .checked_memory()
            .map(|selected| {
                memory::CheckedPlan::new(
                    &parsed.instructions,
                    parsed.terminal.as_ref(),
                    selected,
                    profile.supports_checked_process_helpers(),
                )
            })
            .transpose()?;
        let el1_m0 = (profile == BlockProfile::El1M0IntegerV1)
            .then(|| el1_m0::Plan::new(&parsed))
            .transpose()?;
        let el1_platform = (profile == BlockProfile::El1PlatformV1)
            .then(|| el1_platform::Plan::new(&parsed))
            .transpose()?;
        let resident = if profile.supports_resident_loops() {
            crate::x86_64::block::ResidentLoopPlan::new(
                &parsed.instructions,
                parsed.terminal.as_ref(),
                parsed.next_pc,
            )
        } else {
            None
        };
        Ok(Self {
            parsed,
            checked,
            el1_m0,
            el1_platform,
            target,
            profile,
            resident,
        })
    }
    /// Allow the ordinary runtime to retain eligible internal loop edges. Other
    /// service profiles keep their existing admission and call contracts.
    pub fn with_resident_loops(mut self) -> Self {
        if self.profile == BlockProfile::Ordinary {
            self.resident = crate::x86_64::block::ResidentLoopPlan::new(
                &self.parsed.instructions,
                self.parsed.terminal.as_ref(),
                self.parsed.next_pc,
            );
            if self.resident.is_some() {
                self.profile = BlockProfile::OrdinaryResidentV1;
            }
        }
        self
    }

    pub fn profile(&self) -> BlockProfile {
        self.profile
    }

    pub fn source_bytes(&self) -> usize {
        self.parsed.source_bytes
    }
    pub fn memory_requirements(&self) -> Option<crate::context::memory::MemoryRequirements> {
        if let Some(plan) = &self.el1_platform {
            return plan.requirements();
        }
        if let Some(plan) = &self.el1_m0 {
            return plan.requirements();
        }
        self.checked.as_ref().map(memory::CheckedPlan::requirements)
    }
    /// Typed source intent for this profile; other profiles return None.
    pub fn el1_m0_intent(&self) -> Option<el1_m0::Intent> {
        self.el1_m0.as_ref().map(el1_m0::Plan::intent)
    }
    pub fn el1_platform_intent(&self) -> Option<el1_platform::Intent> {
        self.el1_platform.as_ref().map(el1_platform::Plan::intent)
    }
    pub fn compile(self) -> Result<CompiledBlock, CompileError> {
        let native = if let Some(plan) = self.el1_platform {
            plan.emit(self.target)?
        } else if let Some(plan) = self.el1_m0 {
            plan.emit(self.target)?
        } else if let Some(checked) = self.checked {
            checked.emit(
                self.parsed.terminal.as_ref(),
                self.parsed.next_pc,
                self.target,
            )?
        } else if let Some(resident) = self.resident {
            resident
                .emit(&self.parsed.instructions)
                .map_err(|error| CompileError(format!("resident loop emission: {error:?}")))?
        } else if self.profile.supports_resident_loops() {
            crate::x86_64::block::emit_resident_fallback_for_target(
                &self.parsed.instructions,
                self.parsed.terminal.as_ref(),
                self.parsed.next_pc,
                self.target,
            )
        } else if self.profile == BlockProfile::Ordinary {
            crate::x86_64::block::emit_ordinary_for_target(
                &self.parsed.instructions,
                self.parsed.terminal.as_ref(),
                self.parsed.next_pc,
                self.target,
            )
        } else {
            crate::x86_64::block::emit_for_target(
                &self.parsed.instructions,
                self.parsed.terminal.as_ref(),
                self.parsed.next_pc,
                self.target,
            )
        };
        Ok(CompiledBlock {
            native,
            source_bytes: self.parsed.source_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
