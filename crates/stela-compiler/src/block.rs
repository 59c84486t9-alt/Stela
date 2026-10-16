//! Basic-block translation.
//!
//! Native entry is System V `BlockExit function(GuestState *state)`. Emitted code
//! never jumps to a guest PC: every control-flow change exits to the dispatcher.
//! SVC and BRK exit at a synchronous-trap boundary. PAC instructions call a
//! runtime helper when software PAuth is enabled.

mod analysis;
pub mod el1_m0;
pub mod el1_platform;
pub mod loop_budget;
pub mod memory;
pub mod pauth_lr;
pub mod pauth_memory;
mod pointer_authentication;
pub mod scalable;
pub mod system;
mod thread;

pub use analysis::{
    BlockAnalysis, BlockAnalysisError, DynamicEdge, DynamicEdgeKind, StaticSuccessor,
    SuccessorKind, analyze, analyze_with_profile, source_bytes, source_bytes_with_profile,
};
use analysis::{ParsedBlock, parse};
pub use memory::{
    CHECKED_POINTER_PROCESS_MEMORY_PROFILE_ID, CheckedMemoryProfile,
    ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
};
pub use pointer_authentication::{
    PointerAuthentication, PointerAuthenticationKey, PointerAuthenticationModifier,
    PointerAuthenticationOperation, decode_pointer_authentication,
};
pub use system::{SystemInstruction, decode_system_instruction};
pub use thread::{ThreadRegisterInstruction, decode_thread_register_instruction};

use crate::{
    CompileError, GuestAddress, NativeBlock,
    aarch64::{Operation, Register},
};
use alloc::format;
use serde::Serialize;

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
