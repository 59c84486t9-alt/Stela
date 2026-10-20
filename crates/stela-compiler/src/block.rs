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
use analysis::{ParsedBlock, analyze_parsed, parse};
pub use memory::{
    CHECKED_POINTER_PROCESS_MEMORY_PROFILE_ID, CheckedMemoryProfile,
    ORDINARY_GPR_PROCESS_MEMORY_PROFILE_ID,
};
pub use pointer_authentication::{
    PointerAuthentication, PointerAuthenticationKey, PointerAuthenticationModifier,
    PointerAuthenticationOperation, decode_pointer_authentication,
};
pub use system::{SystemInstruction, decode_system_instruction, decode_system_mode_instruction};
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
/// Direct-RAM blocks for the system-mode engine: guest VAs are native
/// addresses through shadow paging, `GuestState` is exact at every instruction
/// boundary, and every System-class instruction exits with kind 11.
pub const SYSTEM_MODE_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-system-mode-v1";
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
    /// The system-mode engine's profile; see [`SYSTEM_MODE_BLOCK_ABI`].
    SystemModeV1,
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
            Self::SystemModeV1 => SYSTEM_MODE_BLOCK_ABI,
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
            Self::SystemV1 | Self::SystemRegistersV1 | Self::El1PlatformV1 | Self::SystemModeV1
        )
    }

    pub const fn supports_system_registers(self) -> bool {
        matches!(
            self,
            Self::SystemRegistersV1 | Self::El1PlatformV1 | Self::SystemModeV1
        )
    }

    pub const fn supports_pointer_authentication(self) -> bool {
        matches!(
            self,
            Self::AppleArm64eSoftwarePauthV1
                | Self::AppleArm64eSoftwarePauthClockV1
                | Self::AppleArm64eSoftwarePauthThreadV1
                | Self::AppleArm64eSoftwarePauthClockThreadV1
                | Self::CheckedMemoryPauthClockThread(_)
                | Self::SystemModeV1
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

    /// AMX state is per guest thread in the direct-RAM thread profiles and
    /// per PE in system mode; those profiles carry AMX exits.
    pub const fn supports_amx(self) -> bool {
        matches!(
            self,
            Self::SystemModeV1
                | Self::DarwinArm64ThreadV1
                | Self::AppleArm64eSoftwarePauthThreadV1
                | Self::AppleArm64eSoftwarePauthClockThreadV1
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
    /// An Apple AMX coprocessor instruction, still unexecuted; the runtime
    /// completes it against the thread's AMX state.
    Amx = 12,
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
            12 => Ok(Self::Amx),
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

#[derive(Debug, Clone)]
pub struct CompiledBlock {
    pub native: NativeBlock,
    /// Exact consumed prefix, including the terminator when present.
    pub source_bytes: usize,
    /// The native code's direct exits to static successors, which the
    /// system-mode engine may chain (`x86_64::chain`).
    pub direct_exits: alloc::vec::Vec<crate::x86_64::chain::DirectExit>,
    /// Where the native code keeps guest GPRs out of their frame slots
    /// across a faultable access. Only `SystemModeV1` emits entries, and
    /// an engine that recovers from a native fault must apply them
    /// ([`FaultRecovery::apply`]) before it reads the frame.
    pub fault_recovery: alloc::vec::Vec<FaultRecovery>,
}

/// While native code at offsets `start..end` of its block runs, each
/// `(guest, host)` pair's guest GPR (31 is SP) holds the value of host
/// register `host` (its x86 number) rather than its frame slot. A fault
/// there finds the architectural state of every earlier instruction in the
/// frame once these values are written to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultRecovery {
    pub start: usize,
    pub end: usize,
    pub registers: alloc::vec::Vec<(u8, u8)>,
}

impl FaultRecovery {
    /// Write the values `table` names for a fault at native `offset` from
    /// the host GPRs at the fault, RAX through R15, into `state`.
    pub fn apply(table: &[Self], offset: usize, host: &[u64; 16], state: &mut crate::GuestState) {
        const SP: u8 = 31;
        for entry in table
            .iter()
            .filter(|entry| (entry.start..entry.end).contains(&offset))
        {
            for &(guest, register) in &entry.registers {
                let value = host[usize::from(register)];
                if guest == SP {
                    state.sp = value;
                } else {
                    state.x[usize::from(guest)] = value;
                }
            }
        }
    }
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
    Amx(crate::amx::AmxInstruction),
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

/// [`analyze_with_profile`] of `source` and [`CompilationPlan::new`] of the
/// block it finds (`source[..analysis.source_bytes]`) from one parse.
pub fn analyze_and_plan(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
    target: crate::TargetCpu,
) -> Result<(BlockAnalysis, Result<CompilationPlan, CompileError>), BlockAnalysisError> {
    let parsed = parse(source, base, profile)?;
    let analysis = analyze_parsed(&parsed);
    Ok((
        analysis,
        CompilationPlan::from_parsed(parsed, profile, target),
    ))
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
    checks: crate::x86_64::MemoryChecks,
    native: crate::x86_64::NativeSystem,
}
impl CompilationPlan {
    pub fn new(
        source: &[u8],
        base: GuestAddress,
        profile: BlockProfile,
        target: crate::TargetCpu,
    ) -> Result<Self, CompileError> {
        let parsed = parse(source, base, profile).map_err(|error| CompileError(error.detail))?;
        Self::from_parsed(parsed, profile, target)
    }

    fn from_parsed(
        parsed: ParsedBlock,
        profile: BlockProfile,
        target: crate::TargetCpu,
    ) -> Result<Self, CompileError> {
        // System mode emits for a single agent, whose atomics and acquire
        // loads need neither CMPXCHG16B nor a 16-byte snapshot.
        let validated = crate::x86_64::MemoryChecks {
            single_agent: profile == BlockProfile::SystemModeV1,
            ..crate::x86_64::MemoryChecks::DEFAULT
        };
        for instruction in &parsed.instructions {
            if !matches!(
                instruction.operation,
                Operation::Exclusive(_) | Operation::CheckedPointer(_)
            ) || profile.checked_memory().is_none()
            {
                crate::x86_64::validate_target_with(instruction, target, validated)
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
            checks: crate::x86_64::MemoryChecks::DEFAULT,
            native: crate::x86_64::NativeSystem::NONE,
        })
    }

    /// Emit the memory checks of the regime's SCTLR_ELx: the system-mode
    /// engine compiles separate blocks for SA (or SA0 at EL0) clear, where an
    /// access through a misaligned SP proceeds; for A set, where any access
    /// not aligned to its elements faults; and for nAA set, where an ordered
    /// access may cross its 16-byte granule. No other profile admits checks
    /// but [`crate::x86_64::MemoryChecks::DEFAULT`], and a host without the
    /// capability an unchecked SP then needs refuses.
    pub fn with_memory_checks(
        mut self,
        checks: crate::x86_64::MemoryChecks,
    ) -> Result<Self, CompileError> {
        if checks != crate::x86_64::MemoryChecks::DEFAULT
            && self.profile != BlockProfile::SystemModeV1
        {
            return Err(CompileError(format!(
                "{:?} makes only the default memory checks",
                self.profile
            )));
        }
        if !checks.stack_alignment {
            let single_agent = crate::x86_64::MemoryChecks {
                single_agent: true,
                ..checks
            };
            for instruction in &self.parsed.instructions {
                crate::x86_64::validate_target_with(instruction, self.target, single_agent)
                    .map_err(|error| CompileError(format!("{error:?}")))?;
            }
        }
        self.checks = checks;
        Ok(self)
    }
    /// Complete a terminal DC ZVA natively, zeroing the aligned `bytes`
    /// block holding Xt (DCZID_EL0.BS: a power of two from 4 to 2048) and
    /// falling through: the system-mode engine compiles separate blocks for
    /// the contexts where DC ZVA neither traps nor is UNDEFINED. `None`
    /// keeps its System exit.
    pub fn with_zero_block(mut self, bytes: Option<u16>) -> Result<Self, CompileError> {
        use crate::x86_64::zero_block::{MAX_BYTES, MIN_BYTES};
        if let Some(bytes) = bytes {
            if self.profile != BlockProfile::SystemModeV1 {
                return Err(CompileError(format!(
                    "{:?} keeps DC ZVA's System exit",
                    self.profile
                )));
            }
            if !bytes.is_power_of_two() || !(MIN_BYTES..=MAX_BYTES).contains(&bytes) {
                return Err(CompileError(format!(
                    "a {bytes}-byte DC ZVA block is not a DCZID_EL0.BS size"
                )));
            }
        }
        self.native.zero_block = bytes;
        Ok(self)
    }
    /// Complete a terminal DC CVAC, DC CVAU or DC CIVAC among `operations`
    /// natively, checking that Xt translates for a read and falling through
    /// (`x86_64::cache_clean`): the system-mode engine compiles separate
    /// blocks for the contexts where those operations neither trap nor are
    /// UNDEFINED. Other operations keep their System exit.
    pub fn with_cache_clean(
        mut self,
        operations: crate::x86_64::cache_clean::Operations,
    ) -> Result<Self, CompileError> {
        if !operations.is_empty() && self.profile != BlockProfile::SystemModeV1 {
            return Err(CompileError(format!(
                "{:?} keeps the DC clean operations' System exit",
                self.profile
            )));
        }
        self.native.cache_clean = operations;
        Ok(self)
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
            // Only system mode runs one agent at a time and checks the
            // guest's ranges; every other profile keeps the locked recipes
            // and the default checks (`with_memory_checks`).
            let (native, fault_recovery) = if self.profile == BlockProfile::SystemModeV1 {
                crate::x86_64::block::emit_system_mode(
                    &self.parsed.instructions,
                    self.parsed.terminal.as_ref(),
                    self.parsed.next_pc,
                    self.target,
                    self.checks,
                    self.native,
                )
            } else {
                (
                    crate::x86_64::block::emit_ordinary_for_target(
                        &self.parsed.instructions,
                        self.parsed.terminal.as_ref(),
                        self.parsed.next_pc,
                        self.target,
                    ),
                    alloc::vec::Vec::new(),
                )
            };
            let direct_exits = crate::x86_64::block::successor_exits(
                &native.x86_64_code,
                self.parsed.terminal.as_ref(),
                self.parsed.next_pc,
            );
            return Ok(CompiledBlock {
                native,
                source_bytes: self.parsed.source_bytes,
                direct_exits,
                fault_recovery,
            });
        };
        Ok(CompiledBlock {
            native,
            source_bytes: self.parsed.source_bytes,
            direct_exits: alloc::vec::Vec::new(),
            fault_recovery: alloc::vec::Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn one_parse_analyzes_and_plans_the_block_it_finds() {
        const BASE: GuestAddress = GuestAddress(0x4000);
        // add x0, x0, #1; ret; then a word after the block
        let source: Vec<u8> = [0x9100_0400_u32, 0xd65f_03c0, 0x9100_0400]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        for profile in [BlockProfile::Ordinary, BlockProfile::SystemModeV1] {
            let target = crate::TargetCpu::Baseline;
            let (analysis, plan) = analyze_and_plan(&source, BASE, profile, target).unwrap();
            assert_eq!(
                analysis,
                analyze_with_profile(&source, BASE, profile).unwrap()
            );
            let consumed = &source[..analysis.source_bytes];
            assert_eq!(consumed.len(), 8);
            // CompiledBlock has no PartialEq; its Debug form shows every field.
            assert_eq!(
                alloc::format!("{:?}", plan.unwrap().compile().unwrap()),
                alloc::format!(
                    "{:?}",
                    compile_for_target(consumed, BASE, profile, target).unwrap()
                )
            );
        }
        assert!(
            analyze_and_plan(
                &[],
                BASE,
                BlockProfile::Ordinary,
                crate::TargetCpu::Baseline
            )
            .is_err()
        );
    }

    #[test]
    fn el1_direct_branch_profile_is_exact_no_memory_and_source_derived() {
        let profile = BlockProfile::El1DirectBranchV1;
        assert_ne!(profile.abi(), BlockProfile::Ordinary.abi());
        assert_ne!(profile.abi(), BlockProfile::SystemV1.abi());
        assert!(profile.checked_memory().is_none());
        assert!(!profile.supports_system());
        for (word, target) in [
            (0x1400_0000_u32, 0x1000),
            (0x1400_0002, 0x1008),
            (0x17ff_ffff, 0x0ffc),
        ] {
            let source = word.to_le_bytes();
            let analysis = analyze_with_profile(&source, GuestAddress(0x1000), profile).unwrap();
            assert_eq!(analysis.source_bytes, source.len());
            assert_eq!(analysis.terminator_pc, Some(GuestAddress(0x1000)));
            assert_eq!(
                analysis.static_successors,
                vec![StaticSuccessor {
                    kind: SuccessorKind::Direct,
                    target: GuestAddress(target)
                }]
            );
            assert!(
                analysis.dynamic_edge.is_none()
                    && analysis.trap.is_none()
                    && analysis.system_instruction.is_none()
            );
            let plan = CompilationPlan::new(
                &source,
                GuestAddress(0x1000),
                profile,
                crate::TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(plan.source_bytes(), source.len());
            assert!(plan.memory_requirements().is_none());
            let emitted = plan.compile().unwrap();
            assert_eq!(emitted.source_bytes, source.len());
            assert_eq!(emitted.native.source_map, vec![(GuestAddress(0x1000), 0)]);
        }
        for word in [
            0xd503_201f_u32,
            0x9400_0000,
            0xd61f_0000,
            0xd65f_03c0,
            0x5400_0000,
            0xf940_0000,
            0xd400_0001,
        ] {
            assert!(
                CompilationPlan::new(
                    &word.to_le_bytes(),
                    GuestAddress(0x1000),
                    profile,
                    crate::TargetCpu::Baseline
                )
                .is_err()
            );
        }
        for source in [
            vec![],
            vec![0],
            vec![0; 3],
            [0x1400_0000_u32, 0x1400_0000]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        ] {
            assert!(
                CompilationPlan::new(
                    &source,
                    GuestAddress(0x1000),
                    profile,
                    crate::TargetCpu::Baseline
                )
                .is_err()
            );
        }
        assert!(
            CompilationPlan::new(
                &0x1400_0000_u32.to_le_bytes(),
                GuestAddress(0x1001),
                profile,
                crate::TargetCpu::Baseline
            )
            .is_err()
        );
    }

    #[test]
    fn system_mode_blocks_can_omit_the_sp_alignment_check() {
        const SP_CHECK: [u8; 6] = [0xa8, 15, 0x74, 2, 0x0f, 0x0b];
        // ldr x0, [sp, #8]; stp x0, x1, [sp, #-16]!; ldr q0, [sp, x2];
        // ldar x3, [sp]; ldadd x4, x5, [sp]
        let source: Vec<u8> = [
            0xf940_07e0_u32,
            0xa9bf_07e0,
            0x3ce2_6be0,
            0xc8df_ffe3,
            0xf824_03e5,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        let compile = |checked| {
            CompilationPlan::new(
                &source,
                GuestAddress(0x1000),
                BlockProfile::SystemModeV1,
                crate::TargetCpu::detect(),
            )
            .and_then(|plan| {
                plan.with_memory_checks(crate::x86_64::MemoryChecks {
                    stack_alignment: checked,
                    ..crate::x86_64::MemoryChecks::DEFAULT
                })
            })
            .and_then(CompilationPlan::compile)
            .unwrap()
            .native
            .x86_64_code
        };
        let has_check = |code: &[u8]| code.windows(SP_CHECK.len()).any(|bytes| bytes == SP_CHECK);
        assert!(has_check(&compile(true)));
        assert!(!has_check(&compile(false)));
        // Only the system-mode profile admits it.
        assert!(
            CompilationPlan::new(
                &source[..4],
                GuestAddress(0x1000),
                BlockProfile::Ordinary,
                crate::TargetCpu::Baseline
            )
            .and_then(|plan| plan.with_memory_checks(crate::x86_64::MemoryChecks {
                stack_alignment: false,
                ..crate::x86_64::MemoryChecks::DEFAULT
            }))
            .is_err()
        );
    }

    /// Every access of a system-mode block, in a clean-load region or not,
    /// checks its address against the guest's ranges before it is made;
    /// process blocks make no such check.
    #[test]
    fn system_mode_blocks_check_every_access_against_the_guest_ranges() {
        use crate::x86_64::GUEST_RANGE_CHECK;
        let count = |code: &[u8]| {
            code.windows(GUEST_RANGE_CHECK.len())
                .filter(|bytes| *bytes == GUEST_RANGE_CHECK)
                .count()
        };
        let compile = |words: &[u32], profile, plan: fn(CompilationPlan) -> CompilationPlan| {
            let source: Vec<u8> = words.iter().copied().flat_map(u32::to_le_bytes).collect();
            CompilationPlan::new(
                &source,
                GuestAddress(0x1000),
                profile,
                crate::TargetCpu::detect(),
            )
            .map(plan)
            .and_then(CompilationPlan::compile)
            .unwrap()
            .native
            .x86_64_code
        };
        // ldr w0, [x1]; add w0, w0, #1; ldr x0, [x1, #8]; ldp w2, w3, [x1];
        // ldr h0, [x1, x2]; ld1 {v0.4s}, [x1]; ldr x4, <literal>; ldadd x4,
        // x5, [x1]; ldar w6, [x1]; stlr w6, [x1]; ldnp x8, x9, [x1];
        // str x0, [x1]; ldr q0, [x1]; stp q0, q1, [x1]; prfm pldl1keep, [x1]
        let words = [
            0xb940_0020_u32,
            0x1100_0400,
            0xf940_0420,
            0x2940_0c22,
            0x7c62_6820,
            0x4c40_7820,
            0x5800_0084,
            0xf824_0025,
            0x88df_fc26,
            0x889f_fc26,
            0xa840_2428,
            0xf900_0020,
            0x3dc0_0020,
            0xad00_0420,
            0xf980_0020,
        ];
        // Alone, each access checks, but the prefetch, which never faults.
        for (index, word) in words.into_iter().enumerate() {
            let alone = compile(&[word], BlockProfile::SystemModeV1, |plan| plan);
            assert_eq!(
                count(&alone),
                usize::from(![1, 14].contains(&index)),
                "{word:#x}"
            );
        }
        // Together, an immediate-offset access through X1 after another
        // needs none (`x86_64::guest_range`): the SIMD register offset,
        // which forgets every base, makes the LD1 check again, and the
        // literal always checks.
        let system = compile(&words, BlockProfile::SystemModeV1, |plan| plan);
        assert_eq!(count(&system), 4);
        // Under FEAT_CSV3 each access checks, so each masks its own address.
        let masked = compile(&words, BlockProfile::SystemModeV1, |plan| {
            plan.with_memory_checks(crate::x86_64::MemoryChecks::system(true, false, true, true))
                .unwrap()
        });
        assert_eq!(count(&masked), words.len() - 2);
        assert_eq!(
            count(&compile(&words, BlockProfile::Ordinary, |plan| plan)),
            0
        );
        // DC ZVA and DC CVAC completed natively check Xt.
        let zero = compile(&[0xd50b_7423], BlockProfile::SystemModeV1, |plan| {
            plan.with_zero_block(Some(64)).unwrap()
        });
        let clean = compile(&[0xd50b_7a20], BlockProfile::SystemModeV1, |plan| {
            plan.with_cache_clean(crate::x86_64::cache_clean::Operations::ALL)
                .unwrap()
        });
        assert_eq!((count(&zero), count(&clean)), (1, 1));
    }

    #[test]
    fn system_mode_blocks_check_sctlr_a_and_the_ordered_granule_when_asked() {
        // ldr x0, [x1, #8]; ldp w2, w3, [x1]; ldr h0, [x1, x2]; ld1 {v0.4s},
        // [x1]; ldr x4, <literal>; ldadd x4, x5, [x1]; ldar w6, [x1];
        // stlr w6, [x1].
        let words = [
            0xf940_0420_u32,
            0x2940_0c22,
            0x7c62_6820,
            0x4c40_7820,
            0x5800_0084,
            0xf824_0025,
            0x88df_fc26,
            0x889f_fc26,
        ];
        let source: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let compile = |checks| {
            CompilationPlan::new(
                &source,
                GuestAddress(0x1000),
                BlockProfile::SystemModeV1,
                crate::TargetCpu::detect(),
            )
            .and_then(|plan| plan.with_memory_checks(checks))
            .and_then(CompilationPlan::compile)
            .unwrap()
            .native
            .x86_64_code
        };
        // test al,unit-1; jz +2; ud2 for each element size.
        let check = |unit: u8| [0xa8, unit - 1, 0x74, 2, 0x0f, 0x0b];
        let count = |code: &[u8], unit: u8| {
            code.windows(6)
                .filter(|bytes| *bytes == check(unit))
                .count()
        };
        let default = compile(crate::x86_64::MemoryChecks::DEFAULT);
        assert_eq!([2, 4, 8].map(|unit| count(&default, unit)), [0, 0, 0]);
        let aligned = compile(crate::x86_64::MemoryChecks {
            alignment: true,
            ..crate::x86_64::MemoryChecks::DEFAULT
        });
        // LDR H and the halfword vector are 2; LDP W, LD1 .4S, LDAR and STLR
        // W are 4; LDR X, the literal and LDADD X are 8.
        assert_eq!([2, 4, 8].map(|unit| count(&aligned, unit)), [1, 4, 3]);
        // Without the granule check (nAA set) the ordered accesses keep a
        // crossing path; the atomic keeps its LSE2 granule check.
        let granule = |code: &[u8]| {
            code.windows(4)
                .filter(|bytes| *bytes == [0x80, 0xf9, 16 - 4, 0x76])
                .count()
        };
        let relaxed = compile(crate::x86_64::MemoryChecks {
            ordered_granule: false,
            ..crate::x86_64::MemoryChecks::DEFAULT
        });
        assert_eq!(granule(&default), 2);
        assert_eq!(granule(&relaxed), 0);
        assert_ne!(default, relaxed);
    }

    /// The direct exits a system-mode block reports are the exact stubs at
    /// the end of its code, the conditional fallthrough before the target.
    #[test]
    fn system_mode_blocks_report_their_direct_successor_exits() {
        use crate::x86_64::chain::{DIRECT_EXIT_BYTES, direct_exit};
        const BASE: u64 = 0x4000;
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        let fallthrough = (BASE + 8, ExitKind::Fallthrough);
        for (word, expected) in [
            (0x1400_0002_u32, vec![(BASE + 12, ExitKind::Direct)]), // b +8
            (
                0x5400_0040,
                vec![fallthrough, (BASE + 12, ExitKind::Direct)],
            ), // b.eq +8
            (0x5400_004e, vec![(BASE + 12, ExitKind::Direct)]),     // b.al +8
            (
                0xb400_0040,
                vec![fallthrough, (BASE + 12, ExitKind::Direct)],
            ), // cbz x0, +8
            (
                0x3700_0040,
                vec![fallthrough, (BASE + 12, ExitKind::Direct)],
            ), // tbnz w0, #0, +8
            (0x9400_0002, vec![(BASE + 12, ExitKind::Call)]),       // bl +8
            (ADD, vec![fallthrough]),
            (0xd65f_03c0, vec![]), // ret
            (0xd63f_0000, vec![]), // blr x0
            (0xd518_1000, vec![]), // msr sctlr_el1, x0
        ] {
            let source: Vec<u8> = [ADD, word].into_iter().flat_map(u32::to_le_bytes).collect();
            let compiled = compile_for_target(
                &source,
                GuestAddress(BASE),
                BlockProfile::SystemModeV1,
                crate::TargetCpu::Baseline,
            )
            .unwrap();
            let code = &compiled.native.x86_64_code;
            let exits: Vec<_> = compiled
                .direct_exits
                .iter()
                .map(|exit| {
                    assert_eq!(
                        code[exit.offset..exit.offset + DIRECT_EXIT_BYTES],
                        direct_exit(exit.target, exit.kind)
                    );
                    (exit.target.0, exit.kind)
                })
                .collect();
            assert_eq!(exits, expected, "{word:#x}");
            if let Some(last) = compiled.direct_exits.last() {
                assert_eq!(last.offset + DIRECT_EXIT_BYTES, code.len(), "{word:#x}");
            }
        }
    }

    /// With a DC ZVA block size, a terminal DC ZVA zeroes natively and falls
    /// through a chainable direct exit; every other System instruction, and
    /// DC ZVA without one, keeps its System exit.
    #[test]
    fn system_mode_blocks_complete_dc_zva_natively_only_with_a_block_size() {
        use crate::x86_64::chain::{DIRECT_EXIT_BYTES, direct_exit};
        const BASE: u64 = 0x4000;
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const DC_ZVA: u32 = 0xd50b_7423; // dc zva, x3
        const DC_GVA: u32 = 0xd50b_7463; // dc gva, x3
        const MRS: u32 = 0xd538_d080; // mrs x0, tpidr_el1
        let compile = |word: u32, bytes| {
            let source: Vec<u8> = [ADD, word, ADD]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            CompilationPlan::new(
                &source,
                GuestAddress(BASE),
                BlockProfile::SystemModeV1,
                crate::TargetCpu::Baseline,
            )
            .and_then(|plan| plan.with_zero_block(bytes))
            .and_then(CompilationPlan::compile)
            .unwrap()
        };
        let native = compile(DC_ZVA, Some(64));
        assert_eq!(native.source_bytes, 8, "DC ZVA still ends the block");
        let code = &native.native.x86_64_code;
        let at = native.native.source_map[1].1;
        let mut zeroing = Vec::new();
        crate::x86_64::zero_block::emit(&mut zeroing, 3, 64);
        assert_eq!(code[at..at + zeroing.len()], zeroing);
        let next = GuestAddress(BASE + 8);
        assert_eq!(
            code[at + zeroing.len()..],
            direct_exit(next, ExitKind::Fallthrough)
        );
        assert_eq!(native.direct_exits.len(), 1);
        assert_eq!(
            (native.direct_exits[0].target, native.direct_exits[0].kind),
            (next, ExitKind::Fallthrough)
        );
        assert_eq!(
            native.direct_exits[0].offset + DIRECT_EXIT_BYTES,
            code.len()
        );
        let system = direct_exit(GuestAddress(BASE + 4), ExitKind::System);
        for (word, bytes) in [(DC_ZVA, None), (DC_GVA, Some(64)), (MRS, Some(64))] {
            let compiled = compile(word, bytes);
            let code = &compiled.native.x86_64_code;
            assert_eq!(code[code.len() - DIRECT_EXIT_BYTES..], system, "{word:#x}");
            assert!(compiled.direct_exits.is_empty(), "{word:#x}");
        }
        let plan = |profile| {
            CompilationPlan::new(
                &ADD.to_le_bytes(),
                GuestAddress(BASE),
                profile,
                crate::TargetCpu::Baseline,
            )
            .unwrap()
        };
        for bytes in [2, 48, 4096] {
            assert!(
                plan(BlockProfile::SystemModeV1)
                    .with_zero_block(Some(bytes))
                    .is_err()
            );
        }
        assert!(
            plan(BlockProfile::SystemV1)
                .with_zero_block(Some(64))
                .is_err()
        );
        assert!(plan(BlockProfile::SystemV1).with_zero_block(None).is_ok());
    }

    /// A DC clean operation in the plan's set reads the byte at Xt and falls
    /// through; one outside it, and DC IVAC, keep the System exit.
    #[test]
    fn planned_dc_clean_operations_check_xt_and_fall_through() {
        use crate::x86_64::cache_clean::Operations;
        use crate::x86_64::chain::{DIRECT_EXIT_BYTES, direct_exit};
        const BASE: u64 = 0x4000;
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const DC_CIVAC: u32 = 0xd50b_7e20; // dc civac, x0
        const DC_CVAU: u32 = 0xd50b_7b20; // dc cvau, x0
        const DC_IVAC: u32 = 0xd508_7620; // dc ivac, x0
        let compile = |word: u32, operations| {
            let source: Vec<u8> = [ADD, word, ADD]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            CompilationPlan::new(
                &source,
                GuestAddress(BASE),
                BlockProfile::SystemModeV1,
                crate::TargetCpu::Baseline,
            )
            .and_then(|plan| plan.with_cache_clean(operations))
            .and_then(CompilationPlan::compile)
            .unwrap()
        };
        let native = compile(DC_CIVAC, Operations::CIVAC);
        assert_eq!(native.source_bytes, 8, "the DC still ends the block");
        let code = &native.native.x86_64_code;
        let at = native.native.source_map[1].1;
        let mut check = Vec::new();
        crate::x86_64::cache_clean::emit(&mut check, 0);
        assert_eq!(code[at..at + check.len()], check);
        let next = GuestAddress(BASE + 8);
        assert_eq!(
            code[at + check.len()..],
            direct_exit(next, ExitKind::Fallthrough)
        );
        assert_eq!(native.direct_exits.len(), 1);
        assert_eq!(native.direct_exits[0].target, next);
        let system = direct_exit(GuestAddress(BASE + 4), ExitKind::System);
        for (word, operations) in [
            (DC_CIVAC, Operations::CVAC.with(Operations::CVAU)),
            (DC_CVAU, Operations::NONE),
            (DC_IVAC, Operations::ALL),
        ] {
            let compiled = compile(word, operations);
            let code = &compiled.native.x86_64_code;
            assert_eq!(code[code.len() - DIRECT_EXIT_BYTES..], system, "{word:#x}");
        }
        let plan = CompilationPlan::new(
            &ADD.to_le_bytes(),
            GuestAddress(BASE),
            BlockProfile::SystemV1,
            crate::TargetCpu::Baseline,
        )
        .unwrap();
        assert!(plan.with_cache_clean(Operations::CVAC).is_err());
    }

    #[test]
    fn system_mode_profile_keeps_ordinary_memory_and_exits_on_system_instructions() {
        const BASE: GuestAddress = GuestAddress(0x4000);
        const ADD: u32 = 0x9100_0400; // add x0, x0, #1
        const LDR: u32 = 0xf940_0020; // ldr x0, [x1]
        const STP: u32 = 0xa900_0be1; // stp x1, x2, [sp]
        const DMB: u32 = 0xd503_3bbf; // dmb ish
        const YIELD: u32 = 0xd503_203f;
        const NOP: u32 = 0xd503_201f;
        const BTI_C: u32 = 0xd503_245f;
        let profile = BlockProfile::SystemModeV1;
        assert_eq!(profile.abi(), SYSTEM_MODE_BLOCK_ABI);
        assert!(profile.supports_system() && profile.supports_system_registers());
        assert!(profile.supports_pointer_authentication());
        assert!(profile.checked_memory().is_none() && !profile.supports_clock());
        let prefix = [ADD, LDR, STP, DMB, YIELD, NOP, BTI_C];
        for (word, kind) in [
            (0xd518_1000_u32, ExitKind::System), // msr sctlr_el1, x0
            (0xd538_d080, ExitKind::System),     // mrs x0, tpidr_el1
            (0xd500_43df, ExitKind::System),     // msr daifset, #3
            (0xd508_8723, ExitKind::System),     // tlbi vae1, x3
            (0xd50b_7420, ExitKind::System),     // dc zva, x0
            (0xd50b_7520, ExitKind::System),     // ic ivau, x0
            (0xd503_3f9f, ExitKind::System),     // dsb sy
            (0xd503_3fdf, ExitKind::System),     // isb
            (0xd503_207f, ExitKind::System),     // wfi
            (0xd400_0001, ExitKind::System),     // svc #0
            (0xd400_0002, ExitKind::System),     // hvc #0
            (0xd69f_03e0, ExitKind::System),     // eret
            (0x0000_0000, ExitKind::System),     // udf #0
            (0x0020_1420, ExitKind::System),     // genter (Apple GXF)
            (0x0020_1400, ExitKind::System),     // gexit (Apple GXF)
            (0xc04c_73e5, ExitKind::System),     // movt x5, zt0[7] (Debug state)
            (0xc04e_03e0, ExitKind::System),     // movt zt0[0], x0 (Debug state)
            (0xd503_237f, ExitKind::PointerAuthentication), // pacibsp
            (0x0020_1220, ExitKind::Amx),        // AMX set
            (0x0020_1003, ExitKind::Amx),        // AMX ldx x3
            (0x0020_12e0, ExitKind::Amx),        // AMX operation 23
        ] {
            let source: Vec<u8> = prefix
                .iter()
                .chain([word, ADD].iter())
                .flat_map(|word| word.to_le_bytes())
                .collect();
            let terminal_pc = GuestAddress(BASE.0 + 4 * prefix.len() as u64);
            let analysis = analyze_with_profile(&source, BASE, profile).unwrap();
            assert_eq!(analysis.terminator_pc, Some(terminal_pc), "{word:#x}");
            assert_eq!(analysis.source_bytes, 4 * (prefix.len() + 1));
            let compiled =
                compile_for_target(&source, BASE, profile, crate::TargetCpu::Baseline).unwrap();
            let map = &compiled.native.source_map;
            assert_eq!(map.len(), prefix.len() + 1, "{word:#x}");
            assert!(
                map.iter()
                    .enumerate()
                    .all(|(index, (pc, _))| pc.0 == BASE.0 + 4 * index as u64)
            );
            let at = map.last().unwrap().1;
            let mut expected = vec![0x48, 0xb8];
            expected.extend(terminal_pc.0.to_le_bytes());
            expected.push(0xba);
            expected.extend((kind as u32).to_le_bytes());
            expected.push(0xc3);
            assert_eq!(&compiled.native.x86_64_code[at..], expected, "{word:#x}");
        }
        // Ordinary-only prefixes use the ordinary emitter and its regions,
        // which settle the frame before every access and exit, except under
        // SCTLR_ELx.A, whose checks their loads lack, with each access's
        // guest range check.
        let ordinary: Vec<u8> = [ADD, LDR, ADD, ADD, ADD, 0x1400_0000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let parsed = analysis::parse(&ordinary, BASE, profile).unwrap();
        let expected = crate::x86_64::block::emit_ordinary_for_target(
            &parsed.instructions,
            parsed.terminal.as_ref(),
            parsed.next_pc,
            crate::TargetCpu::Baseline,
        );
        let compiled =
            compile_for_target(&ordinary, BASE, profile, crate::TargetCpu::Baseline).unwrap();
        let check = crate::x86_64::GUEST_RANGE_CHECK;
        let mut unchecked = compiled.native.x86_64_code.clone();
        let at = unchecked
            .windows(check.len())
            .position(|bytes| bytes == check)
            .expect("the load checks its address");
        unchecked.drain(at..at + check.len());
        assert_eq!(unchecked, expected.x86_64_code);
        let aligned = crate::x86_64::MemoryChecks {
            alignment: true,
            ..crate::x86_64::MemoryChecks::DEFAULT
        };
        let expected = crate::x86_64::block::emit_for_target(
            &parsed.instructions,
            parsed.terminal.as_ref(),
            parsed.next_pc,
            crate::TargetCpu::Baseline,
            crate::x86_64::MemoryChecks {
                guest_range: true,
                single_agent: true,
                ..aligned
            },
        );
        let compiled = CompilationPlan::new(&ordinary, BASE, profile, crate::TargetCpu::Baseline)
            .unwrap()
            .with_memory_checks(aligned)
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(compiled.native.x86_64_code, expected.x86_64_code);
        assert_ne!(expected.x86_64_code.len(), 0);
        // The trap and system decoders of other profiles do not see SYS.
        assert!(
            analyze_with_profile(&0xd508_8723_u32.to_le_bytes(), BASE, BlockProfile::SystemV1)
                .is_err()
        );
    }

    #[test]
    fn system_mode_compiles_for_a_single_agent_without_cmpxchg16b_or_locks() {
        const BASE: GuestAddress = GuestAddress(0x1000);
        // casp x2, x3, x2, x3, [x4] (Rs = Rt), ldar x0, [x1], dmb sy, b .
        const CASP_X2_X3_X4: u32 = 0x4822_7c82;
        const LDAR_X0_X1: u32 = 0xc8df_fc20;
        const DMB_SY: u32 = 0xd503_3fbf;
        const B_SELF: u32 = 0x1400_0000;
        const LOCK: u8 = 0xf0;
        const MFENCE: [u8; 3] = [0x0f, 0xae, 0xf0];
        let source: Vec<u8> = [CASP_X2_X3_X4, LDAR_X0_X1, DMB_SY, B_SELF]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        // The baseline target has neither CMPXCHG16B nor the aligned 16-byte
        // load, which only another agent could tell apart.
        for profile in [BlockProfile::Ordinary, BlockProfile::SystemModeV1] {
            let plan = CompilationPlan::new(&source, BASE, profile, crate::TargetCpu::Baseline);
            assert_eq!(plan.is_ok(), profile == BlockProfile::SystemModeV1);
        }
        let code = CompilationPlan::new(
            &source,
            BASE,
            BlockProfile::SystemModeV1,
            crate::TargetCpu::Baseline,
        )
        .unwrap()
        .compile()
        .unwrap()
        .native
        .x86_64_code;
        assert!(!code.contains(&LOCK), "{code:02x?}");
        assert!(!code.windows(MFENCE.len()).any(|window| window == MFENCE));
    }

    /// A fault applies exactly the entries covering its offset, SP as 31.
    #[test]
    fn fault_recovery_applies_the_covering_entries() {
        let table = [
            FaultRecovery {
                start: 4,
                end: 10,
                registers: vec![(3, 9), (31, 6)],
            },
            FaultRecovery {
                start: 10,
                end: 20,
                registers: vec![(4, 10)],
            },
        ];
        let host: [u64; 16] = core::array::from_fn(|register| 0x100 + register as u64);
        let mut state = crate::GuestState::default();
        FaultRecovery::apply(&table, 9, &host, &mut state);
        assert_eq!((state.x[3], state.sp, state.x[4]), (0x109, 0x106, 0));
        let mut state = crate::GuestState::default();
        FaultRecovery::apply(&table, 10, &host, &mut state);
        assert_eq!((state.x[3], state.sp, state.x[4]), (0, 0, 0x10a));
        let mut state = crate::GuestState::default();
        FaultRecovery::apply(&table, 3, &host, &mut state);
        assert_eq!(state, crate::GuestState::default());
    }

    /// The process and service profiles share the Ordinary emission of an
    /// ordinary prefix: locked atomics and no guest range checks, which
    /// belong to the system-mode engine alone.
    #[test]
    fn only_system_mode_compiles_for_a_single_agent_with_range_checks() {
        const BASE: GuestAddress = GuestAddress(0x1000);
        // ldaddal x1, x0, [x2]; ldr x3, [x4]; add x0, x0, #1; b .
        let source: Vec<u8> = [0xf8e1_0040_u32, 0xf940_0083, 0x9100_0400, 0x1400_0000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let code = |profile| {
            compile_for_target(&source, BASE, profile, crate::TargetCpu::Baseline)
                .unwrap()
                .native
                .x86_64_code
        };
        let ordinary = code(BlockProfile::Ordinary);
        for profile in [
            BlockProfile::DarwinArm64ThreadV1,
            BlockProfile::AppleArm64eSoftwarePauthV1,
            BlockProfile::AppleArm64eSoftwarePauthClockV1,
            BlockProfile::AppleArm64eSoftwarePauthThreadV1,
            BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
        ] {
            assert_eq!(code(profile), ordinary, "{profile:?}");
        }
        let check = crate::x86_64::GUEST_RANGE_CHECK;
        let has_check = |code: &[u8]| code.windows(check.len()).any(|bytes| bytes == check);
        assert!(!has_check(&ordinary));
        let system = code(BlockProfile::SystemModeV1);
        assert!(has_check(&system));
        assert_ne!(system, ordinary);
    }

    #[test]
    fn system_profile_has_one_source_bound_exit_and_rejects_memory_prefixes() {
        const BASE: GuestAddress = GuestAddress(0x1000);
        const ADD: u32 = 0x9100_0400;
        const SVC: u32 = 0xd400_0001;
        const UDF: u32 = 0x0000_0042;
        const IRG: u32 = 0x9ac0_1000;
        const LDG: u32 = 0xd960_0000;
        const RETURN: u8 = 0xc3;
        const MOV_RAX_IMMEDIATE: [u8; 2] = [0x48, 0xb8];
        const MOV_EDX_IMMEDIATE: u8 = 0xba;
        for word in [SVC, UDF, IRG, LDG] {
            let source: Vec<_> = [ADD, word, ADD]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let analysis = analyze_with_profile(&source, BASE, BlockProfile::SystemV1).unwrap();
            let instruction = analysis.system_instruction.unwrap();
            assert_eq!(analysis.source_bytes, 2 * size_of::<u32>());
            assert_eq!(
                instruction.instruction_pc,
                GuestAddress(BASE.0 + size_of::<u32>() as u64)
            );
            let compiled = compile_for_target(
                &source,
                BASE,
                BlockProfile::SystemV1,
                crate::TargetCpu::Baseline,
            )
            .unwrap();
            let at = compiled.native.source_map.last().unwrap().1;
            let mut expected = MOV_RAX_IMMEDIATE.to_vec();
            expected.extend(instruction.instruction_pc.0.to_le_bytes());
            expected.push(MOV_EDX_IMMEDIATE);
            expected.extend((ExitKind::System as u32).to_le_bytes());
            expected.push(RETURN);
            assert_eq!(&compiled.native.x86_64_code[at..], expected);
        }
        // Ordinary RAM, exclusives and legacy FP/SIMD cannot bypass shared owners.
        for word in [0xf940_0000_u32, 0xf900_0000, 0xc85f_fc00, 0x1e20_2800] {
            let source: Vec<_> = [word, SVC].into_iter().flat_map(u32::to_le_bytes).collect();
            assert!(analyze_with_profile(&source, BASE, BlockProfile::SystemV1).is_err());
        }
        assert_eq!(
            ExitKind::try_from(ExitKind::System as u64),
            Ok(ExitKind::System)
        );
        assert_ne!(BlockProfile::SystemV1.abi(), BlockProfile::Ordinary.abi());
        assert!(
            analyze_with_profile(&SVC.to_le_bytes(), BASE, BlockProfile::Ordinary)
                .unwrap()
                .trap
                .is_some()
        );
    }
    use super::*;

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn unconditional_half_helpers_share_exact_consumption_analysis_and_emission() {
        const NOP: u32 = 0xd503201f;
        const UNSUPPORTED: u32 = 0xffffffff;
        const HALF_OPERATIONS: [u32; 12] = [
            0x1ee02800, // FADD H0,H0,H0
            0x1ee03800, // FSUB H0,H0,H0
            0x1ee00800, // FMUL H0,H0,H0
            0x1ee01800, // FDIV H0,H0,H0
            0x0e401400, // FADD V0.4H,V0.4H,V0.4H
            0x0ec01400, // FSUB V0.4H,V0.4H,V0.4H
            0x2e401c00, // FMUL V0.4H,V0.4H,V0.4H
            0x2e403c00, // FDIV V0.4H,V0.4H,V0.4H
            0x4e401400, // FADD V0.8H,V0.8H,V0.8H
            0x4ec01400, // FSUB V0.8H,V0.8H,V0.8H
            0x6e401c00, // FMUL V0.8H,V0.8H,V0.8H
            0x6e403c00, // FDIV V0.8H,V0.8H,V0.8H
        ];
        let base = GuestAddress(0x1000);
        let helper_pc = GuestAddress(base.0 + size_of::<u32>() as u64);
        let continuation = GuestAddress(helper_pc.0 + size_of::<u32>() as u64);
        for operation in HALF_OPERATIONS {
            for profile in [
                BlockProfile::Ordinary,
                BlockProfile::AppleArm64eSoftwarePauthV1,
                BlockProfile::AppleArm64eSoftwarePauthClockV1,
                BlockProfile::DarwinArm64ThreadV1,
                BlockProfile::AppleArm64eSoftwarePauthThreadV1,
                BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
            ] {
                let source = bytes(&[NOP, operation, UNSUPPORTED]);
                let analysis = analyze_with_profile(&source, base, profile).unwrap();
                let compiled = compile_with_profile(&source, base, profile).unwrap();
                assert_eq!(analysis.source_bytes, 2 * size_of::<u32>());
                assert_eq!(compiled.source_bytes, analysis.source_bytes);
                assert_eq!(
                    source_bytes_with_profile(&source, base, profile).unwrap(),
                    analysis.source_bytes
                );
                assert_eq!(analysis.terminator_pc, Some(helper_pc));
                assert_eq!(analysis.dynamic_edge, None);
                assert_eq!(
                    analysis.static_successors,
                    [StaticSuccessor {
                        kind: SuccessorKind::Fallthrough,
                        target: continuation,
                    }]
                );
                assert_eq!(compiled.native.source_map.len(), 2);
                assert_eq!(compiled.native.source_map[1].0, helper_pc);
                let mut helper = vec![0x48, 0xb8]; // MOVABS RAX,original PC
                helper.extend(helper_pc.0.to_le_bytes());
                helper.push(0xba); // MOV EDX,FloatingPoint; RET
                helper.extend((ExitKind::FloatingPoint as u32).to_le_bytes());
                helper.push(0xc3);
                let offset = compiled.native.source_map[1].1;
                assert_eq!(&compiled.native.x86_64_code[offset..], helper);
                let suffix = &source[analysis.source_bytes..];
                assert_eq!(
                    analyze_with_profile(suffix, continuation, profile)
                        .unwrap_err()
                        .pc,
                    continuation
                );
            }
        }
    }

    #[test]
    fn analysis_shares_consumed_prefix_and_reports_static_and_dynamic_transfer_roles() {
        let base = GuestAddress(0x1000);
        for (word, kinds, targets, dynamic) in [
            (0x14000002, vec![SuccessorKind::Direct], vec![0x1008], None),
            (
                0x54000040,
                vec![
                    SuccessorKind::ConditionalTarget,
                    SuccessorKind::ConditionalFallthrough,
                ],
                vec![0x1008, 0x1004],
                None,
            ),
            (
                0xb4000040,
                vec![
                    SuccessorKind::ConditionalTarget,
                    SuccessorKind::ConditionalFallthrough,
                ],
                vec![0x1008, 0x1004],
                None,
            ),
            (
                0x36000040,
                vec![
                    SuccessorKind::ConditionalTarget,
                    SuccessorKind::ConditionalFallthrough,
                ],
                vec![0x1008, 0x1004],
                None,
            ),
            (
                0x94000002,
                vec![SuccessorKind::CallTarget, SuccessorKind::CallContinuation],
                vec![0x1008, 0x1004],
                None,
            ),
            (
                0xd61f0120,
                vec![],
                vec![],
                Some((DynamicEdgeKind::Branch, 9)),
            ),
            (
                0xd63f0120,
                vec![SuccessorKind::CallContinuation],
                vec![0x1004],
                Some((DynamicEdgeKind::Call, 9)),
            ),
            (
                0xd65f03c0,
                vec![],
                vec![],
                Some((DynamicEdgeKind::Return, 30)),
            ),
            (
                0xd61f03e0,
                vec![],
                vec![],
                Some((DynamicEdgeKind::Branch, 31)),
            ),
        ] {
            let source = bytes(&[word, 0]);
            let analysis = analyze(&source, base).unwrap();
            assert_eq!(analysis.source_bytes, source_bytes(&source, base).unwrap());
            assert_eq!(
                analysis.source_bytes,
                compile(&source, base).unwrap().source_bytes
            );
            assert_eq!(analysis.source_bytes, 4);
            assert_eq!(
                analysis
                    .static_successors
                    .iter()
                    .map(|edge| edge.kind)
                    .collect::<Vec<_>>(),
                kinds
            );
            assert_eq!(
                analysis
                    .static_successors
                    .iter()
                    .map(|edge| edge.target.0)
                    .collect::<Vec<_>>(),
                targets
            );
            assert_eq!(
                analysis.dynamic_edge.map(|edge| (edge.kind, edge.register)),
                dynamic
            );
        }
        let linear = analyze(&bytes(&[0xd503201f; 256]), base).unwrap();
        assert_eq!(
            linear.static_successors[0],
            StaticSuccessor {
                kind: SuccessorKind::Fallthrough,
                target: GuestAddress(0x1400)
            }
        );
    }
    #[test]
    fn analysis_reports_exact_decline_pc_and_never_follows_trap_or_post_terminator_data() {
        let base = GuestAddress(0x1000);
        let source = bytes(&[0xd503201f, 0, 0xd65f03c0]);
        let failure = analyze(&source, base).unwrap_err();
        assert_eq!(failure.pc, GuestAddress(0x1004));
        assert!(failure.detail.contains("unsupported"));
        for word in [0xd4001001, 0xd43fffe0] {
            let analysis = analyze(&bytes(&[0xd503201f, word, 0]), base).unwrap();
            assert_eq!(analysis.source_bytes, 8);
            assert!(analysis.static_successors.is_empty());
            assert!(analysis.dynamic_edge.is_none());
            assert!(analysis.trap.is_some());
        }
        assert!(analyze(&[], base).is_err());
        assert!(analyze(&bytes(&[0xd503201f; 257]), base).is_err());
        assert_eq!(
            analyze(&bytes(&[0xd503201f]), GuestAddress(u64::MAX - 3))
                .unwrap_err()
                .pc,
            GuestAddress(u64::MAX - 3)
        );
    }

    #[test]
    fn exit_layout_and_kind_validation_are_explicit() {
        assert_eq!(core::mem::size_of::<BlockExit>(), 16);
        assert_eq!(core::mem::offset_of!(BlockExit, next_pc), 0);
        assert_eq!(core::mem::offset_of!(BlockExit, kind), 8);
        for kind in 0..=ExitKind::Amx as u64 {
            assert_eq!(ExitKind::try_from(kind).unwrap() as u64, kind);
        }
        assert_eq!(ExitKind::try_from(ExitKind::Amx as u64 + 1), Err(()));
        assert_eq!(ExitKind::try_from(u64::MAX), Err(()));
    }

    #[test]
    fn clock_decode_accepts_all_counter_destinations_and_only_exact_controls() {
        let pc = GuestAddress(0x1000);
        for destination in 0..32 {
            assert_eq!(
                decode_clock_instruction(pc, 0xd53be040 | destination).unwrap(),
                Some(ClockInstruction {
                    operation: ClockOperation::ReadVirtualCounter {
                        destination: destination as u8
                    },
                    instruction_pc: pc,
                    next_pc: GuestAddress(pc.0 + 4),
                })
            );
        }
        assert_eq!(
            decode_clock_instruction(pc, 0xd5033fdf).unwrap(),
            Some(ClockInstruction {
                operation: ClockOperation::InstructionSynchronization,
                instruction_pc: pc,
                next_pc: GuestAddress(pc.0 + 4),
            })
        );
        for bit in 5..32 {
            assert!(
                decode_clock_instruction(pc, 0xd53be040 ^ (1 << bit))
                    .unwrap()
                    .is_none()
            );
        }
        for bit in 0..32 {
            assert!(
                decode_clock_instruction(pc, 0xd5033fdf ^ (1 << bit))
                    .unwrap()
                    .is_none()
            );
        }
        // CNTFRQ/CNTPCT/CNTVCTSS, MSR and other barrier options are not claimed.
        for word in [0xd53be000, 0xd53be020, 0xd53be0c0, 0xd51be040, 0xd5033bdf] {
            assert!(decode_clock_instruction(pc, word).unwrap().is_none());
        }
        for word in [0xd53be040, 0xd5033fdf] {
            assert!(decode_clock_instruction(GuestAddress(pc.0 + 1), word).is_err());
            assert!(decode_clock_instruction(GuestAddress(u64::MAX - 3), word).is_err());
        }
    }

    #[test]
    fn clock_profile_boundaries_share_analysis_and_do_not_widen_old_profiles() {
        let base = GuestAddress(0x4000);
        let profile = BlockProfile::AppleArm64eSoftwarePauthClockV1;
        for word in [0xd5033fdf, 0xd53be040, 0xd53be05f] {
            let source = bytes(&[0xd2800020, word, 0]);
            for previous in [
                BlockProfile::Ordinary,
                BlockProfile::AppleArm64eSoftwarePauthV1,
            ] {
                assert_eq!(
                    analyze_with_profile(&source, base, previous)
                        .unwrap_err()
                        .pc,
                    GuestAddress(base.0 + 4)
                );
                assert!(compile_with_profile(&source, base, previous).is_err());
                assert!(source_bytes_with_profile(&source, base, previous).is_err());
            }
            let analysis = analyze_with_profile(&source, base, profile).unwrap();
            let compiled = compile_with_profile(&source, base, profile).unwrap();
            assert_eq!(analysis.source_bytes, 8);
            assert_eq!(compiled.source_bytes, 8);
            assert_eq!(
                source_bytes_with_profile(&source, base, profile).unwrap(),
                8
            );
            let request = analysis.clock_instruction.unwrap();
            assert_eq!(request.instruction_pc, GuestAddress(base.0 + 4));
            assert_eq!(
                analysis.static_successors,
                [StaticSuccessor {
                    kind: SuccessorKind::Fallthrough,
                    target: request.next_pc
                }]
            );
            assert!(
                analysis.dynamic_edge.is_none()
                    && analysis.trap.is_none()
                    && analysis.pointer_authentication.is_none()
            );
            assert_eq!(
                compiled
                    .native
                    .source_map
                    .iter()
                    .map(|(pc, _)| *pc)
                    .collect::<Vec<_>>(),
                [base, request.instruction_pc]
            );
        }
        for word in [0xd503237f, 0xd50323ff, 0xd65f0fff] {
            let source = bytes(&[word, 0]);
            assert_eq!(
                analyze_with_profile(&source, base, profile).unwrap(),
                analyze_with_profile(&source, base, BlockProfile::AppleArm64eSoftwarePauthV1)
                    .unwrap()
            );
        }
        assert!(profile.supports_pointer_authentication() && profile.supports_clock());
        assert!(!BlockProfile::Ordinary.supports_pointer_authentication());
        assert!(!BlockProfile::AppleArm64eSoftwarePauthV1.supports_clock());
    }

    #[test]
    fn clock_boundary_respects_window_limit_and_does_not_skip_prior_unknown_words() {
        let base = GuestAddress(0x1000);
        let profile = BlockProfile::AppleArm64eSoftwarePauthClockV1;
        let first = analyze_with_profile(&bytes(&[0xd53be05f, 0]), base, profile).unwrap();
        assert_eq!(first.source_bytes, 4);
        assert_eq!(
            first.clock_instruction.unwrap().operation,
            ClockOperation::ReadVirtualCounter { destination: 31 }
        );
        let mut last = [0xd503201f; MAX_BLOCK_INSTRUCTIONS];
        last[MAX_BLOCK_INSTRUCTIONS - 1] = 0xd5033fdf;
        let analysis = analyze_with_profile(&bytes(&last), base, profile).unwrap();
        assert_eq!(analysis.source_bytes, MAX_BLOCK_INSTRUCTIONS * 4);
        assert_eq!(
            analysis.clock_instruction.unwrap().instruction_pc,
            GuestAddress(base.0 + (MAX_BLOCK_INSTRUCTIONS as u64 - 1) * 4)
        );
        assert!(
            compile_with_profile(
                &bytes(&[0xd53be040; MAX_BLOCK_INSTRUCTIONS + 1]),
                base,
                profile
            )
            .is_err()
        );
        assert_eq!(
            analyze_with_profile(&bytes(&[0xd503201f, 0, 0xd53be040]), base, profile)
                .unwrap_err()
                .pc,
            GuestAddress(base.0 + 4)
        );
    }

    #[test]
    fn pointer_authentication_exact_encodings_and_address_guards() {
        let pc = GuestAddress(0x12340000);
        let encodings = [
            (0xd503237f, PointerAuthenticationOperation::SignIbSp),
            (0xd50323ff, PointerAuthenticationOperation::AuthenticateIbSp),
            (0xd65f0fff, PointerAuthenticationOperation::ReturnIbSp),
        ];
        for (word, operation) in encodings {
            assert_eq!(
                decode_pointer_authentication(pc, word).unwrap(),
                Some(PointerAuthentication {
                    operation,
                    instruction_pc: pc,
                    next_pc: GuestAddress(pc.0 + 4),
                })
            );
            for bit in 0..32 {
                let changed = word ^ (1 << bit);
                if !encodings.iter().any(|(word, _)| *word == changed) {
                    assert_ne!(
                        decode_pointer_authentication(pc, changed)
                            .unwrap()
                            .map(|request| request.operation),
                        Some(operation)
                    );
                }
            }
            assert!(decode_pointer_authentication(GuestAddress(pc.0 + 1), word).is_err());
            assert!(decode_pointer_authentication(GuestAddress(u64::MAX - 3), word).is_err());
        }
        // Reserved zero-modifier encodings remain outside this boundary.
        for word in [0xd61f0800, 0xd63f0800, 0xdac12000, 0xdac15000] {
            assert_eq!(decode_pointer_authentication(pc, word).unwrap(), None);
        }
    }

    #[test]
    fn basic_pac_integer_fields_distinguish_sp_zero_and_discard() {
        use PointerAuthenticationKey::{Da, Db, Ia, Ib};
        use PointerAuthenticationModifier::{Register, StackPointer, Zero};
        let pc = GuestAddress(0x1000);
        for authenticate in [false, true] {
            for (key_index, key) in [Ia, Ib, Da, Db].into_iter().enumerate() {
                for rn in 0..32u32 {
                    for rd in 0..32u32 {
                        let opcode =
                            0xdac10000 | ((authenticate as u32) << 12) | ((key_index as u32) << 10);
                        let expected = |modifier| {
                            if authenticate {
                                PointerAuthenticationOperation::Authenticate {
                                    key,
                                    destination: rd as u8,
                                    modifier,
                                }
                            } else {
                                PointerAuthenticationOperation::Sign {
                                    key,
                                    destination: rd as u8,
                                    modifier,
                                }
                            }
                        };
                        let word = opcode | (rn << 5) | rd;
                        let request = decode_pointer_authentication(pc, word).unwrap().unwrap();
                        assert_eq!(
                            request.operation,
                            expected(if rn == 31 {
                                StackPointer
                            } else {
                                Register(rn as u8)
                            })
                        );
                        assert_eq!(request.operation.required_key(), Some(key));
                        assert!(compile(&bytes(&[word]), pc).is_err());
                        let zero_word = word | (1 << 13);
                        let zero = decode_pointer_authentication(pc, zero_word).unwrap();
                        assert_eq!(
                            zero.map(|request| request.operation),
                            (rn == 31).then(|| expected(Zero))
                        );
                    }
                }
            }
        }
        // dyld's pointer signer uses X17 and X16 as the data-key operands.
        for (word, key) in [(0xdac10a11, Da), (0xdac10e11, Db)] {
            assert_eq!(
                decode_pointer_authentication(pc, word)
                    .unwrap()
                    .unwrap()
                    .operation,
                PointerAuthenticationOperation::Sign {
                    key,
                    destination: 17,
                    modifier: Register(16)
                }
            );
        }
        for word in [
            0x5ac10000, 0xfac10000, 0xdac00000, 0xdac18000, 0xdac12000, 0xdac15000, 0xd61f0800,
            0xd63f0c00,
        ] {
            assert!(decode_pointer_authentication(pc, word).unwrap().is_none());
        }
    }

    #[test]
    fn generic_code_requires_explicit_profile_and_retains_helper_source_boundary() {
        const PACGA_X1_X2_X3: u32 = 0x9ac3_3041;
        let pc = GuestAddress(0x1000);
        let source = bytes(&[PACGA_X1_X2_X3]);
        assert!(compile(&source, pc).is_err());
        let instruction = decode_pointer_authentication(pc, PACGA_X1_X2_X3)
            .unwrap()
            .unwrap();
        assert_eq!(
            instruction.operation,
            PointerAuthenticationOperation::GenericCode(pauth_memory::GenericCode {
                destination: 1,
                source: 2,
                modifier: 3,
            })
        );
        let analysis =
            analyze_with_profile(&source, pc, BlockProfile::AppleArm64eSoftwarePauthV1).unwrap();
        assert_eq!(analysis.pointer_authentication, Some(instruction));
        assert_eq!(analysis.terminator_pc, Some(pc));
        assert_eq!(
            analysis.static_successors,
            vec![StaticSuccessor {
                kind: SuccessorKind::Fallthrough,
                target: GuestAddress(pc.0 + 4),
            }]
        );
        assert!(analysis.dynamic_edge.is_none());
    }

    #[test]
    fn authenticated_branch_discovery_preserves_dynamic_target_and_call_continuation() {
        const BRAA_X1_SP: u32 = 0xd71f_083f;
        const BLRAA_X1_SP: u32 = 0xd73f_083f;
        let pc = GuestAddress(0x1000);
        for (word, link) in [(BRAA_X1_SP, false), (BLRAA_X1_SP, true)] {
            let analysis = analyze_with_profile(
                &bytes(&[word]),
                pc,
                BlockProfile::AppleArm64eSoftwarePauthV1,
            )
            .unwrap();
            assert_eq!(
                analysis.dynamic_edge,
                Some(DynamicEdge {
                    kind: if link {
                        DynamicEdgeKind::Call
                    } else {
                        DynamicEdgeKind::Branch
                    },
                    register: 1,
                })
            );
            assert_eq!(
                analysis.static_successors,
                if link {
                    vec![StaticSuccessor {
                        kind: SuccessorKind::CallContinuation,
                        target: GuestAddress(pc.0 + 4),
                    }]
                } else {
                    vec![]
                }
            );
        }
    }

    #[test]
    fn authenticated_branch_fields_distinguish_zero_sp_link_and_instruction_keys() {
        use PointerAuthenticationKey::{Ia, Ib};
        use PointerAuthenticationModifier::{Register, StackPointer, Zero};
        let pc = GuestAddress(0x1000);
        for link in [false, true] {
            for (key_bit, key) in [(0, Ia), (1, Ib)] {
                for zero in [false, true] {
                    for target in 0..32u32 {
                        for rm in 0..32u32 {
                            let word = 0xd61f0800
                                | (u32::from(!zero) << 24)
                                | (u32::from(link) << 21)
                                | (key_bit << 10)
                                | (target << 5)
                                | rm;
                            let decoded = decode_pointer_authentication(pc, word).unwrap();
                            if zero && rm != 31 {
                                assert!(decoded.is_none());
                                continue;
                            }
                            let value = decoded.unwrap();
                            assert_eq!(
                                value.operation,
                                PointerAuthenticationOperation::Branch {
                                    key,
                                    target: target as u8,
                                    modifier: if zero {
                                        Zero
                                    } else if rm == 31 {
                                        StackPointer
                                    } else {
                                        Register(rm as u8)
                                    },
                                    link,
                                }
                            );
                            assert!(value.operation.is_transfer());
                            assert!(!value.operation.is_return());
                            assert_eq!(value.operation.required_key(), Some(key));
                            assert!(compile(&bytes(&[word]), pc).is_err());
                        }
                    }
                }
            }
        }
        for word in [0xd71f0000, 0xd75f0800, 0xd79f0800, 0xd71f1800, 0x571f0800] {
            assert!(decode_pointer_authentication(pc, word).unwrap().is_none());
        }
    }

    #[test]
    fn link_register_helpers_preserve_canonical_source_and_legacy_distinctions() {
        let pc = GuestAddress(0x4000);
        for (word, id) in [
            (0xdac1bbfe, "AUTIA171615_64LR_dp_1src"),
            (0xdac1901e, "AUTIASPPCR_64LRR_dp_1src"),
            (0xf380001f, "AUTIASPPC_only_dp_1src_imm"),
            (0xdac1bffe, "AUTIB171615_64LR_dp_1src"),
            (0xdac1941e, "AUTIBSPPCR_64LRR_dp_1src"),
            (0xf3a0001f, "AUTIBSPPC_only_dp_1src_imm"),
            (0xdac18bfe, "PACIA171615_64LR_dp_1src"),
            (0xdac1a3fe, "PACIASPPC_64LR_dp_1src"),
            (0xdac18ffe, "PACIB171615_64LR_dp_1src"),
            (0xdac1a7fe, "PACIBSPPC_64LR_dp_1src"),
            (0xd50324ff, "PACM_HI_hints"),
            (0xdac183fe, "PACNBIASPPC_64LR_dp_1src"),
            (0xdac187fe, "PACNBIBSPPC_64LR_dp_1src"),
            (0xd65f0be0, "RETAASPPCR_64M_branch_reg"),
            (0x5500001f, "RETAASPPC_only_miscbranch"),
            (0xd65f0fe0, "RETABSPPCR_64M_branch_reg"),
            (0x5520001f, "RETABSPPC_only_miscbranch"),
        ] {
            let request = decode_pointer_authentication(pc, word).unwrap().unwrap();
            let PointerAuthenticationOperation::LinkRegister(instruction) = request.operation
            else {
                panic!("canonical LR form must retain its descriptor");
            };
            assert_eq!(instruction.canonical_id(), id);
            assert_eq!(request.instruction_pc, pc);
            assert_eq!(request.next_pc, GuestAddress(pc.0 + 4));
            assert_eq!(request.operation.is_return(), instruction.is_return());
            let key = instruction.key().map(|key| match key {
                pauth_lr::Key::Ia => PointerAuthenticationKey::Ia,
                pauth_lr::Key::Ib => PointerAuthenticationKey::Ib,
            });
            assert_eq!(request.operation.required_key(), key);
        }
        for (word, key, authenticate) in [
            (0xdac10211, PointerAuthenticationKey::Ia, false),
            (0xdac10611, PointerAuthenticationKey::Ib, false),
            (0xdac11211, PointerAuthenticationKey::Ia, true),
            (0xdac11611, PointerAuthenticationKey::Ib, true),
        ] {
            let request = decode_pointer_authentication(pc, word).unwrap().unwrap();
            let expected = if authenticate {
                PointerAuthenticationOperation::Authenticate {
                    key,
                    destination: 17,
                    modifier: PointerAuthenticationModifier::Register(16),
                }
            } else {
                PointerAuthenticationOperation::Sign {
                    key,
                    destination: 17,
                    modifier: PointerAuthenticationModifier::Register(16),
                }
            };
            assert_eq!(request.operation, expected);
        }
    }

    #[test]
    fn basic_pac_fixed_hints_strip_and_return_have_exact_operands() {
        use PointerAuthenticationKey::{Ia, Ib};
        use PointerAuthenticationModifier::{StackPointer, Zero};
        use PointerAuthenticationOperation::{Authenticate, Sign, Strip};
        let pc = GuestAddress(0x4000);
        let fixed = [
            (
                0xd503211f,
                PointerAuthenticationOperation::Sign1716 { key: Ia },
            ),
            (
                0xd503215f,
                PointerAuthenticationOperation::Sign1716 { key: Ib },
            ),
            (
                0xd503219f,
                PointerAuthenticationOperation::Authenticate1716 { key: Ia },
            ),
            (
                0xd50321df,
                PointerAuthenticationOperation::Authenticate1716 { key: Ib },
            ),
            (
                0xd503231f,
                Sign {
                    key: Ia,
                    destination: 30,
                    modifier: Zero,
                },
            ),
            (
                0xd503233f,
                Sign {
                    key: Ia,
                    destination: 30,
                    modifier: StackPointer,
                },
            ),
            (
                0xd503235f,
                Sign {
                    key: Ib,
                    destination: 30,
                    modifier: Zero,
                },
            ),
            (0xd503237f, PointerAuthenticationOperation::SignIbSp),
            (
                0xd503239f,
                Authenticate {
                    key: Ia,
                    destination: 30,
                    modifier: Zero,
                },
            ),
            (
                0xd50323bf,
                Authenticate {
                    key: Ia,
                    destination: 30,
                    modifier: StackPointer,
                },
            ),
            (
                0xd50323df,
                Authenticate {
                    key: Ib,
                    destination: 30,
                    modifier: Zero,
                },
            ),
            (0xd50323ff, PointerAuthenticationOperation::AuthenticateIbSp),
            (
                0xd50320ff,
                Strip {
                    data: false,
                    destination: 30,
                },
            ),
            (0xd65f0bff, PointerAuthenticationOperation::ReturnIaSp),
            (0xd65f0fff, PointerAuthenticationOperation::ReturnIbSp),
        ];
        for (word, expected) in fixed {
            assert_eq!(
                decode_pointer_authentication(pc, word)
                    .unwrap()
                    .unwrap()
                    .operation,
                expected
            );
            for bit in 0..32 {
                let changed = word ^ (1 << bit);
                let decoded = decode_pointer_authentication(pc, changed).unwrap();
                assert_eq!(
                    decoded.is_some_and(|request| !matches!(
                        request.operation,
                        PointerAuthenticationOperation::Branch { .. }
                            | PointerAuthenticationOperation::LinkRegister(_)
                    )),
                    fixed.iter().any(|(fixed, _)| *fixed == changed)
                );
            }
            for profile in [
                BlockProfile::AppleArm64eSoftwarePauthV1,
                BlockProfile::AppleArm64eSoftwarePauthClockV1,
            ] {
                let analysis = analyze_with_profile(&bytes(&[word, 0]), pc, profile).unwrap();
                assert_eq!(analysis.source_bytes, 4);
                assert_eq!(analysis.dynamic_edge.is_some(), expected.is_return());
                assert_eq!(analysis.static_successors.is_empty(), expected.is_return());
            }
            assert!(compile(&bytes(&[word]), pc).is_err());
        }
        for data in [false, true] {
            for destination in 0..32u32 {
                let word = 0xdac143e0 | ((data as u32) << 10) | destination;
                let request = decode_pointer_authentication(pc, word).unwrap().unwrap();
                assert_eq!(
                    request.operation,
                    Strip {
                        data,
                        destination: destination as u8
                    }
                );
                assert_eq!(request.operation.required_key(), None);
                for bit in 0..32 {
                    if bit < 5 || bit == 10 {
                        continue;
                    }
                    assert_ne!(
                        decode_pointer_authentication(pc, word ^ (1 << bit))
                            .unwrap()
                            .map(|request| request.operation),
                        Some(request.operation)
                    );
                }
            }
        }
    }

    #[test]
    fn pointer_authentication_profile_consumes_only_native_prefix_and_boundary() {
        let base = GuestAddress(0x4000);
        let profile = BlockProfile::AppleArm64eSoftwarePauthV1;
        for word in [0xd503237f, 0xd50323ff, 0xd65f0fff] {
            let source = bytes(&[0xd2800020, word, 0]); // MOV X0,#1; helper; unknown data
            let ordinary = analyze(&source, base).unwrap_err();
            assert_eq!(ordinary.pc, GuestAddress(base.0 + 4));
            assert!(compile(&source, base).is_err());
            assert!(source_bytes(&source, base).is_err());
            let analysis = analyze_with_profile(&source, base, profile).unwrap();
            let compiled = compile_with_profile(&source, base, profile).unwrap();
            assert_eq!(
                source_bytes_with_profile(&source, base, profile).unwrap(),
                8
            );
            assert_eq!(compiled.source_bytes, 8);
            assert_eq!(analysis.source_bytes, 8);
            assert_eq!(analysis.terminator_pc, Some(GuestAddress(base.0 + 4)));
            assert!(analysis.trap.is_none());
            let request = analysis.pointer_authentication.unwrap();
            assert_eq!(request.instruction_pc, GuestAddress(base.0 + 4));
            assert_eq!(request.next_pc, GuestAddress(base.0 + 8));
            assert_eq!(
                compiled
                    .native
                    .source_map
                    .iter()
                    .map(|(pc, _)| *pc)
                    .collect::<Vec<_>>(),
                [base, request.instruction_pc]
            );
            if word == 0xd65f0fff {
                assert!(analysis.static_successors.is_empty());
                assert_eq!(
                    analysis.dynamic_edge,
                    Some(DynamicEdge {
                        kind: DynamicEdgeKind::Return,
                        register: 30
                    })
                );
            } else {
                assert_eq!(
                    analysis.static_successors,
                    [StaticSuccessor {
                        kind: SuccessorKind::Fallthrough,
                        target: request.next_pc
                    }]
                );
                assert!(analysis.dynamic_edge.is_none());
            }
            let failure = analyze_with_profile(&bytes(&[0, word]), base, profile).unwrap_err();
            assert_eq!(failure.pc, base);
        }
        assert_eq!(BlockProfile::default().abi(), BLOCK_ABI);
        assert_ne!(profile.abi(), BLOCK_ABI);
        // Ordinary transfers and trap behavior are identical in either profile.
        for word in [0xd65f03c0, 0x14000002, 0xd4001001] {
            let source = bytes(&[word, 0]);
            assert_eq!(
                analyze(&source, base).unwrap(),
                analyze_with_profile(&source, base, profile).unwrap()
            );
        }
    }

    #[test]
    fn register_transfer_masks_accept_only_ordinary_br_blr_ret() {
        for (encoding, kind) in [
            (0xd61f0000, ExitKind::Indirect),
            (0xd63f0000, ExitKind::Call),
            (0xd65f0000, ExitKind::Return),
        ] {
            for index in 0..32u32 {
                assert_eq!(
                    decode_terminator(GuestAddress(0x1000), encoding | index << 5).unwrap(),
                    Some(Terminator::Register {
                        source: if index == 31 {
                            Register::Zero
                        } else {
                            Register::X(index as u8)
                        },
                        kind,
                    })
                );
            }
            // Every fixed bit must remain fixed; adjacent authenticated and
            // exception-transfer encodings must not enter this ABI.
            for bit in (0..32).filter(|bit| !(5..10).contains(bit)) {
                let altered = encoding ^ (1 << bit);
                assert!(!matches!(
                    decode_terminator(GuestAddress(0x1000), altered),
                    Ok(Some(Terminator::Register { kind: actual, .. })) if actual == kind
                ));
            }
        }
        for encoding in [0xd65f0bff, 0xd65f0fff, 0xd71f0800, 0xd73f0800, 0xd69f03e0] {
            assert!(compile(&bytes(&[encoding]), GuestAddress(0x1000)).is_err());
        }
    }

    #[test]
    fn direct_calls_sign_extend_and_reject_overflow() {
        assert_eq!(
            decode_terminator(GuestAddress(0x1000), 0x94000003).unwrap(),
            Some(Terminator::DirectCall(GuestAddress(0x100c)))
        );
        assert_eq!(
            decode_terminator(GuestAddress(0x1000), 0x97ffffff).unwrap(),
            Some(Terminator::DirectCall(GuestAddress(0xffc)))
        );
        assert!(decode_terminator(GuestAddress(0), 0x97ffffff).is_err());
        assert!(decode_terminator(GuestAddress(u64::MAX - 3), 0x94000001).is_err());
    }

    #[test]
    fn consumes_only_the_real_prefix_and_maps_no_synthetic_return() {
        for terminator in [
            0x14000001, 0x54000020, 0xb4000020, 0x36000020, 0x94000001, 0xd61f0000, 0xd63f03c0,
            0xd65f03c0,
        ] {
            let compiled = compile(
                &bytes(&[0xd503201f, terminator, 0xffffffff]),
                GuestAddress(0x1000),
            )
            .unwrap();
            assert_eq!(compiled.source_bytes, 8);
            assert_eq!(
                source_bytes(
                    &bytes(&[0xd503201f, terminator, 0xffffffff]),
                    GuestAddress(0x1000)
                )
                .unwrap(),
                8
            );
            assert_eq!(compiled.native.source_map.len(), 2);
            assert_eq!(compiled.native.source_map[0], (GuestAddress(0x1000), 0));
            assert_eq!(compiled.native.source_map[1], (GuestAddress(0x1004), 1));
        }
        let compiled = compile(&bytes(&[0xd503201f, 0xd503201f]), GuestAddress(0x1000)).unwrap();
        assert_eq!(compiled.source_bytes, 8);
        assert_eq!(
            compiled.native.source_map,
            [(GuestAddress(0x1000), 0), (GuestAddress(0x1004), 1)]
        );
        assert!(compile(&bytes(&[0xffffffff, 0xd65f03c0]), GuestAddress(0x1000)).is_err());
    }

    #[test]
    fn block_boundaries_are_bounded_aligned_and_checked() {
        for (input, base) in [
            (vec![], 0),
            (vec![0; 3], 0),
            (bytes(&[0xd503201f]), 1),
            (bytes(&[0xd503201f]), u64::MAX - 3),
            (bytes(&vec![0xd503201f; MAX_BLOCK_INSTRUCTIONS + 1]), 0),
        ] {
            assert!(compile(&input, GuestAddress(base)).is_err());
            assert!(source_bytes(&input, GuestAddress(base)).is_err());
        }
        let compiled = compile(
            &bytes(&vec![0xd503201f; MAX_BLOCK_INSTRUCTIONS]),
            GuestAddress(0x1000),
        )
        .unwrap();
        assert_eq!(compiled.source_bytes, MAX_BLOCK_INSTRUCTIONS * 4);
        assert_eq!(compiled.native.source_map.len(), MAX_BLOCK_INSTRUCTIONS);
    }

    #[test]
    fn synchronous_trap_immediates_and_preferred_returns_are_exact() {
        for (encoding, kind, return_pc) in [
            (0xd4000001, TrapKind::SupervisorCall, GuestAddress(0x2004)),
            (
                0xd4200000,
                TrapKind::SoftwareBreakpoint,
                GuestAddress(0x2000),
            ),
        ] {
            for immediate in 0..=u16::MAX {
                let word = encoding | (u32::from(immediate) << 5);
                let trap = SynchronousTrap {
                    kind,
                    immediate,
                    instruction_pc: GuestAddress(0x2000),
                    exception_return_pc: return_pc,
                };
                assert_eq!(decode_trap(GuestAddress(0x2000), word).unwrap(), Some(trap));
                assert_eq!(
                    decode_terminator(GuestAddress(0x2000), word).unwrap(),
                    Some(Terminator::Trap(trap))
                );
            }
        }
        for pc in [1, 2, 3, u64::MAX] {
            assert!(decode_trap(GuestAddress(pc), 0xd4000001).is_err());
            assert!(decode_trap(GuestAddress(pc), 0xd4200000).is_err());
        }
        assert!(decode_trap(GuestAddress(u64::MAX - 3), 0xd4000001).is_err());
        assert_eq!(
            decode_trap(GuestAddress(u64::MAX - 3), 0xd4200000).unwrap(),
            Some(SynchronousTrap {
                kind: TrapKind::SoftwareBreakpoint,
                immediate: 0,
                instruction_pc: GuestAddress(u64::MAX - 3),
                exception_return_pc: GuestAddress(u64::MAX - 3),
            })
        );
    }

    #[test]
    fn trap_masks_reject_every_fixed_bit_neighbor_and_other_exception_classes() {
        for encoding in [0xd4000001, 0xd4200000] {
            for bit in 0..32 {
                if (0xffe0001fu32 & (1 << bit)) != 0 {
                    let word = encoding ^ (1 << bit);
                    assert_eq!(decode_trap(GuestAddress(0x2000), word).unwrap(), None);
                }
            }
        }
        for word in [
            0xd4000002, // HVC
            0xd4000003, // SMC
            0xd4400000, // HLT
            0xd4a00001, // DCPS1
            0xd4a00002, // DCPS2
            0xd4a00003, // DCPS3
            0xd4000000, // reserved exception encoding
            0xd4200001, // reserved BRK neighbor
        ] {
            assert_eq!(decode_trap(GuestAddress(0x2000), word).unwrap(), None);
            assert!(compile(&bytes(&[word]), GuestAddress(0x2000)).is_err());
        }
    }

    #[test]
    fn trap_is_a_consumed_boundary_with_its_own_source_map_and_no_leaf_fallback() {
        for word in [0xd4000001, 0xd4200000, 0xd41fffe1, 0xd43fffe0] {
            let source = bytes(&[0xd503201f, word, 0xffffffff, 0xd65f03c0]);
            let compiled = compile(&source, GuestAddress(0x2ffc)).unwrap();
            assert_eq!(compiled.source_bytes, 8);
            assert_eq!(source_bytes(&source, GuestAddress(0x2ffc)).unwrap(), 8);
            assert_eq!(
                compiled.native.source_map,
                [(GuestAddress(0x2ffc), 0), (GuestAddress(0x3000), 1)]
            );
            assert_eq!(compiled.native.x86_64_code.len(), 17);
            assert_eq!(compiled.native.x86_64_code[0], 0x90);
            assert!(crate::compile(&bytes(&[word, 0xd65f03c0]), GuestAddress(0x3000)).is_err());
        }
        // Original block input-window policy still forbids wrapping extents,
        // even though BRK's standalone preferred return PC is representable.
        for word in [0xd4000001, 0xd4200000] {
            assert!(compile(&bytes(&[word]), GuestAddress(u64::MAX - 3)).is_err());
        }
    }
}
