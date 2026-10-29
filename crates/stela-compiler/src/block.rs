//! Basic-block translation.
//!
//! Native entry is System V `BlockExit function(GuestState *state)`. Emitted code
//! never jumps to a guest PC: every control-flow change exits to the dispatcher.
//! SVC and BRK exit at a synchronous-trap boundary. PAC instructions call a
//! runtime helper when software PAuth is enabled.

mod analysis;
mod features;
mod host_gprs;
pub mod loop_budget;
pub mod memory;
pub mod pauth_lr;
pub mod pauth_memory;
mod pointer_authentication;
pub mod profile;
pub mod scalable;
pub mod scalar;
pub mod system;
mod thread;

pub use analysis::{
    BlockAnalysis, BlockAnalysisError, DynamicEdge, DynamicEdgeKind, StaticSuccessor,
    SuccessorKind, analyze, analyze_with_profile, source_bytes, source_bytes_with_profile,
};
use analysis::{ParsedBlock, analyze_parsed, parse};
pub use features::{BlockProfile, Features};
pub use host_gprs::{FaultRecoveryError, HostGprSnapshot};
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
use serde::Serialize;

const NOP_ENCODING: u32 = 0xd503_201f;

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

/// A native exit tag outside the compiler/runtime ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidExitKind {
    pub value: u64,
}
impl core::fmt::Display for InvalidExitKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown native exit kind {}", self.value)
    }
}
impl core::error::Error for InvalidExitKind {}

impl TryFrom<u64> for ExitKind {
    type Error = InvalidExitKind;

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
            _ => Err(InvalidExitKind { value }),
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
        return Err(
            CompileError::new(crate::CompileErrorKind::MisalignedInstructionAddress)
                .at_instruction(pc, word),
        );
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
        next_pc: GuestAddress(
            pc.0.checked_add(4)
                .ok_or_else(|| CompileError::new(crate::CompileErrorKind::GuestAddressOverflow))?,
        ),
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
        return Err(
            CompileError::new(crate::CompileErrorKind::MisalignedInstructionAddress)
                .at_instruction(pc, word),
        );
    }
    // June 2026 official SVC_EX_exception / BRK_EX_exception encodings:
    // only imm16 at bits 20:5 varies.
    let kind = match word & 0xffe0001f {
        0xd4000001 => TrapKind::SupervisorCall,
        0xd4200000 => TrapKind::SoftwareBreakpoint,
        _ => return Ok(None),
    };
    let exception_return_pc = match kind {
        TrapKind::SupervisorCall => GuestAddress(
            pc.0.checked_add(4)
                .ok_or_else(|| CompileError::new(crate::CompileErrorKind::GuestAddressOverflow))?,
        ),
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
    /// across a faultable access. Only the direct system-mode profile emits entries, and
    /// an engine that recovers from a native fault must apply them
    /// ([`FaultRecovery::apply`]) before it reads the frame.
    pub fault_recovery: alloc::vec::Vec<FaultRecovery>,
}

impl CompiledBlock {
    /// Code with no chainable exits and no fault recovery.
    fn unchained(native: NativeBlock, source_bytes: usize) -> Self {
        Self {
            native,
            source_bytes,
            direct_exits: alloc::vec::Vec::new(),
            fault_recovery: alloc::vec::Vec::new(),
        }
    }
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
    /// Settle the active recovery mappings from a normalized host snapshot.
    /// All indices and required banks are checked before the first guest write.
    pub fn apply(
        table: &[Self],
        offset: usize,
        host: &HostGprSnapshot,
        state: &mut crate::GuestState,
    ) -> Result<(), FaultRecoveryError> {
        const SP: u8 = 31;
        let active = || {
            table
                .iter()
                .filter(move |entry| (entry.start..entry.end).contains(&offset))
        };
        for entry in active() {
            for &(guest, register) in &entry.registers {
                if guest > SP {
                    return Err(FaultRecoveryError::InvalidGuestRegister { register: guest });
                }
                if register >= 32 {
                    return Err(FaultRecoveryError::InvalidHostRegister { register });
                }
                if host.get(register).is_none() {
                    return Err(FaultRecoveryError::ExtendedStateUnavailable { register });
                }
            }
        }
        for entry in active() {
            for &(guest, register) in &entry.registers {
                let value = host
                    .get(register)
                    .expect("active recovery mappings validated");
                if guest == SP {
                    state.sp = value;
                } else {
                    state.x[usize::from(guest)] = value;
                }
            }
        }
        Ok(())
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
    /// Unexecuted scalar or vector operation delegated to numerical completion.
    FloatingPoint,
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
                .ok_or_else(|| CompileError::new(crate::CompileErrorKind::GuestAddressOverflow))?;
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

/// [`analyze_with_profile`] of `source` and [`CompilationPlan::new`] of the
/// block it finds (`source[..analysis.source_bytes]`) from one parse.
pub fn analyze_and_plan(
    source: &[u8],
    base: GuestAddress,
    options: &crate::Options,
) -> Result<(BlockAnalysis, Result<CompilationPlan, CompileError>), BlockAnalysisError> {
    let parsed = parse(source, base, options.profile())?;
    let analysis = analyze_parsed(&parsed);
    Ok((
        analysis,
        options
            .validate()
            .and_then(|()| CompilationPlan::block(parsed, options)),
    ))
}

/// One validated decode of the consumed input, shared by cache requirements
/// and emission. A cache hit may skip emission; it still derives the
/// requirements from source.
pub struct CompilationPlan {
    options: crate::Options,
    stage: Stage,
}

enum Stage {
    Block {
        parsed: ParsedBlock,
        checked: Option<memory::CheckedPlan>,
        resident: Option<crate::x86_64::block::ResidentLoopPlan>,
    },
    Leaf {
        instructions: alloc::vec::Vec<crate::aarch64::Instruction>,
        source_bytes: usize,
    },
    ContextLeaf(crate::scalable_context::Leaf),
    ContextBlock(crate::scalable_context::block::Prefix),
}

impl CompilationPlan {
    pub fn new(
        source: &[u8],
        base: GuestAddress,
        options: &crate::Options,
    ) -> Result<Self, CompileError> {
        options.validate()?;
        let profile = options.profile();
        let target = options.target();
        let stage = match (
            profile.has(Features::CONTEXT),
            profile.has(Features::LEAF),
            options.scalable(),
        ) {
            (true, true, Some(scalable)) => Stage::ContextLeaf(
                crate::scalable_context::Leaf::decode(source, base, scalable, target)?,
            ),
            (true, false, Some(scalable)) => {
                Stage::ContextBlock(crate::scalable_context::block::Prefix::decode(
                    source,
                    base,
                    scalable,
                    options.numerical_features(),
                    target,
                )?)
            }
            (false, true, _) => Stage::Leaf {
                instructions: decode_leaf(source, base)?,
                source_bytes: source.len(),
            },
            _ => {
                let parsed = parse(source, base, profile).map_err(CompileError::from)?;
                return Self::block(parsed, options);
            }
        };
        Ok(Self {
            options: *options,
            stage,
        })
    }

    fn block(parsed: ParsedBlock, options: &crate::Options) -> Result<Self, CompileError> {
        let profile = options.profile();
        let target = options.target();
        let checks = options.memory_checks();
        let shared_system =
            profile.has(Features::FULL_SYSTEM) && profile.checked_memory().is_some();
        for instruction in &parsed.instructions {
            // The shared checked service has a separately required writable
            // CX16 read footprint, so its ordered accesses need no AVX.
            if shared_system
                && matches!(instruction.operation, Operation::Ordered(_))
                && target.supports(crate::TargetCpu::Cx16)
            {
                continue;
            }
            if !matches!(
                instruction.operation,
                Operation::Exclusive(_) | Operation::CheckedPointer(_)
            ) || profile.checked_memory().is_none()
            {
                crate::x86_64::validate_target(instruction, target).map_err(CompileError::from)?;
            }
            // An unchecked SP needs its own host capability.
            if !checks.stack_alignment {
                crate::x86_64::validate_target_with(instruction, target, checks)
                    .map_err(CompileError::from)?;
            }
        }
        let checked = profile
            .checked_memory()
            .map(|selected| {
                memory::CheckedPlan::new(
                    &parsed.instructions,
                    parsed.terminal.as_ref(),
                    selected,
                    profile,
                )
            })
            .transpose()?;
        let resident = if profile.has(Features::RESIDENT_LOOPS) {
            crate::x86_64::block::ResidentLoopPlan::new(
                &parsed.instructions,
                parsed.terminal.as_ref(),
                parsed.next_pc,
            )
        } else {
            None
        };
        Ok(Self {
            options: *options,
            stage: Stage::Block {
                parsed,
                checked,
                resident,
            },
        })
    }

    /// Let an ordinary block keep eligible internal loop edges resident, with
    /// [`Features::RESIDENT_LOOPS`] when it has any. Other profiles keep their
    /// admission and call contracts.
    pub fn with_resident_loops(mut self) -> Self {
        if let Stage::Block {
            parsed, resident, ..
        } = &mut self.stage
            && self.options.profile() == BlockProfile::ORDINARY
        {
            *resident = crate::x86_64::block::ResidentLoopPlan::new(
                &parsed.instructions,
                parsed.terminal.as_ref(),
                parsed.next_pc,
            );
            if resident.is_some() {
                self.options = crate::Options::new(
                    BlockProfile::new(Features::RESIDENT_LOOPS),
                    self.options.target(),
                );
            }
        }
        self
    }

    pub fn profile(&self) -> BlockProfile {
        self.options.profile()
    }

    #[cfg(test)]
    fn parsed(&self) -> &ParsedBlock {
        match &self.stage {
            Stage::Block { parsed, .. } => parsed,
            _ => panic!("not a block plan"),
        }
    }

    pub fn source_bytes(&self) -> usize {
        match &self.stage {
            Stage::Block { parsed, .. } => parsed.source_bytes,
            Stage::Leaf { source_bytes, .. } => *source_bytes,
            Stage::ContextLeaf(leaf) => leaf.source_bytes(),
            Stage::ContextBlock(prefix) => prefix.source_bytes(),
        }
    }

    /// The memory service a checked block or a context leaf needs; `None` for
    /// direct RAM.
    pub fn memory_requirements(&self) -> Option<crate::context::memory::MemoryRequirements> {
        match &self.stage {
            Stage::Block {
                checked: Some(plan),
                ..
            } => {
                let mut requirements = plan.requirements();
                use crate::context::memory::{host_caps, profile_requirements};
                let profile = self.options.profile();
                let target = self.options.target();
                if profile.has(Features::FULL_SYSTEM)
                    && !target.supports(crate::TargetCpu::AtomicLoad16)
                    && target.supports(crate::TargetCpu::Cx16)
                    && requirements.required_host_caps & host_caps::ATOMIC_LOAD16 != 0
                {
                    requirements.required_host_caps = requirements.required_host_caps
                        & !host_caps::ATOMIC_LOAD16
                        | host_caps::CX16;
                    requirements.required_profile |=
                        profile_requirements::SYSTEM_ATOMIC_READ_WRITEBACK;
                }
                Some(requirements)
            }
            Stage::ContextLeaf(leaf) => Some(leaf.memory_requirements()),
            _ => None,
        }
    }

    /// A context leaf's per-instruction scalable execution requirements.
    pub fn execution_requirements(
        &self,
    ) -> Option<crate::aarch64::scalable::execution::ScalableExecutionRequirements> {
        match &self.stage {
            Stage::ContextLeaf(leaf) => Some(leaf.execution_requirements()),
            _ => None,
        }
    }

    pub fn compile(self) -> Result<CompiledBlock, CompileError> {
        self.compile_impl(None)
    }
    /// Emit identical code while recording the selected recipes. Coverage a
    /// stage does not profile stays absent, rather than implying zero work.
    pub fn compile_profiled(
        self,
    ) -> Result<(CompiledBlock, profile::CompileProfile), CompileError> {
        let mut profile = profile::CompileProfile::default();
        let block = self.compile_impl(Some(&mut profile))?;
        Ok((block, profile))
    }

    fn compile_impl(
        self,
        recipes: Option<&mut profile::CompileProfile>,
    ) -> Result<CompiledBlock, CompileError> {
        let options = self.options;
        let profile = options.profile();
        let target = options.target();
        let (parsed, checked, resident) = match self.stage {
            Stage::Block {
                parsed,
                checked,
                resident,
            } => (parsed, checked, resident),
            Stage::Leaf {
                instructions,
                source_bytes,
            } => {
                let native = crate::x86_64::Emitter
                    .emit_for_target(&instructions, target)
                    .map_err(CompileError::from)?;
                return Ok(CompiledBlock::unchained(native, source_bytes));
            }
            Stage::ContextLeaf(leaf) => {
                let source_bytes = leaf.source_bytes();
                return Ok(CompiledBlock::unchained(leaf.emit()?, source_bytes));
            }
            Stage::ContextBlock(prefix) => return prefix.emit(),
        };
        let native = if let Some(checked) = checked {
            checked.emit(parsed.terminal.as_ref(), parsed.next_pc, target, recipes)?
        } else if let Some(resident) = resident {
            resident
                .emit(&parsed.instructions)
                .map_err(CompileError::from)?
        } else if profile.has(Features::RESIDENT_LOOPS) {
            crate::x86_64::block::emit_resident_fallback_for_target(
                &parsed.instructions,
                parsed.terminal.as_ref(),
                parsed.next_pc,
                target,
            )
        } else if profile == BlockProfile::ORDINARY {
            crate::x86_64::block::emit_ordinary_for_target(
                &parsed.instructions,
                parsed.terminal.as_ref(),
                parsed.next_pc,
                target,
            )
        } else {
            // Only system mode runs one agent at a time and checks the
            // guest's ranges; every other profile keeps the locked recipes
            // and the default checks.
            let (native, fault_recovery) = if profile.has(Features::FULL_SYSTEM) {
                crate::x86_64::block::emit_system_mode(
                    &parsed.instructions,
                    parsed.terminal.as_ref(),
                    parsed.next_pc,
                    target,
                    options.memory_checks(),
                    options.native_system(),
                )
            } else {
                (
                    crate::x86_64::block::emit_ordinary_for_target(
                        &parsed.instructions,
                        parsed.terminal.as_ref(),
                        parsed.next_pc,
                        target,
                    ),
                    alloc::vec::Vec::new(),
                )
            };
            let direct_exits = crate::x86_64::block::successor_exits(
                &native.x86_64_code,
                parsed.terminal.as_ref(),
                parsed.next_pc,
            );
            return Ok(CompiledBlock {
                native,
                source_bytes: parsed.source_bytes,
                direct_exits,
                fault_recovery,
            });
        };
        Ok(CompiledBlock::unchained(native, parsed.source_bytes))
    }
}

/// Lift a leaf, which must end in RET X30, instruction by instruction.
fn decode_leaf(
    source: &[u8],
    base: GuestAddress,
) -> Result<alloc::vec::Vec<crate::aarch64::Instruction>, CompileError> {
    use crate::Lifter;
    if source.is_empty() || !source.len().is_multiple_of(4) || !base.0.is_multiple_of(4) {
        return Err(CompileError::new(
            crate::CompileErrorKind::InvalidSourceLayout,
        ));
    }
    let mut instructions = alloc::vec::Vec::with_capacity(source.len() / 4);
    for (index, bytes) in source.as_chunks::<4>().0.iter().enumerate() {
        let pc = GuestAddress(
            base.0
                .checked_add((index as u64) * 4)
                .ok_or_else(|| CompileError::new(crate::CompileErrorKind::GuestAddressOverflow))?,
        );
        let instruction = crate::aarch64::Decoder
            .lift(pc, u32::from_le_bytes(*bytes))
            .map_err(CompileError::from)?;
        instructions.push(instruction);
    }
    if !matches!(
        instructions
            .last()
            .map(|instruction| &instruction.operation),
        Some(Operation::Return)
    ) {
        return Err(CompileError::new(
            crate::CompileErrorKind::MissingLeafReturn,
        ));
    }
    Ok(instructions)
}

#[cfg(test)]
mod tests;
