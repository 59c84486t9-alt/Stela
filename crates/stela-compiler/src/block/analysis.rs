//! Block boundaries, static successors and dynamic edges, found without emitting code.
use super::{
    BlockProfile, ClockInstruction, ExitKind, MAX_BLOCK_INSTRUCTIONS, NOP_ENCODING,
    PointerAuthentication, PointerAuthenticationOperation, SynchronousTrap, SystemInstruction,
    Terminator, ThreadRegisterInstruction, decode_clock_instruction, decode_pointer_authentication,
    decode_system_instruction, decode_terminator, decode_thread_register_instruction, memory,
    system,
};
use crate::{
    CompileError, GuestAddress, Lifter,
    aarch64::{Decoder, Instruction, Operation, Register},
};
use alloc::{format, string::String, vec, vec::Vec};
use serde::Serialize;

pub(super) struct ParsedBlock {
    pub(super) instructions: Vec<Instruction>,
    pub(super) terminal: Option<(GuestAddress, Terminator)>,
    pub(super) next_pc: GuestAddress,
    pub(super) source_bytes: usize,
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
    pub amx_instruction: Option<crate::amx::AmxInstruction>,
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
    parse(source, base, profile).map(|parsed| analyze_parsed(&parsed))
}

/// The analysis of a parsed block.
pub(super) fn analyze_parsed(parsed: &ParsedBlock) -> BlockAnalysis {
    let mut successors = Vec::new();
    let mut dynamic_edge = None;
    let mut trap = None;
    let mut system_instruction = None;
    let mut pointer_authentication = None;
    let mut clock_instruction = None;
    let mut thread_register_instruction = None;
    let mut amx_instruction = None;
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
                    | system::SystemOperation::TagOffset(_)
                    | system::SystemOperation::SendEvent { .. }
                    | system::SystemOperation::Register(_)
                    | system::SystemOperation::PstateImmediate(_)
                    | system::SystemOperation::Wait { .. }
                    | system::SystemOperation::Unprivileged(_)
                    | system::SystemOperation::Exclusive(_)
                    | system::SystemOperation::CheckedPointer(_)
                    | system::SystemOperation::Compression(_)
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
        Some(Terminator::FloatingPoint) => {
            add(SuccessorKind::Fallthrough, parsed.next_pc);
        }
        Some(Terminator::Amx(value)) => {
            amx_instruction = Some(*value);
            add(SuccessorKind::Fallthrough, value.next_pc);
        }
        Some(Terminator::Branch(_)) => {
            unreachable!("private parser only stores branch operations as terminators")
        }
    }
    BlockAnalysis {
        source_bytes: parsed.source_bytes,
        terminator_pc: parsed.terminal.as_ref().map(|(pc, _)| *pc),
        static_successors: successors,
        dynamic_edge,
        trap,
        system_instruction,
        pointer_authentication,
        clock_instruction,
        thread_register_instruction,
        amx_instruction,
    }
}

pub(super) fn parse(
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
        if profile.supports_full_system() {
            // PAuth hints share the hint space, so they are matched first.
            if let Some(decoded) =
                decode_pointer_authentication(pc, word).map_err(|error| BlockAnalysisError {
                    pc,
                    detail: error.0,
                })?
            {
                terminal = Some((pc, Terminator::PointerAuthentication(decoded)));
                break;
            }
            // BTI executes as NOP (Arm `BTI`). PSTATE.BTYPE can be nonzero
            // only for a block's first instruction, after the indirect
            // branch that ended the previous block, and the engine checks
            // that instruction before entering the block.
            if matches!(
                crate::aarch64::system::synchronization::decode(word),
                Some(crate::aarch64::system::synchronization::Operation::BranchTarget { .. })
            ) {
                instructions.push(Instruction {
                    pc,
                    operation: Operation::Nop,
                });
                continue;
            }
            // ISB executes as NOP in the serialized engine (Arm `ISB`): what
            // it synchronizes, a System register write, TLB or cache
            // maintenance, exception entry and return, ends its block and
            // completes in the engine, which recomputes what derives from
            // it before the next fetch. The shared lane's PEs keep it.
            if profile == BlockProfile::SystemModeV1
                && matches!(
                    crate::aarch64::system::synchronization::decode(word),
                    Some(
                        crate::aarch64::system::synchronization::Operation::InstructionSynchronization { .. }
                    )
                )
            {
                instructions.push(Instruction {
                    pc,
                    operation: Operation::Nop,
                });
                continue;
            }
            if let Some(decoded) =
                system::decode_system_mode_instruction(pc, word).map_err(|error| {
                    BlockAnalysisError {
                        pc,
                        detail: error.0,
                    }
                })?
            {
                // The shared lane executes these through the existing typed
                // all-writer memory service, not the single-agent CPU monitor.
                let checked = matches!(profile, BlockProfile::SystemModeSharedV1(_))
                    && matches!(decoded.operation, system::SystemOperation::Exclusive(Ok(_)));
                if !checked {
                    terminal = Some((pc, Terminator::System(decoded)));
                    break;
                }
            }
        }
        if profile.supports_system()
            && !profile.supports_full_system()
            && let Some(decoded) =
                decode_system_instruction(pc, word).map_err(|error| BlockAnalysisError {
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
        if profile.supports_amx()
            && let Some(decoded) =
                crate::amx::decode(pc, word).map_err(|error| BlockAnalysisError {
                    pc,
                    detail: error.0,
                })?
        {
            terminal = Some((pc, Terminator::Amx(decoded)));
            break;
        }
        if let Some(decoded) = decode_terminator(pc, word).map_err(|error| BlockAnalysisError {
            pc,
            detail: error.0,
        })? {
            terminal = Some((pc, decoded));
            break;
        }
        let instruction = Decoder.lift(pc, word).map_err(|error| BlockAnalysisError {
            pc,
            detail: format!("unsupported ARM64 semantics: {error:?}"),
        })?;
        if profile.checked_memory().is_some()
            && instruction.operation == Operation::Nop
            && word != NOP_ENCODING
        {
            return Err(BlockAnalysisError {
                pc,
                detail: "unadmitted original NOP provenance in checked memory profile".into(),
            });
        }
        if profile.supports_system()
            && !profile.supports_full_system()
            && !crate::scalable_context::ordinary_permitted(&instruction.operation)
        {
            return Err(BlockAnalysisError {
                pc,
                detail: "operation outside restricted System prefix profile".into(),
            });
        }
        if let Operation::FloatingPoint(operand) = &instruction.operation
            && (matches!(profile, BlockProfile::SystemModeSharedV1(_))
                || crate::x86_64::numerical_always_exits(operand))
        {
            // The checked full-system prefix has no inline numerical recipe.
            // Recover its exact prefix and complete through the existing FP
            // service, including forms other profiles can execute inline.
            terminal = Some((pc, Terminator::FloatingPoint));
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
            profile,
        )?;
    }
    Ok(parsed.source_bytes)
}
