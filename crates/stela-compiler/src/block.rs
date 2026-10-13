//! Bounded basic-block translation with explicit guest control-flow exits.
//!
//! Native entry is System V `BlockExit function(GuestState *state)`. The caller
//! owns dispatch and fetch validation; emitted code never jumps to a guest PC.
//! Guest memory uses the ordinary direct-RAM profile. GCS and guarded/BTI pages
//! are disabled, and architectural exception entry and PSTATE.BTYPE are not
//! modeled. Ordinary compilation declines PAC; explicit software PAC compilation
//! requests a runtime helper without authenticating or changing its operand.
//! SVC/BRK stop at an explicit synchronous-trap boundary.

use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock,
    aarch64::{Decoder, Instruction, Operation, Register},
};
use serde::Serialize;

/// Separate from the leaf ABI: RAX/RDX return the next guest PC and exit kind.
pub const BLOCK_ABI: &str = "x86_64-sysv-guest-state-v2-block-exit-direct-ram";
/// Same state/return layout, with an explicitly enabled runtime PAC boundary.
/// This identifies software-profile helper requests, not Apple signature identity.
pub const PAUTH_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-v1";
pub const CLOCK_BLOCK_ABI: &str =
    "x86_64-sysv-guest-state-v2-block-exit-direct-ram-apple-arm64e-software-pauth-clock-v1";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockProfile {
    #[default]
    Ordinary,
    AppleArm64eSoftwarePauthV1,
    AppleArm64eSoftwarePauthClockV1,
}

impl BlockProfile {
    pub const fn abi(self) -> &'static str {
        match self {
            Self::Ordinary => BLOCK_ABI,
            Self::AppleArm64eSoftwarePauthV1 => PAUTH_BLOCK_ABI,
            Self::AppleArm64eSoftwarePauthClockV1 => CLOCK_BLOCK_ABI,
        }
    }

    pub const fn supports_pointer_authentication(self) -> bool {
        matches!(
            self,
            Self::AppleArm64eSoftwarePauthV1 | Self::AppleArm64eSoftwarePauthClockV1
        )
    }

    pub const fn supports_clock(self) -> bool {
        matches!(self, Self::AppleArm64eSoftwarePauthClockV1)
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

/// Only reviewed ISB SY and MRS CNTVCT_EL0, with X31 denoting the discard
/// destination. Other counter/control registers and barrier options decline.
/// Completion requires an explicit virtual-clock/synchronization service.
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
    // Preserve the original descriptor representation for existing consumers.
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
            Self::Sign { key, .. } | Self::Authenticate { key, .. } | Self::Branch { key, .. } => {
                Some(key)
            }
            Self::Strip { .. } => None,
        }
    }
}

/// A helper request at an unchanged original instruction. The native block
/// commits its ordinary prefix but performs no PAC operation or guest transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PointerAuthentication {
    pub operation: PointerAuthenticationOperation,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

/// June2026 basic PAC/AUT integer and HINT forms, XPAC and authenticated transfers.
/// The explicit software profile disables PAuth_LR/PACM, FPAC and GCS. Other
/// PAC operations (including PACGA) and system controls remain unsupported.
/// Runtime consumers revalidate this descriptor against immutable source bytes.
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
    let operation = match word {
        0xd503237f => PointerAuthenticationOperation::SignIbSp,
        0xd50323ff => PointerAuthenticationOperation::AuthenticateIbSp,
        0xd65f0fff => PointerAuthenticationOperation::ReturnIbSp,
        0xd65f0bff => PointerAuthenticationOperation::ReturnIaSp,
        0xd503211f => Sign {
            key: Ia,
            destination: 17,
            modifier: Register(16),
        },
        0xd503215f => Sign {
            key: Ib,
            destination: 17,
            modifier: Register(16),
        },
        0xd503219f => Authenticate {
            key: Ia,
            destination: 17,
            modifier: Register(16),
        },
        0xd50321df => Authenticate {
            key: Ib,
            destination: 17,
            modifier: Register(16),
        },
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
        _ => return Ok(None),
    };
    Ok(Some(PointerAuthentication {
        operation,
        instruction_pc: pc,
        next_pc: GuestAddress(pc.0.checked_add(4).ok_or_else(|| {
            CompileError("PAC continuation PC overflows guest address range".into())
        })?),
    }))
}

/// Identifies the original instruction, without performing exception delivery.
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

/// Raw kind permits validation before converting results from executable code.
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
    Register { source: Register, kind: ExitKind },
    Trap(SynchronousTrap),
    PointerAuthentication(PointerAuthentication),
    Clock(ClockInstruction),
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

/// Semantic-analysis failure attached to the original failing instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockAnalysisError {
    pub pc: GuestAddress,
    pub detail: String,
}
impl std::fmt::Display for BlockAnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {:#x}", self.detail, self.pc.0)
    }
}
impl std::error::Error for BlockAnalysisError {}
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
    pub pointer_authentication: Option<PointerAuthentication>,
    pub clock_instruction: Option<ClockInstruction>,
}
/// Discover boundaries and edges from the exact parser used by both AOT and JIT.
/// Static call continuations are candidates, not proof that the callee returns.
/// Dynamic targets and trap resumption require external runtime evidence.
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
    let mut pointer_authentication = None;
    let mut clock_instruction = None;
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
        Some(Terminator::PointerAuthentication(value)) => {
            pointer_authentication = Some(*value);
            if value.operation.is_return() {
                // Signed LR is only a candidate: the service authenticates it.
                dynamic_edge = Some(DynamicEdge {
                    kind: DynamicEdgeKind::Return,
                    register: 30,
                });
            } else {
                add(SuccessorKind::Fallthrough, value.next_pc);
            }
        }
        Some(Terminator::Clock(value)) => {
            clock_instruction = Some(*value);
            add(SuccessorKind::Fallthrough, value.next_pc);
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
        pointer_authentication,
        clock_instruction,
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
    Ok(parse(source, base, profile)
        .map_err(|error| CompileError(error.detail))?
        .source_bytes)
}

/// Compile through the first control transfer/trap, or exit at the input boundary.
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
    let parsed = parse(source, base, profile).map_err(|error| CompileError(error.detail))?;
    let native = crate::x86_64::block::emit_for_target(
        &parsed.instructions,
        parsed.terminal.as_ref(),
        parsed.next_pc,
        target,
    );
    Ok(CompiledBlock {
        native,
        source_bytes: parsed.source_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
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
        assert_eq!(std::mem::size_of::<BlockExit>(), 16);
        assert_eq!(std::mem::offset_of!(BlockExit, next_pc), 0);
        assert_eq!(std::mem::offset_of!(BlockExit, kind), 8);
        for kind in 0..8 {
            assert_eq!(ExitKind::try_from(kind).unwrap() as u64, kind);
        }
        assert_eq!(ExitKind::try_from(8), Err(()));
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
        // PACGA and reserved zero-modifier encodings remain outside this boundary.
        for word in [0xd61f0800, 0xd63f0800, 0x9ac03000, 0xdac12000, 0xdac15000] {
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
        // Actual original dyld signer data-key operands are X17 and X16.
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
            0x5ac10000, 0xfac10000, 0xdac00000, 0xdac18000, 0xdac12000, 0xdac15000, 0x9ac03000,
            0xd61f0800, 0xd63f0c00,
        ] {
            assert!(decode_pointer_authentication(pc, word).unwrap().is_none());
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
    fn basic_pac_fixed_hints_strip_and_return_have_exact_operands() {
        use PointerAuthenticationKey::{Ia, Ib};
        use PointerAuthenticationModifier::{Register, StackPointer, Zero};
        use PointerAuthenticationOperation::{Authenticate, Sign, Strip};
        let pc = GuestAddress(0x4000);
        let fixed = [
            (
                0xd503211f,
                Sign {
                    key: Ia,
                    destination: 17,
                    modifier: Register(16),
                },
            ),
            (
                0xd503215f,
                Sign {
                    key: Ib,
                    destination: 17,
                    modifier: Register(16),
                },
            ),
            (
                0xd503219f,
                Authenticate {
                    key: Ia,
                    destination: 17,
                    modifier: Register(16),
                },
            ),
            (
                0xd50321df,
                Authenticate {
                    key: Ib,
                    destination: 17,
                    modifier: Register(16),
                },
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
