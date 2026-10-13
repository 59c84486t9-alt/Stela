//! Bounded basic-block translation with explicit guest control-flow exits.
//!
//! Native entry is System V `BlockExit function(GuestState *state)`. The caller
//! owns dispatch and fetch validation; emitted code never jumps to a guest PC.
//! Guest memory uses the ordinary direct-RAM profile. GCS and guarded/BTI pages
//! are disabled, and PAC, architectural exception entry and PSTATE.BTYPE are
//! not modeled. SVC/BRK stop at an explicit synchronous-trap boundary.

use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock,
    aarch64::{Decoder, Instruction, Operation, Register},
};
use serde::Serialize;

/// Separate from the leaf ABI: RAX/RDX return the next guest PC and exit kind.
pub const BLOCK_ABI: &str = "x86_64-sysv-guest-state-v1-block-exit-direct-ram";
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
            _ => Err(()),
        }
    }
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
}
/// Discover boundaries and edges from the exact parser used by both AOT and JIT.
/// Static call continuations are candidates, not proof that the callee returns.
/// Dynamic targets and trap resumption require external runtime evidence.
pub fn analyze(source: &[u8], base: GuestAddress) -> Result<BlockAnalysis, BlockAnalysisError> {
    let parsed = parse(source, base)?;
    let mut successors = Vec::new();
    let mut dynamic_edge = None;
    let mut trap = None;
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
    })
}

fn parse(source: &[u8], base: GuestAddress) -> Result<ParsedBlock, BlockAnalysisError> {
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
    Ok(parse(source, base)
        .map_err(|error| CompileError(error.detail))?
        .source_bytes)
}

/// Compile through the first control transfer/trap, or exit at the input boundary.
/// Unknown semantics before that boundary are rejected. Bytes following a
/// terminator are unconsumed and do not participate in the returned source map.
pub fn compile(source: &[u8], base: GuestAddress) -> Result<CompiledBlock, CompileError> {
    let parsed = parse(source, base).map_err(|error| CompileError(error.detail))?;
    let native = crate::x86_64::block::emit(
        &parsed.instructions,
        parsed.terminal.as_ref(),
        parsed.next_pc,
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
        for kind in 0..6 {
            assert_eq!(ExitKind::try_from(kind).unwrap() as u64, kind);
        }
        assert_eq!(ExitKind::try_from(6), Err(()));
        assert_eq!(ExitKind::try_from(u64::MAX), Err(()));
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
