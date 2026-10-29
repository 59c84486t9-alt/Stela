//! Blocks compiled with an execution context. A service exit returns the PC of
//! the instruction still to execute.
use super::{Decoded, INSTRUCTION_BYTES, ScalableProfile, context_wrapper, decode};
use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock, Options, TargetCpu,
    aarch64::{Decoder, Operation, floating::features::NumericalFeatures},
    block::{
        self, BlockProfile, CompilationPlan, CompiledBlock, ExitKind, MAX_BLOCK_INSTRUCTIONS,
        scalable::{
            AdmittedScalableNumericalInstruction, ScalableNumericalOperation,
            admit_scalable_numerical_instruction, decode_scalable_numerical_instruction,
        },
    },
    context::memory::MemoryRequirements,
    x86_64,
};
use alloc::boxed::Box;
use alloc::vec::Vec;

enum Terminal {
    /// An ordinary block of the one terminal instruction.
    Shared(Box<CompilationPlan>),
    Numerical(AdmittedScalableNumericalInstruction),
}

/// Existing Ordinary traps remain ordinary boundaries. Other typed services
/// cannot acquire permission from a successful decode or memory-effect result.
fn reject_unavailable_service(pc: GuestAddress, word: u32) -> Result<(), CompileError> {
    if block::decode_trap(pc, word)?.is_some() {
        return Ok(());
    }
    if block::decode_system_instruction(pc, word)?.is_some()
        || block::decode_pointer_authentication(pc, word)?.is_some()
        || block::decode_clock_instruction(pc, word)?.is_some()
        || block::decode_thread_register_instruction(pc, word)?.is_some()
        || crate::amx::decode(pc, word)?.is_some()
    {
        return Err(CompileError::new(crate::CompileErrorKind::ContextServiceUnimplemented).at(pc));
    }
    Ok(())
}

fn shared_terminal(
    bytes: &[u8; INSTRUCTION_BYTES],
    pc: GuestAddress,
    target: TargetCpu,
) -> Result<Option<CompilationPlan>, CompileError> {
    if let Ok(instruction) = Decoder.lift(pc, u32::from_le_bytes(*bytes))
        && matches!(instruction.operation, Operation::FloatingPoint(_))
    {
        return Ok(None);
    }
    let analysis = block::analyze_with_profile(bytes, pc, BlockProfile::ORDINARY)
        .map_err(CompileError::from)?;
    // The ordinary scalar numerical boundary is excluded until
    // its low-V/upper-Z effects have been integrated in context mode.
    let permitted = analysis.trap.is_some()
        || analysis.dynamic_edge.is_some()
        || (analysis.terminator_pc.is_some() && !analysis.static_successors.is_empty());
    if permitted {
        CompilationPlan::new(bytes, pc, &Options::new(BlockProfile::ORDINARY, target)).map(Some)
    } else {
        Ok(None)
    }
}

fn is_transfer(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Branch { .. }
            | Operation::BranchCondition { .. }
            | Operation::BranchZero { .. }
            | Operation::BranchBit { .. }
            | Operation::Return
    )
}

/// A decoded context block prefix. Direct RAM, AdvSIMD/FP, mode writes and
/// MOVPRFX are refused as in the context leaf compiler.
pub struct Prefix {
    instructions: Vec<(GuestAddress, Decoded)>,
    terminal: Option<Terminal>,
    next_pc: GuestAddress,
    source_bytes: usize,
    scalable: ScalableProfile,
    numerical: NumericalFeatures,
    target: TargetCpu,
}

impl Prefix {
    /// Decode a block prefix. `numerical` must match the guest identity the
    /// runtime uses for completion.
    pub(crate) fn decode(
        source: &[u8],
        base: GuestAddress,
        scalable: ScalableProfile,
        numerical: NumericalFeatures,
        target: TargetCpu,
    ) -> Result<Self, CompileError> {
        if source.is_empty()
            || !source.len().is_multiple_of(INSTRUCTION_BYTES)
            || !base.0.is_multiple_of(INSTRUCTION_BYTES as u64)
            || source.len() / INSTRUCTION_BYTES > MAX_BLOCK_INSTRUCTIONS
        {
            return Err(CompileError::new(
                crate::CompileErrorKind::InvalidContextSourceLayout,
            ));
        }
        let mut instructions = Vec::new();
        let mut terminal = None;
        let mut next_pc = base;
        let mut source_bytes = 0;
        for bytes in source.as_chunks::<INSTRUCTION_BYTES>().0 {
            let pc = next_pc;
            next_pc =
                GuestAddress(pc.0.checked_add(INSTRUCTION_BYTES as u64).ok_or_else(|| {
                    CompileError::new(crate::CompileErrorKind::GuestAddressOverflow)
                })?);
            source_bytes += INSTRUCTION_BYTES;
            let word = u32::from_le_bytes(*bytes);
            reject_unavailable_service(pc, word)?;
            if let Some(numerical_instruction) = decode_scalable_numerical_instruction(pc, word)? {
                let admitted = admit_scalable_numerical_instruction(
                    numerical_instruction,
                    scalable,
                    numerical,
                )?;
                terminal = Some(Terminal::Numerical(admitted));
                break;
            }
            match decode(pc, word, scalable, target) {
                Ok(instruction)
                    if instruction.memory_requirements() != MemoryRequirements::default() =>
                {
                    return Err(CompileError::new(
                        crate::CompileErrorKind::ContextMemoryUnimplemented,
                    )
                    .at(pc));
                }
                Ok(Decoded::Ordinary(instruction)) if is_transfer(&instruction.operation) => {
                    terminal = shared_terminal(bytes, pc, target)?
                        .map(|plan| Terminal::Shared(Box::new(plan)));
                    debug_assert!(
                        terminal.is_some(),
                        "ordinary transfer has a shared boundary"
                    );
                    break;
                }
                Ok(instruction) => instructions.push((pc, instruction)),
                Err(error) => {
                    if let Some(shared) = shared_terminal(bytes, pc, target)? {
                        terminal = Some(Terminal::Shared(Box::new(shared)));
                        break;
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self {
            instructions,
            terminal,
            next_pc,
            source_bytes,
            scalable,
            numerical,
            target,
        })
    }

    pub(crate) const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    pub(crate) fn emit(self) -> Result<CompiledBlock, CompileError> {
        let target = self.target;
        let vector_length = self.scalable.vector_length();
        let mut code = context_wrapper();
        let mut source_map =
            Vec::with_capacity(self.instructions.len() + usize::from(self.terminal.is_some()));
        let mut fixups = Vec::new();
        for (pc, instruction) in self.instructions {
            source_map.push((pc, code.len()));
            super::emit_decoded(
                &mut code,
                pc,
                instruction,
                self.scalable,
                target,
                &mut fixups,
            )?;
        }
        debug_assert!(fixups.is_empty(), "context block prefix cannot transfer");
        let mut terminal_bytes = Vec::new();
        match self.terminal {
            Some(Terminal::Shared(plan)) => {
                let shared = plan.compile()?;
                let offset = code.len();
                source_map.extend(
                    shared
                        .native
                        .source_map
                        .into_iter()
                        .map(|(pc, at)| (pc, at + offset)),
                );
                terminal_bytes = shared.native.x86_64_code;
            }
            Some(Terminal::Numerical(instruction)) => {
                let pc = instruction.instruction_pc();
                source_map.push((pc, code.len()));
                let emitted = match *instruction.operation() {
                    ScalableNumericalOperation::Sve(operation) => x86_64::sve::floating::emit(
                        &mut code,
                        instruction.word(),
                        operation,
                        vector_length,
                        self.numerical,
                        pc,
                        target,
                    )?,
                    ScalableNumericalOperation::SmeExtremaScale(operand) => {
                        x86_64::sme::extrema_scale::emit(
                            &mut code,
                            operand,
                            vector_length,
                            self.numerical,
                            pc,
                            target,
                        )?
                    }
                    ScalableNumericalOperation::SmeVector(_)
                    | ScalableNumericalOperation::SmeMatrix(_)
                    | ScalableNumericalOperation::FixedFp8Conversion(_)
                    | ScalableNumericalOperation::SmeFp8Conversion(_)
                    | ScalableNumericalOperation::SmeFp8Matrix(_) => false,
                };
                if emitted {
                    // The guarded family mapping owns the exact-PC cold exit.
                    // Only its committed fast path reaches the continuation.
                    x86_64::block::direct_exit(
                        &mut code,
                        instruction.next_pc(),
                        ExitKind::Fallthrough,
                    );
                } else {
                    x86_64::block::direct_exit(&mut code, pc, ExitKind::ScalableNumerical);
                }
            }
            None => x86_64::block::direct_exit(&mut code, self.next_pc, ExitKind::Fallthrough),
        }
        let mut bytes = code.into_bytes();
        bytes.extend(terminal_bytes);
        Ok(CompiledBlock {
            native: NativeBlock {
                x86_64_code: bytes,
                source_map,
            },
            source_bytes: self.source_bytes,
            direct_exits: Vec::new(),
            fault_recovery: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::scalable::{ScalableMode, VectorLength};
    use crate::block::Features;
    use alloc::vec;
    use alloc::vec::Vec;
    use alloc::{format, string::ToString};

    const BASE: GuestAddress = GuestAddress(0x1000);
    const ADD_X5_ONE: u32 = 0x9100_04a5;
    const FADD_Z0_SINGLE: u32 = 0x6580_8020;
    const SVC: u32 = 0xd400_0001;
    const BRK: u32 = 0xd420_0000;
    const ERET: u32 = 0xd69f_03e0;
    const IRG: u32 = 0x9ac0_1000;
    const PACIBSP: u32 = 0xd503_237f;
    const CNTVCT: u32 = 0xd53b_e040;
    const TPIDRRO: u32 = 0xd53b_d060;
    const RET: u32 = 0xd65f_03c0;
    const PACGA_X1_X2_X3: u32 = 0x9ac3_3041;
    const LDRAA_X1_X2: u32 = 0xf820_0441;
    const LDRAB_X1_X2: u32 = 0xf8a0_0441;
    const SERVICE_WORDS: &[u32] = &[
        ERET,
        IRG,
        PACIBSP,
        CNTVCT,
        TPIDRRO,
        PACGA_X1_X2_X3,
        LDRAA_X1_X2,
        LDRAB_X1_X2,
    ];

    fn source(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    const CONTEXT_BLOCK: BlockProfile = BlockProfile::new(Features::CONTEXT);

    fn scalable() -> ScalableProfile {
        ScalableProfile::new(
            VectorLength::from_bytes(16).unwrap(),
            ScalableMode::new(true, false),
        )
    }

    fn context_block(
        source: &[u8],
        base: GuestAddress,
        profile: BlockProfile,
        target: TargetCpu,
    ) -> Result<CompiledBlock, CompileError> {
        crate::compile(
            source,
            base,
            &Options::new(profile, target)
                .with_scalable(scalable())
                .with_numerical_features(NumericalFeatures::default()),
        )
    }

    #[test]
    fn context_blocks_refuse_other_services() {
        for services in [
            BlockProfile::new(Features::SYSTEM),
            BlockProfile::new(Features::POINTER_AUTHENTICATION),
            BlockProfile::new(Features::POINTER_AUTHENTICATION.union(Features::CLOCK)),
            BlockProfile::new(Features::THREAD_REGISTERS.union(Features::AMX)),
            BlockProfile::new(
                Features::POINTER_AUTHENTICATION
                    .union(Features::THREAD_REGISTERS)
                    .union(Features::AMX),
            ),
            BlockProfile::new(Features::PROCESS_HELPERS.union(Features::AMX)),
        ] {
            let error = context_block(
                &source(&[RET]),
                BASE,
                BlockProfile::new(Features::CONTEXT | services.features()),
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.to_string().contains("no emitter implements"));
        }
    }

    #[test]
    fn ordinary_trap_extent_stays_distinct_from_forbidden_system_completion() {
        for trap in [SVC, BRK] {
            let compiled = context_block(
                &source(&[ADD_X5_ONE, trap, ERET]),
                BASE,
                CONTEXT_BLOCK,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(compiled.source_bytes, 2 * INSTRUCTION_BYTES);
            assert_eq!(
                compiled
                    .native
                    .source_map
                    .iter()
                    .map(|row| row.0)
                    .collect::<Vec<_>>(),
                [BASE, GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64)]
            );
        }
        for &service in SERVICE_WORDS {
            for words in [vec![service, RET], vec![ADD_X5_ONE, service, RET]] {
                let offset = if words[0] == ADD_X5_ONE {
                    INSTRUCTION_BYTES
                } else {
                    0
                };
                let error =
                    context_block(&source(&words), BASE, CONTEXT_BLOCK, TargetCpu::Baseline)
                        .unwrap_err();
                assert!(error.to_string().contains("service is not integrated"));
                assert!(
                    error
                        .to_string()
                        .contains(&format!("{:#x}", BASE.0 + offset as u64))
                );
            }
        }
    }

    #[test]
    fn unconsumed_service_after_numerical_boundary_does_not_expand_extent() {
        for &service in SERVICE_WORDS {
            let compiled = context_block(
                &source(&[ADD_X5_ONE, FADD_Z0_SINGLE, service]),
                BASE,
                CONTEXT_BLOCK,
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(compiled.source_bytes, 2 * INSTRUCTION_BYTES);
            assert_eq!(compiled.native.source_map.len(), 2);
            assert_eq!(
                compiled.native.source_map[1].0,
                GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64)
            );
        }
    }

    #[test]
    fn strict_ordinary_ram_atomic_legacy_fp_and_prefix_declines_stay_explicit() {
        const LDR_X0_X1: u32 = 0xf940_0020;
        const CAS_X0_X1_X2: u32 = 0xc8a0_7c41;
        const FADD_S0_S1_S2: u32 = 0x1e22_2820;
        const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
        for word in [LDR_X0_X1, CAS_X0_X1_X2, FADD_S0_S1_S2, MOVPRFX_Z0_Z1] {
            assert!(
                context_block(
                    &source(&[ADD_X5_ONE, word, RET]),
                    BASE,
                    CONTEXT_BLOCK,
                    TargetCpu::Baseline,
                )
                .is_err()
            );
        }
    }
    #[test]
    fn movprfx_pairs_remain_leaf_only_and_numerical_followers_decline() {
        const UNPREDICATED_PREFIX: u32 = 0x0420_bc20;
        const ZEROING_PREFIX: u32 = 0x0410_2020;
        const MERGING_PREFIX: u32 = 0x0411_2020;
        const AND_DESTRUCTIVE: u32 = 0x041a_0040;
        let block_profile = CONTEXT_BLOCK;
        for prefix in [UNPREDICATED_PREFIX, ZEROING_PREFIX, MERGING_PREFIX] {
            let bytes = source(&[prefix, AND_DESTRUCTIVE, RET]);
            let leaf = crate::testing::context_leaf(&bytes, BASE, scalable(), TargetCpu::Baseline)
                .unwrap();
            assert_eq!(
                leaf.source_map.iter().map(|row| row.0).collect::<Vec<_>>(),
                [
                    BASE,
                    GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64),
                    GuestAddress(BASE.0 + 2 * INSTRUCTION_BYTES as u64),
                ]
            );
            let error =
                context_block(&bytes, BASE, block_profile, TargetCpu::Baseline).unwrap_err();
            assert!(error.to_string().contains(&format!("{:#x}", BASE.0)));
        }
        let error = crate::testing::context_leaf(
            &source(&[UNPREDICATED_PREFIX, FADD_Z0_SINGLE, RET]),
            BASE,
            scalable(),
            TargetCpu::Baseline,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unsupported follower"));
        assert!(
            error
                .to_string()
                .contains(&format!("{:#x}", BASE.0 + INSTRUCTION_BYTES as u64))
        );
    }
}
