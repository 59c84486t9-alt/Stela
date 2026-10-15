//! Context-backed blocks with shared control-flow and numerical boundaries.
//!
//! A service exit returns its still-unexecuted guest PC. The caller resolves
//! that PC against the immutable consumed source and advances only on success.

use super::{Decoded, INSTRUCTION_BYTES, ScalableProfile, context_wrapper, decode};
use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock, TargetCpu,
    aarch64::{Decoder, Operation, floating::features::NumericalFeatures},
    block::{
        self, BlockProfile, CompiledBlock, ExitKind, MAX_BLOCK_INSTRUCTIONS,
        scalable::{
            AdmittedScalableNumericalInstruction, ScalableNumericalOperation,
            admit_scalable_numerical_instruction, decode_scalable_numerical_instruction,
        },
    },
    context::memory::MemoryRequirements,
    x86_64,
};

const MOV_RAX_IMMEDIATE: &[u8] = &[0x48, 0xb8];
const MOV_EDX_IMMEDIATE: u8 = 0xba;
const RETURN: u8 = 0xc3;

/// Guest services and numerical feature availability remain distinct from host
/// capabilities and the set of instruction mappings currently implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedBlockProfile {
    scalable: ScalableProfile,
    services: BlockProfile,
    numerical_features: NumericalFeatures,
}

impl ExtendedBlockProfile {
    pub const fn new(
        scalable: ScalableProfile,
        services: BlockProfile,
        numerical_features: NumericalFeatures,
    ) -> Self {
        Self {
            scalable,
            services,
            numerical_features,
        }
    }

    pub const fn scalable(self) -> ScalableProfile {
        self.scalable
    }
    pub const fn services(self) -> BlockProfile {
        self.services
    }
    pub const fn numerical_features(self) -> NumericalFeatures {
        self.numerical_features
    }
}

enum Terminal {
    Shared(CompiledBlock),
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
    {
        return Err(CompileError(format!(
            "context block service is not integrated at {:#x}",
            pc.0
        )));
    }
    Ok(())
}

fn shared_terminal(
    bytes: &[u8; INSTRUCTION_BYTES],
    pc: GuestAddress,
    profile: BlockProfile,
    target: TargetCpu,
) -> Result<Option<CompiledBlock>, CompileError> {
    if let Ok(instruction) = Decoder.lift(pc, u32::from_le_bytes(*bytes))
        && matches!(instruction.operation, Operation::FloatingPoint(_))
    {
        return Ok(None);
    }
    let analysis = block::analyze_with_profile(bytes, pc, profile)
        .map_err(|error| CompileError(error.to_string()))?;
    // The ordinary scalar numerical boundary is deliberately excluded until
    // its low-V/upper-Z effects have been integrated in context mode.
    let permitted = analysis.trap.is_some()
        || analysis.dynamic_edge.is_some()
        || (analysis.terminator_pc.is_some() && !analysis.static_successors.is_empty());
    if permitted {
        block::compile_for_target(bytes, pc, profile, target).map(Some)
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

/// Compile a bounded consumed prefix. Ordinary RAM, legacy FP/SIMD, mode writes
/// and MOVPRFX retain the explicit declines of the context leaf compiler.
/// NumericalFeatures must come from the same immutable guest/control identity
/// used by runtime completion; no callback or host capability grants a feature.
pub fn compile_for_profile(
    source: &[u8],
    base: GuestAddress,
    profile: ExtendedBlockProfile,
    target: TargetCpu,
) -> Result<CompiledBlock, CompileError> {
    if profile.services != BlockProfile::Ordinary {
        return Err(CompileError(
            "context block services are not integrated".into(),
        ));
    }
    if source.is_empty()
        || !source.len().is_multiple_of(INSTRUCTION_BYTES)
        || !base.0.is_multiple_of(INSTRUCTION_BYTES as u64)
        || source.len() / INSTRUCTION_BYTES > MAX_BLOCK_INSTRUCTIONS
    {
        return Err(CompileError(
            "context block input must be aligned, nonempty and bounded".into(),
        ));
    }
    let mut instructions = Vec::new();
    let mut terminal = None;
    let mut next_pc = base;
    let mut source_bytes = 0;
    for bytes in source.as_chunks::<INSTRUCTION_BYTES>().0 {
        let pc = next_pc;
        next_pc = GuestAddress(
            pc.0.checked_add(INSTRUCTION_BYTES as u64)
                .ok_or_else(|| CompileError("context block guest address overflow".into()))?,
        );
        source_bytes += INSTRUCTION_BYTES;
        let word = u32::from_le_bytes(*bytes);
        reject_unavailable_service(pc, word)?;
        if let Some(numerical) = decode_scalable_numerical_instruction(pc, word)? {
            let admitted = admit_scalable_numerical_instruction(
                numerical,
                profile.scalable,
                profile.numerical_features,
            )?;
            terminal = Some(Terminal::Numerical(admitted));
            break;
        }
        match decode(pc, word, profile.scalable, target) {
            Ok(instruction)
                if instruction.memory_requirements() != MemoryRequirements::default() =>
            {
                return Err(CompileError(format!(
                    "context block memory entry is not integrated at {:#x}",
                    pc.0
                )));
            }
            Ok(Decoded::Ordinary(instruction)) if is_transfer(&instruction.operation) => {
                terminal =
                    shared_terminal(bytes, pc, profile.services, target)?.map(Terminal::Shared);
                debug_assert!(
                    terminal.is_some(),
                    "ordinary transfer has a shared boundary"
                );
                break;
            }
            Ok(instruction) => instructions.push((pc, instruction)),
            Err(error) => {
                if let Some(shared) = shared_terminal(bytes, pc, profile.services, target)? {
                    terminal = Some(Terminal::Shared(shared));
                    break;
                }
                return Err(error);
            }
        }
    }
    let mut code = context_wrapper();
    let mut source_map = Vec::with_capacity(instructions.len() + usize::from(terminal.is_some()));
    let mut fixups = Vec::new();
    for (pc, instruction) in instructions {
        source_map.push((pc, code.len()));
        super::emit_decoded(
            &mut code,
            pc,
            instruction,
            profile.scalable,
            target,
            &mut fixups,
        )?;
    }
    debug_assert!(fixups.is_empty(), "context block prefix cannot transfer");
    match terminal {
        Some(Terminal::Shared(shared)) => {
            let offset = code.len();
            source_map.extend(
                shared
                    .native
                    .source_map
                    .into_iter()
                    .map(|(pc, at)| (pc, at + offset)),
            );
            code.extend(shared.native.x86_64_code);
        }
        Some(Terminal::Numerical(instruction)) => {
            let pc = instruction.instruction_pc();
            source_map.push((pc, code.len()));
            let emitted = match *instruction.operation() {
                ScalableNumericalOperation::Sve(operation) => x86_64::sve::floating::emit(
                    &mut code,
                    instruction.word(),
                    operation,
                    profile.scalable.vector_length(),
                    profile.numerical_features,
                    pc,
                    target,
                )?,
                ScalableNumericalOperation::SmeExtremaScale(operand) => {
                    x86_64::sme::extrema_scale::emit(
                        &mut code,
                        operand,
                        profile.scalable.vector_length(),
                        profile.numerical_features,
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
                code.extend(
                    x86_64::block::emit_for_target(&[], None, instruction.next_pc(), target)
                        .x86_64_code,
                );
            } else {
                code.extend(MOV_RAX_IMMEDIATE);
                code.extend(pc.0.to_le_bytes());
                code.push(MOV_EDX_IMMEDIATE);
                code.extend((ExitKind::ScalableNumerical as u32).to_le_bytes());
                code.push(RETURN);
            }
        }
        None => code.extend(x86_64::block::emit_for_target(&[], None, next_pc, target).x86_64_code),
    }
    Ok(CompiledBlock {
        native: NativeBlock {
            x86_64_code: code,
            source_map,
        },
        source_bytes,
    })
}

#[cfg(test)]
mod activation_service_tests;
