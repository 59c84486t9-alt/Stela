//! Leaf compilation with an execution context and a scalable specialization.

mod admission;
pub mod block;
pub mod debug_movement;
mod decoded;
mod prefix;
mod profile;

use admission::{decode, decode_recording_features};
pub(crate) use decoded::{Decoded, ordinary_permitted};
pub use profile::ScalableProfile;

use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    aarch64::{
        Instruction, Operation,
        scalable::{
            execution::{InstructionExecutionRequirements, ScalableExecutionRequirements},
            features::FeatureRequirement,
        },
    },
    context::memory::MemoryRequirements,
    x86_64,
};
use alloc::{collections::BTreeMap, format, vec, vec::Vec};

pub const PROFILE_ID: &str = "apple-sme2-streaming-v1";
pub const DECLARED_PROFILE_ID: &str = "sme-streaming-v2";
const INSTRUCTION_BYTES: usize = size_of::<u32>();
const PUSH_R15: &[u8] = &[0x41, 0x57];
const MOV_R15_RSI: &[u8] = &[0x49, 0x89, 0xf7];
const CALL_REL32: u8 = 0xe8;
const POP_R15: &[u8] = &[0x41, 0x5f];
const RET: u8 = 0xc3;
const CALL_BYTES: usize = 1 + size_of::<i32>();
const CALL_END: usize = PUSH_R15.len() + MOV_R15_RSI.len() + CALL_BYTES;
pub const CONTEXT_WRAPPER_BYTES: usize = CALL_END + POP_R15.len() + 1;

pub(crate) fn context_wrapper() -> Vec<u8> {
    let mut code = Vec::with_capacity(CONTEXT_WRAPPER_BYTES);
    code.extend(PUSH_R15);
    code.extend(MOV_R15_RSI);
    code.push(CALL_REL32);
    code.extend(((CONTEXT_WRAPPER_BYTES - CALL_END) as i32).to_le_bytes());
    code.extend(POP_R15);
    code.push(RET);
    code
}

fn emit_decoded(
    code: &mut Vec<u8>,
    pc: GuestAddress,
    instruction: Decoded,
    profile: ScalableProfile,
    target: TargetCpu,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
) -> Result<(), CompileError> {
    match instruction {
        Decoded::Exclusive(_) => {
            return Err(CompileError(
                "exclusive service was not requested by scalable profile".into(),
            ));
        }
        Decoded::MemoryScalar(_) => {
            return Err(CompileError(
                "checked scalar service was not requested by scalable profile".into(),
            ));
        }
        Decoded::MemoryPair(_) | Decoded::MemoryFixed(_) => {
            return Err(CompileError(
                "checked fixed-width memory service was not requested by scalable profile".into(),
            ));
        }
        Decoded::Address(operand) => {
            x86_64::sve::address::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::Ordinary(instruction) => {
            x86_64::emit_instruction(code, &instruction, fixups, target);
        }
        Decoded::IntegerDot(operand) => {
            if !x86_64::sve::dot::emit_integer(code, &operand, profile.vector_length(), target) {
                return Err(CompileError(format!(
                    "unsupported streaming integer dot operands at {:#x}",
                    pc.0
                )));
            }
        }
        Decoded::IntegerPredicateMove(operand) => {
            x86_64::sve::integer_predicate_move::emit(
                code,
                operand,
                profile.vector_length(),
                target,
            );
        }
        Decoded::IntegerBits(operand) => {
            x86_64::sve::integer_bits::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerLogic(operand) => {
            x86_64::sve::integer_logic::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerComparison(operand) => {
            x86_64::sve::integer_comparison::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerArithmetic(operand) => {
            x86_64::sve::integer_arithmetic::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::IntegerSaturation(operand) => {
            x86_64::sve::integer_saturation::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::RearrangeWiden(operand) => {
            x86_64::sve::rearrange_widen::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::Shifts(operand) => {
            x86_64::sve::shifts::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::ShiftsNarrow(operand) => {
            x86_64::sve::shifts_narrow::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::Sign(operand) => {
            x86_64::sve::sign::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::IntegerProducts(operand) => {
            x86_64::sve::integer_products::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::SmeIntegerDots(operand) => {
            x86_64::sme::integer_dots::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::RearrangeExtract(operand) => {
            x86_64::sve::rearrange_extract::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::FloatingCopy(operand) => {
            x86_64::sve::floating_copy::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::PredicateGeneration(operand) => {
            x86_64::sve::predicate_generation::emit(
                code,
                &operand,
                profile.vector_length(),
                target,
            );
        }
        Decoded::PredicateLogic(operand) => {
            x86_64::sve::predicate_logic::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::Reductions(operand) => {
            x86_64::sve::reductions::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::Rearrange(operand) => {
            x86_64::sve::rearrange::emit(code, operand, profile.vector_length(), target);
        }
        Decoded::SmeIntegerVector(operand) => {
            x86_64::sme::integer_vector::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeMovement(operand) => {
            x86_64::sme::movement::emit(code, &operand, profile.vector_length(), target)
                .map_err(|reason| CompileError(format!("{reason} at {:#x}", pc.0)))?;
        }
        Decoded::SmeLutV2(operand) => {
            x86_64::sme::tables::emit_lut_v2(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeTables(operand) => {
            x86_64::sme::tables::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SveTables(operand) => {
            x86_64::sve::tables::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeIntegerMatrix(operand) => {
            x86_64::sme::integer_matrix::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::SmeMemory(operand) => {
            x86_64::sme::memory::emit(code, &operand, profile.vector_length(), target, pc.0)
                .map_err(|reason| CompileError(format!("{reason} at {:#x}", pc.0)))?;
        }
        Decoded::MemoryLoad(operand) => {
            x86_64::sve::memory_load::emit(code, operand, profile.vector_length(), target, pc.0);
        }
        Decoded::MemoryMulti(operand) => {
            x86_64::sve::memory_multi::emit(code, &operand, profile.vector_length(), target, pc.0);
        }
        Decoded::MemoryStore(operand) => {
            x86_64::sve::memory_store::emit(code, &operand, profile.vector_length(), target, pc.0);
        }
        Decoded::MemoryStructure(operand) => {
            x86_64::sve::memory_structure::emit(
                code,
                &operand,
                profile.vector_length(),
                target,
                pc.0,
            );
        }
        Decoded::Length(operand) => {
            x86_64::sme::length::emit(code, &operand, profile.vector_length());
        }
    }
    Ok(())
}

struct DecodedLeafInstruction {
    pc: GuestAddress,
    instruction: Decoded,
    feature_clauses: Vec<FeatureRequirement>,
}

fn decode_leaf(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Vec<DecodedLeafInstruction>, CompileError> {
    if source.is_empty()
        || !source.len().is_multiple_of(INSTRUCTION_BYTES)
        || !base.0.is_multiple_of(INSTRUCTION_BYTES as u64)
    {
        return Err(CompileError(
            "input and guest base must be nonempty/aligned to 4 bytes".into(),
        ));
    }
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < source.len() {
        if let Some(pair) = prefix::decode_pair(source, offset, base, profile, target)? {
            instructions.push(DecodedLeafInstruction {
                pc: pair.prefix_pc,
                instruction: Decoded::IntegerLogic(pair.prefix),
                feature_clauses: vec![pair.prefix_features],
            });
            instructions.push(DecodedLeafInstruction {
                pc: pair.follower_pc,
                instruction: pair.follower,
                feature_clauses: pair.follower_features,
            });
            offset += prefix::PAIR_BYTES;
            continue;
        }
        let pc = GuestAddress(
            base.0
                .checked_add(offset as u64)
                .ok_or_else(|| CompileError("guest address overflow".into()))?,
        );
        let word = u32::from_le_bytes(
            source[offset..offset + INSTRUCTION_BYTES]
                .try_into()
                .expect("checked leaf instruction alignment"),
        );
        let mut feature_clauses = Vec::new();
        let instruction =
            decode_recording_features(pc, word, profile, target, &mut feature_clauses)?;
        instructions.push(DecodedLeafInstruction {
            pc,
            instruction,
            feature_clauses,
        });
        offset += INSTRUCTION_BYTES;
    }
    if !matches!(
        instructions.last(),
        Some(DecodedLeafInstruction {
            instruction: Decoded::Ordinary(Instruction {
                operation: Operation::Return,
                ..
            }),
            ..
        })
    ) {
        return Err(CompileError("leaf region must end in RET X30".into()));
    }
    for DecodedLeafInstruction {
        pc,
        instruction: decoded,
        ..
    } in &instructions
    {
        let Decoded::Ordinary(instruction) = decoded else {
            continue;
        };
        let target = match &instruction.operation {
            Operation::Branch { target }
            | Operation::BranchCondition { target, .. }
            | Operation::BranchZero { target, .. }
            | Operation::BranchBit { target, .. } => Some(*target),
            _ => None,
        };
        if let Some(target) = target
            && instructions
                .binary_search_by_key(&target.0, |instruction| instruction.pc.0)
                .is_err()
        {
            return Err(CompileError(format!(
                "unresolved direct target {:#x} from {:#x}",
                target.0, pc.0
            )));
        }
    }
    Ok(instructions)
}

/// Derive the whole body's service requirements with the same parser used to
/// compile it. Leaves with no memory access return empty requirements.
pub fn memory_requirements(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<MemoryRequirements, CompileError> {
    leaf_memory_requirements(&decode_leaf(source, base, profile, target)?)
}

fn leaf_memory_requirements(
    instructions: &[DecodedLeafInstruction],
) -> Result<MemoryRequirements, CompileError> {
    instructions
        .iter()
        .try_fold(MemoryRequirements::default(), |requirements, decoded| {
            requirements
                .merge(decoded.instruction.memory_requirements())
                .ok_or_else(|| {
                    CompileError(format!(
                        "conflicting memory control requirements at {:#x}",
                        decoded.pc.0
                    ))
                })
        })
}

/// All outputs derive from one validated source vector. No caller-supplied
/// execution metadata or service requirements are accepted.
pub struct PreparedLeafCode {
    pub native: NativeBlock,
    pub memory_requirements: MemoryRequirements,
    pub execution_requirements: ScalableExecutionRequirements,
}

pub fn prepare_leaf(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<PreparedLeafCode, CompileError> {
    let instructions = decode_leaf(source, base, profile, target)?;
    let memory_requirements = leaf_memory_requirements(&instructions)?;
    let execution_requirements = ScalableExecutionRequirements::new(
        instructions
            .iter()
            .map(|decoded| {
                InstructionExecutionRequirements::new(
                    decoded.pc,
                    decoded.feature_clauses.clone(),
                    decoded.instruction.execution_access_requirements(),
                    decoded.instruction.guest_memory_quantity(),
                )
            })
            .collect(),
    );
    let native = emit_leaf(instructions, profile, target)?;
    Ok(PreparedLeafCode {
        native,
        memory_requirements,
        execution_requirements,
    })
}

/// Compile a two-argument context leaf ending in RET X30. The runtime validates
/// this profile against its state before calling it.
pub fn compile_for_profile(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    emit_leaf(decode_leaf(source, base, profile, target)?, profile, target)
}

fn emit_leaf(
    instructions: Vec<DecodedLeafInstruction>,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let mut code = context_wrapper();
    let mut source_map = Vec::with_capacity(instructions.len());
    let mut fixups = Vec::new();
    for DecodedLeafInstruction {
        pc, instruction, ..
    } in instructions
    {
        source_map.push((pc, code.len()));
        emit_decoded(&mut code, pc, instruction, profile, target, &mut fixups)?;
    }
    let offsets: BTreeMap<_, _> = source_map
        .iter()
        .map(|(pc, offset)| (pc.0, *offset))
        .collect();
    for (pc, target, displacement) in fixups {
        let destination = offsets.get(&target.0).ok_or_else(|| {
            CompileError(format!(
                "unresolved direct target {:#x} from {:#x}",
                target.0, pc.0
            ))
        })?;
        let relative =
            i32::try_from(*destination as i128 - (displacement + size_of::<i32>()) as i128)
                .map_err(|_| CompileError("native branch displacement overflow".into()))?;
        code[displacement..displacement + size_of::<i32>()]
            .copy_from_slice(&relative.to_le_bytes());
    }
    Ok(NativeBlock {
        x86_64_code: code,
        source_map,
    })
}

#[cfg(test)]
mod tests;
