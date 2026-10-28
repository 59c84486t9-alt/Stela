//! Leaf compilation with an execution context and a scalable specialization.
use crate::x86_64::asm::Code;

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
    code: &mut Code,
    pc: GuestAddress,
    instruction: Decoded,
    profile: ScalableProfile,
    target: TargetCpu,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
) -> Result<(), CompileError> {
    match instruction {
        Decoded::SharedMemory(_) | Decoded::Exclusive(_) => {
            return Err(CompileError(
                "exclusive service was not requested by scalable profile".into(),
            ));
        }
        Decoded::MemoryScalar(_) => {
            return Err(CompileError(
                "checked scalar service was not requested by scalable profile".into(),
            ));
        }
        Decoded::MemoryPair(_) | Decoded::MemoryFixed(_) | Decoded::PrefetchHint => {
            return Err(CompileError(
                "checked fixed-width memory service was not requested by scalable profile".into(),
            ));
        }
        Decoded::Address(operand) => {
            x86_64::sve::address::emit(code, &operand, profile.vector_length(), target);
        }
        Decoded::Ordinary(instruction) => {
            x86_64::emit_instruction(
                code,
                &instruction,
                fixups,
                target,
                x86_64::MemoryChecks::DEFAULT,
            );
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
    let mut code = Code::from(context_wrapper());
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
        x86_64_code: code.into_bytes(),
        source_map,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Lifter,
        aarch64::{
            Decoder,
            scalable::{
                ElementSize, ScalableMode, VectorLength,
                features::{ScalableFeature, ScalableFeatures},
                profile::ScalableControls,
            },
        },
        context::{ExecutionContext, ScalableStateView},
    };
    use alloc::{vec, vec::Vec};

    mod address {
        use super::*;

        #[test]
        fn address_counts_require_streaming_but_sme_length_does_not() {
            const ADDVL_X0_ONE: u32 = 0x0420_5020;
            const RDVL_X0_ONE: u32 = 0x04bf_5020;
            const CNTP_X0_P0: u32 = 0x2520_8000;
            const CNTP_X0_PN0: u32 = 0x2520_8200;
            const SQINCW_X0_W0: u32 = 0x04a0_f000;
            const UQDECW_Z0: u32 = 0x04a0_cc00;
            for bytes in [16, 32, 64, 128, 256] {
                for word in [
                    ADDVL_X0_ONE,
                    RDVL_X0_ONE,
                    CNTP_X0_P0,
                    CNTP_X0_PN0,
                    SQINCW_X0_W0,
                    UQDECW_Z0,
                ] {
                    for za in [false, true] {
                        let selected = ScalableProfile::new(
                            VectorLength::from_bytes(bytes).unwrap(),
                            ScalableMode::new(true, za),
                        );
                        assert!(
                            compile_for_profile(
                                &words(&[word, RET_X30]),
                                GuestAddress(0),
                                selected,
                                TargetCpu::Baseline
                            )
                            .is_ok()
                        );
                        let inactive = ScalableProfile::new(
                            VectorLength::from_bytes(bytes).unwrap(),
                            ScalableMode::new(false, za),
                        );
                        assert!(
                            compile_for_profile(
                                &words(&[word, RET_X30]),
                                GuestAddress(0),
                                inactive,
                                TargetCpu::Baseline
                            )
                            .unwrap_err()
                            .0
                            .contains("streaming mode required")
                        );
                    }
                    assert!(crate::compile(&words(&[word, RET_X30]), GuestAddress(0)).is_err());
                }
                assert!(
                    compile_for_profile(
                        &words(&[RDSVL_X0_ONE, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, false),
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
            }
        }

        #[test]
        fn address_vector_reserved_width_declines_before_mode_checks() {
            const RESERVED_BYTE_VECTOR_WORDS: [u32; 12] = [
                0x0430_c000,
                0x0430_c400,
                0x0420_c000,
                0x0420_c400,
                0x0420_c800,
                0x0420_cc00,
                0x252c_8000,
                0x252d_8000,
                0x2528_8000,
                0x2529_8000,
                0x252a_8000,
                0x252b_8000,
            ];
            for word in RESERVED_BYTE_VECTOR_WORDS {
                for streaming in [false, true] {
                    assert!(
                        compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            profile(16, streaming),
                            TargetCpu::Baseline
                        )
                        .unwrap_err()
                        .0
                        .contains("reserved")
                    );
                }
            }
        }

        #[test]
        fn address_counter_requires_declared_sme2() {
            const ADDVL_X0_ONE: u32 = 0x0420_5020;
            const CNTP_X0_PN0: u32 = 0x2520_8200;
            let length = VectorLength::from_bytes(16).unwrap();
            let selected = ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, false),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap();
            assert!(
                compile_for_profile(
                    &words(&[ADDVL_X0_ONE, RET_X30]),
                    GuestAddress(0),
                    selected,
                    TargetCpu::Baseline
                )
                .is_ok()
            );
            assert!(
                compile_for_profile(
                    &words(&[CNTP_X0_PN0, RET_X30]),
                    GuestAddress(0),
                    selected,
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("FEAT_SME2")
            );
        }
    }
    mod boundaries {
        use super::*;

        #[test]
        fn ordinary_payload_and_maps_preserve_original_bytes() {
            let source = words(&[NOP, 0xd280_00e0, RET_X30]);
            let old = crate::compile(&source, GuestAddress(0x1000)).unwrap();
            let new = compile_for_profile(
                &source,
                GuestAddress(0x1000),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap();
            assert_eq!(&new.x86_64_code[CONTEXT_WRAPPER_BYTES..], old.x86_64_code);
            assert_eq!(
                new.source_map,
                old.source_map
                    .iter()
                    .map(|(pc, offset)| (*pc, offset + CONTEXT_WRAPPER_BYTES))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                context_wrapper(),
                [
                    0x41, 0x57, 0x49, 0x89, 0xf7, 0xe8, 3, 0, 0, 0, 0x41, 0x5f, 0xc3
                ]
            );
        }

        #[test]
        fn variable_length_modes_and_prefix_boundary_are_explicit() {
            for bytes in [16, 32, 64, 128, 256] {
                let source = words(&[AND_Z0_Z1_Z2, RDSVL_X0_ONE, RET_X30]);
                assert!(
                    compile_for_profile(
                        &source,
                        GuestAddress(0),
                        profile(bytes, true),
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
                assert!(
                    compile_for_profile(
                        &source,
                        GuestAddress(0),
                        profile(bytes, false),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("streaming mode required")
                );
                assert!(
                    compile_for_profile(
                        &words(&[RDSVL_X0_ONE, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, false),
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
            }
            assert!(
                compile_for_profile(
                    &words(&[MOVPRFX_Z0_Z1, AND_Z0_Z1_Z2, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
            for word in [0xf940_0020, 0x4e22_8420, 0x1e22_2820] {
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        profile(32, true),
                        TargetCpu::Baseline
                    )
                    .is_err()
                );
            }
        }
        #[test]
        fn branches_resolve_across_scalable_instruction_bodies() {
            const BRANCH_PLUS_EIGHT: u32 = 0x1400_0002;
            let native = compile_for_profile(
                &words(&[BRANCH_PLUS_EIGHT, AND_Z0_Z1_Z2, RET_X30]),
                GuestAddress(0),
                profile(32, true),
                TargetCpu::Baseline,
            )
            .unwrap();
            let branch = native.source_map[0].1;
            assert_eq!(native.x86_64_code[branch], 0xe9);
            let displacement = i32::from_le_bytes(
                native.x86_64_code[branch + 1..branch + 5]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(
                (branch + 5) as i64 + i64::from(displacement),
                native.source_map[2].1 as i64
            );
        }

        #[test]
        fn multi_vector_integer_access_and_legacy_abi_boundaries() {
            const ADD_PAIR: u32 = 0xc120_a300;
            const SQCVT_PAIR: u32 = 0xc123_e000;
            const SVE_SQCVTN_PAIR: u32 = 0x4531_4000;
            const SRSHL_PAIR: u32 = 0xc120_a220;
            const RESERVED_QUARTET_SHIFT: u32 = 0xc120_d800;
            let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
            let declared = |bytes, streaming| {
                let length = VectorLength::from_bytes(bytes).unwrap();
                ScalableProfile::new_with_features(
                    length,
                    ScalableMode::new(streaming, false),
                    features,
                    ScalableControls::new(length, false),
                )
                .unwrap()
            };
            for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
                let source = words(&[word, RET_X30]);
                assert!(crate::compile(&source, GuestAddress(0)).is_err());
                let compatible = compile_for_profile(
                    &source,
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline,
                )
                .unwrap();
                assert_eq!(
                    compatible.source_map[0],
                    (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for streaming in [false, true] {
                        let result = compile_for_profile(
                            &source,
                            GuestAddress(0),
                            declared(bytes, streaming),
                            TargetCpu::Baseline,
                        );
                        if streaming {
                            let native = result.unwrap();
                            assert_eq!(
                                native.source_map[0],
                                (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                            );
                            assert_eq!(native.source_map[1].0, GuestAddress(4));
                        } else {
                            assert!(result.unwrap_err().0.contains("streaming mode required"));
                        }
                    }
                }
            }
            assert!(
                compile_for_profile(
                    &words(&[RESERVED_QUARTET_SHIFT, RET_X30]),
                    GuestAddress(0),
                    declared(16, true),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("reserved multi-vector integer")
            );
            let sme_only = ScalableProfile::new_with_features(
                VectorLength::from_bytes(16).unwrap(),
                ScalableMode::new(true, false),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(VectorLength::from_bytes(16).unwrap(), false),
            )
            .unwrap();
            for word in [ADD_PAIR, SQCVT_PAIR, SVE_SQCVTN_PAIR, SRSHL_PAIR] {
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        sme_only,
                        TargetCpu::Baseline,
                    )
                    .is_err()
                );
            }
        }

        #[test]
        fn floating_copies_require_streaming_without_za() {
            const FCPY_HALF_P15_Z31: u32 = 0x055f_ce1f;
            const FDUP_DOUBLE_Z31: u32 = 0x25f9_ce1f;
            const RESERVED_FCPY_SIZE: u32 = 0x051f_ce1f;
            for bytes in [16, 32, 64, 128, 256] {
                for svcr in 0..=3 {
                    let profile = ScalableProfile::new(
                        VectorLength::from_bytes(bytes).unwrap(),
                        ScalableMode::from_svcr(svcr).unwrap(),
                    );
                    let source = words(&[FCPY_HALF_P15_Z31, FDUP_DOUBLE_Z31, RET_X30]);
                    let result =
                        compile_for_profile(&source, GuestAddress(0), profile, TargetCpu::Baseline);
                    if profile.mode().streaming() {
                        let native = result.unwrap();
                        assert_eq!(
                            native.source_map[0],
                            (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                        );
                        assert_eq!(native.source_map[1].0, GuestAddress(4));
                        assert!(native.source_map[1].1 > native.source_map[0].1);
                    } else {
                        assert!(result.unwrap_err().0.contains("streaming mode required"));
                    }
                }
            }
            assert!(
                crate::compile(&words(&[FCPY_HALF_P15_Z31, RET_X30]), GuestAddress(0)).is_err()
            );
            assert!(
                compile_for_profile(
                    &words(&[RESERVED_FCPY_SIZE, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved streaming floating copy")
            );
        }
    }
    mod checked_pair {
        //! Checked store-pair routing.
        use super::*;
        use crate::{
            block::{BlockProfile, CheckedMemoryProfile, CompilationPlan},
            context::memory::{SpAlignmentRequirement, flags, host_caps},
        };
        use alloc::vec::Vec;

        const BASE: GuestAddress = GuestAddress(0x1000);
        const RET: u32 = 0xd65f_03c0;
        const FORMS: [u32; 8] = [
            0x2900_0000,
            0x2980_0000,
            0x2880_0000,
            0xa900_0000,
            0xa980_0000,
            0xa880_0000,
            0x2800_0000,
            0xa800_0000,
        ];
        const REGISTER_MASK: u32 = 31;
        const BASE_SHIFT: u32 = 5;
        const SECOND_DATA_SHIFT: u32 = 10;

        fn word(form: u32, base: u32) -> u32 {
            form | (base << BASE_SHIFT) | (1 << SECOND_DATA_SHIFT)
        }

        #[test]
        fn all_store_pair_forms_reach_checked_whole_plan_and_keep_source_intervals() {
            for recipe in [
                CheckedMemoryProfile::SpAlignmentEnabled,
                CheckedMemoryProfile::SpAlignmentDisabled,
            ] {
                for form in FORMS {
                    for base in [2, REGISTER_MASK] {
                        let instruction = Decoder.lift(BASE, word(form, base)).unwrap();
                        let decoded = Decoded::checked_ordinary(instruction, recipe).unwrap();
                        assert!(matches!(decoded, Decoded::MemoryPair(_)));
                        let required = decoded.memory_requirements();
                        assert_eq!(
                            required.required_flags & (flags::WRITE | flags::PAIR),
                            flags::WRITE | flags::PAIR
                        );
                        assert_eq!(required.required_flags & flags::ASIMD, 0);
                        assert_eq!(
                            required.required_sp_alignment,
                            if base == REGISTER_MASK {
                                recipe.sp_requirement()
                            } else {
                                SpAlignmentRequirement::Any
                            }
                        );
                        if form >> 31 != 0 && recipe == CheckedMemoryProfile::SpAlignmentDisabled {
                            assert_eq!(required.required_host_caps, host_caps::CX16);
                        }
                        let source: Vec<_> = [word(form, base), RET]
                            .into_iter()
                            .flat_map(u32::to_le_bytes)
                            .collect();
                        for profile in [
                            BlockProfile::CheckedMemory(recipe),
                            BlockProfile::CheckedMemoryPauthClockThread(recipe),
                        ] {
                            let plan =
                                CompilationPlan::new(&source, BASE, profile, TargetCpu::Cx16)
                                    .unwrap();
                            assert_eq!(plan.memory_requirements(), Some(required));
                            let compiled = plan.compile().unwrap();
                            assert_eq!(
                                compiled
                                    .native
                                    .source_map
                                    .iter()
                                    .map(|(pc, _)| *pc)
                                    .collect::<Vec<_>>(),
                                [BASE, GuestAddress(BASE.0 + size_of::<u32>() as u64)]
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn constrained_store_writeback_overlap_stays_decoder_nop_without_memory_requirements() {
            for form in [0x2980_0000, 0x2880_0000, 0xa980_0000, 0xa880_0000] {
                for recipe in [
                    CheckedMemoryProfile::SpAlignmentEnabled,
                    CheckedMemoryProfile::SpAlignmentDisabled,
                ] {
                    // Rt is X0 and the base is X0. The decoder owns the source-permitted NOP.
                    let instruction = Decoder.lift(BASE, word(form, 0)).unwrap();
                    assert!(matches!(instruction.operation, Operation::Nop));
                    let decoded = Decoded::checked_ordinary(instruction, recipe).unwrap();
                    assert!(matches!(decoded, Decoded::Ordinary(_)));
                    assert_eq!(decoded.memory_requirements(), Default::default());
                }
            }
        }

        #[test]
        fn load_pairs_reach_checked_plans_without_store_or_asimd_authority() {
            let forms = [
                0x2940_0000,
                0x29c0_0000,
                0x28c0_0000,
                0xa940_0000,
                0xa9c0_0000,
                0xa8c0_0000,
                0x6940_0000,
                0x69c0_0000,
                0x68c0_0000,
                0x2840_0000,
                0xa840_0000,
            ];
            for recipe in [
                CheckedMemoryProfile::SpAlignmentEnabled,
                CheckedMemoryProfile::SpAlignmentDisabled,
            ] {
                for form in forms {
                    for base in [2, REGISTER_MASK] {
                        let load = word(form, base);
                        let instruction = Decoder.lift(BASE, load).unwrap();
                        let decoded = Decoded::checked_ordinary(instruction, recipe).unwrap();
                        assert!(matches!(decoded, Decoded::MemoryPair(_)));
                        let required = decoded.memory_requirements();
                        assert_eq!(
                            required.required_flags & (flags::PAIR | flags::WRITE | flags::ASIMD),
                            flags::PAIR
                        );
                        assert_eq!(required.required_host_caps, host_caps::ATOMIC_LOAD16);
                        let source: Vec<_> =
                            [load, RET].into_iter().flat_map(u32::to_le_bytes).collect();
                        for profile in [
                            BlockProfile::CheckedMemory(recipe),
                            BlockProfile::CheckedMemoryPauthClockThread(recipe),
                        ] {
                            let plan = CompilationPlan::new(
                                &source,
                                BASE,
                                profile,
                                TargetCpu::AtomicLoad16,
                            )
                            .unwrap();
                            assert_eq!(plan.memory_requirements(), Some(required));
                            let compiled = plan.compile().unwrap();
                            assert_eq!(
                                compiled
                                    .native
                                    .source_map
                                    .iter()
                                    .map(|(pc, _)| *pc)
                                    .collect::<Vec<_>>(),
                                [BASE, GuestAddress(BASE.0 + 4)]
                            );
                        }
                    }
                }
            }
        }
    }
    mod dot {
        use super::*;
        use crate::aarch64::sve::dot;

        #[test]
        fn integer_dot_admission_requires_streaming_without_requiring_za() {
            const SDOT_Z0_S_Z1_B_Z2_B: u32 = 0x4482_0020;
            const CDOT_RESERVED_BYTE: u32 = 0x4400_1000;
            let source = words(&[SDOT_Z0_S_Z1_B_Z2_B, RET_X30]);
            assert!(crate::compile(&source, GuestAddress(0)).is_err());
            assert!(matches!(
                crate::aarch64::sve::decode(SDOT_Z0_S_Z1_B_Z2_B),
                Some(Ok(crate::aarch64::sve::Operand::Dot(_)))
            ));
            for bytes in [16, 32, 64, 128, 256] {
                for streaming in [false, true] {
                    for za in [false, true] {
                        let profile = ScalableProfile::new(
                            VectorLength::from_bytes(bytes).unwrap(),
                            ScalableMode::new(streaming, za),
                        );
                        let result = compile_for_profile(
                            &source,
                            GuestAddress(0),
                            profile,
                            TargetCpu::Baseline,
                        );
                        if streaming {
                            assert!(result.is_ok());
                        } else {
                            assert!(result.unwrap_err().0.contains("streaming mode required"));
                        }
                    }
                }
                assert!(
                    compile_for_profile(
                        &words(&[CDOT_RESERVED_BYTE, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, true),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming integer dot")
                );
            }
        }

        #[test]
        fn integer_dot_registration_keeps_half_numerical_and_prefix_inputs_explicit() {
            const HALF_NUMERICAL_WORDS: [u32; 10] = [
                0x6420_8000,
                0x6420_4000,
                0x64a0_8000,
                0x64a0_8400,
                0x64a0_a000,
                0x64a0_a400,
                0x64a0_4000,
                0x64a0_4400,
                0x64a0_6000,
                0x64a0_6400,
            ];
            const SDOT_Z0_S_Z1_B_Z2_B: u32 = 0x4482_0020;
            for word in HALF_NUMERICAL_WORDS {
                assert!(dot::decode(word).unwrap().is_ok());
                assert_eq!(crate::aarch64::sve::decode(word), None);
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        profile(32, true),
                        TargetCpu::Baseline,
                    )
                    .is_err()
                );
            }
            assert!(
                compile_for_profile(
                    &words(&[MOVPRFX_Z0_Z1, SDOT_Z0_S_Z1_B_Z2_B, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
        }

        #[test]
        fn mixed_signedness_dot_requires_an_explicit_guest_i8mm_profile() {
            const MIXED_SIGNEDNESS_WORDS: [u32; 3] = [0x44a0_1c00, 0x4480_7800, 0x44a0_1800];
            for word in MIXED_SIGNEDNESS_WORDS {
                assert!(dot::decode_integer(word).unwrap().unwrap().requires_i8mm());
                for bytes in [16, 32, 64, 128, 256] {
                    for za in [false, true] {
                        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                            let profile = ScalableProfile::new(
                                VectorLength::from_bytes(bytes).unwrap(),
                                ScalableMode::new(true, za),
                            );
                            assert!(
                                compile_for_profile(
                                    &words(&[word, RET_X30]),
                                    GuestAddress(0),
                                    profile,
                                    target,
                                )
                                .unwrap_err()
                                .0
                                .contains("guest I8MM is outside the streaming profile")
                            );
                        }
                    }
                }
            }
        }
    }
    mod integer {
        use super::*;
        use crate::aarch64::sve::integer_arithmetic;
        use crate::aarch64::sve::integer_saturation;

        #[test]
        fn integer_comparison_preflight_rejects_non_streaming_reserved_and_prefix_inputs() {
            const CMPEQ_BYTE: u32 = 0x2400_2020;
            const CMPEQ_WIDE_RESERVED_DOUBLEWORD: u32 = 0x24c0_2020;
            const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
            for (input, streaming, reason) in [
                (vec![CMPEQ_BYTE, RET_X30], false, "streaming mode required"),
                (
                    vec![CMPEQ_WIDE_RESERVED_DOUBLEWORD, RET_X30],
                    true,
                    "reserved streaming integer comparison",
                ),
                (vec![MOVPRFX_Z0_Z1, CMPEQ_BYTE, RET_X30], true, "MOVPRFX"),
            ] {
                let error = compile_for_profile(
                    &words(&input),
                    GuestAddress(0),
                    profile(32, streaming),
                    TargetCpu::Baseline,
                )
                .unwrap_err();
                assert!(error.0.contains(reason), "{error:?}");
            }
        }

        #[test]
        fn integer_comparison_accepts_declared_sme_without_sme2() {
            const CMPEQ_BYTE: u32 = 0x2400_2020;
            let length = VectorLength::from_bytes(32).unwrap();
            let mode = ScalableMode::new(true, true);
            let declared = ScalableProfile::new_with_features(
                length,
                mode,
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap();
            let source = words(&[CMPEQ_BYTE, RET_X30]);
            let fixed = compile_for_profile(
                &source,
                GuestAddress(0),
                ScalableProfile::new(length, mode),
                TargetCpu::Baseline,
            )
            .unwrap();
            let explicit =
                compile_for_profile(&source, GuestAddress(0), declared, TargetCpu::Baseline)
                    .unwrap();
            assert_eq!(fixed.x86_64_code, explicit.x86_64_code);
            assert_eq!(fixed.source_map, explicit.source_map);
        }

        #[test]
        fn integer_arithmetic_maps_all_families_with_exact_body_boundaries() {
            const CANONICAL_WORDS: [u32; 48] = [
                0x0416_a000, // abs_z_p_z_m
                0x4500_d000, // adclb_z_zzz_
                0x4500_d400, // adclt_z_zzz_
                0x0400_0000, // add_z_p_zz_
                0x2520_c000, // add_z_zi_
                0x0420_0000, // add_z_zz_
                0x4500_d800, // cadd_z_zz_
                0x0417_a000, // neg_z_p_z_m
                0x4540_0000, // saddlb_z_zz_
                0x4540_8000, // saddlbt_z_zz_
                0x4540_0400, // saddlt_z_zz_
                0x4540_4000, // saddwb_z_zz_
                0x4540_4400, // saddwt_z_zz_
                0x4580_d000, // sbclb_z_zzz_
                0x4580_d400, // sbclt_z_zzz_
                0x4400_c000, // sclamp_z_zz_
                0x0494_0000, // sdiv_z_p_zz_
                0x0496_0000, // sdivr_z_p_zz_
                0x0408_0000, // smax_z_p_zz_
                0x2528_c000, // smax_z_zi_
                0x040a_0000, // smin_z_p_zz_
                0x252a_c000, // smin_z_zi_
                0x4540_1000, // ssublb_z_zz_
                0x4540_8800, // ssublbt_z_zz_
                0x4540_1400, // ssublt_z_zz_
                0x4540_8c00, // ssubltb_z_zz_
                0x4540_5000, // ssubwb_z_zz_
                0x4540_5400, // ssubwt_z_zz_
                0x0401_0000, // sub_z_p_zz_
                0x2521_c000, // sub_z_zi_
                0x0420_0400, // sub_z_zz_
                0x0403_0000, // subr_z_p_zz_
                0x2523_c000, // subr_z_zi_
                0x4540_0800, // uaddlb_z_zz_
                0x4540_0c00, // uaddlt_z_zz_
                0x4540_4800, // uaddwb_z_zz_
                0x4540_4c00, // uaddwt_z_zz_
                0x4400_c400, // uclamp_z_zz_
                0x0495_0000, // udiv_z_p_zz_
                0x0497_0000, // udivr_z_p_zz_
                0x0409_0000, // umax_z_p_zz_
                0x2529_c000, // umax_z_zi_
                0x040b_0000, // umin_z_p_zz_
                0x252b_c000, // umin_z_zi_
                0x4540_1800, // usublb_z_zz_
                0x4540_1c00, // usublt_z_zz_
                0x4540_5800, // usubwb_z_zz_
                0x4540_5c00, // usubwt_z_zz_
            ];
            const DESTINATION_MASK: u32 = 31;
            const SOURCE_MASK: u32 = 31 << 5;
            const SOURCE_REGISTER: u32 = 5;
            for canonical in CANONICAL_WORDS {
                // Distinct operands, destination/source alias, and ordinary Z31.
                for register in [0, SOURCE_REGISTER, 31] {
                    let word = (canonical & !(DESTINATION_MASK | SOURCE_MASK))
                        | register
                        | (SOURCE_REGISTER << 5);
                    let operand = integer_arithmetic::decode(word).unwrap().unwrap();
                    assert_eq!(
                        crate::aarch64::sve::decode(word),
                        Some(Ok(crate::aarch64::sve::Operand::IntegerArithmetic(operand)))
                    );
                    for bytes in [16, 32, 64, 128, 256] {
                        for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                            let native = compile_for_profile(
                                &words(&[word, RET_X30]),
                                GuestAddress(0x1000),
                                profile(bytes, true),
                                target,
                            )
                            .unwrap();
                            let mut expected = Code::new();
                            x86_64::sve::integer_arithmetic::emit(
                                &mut expected,
                                operand,
                                VectorLength::from_bytes(bytes).unwrap(),
                                target,
                            );
                            assert_eq!(
                                native.source_map[0],
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
                            );
                            assert_eq!(
                                native.source_map[1],
                                (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                            );
                            assert_eq!(
                                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                context_wrapper()
                            );
                            assert_eq!(
                                &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                                expected
                            );
                            assert_eq!(native.x86_64_code[native.source_map[1].1..], [RET]);
                        }
                    }
                }
            }
        }

        #[test]
        fn integer_arithmetic_preflight_rejects_mode_reserved_and_prefix_inputs() {
            const ADD_Z0_Z1_Z2: u32 = 0x0422_0020;
            const SDIV_RESERVED_BYTE: u32 = 0x0414_0000;
            const UDIV_RESERVED_HALFWORD: u32 = 0x0455_0000;
            const SADDLB_RESERVED_BYTE: u32 = 0x4500_0000;
            const ADD_RESERVED_BYTE_SHIFT8: u32 = 0x2520_e000;
            for word in [
                SDIV_RESERVED_BYTE,
                UDIV_RESERVED_HALFWORD,
                SADDLB_RESERVED_BYTE,
                ADD_RESERVED_BYTE_SHIFT8,
            ] {
                assert!(
                    compile_for_profile(
                        &words(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(32, true),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming integer arithmetic")
                );
            }
            for bytes in [16, 32, 64, 128, 256] {
                assert!(
                    compile_for_profile(
                        &words(&[ADD_Z0_Z1_Z2, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, false),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("streaming mode required")
                );
            }
            assert!(
                compile_for_profile(
                    &words(&[MOVPRFX_Z0_Z1, ADD_Z0_Z1_Z2, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
            assert!(crate::compile(&words(&[ADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
        }

        #[test]
        fn integer_saturation_maps_all_forms_with_exact_body_boundaries() {
            const CANONICAL_WORDS: [u32; 39] = [
                0x4500_f800, // saba_z_zzz_
                0x4540_c000, // sabalb_z_zzz_
                0x4540_c400, // sabalt_z_zzz_
                0x040c_0000, // sabd_z_p_zz_
                0x4540_3000, // sabdlb_z_zz_
                0x4540_3400, // sabdlt_z_zz_
                0x4410_8000, // shadd_z_p_zz_
                0x4412_8000, // shsub_z_p_zz_
                0x4416_8000, // shsubr_z_p_zz_
                0x4408_a000, // sqabs_z_p_z_m
                0x4418_8000, // sqadd_z_p_zz_
                0x2524_c000, // sqadd_z_zi_
                0x0420_1000, // sqadd_z_zz_
                0x4501_d800, // sqcadd_z_zz_
                0x4409_a000, // sqneg_z_p_z_m
                0x441a_8000, // sqsub_z_p_zz_
                0x2526_c000, // sqsub_z_zi_
                0x0420_1800, // sqsub_z_zz_
                0x441e_8000, // sqsubr_z_p_zz_
                0x4414_8000, // srhadd_z_p_zz_
                0x441c_8000, // suqadd_z_p_zz_
                0x4500_fc00, // uaba_z_zzz_
                0x4540_c800, // uabalb_z_zzz_
                0x4540_cc00, // uabalt_z_zzz_
                0x040d_0000, // uabd_z_p_zz_
                0x4540_3800, // uabdlb_z_zz_
                0x4540_3c00, // uabdlt_z_zz_
                0x4411_8000, // uhadd_z_p_zz_
                0x4413_8000, // uhsub_z_p_zz_
                0x4417_8000, // uhsubr_z_p_zz_
                0x4419_8000, // uqadd_z_p_zz_
                0x2525_c000, // uqadd_z_zi_
                0x0420_1400, // uqadd_z_zz_
                0x441b_8000, // uqsub_z_p_zz_
                0x2527_c000, // uqsub_z_zi_
                0x0420_1c00, // uqsub_z_zz_
                0x441f_8000, // uqsubr_z_p_zz_
                0x4415_8000, // urhadd_z_p_zz_
                0x441d_8000, // usqadd_z_p_zz_
            ];
            const REGISTER_MASK: u32 = 31;
            const SOURCE_SHIFT: u32 = 5;
            const SOURCE_REGISTER: u32 = 5;
            for canonical in CANONICAL_WORDS {
                for register in [0, SOURCE_REGISTER, REGISTER_MASK] {
                    let word = (canonical & !(REGISTER_MASK | (REGISTER_MASK << SOURCE_SHIFT)))
                        | register
                        | (SOURCE_REGISTER << SOURCE_SHIFT);
                    let operand = integer_saturation::decode(word).unwrap().unwrap();
                    assert_eq!(
                        crate::aarch64::sve::decode(word),
                        Some(Ok(crate::aarch64::sve::Operand::IntegerSaturation(operand)))
                    );
                    for bytes in [16, 32, 64, 128, 256] {
                        for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                            let native = compile_for_profile(
                                &words(&[word, RET_X30]),
                                GuestAddress(0x1000),
                                profile(bytes, true),
                                target,
                            )
                            .unwrap();
                            let mut expected = Code::new();
                            x86_64::sve::integer_saturation::emit(
                                &mut expected,
                                operand,
                                VectorLength::from_bytes(bytes).unwrap(),
                                target,
                            );
                            assert_eq!(
                                native.source_map[0],
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
                            );
                            assert_eq!(
                                native.source_map[1],
                                (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                            );
                            assert_eq!(
                                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                context_wrapper()
                            );
                            assert_eq!(
                                &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                                expected
                            );
                            assert_eq!(native.x86_64_code[native.source_map[1].1..], [RET]);
                        }
                    }
                }
            }
        }

        #[test]
        fn integer_saturation_preflight_rejects_reserved_mode_and_prefix_inputs() {
            const SQADD_Z0_Z1_Z2: u32 = 0x0422_1020;
            const SQADD_RESERVED_BYTE_SHIFT8: u32 = 0x2524_e000;
            const SABDLB_RESERVED_BYTE: u32 = 0x4500_3000;
            const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;
            for word in [SQADD_RESERVED_BYTE_SHIFT8, SABDLB_RESERVED_BYTE] {
                assert!(
                    compile_for_profile(
                        &words(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(32, true),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming integer saturation")
                );
            }
            for bytes in [16, 32, 64, 128, 256] {
                assert!(
                    compile_for_profile(
                        &words(&[SQADD_Z0_Z1_Z2, RET_X30]),
                        GuestAddress(0),
                        profile(bytes, false),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("streaming mode required")
                );
            }
            for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
                assert!(
                    compile_for_profile(
                        &words(&[prefix, SQADD_Z0_Z1_Z2, RET_X30]),
                        GuestAddress(0),
                        profile(32, true),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("MOVPRFX pair validation")
                );
            }
            assert!(crate::compile(&words(&[SQADD_Z0_Z1_Z2, RET_X30]), GuestAddress(0)).is_err());
        }

        #[test]
        fn sign_operations_require_streaming_without_za() {
            const FABS_HALF: u32 = 0x045c_a020;
            const FNEG_DOUBLE: u32 = 0x04dd_bfff;
            const RESERVED_SIGN_SIZE: u32 = 0x041c_a020;
            for bytes in [16, 32, 64, 128, 256] {
                for svcr in 0..=3 {
                    let profile = ScalableProfile::new(
                        VectorLength::from_bytes(bytes).unwrap(),
                        ScalableMode::from_svcr(svcr).unwrap(),
                    );
                    let source = words(&[FABS_HALF, FNEG_DOUBLE, RET_X30]);
                    let result =
                        compile_for_profile(&source, GuestAddress(0), profile, TargetCpu::Baseline);
                    if profile.mode().streaming() {
                        let native = result.unwrap();
                        assert_eq!(
                            native.source_map[0],
                            (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                        );
                        assert_eq!(native.source_map[1].0, GuestAddress(4));
                        assert!(native.source_map[1].1 > native.source_map[0].1);
                    } else {
                        assert!(result.unwrap_err().0.contains("streaming mode required"));
                    }
                }
            }
            assert!(crate::compile(&words(&[FABS_HALF, RET_X30]), GuestAddress(0)).is_err());
            assert!(
                compile_for_profile(
                    &words(&[RESERVED_SIGN_SIZE, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved streaming sign")
            );
        }
    }
    mod integer_bits {
        use super::*;
        use crate::aarch64::sve::integer_bits;

        #[test]
        fn integer_bits_register_exact_bodies_and_source_maps() {
            const CANONICAL_WORDS: [u32; 7] = [
                0x0418_a020, // CLS
                0x0419_a020, // CLZ
                0x041a_a020, // CNT
                0x0527_8020, // RBIT
                0x0564_8020, // REVB
                0x05a5_8020, // REVH
                0x05e6_8020, // REVW
            ];
            for word in CANONICAL_WORDS {
                let operand = integer_bits::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::IntegerBits(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
                        let native = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            profile(bytes, true),
                            target,
                        )
                        .unwrap();
                        let mut body = Code::new();
                        x86_64::sve::integer_bits::emit(
                            &mut body,
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                        assert_eq!(
                            native.source_map,
                            [
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                (GuestAddress(0x1004), return_offset)
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                            body
                        );
                        assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
                    }
                }
                let length = VectorLength::from_bytes(16).unwrap();
                for streaming in [false, true] {
                    for za in [false, true] {
                        // Base SME is sufficient; no accidental SME2 requirement.
                        let selected = ScalableProfile::new_with_features(
                            length,
                            ScalableMode::new(streaming, za),
                            ScalableFeatures::of(ScalableFeature::Sme),
                            ScalableControls::new(length, false),
                        )
                        .unwrap();
                        let result = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            selected,
                            TargetCpu::Baseline,
                        );
                        if streaming {
                            assert!(result.is_ok());
                        } else {
                            assert!(result.unwrap_err().0.contains("streaming mode required"));
                        }
                    }
                }
            }
        }

        #[test]
        fn integer_bits_reserved_zeroing_and_prefix_inputs_remain_explicit() {
            const RESERVED_REVERSE_WORDS: [u32; 6] = [
                0x0524_8020,
                0x0525_8020,
                0x0565_8020,
                0x0526_8020,
                0x0566_8020,
                0x05a6_8020,
            ];
            for word in RESERVED_REVERSE_WORDS {
                assert!(
                    compile_for_profile(
                        &words(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(16, true),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming integer-bit")
                );
            }
            const ZEROING_WORDS: [u32; 7] = [
                0x0408_a020,
                0x0409_a020,
                0x040a_a020,
                0x0527_a020,
                0x0564_a020,
                0x05a5_a020,
                0x05e6_a020,
            ];
            for word in ZEROING_WORDS {
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        profile(16, true),
                        TargetCpu::Baseline
                    )
                    .is_err()
                );
            }
            const CLS_Z0_B_P0_Z1_B: u32 = 0x0418_a020;
            assert!(
                compile_for_profile(
                    &words(&[MOVPRFX_Z0_Z1, CLS_Z0_B_P0_Z1_B, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
            assert!(crate::compile(&words(&[CLS_Z0_B_P0_Z1_B, RET_X30]), GuestAddress(0)).is_err());
        }
        #[test]
        fn integer_bits_bsr_recipes_require_declared_dit_zero() {
            const SIZE_SHIFT: u32 = 22;
            const LEADING_COUNT_WORDS: [u32; 2] = [0x0418_a020, 0x0419_a020];
            const VECTOR_BYTES: [usize; 5] = [16, 32, 64, 128, 256];
            // Independent audited B/H/S/D decisions by ascending supported SVL.
            const EXPECTED_DIT_REQUIREMENTS: [[bool; 5]; 4] = [
                [false; 5],
                [false; 5],
                [false, false, false, false, true],
                [true; 5],
            ];
            for canonical in LEADING_COUNT_WORDS {
                for (size, expected_by_length) in EXPECTED_DIT_REQUIREMENTS.into_iter().enumerate()
                {
                    let word = canonical | ((size as u32) << SIZE_SHIFT);
                    let operand = integer_bits::decode(word).unwrap().unwrap();
                    for (length_index, bytes) in VECTOR_BYTES.into_iter().enumerate() {
                        let length = VectorLength::from_bytes(bytes).unwrap();
                        let requires_declared_dit_zero = expected_by_length[length_index];
                        assert_eq!(
                            x86_64::sve::integer_bits::requires_declared_dit_zero(operand, length),
                            requires_declared_dit_zero
                        );
                        let declared = ScalableProfile::new_with_features(
                            length,
                            ScalableMode::new(true, false),
                            ScalableFeatures::of(ScalableFeature::Sme),
                            ScalableControls::new(length, false),
                        )
                        .unwrap();
                        assert_eq!(declared.required_dit(), Some(false));
                        for target in [TargetCpu::Baseline, TargetCpu::Ssse3, TargetCpu::Sse41] {
                            let positive = compile_for_profile(
                                &words(&[word, RET_X30]),
                                GuestAddress(0),
                                declared,
                                target,
                            )
                            .unwrap();
                            let mut body = Code::new();
                            x86_64::sve::integer_bits::emit(&mut body, operand, length, target);
                            assert_eq!(
                                &positive.x86_64_code[CONTEXT_WRAPPER_BYTES..][..body.len()],
                                body
                            );
                            let legacy = compile_for_profile(
                                &words(&[word, RET_X30]),
                                GuestAddress(0),
                                profile(bytes, true),
                                target,
                            );
                            if requires_declared_dit_zero {
                                assert!(legacy.unwrap_err().0.contains("declared DIT=0"));
                            } else {
                                assert_eq!(legacy.unwrap().x86_64_code, positive.x86_64_code);
                            }
                        }
                    }
                }
            }
        }
    }
    mod integer_products {
        use super::*;
        use crate::aarch64::sve::integer_products;

        #[test]
        fn integer_products_maps_every_form_to_exact_body_boundaries() {
            const CANONICAL_WORDS: [u32; 101] = [
                0x4403_20bf, // cmla_z_zzz_
                0x44a3_60bf, // cmla_z_zzzi_h
                0x44e3_60bf, // cmla_z_zzzi_s
                0x0403_de7f, // mad_z_p_zzz_
                0x0403_5cbf, // mla_z_p_zzz_
                0x44e3_08bf, // mla_z_zzzi_d
                0x4423_08bf, // mla_z_zzzi_h
                0x44a3_08bf, // mla_z_zzzi_s
                0x0403_7cbf, // mls_z_p_zzz_
                0x44e3_0cbf, // mls_z_zzzi_d
                0x4423_0cbf, // mls_z_zzzi_h
                0x44a3_0cbf, // mls_z_zzzi_s
                0x0403_fe7f, // msb_z_p_zzz_
                0x0410_1c7f, // mul_z_p_zz_
                0x2530_d01f, // mul_z_zi_
                0x0423_60bf, // mul_z_zz_
                0x44e3_f8bf, // mul_z_zzi_d
                0x4423_f8bf, // mul_z_zzi_h
                0x44a3_f8bf, // mul_z_zzi_s
                0x0423_64bf, // pmul_z_zz_
                0x4543_68bf, // pmullb_z_zz_
                0x4543_6cbf, // pmullt_z_zz_
                0x4443_40bf, // smlalb_z_zzz_
                0x44e3_80bf, // smlalb_z_zzzi_d
                0x44a3_80bf, // smlalb_z_zzzi_s
                0x4443_44bf, // smlalt_z_zzz_
                0x44e3_84bf, // smlalt_z_zzzi_d
                0x44a3_84bf, // smlalt_z_zzzi_s
                0x4443_50bf, // smlslb_z_zzz_
                0x44e3_a0bf, // smlslb_z_zzzi_d
                0x44a3_a0bf, // smlslb_z_zzzi_s
                0x4443_54bf, // smlslt_z_zzz_
                0x44e3_a4bf, // smlslt_z_zzzi_d
                0x44a3_a4bf, // smlslt_z_zzzi_s
                0x0412_1c7f, // smulh_z_p_zz_
                0x0423_68bf, // smulh_z_zz_
                0x4543_70bf, // smullb_z_zz_
                0x44e3_c0bf, // smullb_z_zzi_d
                0x44a3_c0bf, // smullb_z_zzi_s
                0x4543_74bf, // smullt_z_zz_
                0x44e3_c4bf, // smullt_z_zzi_d
                0x44a3_c4bf, // smullt_z_zzi_s
                0x4443_60bf, // sqdmlalb_z_zzz_
                0x44e3_20bf, // sqdmlalb_z_zzzi_d
                0x44a3_20bf, // sqdmlalb_z_zzzi_s
                0x4443_08bf, // sqdmlalbt_z_zzz_
                0x4443_64bf, // sqdmlalt_z_zzz_
                0x44e3_24bf, // sqdmlalt_z_zzzi_d
                0x44a3_24bf, // sqdmlalt_z_zzzi_s
                0x4443_68bf, // sqdmlslb_z_zzz_
                0x44e3_30bf, // sqdmlslb_z_zzzi_d
                0x44a3_30bf, // sqdmlslb_z_zzzi_s
                0x4443_0cbf, // sqdmlslbt_z_zzz_
                0x4443_6cbf, // sqdmlslt_z_zzz_
                0x44e3_34bf, // sqdmlslt_z_zzzi_d
                0x44a3_34bf, // sqdmlslt_z_zzzi_s
                0x0423_70bf, // sqdmulh_z_zz_
                0x44e3_f0bf, // sqdmulh_z_zzi_d
                0x4423_f0bf, // sqdmulh_z_zzi_h
                0x44a3_f0bf, // sqdmulh_z_zzi_s
                0x4543_60bf, // sqdmullb_z_zz_
                0x44e3_e0bf, // sqdmullb_z_zzi_d
                0x44a3_e0bf, // sqdmullb_z_zzi_s
                0x4543_64bf, // sqdmullt_z_zz_
                0x44e3_e4bf, // sqdmullt_z_zzi_d
                0x44a3_e4bf, // sqdmullt_z_zzi_s
                0x4403_30bf, // sqrdcmlah_z_zzz_
                0x44a3_70bf, // sqrdcmlah_z_zzzi_h
                0x44e3_70bf, // sqrdcmlah_z_zzzi_s
                0x4403_70bf, // sqrdmlah_z_zzz_
                0x44e3_10bf, // sqrdmlah_z_zzzi_d
                0x4423_10bf, // sqrdmlah_z_zzzi_h
                0x44a3_10bf, // sqrdmlah_z_zzzi_s
                0x4403_74bf, // sqrdmlsh_z_zzz_
                0x44e3_14bf, // sqrdmlsh_z_zzzi_d
                0x4423_14bf, // sqrdmlsh_z_zzzi_h
                0x44a3_14bf, // sqrdmlsh_z_zzzi_s
                0x0423_74bf, // sqrdmulh_z_zz_
                0x44e3_f4bf, // sqrdmulh_z_zzi_d
                0x4423_f4bf, // sqrdmulh_z_zzi_h
                0x44a3_f4bf, // sqrdmulh_z_zzi_s
                0x4443_48bf, // umlalb_z_zzz_
                0x44e3_90bf, // umlalb_z_zzzi_d
                0x44a3_90bf, // umlalb_z_zzzi_s
                0x4443_4cbf, // umlalt_z_zzz_
                0x44e3_94bf, // umlalt_z_zzzi_d
                0x44a3_94bf, // umlalt_z_zzzi_s
                0x4443_58bf, // umlslb_z_zzz_
                0x44e3_b0bf, // umlslb_z_zzzi_d
                0x44a3_b0bf, // umlslb_z_zzzi_s
                0x4443_5cbf, // umlslt_z_zzz_
                0x44e3_b4bf, // umlslt_z_zzzi_d
                0x44a3_b4bf, // umlslt_z_zzzi_s
                0x0413_1c7f, // umulh_z_p_zz_
                0x0423_6cbf, // umulh_z_zz_
                0x4543_78bf, // umullb_z_zz_
                0x44e3_d0bf, // umullb_z_zzi_d
                0x44a3_d0bf, // umullb_z_zzi_s
                0x4543_7cbf, // umullt_z_zz_
                0x44e3_d4bf, // umullt_z_zzi_d
                0x44a3_d4bf, // umullt_z_zzi_s
            ];
            for word in CANONICAL_WORDS {
                let operand = integer_products::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::IntegerProducts(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for (target, declared) in [
                        (TargetCpu::Baseline, false),
                        (TargetCpu::Sse42, false),
                        (TargetCpu::Baseline, true),
                        (TargetCpu::Sse42, true),
                    ] {
                        let selected_profile = if declared {
                            ScalableProfile::new_with_features(
                                VectorLength::from_bytes(bytes).unwrap(),
                                ScalableMode::new(true, false),
                                ScalableFeatures::of(ScalableFeature::Sme),
                                ScalableControls::new(
                                    VectorLength::from_bytes(bytes).unwrap(),
                                    false,
                                ),
                            )
                            .unwrap()
                        } else {
                            profile(bytes, true)
                        };
                        let native = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            selected_profile,
                            target,
                        )
                        .unwrap();
                        let mut expected = Code::new();
                        x86_64::sve::integer_products::emit(
                            &mut expected,
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        assert_eq!(
                            native.source_map,
                            [
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                            expected
                        );
                        assert_eq!(&native.x86_64_code[native.source_map[1].1..], &[RET]);
                    }
                }
            }
        }

        #[test]
        fn integer_products_preflight_rejects_reserved_modes_and_prefix_pairs() {
            const MUL_Z0_Z1_Z2: u32 = 0x0422_6020;
            const SMULLB_RESERVED_BYTE: u32 = 0x4500_7000;
            const PMULLB_RESERVED_WORD: u32 = 0x4580_6800;
            for word in [SMULLB_RESERVED_BYTE, PMULLB_RESERVED_WORD] {
                assert!(
                    compile_for_profile(
                        &words(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(32, true),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming integer product")
                );
            }
            assert!(
                compile_for_profile(
                    &words(&[MUL_Z0_Z1_Z2, RET_X30]),
                    GuestAddress(0),
                    profile(32, false),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("streaming mode required")
            );
            assert!(
                compile_for_profile(
                    &words(&[MOVPRFX_Z0_Z1, MUL_Z0_Z1_Z2, RET_X30]),
                    GuestAddress(0),
                    profile(32, true),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
        }
    }
    mod memory_load {
        //! SVE load dispatch, source maps and requirements.
        use super::*;
        use crate::aarch64::sve::memory_load;
        use crate::context::memory::{
            SpAlignmentRequirement, flags, host_caps, profile_requirements,
        };
        use alloc::vec;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const BRANCH_PAST_LEAF: u32 = 0x1400_0002;
        const LD1B_Z1_P0_X5: u32 = 0xa400_a0a1;
        const LD1D_Z1_P0_X5: u32 = 0xa5e0_a0a1;
        const LD1D_Z1_P0_SP: u32 = 0xa5e0_a3e1;
        const RESERVED_LD1B_Z1_P0_X5_XZR: u32 = 0xa41f_40a1;
        const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
        const WORDS: [u32; 66] = [
            0xa420a0a1, // ld1b_z_p_bi_u16
            0xa440a0a1, // ld1b_z_p_bi_u32
            0xa460a0a1, // ld1b_z_p_bi_u64
            0xa400a0a1, // ld1b_z_p_bi_u8
            0xa42040a1, // ld1b_z_p_br_u16
            0xa44040a1, // ld1b_z_p_br_u32
            0xa46040a1, // ld1b_z_p_br_u64
            0xa40040a1, // ld1b_z_p_br_u8
            0xa5e0a0a1, // ld1d_z_p_bi_u64
            0xa5e040a1, // ld1d_z_p_br_u64
            0xa4a0a0a1, // ld1h_z_p_bi_u16
            0xa4c0a0a1, // ld1h_z_p_bi_u32
            0xa4e0a0a1, // ld1h_z_p_bi_u64
            0xa4a040a1, // ld1h_z_p_br_u16
            0xa4c040a1, // ld1h_z_p_br_u32
            0xa4e040a1, // ld1h_z_p_br_u64
            0x8440a0a1, // ld1rb_z_p_bi_u16
            0x8440c0a1, // ld1rb_z_p_bi_u32
            0x8440e0a1, // ld1rb_z_p_bi_u64
            0x844080a1, // ld1rb_z_p_bi_u8
            0x85c0e0a1, // ld1rd_z_p_bi_u64
            0x84c0a0a1, // ld1rh_z_p_bi_u16
            0x84c0c0a1, // ld1rh_z_p_bi_u32
            0x84c0e0a1, // ld1rh_z_p_bi_u64
            0xa40020a1, // ld1rqb_z_p_bi_u8
            0xa40000a1, // ld1rqb_z_p_br_contiguous
            0xa58020a1, // ld1rqd_z_p_bi_u64
            0xa58000a1, // ld1rqd_z_p_br_contiguous
            0xa48020a1, // ld1rqh_z_p_bi_u16
            0xa48000a1, // ld1rqh_z_p_br_contiguous
            0xa50020a1, // ld1rqw_z_p_bi_u32
            0xa50000a1, // ld1rqw_z_p_br_contiguous
            0x85c0c0a1, // ld1rsb_z_p_bi_s16
            0x85c0a0a1, // ld1rsb_z_p_bi_s32
            0x85c080a1, // ld1rsb_z_p_bi_s64
            0x8540a0a1, // ld1rsh_z_p_bi_s32
            0x854080a1, // ld1rsh_z_p_bi_s64
            0x84c080a1, // ld1rsw_z_p_bi_s64
            0x8540c0a1, // ld1rw_z_p_bi_u32
            0x8540e0a1, // ld1rw_z_p_bi_u64
            0xa5c0a0a1, // ld1sb_z_p_bi_s16
            0xa5a0a0a1, // ld1sb_z_p_bi_s32
            0xa580a0a1, // ld1sb_z_p_bi_s64
            0xa5c040a1, // ld1sb_z_p_br_s16
            0xa5a040a1, // ld1sb_z_p_br_s32
            0xa58040a1, // ld1sb_z_p_br_s64
            0xa520a0a1, // ld1sh_z_p_bi_s32
            0xa500a0a1, // ld1sh_z_p_bi_s64
            0xa52040a1, // ld1sh_z_p_br_s32
            0xa50040a1, // ld1sh_z_p_br_s64
            0xa480a0a1, // ld1sw_z_p_bi_s64
            0xa48040a1, // ld1sw_z_p_br_s64
            0xa540a0a1, // ld1w_z_p_bi_u32
            0xa560a0a1, // ld1w_z_p_bi_u64
            0xa54040a1, // ld1w_z_p_br_u32
            0xa56040a1, // ld1w_z_p_br_u64
            0xa400e0a1, // ldnt1b_z_p_bi_contiguous
            0xa400c0a1, // ldnt1b_z_p_br_contiguous
            0xa580e0a1, // ldnt1d_z_p_bi_contiguous
            0xa580c0a1, // ldnt1d_z_p_br_contiguous
            0xa480e0a1, // ldnt1h_z_p_bi_contiguous
            0xa480c0a1, // ldnt1h_z_p_br_contiguous
            0xa500e0a1, // ldnt1w_z_p_bi_contiguous
            0xa500c0a1, // ldnt1w_z_p_br_contiguous
            0x858000a1, // ldr_p_bi_
            0x858040a1, // ldr_z_bi_
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }
        fn profile(bytes: usize, streaming: bool) -> ScalableProfile {
            ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(streaming, false),
            )
        }

        #[test]
        fn all_load_forms_dispatch_exact_bodies_and_source_maps_at_every_length() {
            for word in WORDS {
                let operand = memory_load::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::MemoryLoad(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    let profile = profile(bytes, true);
                    let native = compile_for_profile(
                        &source(&[word, RET_X30]),
                        GUEST_BASE,
                        profile,
                        TargetCpu::Baseline,
                    )
                    .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::memory_load::emit(
                        &mut expected,
                        operand,
                        profile.vector_length(),
                        TargetCpu::Baseline,
                        GUEST_BASE.0,
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        native.source_map,
                        [
                            (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                            (
                                GuestAddress(GUEST_BASE.0 + INSTRUCTION_BYTES as u64),
                                CONTEXT_WRAPPER_BYTES + expected.len()
                            ),
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                        expected
                    );
                    assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                    assert_eq!(
                        memory_requirements(
                            &source(&[word, RET_X30]),
                            GUEST_BASE,
                            profile,
                            TargetCpu::Baseline
                        )
                        .unwrap(),
                        x86_64::sve::memory_load::requirements(operand),
                    );
                }
            }
        }

        #[test]
        fn requirements_cover_the_complete_body_and_explicit_pure_case() {
            let profile = profile(16, true);
            assert_eq!(
                memory_requirements(
                    &source(&[NOP, RET_X30]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap(),
                MemoryRequirements::default()
            );
            assert_eq!(
                memory_requirements(
                    &source(&[LD1B_Z1_P0_X5, LD1D_Z1_P0_SP, LD1D_Z1_P0_X5, RET_X30]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap(),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: flags::TAG_CHECKED | flags::SVE_PREDICATED,
                    required_host_caps: host_caps::ATOMIC_LOAD16,
                    required_profile: profile_requirements::NATIVE_ACCESS
                        | profile_requirements::TAG_GRANULES
                        | profile_requirements::SCALABLE_TAG_CHECKS,
                    required_sp_alignment: SpAlignmentRequirement::Enabled,
                    ..MemoryRequirements::default()
                }
            );
        }

        #[test]
        fn scan_and_compile_share_input_reserved_and_mode_declines() {
            for (source, base, profile) in [
                (Vec::new(), GUEST_BASE, profile(16, true)),
                (
                    source(&[BRANCH_PAST_LEAF, RET_X30]),
                    GUEST_BASE,
                    profile(16, true),
                ),
                (vec![0; 3], GUEST_BASE, profile(16, true)),
                (
                    source(&[RET_X30]),
                    GuestAddress(GUEST_BASE.0 + 1),
                    profile(16, true),
                ),
                (source(&[LD1B_Z1_P0_X5]), GUEST_BASE, profile(16, true)),
                (
                    source(&[RESERVED_LD1B_Z1_P0_X5_XZR, RET_X30]),
                    GUEST_BASE,
                    profile(16, true),
                ),
                (
                    source(&[LD1B_Z1_P0_X5, RET_X30]),
                    GUEST_BASE,
                    profile(16, false),
                ),
            ] {
                let scan =
                    memory_requirements(&source, base, profile, TargetCpu::Baseline).unwrap_err();
                let compile =
                    compile_for_profile(&source, base, profile, TargetCpu::Baseline).unwrap_err();
                assert_eq!(scan.0, compile.0);
            }
        }
    }
    mod memory_multi {
        //! Multi-vector load/store dispatch, source maps and requirements.
        use super::*;
        use crate::aarch64::sve::memory_multi;
        use crate::context::memory::{
            SpAlignmentRequirement, flags, host_caps, profile_requirements,
        };
        use alloc::vec;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const LD1D_Z0_Z1_PN8_X5_X0: u32 = 0xa000_60a0;
        const LD1D_Z0_Z1_PN8_SP: u32 = 0xa040_63e0;
        const STNT1B_Z0_Z3_PN8_X5: u32 = 0xa060_80a1;
        const RESERVED_IMMEDIATE: u32 = 0xa050_0000;
        const RESERVED_QUAD_TUPLE: u32 = 0xa040_8002;
        const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
        const CANONICAL_BASE_X5: u32 = 5 << 5;

        const WORDS: [u32; 64] = [
            0xa0400000, // ld1b_mz_p_bi_2
            0xa0408000, // ld1b_mz_p_bi_4
            0xa0000000, // ld1b_mz_p_br_2
            0xa0008000, // ld1b_mz_p_br_4
            0xa0406000, // ld1d_mz_p_bi_2
            0xa040e000, // ld1d_mz_p_bi_4
            0xa0006000, // ld1d_mz_p_br_2
            0xa000e000, // ld1d_mz_p_br_4
            0xa0402000, // ld1h_mz_p_bi_2
            0xa040a000, // ld1h_mz_p_bi_4
            0xa0002000, // ld1h_mz_p_br_2
            0xa000a000, // ld1h_mz_p_br_4
            0xa0404000, // ld1w_mz_p_bi_2
            0xa040c000, // ld1w_mz_p_bi_4
            0xa0004000, // ld1w_mz_p_br_2
            0xa000c000, // ld1w_mz_p_br_4
            0xa0400001, // ldnt1b_mz_p_bi_2
            0xa0408001, // ldnt1b_mz_p_bi_4
            0xa0000001, // ldnt1b_mz_p_br_2
            0xa0008001, // ldnt1b_mz_p_br_4
            0xa0406001, // ldnt1d_mz_p_bi_2
            0xa040e001, // ldnt1d_mz_p_bi_4
            0xa0006001, // ldnt1d_mz_p_br_2
            0xa000e001, // ldnt1d_mz_p_br_4
            0xa0402001, // ldnt1h_mz_p_bi_2
            0xa040a001, // ldnt1h_mz_p_bi_4
            0xa0002001, // ldnt1h_mz_p_br_2
            0xa000a001, // ldnt1h_mz_p_br_4
            0xa0404001, // ldnt1w_mz_p_bi_2
            0xa040c001, // ldnt1w_mz_p_bi_4
            0xa0004001, // ldnt1w_mz_p_br_2
            0xa000c001, // ldnt1w_mz_p_br_4
            0xa0600000, // st1b_mz_p_bi_2
            0xa0608000, // st1b_mz_p_bi_4
            0xa0200000, // st1b_mz_p_br_2
            0xa0208000, // st1b_mz_p_br_4
            0xa0606000, // st1d_mz_p_bi_2
            0xa060e000, // st1d_mz_p_bi_4
            0xa0206000, // st1d_mz_p_br_2
            0xa020e000, // st1d_mz_p_br_4
            0xa0602000, // st1h_mz_p_bi_2
            0xa060a000, // st1h_mz_p_bi_4
            0xa0202000, // st1h_mz_p_br_2
            0xa020a000, // st1h_mz_p_br_4
            0xa0604000, // st1w_mz_p_bi_2
            0xa060c000, // st1w_mz_p_bi_4
            0xa0204000, // st1w_mz_p_br_2
            0xa020c000, // st1w_mz_p_br_4
            0xa0600001, // stnt1b_mz_p_bi_2
            0xa0608001, // stnt1b_mz_p_bi_4
            0xa0200001, // stnt1b_mz_p_br_2
            0xa0208001, // stnt1b_mz_p_br_4
            0xa0606001, // stnt1d_mz_p_bi_2
            0xa060e001, // stnt1d_mz_p_bi_4
            0xa0206001, // stnt1d_mz_p_br_2
            0xa020e001, // stnt1d_mz_p_br_4
            0xa0602001, // stnt1h_mz_p_bi_2
            0xa060a001, // stnt1h_mz_p_bi_4
            0xa0202001, // stnt1h_mz_p_br_2
            0xa020a001, // stnt1h_mz_p_br_4
            0xa0604001, // stnt1w_mz_p_bi_2
            0xa060c001, // stnt1w_mz_p_bi_4
            0xa0204001, // stnt1w_mz_p_br_2
            0xa020c001, // stnt1w_mz_p_br_4
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(bytes: usize, streaming: bool) -> ScalableProfile {
            ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(streaming, false),
            )
        }

        #[test]
        fn multi_forms_dispatch_exact_bodies_and_maps_at_vector_length_boundaries() {
            for canonical in WORDS {
                let word = canonical | CANONICAL_BASE_X5;
                let operand = memory_multi::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::MemoryMulti(operand)))
                );
                for bytes in [16, 256] {
                    let profile = profile(bytes, true);
                    let bytes = source(&[word, RET_X30]);
                    let native =
                        compile_for_profile(&bytes, GUEST_BASE, profile, TargetCpu::Baseline)
                            .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::memory_multi::emit(
                        &mut expected,
                        &operand,
                        profile.vector_length(),
                        TargetCpu::Baseline,
                        GUEST_BASE.0,
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        native.source_map,
                        [
                            (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                            (
                                GuestAddress(GUEST_BASE.0 + INSTRUCTION_BYTES as u64),
                                CONTEXT_WRAPPER_BYTES + expected.len()
                            ),
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                        expected
                    );
                    assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                    assert_eq!(
                        memory_requirements(&bytes, GUEST_BASE, profile, TargetCpu::Baseline)
                            .unwrap(),
                        x86_64::sve::memory_multi::requirements(&operand)
                    );
                }
            }
        }

        #[test]
        fn multi_requirements_fold_every_effect_and_preserve_four_argument_descriptor() {
            let profile = profile(16, true);
            assert_eq!(
                memory_requirements(
                    &source(&[NOP, RET_X30]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap(),
                MemoryRequirements::default()
            );
            assert_eq!(
                memory_requirements(
                    &source(&[
                        LD1D_Z0_Z1_PN8_X5_X0,
                        LD1D_Z0_Z1_PN8_SP,
                        STNT1B_Z0_Z3_PN8_X5,
                        RET_X30,
                    ]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap(),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: flags::TAG_CHECKED | flags::WRITE | flags::NON_TEMPORAL,
                    required_host_caps: host_caps::ATOMIC_LOAD16,
                    required_profile: profile_requirements::NATIVE_ACCESS
                        | profile_requirements::TAG_GRANULES
                        | profile_requirements::SCALABLE_TAG_CHECKS,
                    required_sp_alignment: SpAlignmentRequirement::Enabled,
                    ..MemoryRequirements::default()
                }
            );
            assert_eq!(
                memory_requirements(
                    &source(&[LD1D_Z0_Z1_PN8_SP, RET_X30]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap(),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: 0,
                    required_host_caps: 0,
                    required_profile: profile_requirements::NATIVE_ACCESS,
                    required_sp_alignment: SpAlignmentRequirement::Enabled,
                    ..MemoryRequirements::default()
                }
            );
        }

        #[test]
        fn multi_scan_and_compile_share_reserved_mode_and_feature_declines() {
            let length = VectorLength::from_bytes(16).unwrap();
            let sme_without_sme2 = ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, false),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap();
            for (words, profile) in [
                (vec![RESERVED_IMMEDIATE, RET_X30], profile(16, true)),
                (vec![RESERVED_QUAD_TUPLE, RET_X30], profile(16, true)),
                (vec![LD1D_Z0_Z1_PN8_X5_X0, RET_X30], profile(16, false)),
                (vec![LD1D_Z0_Z1_PN8_X5_X0, RET_X30], sme_without_sme2),
                (vec![LD1D_Z0_Z1_PN8_X5_X0], profile(16, true)),
            ] {
                let bytes = source(&words);
                let scan = memory_requirements(&bytes, GUEST_BASE, profile, TargetCpu::Baseline)
                    .unwrap_err();
                let compile = compile_for_profile(&bytes, GUEST_BASE, profile, TargetCpu::Baseline)
                    .unwrap_err();
                assert_eq!(scan.0, compile.0);
            }
        }
    }
    mod memory_store {
        //! SVE store routing and requirements.
        use super::*;
        use crate::aarch64::sve::memory_store;
        use crate::context::memory::{
            SpAlignmentRequirement, flags, host_caps, profile_requirements,
        };
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const ST1B_Z1_P0_SP: u32 = 0xe400_e3e1;
        const STNT1D_Z1_P0_X5: u32 = 0xe590_e0a1;
        const ST2Q_Z1_P0_X5: u32 = 0xe440_00a1;
        const STR_Z1_X5: u32 = 0xe580_40a1;
        const PRFB_P0_SP: u32 = 0x85c0_03e1;
        const RESERVED_ST1B_Z1_P0_X5_XZR: u32 = 0xe41f_40a1;
        const RESERVED_ST1H_BYTE_SOURCE: u32 = 0xe480_e0a1;
        const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
        const FORMS: [(u32, &str); 56] = [
            (0x85c000a1, "prfb_i_p_bi_s"),
            (0x8400c0a1, "prfb_i_p_br_s"),
            (0x85c060a1, "prfd_i_p_bi_s"),
            (0x8580c0a1, "prfd_i_p_br_s"),
            (0x85c020a1, "prfh_i_p_bi_s"),
            (0x8480c0a1, "prfh_i_p_br_s"),
            (0x85c040a1, "prfw_i_p_bi_s"),
            (0x8500c0a1, "prfw_i_p_br_s"),
            (0xe400e0a1, "st1b_z_p_bi_"),
            (0xe40040a1, "st1b_z_p_br_"),
            (0xe5e0e0a1, "st1d_z_p_bi_"),
            (0xe5e040a1, "st1d_z_p_br_"),
            (0xe4a0e0a1, "st1h_z_p_bi_"),
            (0xe4a040a1, "st1h_z_p_br_"),
            (0xe540e0a1, "st1w_z_p_bi_"),
            (0xe54040a1, "st1w_z_p_br_"),
            (0xe430e0a1, "st2b_z_p_bi_contiguous"),
            (0xe42060a1, "st2b_z_p_br_contiguous"),
            (0xe5b0e0a1, "st2d_z_p_bi_contiguous"),
            (0xe5a060a1, "st2d_z_p_br_contiguous"),
            (0xe4b0e0a1, "st2h_z_p_bi_contiguous"),
            (0xe4a060a1, "st2h_z_p_br_contiguous"),
            (0xe44000a1, "st2q_z_p_bi_contiguous"),
            (0xe46000a1, "st2q_z_p_br_contiguous"),
            (0xe530e0a1, "st2w_z_p_bi_contiguous"),
            (0xe52060a1, "st2w_z_p_br_contiguous"),
            (0xe450e0a1, "st3b_z_p_bi_contiguous"),
            (0xe44060a1, "st3b_z_p_br_contiguous"),
            (0xe5d0e0a1, "st3d_z_p_bi_contiguous"),
            (0xe5c060a1, "st3d_z_p_br_contiguous"),
            (0xe4d0e0a1, "st3h_z_p_bi_contiguous"),
            (0xe4c060a1, "st3h_z_p_br_contiguous"),
            (0xe48000a1, "st3q_z_p_bi_contiguous"),
            (0xe4a000a1, "st3q_z_p_br_contiguous"),
            (0xe550e0a1, "st3w_z_p_bi_contiguous"),
            (0xe54060a1, "st3w_z_p_br_contiguous"),
            (0xe470e0a1, "st4b_z_p_bi_contiguous"),
            (0xe46060a1, "st4b_z_p_br_contiguous"),
            (0xe5f0e0a1, "st4d_z_p_bi_contiguous"),
            (0xe5e060a1, "st4d_z_p_br_contiguous"),
            (0xe4f0e0a1, "st4h_z_p_bi_contiguous"),
            (0xe4e060a1, "st4h_z_p_br_contiguous"),
            (0xe4c000a1, "st4q_z_p_bi_contiguous"),
            (0xe4e000a1, "st4q_z_p_br_contiguous"),
            (0xe570e0a1, "st4w_z_p_bi_contiguous"),
            (0xe56060a1, "st4w_z_p_br_contiguous"),
            (0xe410e0a1, "stnt1b_z_p_bi_contiguous"),
            (0xe40060a1, "stnt1b_z_p_br_contiguous"),
            (0xe590e0a1, "stnt1d_z_p_bi_contiguous"),
            (0xe58060a1, "stnt1d_z_p_br_contiguous"),
            (0xe490e0a1, "stnt1h_z_p_bi_contiguous"),
            (0xe48060a1, "stnt1h_z_p_br_contiguous"),
            (0xe510e0a1, "stnt1w_z_p_bi_contiguous"),
            (0xe50060a1, "stnt1w_z_p_br_contiguous"),
            (0xe58000a1, "str_p_bi_"),
            (0xe58040a1, "str_z_bi_"),
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(bytes: usize, streaming: bool, quadword: bool) -> ScalableProfile {
            let mut features =
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
            if quadword {
                features = features.with(ScalableFeature::Sme2p1);
            }
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(streaming, false),
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
            )
            .unwrap()
        }

        #[test]
        fn all_store_forms_dispatch_exact_bodies_and_maps_at_every_length() {
            for (word, canonical_id) in FORMS {
                let operand = memory_store::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::MemoryStore(operand))),
                    "{canonical_id}"
                );
                for bytes in [16, 32, 64, 128, 256] {
                    let profile = profile(bytes, true, true);
                    let native = compile_for_profile(
                        &source(&[word, RET_X30]),
                        GUEST_BASE,
                        profile,
                        TargetCpu::Baseline,
                    )
                    .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::memory_store::emit(
                        &mut expected,
                        &operand,
                        profile.vector_length(),
                        TargetCpu::Baseline,
                        GUEST_BASE.0,
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        native.source_map,
                        [
                            (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                            (
                                GuestAddress(GUEST_BASE.0 + INSTRUCTION_BYTES as u64),
                                CONTEXT_WRAPPER_BYTES + expected.len()
                            ),
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                        expected,
                        "{canonical_id} at SVL {bytes}"
                    );
                    assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                    assert_eq!(
                        memory_requirements(
                            &source(&[word, RET_X30]),
                            GUEST_BASE,
                            profile,
                            TargetCpu::Baseline
                        )
                        .unwrap(),
                        x86_64::sve::memory_store::requirements(&operand),
                    );
                }
            }
        }

        #[test]
        fn stores_preflight_write_caps_tags_and_original_sp_for_the_complete_body() {
            let profile = profile(16, true, true);
            let requirements = |words: &[u32]| {
                memory_requirements(&source(words), GUEST_BASE, profile, TargetCpu::Baseline)
                    .unwrap()
            };
            assert_eq!(
                requirements(&[NOP, PRFB_P0_SP, RET_X30]),
                MemoryRequirements::default()
            );
            assert_eq!(
                requirements(&[ST1B_Z1_P0_SP, RET_X30]),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: flags::WRITE | flags::SVE_PREDICATED,
                    required_host_caps: 0,
                    required_profile: profile_requirements::NATIVE_ACCESS,
                    required_sp_alignment: SpAlignmentRequirement::Enabled,
                    ..MemoryRequirements::default()
                }
            );
            assert_eq!(
                requirements(&[STR_Z1_X5, RET_X30]),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: flags::WRITE | flags::TAG_CHECKED,
                    required_host_caps: 0,
                    required_profile: profile_requirements::NATIVE_ACCESS
                        | profile_requirements::TAG_GRANULES
                        | profile_requirements::SCALABLE_TAG_CHECKS,
                    required_sp_alignment: SpAlignmentRequirement::Any,
                    ..MemoryRequirements::default()
                }
            );
            assert_eq!(
                requirements(&[NOP, ST1B_Z1_P0_SP, STNT1D_Z1_P0_X5, ST2Q_Z1_P0_X5, RET_X30]),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: flags::WRITE
                        | flags::TAG_CHECKED
                        | flags::NON_TEMPORAL
                        | flags::SVE_PREDICATED,
                    required_host_caps: host_caps::CX16,
                    required_profile: profile_requirements::NATIVE_ACCESS
                        | profile_requirements::TAG_GRANULES
                        | profile_requirements::SCALABLE_TAG_CHECKS,
                    required_sp_alignment: SpAlignmentRequirement::Enabled,
                    ..MemoryRequirements::default()
                }
            );
        }

        #[test]
        fn scan_and_compile_share_reserved_mode_and_q_feature_declines() {
            for (word, profile, reason) in [
                (
                    RESERVED_ST1B_Z1_P0_X5_XZR,
                    profile(16, true, true),
                    "reserved streaming store",
                ),
                (
                    RESERVED_ST1H_BYTE_SOURCE,
                    profile(16, true, true),
                    "reserved streaming store",
                ),
                (
                    ST1B_Z1_P0_SP,
                    profile(16, false, true),
                    "streaming mode required",
                ),
                (
                    PRFB_P0_SP,
                    profile(16, false, true),
                    "streaming mode required",
                ),
                (ST2Q_Z1_P0_X5, profile(16, true, false), "FEAT_SME2p1"),
            ] {
                let source = source(&[word, RET_X30]);
                let scan = memory_requirements(&source, GUEST_BASE, profile, TargetCpu::Baseline)
                    .unwrap_err();
                let compile =
                    compile_for_profile(&source, GUEST_BASE, profile, TargetCpu::Baseline)
                        .unwrap_err();
                assert_eq!(scan.0, compile.0);
                assert!(scan.0.contains(reason), "{}", scan.0);
            }
        }
    }
    mod memory_structure {
        //! Structured load routing, features and requirements.
        use super::*;
        use crate::aarch64::sve::memory_structure;
        use crate::context::memory::{
            SpAlignmentRequirement, flags, host_caps, profile_requirements,
        };
        use alloc::vec;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
        const MAXIMUM_VECTOR_BYTES: usize = 256;
        const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
        const SOURCE_BYTES: u64 = size_of::<u32>() as u64;
        const DESTINATION_Z31: u32 = 31;
        const PREDICATE_P7: u32 = 7 << 10;
        const BASE_X5: u32 = 5 << 5;
        const BASE_SP: u32 = 31 << 5;
        const REGISTER_OFFSET_XZR: u32 = 31 << 16;
        const LD2B_IMMEDIATE: u32 = 0xa420_e000;
        const LD2Q_IMMEDIATE: u32 = 0xa490_e000;

        const CLASSES: [u32; 30] = [
            0xa420_e000, // ld2b_z_p_bi_contiguous
            0xa420_c000, // ld2b_z_p_br_contiguous
            0xa5a0_e000, // ld2d_z_p_bi_contiguous
            0xa5a0_c000, // ld2d_z_p_br_contiguous
            0xa4a0_e000, // ld2h_z_p_bi_contiguous
            0xa4a0_c000, // ld2h_z_p_br_contiguous
            0xa490_e000, // ld2q_z_p_bi_contiguous
            0xa4a0_8000, // ld2q_z_p_br_contiguous
            0xa520_e000, // ld2w_z_p_bi_contiguous
            0xa520_c000, // ld2w_z_p_br_contiguous
            0xa440_e000, // ld3b_z_p_bi_contiguous
            0xa440_c000, // ld3b_z_p_br_contiguous
            0xa5c0_e000, // ld3d_z_p_bi_contiguous
            0xa5c0_c000, // ld3d_z_p_br_contiguous
            0xa4c0_e000, // ld3h_z_p_bi_contiguous
            0xa4c0_c000, // ld3h_z_p_br_contiguous
            0xa510_e000, // ld3q_z_p_bi_contiguous
            0xa520_8000, // ld3q_z_p_br_contiguous
            0xa540_e000, // ld3w_z_p_bi_contiguous
            0xa540_c000, // ld3w_z_p_br_contiguous
            0xa460_e000, // ld4b_z_p_bi_contiguous
            0xa460_c000, // ld4b_z_p_br_contiguous
            0xa5e0_e000, // ld4d_z_p_bi_contiguous
            0xa5e0_c000, // ld4d_z_p_br_contiguous
            0xa4e0_e000, // ld4h_z_p_bi_contiguous
            0xa4e0_c000, // ld4h_z_p_br_contiguous
            0xa590_e000, // ld4q_z_p_bi_contiguous
            0xa5a0_8000, // ld4q_z_p_br_contiguous
            0xa560_e000, // ld4w_z_p_bi_contiguous
            0xa560_c000, // ld4w_z_p_br_contiguous
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(bytes: usize, streaming: bool, quadword: bool) -> ScalableProfile {
            let mut features =
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
            if quadword {
                features = features.with(ScalableFeature::Sme2p1);
            }
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(streaming, false),
                features,
                ScalableControls::new(
                    VectorLength::from_bytes(MAXIMUM_VECTOR_BYTES).unwrap(),
                    true,
                ),
            )
            .unwrap()
        }

        #[test]
        fn all_structure_forms_dispatch_exact_bodies_and_source_maps_at_every_length() {
            for class in CLASSES {
                let word = class | DESTINATION_Z31 | PREDICATE_P7 | BASE_X5;
                let operand = memory_structure::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::MemoryStructure(operand)))
                );
                for bytes in LENGTHS {
                    let profile = profile(bytes, true, true);
                    let input = source(&[word, RET_X30]);
                    let native =
                        compile_for_profile(&input, GUEST_BASE, profile, TargetCpu::Baseline)
                            .unwrap();
                    let mut expected = Code::new();
                    x86_64::sve::memory_structure::emit(
                        &mut expected,
                        &operand,
                        profile.vector_length(),
                        TargetCpu::Baseline,
                        GUEST_BASE.0,
                    );
                    assert_eq!(
                        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                        context_wrapper()
                    );
                    assert_eq!(
                        native.source_map,
                        [
                            (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                            (
                                GuestAddress(GUEST_BASE.0 + SOURCE_BYTES),
                                CONTEXT_WRAPPER_BYTES + expected.len()
                            ),
                        ]
                    );
                    assert_eq!(
                        &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                        expected
                    );
                    assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                    assert_eq!(
                        memory_requirements(&input, GUEST_BASE, profile, TargetCpu::Baseline)
                            .unwrap(),
                        x86_64::sve::memory_structure::requirements(operand)
                    );
                }
            }
        }

        #[test]
        fn structure_scan_and_compile_share_reserved_mode_and_feature_declines() {
            for class in CLASSES {
                let word = class | DESTINATION_Z31 | PREDICATE_P7 | BASE_X5;
                let operand = memory_structure::decode(word).unwrap().unwrap();
                let mut declines = vec![(word, profile(32, false, true))];
                if matches!(
                    operand.address.offset,
                    crate::aarch64::sve::memory::Offset::Register { .. }
                ) {
                    declines.push((word | REGISTER_OFFSET_XZR, profile(32, true, true)));
                }
                if operand.requires_sve2p1_or_sme2p1() {
                    declines.push((word, profile(32, true, false)));
                }
                for (word, profile) in declines {
                    let input = source(&[NOP, word, RET_X30]);
                    let scan =
                        memory_requirements(&input, GUEST_BASE, profile, TargetCpu::Baseline)
                            .unwrap_err();
                    let compile =
                        compile_for_profile(&input, GUEST_BASE, profile, TargetCpu::Baseline)
                            .unwrap_err();
                    assert_eq!(scan.0, compile.0);
                }
            }
        }

        #[test]
        fn structure_requirements_fold_the_complete_body() {
            let input = source(&[
                NOP,
                LD2B_IMMEDIATE | BASE_X5,
                LD2Q_IMMEDIATE | BASE_SP,
                RET_X30,
            ]);
            assert_eq!(
                memory_requirements(
                    &input,
                    GUEST_BASE,
                    profile(16, true, true),
                    TargetCpu::Baseline
                )
                .unwrap(),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_flags: flags::SVE_PREDICATED | flags::TAG_CHECKED,
                    required_host_caps: host_caps::ATOMIC_LOAD16,
                    required_profile: profile_requirements::NATIVE_ACCESS
                        | profile_requirements::TAG_GRANULES
                        | profile_requirements::SCALABLE_TAG_CHECKS,
                    required_sp_alignment: SpAlignmentRequirement::Enabled,
                    ..MemoryRequirements::default()
                }
            );
        }
    }
    mod movement {
        //! ZA movement registration, profile limits and source maps.

        use super::*;
        use crate::aarch64::sme::movement;
        use alloc::string::String;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const MOVA_Z0_ZA0H_BYTE: u32 = 0xc002_0000;
        const MOVA_ZA0H_BYTE_Z0: u32 = 0xc000_0000;
        const MOVA_TWO_Z0_ZA0H_BYTE: u32 = 0xc006_0000;
        const MOVA_FOUR_Z0_ZA0H_DOUBLEWORD: u32 = 0xc0c6_0400;
        const MOVAZ_Z0_ZA0H_BYTE: u32 = 0xc002_0200;
        const ZERO_ZA_EMPTY: u32 = 0xc008_0000;
        const ZERO_ZA_ALL: u32 = 0xc008_00ff;
        const ZERO_ZA_VECTOR_GROUP: u32 = 0xc00c_0000;
        const ZERO_ZT0: u32 = 0xc048_0001;
        const MOVT_X0_ZT0: u32 = 0xc04c_03e0;
        const MOVT_ZT0_X0: u32 = 0xc04e_03e0;
        const SOURCE_BASE: GuestAddress = GuestAddress(0x1000);
        const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
        const ALL_MOVEMENT_FEATURES: ScalableFeatures = ScalableFeatures::of(ScalableFeature::Sme)
            .with(ScalableFeature::Sme2)
            .with(ScalableFeature::Sme2p1);

        const NORMAL_FORMS: &[(&str, u32)] = &[
            ("mova_mz2_za_b1", 0xc006_0000),
            ("mova_mz2_za_d1", 0xc0c6_0000),
            ("mova_mz2_za_h1", 0xc046_0000),
            ("mova_mz2_za_w1", 0xc086_0000),
            ("mova_mz4_za_b1", 0xc006_0400),
            ("mova_mz4_za_d1", 0xc0c6_0400),
            ("mova_mz4_za_h1", 0xc046_0400),
            ("mova_mz4_za_w1", 0xc086_0400),
            ("mova_mz_za2_1", 0xc006_0800),
            ("mova_mz_za4_1", 0xc006_0c00),
            ("mova_z_p_rza_b", 0xc002_0000),
            ("mova_z_p_rza_d", 0xc0c2_0000),
            ("mova_z_p_rza_h", 0xc042_0000),
            ("mova_z_p_rza_q", 0xc0c3_0000),
            ("mova_z_p_rza_w", 0xc082_0000),
            ("mova_za2_z_b1", 0xc004_0000),
            ("mova_za2_z_d1", 0xc0c4_0000),
            ("mova_za2_z_h1", 0xc044_0000),
            ("mova_za2_z_w1", 0xc084_0000),
            ("mova_za4_z_b1", 0xc004_0400),
            ("mova_za4_z_d1", 0xc0c4_0400),
            ("mova_za4_z_h1", 0xc044_0400),
            ("mova_za4_z_w1", 0xc084_0400),
            ("mova_za_mz2_1", 0xc004_0800),
            ("mova_za_mz4_1", 0xc004_0c00),
            ("mova_za_p_rz_b", 0xc000_0000),
            ("mova_za_p_rz_d", 0xc0c0_0000),
            ("mova_za_p_rz_h", 0xc040_0000),
            ("mova_za_p_rz_q", 0xc0c1_0000),
            ("mova_za_p_rz_w", 0xc080_0000),
            ("movaz_mz2_za_b1", 0xc006_0200),
            ("movaz_mz2_za_d1", 0xc0c6_0200),
            ("movaz_mz2_za_h1", 0xc046_0200),
            ("movaz_mz2_za_w1", 0xc086_0200),
            ("movaz_mz4_za_b1", 0xc006_0600),
            ("movaz_mz4_za_d1", 0xc0c6_0600),
            ("movaz_mz4_za_h1", 0xc046_0600),
            ("movaz_mz4_za_w1", 0xc086_0600),
            ("movaz_mz_za2_1", 0xc006_0a00),
            ("movaz_mz_za4_1", 0xc006_0e00),
            ("movaz_z_rza_b", 0xc002_0200),
            ("movaz_z_rza_d", 0xc0c2_0200),
            ("movaz_z_rza_h", 0xc042_0200),
            ("movaz_z_rza_q", 0xc0c3_0200),
            ("movaz_z_rza_w", 0xc082_0200),
            ("zero_za1_ri_2", 0xc00c_0000),
            ("zero_za1_ri_4", 0xc00e_0000),
            ("zero_za2_ri_1", 0xc00c_8000),
            ("zero_za2_ri_2", 0xc00d_0000),
            ("zero_za2_ri_4", 0xc00d_8000),
            ("zero_za4_ri_1", 0xc00e_8000),
            ("zero_za4_ri_2", 0xc00f_0000),
            ("zero_za4_ri_4", 0xc00f_8000),
            ("zero_za_i_", 0xc008_0000),
            ("zero_zt_i_", 0xc048_0001),
        ];

        fn words(input: &[u32]) -> Vec<u8> {
            input.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(
            bytes: usize,
            streaming: bool,
            za: bool,
            features: ScalableFeatures,
            max_bytes: usize,
            zt0: bool,
        ) -> ScalableProfile {
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(streaming, za),
                features,
                ScalableControls::new(VectorLength::from_bytes(max_bytes).unwrap(), zt0),
            )
            .unwrap()
        }

        fn rejection(word: u32, profile: ScalableProfile) -> String {
            compile_for_profile(
                &words(&[NOP, word, RET_X30]),
                SOURCE_BASE,
                profile,
                TargetCpu::Baseline,
            )
            .unwrap_err()
            .0
        }

        #[test]
        fn all_normal_forms_route_through_exact_compiler_body_and_maps() {
            assert_eq!(NORMAL_FORMS.len(), 55);
            for &(canonical, word) in NORMAL_FORMS {
                let operand = movement::decode(word).unwrap();
                assert_eq!(operand.canonical_id, canonical);
                assert!(!operand.requirements.halted);
                assert_eq!(
                    crate::aarch64::sme::decode(word),
                    Some(Ok(crate::aarch64::sme::Operand::Movement(operand)))
                );
                for bytes in LENGTHS {
                    let profile = profile(bytes, true, true, ALL_MOVEMENT_FEATURES, 256, true);
                    for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                        let source = words(&[word, RET_X30]);
                        if profile.vector_length().bits()
                            < usize::from(operand.requirements.minimum_current_svl_bits)
                        {
                            assert!(
                                compile_for_profile(&source, SOURCE_BASE, profile, target).is_err()
                            );
                            continue;
                        }
                        let native =
                            compile_for_profile(&source, SOURCE_BASE, profile, target).unwrap();
                        let mut body = Code::new();
                        x86_64::sme::movement::emit(
                            &mut body,
                            &operand,
                            profile.vector_length(),
                            target,
                        )
                        .unwrap();
                        assert_eq!(
                            native.source_map,
                            [
                                (SOURCE_BASE, CONTEXT_WRAPPER_BYTES),
                                (
                                    GuestAddress(SOURCE_BASE.0 + INSTRUCTION_BYTES as u64),
                                    CONTEXT_WRAPPER_BYTES + body.len()
                                ),
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code
                                [CONTEXT_WRAPPER_BYTES..CONTEXT_WRAPPER_BYTES + body.len()],
                            body
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES + body.len()..],
                            [RET]
                        );
                    }
                }
                assert!(crate::compile(&words(&[word, RET_X30]), SOURCE_BASE).is_err());
            }
        }

        #[test]
        fn mode_guards_run_before_empty_zero_or_any_movement_emission() {
            for bytes in LENGTHS {
                for streaming in [false, true] {
                    let no_za = profile(bytes, streaming, false, ALL_MOVEMENT_FEATURES, 256, true);
                    for word in [
                        ZERO_ZA_EMPTY,
                        ZERO_ZA_ALL,
                        ZERO_ZT0,
                        MOVA_Z0_ZA0H_BYTE,
                        MOVA_ZA0H_BYTE_Z0,
                        MOVAZ_Z0_ZA0H_BYTE,
                        ZERO_ZA_VECTOR_GROUP,
                    ] {
                        assert!(rejection(word, no_za).contains("ZA"));
                    }
                }
                let no_stream = profile(bytes, false, true, ALL_MOVEMENT_FEATURES, 256, true);
                for word in [
                    MOVA_Z0_ZA0H_BYTE,
                    MOVA_ZA0H_BYTE_Z0,
                    MOVAZ_Z0_ZA0H_BYTE,
                    ZERO_ZA_VECTOR_GROUP,
                ] {
                    assert!(rejection(word, no_stream).contains("streaming mode"));
                }
                for word in [ZERO_ZA_EMPTY, ZERO_ZA_ALL, ZERO_ZT0] {
                    assert!(
                        compile_for_profile(
                            &words(&[word, RET_X30]),
                            SOURCE_BASE,
                            no_stream,
                            TargetCpu::Baseline
                        )
                        .is_ok()
                    );
                }
                let no_zt0 = profile(bytes, false, true, ALL_MOVEMENT_FEATURES, 256, false);
                assert!(rejection(ZERO_ZT0, no_zt0).contains("ZT0"));
            }
        }

        #[test]
        fn guest_features_and_debug_requirements_do_not_come_from_host_target() {
            let sme = ScalableFeatures::of(ScalableFeature::Sme);
            let no_sme2 = profile(32, true, true, sme, 256, false);
            assert!(rejection(MOVA_TWO_Z0_ZA0H_BYTE, no_sme2).contains("FEAT_SME2"));
            let no_sme2p1 = profile(32, true, true, sme.with(ScalableFeature::Sme2), 256, true);
            for word in [MOVAZ_Z0_ZA0H_BYTE, ZERO_ZA_VECTOR_GROUP] {
                assert!(rejection(word, no_sme2p1).contains("FEAT_SME2p1"));
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        SOURCE_BASE,
                        no_sme2p1,
                        TargetCpu::Sse41
                    )
                    .is_err()
                );
            }
            let declared = profile(32, true, true, ALL_MOVEMENT_FEATURES, 256, true);
            let original = ScalableProfile::new(
                VectorLength::from_bytes(32).unwrap(),
                ScalableMode::new(true, true),
            );
            for profile in [declared, original] {
                for word in [MOVT_X0_ZT0, MOVT_ZT0_X0] {
                    assert!(rejection(word, profile).contains("halted debug"));
                }
            }
        }

        #[test]
        fn current_and_maximum_length_guards_are_distinct() {
            let low_max = profile(16, true, true, ALL_MOVEMENT_FEATURES, 16, true);
            let larger_max = profile(16, true, true, ALL_MOVEMENT_FEATURES, 32, true);
            assert!(
                rejection(MOVA_FOUR_Z0_ZA0H_DOUBLEWORD, low_max)
                    .contains("maximum streaming vector length")
            );
            assert!(
                rejection(MOVA_FOUR_Z0_ZA0H_DOUBLEWORD, larger_max)
                    .contains("current streaming vector length")
            );
            assert!(
                ScalableProfile::new_with_features(
                    VectorLength::from_bytes(32).unwrap(),
                    ScalableMode::new(true, true),
                    ALL_MOVEMENT_FEATURES,
                    ScalableControls::new(VectorLength::from_bytes(16).unwrap(), true),
                )
                .is_err()
            );
        }

        #[test]
        fn sme1_nonstreaming_za_zero_needs_no_zt0_or_streaming_banks() {
            let profile = profile(
                16,
                false,
                true,
                ScalableFeatures::of(ScalableFeature::Sme),
                16,
                false,
            );
            let mut za = [0_u8; 16 * 16];
            let mut view = ScalableStateView {
                svl_bytes: 16,
                reserved: [0; 6],
                svcr: ScalableMode::new(false, true).svcr(),
                tpidr2_el0: 0,
                fpmr: 0,
                z_upper: core::ptr::null_mut(),
                predicates: core::ptr::null_mut(),
                ffr: core::ptr::null_mut(),
                za: za.as_mut_ptr(),
                zt0: core::ptr::null_mut(),
            };
            let context = ExecutionContext {
                scalable: &mut view,
                ..ExecutionContext::default()
            };
            profile.validate_view(&context, &view).unwrap();
            assert!(
                compile_for_profile(
                    &words(&[ZERO_ZA_ALL, RET_X30]),
                    SOURCE_BASE,
                    profile,
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }

        #[test]
        fn legacy_and_declared_profiles_keep_the_same_movement_bodies() {
            let length = VectorLength::from_bytes(32).unwrap();
            let legacy = ScalableProfile::new(length, ScalableMode::new(true, true));
            let declared = profile(32, true, true, ALL_MOVEMENT_FEATURES, 256, true);
            for word in [
                MOVA_Z0_ZA0H_BYTE,
                MOVA_ZA0H_BYTE_Z0,
                MOVA_TWO_Z0_ZA0H_BYTE,
                ZERO_ZA_EMPTY,
                ZERO_ZA_ALL,
            ] {
                let source = words(&[word, RET_X30]);
                let first =
                    compile_for_profile(&source, SOURCE_BASE, legacy, TargetCpu::Baseline).unwrap();
                let second =
                    compile_for_profile(&source, SOURCE_BASE, declared, TargetCpu::Baseline)
                        .unwrap();
                assert_eq!(first.x86_64_code, second.x86_64_code);
                assert_eq!(first.source_map, second.source_map);
            }
        }
    }
    mod predicate_generation {
        //! Predicate generation dispatch, feature limits and source maps.
        use super::*;
        use crate::aarch64::sve::predicate_generation;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const WORDS: [u32; 45] = [
            0x25104000, // brka_p_p_p_
            0x25504000, // brkas_p_p_p_z
            0x25904000, // brkb_p_p_p_
            0x25d04000, // brkbs_p_p_p_z
            0x25184000, // brkn_p_p_pp_
            0x25584000, // brkns_p_p_pp_
            0x2500c000, // brkpa_p_p_pp_
            0x2540c000, // brkpas_p_p_pp_
            0x2500c010, // brkpb_p_p_pp_
            0x2540c010, // brkpbs_p_p_pp_
            0x25a02000, // ctermeq_rr_
            0x25a02010, // ctermne_rr_
            0x2518e400, // pfalse_p_
            0x2558c000, // pfirst_p_p_p_
            0x2519c400, // pnext_p_p_p_
            0x2550c000, // ptest__p_p_
            0x2518e000, // ptrue_p_s_
            0x25207810, // ptrue_pn_i_
            0x2519e000, // ptrues_p_s_
            0x25200000, // whilege_p_p_rr_
            0x25204010, // whilege_pn_rr_
            0x25205010, // whilege_pp_rr_
            0x25200010, // whilegt_p_p_rr_
            0x25204018, // whilegt_pn_rr_
            0x25205011, // whilegt_pp_rr_
            0x25200810, // whilehi_p_p_rr_
            0x25204818, // whilehi_pn_rr_
            0x25205811, // whilehi_pp_rr_
            0x25200800, // whilehs_p_p_rr_
            0x25204810, // whilehs_pn_rr_
            0x25205810, // whilehs_pp_rr_
            0x25200410, // whilele_p_p_rr_
            0x25204418, // whilele_pn_rr_
            0x25205411, // whilele_pp_rr_
            0x25200c00, // whilelo_p_p_rr_
            0x25204c10, // whilelo_pn_rr_
            0x25205c10, // whilelo_pp_rr_
            0x25200c10, // whilels_p_p_rr_
            0x25204c18, // whilels_pn_rr_
            0x25205c11, // whilels_pp_rr_
            0x25200400, // whilelt_p_p_rr_
            0x25204410, // whilelt_pn_rr_
            0x25205410, // whilelt_pp_rr_
            0x25203010, // whilerw_p_rr_
            0x25203000, // whilewr_p_rr_
        ];
        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }
        fn profile(bytes: usize, svcr: u64, sme2: bool) -> ScalableProfile {
            let length = VectorLength::from_bytes(bytes).unwrap();
            let mut features = ScalableFeatures::of(ScalableFeature::Sme);
            if sme2 {
                features = features.with(ScalableFeature::Sme2);
            }
            ScalableProfile::new_with_features(
                length,
                ScalableMode::from_svcr(svcr).unwrap(),
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
            )
            .unwrap()
        }
        #[test]
        fn generation_production_dispatch_preserves_exact_body_source_maps() {
            for word in WORDS {
                let operand = predicate_generation::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::PredicateGeneration(
                        operand
                    )))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [1, 3] {
                        for target in [TargetCpu::Baseline, TargetCpu::Bmi1] {
                            let native = compile_for_profile(
                                &source(&[word, RET_X30]),
                                GuestAddress(0x1000),
                                profile(bytes, svcr, true),
                                target,
                            )
                            .unwrap();
                            let mut expected = Code::new();
                            x86_64::sve::predicate_generation::emit(
                                &mut expected,
                                &operand,
                                VectorLength::from_bytes(bytes).unwrap(),
                                target,
                            );
                            assert_eq!(
                                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                context_wrapper()
                            );
                            assert_eq!(
                                native.source_map,
                                [
                                    (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                    (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len())
                                ]
                            );
                            assert_eq!(
                                &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                                expected
                            );
                            assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                        }
                    }
                }
            }
        }
        #[test]
        fn generation_preflight_requires_streaming_and_sme2_only_for_counter_or_pair() {
            let mut sme2_forms = 0;
            for word in WORDS {
                let operand = predicate_generation::decode(word).unwrap().unwrap();
                sme2_forms += usize::from(operand.requires_sme2());
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [0, 2] {
                        assert!(
                            compile_for_profile(
                                &source(&[word, RET_X30]),
                                GuestAddress(0),
                                profile(bytes, svcr, true),
                                TargetCpu::Baseline
                            )
                            .unwrap_err()
                            .0
                            .contains("streaming mode required")
                        );
                    }
                    for svcr in [1, 3] {
                        let result = compile_for_profile(
                            &source(&[word, RET_X30]),
                            GuestAddress(0),
                            profile(bytes, svcr, false),
                            TargetCpu::Baseline,
                        );
                        if operand.requires_sme2() {
                            assert!(result.unwrap_err().0.contains("FEAT_SME2"));
                        } else {
                            assert!(result.is_ok());
                        }
                    }
                }
                assert!(crate::compile(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
            }
            assert_eq!(sme2_forms, 17);
        }
    }
    mod predicate_logic {
        //! Predicate logic dispatch, feature limits and source maps.
        use super::*;
        use crate::aarch64::sve::predicate_logic;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const RESERVED_PSEL_SIZE: u32 = 0x2520_4000;
        const WORDS: [u32; 31] = [
            0x25024c20, // and_p_p_pp_z
            0x25424c20, // ands_p_p_pp_z
            0x25024c30, // bic_p_p_pp_z
            0x25424c30, // bics_p_p_pp_z
            0x25024e20, // eor_p_p_pp_z
            0x25424e20, // eors_p_p_pp_z
            0x25824e30, // nand_p_p_pp_z
            0x25c24e30, // nands_p_p_pp_z
            0x25824e20, // nor_p_p_pp_z
            0x25c24e20, // nors_p_p_pp_z
            0x25824c30, // orn_p_p_pp_z
            0x25c24c30, // orns_p_p_pp_z
            0x25824c20, // orr_p_p_pp_z
            0x25c24c20, // orrs_p_p_pp_z
            0x25207010, // pext_pn_rr_
            0x25207410, // pext_pp_rr_
            0x052a3800, // pmov_p_zi_b
            0x05a83800, // pmov_p_zi_d
            0x052c3800, // pmov_p_zi_h
            0x05683800, // pmov_p_zi_s
            0x25244440, // psel_p_ppi_
            0x05314020, // punpkhi_p_p_
            0x05304020, // punpklo_p_p_
            0x05344020, // rev_p_p_
            0x25024e30, // sel_p_p_pp_
            0x05225020, // trn1_p_pp_
            0x05225420, // trn2_p_pp_
            0x05224820, // uzp1_p_pp_
            0x05224c20, // uzp2_p_pp_
            0x05224020, // zip1_p_pp_
            0x05224420, // zip2_p_pp_
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(bytes: usize, svcr: u64, features: ScalableFeatures) -> ScalableProfile {
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::from_svcr(svcr).unwrap(),
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
            )
            .unwrap()
        }

        #[test]
        fn predicate_logic_dispatch_preserves_exact_body_and_source_maps() {
            let features = ScalableFeatures::of(ScalableFeature::Sme)
                .with(ScalableFeature::Sme2)
                .with(ScalableFeature::Sme2p1);
            for word in WORDS {
                let operand = predicate_logic::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::PredicateLogic(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                        let native = compile_for_profile(
                            &source(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            profile(bytes, 3, features),
                            target,
                        )
                        .unwrap();
                        let mut expected = Code::new();
                        x86_64::sve::predicate_logic::emit(
                            &mut expected,
                            &operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            native.source_map,
                            [
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + expected.len()),
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                            expected
                        );
                        assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                    }
                }
            }
        }

        #[test]
        fn predicate_logic_requires_streaming_and_declared_counter_or_move_features() {
            let sme = ScalableFeatures::of(ScalableFeature::Sme);
            let sme2 = sme.with(ScalableFeature::Sme2);
            let all = sme2.with(ScalableFeature::Sme2p1);
            let mut counter_forms = 0;
            let mut move_forms = 0;
            for word in WORDS {
                let operand = predicate_logic::decode(word).unwrap().unwrap();
                let counter = matches!(operand.kind, predicate_logic::Kind::ExtractCounter { .. });
                let vector_move = matches!(operand.kind, predicate_logic::Kind::MoveVector { .. });
                counter_forms += usize::from(counter);
                move_forms += usize::from(vector_move);
                for svcr in [0, 2] {
                    assert!(
                        compile_for_profile(
                            &source(&[word, RET_X30]),
                            GuestAddress(0),
                            profile(16, svcr, all),
                            TargetCpu::Baseline
                        )
                        .unwrap_err()
                        .0
                        .contains("streaming mode required")
                    );
                }
                for (features, permitted, missing) in [
                    (
                        sme,
                        !counter && !vector_move,
                        if vector_move {
                            "FEAT_SME2p1"
                        } else {
                            "FEAT_SME2"
                        },
                    ),
                    (sme2, !vector_move, "FEAT_SME2p1"),
                    (all, true, ""),
                ] {
                    let result = compile_for_profile(
                        &source(&[word, RET_X30]),
                        GuestAddress(0),
                        profile(16, 3, features),
                        TargetCpu::Baseline,
                    );
                    if permitted {
                        assert!(result.is_ok());
                    } else {
                        assert!(result.unwrap_err().0.contains(missing));
                    }
                }
                let v1 = ScalableProfile::new(
                    VectorLength::from_bytes(16).unwrap(),
                    ScalableMode::from_svcr(3).unwrap(),
                );
                let result = compile_for_profile(
                    &source(&[word, RET_X30]),
                    GuestAddress(0),
                    v1,
                    TargetCpu::Baseline,
                );
                if vector_move {
                    assert!(result.unwrap_err().0.contains("FEAT_SME2p1"));
                } else {
                    assert!(result.is_ok());
                }
                assert!(crate::compile(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
            }
            assert_eq!(counter_forms, 2);
            assert_eq!(move_forms, 4);
            assert!(
                compile_for_profile(
                    &source(&[RESERVED_PSEL_SIZE, RET_X30]),
                    GuestAddress(0),
                    profile(16, 3, all),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("reserved streaming predicate logic")
            );
        }
    }
    mod predicate_move {
        //! PMOV dispatch, source maps and feature/mode limits.
        use super::*;
        use crate::aarch64::sve::integer_predicate_move;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const BASES: [u32; 4] = [0x052b_3800, 0x052d_3800, 0x0569_3800, 0x05a9_3800];
        const PORTION_LOW_SHIFT: u32 = 17;
        const PORTION_HIGH_SHIFT: u32 = 22;
        const PREDICATE_SHIFT: u32 = 5;

        fn source(word: u32) -> Vec<u8> {
            [word, RET_X30]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect()
        }
        fn profile(bytes: usize, streaming: bool, za: bool, p1: bool) -> ScalableProfile {
            let mut features =
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
            if p1 {
                features = features.with(ScalableFeature::Sme2p1);
            }
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::new(streaming, za),
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
            )
            .unwrap()
        }

        #[test]
        fn predicate_move_dispatch_preserves_complete_bodies_and_maps() {
            for (size, base) in BASES.into_iter().enumerate() {
                for portion in 0..(1u32 << size) {
                    let word = base
                        | ((portion & 3) << PORTION_LOW_SHIFT)
                        | ((portion >> 2) << PORTION_HIGH_SHIFT)
                        | (15 << PREDICATE_SHIFT)
                        | 31;
                    let operand = integer_predicate_move::decode(word).unwrap().unwrap();
                    assert_eq!(
                        crate::aarch64::sve::decode(word),
                        Some(Ok(crate::aarch64::sve::Operand::IntegerPredicateMove(
                            operand
                        )))
                    );
                    for bytes in [16, 32, 64, 128, 256] {
                        for za in [false, true] {
                            for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                                let native = compile_for_profile(
                                    &source(word),
                                    GuestAddress(0x1000),
                                    profile(bytes, true, za, true),
                                    target,
                                )
                                .unwrap();
                                let mut expected = Code::new();
                                x86_64::sve::integer_predicate_move::emit(
                                    &mut expected,
                                    operand,
                                    VectorLength::from_bytes(bytes).unwrap(),
                                    target,
                                );
                                assert_eq!(
                                    native.source_map,
                                    [
                                        (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                        (
                                            GuestAddress(0x1004),
                                            CONTEXT_WRAPPER_BYTES + expected.len()
                                        )
                                    ]
                                );
                                assert_eq!(
                                    &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                    context_wrapper()
                                );
                                assert_eq!(
                                    &native.x86_64_code
                                        [CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                                    expected
                                );
                                assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                            }
                        }
                    }
                }
            }
        }

        #[test]
        fn predicate_move_requires_sme2p1_streaming_without_requiring_za() {
            for word in BASES {
                let error = compile_for_profile(
                    &source(word),
                    GuestAddress(0),
                    profile(16, true, false, false),
                    TargetCpu::Baseline,
                )
                .unwrap_err();
                assert!(error.0.contains("FEAT_SME2p1"));
                for za in [false, true] {
                    let error = compile_for_profile(
                        &source(word),
                        GuestAddress(0),
                        profile(16, false, za, true),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err();
                    assert!(error.0.contains("streaming mode required"));
                    assert!(
                        compile_for_profile(
                            &source(word),
                            GuestAddress(0),
                            profile(16, true, za, true),
                            TargetCpu::Baseline
                        )
                        .is_ok()
                    );
                }
                assert!(
                    compile_for_profile(
                        &source(word),
                        GuestAddress(0),
                        ScalableProfile::new(
                            VectorLength::from_bytes(16).unwrap(),
                            ScalableMode::new(true, false)
                        ),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("FEAT_SME2p1")
                );
            }
        }
    }
    mod prefix_pair {
        use super::*;
        use alloc::vec::Vec;

        const BASE: GuestAddress = GuestAddress(0x1000);
        const UNPREDICATED_PREFIX: u32 = 0x0420_bc20;
        const ZEROING_PREFIX: u32 = 0x0410_2020;
        const MERGING_PREFIX: u32 = 0x0411_2020;
        const AND_DESTRUCTIVE: u32 = 0x041a_0040;
        const RET: u32 = 0xd65f_03c0;

        #[test]
        fn both_prefix_forms_compile_as_two_individual_source_map_intervals() {
            for bytes in [16, 32, 64, 128, 256] {
                let profile = ScalableProfile::new(
                    VectorLength::from_bytes(bytes).unwrap(),
                    ScalableMode::new(true, false),
                );
                for prefix in [UNPREDICATED_PREFIX, ZEROING_PREFIX, MERGING_PREFIX] {
                    let source: Vec<_> = [prefix, AND_DESTRUCTIVE, RET]
                        .iter()
                        .flat_map(|word| word.to_le_bytes())
                        .collect();
                    let native =
                        compile_for_profile(&source, BASE, profile, TargetCpu::Baseline).unwrap();
                    assert_eq!(
                        native
                            .source_map
                            .iter()
                            .map(|(pc, _)| *pc)
                            .collect::<Vec<_>>(),
                        [
                            BASE,
                            GuestAddress(BASE.0 + INSTRUCTION_BYTES as u64),
                            GuestAddress(BASE.0 + prefix::PAIR_BYTES as u64)
                        ]
                    );
                    assert_eq!(native.source_map[0].1, CONTEXT_WRAPPER_BYTES);
                    assert!(
                        native
                            .source_map
                            .windows(2)
                            .all(|pair| pair[0].1 < pair[1].1)
                    );
                }
            }
        }
        #[test]
        fn prepared_prefix_records_both_source_clauses_and_preserves_refusals() {
            use crate::aarch64::scalable::execution::{
                GuestMemoryQuantity, ScalableAccessRequirements,
            };
            let profile = ScalableProfile::new(
                VectorLength::from_bytes(16).unwrap(),
                ScalableMode::new(true, false),
            );
            let source: Vec<_> = [UNPREDICATED_PREFIX, AND_DESTRUCTIVE, RET]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            let prepared = prepare_leaf(&source, BASE, profile, TargetCpu::Baseline).unwrap();
            let ordinary =
                compile_for_profile(&source, BASE, profile, TargetCpu::Baseline).unwrap();
            assert_eq!(prepared.native.x86_64_code, ordinary.x86_64_code);
            assert_eq!(prepared.native.source_map, ordinary.source_map);
            let instructions = prepared.execution_requirements.instructions();
            assert_eq!(instructions.len(), 3);
            let clause = FeatureRequirement::all(ScalableFeatures::of(ScalableFeature::Sme));
            for (index, instruction) in instructions[..2].iter().enumerate() {
                assert_eq!(
                    instruction.pc(),
                    GuestAddress(BASE.0 + (index * INSTRUCTION_BYTES) as u64)
                );
                assert_eq!(instruction.feature_clauses(), &[clause]);
                assert_eq!(
                    instruction.access(),
                    &ScalableAccessRequirements::Unqualified
                );
                assert_eq!(
                    instruction.guest_memory_quantity(),
                    GuestMemoryQuantity::Unqualified
                );
            }
            assert!(instructions[2].feature_clauses().is_empty());
            assert_eq!(
                instructions[2].guest_memory_quantity(),
                GuestMemoryQuantity::None
            );
            let refused: Vec<_> = [UNPREDICATED_PREFIX, RET]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect();
            let error = match prepare_leaf(&refused, BASE, profile, TargetCpu::Baseline) {
                Err(error) => error,
                Ok(_) => panic!("unreviewed MOVPRFX pair accepted"),
            };
            assert!(error.0.contains("MOVPRFX pair validation"));
        }
    }
    mod profile {
        use super::*;

        #[test]
        fn feature_admission_declines_with_exact_pc_and_missing_clause_names() {
            let length = VectorLength::from_bytes(16).unwrap();
            let features = ScalableFeatures::of(ScalableFeature::Sme);
            let profile = ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, false),
                features,
                ScalableControls::new(length, false),
            )
            .unwrap();
            let required = ScalableFeatures::of(ScalableFeature::Sme2);
            let alternatives =
                ScalableFeatures::of(ScalableFeature::SmeF16F16).with(ScalableFeature::SmeF8F16);
            let pc = GuestAddress(0x1234);
            let error = profile
                .require_features(FeatureRequirement::all_and_any(required, alternatives), pc)
                .unwrap_err();
            assert_eq!(
                error.0,
                "unavailable guest features at 0x1234: requires FEAT_SME2; requires one of FEAT_SME_F16F16, FEAT_SME_F8F16"
            );
            assert!(
                profile
                    .require_features(FeatureRequirement::all(features), pc)
                    .is_ok()
            );
            assert!(
                profile
                    .require_features(FeatureRequirement::default(), pc)
                    .is_ok()
            );
            assert!(
                ScalableProfile::new(length, ScalableMode::default())
                    .require_features(FeatureRequirement::all(required), pc)
                    .is_ok()
            );
        }

        #[test]
        fn declared_sme1_za_storage_does_not_require_zt0_or_streaming_banks() {
            let length = VectorLength::from_bytes(64).unwrap();
            let mode = ScalableMode::new(false, true);
            let sme = ScalableFeatures::of(ScalableFeature::Sme);
            let mut za = [0_u8; 64 * 64];
            let mut view = ScalableStateView {
                svl_bytes: length.bytes() as u16,
                reserved: [0; 6],
                svcr: mode.svcr(),
                tpidr2_el0: 0,
                fpmr: 0,
                z_upper: core::ptr::null_mut(),
                predicates: core::ptr::null_mut(),
                ffr: core::ptr::null_mut(),
                za: za.as_mut_ptr(),
                zt0: core::ptr::null_mut(),
            };
            let context = ExecutionContext {
                scalable: &mut view,
                ..ExecutionContext::default()
            };
            let profile = ScalableProfile::new_with_features(
                length,
                mode,
                sme,
                ScalableControls::new(length, false),
            )
            .unwrap();
            assert!(profile.validate_view(&context, &view).is_ok());
            assert_eq!(profile.required_dit(), Some(false));
            let zt0_profile = ScalableProfile::new_with_features(
                length,
                mode,
                sme.with(ScalableFeature::Sme2),
                ScalableControls::new(length, true),
            )
            .unwrap();
            assert!(zt0_profile.validate_view(&context, &view).is_err());
            let original = ScalableProfile::new(length, mode);
            assert!(original.validate_view(&context, &view).is_err());
            assert_eq!(original.required_dit(), None);
            let mut zt0 = [0_u8; crate::aarch64::scalable::LOOKUP_TABLE_BYTES];
            view.zt0 = zt0.as_mut_ptr();
            assert!(zt0_profile.validate_view(&context, &view).is_ok());
            assert!(original.validate_view(&context, &view).is_ok());
            view.za = core::ptr::null_mut();
            assert!(profile.validate_view(&context, &view).is_err());
            assert!(zt0_profile.validate_view(&context, &view).is_err());
        }

        #[test]
        fn declared_profile_requires_explicit_dependencies_and_controls() {
            let length = VectorLength::from_bytes(64).unwrap();
            let controls = ScalableControls::new(length, false);
            let sme = ScalableFeatures::of(ScalableFeature::Sme);
            let mode = ScalableMode::new(true, false);
            assert!(
                ScalableProfile::new_with_features(
                    length,
                    mode,
                    ScalableFeatures::empty(),
                    controls
                )
                .is_err()
            );
            assert!(
                ScalableProfile::new_with_features(
                    length,
                    mode,
                    sme.with(ScalableFeature::Sme2p1),
                    controls
                )
                .is_err()
            );
            assert!(
                ScalableProfile::new_with_features(
                    length,
                    mode,
                    sme,
                    ScalableControls::new(length, true)
                )
                .is_err()
            );
            assert!(
                ScalableProfile::new_with_features(
                    length,
                    mode,
                    sme,
                    ScalableControls::new(VectorLength::from_bytes(32).unwrap(), false)
                )
                .is_err()
            );
            let profile = ScalableProfile::new_with_features(length, mode, sme, controls).unwrap();
            assert_eq!(profile.id(), DECLARED_PROFILE_ID);
            assert_eq!(profile.features(), sme);
            assert_eq!(profile.declared_features(), Some(sme));
            assert_eq!(profile.controls(), controls);
        }

        #[test]
        fn declared_profile_identity_includes_features_and_controls() {
            let length = VectorLength::from_bytes(32).unwrap();
            let mode = ScalableMode::new(true, true);
            let features = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
            let controls = ScalableControls::new(length, false);
            let original =
                ScalableProfile::new_with_features(length, mode, features, controls).unwrap();
            for (other_features, other_controls) in [
                (features.with(ScalableFeature::Sme2p1), controls),
                (
                    features,
                    ScalableControls::new(VectorLength::from_bytes(64).unwrap(), false),
                ),
                (features, ScalableControls::new(length, true)),
            ] {
                assert_ne!(
                    original,
                    ScalableProfile::new_with_features(
                        length,
                        mode,
                        other_features,
                        other_controls
                    )
                    .unwrap()
                );
            }
        }

        #[test]
        fn original_profile_retains_fixed_identity_and_manifest_shape() {
            let length = VectorLength::from_bytes(64).unwrap();
            let mode = ScalableMode::new(false, true);
            let original = ScalableProfile::new(length, mode);
            assert_eq!(original.id(), PROFILE_ID);
            assert_eq!(original.vector_length(), length);
            assert_eq!(original.mode(), mode);
            assert_eq!(original.declared_features(), None);
            assert_eq!(original.features().names(), ["FEAT_SME", "FEAT_SME2"]);
            assert_eq!(original.controls(), ScalableControls::new(length, false));
            assert_ne!(
                original,
                ScalableProfile::new_with_features(
                    length,
                    mode,
                    original.features(),
                    original.controls()
                )
                .unwrap()
            );
        }

        #[test]
        fn declared_profiles_keep_base_sme_families_available() {
            const BASE_SME_WORDS: [u32; 6] = [
                0x041a_0040, // AND predicated.
                0x0461_5820, // ADDSPL.
                0x0416_a020, // ABS predicated.
                0x045c_bfff, // FABS predicated.
                0x4500_f820, // SABA.
                0x4482_003f, // Four-product SDOT.
            ];
            for bytes in [16, 32, 64, 128, 256] {
                let length = VectorLength::from_bytes(bytes).unwrap();
                let profile = ScalableProfile::new_with_features(
                    length,
                    ScalableMode::new(true, false),
                    ScalableFeatures::of(ScalableFeature::Sme),
                    ScalableControls::new(length, false),
                )
                .unwrap();
                for word in BASE_SME_WORDS {
                    assert!(
                        compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0x1234),
                            profile,
                            TargetCpu::Baseline,
                        )
                        .is_ok()
                    );
                }
            }
        }

        #[test]
        fn declared_dot_features_preserve_v1_scope_and_check_optional_requirements() {
            const TWO_PRODUCT_SDOT: u32 = 0x4402_c820;
            const MIXED_DOT_WORDS: [u32; 3] = [0x4482_7820, 0x44a2_1820, 0x44a2_1c20];
            let length = VectorLength::from_bytes(16).unwrap();
            let mode = ScalableMode::new(true, false);
            let sme = ScalableFeatures::of(ScalableFeature::Sme);
            let declared = |features| {
                ScalableProfile::new_with_features(
                    length,
                    mode,
                    features,
                    ScalableControls::new(length, false),
                )
                .unwrap()
            };
            let compile = |word, profile| {
                compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1234),
                    profile,
                    TargetCpu::Baseline,
                )
            };
            let missing = compile(TWO_PRODUCT_SDOT, declared(sme)).unwrap_err();
            assert!(missing.0.contains("0x1234") && missing.0.contains("requires FEAT_SME2"));
            assert!(compile(TWO_PRODUCT_SDOT, declared(sme.with(ScalableFeature::Sme2))).is_ok());
            assert!(compile(TWO_PRODUCT_SDOT, ScalableProfile::new(length, mode)).is_ok());
            for word in MIXED_DOT_WORDS {
                let legacy = compile(word, ScalableProfile::new(length, mode)).unwrap_err();
                assert!(legacy.0.contains("I8MM is outside") && legacy.0.contains("0x1234"));
                let missing = compile(word, declared(sme.with(ScalableFeature::Sme2))).unwrap_err();
                assert!(missing.0.contains("requires FEAT_I8MM") && missing.0.contains("0x1234"));
                assert!(compile(word, declared(sme.with(ScalableFeature::I8mm))).is_ok());
            }
        }
    }
    mod rearrange {
        //! SVE permute dispatch, bodies and source maps.
        use super::*;
        use crate::aarch64::sve::rearrange;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
        const RESERVED_LOGICAL_MASK: u32 = 0x05c0_07e0;
        const NONZERO_REVD_SIZE: u32 = 0x056e_8000;
        const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;
        const REARRANGEMENT_WORDS: [u32; 20] = [
            0x05c00003, // dupm_z_i_
            0x05600023, // ext_z_zi_con
            0x05200023, // ext_z_zi_des
            0x04224023, // index_z_ii_
            0x04224823, // index_z_ir_
            0x04224423, // index_z_ri_
            0x04224c23, // index_z_rr_
            0x05383823, // rev_z_z_
            0x052e8023, // revd_z_p_z_m
            0x052d8023, // splice_z_p_zz_con
            0x052c8023, // splice_z_p_zz_des
            0x05223023, // tbl_z_zz_1
            0x05222823, // tbl_z_zz_2
            0x05222c23, // tbx_z_zz_
            0x05227023, // trn1_z_zz_
            0x05227423, // trn2_z_zz_
            0x05226823, // uzp1_z_zz_
            0x05226c23, // uzp2_z_zz_
            0x05226023, // zip1_z_zz_
            0x05226423, // zip2_z_zz_
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(bytes: usize, svcr: u64) -> ScalableProfile {
            ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::from_svcr(svcr).unwrap(),
            )
        }

        fn dit_zero_profile(bytes: usize, svcr: u64) -> ScalableProfile {
            let length = VectorLength::from_bytes(bytes).unwrap();
            ScalableProfile::new_with_features(
                length,
                ScalableMode::from_svcr(svcr).unwrap(),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap()
        }

        #[test]
        fn rearrangement_production_dispatch_has_exact_body_maps_and_target_encoding() {
            for word in REARRANGEMENT_WORDS {
                let operand = rearrange::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::Rearrange(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [1, 3] {
                        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                            let length = VectorLength::from_bytes(bytes).unwrap();
                            let execution = if x86_64::sve::rearrange::requires_explicit_dit_zero(
                                operand, length, target,
                            ) {
                                dit_zero_profile(bytes, svcr)
                            } else {
                                profile(bytes, svcr)
                            };
                            let native = compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0x1000),
                                execution,
                                target,
                            )
                            .unwrap();
                            let mut expected = Code::new();
                            x86_64::sve::rearrange::emit(
                                &mut expected,
                                operand,
                                VectorLength::from_bytes(bytes).unwrap(),
                                target,
                            );
                            assert_eq!(
                                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                context_wrapper()
                            );
                            assert_eq!(
                                native.source_map,
                                [
                                    (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                    (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + 1),
                                    (
                                        GuestAddress(0x1008),
                                        CONTEXT_WRAPPER_BYTES + 1 + expected.len()
                                    ),
                                ]
                            );
                            assert_eq!(
                                &native.x86_64_code
                                    [CONTEXT_WRAPPER_BYTES + 1..native.source_map[2].1],
                                expected
                            );
                            assert_eq!(&native.x86_64_code[native.source_map[2].1..], [RET]);
                        }
                    }
                }
            }
        }

        #[test]
        fn rearrangement_preflight_preserves_mode_reserved_legacy_and_prefix_boundaries() {
            for word in REARRANGEMENT_WORDS {
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [0, 2] {
                        assert!(
                            compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0),
                                profile(bytes, svcr),
                                TargetCpu::Baseline,
                            )
                            .unwrap_err()
                            .0
                            .contains("streaming mode required")
                        );
                    }
                }
                assert!(crate::compile(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
                assert!(
                    compile_for_profile(
                        &source(&[MOVPRFX_Z0_Z1, word, RET_X30]),
                        GuestAddress(0),
                        profile(32, 3),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("MOVPRFX pair validation")
                );
            }
            assert!(
                compile_for_profile(
                    &source(&[NOP, RESERVED_LOGICAL_MASK, RET_X30]),
                    GuestAddress(0),
                    profile(32, 3),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("reserved streaming rearrangement")
            );
        }

        #[test]
        fn rearrangement_declines_nonzero_revd_size_and_both_prefix_forms() {
            assert!(
                compile_for_profile(
                    &source(&[NONZERO_REVD_SIZE, RET_X30]),
                    GuestAddress(0),
                    profile(32, 3),
                    TargetCpu::Baseline,
                )
                .is_err()
            );
            for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
                assert!(
                    compile_for_profile(
                        &source(&[prefix, REARRANGEMENT_WORDS[0], RET_X30]),
                        GuestAddress(0),
                        profile(32, 3),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("MOVPRFX pair validation")
                );
            }
        }

        #[test]
        fn rearrangement_scalar_tables_require_explicit_dit_zero_while_byte_shuffle_stays_v1() {
            const TBL_B_Z3_Z1_Z2: u32 = 0x0522_3023;
            const TBL_H_Z3_Z1_Z2: u32 = 0x0562_3023;
            for bytes in [16, 32, 64, 128, 256] {
                for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                    for svcr in [1, 3] {
                        for word in [TBL_B_Z3_Z1_Z2, TBL_H_Z3_Z1_Z2] {
                            let operand = rearrange::decode(word).unwrap().unwrap();
                            let requires = x86_64::sve::rearrange::requires_explicit_dit_zero(
                                operand,
                                VectorLength::from_bytes(bytes).unwrap(),
                                target,
                            );
                            let legacy = compile_for_profile(
                                &source(&[word, RET_X30]),
                                GuestAddress(0x1000),
                                profile(bytes, svcr),
                                target,
                            );
                            if requires {
                                assert!(legacy.unwrap_err().0.contains(
                            "scalar table lookup requires explicitly declared DIT=0 at 0x1000"
                        ));
                                assert_eq!(profile(bytes, svcr).required_dit(), None);
                            } else {
                                assert!(legacy.is_ok());
                            }
                            let declared = dit_zero_profile(bytes, svcr);
                            assert_eq!(declared.required_dit(), Some(false));
                            assert!(
                                compile_for_profile(
                                    &source(&[word, RET_X30]),
                                    GuestAddress(0x1000),
                                    declared,
                                    target,
                                )
                                .is_ok()
                            );
                        }
                    }
                }
            }
            // These observations distinguish fixed-work PSHUFB from scalar gather;
            // the frontend itself consumes the shared selector rather than a cutoff copy.
            let byte = rearrange::decode(TBL_B_Z3_Z1_Z2).unwrap().unwrap();
            let half = rearrange::decode(TBL_H_Z3_Z1_Z2).unwrap().unwrap();
            let small = VectorLength::from_bytes(16).unwrap();
            let wide = VectorLength::from_bytes(256).unwrap();
            assert!(x86_64::sve::rearrange::requires_explicit_dit_zero(
                byte,
                small,
                TargetCpu::Baseline
            ));
            assert!(!x86_64::sve::rearrange::requires_explicit_dit_zero(
                byte,
                small,
                TargetCpu::Ssse3
            ));
            assert!(x86_64::sve::rearrange::requires_explicit_dit_zero(
                byte,
                wide,
                TargetCpu::Ssse3
            ));
            assert!(x86_64::sve::rearrange::requires_explicit_dit_zero(
                half,
                small,
                TargetCpu::Ssse3
            ));
        }
    }
    mod rearrange_extract {
        //! SVE extraction dispatch, bodies and source maps.
        use super::*;
        use crate::aarch64::sve::rearrange_extract;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
        const RESERVED_BYTE_SHIFT: u32 = 0x2538_e000;
        const RESERVED_ZERO_INDEX_SIZE: u32 = 0x0520_2000;
        const EXTRACTION_WORDS: [u32; 15] = [
            0x0520bca5, // lasta_r_p_z_
            0x0521bca5, // lastb_r_p_z_
            0x05229ca5, // lasta_v_p_z_
            0x05239ca5, // lastb_v_p_z_
            0x0530bca5, // clasta_r_p_z_
            0x0531bca5, // clastb_r_p_z_
            0x052a9ca5, // clasta_v_p_z_
            0x052b9ca5, // clastb_v_p_z_
            0x05289ca5, // clasta_z_p_zz_
            0x05299ca5, // clastb_z_p_zz_
            0x052038a5, // dup_z_r_
            0x052438a5, // insr_z_r_
            0x053438a5, // insr_z_v_
            0x2538d01f, // dup_z_i_
            0x052120a5, // dup_z_zi_
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(bytes: usize, svcr: u64) -> ScalableProfile {
            ScalableProfile::new(
                VectorLength::from_bytes(bytes).unwrap(),
                ScalableMode::from_svcr(svcr).unwrap(),
            )
        }

        #[test]
        fn extraction_production_dispatch_has_exact_body_maps_and_target_encoding() {
            for word in EXTRACTION_WORDS {
                let operand = rearrange_extract::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::RearrangeExtract(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [1, 3] {
                        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                            let native = compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0x1000),
                                profile(bytes, svcr),
                                target,
                            )
                            .unwrap();
                            let mut expected = Code::new();
                            x86_64::sve::rearrange_extract::emit(
                                &mut expected,
                                operand,
                                VectorLength::from_bytes(bytes).unwrap(),
                                target,
                            );
                            assert_eq!(
                                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                context_wrapper()
                            );
                            assert_eq!(
                                native.source_map,
                                [
                                    (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                    (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + 1),
                                    (
                                        GuestAddress(0x1008),
                                        CONTEXT_WRAPPER_BYTES + 1 + expected.len()
                                    ),
                                ]
                            );
                            assert_eq!(
                                &native.x86_64_code
                                    [CONTEXT_WRAPPER_BYTES + 1..native.source_map[2].1],
                                expected
                            );
                            assert_eq!(&native.x86_64_code[native.source_map[2].1..], [RET]);
                        }
                    }
                }
            }
        }

        #[test]
        fn extraction_preflight_preserves_mode_reserved_legacy_and_prefix_boundaries() {
            for word in EXTRACTION_WORDS {
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [0, 2] {
                        assert!(
                            compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0),
                                profile(bytes, svcr),
                                TargetCpu::Baseline,
                            )
                            .unwrap_err()
                            .0
                            .contains("streaming mode required")
                        );
                    }
                }
                assert!(crate::compile(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
                assert!(
                    compile_for_profile(
                        &source(&[MOVPRFX_Z0_Z1, word, RET_X30]),
                        GuestAddress(0),
                        profile(32, 3),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("MOVPRFX pair validation")
                );
            }
            for word in [RESERVED_BYTE_SHIFT, RESERVED_ZERO_INDEX_SIZE] {
                assert!(
                    compile_for_profile(
                        &source(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(32, 3),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming extraction")
                );
            }
        }

        #[test]
        fn extraction_base_sme_profile_requires_no_sme2_or_za_enablement() {
            for bytes in [16, 32, 64, 128, 256] {
                let length = VectorLength::from_bytes(bytes).unwrap();
                for svcr in [1, 3] {
                    let declared = ScalableProfile::new_with_features(
                        length,
                        ScalableMode::from_svcr(svcr).unwrap(),
                        ScalableFeatures::of(ScalableFeature::Sme),
                        ScalableControls::new(length, false),
                    )
                    .unwrap();
                    assert!(!declared.features().contains(ScalableFeature::Sme2));
                    assert!(!declared.features().contains(ScalableFeature::Sme2p1));
                    for word in EXTRACTION_WORDS {
                        for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                            let input = source(&[word, RET_X30]);
                            let base = GuestAddress(0x1000);
                            let v1 =
                                compile_for_profile(&input, base, profile(bytes, svcr), target)
                                    .unwrap();
                            let v2 = compile_for_profile(&input, base, declared, target).unwrap();
                            assert_eq!(v1.x86_64_code, v2.x86_64_code);
                            assert_eq!(v1.source_map, v2.source_map);
                        }
                    }
                }
            }
        }
    }
    mod reductions {
        //! SVE reduction dispatch, element sizes, source maps and limits.
        use super::*;
        use crate::aarch64::sve::reductions::{self, Output};
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
        const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;
        const SIGNED_ADD: u32 = 0x0400_2000;
        const RESERVED_SIGNED_DOUBLEWORD: u32 = 0x04c0_2020;
        const SIZE_SHIFT: u32 = 22;
        const SOURCE_ONE_DESTINATION_ZERO: u32 = 0x20;
        const BASE_CLASSES: [u32; 9] = [
            0x041a_2000,
            0x0418_2000,
            0x0419_2000,
            0x0400_2000,
            0x0401_2000,
            0x0408_2000,
            0x0409_2000,
            0x040a_2000,
            0x040b_2000,
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn profile(bytes: usize, svcr: u64) -> ScalableProfile {
            let length = VectorLength::from_bytes(bytes).unwrap();
            ScalableProfile::new_with_features(
                length,
                ScalableMode::from_svcr(svcr).unwrap(),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(length, false),
            )
            .unwrap()
        }

        fn base_words() -> impl Iterator<Item = u32> {
            BASE_CLASSES.into_iter().flat_map(|class| {
                (0..4).filter_map(move |size| {
                    (class != SIGNED_ADD || size != 3)
                        .then_some(class | size << SIZE_SHIFT | SOURCE_ONE_DESTINATION_ZERO)
                })
            })
        }

        #[test]
        fn scalar_reductions_all_35_widths_have_exact_dispatch_body_maps_and_targets() {
            assert_eq!(base_words().count(), 35);
            for word in base_words() {
                let operand = reductions::decode(word).unwrap().unwrap();
                assert_eq!(operand.output, Output::Scalar);
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::Reductions(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [1, 3] {
                        for target in [TargetCpu::Baseline, TargetCpu::Sse41, TargetCpu::Sse42] {
                            let native = compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0x1000),
                                profile(bytes, svcr),
                                target,
                            )
                            .unwrap();
                            let mut expected = Code::new();
                            x86_64::sve::reductions::emit(
                                &mut expected,
                                operand,
                                VectorLength::from_bytes(bytes).unwrap(),
                                target,
                            );
                            assert_eq!(
                                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                context_wrapper()
                            );
                            assert_eq!(
                                native.source_map,
                                [
                                    (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                    (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + 1),
                                    (
                                        GuestAddress(0x1008),
                                        CONTEXT_WRAPPER_BYTES + 1 + expected.len()
                                    ),
                                ]
                            );
                            assert_eq!(
                                &native.x86_64_code
                                    [CONTEXT_WRAPPER_BYTES + 1..native.source_map[2].1],
                                expected
                            );
                            assert_eq!(&native.x86_64_code[native.source_map[2].1..], [RET]);
                        }
                    }
                }
            }
        }

        #[test]
        fn scalar_reductions_preserve_mode_reserved_legacy_and_prefix_boundaries() {
            for word in base_words() {
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [0, 2] {
                        assert!(
                            compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0),
                                profile(bytes, svcr),
                                TargetCpu::Baseline,
                            )
                            .unwrap_err()
                            .0
                            .contains("streaming mode required")
                        );
                    }
                }
                assert!(crate::compile(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
                for prefix in [MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1] {
                    assert!(
                        compile_for_profile(
                            &source(&[prefix, word, RET_X30]),
                            GuestAddress(0),
                            profile(32, 3),
                            TargetCpu::Baseline,
                        )
                        .unwrap_err()
                        .0
                        .contains("MOVPRFX pair validation")
                    );
                }
            }
            assert_eq!(
                reductions::decode(RESERVED_SIGNED_DOUBLEWORD),
                Some(Err(crate::aarch64::Unsupported))
            );
            assert!(
                compile_for_profile(
                    &source(&[NOP, RESERVED_SIGNED_DOUBLEWORD, RET_X30]),
                    GuestAddress(0),
                    profile(32, 3),
                    TargetCpu::Baseline,
                )
                .unwrap_err()
                .0
                .contains("reserved streaming integer reduction")
            );
        }
    }
    mod shifts {
        use super::*;
        use crate::aarch64::sve::shifts;
        use crate::aarch64::sve::shifts_narrow;

        fn declared_dit_zero_profile(bytes: usize) -> ScalableProfile {
            let length = VectorLength::from_bytes(bytes).unwrap();
            ScalableProfile::new_with_features(
                length,
                ScalableMode::new(true, false),
                ScalableFeatures::of(ScalableFeature::Sme),
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
            )
            .unwrap()
        }

        #[test]
        fn integer_shifts_register_exact_bodies_and_source_maps() {
            const CANONICAL_WORDS: [u32; 43] = [
                0x040081e0, // ASR
                0x04188040, // ASR
                0x04108040, // ASR
                0x042f9020, // ASR
                0x04228020, // ASR
                0x040481e0, // ASRD
                0x04148040, // ASRR
                0x04038100, // LSL
                0x041b8040, // LSL
                0x04138040, // LSL
                0x04289c20, // LSL
                0x04228c20, // LSL
                0x04178040, // LSLR
                0x040181e0, // LSR
                0x04198040, // LSR
                0x04118040, // LSR
                0x042f9420, // LSR
                0x04228420, // LSR
                0x04158040, // LSRR
                0x4508f420, // SLI
                0x440a8040, // SQRSHL
                0x440e8040, // SQRSHLR
                0x04068100, // SQSHL
                0x44088040, // SQSHL
                0x440c8040, // SQSHLR
                0x040f8100, // SQSHLU
                0x450ff020, // SRI
                0x44028040, // SRSHL
                0x44068040, // SRSHLR
                0x040c81e0, // SRSHR
                0x450fe820, // SRSRA
                0x450fe020, // SSRA
                0x440b8040, // UQRSHL
                0x440f8040, // UQRSHLR
                0x04078100, // UQSHL
                0x44098040, // UQSHL
                0x440d8040, // UQSHLR
                0x44038040, // URSHL
                0x44078040, // URSHLR
                0x040d81e0, // URSHR
                0x450fec20, // URSRA
                0x450fe420, // USRA
                0x042f3440, // XAR
            ];
            for word in CANONICAL_WORDS {
                let operand = shifts::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::Shifts(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                        let native = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            declared_dit_zero_profile(bytes),
                            target,
                        )
                        .unwrap();
                        let mut body = Code::new();
                        x86_64::sve::shifts::emit(
                            &mut body,
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                        assert_eq!(
                            native.source_map,
                            [
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                (GuestAddress(0x1004), return_offset)
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                            body
                        );
                        assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
                    }
                }
                let length = VectorLength::from_bytes(16).unwrap();
                let base_sme = ScalableProfile::new_with_features(
                    length,
                    ScalableMode::new(true, false),
                    ScalableFeatures::of(ScalableFeature::Sme),
                    ScalableControls::new(length, false),
                )
                .unwrap();
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0),
                        base_sme,
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
                for streaming in [false, true] {
                    for za in [false, true] {
                        let selected = ScalableProfile::new(
                            VectorLength::from_bytes(16).unwrap(),
                            ScalableMode::new(streaming, za),
                        );
                        let result = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            selected,
                            TargetCpu::Baseline,
                        );
                        if streaming
                            && x86_64::sve::shifts::requires_declared_dit_zero(operand, length)
                        {
                            assert!(result.unwrap_err().0.contains("requires declared DIT=0"));
                        } else if streaming {
                            assert!(result.is_ok());
                        } else {
                            assert!(result.unwrap_err().0.contains("streaming mode required"));
                        }
                    }
                }
            }
        }

        #[test]
        fn integer_shift_dit_policy_preserves_canonical_width_boundaries() {
            // Expected decisions come from the source-bound June per-form audit,
            // including forward/reverse rounding identity and byte packed exceptions.
            const AUDITED_WORDS: &[(u32, bool, bool)] = &[
                (0x0400_81e0, true, false),  // asr_z_p_zi_
                (0x0400_83e0, true, false),  // asr_z_p_zi_
                (0x0440_83e0, true, false),  // asr_z_p_zi_
                (0x04c0_83e0, true, false),  // asr_z_p_zi_
                (0x0418_8040, true, true),   // asr_z_p_zw_
                (0x0458_8040, true, true),   // asr_z_p_zw_
                (0x0498_8040, true, true),   // asr_z_p_zw_
                (0x0410_8040, true, true),   // asr_z_p_zz_
                (0x0450_8040, true, true),   // asr_z_p_zz_
                (0x0490_8040, true, true),   // asr_z_p_zz_
                (0x04d0_8040, true, true),   // asr_z_p_zz_
                (0x042f_9020, true, false),  // asr_z_zi_
                (0x043f_9020, true, false),  // asr_z_zi_
                (0x047f_9020, true, false),  // asr_z_zi_
                (0x04ff_9020, true, false),  // asr_z_zi_
                (0x0422_8020, true, true),   // asr_z_zw_
                (0x0462_8020, true, true),   // asr_z_zw_
                (0x04a2_8020, true, true),   // asr_z_zw_
                (0x0404_81e0, true, false),  // asrd_z_p_zi_
                (0x0404_83e0, true, false),  // asrd_z_p_zi_
                (0x0444_83e0, true, false),  // asrd_z_p_zi_
                (0x04c4_83e0, true, false),  // asrd_z_p_zi_
                (0x0414_8040, true, true),   // asrr_z_p_zz_
                (0x0454_8040, true, true),   // asrr_z_p_zz_
                (0x0494_8040, true, true),   // asrr_z_p_zz_
                (0x04d4_8040, true, true),   // asrr_z_p_zz_
                (0x0403_8100, true, false),  // lsl_z_p_zi_
                (0x0403_8200, true, false),  // lsl_z_p_zi_
                (0x0443_8000, true, false),  // lsl_z_p_zi_
                (0x0483_8000, true, false),  // lsl_z_p_zi_
                (0x041b_8040, true, true),   // lsl_z_p_zw_
                (0x045b_8040, true, true),   // lsl_z_p_zw_
                (0x049b_8040, true, true),   // lsl_z_p_zw_
                (0x0413_8040, true, false),  // lsl_z_p_zz_
                (0x0453_8040, true, true),   // lsl_z_p_zz_
                (0x0493_8040, true, true),   // lsl_z_p_zz_
                (0x04d3_8040, true, true),   // lsl_z_p_zz_
                (0x0428_9c20, true, false),  // lsl_z_zi_
                (0x0430_9c20, true, false),  // lsl_z_zi_
                (0x0460_9c20, true, false),  // lsl_z_zi_
                (0x04a0_9c20, true, false),  // lsl_z_zi_
                (0x0422_8c20, true, true),   // lsl_z_zw_
                (0x0462_8c20, true, true),   // lsl_z_zw_
                (0x04a2_8c20, true, true),   // lsl_z_zw_
                (0x0417_8040, true, false),  // lslr_z_p_zz_
                (0x0457_8040, true, true),   // lslr_z_p_zz_
                (0x0497_8040, true, true),   // lslr_z_p_zz_
                (0x04d7_8040, true, true),   // lslr_z_p_zz_
                (0x0401_81e0, true, false),  // lsr_z_p_zi_
                (0x0401_83e0, true, false),  // lsr_z_p_zi_
                (0x0441_83e0, true, false),  // lsr_z_p_zi_
                (0x04c1_83e0, true, false),  // lsr_z_p_zi_
                (0x0419_8040, true, true),   // lsr_z_p_zw_
                (0x0459_8040, true, true),   // lsr_z_p_zw_
                (0x0499_8040, true, true),   // lsr_z_p_zw_
                (0x0411_8040, true, false),  // lsr_z_p_zz_
                (0x0451_8040, true, true),   // lsr_z_p_zz_
                (0x0491_8040, true, true),   // lsr_z_p_zz_
                (0x04d1_8040, true, true),   // lsr_z_p_zz_
                (0x042f_9420, true, false),  // lsr_z_zi_
                (0x043f_9420, true, false),  // lsr_z_zi_
                (0x047f_9420, true, false),  // lsr_z_zi_
                (0x04ff_9420, true, false),  // lsr_z_zi_
                (0x0422_8420, true, true),   // lsr_z_zw_
                (0x0462_8420, true, true),   // lsr_z_zw_
                (0x04a2_8420, true, true),   // lsr_z_zw_
                (0x0415_8040, true, false),  // lsrr_z_p_zz_
                (0x0455_8040, true, true),   // lsrr_z_p_zz_
                (0x0495_8040, true, true),   // lsrr_z_p_zz_
                (0x04d5_8040, true, true),   // lsrr_z_p_zz_
                (0x4508_f420, true, false),  // sli_z_zzi_
                (0x4510_f420, true, false),  // sli_z_zzi_
                (0x4540_f420, true, false),  // sli_z_zzi_
                (0x4580_f420, true, false),  // sli_z_zzi_
                (0x440a_8040, false, false), // sqrshl_z_p_zz_
                (0x444a_8040, false, false), // sqrshl_z_p_zz_
                (0x448a_8040, false, false), // sqrshl_z_p_zz_
                (0x44ca_8040, false, false), // sqrshl_z_p_zz_
                (0x440e_8040, false, false), // sqrshlr_z_p_zz_
                (0x444e_8040, false, false), // sqrshlr_z_p_zz_
                (0x448e_8040, false, false), // sqrshlr_z_p_zz_
                (0x44ce_8040, false, false), // sqrshlr_z_p_zz_
                (0x0406_8100, false, false), // sqshl_z_p_zi_
                (0x0406_8200, false, false), // sqshl_z_p_zi_
                (0x0446_8000, false, false), // sqshl_z_p_zi_
                (0x0486_8000, false, false), // sqshl_z_p_zi_
                (0x4408_8040, false, false), // sqshl_z_p_zz_
                (0x4448_8040, false, false), // sqshl_z_p_zz_
                (0x4488_8040, false, false), // sqshl_z_p_zz_
                (0x44c8_8040, false, false), // sqshl_z_p_zz_
                (0x440c_8040, false, false), // sqshlr_z_p_zz_
                (0x444c_8040, false, false), // sqshlr_z_p_zz_
                (0x448c_8040, false, false), // sqshlr_z_p_zz_
                (0x44cc_8040, false, false), // sqshlr_z_p_zz_
                (0x040f_8100, false, false), // sqshlu_z_p_zi_
                (0x040f_8200, false, false), // sqshlu_z_p_zi_
                (0x044f_8000, false, false), // sqshlu_z_p_zi_
                (0x048f_8000, false, false), // sqshlu_z_p_zi_
                (0x450f_f020, true, false),  // sri_z_zzi_
                (0x451f_f020, true, false),  // sri_z_zzi_
                (0x455f_f020, true, false),  // sri_z_zzi_
                (0x45df_f020, true, false),  // sri_z_zzi_
                (0x4402_8040, true, true),   // srshl_z_p_zz_
                (0x4442_8040, true, true),   // srshl_z_p_zz_
                (0x4482_8040, true, true),   // srshl_z_p_zz_
                (0x44c2_8040, true, true),   // srshl_z_p_zz_
                (0x4406_8040, false, false), // srshlr_z_p_zz_
                (0x4446_8040, false, false), // srshlr_z_p_zz_
                (0x4486_8040, false, false), // srshlr_z_p_zz_
                (0x44c6_8040, false, false), // srshlr_z_p_zz_
                (0x040c_81e0, true, false),  // srshr_z_p_zi_
                (0x040c_83e0, true, false),  // srshr_z_p_zi_
                (0x044c_83e0, true, false),  // srshr_z_p_zi_
                (0x04cc_83e0, true, false),  // srshr_z_p_zi_
                (0x450f_e820, true, false),  // srsra_z_zi_
                (0x451f_e820, true, false),  // srsra_z_zi_
                (0x455f_e820, true, false),  // srsra_z_zi_
                (0x45df_e820, true, false),  // srsra_z_zi_
                (0x450f_e020, true, false),  // ssra_z_zi_
                (0x451f_e020, true, false),  // ssra_z_zi_
                (0x455f_e020, true, false),  // ssra_z_zi_
                (0x45df_e020, true, false),  // ssra_z_zi_
                (0x440b_8040, false, false), // uqrshl_z_p_zz_
                (0x444b_8040, false, false), // uqrshl_z_p_zz_
                (0x448b_8040, false, false), // uqrshl_z_p_zz_
                (0x44cb_8040, false, false), // uqrshl_z_p_zz_
                (0x440f_8040, false, false), // uqrshlr_z_p_zz_
                (0x444f_8040, false, false), // uqrshlr_z_p_zz_
                (0x448f_8040, false, false), // uqrshlr_z_p_zz_
                (0x44cf_8040, false, false), // uqrshlr_z_p_zz_
                (0x0407_8100, false, false), // uqshl_z_p_zi_
                (0x0407_8200, false, false), // uqshl_z_p_zi_
                (0x0447_8000, false, false), // uqshl_z_p_zi_
                (0x0487_8000, false, false), // uqshl_z_p_zi_
                (0x4409_8040, false, false), // uqshl_z_p_zz_
                (0x4449_8040, false, false), // uqshl_z_p_zz_
                (0x4489_8040, false, false), // uqshl_z_p_zz_
                (0x44c9_8040, false, false), // uqshl_z_p_zz_
                (0x440d_8040, false, false), // uqshlr_z_p_zz_
                (0x444d_8040, false, false), // uqshlr_z_p_zz_
                (0x448d_8040, false, false), // uqshlr_z_p_zz_
                (0x44cd_8040, false, false), // uqshlr_z_p_zz_
                (0x4403_8040, true, true),   // urshl_z_p_zz_
                (0x4443_8040, true, true),   // urshl_z_p_zz_
                (0x4483_8040, true, true),   // urshl_z_p_zz_
                (0x44c3_8040, true, true),   // urshl_z_p_zz_
                (0x4407_8040, false, false), // urshlr_z_p_zz_
                (0x4447_8040, false, false), // urshlr_z_p_zz_
                (0x4487_8040, false, false), // urshlr_z_p_zz_
                (0x44c7_8040, false, false), // urshlr_z_p_zz_
                (0x040d_81e0, true, false),  // urshr_z_p_zi_
                (0x040d_83e0, true, false),  // urshr_z_p_zi_
                (0x044d_83e0, true, false),  // urshr_z_p_zi_
                (0x04cd_83e0, true, false),  // urshr_z_p_zi_
                (0x450f_ec20, true, false),  // ursra_z_zi_
                (0x451f_ec20, true, false),  // ursra_z_zi_
                (0x455f_ec20, true, false),  // ursra_z_zi_
                (0x45df_ec20, true, false),  // ursra_z_zi_
                (0x450f_e420, true, false),  // usra_z_zi_
                (0x451f_e420, true, false),  // usra_z_zi_
                (0x455f_e420, true, false),  // usra_z_zi_
                (0x45df_e420, true, false),  // usra_z_zi_
                (0x042f_3440, true, false),  // xar_z_zzi_
                (0x043f_3440, true, false),  // xar_z_zzi_
                (0x047f_3440, true, false),  // xar_z_zzi_
                (0x04ff_3440, true, false),  // xar_z_zzi_
            ];
            for &(word, noted, requires_dit_zero) in AUDITED_WORDS {
                let operand = shifts::decode(word).unwrap().unwrap();
                assert_eq!(operand.has_dit_guarantee, noted, "{word:#x}");
                for bytes in [16, 32, 64, 128, 256] {
                    let length = VectorLength::from_bytes(bytes).unwrap();
                    assert_eq!(
                        x86_64::sve::shifts::requires_declared_dit_zero(operand, length),
                        requires_dit_zero,
                        "{word:#x} at {bytes} bytes",
                    );
                    let source = words(&[NOP, word, RET_X30]);
                    let legacy = compile_for_profile(
                        &source,
                        GuestAddress(0),
                        profile(bytes, true),
                        TargetCpu::Baseline,
                    );
                    if requires_dit_zero {
                        assert!(legacy.unwrap_err().0.contains("requires declared DIT=0"));
                    } else {
                        assert!(legacy.is_ok());
                    }
                    assert!(
                        compile_for_profile(
                            &source,
                            GuestAddress(0),
                            declared_dit_zero_profile(bytes),
                            TargetCpu::Baseline,
                        )
                        .is_ok()
                    );
                }
            }
        }

        #[test]
        fn integer_shifts_reserved_and_prefix_inputs_remain_explicit() {
            const LSL_RESERVED_SIZE: u32 = 0x0403_8000;
            const ASR_RESERVED_DOUBLEWORDS: u32 = 0x04d8_8000;
            const LSL_Z0_B_P0_Z0_B_ZERO: u32 = 0x0403_8100;
            for word in [LSL_RESERVED_SIZE, ASR_RESERVED_DOUBLEWORDS] {
                assert!(
                    compile_for_profile(
                        &words(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(16, true),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming integer shift")
                );
            }
            assert!(
                compile_for_profile(
                    &words(&[MOVPRFX_Z0_Z1, LSL_Z0_B_P0_Z0_B_ZERO, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
            assert!(
                crate::compile(&words(&[LSL_Z0_B_P0_Z0_B_ZERO, RET_X30]), GuestAddress(0)).is_err()
            );
        }

        #[test]
        fn width_conversions_register_exact_bodies_and_source_maps() {
            const CANONICAL_WORDS: [u32; 26] = [
                0x452f1820, // RSHRNB
                0x452f1c20, // RSHRNT
                0x452f1020, // SHRNB
                0x452f1420, // SHRNT
                0x452f2820, // SQRSHRNB
                0x452f2c20, // SQRSHRNT
                0x452f0820, // SQRSHRUNB
                0x452f0c20, // SQRSHRUNT
                0x452f2020, // SQSHRNB
                0x452f2420, // SQSHRNT
                0x452f0020, // SQSHRUNB
                0x452f0420, // SQSHRUNT
                0x45284020, // SQXTNB
                0x45284420, // SQXTNT
                0x45285020, // SQXTUNB
                0x45285420, // SQXTUNT
                0x4508a020, // SSHLLB
                0x4508a420, // SSHLLT
                0x452f3820, // UQRSHRNB
                0x452f3c20, // UQRSHRNT
                0x452f3020, // UQSHRNB
                0x452f3420, // UQSHRNT
                0x45284820, // UQXTNB
                0x45284c20, // UQXTNT
                0x4508a820, // USHLLB
                0x4508ac20, // USHLLT
            ];
            for word in CANONICAL_WORDS {
                let operand = shifts_narrow::decode(word).unwrap().unwrap();
                assert_eq!(
                    crate::aarch64::sve::decode(word),
                    Some(Ok(crate::aarch64::sve::Operand::ShiftsNarrow(operand)))
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [TargetCpu::Baseline, TargetCpu::Sse41] {
                        let native = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0x1000),
                            profile(bytes, true),
                            target,
                        )
                        .unwrap();
                        let mut body = Code::new();
                        x86_64::sve::shifts_narrow::emit(
                            &mut body,
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        let return_offset = CONTEXT_WRAPPER_BYTES + body.len();
                        assert_eq!(
                            native.source_map,
                            [
                                (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                (GuestAddress(0x1004), return_offset)
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..return_offset],
                            body
                        );
                        assert_eq!(&native.x86_64_code[return_offset..], &[RET]);
                    }
                }
                for streaming in [false, true] {
                    for za in [false, true] {
                        let selected = ScalableProfile::new(
                            VectorLength::from_bytes(16).unwrap(),
                            ScalableMode::new(streaming, za),
                        );
                        let result = compile_for_profile(
                            &words(&[word, RET_X30]),
                            GuestAddress(0),
                            selected,
                            TargetCpu::Baseline,
                        );
                        if streaming {
                            assert!(result.is_ok());
                        } else {
                            assert!(result.unwrap_err().0.contains("streaming mode required"));
                        }
                    }
                }
            }
        }

        #[test]
        fn width_conversion_reserved_and_prefix_inputs_remain_explicit() {
            const SSHLLB_RESERVED_SIZE: u32 = 0x4500_a000;
            const SQXTNB_RESERVED_SIZE: u32 = 0x4520_4000;
            const SSHLLB_Z0_H_Z1_B: u32 = 0x4508_a020;
            for word in [SSHLLB_RESERVED_SIZE, SQXTNB_RESERVED_SIZE] {
                assert!(
                    compile_for_profile(
                        &words(&[NOP, word, RET_X30]),
                        GuestAddress(0),
                        profile(16, true),
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("reserved streaming width-conversion")
                );
            }
            assert!(
                compile_for_profile(
                    &words(&[MOVPRFX_Z0_Z1, SSHLLB_Z0_H_Z1_B, RET_X30]),
                    GuestAddress(0),
                    profile(16, true),
                    TargetCpu::Baseline
                )
                .unwrap_err()
                .0
                .contains("MOVPRFX pair validation")
            );
            assert!(crate::compile(&words(&[SSHLLB_Z0_H_Z1_B, RET_X30]), GuestAddress(0)).is_err());
        }
    }
    mod sme2p1 {
        //! SME2.1 dispatch, features, modes and source maps.
        use super::*;
        use crate::aarch64::sve::{rearrange, reductions};
        use alloc::vec::Vec;
        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const PARENT_Q_WORDS: [u32; 105] = [
            0x052037ff, // tbxq_z_zz_
            0x05212421, // dupq_z_zi_
            0x05212423, // dupq_z_zi_
            0x052127ff, // dupq_z_zi_
            0x05222421, // dupq_z_zi_
            0x05222423, // dupq_z_zi_
            0x052227ff, // dupq_z_zi_
            0x05223421, // tbxq_z_zz_
            0x05223423, // tbxq_z_zz_
            0x05232421, // dupq_z_zi_
            0x05232423, // dupq_z_zi_
            0x052327ff, // dupq_z_zi_
            0x05242421, // dupq_z_zi_
            0x05242423, // dupq_z_zi_
            0x052427ff, // dupq_z_zi_
            0x05262421, // dupq_z_zi_
            0x05262423, // dupq_z_zi_
            0x052627ff, // dupq_z_zi_
            0x05282421, // dupq_z_zi_
            0x05282423, // dupq_z_zi_
            0x052827ff, // dupq_z_zi_
            0x052c2421, // dupq_z_zi_
            0x052c2423, // dupq_z_zi_
            0x052c27ff, // dupq_z_zi_
            0x05382421, // dupq_z_zi_
            0x05382423, // dupq_z_zi_
            0x053827ff, // dupq_z_zi_
            0x05602421, // extq_z_zi_des
            0x05602423, // extq_z_zi_des
            0x056027ff, // extq_z_zi_des
            0x056037ff, // tbxq_z_zz_
            0x05612421, // extq_z_zi_des
            0x05612423, // extq_z_zi_des
            0x056127ff, // extq_z_zi_des
            0x05623421, // tbxq_z_zz_
            0x05623423, // tbxq_z_zz_
            0x056f2421, // extq_z_zi_des
            0x056f2423, // extq_z_zi_des
            0x056f27ff, // extq_z_zi_des
            0x05a037ff, // tbxq_z_zz_
            0x05a23421, // tbxq_z_zz_
            0x05a23423, // tbxq_z_zz_
            0x05e037ff, // tbxq_z_zz_
            0x05e23421, // tbxq_z_zz_
            0x05e23423, // tbxq_z_zz_
            0x4400e3ff, // zipq1_z_zz_
            0x4400e7ff, // zipq2_z_zz_
            0x4400ebff, // uzpq1_z_zz_
            0x4400efff, // uzpq2_z_zz_
            0x4400fbff, // tblq_z_zz_
            0x4402e021, // zipq1_z_zz_
            0x4402e023, // zipq1_z_zz_
            0x4402e421, // zipq2_z_zz_
            0x4402e423, // zipq2_z_zz_
            0x4402e821, // uzpq1_z_zz_
            0x4402e823, // uzpq1_z_zz_
            0x4402ec21, // uzpq2_z_zz_
            0x4402ec23, // uzpq2_z_zz_
            0x4402f821, // tblq_z_zz_
            0x4402f823, // tblq_z_zz_
            0x4440e3ff, // zipq1_z_zz_
            0x4440e7ff, // zipq2_z_zz_
            0x4440ebff, // uzpq1_z_zz_
            0x4440efff, // uzpq2_z_zz_
            0x4440fbff, // tblq_z_zz_
            0x4442e021, // zipq1_z_zz_
            0x4442e023, // zipq1_z_zz_
            0x4442e421, // zipq2_z_zz_
            0x4442e423, // zipq2_z_zz_
            0x4442e821, // uzpq1_z_zz_
            0x4442e823, // uzpq1_z_zz_
            0x4442ec21, // uzpq2_z_zz_
            0x4442ec23, // uzpq2_z_zz_
            0x4442f821, // tblq_z_zz_
            0x4442f823, // tblq_z_zz_
            0x4480e3ff, // zipq1_z_zz_
            0x4480e7ff, // zipq2_z_zz_
            0x4480ebff, // uzpq1_z_zz_
            0x4480efff, // uzpq2_z_zz_
            0x4480fbff, // tblq_z_zz_
            0x4482e021, // zipq1_z_zz_
            0x4482e023, // zipq1_z_zz_
            0x4482e421, // zipq2_z_zz_
            0x4482e423, // zipq2_z_zz_
            0x4482e821, // uzpq1_z_zz_
            0x4482e823, // uzpq1_z_zz_
            0x4482ec21, // uzpq2_z_zz_
            0x4482ec23, // uzpq2_z_zz_
            0x4482f821, // tblq_z_zz_
            0x4482f823, // tblq_z_zz_
            0x44c0e3ff, // zipq1_z_zz_
            0x44c0e7ff, // zipq2_z_zz_
            0x44c0ebff, // uzpq1_z_zz_
            0x44c0efff, // uzpq2_z_zz_
            0x44c0fbff, // tblq_z_zz_
            0x44c2e021, // zipq1_z_zz_
            0x44c2e023, // zipq1_z_zz_
            0x44c2e421, // zipq2_z_zz_
            0x44c2e423, // zipq2_z_zz_
            0x44c2e821, // uzpq1_z_zz_
            0x44c2e823, // uzpq1_z_zz_
            0x44c2ec21, // uzpq2_z_zz_
            0x44c2ec23, // uzpq2_z_zz_
            0x44c2f821, // tblq_z_zz_
            0x44c2f823, // tblq_z_zz_
        ];
        const REDUCTION_Q_CLASSES: [u32; 8] = [
            0x0405_2000,
            0x041e_2000,
            0x041d_2000,
            0x041c_2000,
            0x040c_2000,
            0x040e_2000,
            0x040d_2000,
            0x040f_2000,
        ];
        const SIZE_SHIFT: u32 = 22;
        const SOURCE_ONE_DESTINATION_ZERO: u32 = 0x20;
        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }
        fn features(q: bool) -> ScalableFeatures {
            let base = ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
            if q {
                base.with(ScalableFeature::Sme2p1)
            } else {
                base
            }
        }
        fn declared(bytes: usize, svcr: u64, q: bool) -> ScalableProfile {
            let length = VectorLength::from_bytes(bytes).unwrap();
            ScalableProfile::new_with_features(
                length,
                ScalableMode::from_svcr(svcr).unwrap(),
                features(q),
                ScalableControls::new(length, false),
            )
            .unwrap()
        }
        fn reduction_words() -> impl Iterator<Item = u32> {
            REDUCTION_Q_CLASSES.into_iter().flat_map(|class| {
                (0..4).map(move |size| class | size << SIZE_SHIFT | SOURCE_ONE_DESTINATION_ZERO)
            })
        }
        #[test]
        fn sme2p1_q_dispatch_has_exact_body_and_maps_for_all_declared_lengths_modes_targets() {
            assert_eq!(reduction_words().count(), 32);
            for word in PARENT_Q_WORDS.into_iter().chain(reduction_words()) {
                for bytes in [16, 32, 64, 128, 256] {
                    for svcr in [1, 3] {
                        for target in [
                            TargetCpu::Baseline,
                            TargetCpu::Ssse3,
                            TargetCpu::Sse41,
                            TargetCpu::Sse42,
                        ] {
                            let length = VectorLength::from_bytes(bytes).unwrap();
                            let native = compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0x1000),
                                declared(bytes, svcr, true),
                                target,
                            )
                            .unwrap();
                            let mut expected = Code::new();
                            if let Some(Ok(operand)) = reductions::decode(word) {
                                assert_eq!(operand.output, reductions::Output::Quadword);
                                x86_64::sve::reductions::emit(
                                    &mut expected,
                                    operand,
                                    length,
                                    target,
                                );
                            } else {
                                let operand = rearrange::decode(word).unwrap().unwrap();
                                assert!(matches!(
                                    operand,
                                    rearrange::Operand::Interleave { segment: true, .. }
                                        | rearrange::Operand::Extract { segment: true, .. }
                                        | rearrange::Operand::Table { segment: true, .. }
                                        | rearrange::Operand::DuplicateSegment { .. }
                                ));
                                x86_64::sve::rearrange::emit(
                                    &mut expected,
                                    operand,
                                    length,
                                    target,
                                );
                            }
                            assert_eq!(
                                &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                                context_wrapper()
                            );
                            assert_eq!(
                                native.source_map,
                                [
                                    (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES),
                                    (GuestAddress(0x1004), CONTEXT_WRAPPER_BYTES + 1),
                                    (
                                        GuestAddress(0x1008),
                                        CONTEXT_WRAPPER_BYTES + 1 + expected.len()
                                    ),
                                ]
                            );
                            assert_eq!(
                                &native.x86_64_code
                                    [CONTEXT_WRAPPER_BYTES + 1..native.source_map[2].1],
                                expected
                            );
                            assert_eq!(&native.x86_64_code[native.source_map[2].1..], [RET]);
                        }
                    }
                }
            }
        }
        #[test]
        fn sme2p1_q_requires_explicit_guest_feature_and_streaming_mode_independent_of_za() {
            for word in PARENT_Q_WORDS.into_iter().chain(reduction_words()) {
                for bytes in [16, 32, 64, 128, 256] {
                    let length = VectorLength::from_bytes(bytes).unwrap();
                    for svcr in [1, 3] {
                        for profile in [
                            ScalableProfile::new(length, ScalableMode::from_svcr(svcr).unwrap()),
                            declared(bytes, svcr, false),
                        ] {
                            let error = compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0x1000),
                                profile,
                                TargetCpu::Baseline,
                            )
                            .unwrap_err()
                            .0;
                            assert!(error.contains("unavailable guest features at 0x1004"));
                            assert!(error.contains("FEAT_SME2p1"));
                        }
                    }
                    for svcr in [0, 2] {
                        assert!(
                            compile_for_profile(
                                &source(&[NOP, word, RET_X30]),
                                GuestAddress(0x1000),
                                declared(bytes, svcr, true),
                                TargetCpu::Baseline
                            )
                            .unwrap_err()
                            .0
                            .contains("streaming mode required at 0x1004")
                        );
                    }
                }
                assert!(crate::compile(&source(&[word, RET_X30]), GuestAddress(0)).is_err());
                for prefix in [0x0420_bc20, 0x0410_2020] {
                    assert!(
                        compile_for_profile(
                            &source(&[prefix, word, RET_X30]),
                            GuestAddress(0),
                            declared(32, 3, true),
                            TargetCpu::Baseline
                        )
                        .unwrap_err()
                        .0
                        .contains("MOVPRFX pair validation")
                    );
                }
            }
        }

        #[test]
        fn sme2p1_q_table_dit_scope_follows_selected_recipe_and_other_q_forms_stay_unrestricted() {
            for word in PARENT_Q_WORDS {
                let operand = rearrange::decode(word).unwrap().unwrap();
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [
                        TargetCpu::Baseline,
                        TargetCpu::Ssse3,
                        TargetCpu::Sse41,
                        TargetCpu::Sse42,
                    ] {
                        let required = x86_64::sve::rearrange::requires_explicit_dit_zero(
                            operand,
                            VectorLength::from_bytes(bytes).unwrap(),
                            target,
                        );
                        let table =
                            matches!(operand, rearrange::Operand::Table { segment: true, .. });
                        if !table {
                            assert!(!required);
                        }
                        if let rearrange::Operand::Table { element_size, .. } = operand {
                            let byte = element_size == crate::aarch64::scalable::ElementSize::Byte;
                            assert_eq!(required, !(byte && target.supports(TargetCpu::Ssse3)));
                        }
                        for svcr in [1, 3] {
                            assert!(
                                compile_for_profile(
                                    &source(&[word, RET_X30]),
                                    GuestAddress(0),
                                    declared(bytes, svcr, true),
                                    target
                                )
                                .is_ok()
                            );
                        }
                    }
                }
            }
        }
    }
    mod sme_integer {
        //! SME integer dot and matrix registration and profile limits.
        use super::*;
        use crate::aarch64::scalable::profile::ScalableControls;
        use crate::aarch64::sme::{integer_dots, integer_matrix};
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const DOT_WORD: u32 = 0xc150_1000;
        const DOT_DOUBLEWORD: u32 = 0xc1d0_0008;
        const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
        const ALLOCATED_WORDS: [u32; 54] = [
            0xc150_1000, // sdot_za32_zzi_2xi
            0xc150_9000, // sdot_za32_zzi_4xi
            0xc160_1408, // sdot_za32_zzv_2x1
            0xc170_1408, // sdot_za32_zzv_4x1
            0xc1e0_1408, // sdot_za32_zzw_2x2
            0xc1e1_1408, // sdot_za32_zzw_4x4
            0xc150_1020, // sdot_za_zzi_s2xi
            0xc1d0_0008, // sdot_za_zzi_d2xi
            0xc150_9020, // sdot_za_zzi_s4xi
            0xc1d0_8008, // sdot_za_zzi_d4xi
            0xc120_1400, // sdot_za_zzv_2x1
            0xc130_1400, // sdot_za_zzv_4x1
            0xc1a0_1400, // sdot_za_zzw_2x2
            0xc1a1_1400, // sdot_za_zzw_4x4
            0xc150_1038, // sudot_za_zzi_s2xi
            0xc150_9038, // sudot_za_zzi_s4xi
            0xc120_1418, // sudot_za_zzv_s2x1
            0xc130_1418, // sudot_za_zzv_s4x1
            0xc150_8038, // suvdot_za_zzi_s4xi
            0xc150_0020, // svdot_za32_zzi_2xi
            0xc150_8020, // svdot_za_zzi_s4xi
            0xc1d0_8808, // svdot_za_zzi_d4xi
            0xc150_1010, // udot_za32_zzi_2xi
            0xc150_9010, // udot_za32_zzi_4xi
            0xc160_1418, // udot_za32_zzv_2x1
            0xc170_1418, // udot_za32_zzv_4x1
            0xc1e0_1418, // udot_za32_zzw_2x2
            0xc1e1_1418, // udot_za32_zzw_4x4
            0xc150_1030, // udot_za_zzi_s2xi
            0xc1d0_0018, // udot_za_zzi_d2xi
            0xc150_9030, // udot_za_zzi_s4xi
            0xc1d0_8018, // udot_za_zzi_d4xi
            0xc120_1410, // udot_za_zzv_2x1
            0xc130_1410, // udot_za_zzv_4x1
            0xc1a0_1410, // udot_za_zzw_2x2
            0xc1a1_1410, // udot_za_zzw_4x4
            0xc150_1028, // usdot_za_zzi_s2xi
            0xc150_9028, // usdot_za_zzi_s4xi
            0xc120_1408, // usdot_za_zzv_s2x1
            0xc130_1408, // usdot_za_zzv_s4x1
            0xc1a0_1408, // usdot_za_zzw_s2x2
            0xc1a1_1408, // usdot_za_zzw_s4x4
            0xc150_8028, // usvdot_za_zzi_s4xi
            0xc150_0030, // uvdot_za32_zzi_2xi
            0xc150_8030, // uvdot_za_zzi_s4xi
            0xc1d0_8818, // uvdot_za_zzi_d4xi
            0xc160_1400, // sdot_za_zzv_2x1 Doubleword
            0xc170_1400, // sdot_za_zzv_4x1 Doubleword
            0xc1e0_1400, // sdot_za_zzw_2x2 Doubleword
            0xc1e1_1400, // sdot_za_zzw_4x4 Doubleword
            0xc160_1410, // udot_za_zzv_2x1 Doubleword
            0xc170_1410, // udot_za_zzv_4x1 Doubleword
            0xc1e0_1410, // udot_za_zzw_2x2 Doubleword
            0xc1e1_1410, // udot_za_zzw_4x4 Doubleword
        ];

        fn dot_body(word: u32) -> Vec<u8> {
            [word, RET_X30]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect()
        }

        fn profile(
            bytes: usize,
            mode: ScalableMode,
            features: ScalableFeatures,
        ) -> ScalableProfile {
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                mode,
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), false),
            )
            .unwrap()
        }

        fn features() -> ScalableFeatures {
            ScalableFeatures::of(ScalableFeature::Sme)
                .with(ScalableFeature::Sme2)
                .with(ScalableFeature::SmeI16I64)
        }

        #[test]
        fn canonical_dots_emit_exact_bodies_and_maps() {
            for word in ALLOCATED_WORDS {
                let operand = integer_dots::decode(word).unwrap();
                assert_eq!(
                    crate::aarch64::sme::decode(word),
                    Some(Ok(crate::aarch64::sme::Operand::IntegerDots(operand))),
                );
                for bytes in [16, 32, 64, 128, 256] {
                    for target in [TargetCpu::Baseline, TargetCpu::Ssse3] {
                        let profile = profile(bytes, ScalableMode::new(true, true), features());
                        let native =
                            compile_for_profile(&dot_body(word), GUEST_BASE, profile, target)
                                .unwrap();
                        let mut expected = Code::new();
                        x86_64::sme::integer_dots::emit(
                            &mut expected,
                            &operand,
                            profile.vector_length(),
                            target,
                        );
                        assert_eq!(
                            native.source_map,
                            [
                                (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                                (
                                    GuestAddress(GUEST_BASE.0 + size_of::<u32>() as u64),
                                    CONTEXT_WRAPPER_BYTES + expected.len()
                                ),
                            ]
                        );
                        assert_eq!(
                            &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                            context_wrapper()
                        );
                        assert_eq!(
                            &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                            expected
                        );
                        assert_eq!(native.x86_64_code[native.source_map[1].1..], [RET]);
                    }
                }
                assert!(crate::compile(&dot_body(word), GUEST_BASE).is_err());
            }
        }

        #[test]
        fn dots_require_each_guest_feature_and_both_mode_bits() {
            let sme_only = ScalableFeatures::of(ScalableFeature::Sme);
            let sme2 = sme_only.with(ScalableFeature::Sme2);
            for bytes in [16, 32, 64, 128, 256] {
                for (word, available, required) in [
                    (DOT_WORD, sme_only, "FEAT_SME2"),
                    (DOT_DOUBLEWORD, sme2, "FEAT_SME_I16I64"),
                ] {
                    let error = compile_for_profile(
                        &dot_body(word),
                        GUEST_BASE,
                        profile(bytes, ScalableMode::new(true, true), available),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err();
                    assert!(
                        error.0.contains(required) && error.0.contains("0x1000"),
                        "{error}"
                    );
                }
                for (streaming, za, reason) in [
                    (false, false, "streaming mode required"),
                    (false, true, "streaming mode required"),
                    (true, false, "ZA enable required"),
                ] {
                    let error = compile_for_profile(
                        &dot_body(DOT_WORD),
                        GUEST_BASE,
                        profile(bytes, ScalableMode::new(streaming, za), features()),
                        TargetCpu::Baseline,
                    )
                    .unwrap_err();
                    assert!(
                        error.0.contains(reason) && error.0.contains("0x1000"),
                        "{error}"
                    );
                }
                let fixed = ScalableProfile::new(
                    VectorLength::from_bytes(bytes).unwrap(),
                    ScalableMode::new(true, true),
                );
                assert!(
                    compile_for_profile(
                        &dot_body(DOT_WORD),
                        GUEST_BASE,
                        fixed,
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
                assert!(
                    compile_for_profile(
                        &dot_body(DOT_DOUBLEWORD),
                        GUEST_BASE,
                        fixed,
                        TargetCpu::Baseline
                    )
                    .unwrap_err()
                    .0
                    .contains("FEAT_SME_I16I64")
                );
            }
        }

        #[test]
        fn integer_matrix_admission_checks_features_mode_and_source_maps() {
            const MATRIX_WORDS: [u32; 6] = [
                0xc1a0_1c10, // ADD ZA.S pair.
                0xc100_0000, // SMLALL ZA.S indexed byte products.
                0xc180_0000, // SMLALL ZA.D indexed halfword products.
                0xa080_0000, // SMOPA ZA.S byte outer products.
                0xa0c0_0000, // SMOPA ZA.D halfword outer products.
                0x8080_0008, // BMOPA ZA.S XNOR outer products.
            ];
            for word in MATRIX_WORDS {
                let operand = integer_matrix::decode(word).unwrap();
                let source = words(&[word, RET_X30]);
                assert!(crate::compile(&source, GuestAddress(0)).is_err());
                let legacy = ScalableProfile::new(
                    VectorLength::from_bytes(16).unwrap(),
                    ScalableMode::new(true, true),
                );
                let legacy_result =
                    compile_for_profile(&source, GuestAddress(0), legacy, TargetCpu::Baseline);
                assert_eq!(legacy_result.is_ok(), !operand.requires_i16i64());
                if operand.requires_i16i64() {
                    assert!(legacy_result.unwrap_err().0.contains("FEAT_SME_I16I64"));
                }
                for bytes in [16, 32, 64, 128, 256] {
                    let length = VectorLength::from_bytes(bytes).unwrap();
                    for sme2 in [false, true] {
                        for i16i64 in [false, true] {
                            let mut features = ScalableFeatures::of(ScalableFeature::Sme);
                            if sme2 {
                                features = features.with(ScalableFeature::Sme2);
                            }
                            if i16i64 {
                                features = features.with(ScalableFeature::SmeI16I64);
                            }
                            for streaming in [false, true] {
                                for za in [false, true] {
                                    let profile = ScalableProfile::new_with_features(
                                        length,
                                        ScalableMode::new(streaming, za),
                                        features,
                                        ScalableControls::new(length, false),
                                    )
                                    .unwrap();
                                    let result = compile_for_profile(
                                        &source,
                                        GuestAddress(0),
                                        profile,
                                        TargetCpu::Baseline,
                                    );
                                    let permitted = streaming
                                        && za
                                        && (!operand.requires_sme2() || sme2)
                                        && (!operand.requires_i16i64() || i16i64);
                                    assert_eq!(
                                        result.is_ok(),
                                        permitted,
                                        "word={word:#x} bytes={bytes} sme2={sme2} i16i64={i16i64} sm={streaming} za={za}"
                                    );
                                    if let Ok(native) = result {
                                        let mut body = Code::new();
                                        x86_64::sme::integer_matrix::emit(
                                            &mut body,
                                            &operand,
                                            length,
                                            TargetCpu::Baseline,
                                        );
                                        let map = &native.source_map;
                                        assert_eq!(map.len(), 2);
                                        assert_eq!(
                                            map[0],
                                            (GuestAddress(0), CONTEXT_WRAPPER_BYTES)
                                        );
                                        assert_eq!(
                                            map[1],
                                            (GuestAddress(4), CONTEXT_WRAPPER_BYTES + body.len())
                                        );
                                        assert_eq!(&native.x86_64_code[map[0].1..map[1].1], body);
                                        assert_eq!(&native.x86_64_code[map[1].1..], &[RET]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    mod sme_memory {
        //! SME memory dispatch, guest features and memory-service requirements.
        use super::*;
        use crate::aarch64::sme::memory::{self as sme_memory, Operand as SmeMemoryOperand};
        use alloc::vec;
        use alloc::vec::Vec;

        const RET_X30: u32 = 0xd65f_03c0;
        const NOP: u32 = 0xd503_201f;
        const GUEST_BASE: GuestAddress = GuestAddress(0x1000);
        const BASE_REGISTER_SHIFT: u32 = 5;
        const BASE_REGISTER_MASK: u32 = 31 << BASE_REGISTER_SHIFT;
        const WORDS: [u32; 78] = [
            0xa14000a0, // ld1b_mzx_p_bi_2x8
            0xa14080a0, // ld1b_mzx_p_bi_4x4
            0xa10000a0, // ld1b_mzx_p_br_2x8
            0xa10080a0, // ld1b_mzx_p_br_4x4
            0xe00000a0, // ld1b_za_p_rrr_
            0xa14060a0, // ld1d_mzx_p_bi_2x8
            0xa140e0a0, // ld1d_mzx_p_bi_4x4
            0xa10060a0, // ld1d_mzx_p_br_2x8
            0xa100e0a0, // ld1d_mzx_p_br_4x4
            0xe0c000a0, // ld1d_za_p_rrr_
            0xa14020a0, // ld1h_mzx_p_bi_2x8
            0xa140a0a0, // ld1h_mzx_p_bi_4x4
            0xa10020a0, // ld1h_mzx_p_br_2x8
            0xa100a0a0, // ld1h_mzx_p_br_4x4
            0xe04000a0, // ld1h_za_p_rrr_
            0xe1c000a0, // ld1q_za_p_rrr_
            0xa14040a0, // ld1w_mzx_p_bi_2x8
            0xa140c0a0, // ld1w_mzx_p_bi_4x4
            0xa10040a0, // ld1w_mzx_p_br_2x8
            0xa100c0a0, // ld1w_mzx_p_br_4x4
            0xe08000a0, // ld1w_za_p_rrr_
            0xa14000a8, // ldnt1b_mzx_p_bi_2x8
            0xa14080a8, // ldnt1b_mzx_p_bi_4x4
            0xa10000a8, // ldnt1b_mzx_p_br_2x8
            0xa10080a8, // ldnt1b_mzx_p_br_4x4
            0xa14060a8, // ldnt1d_mzx_p_bi_2x8
            0xa140e0a8, // ldnt1d_mzx_p_bi_4x4
            0xa10060a8, // ldnt1d_mzx_p_br_2x8
            0xa100e0a8, // ldnt1d_mzx_p_br_4x4
            0xa14020a8, // ldnt1h_mzx_p_bi_2x8
            0xa140a0a8, // ldnt1h_mzx_p_bi_4x4
            0xa10020a8, // ldnt1h_mzx_p_br_2x8
            0xa100a0a8, // ldnt1h_mzx_p_br_4x4
            0xa14040a8, // ldnt1w_mzx_p_bi_2x8
            0xa140c0a8, // ldnt1w_mzx_p_bi_4x4
            0xa10040a8, // ldnt1w_mzx_p_br_2x8
            0xa100c0a8, // ldnt1w_mzx_p_br_4x4
            0xe10000a0, // ldr_za_ri_
            0xe11f80a0, // ldr_zt_br_
            0xa16000a0, // st1b_mzx_p_bi_2x8
            0xa16080a0, // st1b_mzx_p_bi_4x4
            0xa12000a0, // st1b_mzx_p_br_2x8
            0xa12080a0, // st1b_mzx_p_br_4x4
            0xe02000a0, // st1b_za_p_rrr_
            0xa16060a0, // st1d_mzx_p_bi_2x8
            0xa160e0a0, // st1d_mzx_p_bi_4x4
            0xa12060a0, // st1d_mzx_p_br_2x8
            0xa120e0a0, // st1d_mzx_p_br_4x4
            0xe0e000a0, // st1d_za_p_rrr_
            0xa16020a0, // st1h_mzx_p_bi_2x8
            0xa160a0a0, // st1h_mzx_p_bi_4x4
            0xa12020a0, // st1h_mzx_p_br_2x8
            0xa120a0a0, // st1h_mzx_p_br_4x4
            0xe06000a0, // st1h_za_p_rrr_
            0xe1e000a0, // st1q_za_p_rrr_
            0xa16040a0, // st1w_mzx_p_bi_2x8
            0xa160c0a0, // st1w_mzx_p_bi_4x4
            0xa12040a0, // st1w_mzx_p_br_2x8
            0xa120c0a0, // st1w_mzx_p_br_4x4
            0xe0a000a0, // st1w_za_p_rrr_
            0xa16000a8, // stnt1b_mzx_p_bi_2x8
            0xa16080a8, // stnt1b_mzx_p_bi_4x4
            0xa12000a8, // stnt1b_mzx_p_br_2x8
            0xa12080a8, // stnt1b_mzx_p_br_4x4
            0xa16060a8, // stnt1d_mzx_p_bi_2x8
            0xa160e0a8, // stnt1d_mzx_p_bi_4x4
            0xa12060a8, // stnt1d_mzx_p_br_2x8
            0xa120e0a8, // stnt1d_mzx_p_br_4x4
            0xa16020a8, // stnt1h_mzx_p_bi_2x8
            0xa160a0a8, // stnt1h_mzx_p_bi_4x4
            0xa12020a8, // stnt1h_mzx_p_br_2x8
            0xa120a0a8, // stnt1h_mzx_p_br_4x4
            0xa16040a8, // stnt1w_mzx_p_bi_2x8
            0xa160c0a8, // stnt1w_mzx_p_bi_4x4
            0xa12040a8, // stnt1w_mzx_p_br_2x8
            0xa120c0a8, // stnt1w_mzx_p_br_4x4
            0xe12000a0, // str_za_ri_
            0xe13f80a0, // str_zt_br_
        ];

        fn source(words: &[u32]) -> Vec<u8> {
            words.iter().flat_map(|word| word.to_le_bytes()).collect()
        }

        fn declared_profile(streaming: bool, za: bool, sme2: bool, zt0: bool) -> ScalableProfile {
            let length = VectorLength::from_bytes(16).unwrap();
            let features = if sme2 {
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2)
            } else {
                ScalableFeatures::of(ScalableFeature::Sme)
            };
            ScalableProfile::new_with_features(
                length,
                ScalableMode::new(streaming, za),
                features,
                ScalableControls::new(length, zt0),
            )
            .unwrap()
        }

        fn target() -> TargetCpu {
            TargetCpu::AtomicLoad16.with_cx16()
        }

        fn assert_declined(word: u32, profile: ScalableProfile, target: TargetCpu) {
            let bytes = source(&[word, RET_X30]);
            let scan = memory_requirements(&bytes, GUEST_BASE, profile, target).unwrap_err();
            let compile = compile_for_profile(&bytes, GUEST_BASE, profile, target).unwrap_err();
            assert_eq!(scan.0, compile.0);
        }

        #[test]
        fn every_form_dispatches_exact_body_and_source_map() {
            for word in WORDS {
                let operand = sme_memory::decode(word).unwrap();
                assert_eq!(
                    crate::aarch64::sme::decode(word),
                    Some(Ok(crate::aarch64::sme::Operand::Memory(operand)))
                );
                let profile = declared_profile(true, true, true, true);
                let bytes = source(&[word, RET_X30]);
                let native = compile_for_profile(&bytes, GUEST_BASE, profile, target()).unwrap();
                let mut expected = Code::new();
                x86_64::sme::memory::emit(
                    &mut expected,
                    &operand,
                    profile.vector_length(),
                    target(),
                    GUEST_BASE.0,
                )
                .unwrap();
                assert_eq!(
                    &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
                    context_wrapper()
                );
                assert_eq!(
                    native.source_map,
                    [
                        (GUEST_BASE, CONTEXT_WRAPPER_BYTES),
                        (
                            GuestAddress(GUEST_BASE.0 + INSTRUCTION_BYTES as u64),
                            CONTEXT_WRAPPER_BYTES + expected.len()
                        )
                    ]
                );
                assert_eq!(
                    &native.x86_64_code[CONTEXT_WRAPPER_BYTES..native.source_map[1].1],
                    expected
                );
                assert_eq!(&native.x86_64_code[native.source_map[1].1..], [RET]);
                assert_eq!(
                    memory_requirements(&bytes, GUEST_BASE, profile, target()).unwrap(),
                    x86_64::sme::memory::requirements(&operand)
                );
            }
        }

        #[test]
        fn mode_feature_and_ezt0_checks_follow_each_memory_class() {
            for word in WORDS {
                match sme_memory::decode(word).unwrap() {
                    SmeMemoryOperand::Vectors(_) => {
                        assert_declined(
                            word,
                            declared_profile(false, false, true, false),
                            target(),
                        );
                        assert_declined(word, declared_profile(true, true, false, false), target());
                        assert!(
                            compile_for_profile(
                                &source(&[word, RET_X30]),
                                GUEST_BASE,
                                declared_profile(true, false, true, false),
                                target()
                            )
                            .is_ok()
                        );
                    }
                    SmeMemoryOperand::Tile(_) => {
                        assert_declined(word, declared_profile(false, true, true, false), target());
                        assert_declined(word, declared_profile(true, false, true, false), target());
                        assert!(
                            compile_for_profile(
                                &source(&[word, RET_X30]),
                                GUEST_BASE,
                                declared_profile(true, true, false, false),
                                target()
                            )
                            .is_ok()
                        );
                    }
                    SmeMemoryOperand::ZaVector(_) => {
                        assert_declined(word, declared_profile(true, false, true, false), target());
                        assert!(
                            compile_for_profile(
                                &source(&[word, RET_X30]),
                                GUEST_BASE,
                                declared_profile(false, true, false, false),
                                target()
                            )
                            .is_ok()
                        );
                    }
                    SmeMemoryOperand::Zt(_) => {
                        assert_declined(word, declared_profile(true, false, true, true), target());
                        assert_declined(word, declared_profile(true, true, false, false), target());
                        assert_declined(word, declared_profile(true, true, true, false), target());
                        assert!(
                            compile_for_profile(
                                &source(&[word, RET_X30]),
                                GUEST_BASE,
                                declared_profile(false, true, true, true),
                                target()
                            )
                            .is_ok()
                        );
                    }
                }
            }
        }

        #[test]
        fn independent_host_capabilities_decline_before_scan_or_emission() {
            let profile = declared_profile(true, true, true, true);
            for word in WORDS {
                let operand = sme_memory::decode(word).unwrap();
                for target in [
                    TargetCpu::Baseline,
                    TargetCpu::AtomicLoad16,
                    TargetCpu::Cx16,
                ] {
                    if x86_64::sme::memory::validate_target(&operand, target).is_err() {
                        assert_declined(word, profile, target);
                    }
                }
            }
        }

        #[test]
        fn existing_v1_contract_admits_its_features_and_declines_disabled_zt0() {
            let profile = ScalableProfile::new(
                VectorLength::from_bytes(16).unwrap(),
                ScalableMode::new(true, true),
            );
            assert_eq!(profile.id(), PROFILE_ID);
            assert_eq!(profile.declared_features(), None);
            assert_eq!(profile.required_dit(), None);
            assert!(!profile.controls().zt0_enabled());
            for word in WORDS {
                if matches!(sme_memory::decode(word), Some(SmeMemoryOperand::Zt(_))) {
                    assert_declined(word, profile, target());
                } else {
                    assert!(
                        compile_for_profile(
                            &source(&[word, RET_X30]),
                            GUEST_BASE,
                            profile,
                            target()
                        )
                        .is_ok()
                    );
                }
            }
            assert!(
                compile_for_profile(
                    &source(&[NOP, RET_X30]),
                    GUEST_BASE,
                    profile,
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }

        #[test]
        fn complete_body_requirements_fold_every_memory_instruction() {
            let profile = declared_profile(true, true, true, true);
            let mut words = vec![NOP];
            let mut expected = MemoryRequirements::default();
            for word in WORDS {
                let sp_word = (word & !BASE_REGISTER_MASK) | BASE_REGISTER_MASK;
                words.push(sp_word);
                let operand = sme_memory::decode(sp_word).unwrap();
                expected = expected
                    .merge(x86_64::sme::memory::requirements(&operand))
                    .unwrap();
            }
            words.push(RET_X30);
            assert_eq!(
                memory_requirements(&source(&words), GUEST_BASE, profile, target()).unwrap(),
                expected
            );
            assert!(compile_for_profile(&source(&words), GUEST_BASE, profile, target()).is_ok());
        }

        // Append to scalable_context/sme_memory_tests.rs; reuse its source/profile/target helpers.

        #[test]
        fn prepared_memory_metadata_retains_per_pc_features_helpers_and_quantities() {
            use crate::aarch64::scalable::execution::{
                GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements,
            };

            const MULTI_Z_LOAD_BYTE: u32 = 0xa140_00a0;
            const TILE_LOAD_QUADWORD: u32 = 0xe1c0_00a0;
            const WHOLE_ZA_LOAD: u32 = 0xe100_00a0;
            const ZT_LOAD: u32 = 0xe11f_80a0;
            let words = [
                NOP,
                MULTI_Z_LOAD_BYTE,
                TILE_LOAD_QUADWORD,
                WHOLE_ZA_LOAD,
                ZT_LOAD,
                RET_X30,
            ];
            let prepared = prepare_leaf(
                &source(&words),
                GUEST_BASE,
                declared_profile(true, true, true, true),
                target(),
            )
            .unwrap();
            let instructions = prepared.execution_requirements.instructions();
            assert_eq!(instructions.len(), words.len());
            let sme = ScalableFeatures::of(ScalableFeature::Sme);
            let sme2 = sme.with(ScalableFeature::Sme2);
            let expected = [
                (None, vec![], GuestMemoryQuantity::None),
                (
                    Some(sme2),
                    vec![ScalableAccessCheck::StreamingSveEnabled],
                    GuestMemoryQuantity::Maximum(ElementSize::Byte),
                ),
                (
                    Some(sme),
                    vec![ScalableAccessCheck::StreamingSveAndZaEnabled],
                    GuestMemoryQuantity::Maximum(ElementSize::Quadword),
                ),
                (
                    Some(sme),
                    vec![ScalableAccessCheck::SmeAndZaEnabled],
                    GuestMemoryQuantity::Maximum(ElementSize::Byte),
                ),
                (
                    Some(sme2),
                    vec![
                        ScalableAccessCheck::SmeEnabled,
                        ScalableAccessCheck::SmeZt0Enabled,
                    ],
                    GuestMemoryQuantity::Maximum(ElementSize::Byte),
                ),
                (None, vec![], GuestMemoryQuantity::None),
            ];
            for (index, (instruction, (features, helpers, quantity))) in
                instructions.iter().zip(expected).enumerate()
            {
                let pc = GuestAddress(GUEST_BASE.0 + (index * size_of::<u32>()) as u64);
                assert_eq!(instruction.pc(), pc);
                assert_eq!(prepared.native.source_map[index].0, pc);
                let clauses: Vec<_> = features.into_iter().map(FeatureRequirement::all).collect();
                assert_eq!(instruction.feature_clauses(), clauses);
                assert_eq!(
                    instruction.access(),
                    &ScalableAccessRequirements::Known(helpers.into_boxed_slice())
                );
                assert_eq!(instruction.guest_memory_quantity(), quantity);
            }
        }

        #[test]
        fn prepared_sm0_whole_banks_keep_sme_helpers_and_byte_quantities() {
            use crate::aarch64::scalable::execution::{
                GuestMemoryQuantity, ScalableAccessCheck, ScalableAccessRequirements,
            };

            const MEMORY_INSTRUCTIONS: usize = 2;
            const WHOLE_ZA_LOAD: u32 = 0xe100_00a0;
            const WHOLE_ZA_STORE: u32 = 0xe120_00a0;
            const ZT_LOAD: u32 = 0xe11f_80a0;
            const ZT_STORE: u32 = 0xe13f_80a0;
            for (words, sme2, checks) in [
                (
                    [WHOLE_ZA_LOAD, WHOLE_ZA_STORE, RET_X30],
                    false,
                    vec![ScalableAccessCheck::SmeAndZaEnabled],
                ),
                (
                    [ZT_LOAD, ZT_STORE, RET_X30],
                    true,
                    vec![
                        ScalableAccessCheck::SmeEnabled,
                        ScalableAccessCheck::SmeZt0Enabled,
                    ],
                ),
            ] {
                let prepared = prepare_leaf(
                    &source(&words),
                    GUEST_BASE,
                    declared_profile(false, true, sme2, sme2),
                    target(),
                )
                .unwrap();
                for instruction in
                    &prepared.execution_requirements.instructions()[..MEMORY_INSTRUCTIONS]
                {
                    assert_eq!(
                        instruction.access(),
                        &ScalableAccessRequirements::Known(checks.clone().into_boxed_slice())
                    );
                    assert_eq!(
                        instruction.guest_memory_quantity(),
                        GuestMemoryQuantity::Maximum(ElementSize::Byte)
                    );
                }
            }
        }
    }
    mod tables {
        use super::*;
        use crate::aarch64::sme::tables;

        fn table_profile(
            bytes: usize,
            mode: ScalableMode,
            features: ScalableFeatures,
            zt0_enabled: bool,
        ) -> ScalableProfile {
            ScalableProfile::new_with_features(
                VectorLength::from_bytes(bytes).unwrap(),
                mode,
                features,
                ScalableControls::new(VectorLength::from_bytes(256).unwrap(), zt0_enabled),
            )
            .unwrap()
        }

        fn table_features() -> ScalableFeatures {
            ScalableFeatures::of(ScalableFeature::Sme)
                .with(ScalableFeature::Sme2)
                .with(ScalableFeature::Sme2p1)
        }

        #[test]
        fn fixed_table_routes_retain_compatible_legacy_profiles() {
            let legacy = ScalableProfile::new(
                VectorLength::from_bytes(64).unwrap(),
                ScalableMode::new(true, false),
            );
            for word in [TABLE_SELECT, TABLE_ZIP_PAIR_Q, TABLE_ZIP_QUAD_Q, 0xc165e000] {
                assert!(
                    compile_for_profile(
                        &words(&[word, RET_X30]),
                        GuestAddress(0x1000),
                        legacy,
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
            }
        }

        #[test]
        fn scalar_lookup_policy_tracks_the_selected_recipe() {
            use crate::aarch64::scalable::ElementSize;
            let mut operand = tables::decode(TABLE_LOOKUP).unwrap();
            let short = VectorLength::from_bytes(16).unwrap();
            let long = VectorLength::from_bytes(64).unwrap();
            operand.element = ElementSize::Word;
            assert!(x86_64::sme::tables::requires_dit_zero(
                &operand,
                short,
                TargetCpu::Baseline
            ));
            assert!(x86_64::sme::tables::requires_dit_zero(
                &operand,
                short,
                TargetCpu::Ssse3
            ));
            assert!(!x86_64::sme::tables::requires_dit_zero(
                &operand,
                long,
                TargetCpu::Ssse3
            ));
            operand.element = ElementSize::Halfword;
            assert!(x86_64::sme::tables::requires_dit_zero(
                &operand,
                short,
                TargetCpu::Baseline
            ));
            assert!(!x86_64::sme::tables::requires_dit_zero(
                &operand,
                long,
                TargetCpu::Baseline
            ));
            assert!(!x86_64::sme::tables::requires_dit_zero(
                &operand,
                short,
                TargetCpu::Ssse3
            ));
            operand.element = ElementSize::Byte;
            assert!(!x86_64::sme::tables::requires_dit_zero(
                &operand,
                short,
                TargetCpu::Baseline
            ));
            let legacy = ScalableProfile::new(short, ScalableMode::new(true, true));
            let scalar_word = TABLE_LOOKUP | (2 << 12);
            let error = compile_for_profile(
                &words(&[scalar_word, RET_X30]),
                GuestAddress(0x1000),
                legacy,
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.0.contains("scalar SME lookup"));
        }

        #[test]
        fn table_lookup_requires_za_and_enabled_zt0() {
            for (za_enabled, zt0_enabled) in [(false, false), (false, true), (true, false)] {
                let profile = table_profile(
                    16,
                    ScalableMode::new(true, za_enabled),
                    table_features(),
                    zt0_enabled,
                );
                let error = compile_for_profile(
                    &words(&[TABLE_LOOKUP, RET_X30]),
                    GuestAddress(0x1000),
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap_err();
                assert!(error.0.contains("ZA and enabled ZT0"));
            }
            let profile = table_profile(16, ScalableMode::new(true, true), table_features(), true);
            assert!(
                compile_for_profile(
                    &words(&[TABLE_LOOKUP, RET_X30]),
                    GuestAddress(0x1000),
                    profile,
                    TargetCpu::Baseline
                )
                .is_ok()
            );
        }

        #[test]
        fn table_strided_lookups_require_sme2p1() {
            let feature_base =
                ScalableFeatures::of(ScalableFeature::Sme).with(ScalableFeature::Sme2);
            let base = table_profile(16, ScalableMode::new(true, true), feature_base, true);
            let complete = table_profile(16, ScalableMode::new(true, true), table_features(), true);
            for word in [0xc09c4000, 0xc09c8000, 0xc09a4000, 0xc09a9000] {
                let input = words(&[word, RET_X30]);
                let error =
                    compile_for_profile(&input, GuestAddress(0x1000), base, TargetCpu::Baseline)
                        .unwrap_err();
                assert!(error.0.contains("FEAT_SME2p1"));
                assert!(
                    compile_for_profile(
                        &input,
                        GuestAddress(0x1000),
                        complete,
                        TargetCpu::Baseline
                    )
                    .is_ok()
                );
            }
        }

        #[test]
        fn table_permutations_validate_current_length_despite_larger_maximum() {
            for (word, too_short, minimum) in
                [(TABLE_ZIP_PAIR_Q, 16, 32), (TABLE_ZIP_QUAD_Q, 32, 64)]
            {
                let input = words(&[word, RET_X30]);
                let short = table_profile(
                    too_short,
                    ScalableMode::new(true, false),
                    table_features(),
                    false,
                );
                let error =
                    compile_for_profile(&input, GuestAddress(0x1000), short, TargetCpu::Baseline)
                        .unwrap_err();
                assert!(error.0.contains("require SVL"));
                let valid = table_profile(
                    minimum,
                    ScalableMode::new(true, false),
                    table_features(),
                    false,
                );
                assert!(
                    compile_for_profile(&input, GuestAddress(0x1000), valid, TargetCpu::Baseline)
                        .is_ok()
                );
            }
        }

        #[test]
        fn every_table_family_routes_through_the_shared_context_entry() {
            let profile = table_profile(64, ScalableMode::new(true, true), table_features(), true);
            for word in [
                0xc08c4000, 0xc09c4000, 0xc08c8000, 0xc09c8000, 0xc0cc0000, 0xc08a4000, 0xc09a4000,
                0xc08a9000, 0xc09a9000, 0xc0ca0000, 0xc1208000, 0xc1218000, 0xc165e000, 0xc175e000,
                0xc165e001, 0xc175e001, 0xc136e002, 0xc137e002, 0xc120d001, 0xc120d401, 0xc136e000,
                0xc137e000, 0xc120d000, 0xc120d400,
            ] {
                let result = compile_for_profile(
                    &words(&[word, RET_X30]),
                    GuestAddress(0x1000),
                    profile,
                    TargetCpu::Baseline,
                )
                .unwrap();
                assert_eq!(result.source_map.len(), 2);
                assert_eq!(
                    result.source_map[0],
                    (GuestAddress(0x1000), CONTEXT_WRAPPER_BYTES)
                );
                assert_eq!(result.source_map[1].0, GuestAddress(0x1004));
                assert!(result.source_map[1].1 > result.source_map[0].1);
            }
        }

        #[test]
        fn table_admission_requires_sme2_and_streaming() {
            let sme_only = table_profile(
                16,
                ScalableMode::new(true, false),
                ScalableFeatures::of(ScalableFeature::Sme),
                false,
            );
            let error = compile_for_profile(
                &words(&[TABLE_SELECT, RET_X30]),
                GuestAddress(0x1000),
                sme_only,
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.0.contains("FEAT_SME2"));
            let non_streaming =
                table_profile(16, ScalableMode::new(false, false), table_features(), false);
            let error = compile_for_profile(
                &words(&[TABLE_SELECT, RET_X30]),
                GuestAddress(0x1000),
                non_streaming,
                TargetCpu::Baseline,
            )
            .unwrap_err();
            assert!(error.0.contains("streaming mode required"));
        }
    }

    const RET_X30: u32 = 0xd65f_03c0;
    const NOP: u32 = 0xd503_201f;
    const AND_Z0_Z1_Z2: u32 = 0x0422_3020;
    const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
    const RDSVL_X0_ONE: u32 = 0x04bf_5820;

    fn profile(bytes: usize, streaming: bool) -> ScalableProfile {
        ScalableProfile::new(
            VectorLength::from_bytes(bytes).unwrap(),
            ScalableMode::new(streaming, false),
        )
    }

    fn words(input: &[u32]) -> Vec<u8> {
        input.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    const TABLE_LOOKUP: u32 = 0xc0cc0000;
    const TABLE_SELECT: u32 = 0xc1208000;
    const TABLE_ZIP_PAIR_Q: u32 = 0xc120d400;
    const TABLE_ZIP_QUAD_Q: u32 = 0xc137e000;
}
