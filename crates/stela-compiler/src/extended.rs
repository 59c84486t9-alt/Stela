//! Context-backed leaf compilation with immutable scalable specialization.
//!
//! The profile admits streaming integer logic/arithmetic, SME length arithmetic and
//! floating sign operations and existing pure GPR/control mappings. Other effects remain explicit declines.

use std::collections::BTreeMap;

use crate::{
    CompileError, GuestAddress, Lifter, NativeBlock, TargetCpu,
    aarch64::{
        Decoder, Instruction, Operation,
        scalable::{ScalableMode, VectorLength},
        sme::length,
        sve::{
            integer_arithmetic,
            integer_logic::{self, CopySource, Kind},
            sign,
        },
    },
    context::{ExecutionContext, ScalableStateView},
    x86_64,
};

pub const PROFILE_ID: &str = "apple-sme2-streaming-v1";
const INSTRUCTION_BYTES: usize = size_of::<u32>();
const PUSH_R15: &[u8] = &[0x41, 0x57];
const MOV_R15_RSI: &[u8] = &[0x49, 0x89, 0xf7];
const CALL_REL32: u8 = 0xe8;
const POP_R15: &[u8] = &[0x41, 0x5f];
const RET: u8 = 0xc3;
const CALL_BYTES: usize = 1 + size_of::<i32>();
const CALL_END: usize = PUSH_R15.len() + MOV_R15_RSI.len() + CALL_BYTES;
pub const CONTEXT_WRAPPER_BYTES: usize = CALL_END + POP_R15.len() + 1;

/// A declared SME2 integer execution profile, not an Apple hardware capture.
/// Host capability selection remains a separate TargetCpu value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScalableProfile {
    length: VectorLength,
    mode: ScalableMode,
}

impl ScalableProfile {
    pub const fn new(length: VectorLength, mode: ScalableMode) -> Self {
        Self { length, mode }
    }

    pub const fn id(self) -> &'static str {
        PROFILE_ID
    }

    pub const fn vector_length(self) -> VectorLength {
        self.length
    }

    pub const fn mode(self) -> ScalableMode {
        self.mode
    }

    /// Validate borrowed metadata before native entry. Ownership, bounds and
    /// guest-RAM separation remain requirements of the unsafe execution caller.
    pub fn validate_view(
        self,
        context: &ExecutionContext,
        view: &ScalableStateView,
    ) -> Result<(), CompileError> {
        let valid = context.has_supported_header()
            && std::ptr::eq(context.scalable.cast_const(), view)
            && usize::from(view.svl_bytes) == self.length.bytes()
            && view.reserved == [0; 6]
            && view.svcr == self.mode.svcr()
            && (!self.mode.streaming()
                || ((!view.z_upper.is_null() || self.length.chunks() == 1)
                    && !view.predicates.is_null()
                    && !view.ffr.is_null()))
            && (!self.mode.za_enabled() || (!view.za.is_null() && !view.zt0.is_null()));
        if valid {
            Ok(())
        } else {
            Err(CompileError(
                "extended execution context/profile mismatch".into(),
            ))
        }
    }
}

enum Decoded {
    Ordinary(Instruction),
    IntegerLogic(integer_logic::Operand),
    Sign(sign::Operand),
    IntegerArithmetic(integer_arithmetic::Operand),
    Length(length::Operand),
}

fn ordinary_permitted(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Bitfield(_)
            | Operation::PcRelative(_)
            | Operation::ConditionalSelect(_)
            | Operation::ConditionalCompare(_)
            | Operation::Crc(_)
            | Operation::Flags(_)
            | Operation::IntegerMath(_)
            | Operation::IntegerMinMax(_)
            | Operation::IntegerUnary(_)
            | Operation::AddSubRegister { .. }
            | Operation::AddSubCarry { .. }
            | Operation::AddSubExtended { .. }
            | Operation::LogicalRegister { .. }
            | Operation::LogicalImmediate { .. }
            | Operation::Branch { .. }
            | Operation::BranchCondition { .. }
            | Operation::BranchZero { .. }
            | Operation::BranchBit { .. }
            | Operation::MoveWide { .. }
            | Operation::AddSub { .. }
            | Operation::Nop
            | Operation::Return
    )
}

fn decode(
    pc: GuestAddress,
    word: u32,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<Decoded, CompileError> {
    if let Some(decoded) = integer_logic::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        if matches!(operand.kind, Kind::Copy(CopySource::Vector(_))) {
            return Err(CompileError(format!(
                "MOVPRFX pair validation required at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::IntegerLogic(operand));
    }
    if let Some(decoded) = integer_arithmetic::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!(
                "reserved streaming integer arithmetic encoding at {:#x}",
                pc.0
            ))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::IntegerArithmetic(operand));
    }
    if let Some(decoded) = sign::decode(word) {
        let operand = decoded.map_err(|()| {
            CompileError(format!("reserved streaming sign encoding at {:#x}", pc.0))
        })?;
        if !profile.mode.streaming() {
            return Err(CompileError(format!(
                "streaming mode required at {:#x}",
                pc.0
            )));
        }
        return Ok(Decoded::Sign(operand));
    }
    if let Some(operand) = length::decode(word) {
        return Ok(Decoded::Length(operand));
    }
    let instruction = Decoder
        .lift(pc, word)
        .map_err(|reason| CompileError(format!("unsupported ARM64 semantics: {reason:?}")))?;
    if !ordinary_permitted(&instruction.operation) {
        return Err(CompileError(format!(
            "operation outside extended integer profile at {:#x}: {:#010x}",
            pc.0, word
        )));
    }
    x86_64::validate_target(&instruction, target)
        .map_err(|reason| CompileError(format!("x86 emission failed: {reason:?}")))?;
    Ok(Decoded::Ordinary(instruction))
}

fn context_wrapper() -> Vec<u8> {
    let mut code = Vec::with_capacity(CONTEXT_WRAPPER_BYTES);
    code.extend(PUSH_R15);
    code.extend(MOV_R15_RSI);
    code.push(CALL_REL32);
    code.extend(((CONTEXT_WRAPPER_BYTES - CALL_END) as i32).to_le_bytes());
    code.extend(POP_R15);
    code.push(RET);
    code
}

/// Compile an extended two-argument leaf ending in RET X30. The runtime must
/// validate this exact profile against its owned view before unsafe invocation.
pub fn compile_for_profile(
    source: &[u8],
    base: GuestAddress,
    profile: ScalableProfile,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    if source.is_empty()
        || !source.len().is_multiple_of(INSTRUCTION_BYTES)
        || !base.0.is_multiple_of(INSTRUCTION_BYTES as u64)
    {
        return Err(CompileError(
            "input and guest base must be nonempty/aligned to 4 bytes".into(),
        ));
    }
    let instructions: Vec<_> = source
        .as_chunks::<INSTRUCTION_BYTES>()
        .0
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let pc = base
                .0
                .checked_add((index as u64) * INSTRUCTION_BYTES as u64)
                .map(GuestAddress)
                .ok_or_else(|| CompileError("guest address overflow".into()))?;
            Ok((pc, decode(pc, u32::from_le_bytes(*bytes), profile, target)?))
        })
        .collect::<Result<_, CompileError>>()?;
    if !matches!(
        instructions.last(),
        Some((
            _,
            Decoded::Ordinary(Instruction {
                operation: Operation::Return,
                ..
            })
        ))
    ) {
        return Err(CompileError("leaf region must end in RET X30".into()));
    }
    let mut code = context_wrapper();
    let mut source_map = Vec::with_capacity(instructions.len());
    let mut fixups = Vec::new();
    for (pc, instruction) in instructions {
        source_map.push((pc, code.len()));
        match instruction {
            Decoded::Ordinary(instruction) => {
                x86_64::emit_instruction(&mut code, &instruction, &mut fixups, target);
            }
            Decoded::IntegerLogic(operand) => {
                x86_64::sve::integer_logic::emit(&mut code, operand, profile.length, target);
            }
            Decoded::IntegerArithmetic(operand) => {
                x86_64::sve::integer_arithmetic::emit(&mut code, operand, profile.length, target);
            }
            Decoded::Sign(operand) => {
                x86_64::sve::sign::emit(&mut code, &operand, profile.length, target);
            }
            Decoded::Length(operand) => {
                x86_64::sme::length::emit(&mut code, &operand, profile.length);
            }
        }
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
mod tests {
    use super::*;

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
                        let mut expected = Vec::new();
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
}
