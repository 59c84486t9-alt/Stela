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
            let native = compile_for_profile(&source, BASE, profile, TargetCpu::Baseline).unwrap();
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
    use crate::aarch64::scalable::execution::{GuestMemoryQuantity, ScalableAccessRequirements};
    let profile = ScalableProfile::new(
        VectorLength::from_bytes(16).unwrap(),
        ScalableMode::new(true, false),
    );
    let source: Vec<_> = [UNPREDICATED_PREFIX, AND_DESTRUCTIVE, RET]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    let prepared = prepare_leaf(&source, BASE, profile, TargetCpu::Baseline).unwrap();
    let ordinary = compile_for_profile(&source, BASE, profile, TargetCpu::Baseline).unwrap();
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
