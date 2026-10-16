use super::*;
use alloc::vec::Vec;

const DESTINATION: u8 = 0;
const CLAMP_LEFT: u8 = 1;
const RIGHT_SOURCE: u8 = 2;
const PREDICATE: u8 = 0;
const PC: GuestAddress = GuestAddress(0x1234_5678_9abc_def0);
const QUALIFIED_LENGTHS: [usize; 2] = [16, 64];
const UNMEASURED_LENGTHS: [usize; 3] = [32, 128, 256];
const ALL_LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
const FEATURES: NumericalFeatures = NumericalFeatures::new(false, true, true);

fn operands() -> impl Iterator<Item = Operand> {
    [
        Kind::Clamp,
        Kind::Binary(BinaryOperation::Maximum),
        Kind::Binary(BinaryOperation::MaximumNumber),
        Kind::Binary(BinaryOperation::Minimum),
        Kind::Binary(BinaryOperation::MinimumNumber),
    ]
    .into_iter()
    .map(|kind| Operand {
        kind,
        destination: DESTINATION,
        left: if kind == Kind::Clamp {
            CLAMP_LEFT
        } else {
            DESTINATION
        },
        right: RightOperand::Vector(RIGHT_SOURCE),
        predicate: (kind != Kind::Clamp).then_some(PREDICATE),
    })
}

fn assert_routing(
    operand: Operand,
    bytes: usize,
    target: TargetCpu,
    recipe: Recipe,
    changes_default: bool,
) {
    let length = VectorLength::from_bytes(bytes).unwrap();
    let mut selected = Vec::new();
    assert!(emit(&mut selected, operand, length, FEATURES, PC, target).unwrap());
    let mut expected = Vec::new();
    assert!(
        emit_with_recipe(&mut expected, operand, length, FEATURES, PC, target, recipe,).unwrap()
    );
    assert_eq!(selected, expected, "{operand:?}, {bytes}, {target:?}");
    if changes_default {
        let mut baseline = Vec::new();
        assert!(
            emit_with_recipe(
                &mut baseline,
                operand,
                length,
                FEATURES,
                PC,
                target,
                Recipe::CompareSelect,
            )
            .unwrap()
        );
        assert_ne!(selected, baseline);
    }
}

#[test]
fn measured_selection_uses_sse41_without_fma_or_f16c() {
    for target in [TargetCpu::Sse41, TargetCpu::Sse42] {
        for bytes in QUALIFIED_LENGTHS {
            for operand in operands() {
                assert_routing(operand, bytes, target, Recipe::CheckedBlend, true);
            }
        }
    }
}

#[test]
fn unmeasured_lengths_keep_compare_select() {
    let target = TargetCpu::Sse41.with_f16c().with_fma();
    for bytes in UNMEASURED_LENGTHS {
        for operand in operands() {
            assert_routing(operand, bytes, target, Recipe::CompareSelect, false);
        }
    }
}

#[test]
fn independent_optional_features_do_not_substitute_for_sse41() {
    for target in [
        TargetCpu::Baseline,
        TargetCpu::Ssse3,
        TargetCpu::Baseline.with_f16c().with_fma(),
    ] {
        for bytes in ALL_LENGTHS {
            for operand in operands() {
                assert_routing(operand, bytes, target, Recipe::CompareSelect, false);
            }
        }
    }
}

#[test]
fn explicit_blend_declines_missing_capability_before_emission() {
    for operand in operands() {
        let mut code = Vec::new();
        assert!(
            !emit_with_recipe(
                &mut code,
                operand,
                VectorLength::from_bytes(QUALIFIED_LENGTHS[0]).unwrap(),
                FEATURES,
                PC,
                TargetCpu::Baseline,
                Recipe::CheckedBlend,
            )
            .unwrap()
        );
        assert!(code.is_empty());
    }
}
