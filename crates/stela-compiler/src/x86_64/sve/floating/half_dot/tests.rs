use super::*;
use alloc::vec::Vec;

const DESTINATION: u8 = 0;
const LEFT_SOURCE: u8 = 1;
const RIGHT_SOURCE: u8 = 2;
const INDEXED_ELEMENT: u8 = 1;
const PC: GuestAddress = GuestAddress(0x1234_5678_9abc_def0);
const QUALIFIED_LENGTHS: [usize; 2] = [16, 64];
const UNMEASURED_LENGTHS: [usize; 3] = [32, 128, 256];
const ALL_LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
const FEATURES: NumericalFeatures = NumericalFeatures::new(false, true, true);

fn operand(kind: Kind, indexed: bool) -> Operand {
    Operand {
        kind,
        element_size: ElementSize::Word,
        destination: DESTINATION,
        left: LEFT_SOURCE,
        right: if indexed {
            RightOperand::Indexed {
                register: RIGHT_SOURCE,
                index: INDEXED_ELEMENT,
            }
        } else {
            RightOperand::Vector(RIGHT_SOURCE)
        },
    }
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
    assert!(emit_candidate(&mut expected, operand, length, FEATURES, PC, target, recipe,).unwrap());
    assert_eq!(selected, expected, "{operand:?}, {bytes}, {target:?}");
    if changes_default {
        let mut baseline = Vec::new();
        assert!(
            emit_candidate(
                &mut baseline,
                operand,
                length,
                FEATURES,
                PC,
                target,
                Recipe::default(),
            )
            .unwrap()
        );
        assert_ne!(selected, baseline, "selection must change emitted bytes");
    }
}

fn long_operands() -> impl Iterator<Item = Operand> {
    [false, true].into_iter().flat_map(|subtract| {
        [VectorPart::Bottom, VectorPart::Top]
            .into_iter()
            .flat_map(move |part| {
                [false, true]
                    .into_iter()
                    .map(move |indexed| operand(Kind::HalfMultiplyLong { subtract, part }, indexed))
            })
    })
}

#[test]
fn measured_widening_uses_f16c_and_fma_without_requiring_ssse3() {
    let recipe = Recipe {
        half_convert: true,
        byte_shuffle: false,
        fused_widening: true,
    };
    for target in [
        TargetCpu::Baseline.with_f16c().with_fma(),
        TargetCpu::Sse41.with_f16c().with_fma(),
    ] {
        for bytes in QUALIFIED_LENGTHS {
            for operand in long_operands() {
                assert_routing(operand, bytes, target, recipe, true);
            }
        }
    }
}

#[test]
fn measured_vector_dot_uses_f16c_without_requiring_fma() {
    let recipe = Recipe {
        half_convert: true,
        ..Recipe::default()
    };
    for target in [TargetCpu::F16c, TargetCpu::Sse41.with_f16c().with_fma()] {
        for bytes in QUALIFIED_LENGTHS {
            assert_routing(operand(Kind::HalfDot, false), bytes, target, recipe, true);
        }
    }
}

#[test]
fn indexed_dot_and_unmeasured_lengths_keep_existing_bodies() {
    let target = TargetCpu::Sse41.with_f16c().with_fma();
    for bytes in ALL_LENGTHS {
        assert_routing(
            operand(Kind::HalfDot, true),
            bytes,
            target,
            Recipe::default(),
            false,
        );
    }
    for bytes in UNMEASURED_LENGTHS {
        for operand in long_operands().chain([operand(Kind::HalfDot, false)]) {
            assert_routing(operand, bytes, target, Recipe::default(), false);
        }
    }
}

#[test]
fn absent_capabilities_preserve_default_instead_of_declining() {
    for target in [TargetCpu::Baseline, TargetCpu::F16c, TargetCpu::Fma] {
        for bytes in QUALIFIED_LENGTHS {
            for operand in long_operands() {
                assert_routing(operand, bytes, target, Recipe::default(), false);
            }
        }
    }
    for target in [TargetCpu::Baseline, TargetCpu::Fma] {
        for bytes in QUALIFIED_LENGTHS {
            assert_routing(
                operand(Kind::HalfDot, false),
                bytes,
                target,
                Recipe::default(),
                false,
            );
        }
    }
}

#[test]
fn explicit_candidate_rejects_missing_capabilities_before_emission() {
    let operand = operand(
        Kind::HalfMultiplyLong {
            subtract: false,
            part: VectorPart::Bottom,
        },
        false,
    );
    let recipe = Recipe {
        half_convert: true,
        fused_widening: true,
        ..Recipe::default()
    };
    for target in [TargetCpu::Baseline, TargetCpu::F16c, TargetCpu::Fma] {
        let mut code = Vec::new();
        assert!(
            emit_candidate(
                &mut code,
                operand,
                VectorLength::from_bytes(QUALIFIED_LENGTHS[0]).unwrap(),
                FEATURES,
                PC,
                target,
                recipe,
            )
            .is_err()
        );
        assert!(code.is_empty());
    }
}
