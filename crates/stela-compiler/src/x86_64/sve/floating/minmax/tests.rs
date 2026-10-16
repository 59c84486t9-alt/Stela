use super::*;
use alloc::vec;

#[test]
fn half_and_non_minmax_shapes_emit_no_frame() {
    let base = Operand {
        kind: Kind::MinMax(MinMaxOperation::Minimum),
        format: Format::Half,
        destination: 0,
        predicate: Some(7),
        inputs: Inputs::Binary {
            left: Source::Vector(0),
            right: Source::Vector(31),
        },
        shape: ResultShape::Vector,
    };
    for operand in [
        base,
        Operand {
            format: Format::Single,
            predicate: None,
            ..base
        },
        Operand {
            format: Format::Double,
            shape: ResultShape::ScalarReduction,
            ..base
        },
        Operand {
            format: Format::Single,
            inputs: Inputs::Binary {
                left: Source::Vector(1),
                right: Source::ImmediateBits(0),
            },
            ..base
        },
    ] {
        let mut code = vec![0x90];
        assert!(
            !emit(
                &mut code,
                operand,
                VectorLength::from_bytes(256).unwrap(),
                NumericalFeatures::new(true, true, true),
                GuestAddress(0x1000),
                TargetCpu::Baseline,
            )
            .unwrap()
        );
        assert_eq!(code, [0x90]);
    }
}
