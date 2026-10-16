use super::*;
use alloc::vec;

#[test]
fn addends_are_exact_two_and_one_point_five() {
    for (format, reciprocal, square_root) in [
        (Format::Single, 0x4000_0000, 0x3fc0_0000),
        (Format::Double, 0x4000_0000_0000_0000, 0x3ff8_0000_0000_0000),
    ] {
        assert_eq!(addend_bits(format, RefinementKind::Reciprocal), reciprocal);
        assert_eq!(
            addend_bits(format, RefinementKind::ReciprocalSquareRoot),
            square_root
        );
    }
}

#[test]
fn unrelated_shapes_leave_output_untouched() {
    let length = VectorLength::from_bytes(16).unwrap();
    let base = Operand {
        kind: Kind::Refinement(RefinementKind::Reciprocal),
        format: Format::Single,
        destination: 0,
        predicate: None,
        inputs: Inputs::Binary {
            left: Source::Vector(1),
            right: Source::Vector(2),
        },
        shape: ResultShape::Vector,
    };
    for operand in [
        Operand {
            format: Format::Half,
            ..base
        },
        Operand {
            predicate: Some(0),
            ..base
        },
        Operand {
            shape: ResultShape::ScalarReduction,
            ..base
        },
        Operand {
            kind: Kind::SquareRoot,
            ..base
        },
        Operand {
            inputs: Inputs::Unary { source: 1 },
            ..base
        },
    ] {
        let mut code = vec![0xaa];
        assert!(
            !emit(
                &mut code,
                operand,
                length,
                NumericalFeatures::default(),
                GuestAddress(0),
                TargetCpu::Baseline
            )
            .unwrap()
        );
        assert_eq!(code, [0xaa]);
    }
}
