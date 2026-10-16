use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn floating_and_unallocated_operands_decline_without_partial_output() {
    let length = VectorLength::from_bytes(VECTOR_CHUNK_BYTES).unwrap();
    let base = Operand {
        kind: Kind::HalfDot,
        element_size: ElementSize::Word,
        destination: 0,
        left: 1,
        right: RightOperand::Vector(2),
    };
    for operand in [
        base,
        Operand {
            kind: Kind::Integer {
                signedness: Signedness::UnsignedSigned,
                products: Products::Four,
            },
            element_size: ElementSize::Doubleword,
            ..base
        },
        Operand {
            kind: Kind::Integer {
                signedness: Signedness::Signed,
                products: Products::Four,
            },
            right: RightOperand::Indexed {
                register: INDEXED_WORD_REGISTERS,
                index: 0,
            },
            ..base
        },
    ] {
        let mut code = vec![0xcc];
        assert!(!emit_integer(
            &mut code,
            &operand,
            length,
            TargetCpu::Baseline
        ));
        assert_eq!(code, [0xcc]);
    }
}

#[test]
fn horizontal_unsigned_pair_recipe_requires_ssse3() {
    let mut baseline = Vec::new();
    sum_halfword_pairs(&mut baseline, TargetCpu::Baseline);
    assert!(
        !baseline
            .windows(Host::HorizontalAddDword.encoding().len())
            .any(|bytes| bytes == Host::HorizontalAddDword.encoding())
    );
    let mut checked = Vec::new();
    sum_halfword_pairs(&mut checked, TargetCpu::Ssse3);
    assert!(checked.starts_with(Host::HorizontalAddDword.encoding()));
    assert!(checked.len() < baseline.len());
}
