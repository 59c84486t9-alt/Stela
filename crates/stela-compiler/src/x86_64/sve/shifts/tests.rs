use super::*;
use alloc::vec::Vec;

fn variable_operand(element_size: ElementSize, kind: Kind) -> Operand {
    Operand {
        kind,
        element_size,
        destination: 31,
        source: 31,
        count: Count::Elements(31),
        predication: Predication::Merging(7),
        second_source: None,
        has_dit_guarantee: true,
    }
}

#[test]
fn avx2_variable_shift_body_replaces_scalar_scratch_without_widening_state_access() {
    let length = VectorLength::from_bytes(64).unwrap();
    let operand = variable_operand(ElementSize::Word, Kind::LogicalLeft);
    let mut baseline = Vec::new();
    let mut avx2 = Vec::new();
    emit(&mut baseline, operand, length, TargetCpu::Baseline);
    emit(&mut avx2, operand, length, TargetCpu::Avx2);
    assert!(baseline.starts_with(&[0x48, 0x83, 0xec, scalar::STACK_BYTES]));
    assert!(avx2.starts_with(&[0xc5, 0xf8, 0x77]));
    let shift = [0xc4, 0xe2, 0x79, 0x47, 0xc1];
    assert_eq!(
        avx2.windows(shift.len())
            .filter(|row| *row == shift)
            .count(),
        length.chunks()
    );
    assert!(!baseline.windows(shift.len()).any(|row| row == shift));
    assert!(avx2.len() < baseline.len());
    assert!(requires_declared_dit_zero(operand, length));

    let excluded = variable_operand(ElementSize::Doubleword, Kind::ArithmeticRight);
    baseline.clear();
    avx2.clear();
    emit(&mut baseline, excluded, length, TargetCpu::Baseline);
    emit(&mut avx2, excluded, length, TargetCpu::Avx2);
    assert_eq!(baseline, avx2);
}
