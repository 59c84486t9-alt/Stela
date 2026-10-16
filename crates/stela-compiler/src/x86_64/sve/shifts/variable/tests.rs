use super::*;

#[test]
fn avx2_route_excludes_different_count_semantics_and_missing_widths() {
    for (kind, element, count, target) in [
        (
            Kind::LogicalLeft,
            ElementSize::Word,
            Count::Elements(1),
            TargetCpu::Baseline,
        ),
        (
            Kind::LogicalLeft,
            ElementSize::Word,
            Count::Doublewords(1),
            TargetCpu::Avx2,
        ),
        (
            Kind::LogicalLeft,
            ElementSize::Word,
            Count::Immediate(1),
            TargetCpu::Avx2,
        ),
        (
            Kind::LogicalLeft,
            ElementSize::Byte,
            Count::Elements(1),
            TargetCpu::Avx2,
        ),
        (
            Kind::LogicalRight,
            ElementSize::Halfword,
            Count::Elements(1),
            TargetCpu::Avx2,
        ),
        (
            Kind::ArithmeticRight,
            ElementSize::Doubleword,
            Count::Elements(1),
            TargetCpu::Avx2,
        ),
        (
            Kind::RoundingSigned,
            ElementSize::Word,
            Count::Elements(1),
            TargetCpu::Avx2,
        ),
        (
            Kind::SaturatingUnsigned,
            ElementSize::Word,
            Count::Elements(1),
            TargetCpu::Avx2,
        ),
    ] {
        assert_eq!(avx2_opcode(kind, element, count, target), None);
    }
    assert_eq!(
        avx2_opcode(
            Kind::ArithmeticRight,
            ElementSize::Word,
            Count::Elements(1),
            TargetCpu::Avx2
        ),
        Some(VexShiftOpcode::ArithmeticDword),
    );
}
