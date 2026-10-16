use super::*;
use alloc::vec::Vec;

#[test]
fn optional_hardware_is_castagnoli_only_and_discard_preserves_map_interval() {
    for size in [
        DataSize::Byte,
        DataSize::Halfword,
        DataSize::Word,
        DataSize::Doubleword,
    ] {
        for polynomial in [Polynomial::Ieee, Polynomial::Castagnoli] {
            let mut operand = Operand {
                size,
                polynomial,
                destination: Register::X(0),
                accumulator: Register::X(1),
                data: Register::X(2),
            };
            let mut baseline = Vec::new();
            let mut checked = Vec::new();
            emit(&mut baseline, &operand, TargetCpu::Baseline);
            emit(&mut checked, &operand, TargetCpu::Sse42);
            if polynomial == Polynomial::Castagnoli {
                assert!(checked.len() < baseline.len());
                let mut expected = Vec::new();
                load(&mut expected, operand.accumulator);
                right_operand(&mut expected, operand.data, Width::X64, Shift::Lsl, 0);
                CrcOpcode::for_bytes(size.bytes()).emit(&mut expected, TargetCpu::Sse42);
                store(&mut expected, operand.destination);
                assert_eq!(checked, expected);
            } else {
                assert_eq!(checked, baseline);
            }
            operand.destination = Register::Zero;
            for target in [TargetCpu::Baseline, TargetCpu::Sse42] {
                let mut discarded = Vec::new();
                emit(&mut discarded, &operand, target);
                let mut nop = Vec::new();
                Table::Discard.emit(&mut nop);
                assert_eq!(discarded, nop);
            }
        }
    }
}
