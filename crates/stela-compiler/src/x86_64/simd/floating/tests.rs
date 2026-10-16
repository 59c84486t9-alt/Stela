use super::*;
use alloc::vec::Vec;

#[test]
fn checked_qword_classifier_and_no_numeric_host_fp() {
    let operation = Operand::Sign {
        operation: SignOperation::Neg,
        destination: 31,
        source: 31,
        lane_bytes: 8,
        bytes: 16,
        scalar: false,
    };
    let mut baseline = Vec::new();
    emit(&mut baseline, &operation, TargetCpu::Baseline);
    let mut optimized = Vec::new();
    emit(&mut optimized, &operation, TargetCpu::Sse42);
    assert!(
        !baseline
            .windows(4)
            .any(|bytes| bytes == Host::GreaterQword.encoding())
    );
    assert!(
        optimized
            .windows(4)
            .any(|bytes| bytes == Host::GreaterQword.encoding())
    );
    assert!(optimized.len() < baseline.len());
    for code in [baseline, optimized] {
        assert!(!code.windows(2).any(|bytes| bytes == [0x0f, 0xae])); // No MXCSR load/store.
    }
}
