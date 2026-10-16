use super::*;
use alloc::vec::Vec;

#[test]
fn baseline_has_no_sha_and_checked_rounds_cancel_the_selected_constant() {
    for (kind, constant) in [
        (Kind::Choose, CHOOSE_CONSTANT),
        (Kind::Parity, PARITY_CONSTANT),
        (Kind::Majority, MAJORITY_CONSTANT),
    ] {
        let operand = Operand {
            kind,
            destination: 31,
            left: 31,
            right: 31,
        };
        let mut baseline = Vec::new();
        emit(&mut baseline, &operand, TargetCpu::Baseline);
        assert!(!baseline.windows(3).any(|w| w == [0x0f, 0x3a, 0xcc]));
        let mut checked = Vec::new();
        emit(&mut checked, &operand, TargetCpu::Sha);
        assert!(checked.windows(3).any(|w| w == [0x0f, 0x3a, 0xcc]));
        assert!(checked.windows(4).any(|w| w == constant.to_le_bytes()));
        assert!(checked.windows(3).any(|w| w == Host::SubDword.encoding()));
    }
}
