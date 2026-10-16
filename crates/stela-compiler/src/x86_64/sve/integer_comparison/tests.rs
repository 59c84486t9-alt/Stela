use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn optional_doubleword_opcodes_require_exact_tier() {
    for (relation, required, optional) in [
        (
            Relation::Equal,
            TargetCpu::Sse41,
            Host::EqualQword.encoding(),
        ),
        (
            Relation::Greater,
            TargetCpu::Sse42,
            Host::GreaterQword.encoding(),
        ),
    ] {
        let mut baseline = Vec::new();
        emit_compare_chunk(
            &mut baseline,
            relation,
            false,
            ElementSize::Doubleword,
            TargetCpu::Baseline,
        )
        .unwrap();
        assert!(
            !baseline
                .windows(optional.len())
                .any(|bytes| bytes == optional)
        );
        let mut checked = Vec::new();
        emit_compare_chunk(
            &mut checked,
            relation,
            false,
            ElementSize::Doubleword,
            required,
        )
        .unwrap();
        assert!(
            checked
                .windows(optional.len())
                .any(|bytes| bytes == optional)
        );
        assert!(checked.len() < baseline.len());
    }
}

#[test]
fn reserved_element_width_does_not_emit_prefix() {
    let mut code = vec![0x90];
    assert_eq!(
        emit_compare_chunk(
            &mut code,
            Relation::Equal,
            false,
            ElementSize::Quadword,
            TargetCpu::Sse42
        ),
        Err(())
    );
    assert_eq!(code, [0x90]);
}
