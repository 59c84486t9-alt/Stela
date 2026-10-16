use super::*;

#[test]
fn multiplication_check_requires_addition_check() {
    assert_eq!(EffectivePointerChecks::from_effective(false, true), None);
    for (cpta, cptm, expected) in [
        (false, false, EffectivePointerChecks::Unchecked),
        (true, false, EffectivePointerChecks::Addition),
        (
            true,
            true,
            EffectivePointerChecks::AdditionAndMultiplication,
        ),
    ] {
        assert_eq!(
            EffectivePointerChecks::from_effective(cpta, cptm),
            Some(expected)
        );
    }
}

#[test]
fn checks_preserve_base_high_bits_and_mark_bit_54() {
    let base = 0x1280_0000_0000_0000;
    let changed_top_byte = 0x1380_0000_0000_0005;
    assert_eq!(
        EffectivePointerChecks::Unchecked.apply(changed_top_byte, base, true),
        changed_top_byte
    );
    assert_eq!(
        EffectivePointerChecks::Addition.apply(changed_top_byte, base, false),
        0x1280_0000_0000_0005
    );
    // Base bits55/54 differ: detection persists even without a top-byte change.
    assert_eq!(
        EffectivePointerChecks::Addition.apply(base | 5, base, false),
        base | 5
    );
    let ordinary_base = 0x1200_0000_0000_0000;
    let ordinary_result = ordinary_base | 5;
    assert_eq!(
        EffectivePointerChecks::Addition.apply(ordinary_result, ordinary_base, true),
        ordinary_result
    );
    assert_eq!(
        EffectivePointerChecks::AdditionAndMultiplication.apply(
            ordinary_result,
            ordinary_base,
            true
        ),
        0x1240_0000_0000_0005
    );
}
