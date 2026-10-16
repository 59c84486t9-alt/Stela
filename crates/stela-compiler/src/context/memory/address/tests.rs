use super::*;

#[test]
fn mixed_access_levels_retain_opposite_effects_and_reject_same_level_conflicts() {
    let resolved =
        EffectiveAddressChecks::new(AddressAddChecks::Disabled, AddressAddChecks::Enabled);
    let el0 = AddressCheckRequirements::for_access(AccessEl::El0, AddressAddChecks::Disabled);
    let el1 = AddressCheckRequirements::for_access(AccessEl::El1, AddressAddChecks::Enabled);
    let mixed = el0.merge(el1).expect("different access levels compose");
    assert!(mixed.matches(resolved, IncrementChoice::Unchecked));
    assert!(!mixed.matches(
        EffectiveAddressChecks::new(AddressAddChecks::Enabled, AddressAddChecks::Enabled,),
        IncrementChoice::Unchecked
    ));
    assert_eq!(
        mixed.merge(AddressCheckRequirements::default()),
        Some(mixed)
    );
    assert!(
        mixed
            .merge(AddressCheckRequirements::for_access(
                AccessEl::El0,
                AddressAddChecks::Enabled,
            ))
            .is_none()
    );
    assert!(
        mixed
            .merge(AddressCheckRequirements::for_access(
                AccessEl::El1,
                AddressAddChecks::Disabled,
            ))
            .is_none()
    );
}

#[test]
fn secondary_increment_choice_is_independent_and_cannot_silently_merge() {
    let unchecked =
        AddressCheckRequirements::default().with_increment_choice(IncrementChoice::Unchecked);
    let checked =
        AddressCheckRequirements::default().with_increment_choice(IncrementChoice::Checked);
    assert!(unchecked.merge(checked).is_none());
    let resolved =
        EffectiveAddressChecks::new(AddressAddChecks::Enabled, AddressAddChecks::Disabled);
    assert!(unchecked.matches(resolved, IncrementChoice::Unchecked));
    assert!(!unchecked.matches(resolved, IncrementChoice::Checked));
    assert!(AddressCheckRequirements::default().is_empty());
    assert!(!unchecked.is_empty());
}

#[test]
fn enabled_addition_marks_top_byte_change_and_is_idempotent_for_zero_offset() {
    let base = 0x1200_0000_0000_1000;
    let result = 0x1300_0000_0000_1000;
    let marked = 0x1240_0000_0000_1000;
    assert_eq!(AddressAddChecks::Disabled.apply(result, base), result);
    assert_eq!(AddressAddChecks::Enabled.apply(result, base), marked);
    assert_eq!(AddressAddChecks::Enabled.apply(base, base), base);
    assert_eq!(AddressAddChecks::Enabled.apply(marked, marked), marked);
}
