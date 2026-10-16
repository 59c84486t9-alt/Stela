use super::*;
const VALUES: [u64; 4] = [0x1000, 0x2000, 0x3000, 0x4000];
fn initialized() -> (InactiveStacks, GuestState) {
    let mut stacks = InactiveStacks::lower(StackBank::El0, VALUES[1]);
    stacks.initialize_higher(Some(VALUES[2]), Some(VALUES[3]));
    (
        stacks,
        GuestState {
            sp: VALUES[0],
            ..GuestState::default()
        },
    )
}
#[test]
fn every_bank_round_trip_has_one_active_value() {
    let (mut stacks, mut registers) = initialized();
    let mut active = StackBank::El0;
    for destination in [
        StackBank::El2,
        StackBank::El3,
        StackBank::El1,
        StackBank::El0,
        StackBank::El3,
        StackBank::El2,
        StackBank::El0,
    ] {
        stacks.select(active, destination, &mut registers).unwrap();
        active = destination;
        assert_eq!(
            stacks.values.iter().filter(|value| value.is_none()).count(),
            1
        );
        assert_eq!(registers.sp, VALUES[active.index()]);
        for bank in [
            StackBank::El0,
            StackBank::El1,
            StackBank::El2,
            StackBank::El3,
        ] {
            assert_eq!(
                stacks.read(active, bank, &registers),
                Ok(VALUES[bank.index()])
            );
        }
    }
}
#[test]
fn unavailable_bank_declines_without_any_sp_or_slot_write() {
    let mut stacks = InactiveStacks::lower(StackBank::El0, VALUES[1]);
    let mut registers = GuestState {
        sp: VALUES[0],
        ..GuestState::default()
    };
    let before = (stacks.clone(), registers.clone());
    assert_eq!(
        stacks.select(StackBank::El0, StackBank::El2, &mut registers),
        Err(StateError::UnavailableStack(StackBank::El2))
    );
    assert_eq!((stacks, registers), before);
}
