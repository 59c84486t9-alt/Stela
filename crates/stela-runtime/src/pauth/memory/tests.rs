use super::*;
use std::cell::Cell;

fn load(base: u8, destination: u8, writeback: bool) -> Load {
    Load {
        key: DataKey::A,
        destination,
        base,
        displacement: -8,
        writeback,
    }
}

#[test]
fn load_stages_aliases_and_commits_only_declared_outputs() {
    for base in 0..=ZERO_REGISTER_INDEX {
        for destination in 0..=ZERO_REGISTER_INDEX {
            for writeback in [false, true] {
                let instruction = load(base, destination, writeback);
                let mut state = GuestState::default();
                state.x.fill(0xdead_beef_1234_5678);
                state.sp = 0xa500_0000_0000_2000;
                state.nzcv = 0xf000_0000;
                state.reserved = 0xa5a5_5a5a;
                state.fpcr = 0x0300_0000;
                state.fpsr = 0x0800_009f;
                state.v.fill([0x1122_3344, 0x8877_6655]);
                let pointer = if base == ZERO_REGISTER_INDEX {
                    state.sp
                } else {
                    state.x[usize::from(base)]
                };
                let initial = state.clone();
                let result = complete(
                    instruction,
                    Controls::default(),
                    &mut state,
                    |key, old| {
                        assert_eq!(key, DataKey::A);
                        assert_eq!(old, pointer);
                        Ok::<_, ()>(0xa500_0000_0000_1000)
                    },
                    |address| {
                        assert_eq!(address, 0xa500_0000_0000_0ff8);
                        Ok::<_, ()>(0x8877_6655_4433_2211)
                    },
                );
                if instruction.undefined_overlap() {
                    assert_eq!(result, Err(Fault::UndefinedOverlap));
                    assert_eq!(state, initial);
                    continue;
                }
                assert_eq!(
                    result,
                    Ok(Completion {
                        effective_address: 0xa500_0000_0000_0ff8
                    })
                );
                let mut expected = initial;
                if destination != ZERO_REGISTER_INDEX {
                    expected.x[usize::from(destination)] = 0x8877_6655_4433_2211;
                }
                if writeback {
                    if base == ZERO_REGISTER_INDEX {
                        expected.sp = 0xa500_0000_0000_0ff8;
                    } else {
                        expected.x[usize::from(base)] = 0xa500_0000_0000_0ff8;
                    }
                }
                assert_eq!(state, expected);
            }
        }
    }
}

#[test]
fn authentication_precedes_sp_alignment_and_read_faults() {
    let mut state = GuestState {
        sp: 0x2001,
        ..GuestState::default()
    };
    let initial = state.clone();
    let called = Cell::new(false);
    let result = complete(
        load(ZERO_REGISTER_INDEX, 0, true),
        Controls::default(),
        &mut state,
        |_, _| Err::<u64, _>("authentication"),
        |_| {
            called.set(true);
            Ok::<_, ()>(0)
        },
    );
    assert_eq!(result, Err(Fault::Authentication("authentication")));
    assert!(!called.get());
    assert_eq!(state, initial);
    let result = complete(
        load(ZERO_REGISTER_INDEX, 0, true),
        Controls::default(),
        &mut state,
        |_, _| Ok::<_, ()>(0x3000),
        |_| {
            called.set(true);
            Ok::<_, ()>(0)
        },
    );
    assert_eq!(
        result,
        Err(Fault::StackAlignment {
            stack_pointer: 0x2001
        })
    );
    assert!(!called.get());
    assert_eq!(state, initial);
}

#[test]
fn overlap_is_undefined_before_authentication_and_read() {
    let mut state = GuestState::default();
    let initial = state.clone();
    let called = Cell::new(false);
    let result = complete(
        load(3, 3, true),
        Controls::default(),
        &mut state,
        |_, _| {
            called.set(true);
            Ok::<_, ()>(0)
        },
        |_| {
            called.set(true);
            Ok::<_, ()>(0)
        },
    );
    assert_eq!(result, Err(Fault::UndefinedOverlap));
    assert!(!called.get());
    assert_eq!(state, initial);
}

#[test]
fn read_failure_preserves_destination_and_base_including_sp_and_xzr() {
    for base in [0, ZERO_REGISTER_INDEX] {
        for destination in [1, ZERO_REGISTER_INDEX] {
            let mut state = GuestState::default();
            state.x[0] = 0x3000;
            state.x[1] = 0x1122;
            state.sp = 0x4000;
            let initial = state.clone();
            let result = complete(
                load(base, destination, true),
                Controls::default(),
                &mut state,
                |_, _| Ok::<_, ()>(4),
                |address| {
                    assert_eq!(address, u64::MAX - 3);
                    Err::<u64, _>("permission")
                },
            );
            assert_eq!(
                result,
                Err(Fault::Read {
                    address: u64::MAX - 3,
                    error: "permission"
                })
            );
            assert_eq!(state, initial);
        }
    }
}
#[test]
fn nonfaulting_authentication_result_reaches_address_add_before_translation() {
    let mut state = GuestState::default();
    state.x[0] = 0x1234;
    let result = complete(
        load(0, 1, true),
        Controls::default(),
        &mut state,
        |_, _| Ok::<_, ()>(1 << 47),
        |address| {
            assert_eq!(address, 0x7fff_ffff_fff8);
            Ok::<_, ()>(0x5678)
        },
    );
    assert_eq!(
        result,
        Ok(Completion {
            effective_address: 0x7fff_ffff_fff8
        })
    );
    assert_eq!(state.x[0], 0x7fff_ffff_fff8);
    assert_eq!(state.x[1], 0x5678);
}
#[test]
fn disabled_sp_alignment_reaches_read_without_weakening_enabled_checks() {
    let mut state = GuestState {
        sp: 0x2001,
        ..GuestState::default()
    };
    let result = complete(
        load(ZERO_REGISTER_INDEX, 0, true),
        Controls {
            check_sp_alignment: false,
            privileged: false,
        },
        &mut state,
        |_, pointer| {
            assert_eq!(pointer, 0x2001);
            Ok::<_, ()>(0x3001)
        },
        |address| {
            assert_eq!(address, 0x2ff9);
            Ok::<_, ()>(0x8877)
        },
    );
    assert_eq!(
        result,
        Ok(Completion {
            effective_address: 0x2ff9
        })
    );
    assert_eq!(state.x[0], 0x8877);
    assert_eq!(state.sp, 0x2ff9);
}
#[test]
fn invalid_public_descriptors_decline_before_callbacks_or_commit() {
    for instruction in [
        Load {
            base: 32,
            ..load(0, 1, false)
        },
        Load {
            destination: 32,
            ..load(0, 1, false)
        },
        Load {
            displacement: -4097,
            ..load(0, 1, false)
        },
        Load {
            displacement: 4096,
            ..load(0, 1, false)
        },
        Load {
            displacement: 1,
            ..load(0, 1, false)
        },
    ] {
        let mut state = GuestState::default();
        let initial = state.clone();
        let result = complete(
            instruction,
            Controls::default(),
            &mut state,
            |_, _| -> Result<u64, ()> { panic!("invalid descriptor authenticated") },
            |_| -> Result<u64, ()> { panic!("invalid descriptor read memory") },
        );
        assert_eq!(result, Err(Fault::InvalidOperands));
        assert_eq!(state, initial);
    }
}
