use super::*;
use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::InterruptLatch};

fn lifecycle() -> LifecycleState {
    LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    }
}
fn ranges() -> Vec<Range> {
    vec![
        Range {
            id: 2,
            start: 1,
            count: 1,
            name: "PMP-STATUS".into(),
        },
        Range {
            id: 10,
            start: 248,
            count: 8,
            name: "SOC-DEV-PS-REQ".into(),
        },
        Range {
            id: 11,
            start: 256,
            count: 8,
            name: "SOC-DEV-PS-ACK".into(),
        },
    ]
}
fn bank() -> Ptd {
    Ptd::initialized(384, &ranges(), lifecycle(), [None; ROUTES]).unwrap()
}
fn write(
    bank: &mut Ptd,
    entry: u32,
    value: u64,
    now: u64,
    latch: &mut InterruptLatch,
) -> Result<(), MmioError> {
    bank.write(
        UPDATE_OFFSET + u64::from(entry) * 8,
        Width::Double,
        value,
        &mut Access::new(0, now, latch),
    )
}

#[test]
fn initialized_backing_never_fabricates_readiness_power_ack_or_quota() {
    let mut bank = bank();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert_eq!(bank.read(16, Width::Double, &mut access), Ok(0));
    assert_eq!(bank.read(24, Width::Double, &mut access), Ok(0));
    write(&mut bank, 248, 0xfedc, 17, &mut latch).unwrap();
    let request = bank
        .consume_entry(248, &mut Access::new(0, 18, &mut latch))
        .unwrap();
    assert_eq!(
        request,
        Entry {
            value: 0xfedc,
            metadata: 17 << 10 | NEW_DATA
        }
    );
    assert_eq!(
        bank.consume_entry(256, &mut Access::new(0, 18, &mut latch))
            .unwrap(),
        Entry {
            value: 0,
            metadata: 0
        }
    );
    assert_eq!(
        bank.requests(),
        [Request {
            serial: 1,
            entry: 248,
            value: 0xfedc,
            at: 17
        }]
    );
    assert!(Ptd::new(&ranges()).is_err());
}

#[test]
fn overwrite_dropped_timestamp_and_consume_are_actual_transport_effects() {
    let mut bank = bank();
    let mut latch = InterruptLatch::new();
    write(&mut bank, 3, 0x1234, (1 << 54) - 1, &mut latch).unwrap();
    write(&mut bank, 3, 0x5678, 1 << 54, &mut latch).unwrap();
    let mut access = Access::new(0, 0, &mut latch);
    assert_eq!(bank.read(IRQ_STATUS, Width::Word, &mut access), Ok(1 << 3));
    assert!(bank.read(3 * 16, Width::Double, &mut access).is_err());
    assert!(bank.read(3 * 16 + 8, Width::Double, &mut access).is_err());
    assert_eq!(
        bank.consume_entry(3, &mut access).unwrap(),
        Entry {
            value: 0x5678,
            metadata: FLAGS
        }
    );
    assert_eq!(bank.read(IRQ_STATUS, Width::Word, &mut access), Ok(0));
    assert_eq!(bank.read(3 * 16, Width::Double, &mut access), Ok(0x5678));
    assert_eq!(bank.read(3 * 16 + 8, Width::Double, &mut access), Ok(0));
    assert_eq!(
        bank.requests().iter().map(|r| r.serial).collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn aliases_share_identity_and_retained_pause_keeps_the_complete_prefix() {
    let mut bank = bank();
    let mut alias = bank.clone();
    let mut latch = InterruptLatch::new();
    write(&mut bank, 1, 0xabc, 9, &mut latch).unwrap();
    let paused = LifecycleState {
        clocked: false,
        ..lifecycle()
    };
    Lifecycle::set_lifecycle(&mut alias, paused, &mut Access::new(0, 10, &mut latch));
    assert_eq!(bank.lifecycle_state(), paused);
    assert!(write(&mut bank, 1, 0, 11, &mut latch).is_err());
    assert!(
        bank.consume_entry(1, &mut Access::new(0, 11, &mut latch))
            .is_err()
    );
    assert_eq!(alias.requests().len(), 1);
    assert!(
        Lifecycle::check_lifecycle(
            &bank,
            LifecycleState {
                reset: true,
                ..lifecycle()
            }
        )
        .is_err()
    );
    assert!(
        Lifecycle::check_lifecycle(
            &bank,
            LifecycleState {
                powered: false,
                retention: false,
                ..lifecycle()
            }
        )
        .is_err()
    );
    Lifecycle::set_lifecycle(&mut bank, lifecycle(), &mut Access::new(0, 12, &mut latch));
    assert_eq!(
        alias
            .consume_entry(1, &mut Access::new(0, 13, &mut latch))
            .unwrap()
            .value,
        0xabc
    );
}

#[test]
fn qualified_routes_aggregate_same_wire_and_unqualified_routes_roll_back() {
    let wire = Wire::Aic(AicInput::new(0, 77));
    let mut bindings = [None; ROUTES];
    bindings[1] = Some(wire);
    bindings[2] = Some(wire);
    let mut bank = Ptd::initialized(384, &ranges(), lifecycle(), bindings).unwrap();
    let mut latch = InterruptLatch::new();
    bank.write(
        IRQ_ROUTE,
        Width::Word,
        0x21,
        &mut Access::new(0, 0, &mut latch),
    )
    .unwrap();
    bank.write(
        IRQ_ENABLE,
        Width::Word,
        3,
        &mut Access::new(0, 0, &mut latch),
    )
    .unwrap();
    write(&mut bank, 0, 1, 1, &mut latch).unwrap();
    write(&mut bank, 1, 2, 2, &mut latch).unwrap();
    assert!(latch.is_asserted(wire));
    bank.consume_entry(0, &mut Access::new(0, 3, &mut latch))
        .unwrap();
    assert!(latch.is_asserted(wire));
    assert!(
        bank.write(
            IRQ_ROUTE,
            Width::Word,
            0x31,
            &mut Access::new(0, 4, &mut latch)
        )
        .is_err()
    );
    assert_eq!(
        bank.read(IRQ_ROUTE, Width::Word, &mut Access::new(0, 4, &mut latch)),
        Ok(0x21)
    );
    bank.write(
        IRQ_DISABLE,
        Width::Word,
        2,
        &mut Access::new(0, 5, &mut latch),
    )
    .unwrap();
    assert!(!latch.is_asserted(wire));
    bank.write(
        IRQ_ENABLE,
        Width::Word,
        2,
        &mut Access::new(0, 6, &mut latch),
    )
    .unwrap();
    assert!(latch.is_asserted(wire));
    bank.consume_entry(1, &mut Access::new(0, 7, &mut latch))
        .unwrap();
    assert!(!latch.is_asserted(wire));
    // An unknown route refuses the triggering store before any effect.
    bank.write(
        IRQ_ENABLE,
        Width::Word,
        4,
        &mut Access::new(0, 8, &mut latch),
    )
    .unwrap();
    let before = bank.requests();
    assert!(write(&mut bank, 2, 9, 9, &mut latch).is_err());
    assert_eq!(bank.requests(), before);
    assert_eq!(
        bank.consume_entry(2, &mut Access::new(0, 10, &mut latch))
            .unwrap(),
        Entry {
            value: 0,
            metadata: 0
        }
    );
}

#[test]
fn observation_unknownness_never_becomes_reset_or_native_clock_state() {
    let mut bank = Ptd::from_observations(
        384,
        &ranges(),
        lifecycle(),
        [None; ROUTES],
        &[
            Observation {
                offset: 16,
                value: 0,
                known: u64::MAX,
            },
            Observation {
                offset: 24,
                value: 0,
                known: u64::MAX,
            },
        ],
    )
    .unwrap();
    let mut latch = InterruptLatch::new();
    assert_eq!(
        bank.read(16, Width::Double, &mut Access::new(0, 0, &mut latch)),
        Ok(0)
    );
    assert!(
        bank.read(IRQ_STATUS, Width::Word, &mut Access::new(0, 0, &mut latch))
            .is_err()
    );
    assert!(write(&mut bank, 1, 1, 1, &mut latch).is_err());
    assert!(bank.requests().is_empty());
    assert!(
        Ptd::from_observations(
            384,
            &ranges(),
            lifecycle(),
            [None; ROUTES],
            &[Observation {
                offset: IRQ_STATUS,
                value: 1 << 32,
                known: 0
            },]
        )
        .is_err()
    );
    assert!(
        Ptd::from_observations(
            384,
            &ranges(),
            lifecycle(),
            [None; ROUTES],
            &[
                Observation {
                    offset: 16,
                    value: 0,
                    known: 0
                },
                Observation {
                    offset: 16,
                    value: 1,
                    known: 0
                },
            ]
        )
        .is_err()
    );
}

#[test]
fn range_identity_widths_and_last_word_boundaries_are_checked() {
    let source = ranges();
    for bad in [
        Range {
            id: 2,
            start: 300,
            count: 1,
            name: "duplicate-id".into(),
        },
        Range {
            id: 90,
            start: 300,
            count: 1,
            name: "PMP-STATUS".into(),
        },
        Range {
            id: 90,
            start: 250,
            count: 1,
            name: "overlap".into(),
        },
        Range {
            id: 90,
            start: u32::MAX,
            count: 1,
            name: "overflow".into(),
        },
    ] {
        let mut bad_ranges = source.clone();
        bad_ranges.push(bad);
        assert!(Ptd::initialized(384, &bad_ranges, lifecycle(), [None; ROUTES]).is_err());
    }
    let mut bank = Ptd::initialized(377, &ranges(), lifecycle(), [None; ROUTES]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(
        bank.read(IRQ_STATUS + 44, Width::Double, &mut access)
            .is_err()
    );
    assert_eq!(
        bank.read(IRQ_STATUS + 40, Width::Double, &mut access),
        Ok(0)
    );
    for (offset, width) in [
        (PTD_BYTES, Width::Word),
        (16, Width::Word),
        (17, Width::Double),
        (UPDATE_OFFSET, Width::Word),
        (IRQ_ROUTE, Width::Double),
    ] {
        assert!(bank.read(offset, width, &mut access).is_err());
    }
    assert!(
        bank.write(IRQ_ENABLE + 44, Width::Word, 1 << 25, &mut access)
            .is_err()
    );
    assert!(
        bank.write(IRQ_ROUTE + 188, Width::Word, 0x10, &mut access)
            .is_err()
    );
    assert!(bank.requests().is_empty());
}
