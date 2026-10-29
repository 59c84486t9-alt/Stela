use super::*;
use alloc::vec::Vec;
use {
    crate::platform::apple::ptd::transport::Observation, stela_contracts::bus::Access,
    stela_contracts::bus::Lifecycle, stela_contracts::bus::LifecycleState,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::Width as BusWidth,
    stela_contracts::interrupt::InterruptLatch, stela_soc_data::ptd::Range,
    stela_soc_data::ptd::UPDATE_OFFSET,
};

const PATTERN: [u32; 12] = [
    0x01234567, 0x89abcdef, 0x13579bdf, 0x2468ace0, 0x55667788, 0x99aabbcc, 0xddeeff00, 0x10203040,
    1, 0xdeadbeef, 0xfeedface, 0x80000000,
];

fn lifecycle() -> LifecycleState {
    LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    }
}

fn ranges(entries: u32) -> [Range; 1] {
    [Range {
        id: 1,
        start: 0,
        count: entries,
        name: "declared status test".into(),
    }]
}

fn observations() -> Vec<Observation> {
    PATTERN
        .iter()
        .enumerate()
        .map(|(index, &value)| Observation {
            offset: IRQ_STATUS + u64::try_from(index).unwrap() * 4,
            value: u64::from(value),
            known: u64::from(u32::MAX),
        })
        .collect()
}

fn observed(entries: u32, observations: &[Observation]) -> Ptd {
    Ptd::from_observations(
        entries,
        &ranges(entries),
        lifecycle(),
        [None; 16],
        observations,
    )
    .unwrap()
}

#[test]
fn pending_ranges_shift_and_mask_real_words_without_consumption() {
    let (mut bank, _) = Ptd::initialized_local(384, &ranges(384), lifecycle()).unwrap();
    let mut latch = InterruptLatch::new();
    let entries = [
        0, 15, 16, 31, 32, 63, 64, 79, 80, 127, 128, 143, 207, 208, 383,
    ];
    for entry in entries {
        bank.write(
            UPDATE_OFFSET + u64::from(entry) * 8,
            BusWidth::Double,
            u64::from(entry),
            &mut Access::new(0, 17, &mut latch),
        )
        .unwrap();
    }
    let history = bank.requests();
    for (start, count) in [
        (16, 112),
        (80, 128),
        (127, 1),
        (128, 16),
        (256, 128),
        (384, 0),
    ] {
        let expected = entries
            .iter()
            .filter(|entry| **entry >= start && **entry < start + count)
            .fold(0u128, |mask, entry| mask | (1u128 << (entry - start)));
        let snapshot = bank.pending_range(start, count).unwrap();
        assert_eq!(
            u128::from(snapshot.low) | u128::from(snapshot.high) << 64,
            expected
        );
    }
    for (start, count) in [(0, 129), (300, 128), (385, 0), (u32::MAX, 2)] {
        assert!(bank.pending_range(start, count).is_err());
    }
    assert_eq!(bank.requests(), history);
    for entry in entries {
        assert_eq!(
            bank.consume_entry(entry, &mut Access::new(0, 18, &mut latch))
                .unwrap()
                .metadata,
            17 << 10 | 2
        );
    }
}
#[test]
fn stable_little_endian_snapshots_preserve_existing_scalar_reads() {
    let mut bank = observed(384, &observations());
    let mut latch = InterruptLatch::new();
    for (index, value) in PATTERN.into_iter().enumerate() {
        let offset = IRQ_STATUS + u64::try_from(index).unwrap() * 4;
        assert_eq!(
            bank.interrupt_snapshot(offset, Width::Word).unwrap(),
            Snapshot {
                low: u64::from(value),
                high: 0
            }
        );
        assert_eq!(
            bank.read(offset, BusWidth::Word, &mut Access::new(0, 0, &mut latch))
                .unwrap(),
            u64::from(value)
        );
    }
    for (index, words) in PATTERN.as_chunks::<2>().0.iter().enumerate() {
        let offset = IRQ_STATUS + u64::try_from(index).unwrap() * 8;
        let expected = u64::from(words[0]) | u64::from(words[1]) << 32;
        assert_eq!(
            bank.interrupt_snapshot(offset, Width::Double).unwrap(),
            Snapshot {
                low: expected,
                high: 0
            }
        );
        assert_eq!(
            bank.read(offset, BusWidth::Double, &mut Access::new(0, 0, &mut latch))
                .unwrap(),
            expected
        );
    }
    for (offset, low, high) in [
        (0, 0x89abcdef01234567, 0x2468ace013579bdf),
        (16, 0x99aabbcc55667788, 0x10203040ddeeff00),
        (32, 0xdeadbeef00000001, 0x80000000feedface),
    ] {
        assert_eq!(
            bank.interrupt_snapshot(IRQ_STATUS + offset, Width::Quad)
                .unwrap(),
            Snapshot { low, high }
        );
    }
    assert!(bank.requests().is_empty());
    assert!(latch.take_aic_inputs().is_empty());
}

#[test]
fn complete_width_alignment_and_knownness_are_required_without_padding_registers() {
    let mut bank = observed(384, &observations());
    let mut latch = InterruptLatch::new();
    for width in [Width::Word, Width::Double, Width::Quad] {
        assert_eq!(width.bytes(), 4 * u64::try_from(width.words()).unwrap());
        for offset in [
            0,
            UPDATE_OFFSET,
            IRQ_STATUS - 16,
            IRQ_STATUS + 48,
            0x18200,
            0x18300,
            0x18400,
            u64::MAX - 15,
        ] {
            assert!(bank.interrupt_snapshot(offset, width).is_err());
        }
        for delta in 1..width.bytes() {
            assert_eq!(
                bank.interrupt_snapshot(IRQ_STATUS + delta, width),
                Err("PTD IRQ access is not aligned")
            );
        }
    }
    for width in [BusWidth::Byte, BusWidth::Half] {
        assert!(
            bank.read(IRQ_STATUS, width, &mut Access::new(0, 0, &mut latch))
                .is_err()
        );
    }
    assert!(
        bank.read(
            IRQ_STATUS + 4,
            BusWidth::Double,
            &mut Access::new(0, 0, &mut latch)
        )
        .is_err()
    );
    let tiny = observed(65, &observations()[..3]);
    assert_eq!(
        tiny.interrupt_snapshot(IRQ_STATUS + 8, Width::Double),
        Err("PTD IRQ read crosses its bank")
    );
    assert_eq!(
        tiny.interrupt_snapshot(IRQ_STATUS, Width::Quad),
        Err("PTD IRQ read crosses its bank")
    );
    assert_eq!(
        tiny.interrupt_snapshot(IRQ_STATUS + 8, Width::Word)
            .unwrap()
            .low,
        u64::from(PATTERN[2])
    );
    for index in 0..4 {
        let mut observations = observations();
        observations[index].known &= !(1 << 31);
        let bank = observed(384, &observations);
        assert_eq!(
            bank.interrupt_snapshot(IRQ_STATUS, Width::Quad),
            Err("PTD register contains unqualified bits")
        );
        assert!(
            bank.interrupt_snapshot(IRQ_STATUS + 16, Width::Quad)
                .is_ok()
        );
        observations.remove(index);
        assert!(
            observed(384, &observations)
                .interrupt_snapshot(IRQ_STATUS, Width::Quad)
                .is_err()
        );
    }
}

#[test]
fn snapshots_never_consume_metadata_notifications_or_kept_lifecycle() {
    let (mut bank, local) = Ptd::initialized_local(384, &ranges(384), lifecycle()).unwrap();
    let mut latch = InterruptLatch::new();
    for entry in [0u32, 33, 98, 383] {
        let bit = u64::from(1u32 << (entry % 32));
        bank.write(
            0x18200 + u64::from(entry / 32) * 4,
            BusWidth::Word,
            bit,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        for (now, value) in [(7, 0x1234), (9, 0x5678)] {
            bank.write(
                UPDATE_OFFSET + u64::from(entry) * 8,
                BusWidth::Double,
                value + u64::from(entry),
                &mut Access::new(0, now, &mut latch),
            )
            .unwrap();
        }
    }
    let history = bank.requests();
    let first = Snapshot {
        low: 0x0000000200000001,
        high: 0x0000000400000000,
    };
    for _ in 0..3 {
        assert_eq!(
            local
                .bank()
                .interrupt_snapshot(IRQ_STATUS, Width::Quad)
                .unwrap(),
            first
        );
        assert_eq!(
            bank.interrupt_snapshot(IRQ_STATUS + 32, Width::Quad)
                .unwrap(),
            Snapshot {
                low: 0,
                high: 0x8000000000000000
            }
        );
        assert_eq!(local.asserted(), 1);
        assert_eq!(bank.requests(), history);
    }
    let paused = LifecycleState {
        clocked: false,
        ..lifecycle()
    };
    bank.set_lifecycle(paused, &mut Access::new(0, 10, &mut latch));
    for width in [Width::Word, Width::Double, Width::Quad] {
        assert_eq!(
            bank.interrupt_snapshot(IRQ_STATUS, width),
            Err("PTD transport is paused by its actual owner")
        );
    }
    assert_eq!(local.asserted(), 1);
    bank.set_lifecycle(lifecycle(), &mut Access::new(0, 11, &mut latch));
    assert_eq!(
        bank.interrupt_snapshot(IRQ_STATUS, Width::Quad).unwrap(),
        first
    );
    assert!(
        bank.check_lifecycle(LifecycleState {
            reset: true,
            ..lifecycle()
        })
        .is_err()
    );
    for entry in [0u32, 33, 98, 383] {
        let raw = bank
            .consume_entry(entry, &mut Access::new(0, 12, &mut latch))
            .unwrap();
        assert_eq!(raw.value, 0x5678 + u64::from(entry));
        assert_eq!(raw.metadata, 9 << 10 | 3);
    }
    assert_eq!(local.asserted(), 0);
    assert_eq!(
        bank.interrupt_snapshot(IRQ_STATUS, Width::Quad).unwrap(),
        Snapshot { low: 0, high: 0 }
    );
    assert_eq!(
        bank.interrupt_snapshot(IRQ_STATUS + 32, Width::Quad)
            .unwrap(),
        Snapshot { low: 0, high: 0 }
    );
    assert_eq!(bank.requests(), history);
    assert!(latch.take_aic_inputs().is_empty());
}
