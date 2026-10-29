use super::*;
use alloc::boxed::Box;
use {stela_contracts::bus::Bus, stela_contracts::interrupt::InterruptLatch};

fn snapshot(kind: Kind, value: u32) -> Power {
    Power::from_snapshot(
        kind,
        kind.offsets().into_iter().map(|offset| (offset, value)),
    )
    .unwrap()
}
#[test]
fn unknown_handoff_is_never_zero_marker_unlocked_channel_or_healthy_status() {
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    for kind in [
        Kind::Volman,
        Kind::Marker,
        Kind::Gpce,
        Kind::Cio,
        Kind::GpceFinalize,
        Kind::NubBindings,
        Kind::Gating,
        Kind::Tvm,
    ] {
        let mut model = Power::new(kind);
        for offset in kind.offsets() {
            assert!(matches!(
                model.read(offset, Width::Word, &mut access),
                Err(MmioError::Unsupported {
                    reason: "SOC power handoff register value is unknown",
                    ..
                })
            ));
            assert!(model.write(offset, Width::Word, 0, &mut access).is_err());
        }
        assert!(model.pending_gpce().next().is_none());
    }
    assert!(matches!(
        Power::from_snapshot(Kind::Gpce, [(0, 0)]),
        Err(SnapshotError::Missing(4))
    ));
    assert!(matches!(
        Power::from_snapshot(Kind::Gpce, [(0, 0), (0, 0)]),
        Err(SnapshotError::Duplicate(0))
    ));
    assert!(matches!(
        Power::from_snapshot(Kind::Gpce, [(8, 0)]),
        Err(SnapshotError::UnknownOffset(8))
    ));
}
#[test]
fn mounted_gpce_preserves_real_busy_and_keeps_request_without_fake_readiness() {
    let mut bus = Bus::new();
    let id = bus.add(Box::new(
        Power::from_snapshot(Kind::Gpce, [(0, 0x120), (4, 0x830)]).unwrap(),
    ));
    bus.map(id, 0x23b780000, 8, 0).unwrap();
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    assert_eq!(bus.read(0x23b780004, Width::Word, &mut access), Ok(0x830));
    bus.write(0x23b780000, Width::Word, 0x12f, &mut access)
        .unwrap();
    assert!(bus.read(0x23b780000, Width::Word, &mut access).is_err());
    assert_eq!(bus.read(0x23b780004, Width::Word, &mut access), Ok(0x830));
    // Software cannot clear BUSY or overwrite the first pending request.
    assert!(
        bus.write(0x23b780000, Width::Word, 0x120, &mut access)
            .is_err()
    );
    let model = bus.device_mut::<Power>(id).unwrap();
    assert_eq!(
        model.pending_gpce().collect::<Vec<_>>(),
        [GpceRequest {
            offset: 0,
            previous: 0x120,
            written: 0x12f
        }]
    );
    assert!(model.advance(&mut access).is_err());
    assert_eq!(model.pending_gpce().count(), 1);
    assert!(model.write(4, Width::Word, 0x82f, &mut access).is_err());
    assert!(model.write(4, Width::Word, 0x833, &mut access).is_err());
    assert_eq!(model.read(4, Width::Word, &mut access), Ok(0x830));
}

#[test]
fn mounted_cio_preserves_both_ports_and_request_ownership_before_unknown_pc_selection() {
    let mut bus = Bus::new();
    let id = bus.add(Box::new(
        Power::from_snapshot(Kind::Cio, [(0x4000, 0xa0), (0x8000, 0xb1)]).unwrap(),
    ));
    bus.map(id, 0x23b78c000, 0x9000, 0).unwrap();
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    // Refuse a made-up disable and unrelated field changes before effects.
    assert!(
        bus.write(0x23b794000, Width::Word, 0xb0, &mut access)
            .is_err()
    );
    assert!(
        bus.write(0x23b790000, Width::Word, 0x81, &mut access)
            .is_err()
    );
    assert_eq!(bus.read(0x23b794000, Width::Word, &mut access), Ok(0xb1));
    // A same-value bit0 request is still an owned original write. Never
    // mark it idempotent or use it to claim an already completed program.
    bus.write(0x23b794000, Width::Word, 0xb1, &mut access)
        .unwrap();
    assert!(bus.read(0x23b794000, Width::Word, &mut access).is_err());
    assert!(
        bus.write(0x23b794000, Width::Word, 0xb1, &mut access)
            .is_err()
    );
    assert_eq!(bus.read(0x23b790000, Width::Word, &mut access), Ok(0xa0));
    bus.write(0x23b790000, Width::Word, 0xa1, &mut access)
        .unwrap();
    let model = bus.device_mut::<Power>(id).unwrap();
    assert_eq!(
        model.pending_cio().collect::<Vec<_>>(),
        [
            CioRequest {
                offset: 0x8000,
                previous: 0xb1,
                written: 0xb1
            },
            CioRequest {
                offset: 0x4000,
                previous: 0xa0,
                written: 0xa1
            },
        ]
    );
    assert!(model.advance(&mut access).is_err());
    assert_eq!(model.pending_cio().count(), 2);
    assert!(model.read(0, Width::Word, &mut access).is_err());
    assert!(model.read(0x4000, Width::Double, &mut access).is_err());
}

#[test]
fn captured_unready_gpce_and_cio_work_cannot_become_an_empty_idle_queue() {
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    for (kind, entries, mask) in [
        (Kind::Gpce, [(0, 0x10), (4, 0x2f)], 0x10),
        (Kind::Cio, [(0x4000, 0xa2), (0x8000, 0xb1)], 2),
    ] {
        let mut model = Power::from_snapshot(kind, entries).unwrap();
        assert_eq!(
            model.pending_gpce().count() + model.pending_cio().count(),
            0
        );
        assert_eq!(
            model.unresolved_readiness().collect::<Vec<_>>(),
            [UnresolvedReadiness {
                offset: entries[0].0,
                observed: entries[0].1,
                mask
            }]
        );
        assert_eq!(
            model.read(entries[0].0, Width::Word, &mut access),
            Ok(u64::from(entries[0].1))
        );
        assert!(model.advance(&mut access).is_err());
        assert_eq!(model.unresolved_readiness().count(), 1);
        assert_eq!(
            model.read(entries[0].0, Width::Word, &mut access),
            Ok(u64::from(entries[0].1))
        );
    }
}

#[test]
fn gpce_finalization_keeps_ordered_masked_effects_without_clearing_native_progress() {
    let mut bus = Bus::new();
    let id = bus.add(Box::new(
        Power::from_snapshot(Kind::GpceFinalize, [(0x2008, 0x123), (0x200c, 0x456)]).unwrap(),
    ));
    bus.map(id, 0x23b782008, 8, 0x2008).unwrap();
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    assert!(bus.write(0x23b782008, Width::Word, 0, &mut access).is_err());
    let first = bus.read(0x23b782008, Width::Word, &mut access).unwrap();
    bus.write(0x23b782008, Width::Word, first & !1, &mut access)
        .unwrap();
    assert_eq!(bus.read(0x23b782008, Width::Word, &mut access), Ok(0x122));
    // Later unchecked rearm refuses without erasing the first write.
    assert!(
        bus.write(0x23b78200c, Width::Word, 0x457, &mut access)
            .is_err()
    );
    assert_eq!(bus.read(0x23b78200c, Width::Word, &mut access), Ok(0x456));
    let second = bus.read(0x23b78200c, Width::Word, &mut access).unwrap();
    // The original RMW stores even when the bit was already clear.
    bus.write(0x23b78200c, Width::Word, second & !1, &mut access)
        .unwrap();
    let model = bus.device_mut::<Power>(id).unwrap();
    assert_eq!(
        model.pending_configuration().collect::<Vec<_>>(),
        [
            ConfigurationRequest {
                offset: 0x2008,
                previous: 0x123,
                written: 0x122
            },
            ConfigurationRequest {
                offset: 0x200c,
                previous: 0x456,
                written: 0x456
            },
        ]
    );
    assert!(model.advance(&mut access).is_err());
    assert_eq!(model.pending_configuration().count(), 2);
    assert!(
        model
            .write(0x2008, Width::Word, 0x122, &mut access)
            .is_err()
    );
}

#[test]
fn native_gpce_status_control_fields_do_not_gain_semantics_from_the_ap_request_setter() {
    let mut model = Power::from_snapshot(Kind::Gpce, [(0, 0xf), (4, 0x2f)]).unwrap();
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    // Original native programs use bit5 too; its hardware effect cannot
    // be invented from the AP driver's preserving low4 update.
    assert!(model.write(0, Width::Word, 0x2f, &mut access).is_err());
    assert!(model.write(4, Width::Word, 0xf, &mut access).is_err());
    assert_eq!(model.read(0, Width::Word, &mut access), Ok(0xf));
    assert_eq!(model.read(4, Width::Word, &mut access), Ok(0x2f));
    assert_eq!(model.pending_gpce().count(), 0);
}
#[test]
fn tvm_keeps_config_and_other_domains_without_claiming_idle_progress() {
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    let mut model = snapshot(Kind::Tvm, 0x123);
    model.write(0x400, Width::Word, 0x122, &mut access).unwrap();
    assert_eq!(model.read(0x400, Width::Word, &mut access), Ok(0x122));
    assert!(model.read(0x7e0, Width::Word, &mut access).is_err());
    assert_eq!(model.read(0x3e0, Width::Word, &mut access), Ok(0x123));
    assert!(model.write(0x7e0, Width::Word, 0, &mut access).is_err());
    assert!(model.advance(&mut access).is_err());
}
#[test]
fn captured_volman_errors_acknowledge_without_replacing_them_with_health() {
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    let mut model = snapshot(Kind::Volman, 0);
    model.registers.insert(STATUS, Word::captured(0x120035));
    model.write(STATUS, Width::Word, 5, &mut access).unwrap();
    assert_eq!(model.read(STATUS, Width::Word, &mut access), Ok(0x120030));
    assert!(
        model
            .write(STATUS, Width::Word, 0x10000, &mut access)
            .is_err()
    );
    model
        .write(0x30, Width::Word, LOCK | 7, &mut access)
        .unwrap();
    assert!(model.write(0x30, Width::Word, 0, &mut access).is_err());
    model
        .write(MASK, Width::Word, 0xff000, &mut access)
        .unwrap();
    model.write(FINAL, Width::Word, 1, &mut access).unwrap();
    assert_eq!(model.read(FINAL, Width::Word, &mut access), Ok(1));
    assert!(model.read(STATUS, Width::Word, &mut access).is_err());
    assert!(model.advance(&mut access).is_err());
}
#[test]
fn native_binding_guards_and_pending_requests_preserve_order() {
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    let mut gpce = Power::from_snapshot(Kind::Gpce, [(0, 0x120), (4, 0x830)]).unwrap();
    gpce.write(4, Width::Word, 0x83f, &mut access).unwrap();
    gpce.write(0, Width::Word, 0x12f, &mut access).unwrap();
    assert_eq!(
        gpce.pending_gpce()
            .map(|request| request.offset)
            .collect::<Vec<_>>(),
        [4, 0]
    );
    let mut bindings = snapshot(Kind::NubBindings, 0);
    bindings.registers.insert(0x23d2d0200, Word::captured(1));
    assert!(
        bindings
            .write(0x23d2d0200, Width::Word, 0x5000, &mut access)
            .is_err()
    );
    assert_eq!(bindings.read(0x23d2d0200, Width::Word, &mut access), Ok(1));
    assert_eq!(bindings.pending_configuration().count(), 0);
    bindings
        .write(0x23d2d0204, Width::Word, 0x103, &mut access)
        .unwrap();
    bindings
        .write(0x23d2d0204, Width::Word, 0x1090103, &mut access)
        .unwrap();
    assert!(
        bindings
            .write(0x23d2d0204, Width::Word, 0, &mut access)
            .is_err()
    );
    bindings
        .write(0x23b781004, Width::Word, 1, &mut access)
        .unwrap();
    assert!(
        bindings
            .write(0x23b781004, Width::Word, 0, &mut access)
            .is_err()
    );
    assert_eq!(
        bindings
            .pending_configuration()
            .map(|request| request.offset)
            .collect::<Vec<_>>(),
        [0x23d2d0204, 0x23d2d0204, 0x23b781004]
    );
    assert!(bindings.advance(&mut access).is_err());
}

#[test]
fn marker_and_gating_preserve_supplied_values_without_inventing_power_edges() {
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    let mut marker = snapshot(Kind::Marker, 0xdeadbeef);
    assert_eq!(
        marker.read(MARKER, Width::Word, &mut access),
        Ok(0xdeadbeef)
    );
    assert!(marker.write(MARKER, Width::Word, 0, &mut access).is_err());
    let mut gating = snapshot(Kind::Gating, 0x80000001);
    gating
        .write(0, Width::Word, 0x80000023, &mut access)
        .unwrap();
    assert_eq!(gating.read(0, Width::Word, &mut access), Ok(0x80000023));
    assert_eq!(gating.read(0x40, Width::Word, &mut access), Ok(0x80000001));
    assert!(gating.write(3, Width::Word, 0, &mut access).is_err());
    assert!(gating.read(0, Width::Double, &mut access).is_err());
}
