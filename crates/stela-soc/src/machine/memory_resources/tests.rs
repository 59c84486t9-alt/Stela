use super::*;
use crate::mcc::RequestKind;
use stela_soc_data::board::PtdBank;

use alloc::{boxed::Box, vec};
use stela_contracts::bus::Bus;
use stela_contracts::interrupt::InterruptLatch;
use stela_soc_data::amcc::LockGroup;

pub(super) fn prepared() -> Prepared {
    let reg = |offset, mask, value| Register {
        offset,
        mask,
        value,
    };
    let locks = MemoryController {
        apertures: vec![0x200000000, 0x201000000],
        layout: Layout {
            aperture_bytes: 0x200000,
            planes: 4,
            stride: mcc::PLANE_STRIDE,
            cache_status: Some(reg(0x1c00, 0x1f, 0)),
            dram_base: 0x800000000,
            groups: [
                Some(LockGroup {
                    page_size_shift: 14,
                    lower_limit: reg(0x680, u32::MAX, 0),
                    upper_limit: reg(0x684, u32::MAX, 0),
                    enable: Some(reg(0x688, 1, 1)),
                    write_disable: None,
                    lock: Some(reg(0x68c, 1, 1)),
                }),
                None,
                None,
                None,
            ],
        },
    };
    let descriptor = DirectMemoryCache {
        apertures: locks.apertures.clone(),
        config_data: vec![1],
        alternate_dram_configuration: 0xffff0000,
        ptd: PtdBank {
            physical: 0x28e3c0000,
            ranges: vec![stela_soc_data::ptd::Range {
                id: 1,
                start: 0,
                count: 2,
                name: "DECLARED".into(),
            }],
            interrupts: vec![14],
        },
        ptd_updates: (0x28e3d0000, 0xc00),
        ptd_entries: 384,
    };
    Prepared::new(
        descriptor,
        &locks,
        stela_soc_data::amcc::ctrr_a(Some((0x800004000, 0x4000))),
        Configuration {
            dram: vec![[7; 4]; 2],
            weights: [1; 32],
        },
        LifecycleState {
            powered: true,
            clocked: true,
            reset: false,
            quiesced: false,
            retention: true,
        },
        [None; 16],
    )
    .unwrap()
}
#[test]
fn joint_resource_has_one_backing_for_broadcast_policy_and_publications() {
    let owner = prepared();
    let controller = owner.controller().clone();
    let publication = owner.publication_bank().clone();
    let bindings = owner.bindings();
    assert_eq!(bindings.len(), 3);
    let mut bus = Bus::new();
    let id = bus.install(Box::new(owner), &bindings).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 17, &mut latch);
    let base = 0x200000000;
    assert_eq!(bus.read(base + 0x10000c, Width::Word, &mut access), Ok(0));
    bus.write(base + 0x10000c, Width::Word, 1, &mut access)
        .unwrap();
    assert_eq!(
        controller
            .observations()
            .iter()
            .find(|word| word.aperture == 0 && word.offset == 0x10000c)
            .unwrap()
            .value,
        1
    );
    // The extra Stela status views share the selector; no
    // independent Amcc disabled/ready values exist behind these addresses.
    for plane in 1..4 {
        assert_eq!(
            bus.read(
                base + 0x10000c + plane * mcc::PLANE_STRIDE,
                Width::Word,
                &mut access
            ),
            Ok(1)
        );
    }
    bus.write(base + 0x1c00, Width::Word, 0, &mut access)
        .unwrap();
    assert_eq!(bus.read(base + 0x1c04, Width::Word, &mut access), Ok(0));
    assert!(
        bus.write(base + 0x1c00, Width::Word, 1, &mut access)
            .is_err()
    );
    bus.write(base + 0x14000, Width::Word, 2, &mut access)
        .unwrap();
    assert!(matches!(
        controller.requests().last().unwrap().kind,
        RequestKind::Deprioritize { dsid: 1, .. }
    ));
    let before = controller.requests();
    assert!(
        bus.write(base + 0x14000, Width::Word, 1, &mut access)
            .is_err()
    );
    assert!(
        bus.write(base + mcc::DCS_BASE + 0xa40, Width::Word, 0, &mut access)
            .is_err()
    );
    assert_eq!(controller.requests(), before);
    // The second aperture reaches the same owner's separate bank.
    bus.write(
        base + mcc::APERTURE_BYTES + 0xa000,
        Width::Word,
        0x10002,
        &mut access,
    )
    .unwrap();
    assert_eq!(
        controller.policy(1, 1, 0).unwrap().configured_quota_bytes(),
        2 << 17
    );
    assert_eq!(
        controller.policy(0, 1, 0).unwrap().configured_quota_bytes(),
        0
    );
    bus.write(0x28e3d0000, Width::Double, 0x1234, &mut access)
        .unwrap();
    assert!(bus.read(0x28e3c0000, Width::Double, &mut access).is_err());
    assert_eq!(
        publication.consume_entry(0, &mut access).unwrap().value,
        0x1234
    );
    assert_eq!(
        bus.device::<Prepared>(id).unwrap().locked_regions(),
        [None; 4]
    );
    // No register beyond AMCC's smaller lock aperture can alias a later
    // aperture's lock plane through a changed device-offset divisor.
    assert!(bus.read(base + 0x200680, Width::Word, &mut access).is_err());
}
#[test]
fn old_mount_paths_refuse_missing_owners_before_publishing_any_aperture() {
    let owner = prepared();
    let mut devices = super::super::AppleDevices::new();
    let mut layout = owner.router.lock_layout;
    let missing = devices.add_memory_controller(
        &[0x400000000],
        layout,
        [None; 4],
        Some(stela_soc_data::amcc::Cache {
            shared: (0x100000, 0x80000),
            broadcast: 0xf00000,
            bytes: 8 << 20,
            ways: 16,
        }),
    );
    assert!(
        missing
            .unwrap_err()
            .to_string()
            .contains("qualified memory, drain and service owner")
    );
    assert!(devices.memory_controller.is_none());
    assert!(devices.bus.route(0x400000680, Width::Word).is_err());
    layout.cache_status = Some(Register {
        offset: 0x10000c,
        mask: 1,
        value: 1,
    });
    assert!(
        devices
            .add_memory_controller(&[0x400000000], layout, [None; 4], None)
            .is_err()
    );
    assert!(devices.bus.route(0x400000680, Width::Word).is_err());
    // Failure at a later aperture must not leave the earlier one mapped.
    layout.cache_status = None;
    let bindings = owner.bindings();
    devices.bus.install(Box::new(owner), &bindings).unwrap();
    assert!(
        devices
            .add_io_access_controller(&[0x400000000, 0x200000000], layout, [None; 4])
            .is_err()
    );
    assert!(devices.bus.route(0x400000680, Width::Word).is_err());
    assert!(devices.bus.route(0x200000680, Width::Word).is_ok());
}

#[test]
fn paused_joint_owner_refuses_locks_and_keeps_checked_state() {
    let mut owner = prepared();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert_eq!(owner.read(0x680, Width::Word, &mut access), Ok(1));
    let running = owner.controller().lifecycle_state();
    let paused = LifecycleState {
        clocked: false,
        ..running
    };
    owner.set_lifecycle(paused, &mut access);
    assert!(owner.read(0x680, Width::Word, &mut access).is_err());
    assert!(owner.write(0x688, Width::Word, 1, &mut access).is_err());
    owner.set_lifecycle(running, &mut access);
    assert_eq!(owner.read(0x680, Width::Word, &mut access), Ok(1));
    assert!(
        owner
            .check_lifecycle(LifecycleState {
                reset: true,
                ..running
            })
            .is_err()
    );
    assert!(
        owner
            .check_lifecycle(LifecycleState {
                powered: false,
                retention: false,
                ..running
            })
            .is_err()
    );
    owner.write(0x688, Width::Word, 1, &mut access).unwrap();
    assert_eq!(owner.locked_regions()[0], Some((0x800004000, 0x800007fff)));
    for aperture in 0..2 {
        for plane in 0..4 {
            owner
                .write(
                    aperture * mcc::APERTURE_BYTES + plane * mcc::PLANE_STRIDE + 0x688,
                    Width::Word,
                    1,
                    &mut access,
                )
                .unwrap();
        }
    }
    assert_eq!(owner.locked_regions()[0], Some((0x800004000, 0x800007fff)));
}

#[test]
fn paired_read_consumes_only_the_complete_publication_entry() {
    use stela_engine::machine::Devices;
    let owner = prepared();
    let offset = owner.ptd_offset();
    assert_eq!(owner.publication_layout().entry(offset, 8), Some(0));
    assert_eq!(
        owner.publication_layout().entry(offset + 383 * 16, 8),
        Some(383)
    );
    for (offset, bytes) in [
        (offset, 4),
        (offset + 8, 8),
        (offset + 384 * 16, 8),
        (offset + stela_soc_data::ptd::UPDATE_OFFSET, 8),
        (0, 8),
    ] {
        assert_eq!(owner.publication_layout().entry(offset, bytes), None);
    }
    let publication = owner.publication_bank().clone();
    let bindings = owner.bindings();
    let mut board = super::super::AppleDevices::new();
    let id = board.bus.install(Box::new(owner), &bindings).unwrap();
    board.memory_controller = Some(id);
    let mut access = Access::new(0, 17, &mut board.latch);
    board
        .bus
        .write(0x28e3d0000, Width::Double, 0x1234, &mut access)
        .unwrap();
    // Probing an unrelated width/half must not consume or settle anything.
    assert_eq!(board.read_pair(0, 0x28e3c0000, 4, 17), Ok(None));
    assert_eq!(board.read_pair(0, 0x28e3c0008, 8, 17), Ok(None));
    let pair = board.read_pair(0, 0x28e3c0000, 8, 17).unwrap().unwrap();
    assert_eq!(pair.values[0], 0x1234);
    assert!(pair.values[1] & 2 != 0);
    assert_eq!(pair.settlement, Ok(()));
    let mut access = Access::new(0, 17, &mut board.latch);
    let consumed = publication.consume_entry(0, &mut access).unwrap();
    assert_eq!(consumed.value, 0x1234);
    assert_eq!(consumed.metadata & 3, 0);
    // CPU and DMA callers query the very same prepared lock owner.
    board
        .bus
        .write(0x200000688, Width::Word, 1, &mut access)
        .unwrap();
    assert_eq!(board.memory_lock()[0], Some((0x800004000, 0x800007fff)));
}

#[test]
fn local_constructor_returns_the_same_publication_and_notification_owner() {
    let original = prepared();
    let lifecycle = original.controller().lifecycle_state();
    let mut locks = MemoryController {
        apertures: original.descriptor.apertures.clone(),
        layout: original.router.lock_layout,
    };
    // Router removed this alias from Amcc because the MCC
    // controller owns it. Reconstruct the source descriptor, not that
    // already-normalized private lock-only view.
    locks.layout.cache_status = Some(Register {
        offset: 0x1c00,
        mask: 0x1f,
        value: 0,
    });
    let (mut owner, local) = Prepared::new_local(
        original.descriptor,
        &locks,
        [None; 4],
        Configuration {
            dram: vec![[7; 4]; 2],
            weights: [1; 32],
        },
        lifecycle,
    )
    .unwrap();
    assert!(local.owns(owner.publication_bank()));
    assert_eq!(local.asserted(), 0);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 17, &mut latch);
    let base = owner.ptd_offset();
    owner
        .write(base + 0x18400, Width::Word, 3, &mut access)
        .unwrap();
    owner
        .write(base + 0x18200, Width::Word, 1, &mut access)
        .unwrap();
    owner
        .write(
            base + stela_soc_data::ptd::UPDATE_OFFSET,
            Width::Double,
            0x1234,
            &mut access,
        )
        .unwrap();
    assert_eq!(local.asserted(), 1 << 3);
    assert_eq!(
        owner
            .publication_bank()
            .consume_entry(0, &mut access)
            .unwrap()
            .value,
        0x1234
    );
    assert_eq!(local.asserted(), 0);
    assert!(latch.take_aic_inputs().is_empty());
}

#[test]
fn paired_read_keeps_data_and_pending_service_after_wire_forwarding_refusal() {
    use stela_contracts::interrupt::AicInput;
    use stela_contracts::interrupt::InterruptSink;
    use stela_engine::machine::Devices;
    let owner = prepared();
    let publication = owner.publication_bank().clone();
    let bindings = owner.bindings();
    let mut board = super::super::AppleDevices::new();
    board.bus.install(Box::new(owner), &bindings).unwrap();
    let mut access = Access::new(0, 17, &mut board.latch);
    board
        .bus
        .write(0x28e3d0000, Width::Double, 0x5678, &mut access)
        .unwrap();
    // This queued wire has no AIC receiver. Its failed
    // forwarding follows consumption and must not erase the read result.
    board.latch.set_level(Wire::Aic(AicInput::new(0, 3)), true);
    let pair = board.read_pair(0, 0x28e3c0000, 8, 17).unwrap().unwrap();
    assert_eq!(pair.values[0], 0x5678);
    assert!(pair.values[1] & 2 != 0);
    assert!(pair.settlement.is_err());
    assert_eq!(board.pending_service().unwrap().committed(), 0);
    assert_eq!(board.pending_service().unwrap().inputs().len(), 1);
    let mut access = Access::new(0, 17, &mut board.latch);
    assert_eq!(
        publication.consume_entry(0, &mut access).unwrap().metadata & 3,
        0
    );
}

#[test]
fn status_pairs_snapshot_one_pending_bank_without_consuming_publications() {
    use crate::ptd::transport::IRQ_STATUS;
    use stela_engine::machine::Devices;
    let owner = prepared();
    let bindings = owner.bindings();
    let mut board = super::super::AppleDevices::new();
    board.bus.install(Box::new(owner), &bindings).unwrap();
    let mut access = Access::new(0, 17, &mut board.latch);
    for entry in [0, 33, 65] {
        board
            .bus
            .write(
                0x28e3d0000 + entry * 8,
                Width::Double,
                entry + 0x1000,
                &mut access,
            )
            .unwrap();
    }
    let status = 0x28e3c0000 + IRQ_STATUS;
    for _ in 0..2 {
        let narrow = board.read_pair(0, status, 4, 17).unwrap().unwrap();
        assert_eq!(narrow.values, [1, 2]);
        assert_eq!(narrow.settlement, Ok(()));
        let wide = board.read_pair(0, status, 8, 17).unwrap().unwrap();
        assert_eq!(wide.values, [0x0000000200000001, 2]);
        assert_eq!(wide.settlement, Ok(()));
    }
    // The last status pair cannot extend past the twelve words.
    assert_eq!(board.read_pair(0, status + 40, 8, 17), Ok(None));
    // Only a publication read consumes its pending flag.
    assert_eq!(
        board
            .read_pair(0, 0x28e3c0000, 8, 17)
            .unwrap()
            .unwrap()
            .values[0],
        0x1000
    );
    assert_eq!(
        board.read_pair(0, status, 8, 17).unwrap().unwrap().values,
        [0x0000000200000000, 2]
    );
}

#[test]
fn original_cache_status_reads_the_same_per_plane_way_commands() {
    let mut owner = prepared();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 3, &mut latch);
    for aperture in 0..2 {
        let base = aperture * mcc::APERTURE_BYTES;
        for plane in 0..u64::from(mcc::PLANES) {
            let status = base + plane * mcc::PLANE_STRIDE + 0x1c00;
            assert_eq!(owner.read(status, Width::Word, &mut access), Ok(0));
            owner.write(status, Width::Word, 0, &mut access).unwrap();
            assert_eq!(owner.read(status, Width::Word, &mut access), Ok(0));
            assert!(owner.write(status, Width::Word, 1, &mut access).is_err());
            assert_eq!(owner.read(status, Width::Word, &mut access), Ok(0));
        }
        // Changing broadcast selects scope; it cannot invent powered
        // ways or change the separate original cache-status word.
        owner
            .write(base + 0x10000c, Width::Word, 1, &mut access)
            .unwrap();
        assert_eq!(owner.read(base + 0x1c00, Width::Word, &mut access), Ok(0));
    }
    let original = prepared();
    let mut layout = original.router.lock_layout;
    for invalid in [
        Register {
            offset: 0x10000c,
            mask: 1,
            value: 1,
        },
        Register {
            offset: 0x1c00,
            mask: 1,
            value: 0,
        },
        Register {
            offset: 0x1c00,
            mask: 0x1f,
            value: 1,
        },
    ] {
        layout.cache_status = Some(invalid);
        let controller = original.controller().clone();
        assert!(Router::new(layout, [None; 4], controller, 2).is_err());
    }
}

#[test]
fn native_memory_preflight_matches_live_descriptors_and_ram() {
    let (memory, cache) = t8112::cache::EmptyResource::service_test_components();
    let descriptor = memory.descriptor().clone();
    let controller = cache.source().clone();
    let resources = MemoryResources::T8112 { memory, cache };
    assert_eq!(
        resources.validate(Some(&controller), Some(&descriptor), None),
        Ok(())
    );

    let mut changed = descriptor.clone();
    changed.ptd.interrupts[0] ^= 1;
    assert!(
        resources
            .validate(Some(&controller), Some(&changed), None)
            .is_err()
    );
    let mut changed = controller.clone();
    changed.apertures[0] += 0x40000;
    assert!(
        resources
            .validate(Some(&changed), Some(&descriptor), None)
            .is_err()
    );
    assert!(resources.validate(None, Some(&descriptor), None).is_err());
    assert!(resources.validate(Some(&controller), None, None).is_err());

    let (memory, _) = t8112::cache::EmptyResource::service_test_components();
    let (_, cache) = t8112::cache::EmptyResource::service_test_components();
    assert!(
        MemoryResources::T8112 { memory, cache }
            .validate(Some(&controller), Some(&descriptor), None)
            .unwrap_err()
            .to_string()
            .contains("same actual registered RAM")
    );
}
