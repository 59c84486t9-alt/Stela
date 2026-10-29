use super::*;
use crate::machine::apple::AppleDevices;
use stela_soc_data::board::PtdBank;

use alloc::{boxed::Box, vec};
use core::{cell::UnsafeCell, ptr::NonNull};
use stela_contracts::interrupt::InterruptLatch;
use stela_engine::machine::Devices;
use stela_engine::memory::ReservedSystemRamRange;
use stela_engine::memory::system_ram::fixture;
const DCS: u64 = 0x201000000;
const PTD: u64 = 0x23b3c0000;
const DRAIN: u64 = 0xa40;
const LIVE: LifecycleState = LifecycleState {
    powered: true,
    clocked: true,
    quiesced: false,
    reset: false,
    retention: true,
};
#[repr(C, align(16))]
struct Storage(UnsafeCell<[u8; 128]>);
// SAFETY: fixture reservation has no Rust references after registration.
unsafe impl Sync for Storage {}
pub(super) fn ram_at(source_pa: u64) -> Arc<RegisteredSystemRam> {
    let storage = Arc::new(Storage(UnsafeCell::new([0; 128])));
    let range = ReservedSystemRamRange {
        source_pa,
        host_pa: 0x400000,
        host_base: NonNull::new(storage.0.get().cast()).unwrap(),
        bytes: 128,
    };
    // SAFETY: fixture exclusively owns these stable bytes and closed writers.
    Arc::new(unsafe { fixture(&[range], storage) })
}
pub(super) fn ram() -> Arc<RegisteredSystemRam> {
    ram_at(0x800000000)
}
pub(super) fn configuration() -> Vec<ChannelConfiguration> {
    (0..CHANNELS)
        .map(|i| ChannelConfiguration {
            ec8: 0x12340000 + i as u32,
            ed0: 0x56780000 + i as u32,
            gating: 0,
            drain_high: 0x9000 + i as u16,
        })
        .collect()
}
pub(super) fn descriptor() -> MemoryCache {
    MemoryCache {
        // Cache/AMCC are not part of this composition.
        cache: stela_soc_data::amcc::Cache {
            shared: (0, 0),
            broadcast: 0,
            bytes: 0,
            ways: 0,
        },
        channels: (DCS, DCS_BYTES, CHANNELS),
        ptd: PtdBank {
            physical: PTD,
            ranges: vec![stela_soc_data::ptd::Range {
                id: 73,
                start: 0,
                count: 256,
                name: "fixture".into(),
            }],
            interrupts: vec![0xfedcba98],
        },
        ptd_updates: (PTD + stela_soc_data::ptd::UPDATE_OFFSET, 0x4000),
        ptd_entries: ALIAS_ENTRIES,
    }
}
fn owner(ram: Arc<RegisteredSystemRam>) -> Prepared {
    Prepared::initialized(descriptor(), configuration(), LIVE, ram).unwrap()
}
#[test]
fn source_placement_and_native_capacity_are_checked_before_publication() {
    let baseline = descriptor();
    let mut cases = Vec::new();
    for (physical, bytes, channels) in [
        (DCS, DCS_BYTES, 7),
        (DCS, DCS_BYTES - 4, 8),
        (DCS + 4, DCS_BYTES, 8),
        (u64::MAX - 3, DCS_BYTES, 8),
        (PTD & !(CHANNEL_STRIDE - 1), DCS_BYTES, 8),
    ] {
        let mut d = baseline.clone();
        d.channels = (physical, bytes, channels);
        cases.push(d);
    }
    let mut d = baseline.clone();
    d.ptd_entries = 256;
    cases.push(d);
    let mut d = baseline.clone();
    d.ptd_updates.1 = 256 * 8;
    cases.push(d);
    let mut d = baseline.clone();
    d.ptd_updates.0 += 8;
    cases.push(d);
    let mut d = baseline.clone();
    d.ptd.ranges[0].count = 257;
    cases.push(d);
    let mut d = baseline.clone();
    d.ptd.interrupts.clear();
    cases.push(d);
    for d in cases {
        assert!(Prepared::initialized(d, configuration(), LIVE, ram()).is_err());
    }
    assert!(
        Prepared::initialized(baseline.clone(), configuration()[..7].to_vec(), LIVE, ram())
            .is_err()
    );
    assert!(Prepared::initialized(baseline, configuration(), LIVE, ram_at(DCS)).is_err());
    let owner = owner(ram());
    assert_eq!(owner.descriptor().ptd.interrupts, [0xfedcba98]);
    assert_eq!(owner.descriptor().ptd_entries, 2048);
}
#[test]
fn publication_aliases_and_pairs_keep_one_actual_256_entry_local_bank() {
    let ram = ram();
    let owner = owner(Arc::clone(&ram));
    assert!(Arc::ptr_eq(owner.registered_ram(), &ram));
    let local = owner.notifications().clone();
    let publication = owner.publication_bank().clone();
    assert!(local.owns(&publication));
    assert!(!local.owns(owner_for_other_bank().publication_bank()));
    let update = owner
        .display_publication_view(PTD + stela_soc_data::ptd::UPDATE_OFFSET, 0x4000)
        .unwrap();
    let mut board = AppleDevices::new();
    board.add_t8112_memory_resources(owner).unwrap();
    let id = board.memory_publication.unwrap();
    assert!(board.memory_controller.is_none());
    assert_eq!(
        board.bus.route(PTD + 255 * 16, Width::Double),
        Ok((id, PTD_OFFSET + 255 * 16))
    );
    assert_eq!(board.bus.route(update.0, Width::Double), Ok((id, update.2)));
    board
        .bus
        .shared_view(id, update.0, update.1, update.2)
        .unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 7, &mut latch);
    for (offset, value) in [(0x18400 + 31 * 4, 15 << 28), (0x18200 + 7 * 4, 1 << 31)] {
        board
            .bus
            .write(PTD + offset, Width::Word, value, &mut access)
            .unwrap();
    }
    board
        .bus
        .write(update.0 + 255 * 8, Width::Double, 0x1234, &mut access)
        .unwrap();
    assert_eq!(local.asserted(), 1 << 15);
    assert!(
        board
            .bus
            .write(update.0 + 256 * 8, Width::Double, 9, &mut access)
            .is_err()
    );
    let resource = super::super::resource_for(&board.bus, id).unwrap();
    assert_eq!(
        resource.publication_binding().unwrap(),
        (PTD, stela_soc_data::ptd::PTD_BYTES, PTD_OFFSET)
    );
    assert_eq!(
        resource.display_publication_view(update.0, update.1),
        Ok(update)
    );
    let pair = board.read_pair(0, PTD + 255 * 16, 8, 7).unwrap().unwrap();
    pair.settlement.unwrap();
    let pair = pair.values;
    assert_eq!(pair[0], 0x1234);
    assert_ne!(pair[1] & 2, 0);
    assert_eq!(local.asserted(), 0);
    assert_eq!(
        publication
            .consume_entry(255, &mut access)
            .unwrap()
            .metadata
            & 3,
        0
    );
    let resource = super::super::resource_for(&board.bus, id).unwrap();
    for (offset, bytes) in [
        (PTD_OFFSET + 256 * 16, 8),
        (PTD_OFFSET + 8, 8),
        (PTD_OFFSET, 4),
        (PTD_OFFSET + stela_soc_data::ptd::UPDATE_OFFSET, 8),
        (DRAIN, 8),
    ] {
        assert!(!resource.supports_pair(offset, bytes));
        assert!(
            resource
                .read_pair_values(offset, bytes, &mut access)
                .is_err()
        );
    }
    assert!(latch.take_aic_inputs().is_empty());
}
#[test]
fn placement_keeps_actual_amcc_lock_identity_and_refuses_a_second_publication_owner() {
    let mut board = AppleDevices::new();
    let reg = |offset| stela_soc_data::amcc::Register {
        offset,
        mask: u32::MAX,
        value: 1,
    };
    let layout = stela_soc_data::amcc::Layout {
        aperture_bytes: 0x1000,
        planes: 1,
        stride: 0x1000,
        cache_status: None,
        dram_base: 0x800000000,
        groups: [
            Some(stela_soc_data::amcc::LockGroup {
                page_size_shift: 14,
                lower_limit: reg(0x680),
                upper_limit: reg(0x684),
                enable: Some(reg(0x688)),
                write_disable: Some(reg(0x68c)),
                lock: Some(reg(0x690)),
            }),
            None,
            None,
            None,
        ],
    };
    let programmed = stela_soc_data::amcc::ctrr_a(Some((0x800004000, 0x4000)));
    board
        .add_memory_controller(&[0x400000000], layout, programmed, None)
        .unwrap();
    let lock = board.memory_controller.unwrap();
    board.write(0, 0x400000688, 4, 1, 0).unwrap();
    let before = board.memory_lock();
    assert_eq!(before, [Some((0x800004000, 0x800007fff)), None, None, None]);
    board.add_t8112_memory_resources(owner(ram())).unwrap();
    let publication = board.memory_publication.unwrap();
    assert_ne!(lock, publication);
    assert_eq!(board.memory_controller, Some(lock));
    assert_eq!(board.memory_lock(), before);
    assert_eq!(board.bus.route(0x400000680, Width::Word), Ok((lock, 0x680)));
    let route = board.bus.route(PTD, Width::Double).unwrap();
    assert_eq!(route.0, publication);
    assert!(board.add_t8112_memory_resources(owner(ram())).is_err());
    assert_eq!(board.memory_publication, Some(publication));
    assert_eq!(board.bus.route(PTD, Width::Double), Ok(route));
    assert_eq!(board.memory_lock(), before);
}
fn owner_for_other_bank() -> Prepared {
    owner(ram())
}
#[test]
fn status_pairs_cover_only_native_words_and_do_not_consume_publications() {
    let mut owner = owner(ram());
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 5, &mut latch);
    owner
        .write(
            PTD_OFFSET + stela_soc_data::ptd::UPDATE_OFFSET,
            Width::Double,
            7,
            &mut access,
        )
        .unwrap();
    let first = PTD_OFFSET + IRQ_STATUS;
    assert_eq!(
        owner.read_pair_values(first, 8, &mut access).unwrap()[0] & 1,
        1
    );
    assert!(owner.supports_pair(first + 16, 8));
    assert!(!owner.supports_pair(first + 24, 8));
    assert!(owner.supports_pair(first + 24, 4));
    assert!(!owner.supports_pair(first + 32, 4));
    assert_ne!(
        owner.read_pair_values(PTD_OFFSET, 8, &mut access).unwrap()[1] & 2,
        0
    );
    for (physical, bytes) in [
        (PTD, 0x4000),
        (PTD + stela_soc_data::ptd::UPDATE_OFFSET, 0x3ff8),
        (PTD + stela_soc_data::ptd::UPDATE_OFFSET, 0x10008),
        (u64::MAX, 16),
    ] {
        assert!(owner.display_publication_view(physical, bytes).is_err());
    }
}
#[test]
fn canonical_dispatch_requires_the_same_ram_and_preserves_consuming_drain_effects() {
    let ram = ram();
    let foreign = ram_at(0x800000000);
    let owner = owner(Arc::clone(&ram));
    let bindings = owner.bindings();
    let mut board = AppleDevices::new();
    let id = board.bus.install(Box::new(owner), &bindings).unwrap();
    assert!(board.read(0, DCS + DRAIN, 4, 0).is_err());
    assert!(board.write(0, DCS + DRAIN, 4, 0x90000000, 0).is_err());
    let service = ram.try_service().unwrap().unwrap();
    let other = foreign.try_service().unwrap().unwrap();
    for i in 0..CHANNELS {
        let offset = i as u64 * CHANNEL_STRIDE + DRAIN;
        assert!(board.read_needs_ram(
            DCS + offset,
            stela_engine::machine::engine::DeviceReadShape::Scalar { bytes: 4 }
        ));
        assert!(!board.read_needs_ram(
            DCS + offset,
            stela_engine::machine::engine::DeviceReadShape::Scalar { bytes: 8 }
        ));
        let resource = super::super::resource_for(&board.bus, id).unwrap();
        // SAFETY: no PE/background publisher exists; all fixture gates and exclusive board ownership remain held.
        unsafe {
            assert!(
                resource
                    .read_ram_drain(offset, Width::Word, &other)
                    .is_err()
            );
            assert!(
                resource
                    .write_ram_drain(offset, Width::Word, 0, 1, &other)
                    .is_err()
            );
            assert!(
                resource
                    .read_ram_drain(offset, Width::Double, &service)
                    .is_err()
            );
            let value = resource
                .read_ram_drain(offset, Width::Word, &service)
                .unwrap();
            assert_eq!(value, (0x9000 + i as u64) << 16);
            assert!(
                resource
                    .write_ram_drain(offset, Width::Word, value | 1, 2, &service)
                    .is_err()
            );
            resource
                .write_ram_drain(offset, Width::Word, value, 3, &service)
                .unwrap();
        }
    }
    let owner = board.bus.device::<Prepared>(id).unwrap();
    for progress in owner.progress() {
        assert_eq!(progress.completed_drains, 1);
        assert_eq!(progress.latest_drain.unwrap().at, 3);
    }
}
#[test]
fn missing_effects_and_joint_lifecycle_refuse_without_claiming_completion() {
    let ram = ram();
    let mut owner = owner(Arc::clone(&ram));
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 9, &mut latch);
    assert_eq!(owner.read(0x41c, Width::Word, &mut access), Ok(0x14a));
    for offset in [0x4000, DCS_BYTES + stela_soc_data::ptd::PTD_BYTES] {
        assert!(owner.read(offset, Width::Word, &mut access).is_err());
    }
    let paused = LifecycleState {
        quiesced: true,
        ..LIVE
    };
    owner.set_lifecycle(paused, &mut access);
    assert_eq!(owner.publication_bank().lifecycle_state(), paused);
    assert!(owner.read(0xec8, Width::Word, &mut access).is_err());
    assert!(owner.read_pair_values(PTD_OFFSET, 8, &mut access).is_err());
    owner.set_lifecycle(LIVE, &mut access);
    owner
        .write(0xec8, Width::Word, 0x33333333, &mut access)
        .unwrap();
    assert!(owner.progress()[0].pending_configuration.is_some());
    assert!(owner.check_lifecycle(paused).is_err());
    assert_eq!(owner.publication_bank().lifecycle_state(), LIVE);
    let service = ram.try_service().unwrap().unwrap();
    assert!(
        // SAFETY: fixture RAM gates held, no independently running publisher.
        unsafe { owner.read_ram_drain(CHANNEL_STRIDE + DRAIN, Width::Word, &service) }.is_err()
    );
    assert!(owner.read(0xec8, Width::Word, &mut access).is_err());
    assert!(
        owner
            .check_lifecycle(LifecycleState {
                reset: true,
                ..LIVE
            })
            .is_err()
    );
    assert!(owner.progress().iter().all(|p| p.completed_drains == 0));
}
#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_MCC_J473_DT"]
fn original_j473_dcs_and_ptd_placement_builds_one_source_profiled_resource() {
    use stela_contracts::adt::Node;
    let bytes = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&bytes),
        "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
    );
    let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
    let mcc = io.child("mcc").unwrap();
    let pmp = io.child("pmp").unwrap();
    let ranges = mcc.pairs("reg").unwrap();
    let translate = |(base, bytes)| (io.translate_range(base, bytes).unwrap(), bytes);
    let (dcs, dcs_bytes) = translate(ranges[2]);
    let bank = translate(ranges[mcc.first_u32("pmp_ptd_reg_idx").unwrap() as usize]);
    let updates = translate(
        pmp.pairs("reg").unwrap()[pmp.first_u32("ptd-update-reg-index").unwrap() as usize],
    );
    let geometry = Geometry::new(bank, updates).unwrap();
    let records = pmp
        .child("iop-pmp-nub")
        .unwrap()
        .property("ptd-range")
        .unwrap();
    let (records, tail) = records.as_chunks::<32>();
    assert!(tail.is_empty());
    // This fixture tests only the DCS/PTD source placement. Cache/AMCC stay
    // outside the composition, with the explicitly authored metadata above.
    let mut source = descriptor();
    source.channels = (
        dcs,
        dcs_bytes,
        mcc.first_u32("dcs_num_channels").unwrap() as usize,
    );
    source.ptd.physical = bank.0;
    source.ptd_updates = updates;
    source.ptd_entries = geometry.entries();
    source.ptd.ranges.clear();
    source.ptd.interrupts.clear();
    for row in records {
        let word = |i| u32::from_le_bytes(row[i..i + 4].try_into().unwrap());
        let name = row[16..].split(|b| *b == 0).next().unwrap();
        source.ptd.ranges.push(stela_soc_data::ptd::Range {
            id: word(0),
            start: word(4),
            count: word(8),
            name: core::str::from_utf8(name).unwrap().into(),
        });
        source.ptd.interrupts.push(word(12));
    }
    assert_eq!(source.channels, (DCS, DCS_BYTES, CHANNELS));
    assert_eq!(source.ptd_entries, 2048);
    assert_eq!(source.ptd.ranges.len(), 27);
    let expected = source.clone();
    let owner = Prepared::initialized(source, configuration(), LIVE, ram()).unwrap();
    assert_eq!(owner.descriptor(), &expected);
    assert!(owner.notifications().owns(owner.publication_bank()));
    assert!(owner.supports_pair(PTD_OFFSET + 255 * 16, 8));
    assert!(!owner.supports_pair(PTD_OFFSET + 256 * 16, 8));
}
