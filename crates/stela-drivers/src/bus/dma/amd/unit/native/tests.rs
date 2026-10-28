extern crate std;
mod model;
use super::*;
use crate::bus::dma::{amd::ivrs::Ivrs, pages::PageRange};
use crate::bus::pci::ConfigSpace;
use alloc::vec;
use model::*;

#[test]
fn cold_native_requester_walks_exact_pages_permissions_unmap_and_retirement() {
    let (mut unit, peer) = model::unit();
    assert_eq!(
        peer.walk(0x20, 4096),
        None,
        "prime actual blocked DTE cache before attach"
    );
    assert_eq!(unit.drain_posted_writes(), Err(DmaError::DrainUnavailable));
    // SAFETY: isolated synchronous peer never submits requester DMA/work.
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    assert_eq!(
        unsafe {
            requester.with_function(|function| {
                function.config().write16(4, 4);
                function.config().read16(4)
            })
        }
        .unwrap(),
        4,
        "owning driver configures original retained function after attach"
    );
    assert_eq!(
        requester.drain_posted_writes(),
        Err(DmaError::DrainUnavailable)
    );
    for (direction, read, write) in [
        (Direction::ToDevice, true, false),
        (Direction::FromDevice, false, true),
        (Direction::Bidirectional, true, true),
    ] {
        let pages = peer.pages(8192);
        let physical = pages.physical_pages().to_vec();
        let mapping = requester
            .map(pages.into(), direction, u32::MAX as u64)
            .unwrap();
        for (index, pa) in physical.into_iter().enumerate() {
            assert_eq!(
                peer.walk(0x20, mapping.address() + (index * 4096) as u64),
                Some((pa, read, write))
            );
        }
        // SAFETY: model has no asynchronous CPU/device writers.
        unsafe { requester.sync(&mapping, 0..mapping.bytes(), false) }.unwrap();
        unsafe { requester.sync(&mapping, 0..mapping.bytes(), true) }.unwrap();
        assert_eq!(peer.syncs(), 2);
        peer.clear_syncs();
        // SAFETY: all model DMA/submissions/IRQ/work are synchronously absent.
        unsafe { requester.unmap(&mapping) }.unwrap();
        assert_eq!(peer.walk(0x20, mapping.address()), None);
        let before = peer.commands();
        assert_eq!(unsafe { requester.unmap(&mapping) }, Err(Error::Mapping));
        assert_eq!(peer.commands(), before);
    }
    // Real repeated physical-page aliases remain in exact submitted order.
    let pages = peer.pages(8192);
    let first = pages.physical_pages()[0];
    let second = pages.physical_pages()[1];
    let sequence = DmaPages::from_ranges(vec![
        PageRange::new(pages.clone(), 4096..8192).unwrap(),
        PageRange::new(pages.clone(), 0..4096).unwrap(),
        PageRange::new(pages, 4096..8192).unwrap(),
    ])
    .unwrap();
    let mapping = requester
        .map(sequence, Direction::Bidirectional, u32::MAX as u64)
        .unwrap();
    for (index, pa) in [second, first, second].into_iter().enumerate() {
        assert_eq!(
            peer.walk(0x20, mapping.address() + (index * 4096) as u64),
            Some((pa, true, true))
        );
    }
    assert_eq!(unsafe { requester.detach() }, Err(Error::Busy));
    unsafe { requester.unmap(&mapping) }.unwrap();
    unsafe { requester.detach() }.unwrap();
    assert_eq!(peer.walk(0x20, 4096), None);
    let before = peer.commands();
    assert_eq!(unsafe { requester.detach() }, Err(Error::Poisoned));
    assert_eq!(peer.commands(), before);
    drop(requester);
    unsafe { unit.retire() }.unwrap();
    let before = peer.registers();
    assert_eq!(unsafe { unit.retire() }, Err(Error::Poisoned));
    assert!(matches!(
        unsafe { unit.attach(function(0x21)) },
        Err(Error::Poisoned)
    ));
    assert_eq!(peer.registers(), before);
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn foreign_and_stale_mapping_tokens_refuse_before_mmio_or_ram_mutation() {
    let (mut unit, peer) = model::unit();
    let mut first = unsafe { unit.attach(function(0x20)) }.unwrap();
    let mut second = unsafe { unit.attach(function(0x21)) }.unwrap();
    let mapping = first
        .map(
            peer.pages(4096).into(),
            Direction::ToDevice,
            u32::MAX as u64,
        )
        .unwrap();
    let before = peer.image();
    let entries = peer.enters();
    assert_eq!(unsafe { second.unmap(&mapping) }, Err(Error::Mapping));
    assert_eq!(
        unsafe { second.sync(&mapping, 0..4096, false) },
        Err(Error::Mapping)
    );
    assert_eq!(
        peer.enters(),
        entries,
        "private-owner rejection precedes context/MMIO"
    );
    assert_eq!(peer.image(), before);
    unsafe { first.unmap(&mapping) }.unwrap();
    let replacement = first
        .map(
            peer.pages(4096).into(),
            Direction::FromDevice,
            u32::MAX as u64,
        )
        .unwrap();
    assert_eq!(
        mapping.address(),
        replacement.address(),
        "acknowledged aperture reuse"
    );
    let before = peer.image();
    assert_eq!(unsafe { first.unmap(&mapping) }, Err(Error::Mapping));
    assert_eq!(
        unsafe { first.sync(&mapping, 0..4096, true) },
        Err(Error::Mapping)
    );
    assert_eq!(peer.image(), before);
    unsafe { first.unmap(&replacement) }.unwrap();
    unsafe { first.detach() }.unwrap();
    unsafe { second.detach() }.unwrap();
    drop((first, second));
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn native_queue_wraps_and_requires_exact_store_even_after_head_advances() {
    let (mut unit, peer) = model::unit();
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    // More than512 actual commands wraps the real ring multiple times. The
    // peer decodes ring RAM and writes the PA named by every completion entry.
    for _ in 0..300 {
        let mapping = requester
            .map(
                peer.pages(4096).into(),
                Direction::Bidirectional,
                u32::MAX as u64,
            )
            .unwrap();
        unsafe { requester.unmap(&mapping) }.unwrap();
    }
    assert!(peer.commands().len() > 1024);
    peer.mode(Mode::StoreBeforeHead);
    let mapping = requester
        .map(
            peer.pages(4096).into(),
            Direction::ToDevice,
            u32::MAX as u64,
        )
        .unwrap();
    unsafe { requester.unmap(&mapping) }.unwrap();
    unsafe { requester.detach() }.unwrap();
    drop(requester);
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);

    for mode in [
        Mode::HeadOnly,
        Mode::OldStore,
        Mode::FutureStore,
        Mode::BadHead,
        Mode::Halt,
        Mode::Event,
        Mode::Overflow,
        Mode::HardwareError,
        Mode::AlterBase,
    ] {
        let (mut unit, peer) = model::unit();
        let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
        peer.mode(mode);
        assert!(
            requester
                .map(
                    peer.pages(4096).into(),
                    Direction::FromDevice,
                    u32::MAX as u64
                )
                .is_err()
        );
        assert!(unit.check_health().is_err());
        assert_eq!(unsafe { requester.detach() }, Err(Error::Poisoned));
        let commands = peer.commands();
        assert!(
            requester
                .map(
                    peer.pages(4096).into(),
                    Direction::ToDevice,
                    u32::MAX as u64
                )
                .is_err()
        );
        assert_eq!(peer.commands(), commands);
        let retained = peer.live_ram();
        assert!(retained >= 6);
        drop(requester);
        drop(unit);
        assert_eq!(
            peer.live_ram(),
            retained,
            "uncertain unit/tree/payload pins are quarantined"
        );
        assert_ne!(
            peer.register(CONTROL) & IOMMU_ENABLE,
            0,
            "fault must not enable bypass"
        );
    }
}

#[test]
fn failed_removal_preserves_payload_and_original_requester_until_real_retirement() {
    let (mut unit, peer) = model::unit();
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    let mapping = requester
        .map(
            peer.pages(4096).into(),
            Direction::Bidirectional,
            u32::MAX as u64,
        )
        .unwrap();
    peer.mode(Mode::HeadOnly);
    assert!(unsafe { requester.unmap(&mapping) }.is_err());
    assert_eq!(
        peer.walk(0x20, mapping.address()),
        None,
        "actual leaf was cleared before uncertain completion"
    );
    let retained = peer.live_ram();
    assert_eq!(unsafe { requester.unmap(&mapping) }, Err(Error::Poisoned));
    assert_eq!(unsafe { unit.retire() }, Err(Error::Busy));
    drop(requester);
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
}

#[test]
fn cold_and_firmware_refusals_precede_native_publication() {
    for mutation in [0, 1, 2, 3, 4, 5] {
        let (inspection, platform, peer, mut bytes) = inputs();
        match mutation {
            0 => peer.set(CONTROL, IOMMU_ENABLE),
            1 => peer.set(STATUS, COMMAND_RUNNING),
            2 => bytes[88] = 0x42, // Alias entry requires original group owner.
            3 => bytes[91] = 0x10, // System-management bypass policy refused.
            4 => bytes[24] = 1,    // Even unrelated OEM bytes must match discovery.
            _ => peer.set(HARDWARE_EVENT_STATUS, 1),
        }
        checksum(&mut bytes);
        let ivrs = Ivrs::parse(&bytes, 8);
        if let Ok(ivrs) = ivrs {
            assert!(unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.is_err());
            assert_eq!(peer.register(DEVICE_TABLE), 0);
            assert_eq!(peer.register(COMMAND_BASE), 0);
            assert_eq!(peer.register(EVENT_BASE), 0);
            assert_eq!(peer.live_ram(), 0);
        }
    }
}

fn unit_with_entries(entries: &[u8]) -> (Unit<Platform>, Peer) {
    let (inspection, platform, peer, bytes) = inputs_with_entries(entries);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    (
        unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap(),
        peer,
    )
}

#[test]
fn an_alias_shares_its_sources_domain_and_a_shared_alias_has_none_of_its_own() {
    let (mut unit, peer) = unit_with_entries(&[0x42, 0x20, 0, 0, 0, 0x21, 0, 0]);
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    let pages = peer.pages(4096);
    let physical = pages.physical_pages()[0];
    let mapping = requester
        .map(pages.into(), Direction::ToDevice, u32::MAX as u64)
        .unwrap();
    for rid in [0x20, 0x21] {
        assert_eq!(
            peer.walk(rid, mapping.address()),
            Some((physical, true, false))
        );
    }
    unsafe { requester.unmap(&mapping) }.unwrap();
    unsafe { requester.detach() }.unwrap();
    assert_eq!(peer.walk(0x21, mapping.address()), None);
    // Two sources under one alias: neither gets a domain of its own.
    let (mut unit, _) = unit_with_entries(&[
        0x42, 0x20, 0, 0, 0, 0x30, 0, 0, 0x42, 0x28, 0, 0, 0, 0x30, 0, 0,
    ]);
    assert!(matches!(
        unsafe { unit.attach(function(0x20)) },
        Err(Error::Requester)
    ));
}

#[test]
fn device_settings_reach_the_dte_and_later_entries_override_earlier_ones() {
    // SysMgt=01 and Lint1Pass on every requester, then plain settings for
    // 0x20; an IOAPIC special entry names only an interrupt source.
    let (unit, _) = unit_with_entries(&[
        1, 0, 0, 0x90, 2, 0x20, 0, 0, 0x48, 0, 0, 0xd7, 0x21, 0xa0, 0, 1,
    ]);
    let other = unit.table.borrow().snapshot(0x28).unwrap();
    assert_eq!(other[1] >> 40 & 3, 1);
    assert_ne!(other[0] & 1 << 62, 0, "AMD erratum 63 write permission");
    assert_ne!(other[2] & 1 << 63, 0);
    let plain = unit.table.borrow().snapshot(0x20).unwrap();
    assert_eq!(plain, [1, 0, 0, 0]);
}

#[test]
fn each_device_setting_reaches_its_dte_bit() {
    // INITPass, EIntPass, NMIPass, Lint0Pass, Lint1Pass and SysMgt=10, one
    // requester each.
    let (unit, _) = unit_with_entries(&[
        2, 0x20, 0, 0x01, 2, 0x21, 0, 0x02, 2, 0x22, 0, 0x04, 2, 0x23, 0, 0x40, 2, 0x24, 0, 0x80,
        2, 0x25, 0, 0x20,
    ]);
    let table = unit.table.borrow();
    for (rid, bit) in [(0x20, 56), (0x21, 57), (0x22, 58), (0x23, 62), (0x24, 63)] {
        let words = table.snapshot(rid).unwrap();
        assert_eq!(words[2], 1 << bit, "requester {rid:#x}");
        assert_eq!(words[1], 0);
    }
    let words = table.snapshot(0x25).unwrap();
    assert_eq!(words[1] >> 40 & 3, 2);
    assert_eq!(words[0] & 1 << 62, 0);
    assert_eq!(words[2], 0);
}

#[test]
fn an_alias_range_reaches_the_window_under_its_alias_and_shares_one_domain() {
    // 0x20..=0x22 DMA as 0x30.
    let (mut unit, peer) = unit_with_entries(&[0x43, 0x20, 0, 0, 0, 0x30, 0, 0, 4, 0x22, 0, 0]);
    let pages = peer.pages(4096);
    let physical = pages.physical_pages()[0];
    unsafe { unit.window(&[0x20, 0x21, 0x22], vec![pages.into()]) }.unwrap();
    for rid in [0x20, 0x21, 0x22, 0x30] {
        assert_eq!(peer.walk(rid, physical), Some((physical, true, true)));
    }
    assert!(matches!(
        unsafe { unit.attach(function(0x21)) },
        Err(Error::Requester)
    ));
    unsafe { unit.retire() }.unwrap();
}

#[test]
fn window_requesters_reach_its_memory_until_they_attach() {
    let (mut unit, peer) = model::unit();
    let pages = peer.pages(8192);
    let physical = pages.physical_pages()[0];
    unsafe { unit.window(&[0x20, 0x21], vec![pages.into()]) }.unwrap();
    for rid in [0x20, 0x21] {
        assert_eq!(peer.walk(rid, physical), Some((physical, true, true)));
        assert_eq!(
            peer.walk(rid, physical + 4096),
            Some((physical + 4096, true, true))
        );
        assert_eq!(peer.walk(rid, physical + 8192), None);
    }
    assert_eq!(peer.walk(0x22, physical), None);
    let mut own = unsafe { unit.attach(function(0x20)) }.unwrap();
    assert_eq!(peer.walk(0x20, physical), None);
    assert_eq!(peer.walk(0x21, physical), Some((physical, true, true)));
    unsafe { own.detach() }.unwrap();
    drop(own);
    assert_eq!(peer.walk(0x20, physical), None);
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    // Retirement releases every pin, the window's included.
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn uncovered_and_attached_requesters_are_refused() {
    let (inspection, platform, peer, bytes) = inputs_with_entries(&[2, 0x20, 0, 0]);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    let mut unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap();
    let before = peer.image();
    assert!(matches!(
        unsafe { unit.attach(function(0x21)) },
        Err(Error::Requester)
    ));
    assert_eq!(peer.image(), before);
    let mut owner = unsafe { unit.attach(function(0x20)) }.unwrap();
    let before = peer.image();
    assert!(matches!(
        unsafe { unit.attach(function(0x20)) },
        Err(Error::Busy)
    ));
    assert_eq!(peer.image(), before);
    unsafe { owner.detach() }.unwrap();
    drop(owner);
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn initial_and_final_completion_timeouts_quarantine_original_unit_resources() {
    let (inspection, platform, peer, bytes) = inputs();
    peer.mode(Mode::HeadOnly);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    assert!(matches!(
        unsafe { Unit::cold(inspection, &ivrs, platform, limits()) },
        Err(Error::Timeout)
    ));
    assert_eq!(
        peer.live_ram(),
        4,
        "table plus all three actual command/event/store targets retained"
    );
    assert_ne!(peer.register(CONTROL) & IOMMU_ENABLE, 0);

    let (mut unit, peer) = model::unit();
    peer.mode(Mode::OldStore);
    assert_eq!(unsafe { unit.retire() }, Err(Error::Timeout));
    let retained = peer.live_ram();
    assert_eq!(retained, 4);
    let commands = peer.commands();
    assert_eq!(unsafe { unit.retire() }, Err(Error::Poisoned));
    assert_eq!(peer.commands(), commands);
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
    assert_ne!(peer.register(CONTROL) & IOMMU_ENABLE, 0);
}

#[test]
fn original_guard_teardown_unwinds_keep_requester_and_unit_owners_quarantined() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    for remove in [false, true] {
        let (mut unit, peer) = model::unit();
        let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
        let mapping = if remove {
            Some(
                requester
                    .map(
                        peer.pages(4096).into(),
                        Direction::Bidirectional,
                        u32::MAX as u64,
                    )
                    .unwrap(),
            )
        } else {
            None
        };
        let pages: DmaPages = peer.pages(4096).into();
        let payload = mapping
            .as_ref()
            .map(|mapping| peer.walk(0x20, mapping.address()).unwrap().0)
            .unwrap_or(pages.physical_pages()[0]);
        peer.fail_outer_guard();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if let Some(mapping) = &mapping {
                    unsafe { requester.unmap(mapping) }.unwrap();
                } else {
                    requester
                        .map(pages.clone(), Direction::FromDevice, u32::MAX as u64)
                        .unwrap();
                }
            }))
            .is_err()
        );
        drop(pages);
        assert!(
            peer.retains(payload),
            "exact original payload PA remains pinned after caught teardown unwind"
        );
        assert_eq!(unsafe { requester.detach() }, Err(Error::Poisoned));
        let retained = peer.live_ram();
        drop(requester);
        drop(unit);
        assert_eq!(peer.live_ram(), retained);
        assert!(
            peer.retains(payload),
            "unmapped tree has no binding; requester Drop must retain its exact payload pin"
        );
    }
    let (mut unit, peer) = model::unit();
    peer.fail_outer_guard();
    assert!(catch_unwind(AssertUnwindSafe(|| unsafe { unit.retire() })).is_err());
    let retained = peer.live_ram();
    assert_eq!(retained, 4);
    assert_eq!(unsafe { unit.retire() }, Err(Error::Poisoned));
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
}

#[test]
fn failed_actual_dte_attachment_retains_original_function_root_and_rid_reservation() {
    let (mut unit, peer) = model::unit();
    let (function, counters) = function_with_counters(0x20);
    let references = Rc::strong_count(&unit.engine);
    peer.mode(Mode::HeadOnly);
    assert!(matches!(
        unsafe { unit.attach(function) },
        Err(Error::DeviceTable(DeviceTableError::Invalidation(
            DmaError::InvalidationFailed
        )))
    ));
    assert!(unit.active.borrow().contains(&0x20));
    assert!(unit.table.borrow().is_poisoned());
    assert_eq!(
        Rc::strong_count(&unit.engine),
        references + 1,
        "quarantined real page tree retains its hardware/requester owner"
    );
    let dte = unit.table.borrow().snapshot(0x20).unwrap();
    assert_eq!(
        dte[0] & 3,
        3,
        "actual translated DTE reached RAM before uncertain completion"
    );
    let root = dte[0] & 0x000f_ffff_ffff_f000;
    assert!(peer.retains(root));
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    assert_eq!(unsafe { unit.retire() }, Err(Error::Busy));
    let retained = peer.live_ram();
    drop(unit);
    assert_eq!(peer.live_ram(), retained);
    assert!(peer.retains(root));
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn actual_ivinfo_widths_reserved_bits_and_hats_admission_precede_publication() {
    let ordinary = 1u32 | (48 << 8) | (48 << 15);
    for (info, features) in [
        (ordinary | (1 << 23), 1 << 6), // Reserved IVinfo upper byte.
        (1 | (31 << 8) | (48 << 15), 1 << 6),
        (1 | (48 << 8) | (29 << 15), 1 << 6),
        (ordinary, 0),                    // No actual invalidate-all support.
        (ordinary, (1 << 6) | (3 << 10)), // Reserved HATS.
        (ordinary, (1 << 6) | (1 << 63)), // SNP changes completion ownership.
    ] {
        let (inspection, platform, peer, bytes) = inputs_profile(&[1, 0, 0, 0], info, features);
        let ivrs = Ivrs::parse(&bytes, 8).unwrap();
        assert!(matches!(
            unsafe { Unit::cold(inspection, &ivrs, platform, limits()) },
            Err(Error::Profile)
        ));
        assert_eq!(peer.register(DEVICE_TABLE), 0);
        assert_eq!(peer.live_ram(), 0);
    }
    // GVAsize occupies [7:5], not reserved upper bits. It grants no guest
    // translation in this host-only subset and must not shift the PA/VA fields.
    let (inspection, platform, peer, bytes) =
        inputs_profile(&[1, 0, 0, 0], ordinary | (2 << 5), 1 << 6);
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    let mut unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap();
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}

#[test]
fn actual_unit_capability_width_bounds_firmware_and_cpu_payload_admission() {
    let info = 1u32 | (48 << 8) | (48 << 15);
    for miscellaneous in [
        0,
        (31 << 8) | (48 << 15),
        (48 << 8) | (31 << 15),
        (48 << 8) | (48 << 15) | (1 << 23),
    ] {
        let (inspection, platform, peer, bytes) =
            inputs_hardware(&[1, 0, 0, 0], info, 1 << 6, miscellaneous);
        let ivrs = Ivrs::parse(&bytes, 8).unwrap();
        assert!(matches!(
            unsafe { Unit::cold(inspection, &ivrs, platform, limits()) },
            Err(Error::Profile)
        ));
        assert_eq!(peer.register(DEVICE_TABLE), 0);
        assert_eq!(peer.live_ram(), 0);
    }
    let (inspection, platform, peer, bytes) =
        inputs_hardware(&[1, 0, 0, 0], info, 1 << 6, (40 << 8) | (32 << 15));
    let ivrs = Ivrs::parse(&bytes, 8).unwrap();
    let mut unit = unsafe { Unit::cold(inspection, &ivrs, platform, limits()) }.unwrap();
    assert_eq!(
        unit.physical_bits, 40,
        "actual unit width bounds wider firmware and native CPU"
    );
    let mut requester = unsafe { unit.attach(function(0x20)) }.unwrap();
    peer.next_physical(1 << 40);
    let pages = peer.pages(4096);
    let before = peer.image();
    let commands = peer.commands();
    assert!(
        requester
            .map(pages.clone().into(), Direction::ToDevice, u32::MAX as u64)
            .is_err()
    );
    assert_eq!(peer.image(), before);
    assert_eq!(peer.commands(), commands);
    drop(pages);
    unsafe { requester.detach() }.unwrap();
    drop(requester);
    unsafe { unit.retire() }.unwrap();
    drop(unit);
    assert_eq!(peer.live_ram(), 0);
}
