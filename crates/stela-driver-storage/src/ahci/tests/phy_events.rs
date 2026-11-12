// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2004-2005 Red Hat, Inc.
//! AHCI PhyRdy change cases: link power transitions against hotplug.
use super::*;

/// COMRESET's DET values written to PxSCTL, in order.
fn resets(link: &Link) -> Vec<u32> {
    link.writes_to(PORT_SATA_CONTROL)
        .iter()
        .map(|control| control & SATA_CONTROL_DETECTION)
        .collect()
}

/// An NCQ disk with two queued slots, its IDENTIFY data saying so for
/// revalidation.
fn queued() -> (Fixture, crate::test_clock::Guard) {
    let mut page = identify_page("S1", 1024);
    for (word, value) in [
        (IDENTIFY_SATA_CAPABILITY, SATA_CAPABILITY_NCQ),
        (IDENTIFY_QUEUE_DEPTH, 31),
    ] {
        page[2 * word..2 * word + 2].copy_from_slice(&value.to_le_bytes());
    }
    let (mut fixture, clock) = recovering_with(page, 2);
    (fixture.disk.ncq.host, fixture.disk.ncq.device) = (true, true);
    fixture.disk.command_timeout_us = 1_000_000_000;
    (fixture, clock)
}

/// Run two queued writes on `link` until both have results.
fn two_writes(
    disk: &mut AhciDisk,
    link: &Link,
) -> Vec<Option<Result<Option<Vec<u8>>, BlockError>>> {
    for index in 0..2 {
        disk.begin(Command::Write {
            lba: 8 * index,
            data: vec![0x5a; 512],
            fua: false,
        })
        .unwrap();
    }
    for _ in 0..64 {
        disk.run(link);
        if disk.running.iter().all(|running| running.result.is_some()) {
            break;
        }
    }
    disk.running
        .drain(..)
        .map(|mut running| running.result.take())
        .collect()
}

#[test]
fn phy_ready_changes_under_link_power_management_are_not_errors() {
    // Reference: sata_lpm_ignore_phy_events and ahci_handle_port_interrupt.
    // A disk in Slumber between commands changes PhyRdy; with LPM on, the
    // change is dropped and SError.N cleared, and the write completes.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    fixture.disk.lpm.policy = LPM_MED_POWER_WITH_DIPM;
    let link = Link::new(&[Fault::PhyEvent]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
        Ok(())
    );
    assert_eq!(link.issued.get(), 1);
    assert!(resets(&link).is_empty());
    assert_eq!(link.writes_to(PORT_SATA_ERROR), [SERROR_PHY_READY_CHANGE]);
    assert_eq!(link.read32(PORT_INTERRUPTS) & INTERRUPT_PHY_READY_CHANGE, 0);
    assert!(fixture.disk.fault.is_none());
    assert_eq!(fixture.disk.errors.newest().count(), 0);

    // The same with queued commands outstanding: none fails or reruns.
    let (mut fixture, _clock) = queued();
    fixture.disk.lpm.policy = LPM_MED_POWER_WITH_DIPM;
    let link = Link::new(&[Fault::PhyEvent, Fault::Complete]);
    let results = two_writes(&mut fixture.disk, &link);
    assert_eq!(results, [Some(Ok(None)), Some(Ok(None))]);
    assert_eq!(link.issued.get(), 2);
    assert!(resets(&link).is_empty());
}

#[test]
fn phy_ready_changes_at_maximum_power_are_hotplug_recovered_and_retried() {
    // Reference: ahci_error_intr (PORT_IRQ_PHYRDY freezes the port),
    // ata_eh_analyze_serror and ata_eh_recover. Without LPM a PhyRdy change
    // is a hotplug: COMRESET, revalidation that finds the same disk, and
    // the write again.
    for fault in [Fault::PhyEvent, Fault::Flap] {
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        fixture.disk.lpm.policy = LPM_MAX_POWER;
        let link = Link::new(&[fault]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
            Ok(())
        );
        // The write, IDENTIFY, SET FEATURES UDMA 6, IDENTIFY, the write.
        assert_eq!(link.issued.get(), 5);
        assert_eq!(resets(&link), [SATA_CONTROL_RESET, 0]);
        assert_eq!(link.read32(PORT_INTERRUPTS) & INTERRUPT_PHY_READY_CHANGE, 0);
        assert_eq!(link.read32(PORT_SATA_ERROR), 0);
        assert!(fixture.disk.fault.is_none());
    }

    // Queued commands outstanding all run again after the reset.
    let (mut fixture, _clock) = queued();
    fixture.disk.lpm.policy = LPM_MAX_POWER;
    let link = Link::new(&[Fault::Flap, Fault::Timeout]);
    let results = two_writes(&mut fixture.disk, &link);
    assert_eq!(results, [Some(Ok(None)), Some(Ok(None))]);
    assert_eq!(resets(&link), [SATA_CONTROL_RESET, 0]);
    let queued = link.writes_to(PORT_SATA_ACTIVE);
    assert_eq!(queued.iter().filter(|slots| **slots == 1).count(), 2);
    assert_eq!(queued.iter().filter(|slots| **slots == 2).count(), 2);
    assert!(fixture.disk.fault.is_none());
}

#[test]
fn a_phy_ready_change_soon_after_a_policy_change_is_spurious() {
    // Reference: sata_lpm_ignore_phy_events' ATA_TMOUT_SPURIOUS_PHY window
    // after ata_eh_link_set_lpm sets ATA_LFLAG_CHANGED.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let clock = fixture.disk.clock;
    fixture.disk.lpm.policy = LPM_MAX_POWER;
    fixture.disk.lpm.changed = Some(clock.try_start().unwrap());
    let link = Link::new(&[Fault::PhyEvent]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
        Ok(())
    );
    assert_eq!(link.issued.get(), 1);
    assert!(resets(&link).is_empty());

    // Past the window it is a hotplug again.
    crate::test_clock::advance(clock, SPURIOUS_PHY_US);
    link.faults.borrow_mut().push_back(Fault::PhyEvent);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
        Ok(())
    );
    assert_eq!(link.issued.get(), 6);
    assert_eq!(resets(&link), [SATA_CONTROL_RESET, 0]);
}

#[test]
fn applying_a_policy_starts_the_spurious_window() {
    // Reference: ata_eh_link_set_lpm records last_lpm_change on success.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    fixture.disk.lpm = Lpm {
        hipm: true,
        ..Lpm::new(CAP_AGGRESSIVE_LPM | CAP_SLUMBER | CAP_PARTIAL, 0, 0)
    };
    assert!(fixture.disk.lpm.changed.is_none());
    fixture
        .disk
        .apply_lpm(&Link::new(&[]), LPM_MAX_POWER)
        .unwrap();
    assert!(fixture.disk.lpm.changed.is_some());
    assert!(fixture.disk.ignore_phy_events());
    crate::test_clock::advance(fixture.disk.clock, SPURIOUS_PHY_US);
    assert!(!fixture.disk.ignore_phy_events());
    fixture
        .disk
        .apply_lpm(&Link::new(&[]), LPM_MED_POWER_WITH_DIPM)
        .unwrap();
    crate::test_clock::advance(fixture.disk.clock, SPURIOUS_PHY_US);
    assert!(fixture.disk.ignore_phy_events());
}

#[test]
fn serror_hotplug_bits_mean_nothing_under_link_power_management() {
    // Reference: ata_eh_analyze_serror's hotplug_mask, 0 with LPM on.
    let serror = SERROR_PHY_READY_CHANGE | SERROR_DEVICE_EXCHANGED;
    let failure = classify(INTERRUPT_TASK_FILE_ERROR, serror, 0x0451, false, true);
    assert!(!failure.hotplug && !failure.reset);
    assert_eq!(failure.mask, ERR_DEVICE);
    let failure = classify(INTERRUPT_TASK_FILE_ERROR, serror, 0x0451, false, false);
    assert!(failure.hotplug && failure.reset);
    assert_eq!(failure.mask & ERR_ATA_BUS, ERR_ATA_BUS);
    // Interface and host bus errors still reset with LPM on.
    let failure = classify(INTERRUPT_INTERFACE_FATAL, SERROR_DATA, 0x50, false, true);
    assert!(failure.reset && failure.frozen);
}

#[test]
fn a_disk_that_leaves_under_link_power_management_fails_in_bounded_time() {
    // Reference: with LPM hotplug is not reported (AHCI 1.3.1 §7.3.1); the
    // command times out, the reset finds no device and the disk is
    // disabled, as libata disables a device that does not come back.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    fixture.disk.lpm.policy = LPM_MED_POWER_WITH_DIPM;
    let link = Link::new(&[Fault::Gone]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Err(DETACHED)
    );
    assert_eq!(fixture.disk.fault, Some(DETACHED));
    assert_eq!(link.issued.get(), 1);
    assert_eq!(
        alloc::format!("{DETACHED}"),
        "transport protocol violation: the SATA disk detached or changed"
    );
}
