// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2004-2005 Red Hat, Inc.
//! Controller admission and the parallel link reset of every port.
use super::*;

fn identity(vendor: u16, device: u16, class: [u8; 3]) -> crate::bus::pci::Identity {
    crate::bus::pci::Identity {
        address: crate::bus::pci::Address {
            segment: 0,
            bus: 0,
            device: 0x17,
            function: 0,
        },
        vendor,
        device,
        class,
    }
}

#[test]
fn intel_raid_mode_sata_is_admitted_as_ahci_and_vmd_is_not() {
    // Reference: ahci_pci_tbl.
    for device in [0x2822, 0x282a, 0x06d6, 0xa102, 0xa182, 0x43d6] {
        assert!(
            matches_identity(&identity(INTEL, device, CLASS_RAID)),
            "{device:#06x}"
        );
    }
    // Intel VMD, and a RAID controller the table does not list.
    for device in [
        0x201d, 0x28c0, 0x467f, 0x4c3d, 0x7d0b, 0x9a0b, 0xad0b, 0x1234,
    ] {
        assert!(
            !matches_identity(&identity(INTEL, device, CLASS_RAID)),
            "{device:#06x}"
        );
    }
    assert!(matches_identity(&identity(VENDOR_AMD, 0x7905, CLASS_RAID)));
    assert!(!matches_identity(&identity(0x1b4b, 0x9230, CLASS_RAID)));
    assert!(matches_identity(&identity(0x1b4b, 0x9230, CLASS)));
    assert!(INTEL_AHCI.is_sorted());
}

#[test]
fn empty_ports_are_found_in_one_parallel_debounce() {
    // Reference: sata_link_hardreset, sata_link_resume and
    // sata_link_debounce with sata_deb_timing_normal.
    let _clock = crate::test_clock::virtualize();
    let timer = Rc::new(MinimumModel::default());
    let control = Control::model(timer.clone());
    let ports: Vec<Link> = (0..6).map(|_| Link::new(&[])).collect();
    for port in &ports[1..] {
        port.present.set(false);
    }
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    let links = Disk::link_ports(&ports.iter().collect::<Vec<_>>(), 0, clock, &control);
    assert!(matches!(links[0], Ok(Some(_))));
    assert!(links[1..].iter().all(|link| matches!(link, Ok(None))));
    let waits = timer.waits.borrow();
    // A COMRESET hold per port, one settle for all, then one debounce.
    assert_eq!(&waits[..6], &[COMRESET_HOLD_US; 6]);
    assert_eq!(waits[6], RESUME_SETTLE_US);
    assert!(waits[7..].iter().all(|us| *us == DEBOUNCE_NORMAL[0]));
    let debounce: u64 = waits[7..].iter().sum();
    assert!(
        debounce > DEBOUNCE_NORMAL[1] && debounce <= DEBOUNCE_NORMAL[1] + 2 * DEBOUNCE_NORMAL[0]
    );
    // Well under the 1.2 s each empty port took one after another.
    assert!(timer.now.get() < 6 * COMRESET_HOLD_US + RESUME_SETTLE_US + 150_000);
    // Every port's COMRESET was released.
    for port in &ports {
        assert_eq!(
            port.writes_to(PORT_SATA_CONTROL)
                .iter()
                .map(|value| value & SATA_CONTROL_DETECTION)
                .collect::<Vec<_>>(),
            [SATA_CONTROL_RESET, 0]
        );
    }
}

#[test]
fn a_timing_failure_during_the_shared_settle_fails_every_port() {
    let _clock = crate::test_clock::virtualize();
    let timer = Rc::new(MinimumModel::default());
    // Two holds, then the shared settle fails.
    timer.fail_wait.set(Some(3));
    let control = Control::model(timer.clone());
    let ports = [Link::new(&[]), Link::new(&[])];
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    let links = Disk::link_ports(&[&ports[0], &ports[1]], 0, clock, &control);
    assert!(links.iter().all(|link| link.is_err()));
    assert!(control.ready().is_err());
}

#[test]
fn the_first_link_reset_refuses_partial_and_slumber_and_keeps_the_speed_limit() {
    // Reference: sata_link_hardreset writes (SControl & 0x0f0) | 0x301,
    // sata_link_resume (SControl & 0x0f0) | 0x300, whatever IPM the
    // firmware left.
    let _clock = crate::test_clock::virtualize();
    let control = Control::model(Rc::new(MinimumModel::default()));
    let port = Link::new(&[]);
    port.registers.borrow_mut()[PORT_SATA_CONTROL / 4] = 0x020;
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    let links = Disk::link_ports(&[&port], 0, clock, &control);
    assert!(matches!(links[0], Ok(Some(_))));
    assert_eq!(port.writes_to(PORT_SATA_CONTROL), [0x321, 0x320]);
}
