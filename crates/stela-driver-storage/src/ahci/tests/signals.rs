// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2004-2005 Red Hat, Inc.
//! AHCI completion messages: PxIE, the status clear order, and a message
//! that never comes or comes for nothing.
use super::*;

/// The HBA's registers, IS among them, as plain memory.
struct Hba {
    registers: Box<[u64]>,
    mmio: Mmio,
}

impl Hba {
    fn new() -> Self {
        let mut registers = vec![0u64; 8].into_boxed_slice();
        // SAFETY: the allocation outlives every access through `mmio`.
        let mmio = unsafe { Mmio::new(registers.as_mut_ptr() as u64, 64) };
        Self { registers, mmio }
    }

    /// What IS last held or was last written.
    fn interrupts(&self) -> u32 {
        let _ = &self.registers;
        self.mmio.read32(HOST_INTERRUPTS)
    }

    fn set_interrupts(&self, value: u32) {
        self.mmio.write32(HOST_INTERRUPTS, value);
    }
}

/// An NCQ disk with two queued slots whose port sends messages as port 2.
fn signalled(hba: &Hba, link: &Link) -> (Fixture, crate::test_clock::Guard) {
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
    fixture.disk.enable_signal(link, hba.mmio, 2);
    (fixture, clock)
}

#[test]
fn a_signalled_port_enables_completion_and_error_bits_and_masks_phy_events_under_lpm() {
    // Reference: DEF_PORT_IRQ and ahci_set_lpm.
    let hba = Hba::new();
    let link = Link::new(&[]);
    let (mut fixture, _clock) = signalled(&hba, &link);
    assert!(fixture.disk.signals());
    let all = INTERRUPT_ERROR | INTERRUPT_COMPLETION;
    assert_eq!(link.writes_to(PORT_INTERRUPT_ENABLE), [all]);
    assert_eq!(all & 1 << 2, 0, "no DMA Setup FIS");
    fixture.disk.lpm = Lpm {
        hipm: true,
        ..Lpm::new(CAP_AGGRESSIVE_LPM | CAP_SLUMBER | CAP_PARTIAL, 0, 0)
    };
    // Saving power: PhyRdy and COMINIT masked before the link is restricted.
    let link = Link::new(&[]);
    fixture
        .disk
        .apply_lpm(&link, LPM_MED_POWER_WITH_DIPM)
        .unwrap();
    let saving = all & !(INTERRUPT_PHY_READY_CHANGE | INTERRUPT_CONNECT_CHANGE);
    assert_eq!(link.writes_to(PORT_INTERRUPT_ENABLE), [saving]);
    let writes = link.writes.borrow().clone();
    let at = |offset| writes.iter().position(|&(written, _)| written == offset);
    assert!(at(PORT_INTERRUPT_ENABLE) < at(PORT_SATA_CONTROL));
    // Maximum power: unmasked after the restrictions are lifted.
    let link = Link::new(&[]);
    fixture.disk.apply_lpm(&link, LPM_MAX_POWER).unwrap();
    assert_eq!(link.writes_to(PORT_INTERRUPT_ENABLE), [all]);
    let writes = link.writes.borrow().clone();
    let last = |offset| writes.iter().rposition(|&(written, _)| written == offset);
    assert!(last(PORT_INTERRUPT_ENABLE) > last(PORT_SATA_CONTROL));
    // A polled port has no PxIE to set.
    let (mut polled, _clock) = recovering(identify_page("S1", 1024));
    assert!(!polled.disk.signals());
    let link = Link::new(&[]);
    polled.disk.apply_lpm(&link, LPM_MAX_POWER).unwrap();
    assert!(link.writes_to(PORT_INTERRUPT_ENABLE).is_empty());
}

#[test]
fn a_completion_clears_its_status_bits_then_its_is_bit() {
    // Reference: ahci_port_intr and ahci_handle_port_intr.
    let hba = Hba::new();
    let link = Link::new(&[Fault::Timeout]);
    let (mut fixture, _clock) = signalled(&hba, &link);
    let disk = &mut fixture.disk;
    disk.begin(Command::Read { lba: 8, bytes: 512 }).unwrap();
    disk.run(&link);
    assert!(disk.running[0].result.is_none());
    // The disk completes the read: its Set Device Bits FIS lands, PxSACT
    // clears, PxIS.SDBS and the port's IS bit are set and the message sent.
    disk.slot_page(0, 0)[..512].fill(0x22);
    {
        let mut registers = link.registers.borrow_mut();
        registers[PORT_SATA_ACTIVE / 4] = 0;
        registers[PORT_INTERRUPTS / 4] |= 1 << 3;
    }
    hba.set_interrupts(1 << 2);
    disk.commands.write(RECEIVED_SDB, FIS_SET_DEVICE_BITS);
    assert!(disk.posted());
    let cleared = link.writes_to(PORT_INTERRUPTS).len();
    hba.set_interrupts(0);
    disk.run(&link);
    assert_eq!(
        disk.running[0].result.take(),
        Some(Ok(Some(vec![0x22; 512])))
    );
    assert_eq!(link.writes_to(PORT_INTERRUPTS)[cleared..], [1 << 3]);
    assert_eq!(link.read32(PORT_INTERRUPTS) & INTERRUPT_COMPLETION, 0);
    assert_eq!(hba.interrupts(), 1 << 2, "the port's IS bit, last");
}

#[test]
fn a_message_with_nothing_posted_reaches_no_register() {
    let hba = Hba::new();
    let link = Link::new(&[Fault::Timeout]);
    let (mut fixture, _clock) = signalled(&hba, &link);
    let disk = &mut fixture.disk;
    disk.begin(Command::Read { lba: 8, bytes: 512 }).unwrap();
    disk.run(&link);
    // A message comes and nothing has ended: each look after it reads
    // memory alone and leaves IS as it is, so it cannot spin.
    hba.set_interrupts(0x80);
    let (reads, writes) = (link.reads.get(), link.writes.borrow().len());
    for _ in 0..REGISTER_POLL_INTERVAL - 2 {
        assert!(!disk.posted());
        disk.run(&link);
    }
    assert_eq!(link.reads.get(), reads);
    assert_eq!(link.writes.borrow().len(), writes);
    assert_eq!(hba.interrupts(), 0x80);
    assert!(disk.running[0].result.is_none());
}

#[test]
fn a_message_that_never_comes_leaves_completions_to_the_looks() {
    // The read completes with no FIS posted and no message: the look that
    // reads the registers anyway finds it, as on a polled port.
    let hba = Hba::new();
    let link = Link::new(&[Fault::Complete]);
    let (mut fixture, _clock) = signalled(&hba, &link);
    let disk = &mut fixture.disk;
    disk.begin(Command::Read { lba: 8, bytes: 512 }).unwrap();
    for _ in 0..REGISTER_POLL_INTERVAL {
        disk.run(&link);
        if disk.running[0].result.is_some() {
            break;
        }
    }
    assert!(matches!(disk.running[0].result, Some(Ok(Some(_)))));
}

#[test]
fn error_bits_are_cleared_by_the_failure_before_the_is_bit() {
    // Reference: ahci_error_intr runs inside ahci_port_intr, before
    // ahci_handle_port_intr clears IS.
    let hba = Hba::new();
    let link = Link::new(&[Fault::TaskFile(0x0451)]);
    let (mut fixture, _clock) = signalled(&hba, &link);
    hba.set_interrupts(0x80);
    // Retried after the failure, it completes.
    let result = fixture
        .disk
        .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true);
    assert_eq!(result, Ok(()));
    // The failure cleared PxIS whole, completion bits included only then.
    assert!(
        link.writes_to(PORT_INTERRUPTS)
            .iter()
            .any(|&value| value & INTERRUPT_TASK_FILE_ERROR != 0)
    );
    assert_eq!(link.read32(PORT_INTERRUPTS) & INTERRUPT_ERROR, 0);
    assert_eq!(hba.interrupts(), 1 << 2);
}
