//! AHCI queue cases.
use super::*;
#[test]
fn queued_commands_keep_independent_slots() {
    // Reference: ahci_qc_issue.
    // An NCQ disk taking 32 queued commands, on a host with three slots.
    let mut page = identify_page("S1", 1024);
    for (word, value) in [
        (IDENTIFY_SATA_CAPABILITY, SATA_CAPABILITY_NCQ),
        (IDENTIFY_QUEUE_DEPTH, 31),
    ] {
        page[2 * word..2 * word + 2].copy_from_slice(&value.to_le_bytes());
    }
    let (mut fixture, _clock) = recovering_with(page, 2);
    let disk = &mut fixture.disk;
    (disk.ncq.host, disk.ncq.device) = (true, true);
    assert_eq!(disk.depth(), 3);
    // Every look reads the virtual clock: no command times out here.
    disk.command_timeout_us = 1_000_000_000;

    // Three reads are queued at once, each in its slot under its tag.
    let link = Link::new(&[Fault::Timeout; 3]);
    for index in 0..3 {
        disk.begin(Command::Read {
            lba: 8 * index,
            bytes: 512,
        })
        .unwrap();
    }
    assert!(!disk.room());
    disk.run(&link);
    assert_eq!(link.writes_to(PORT_SATA_ACTIVE), [1, 2, 4]);
    assert_eq!(link.writes_to(PORT_ISSUE), [1, 2, 4]);
    for slot in 0..3 {
        let fis = &disk.table(slot).bytes()[..14];
        assert_eq!(
            [fis[2], fis[3], fis[4], fis[12]],
            [ATA_READ_FPDMA_QUEUED, 1, 8 * slot as u8, (slot as u8) << 3]
        );
        assert_eq!(
            disk.commands.read::<u64>(slot * COMMAND_HEADER_BYTES + 8),
            disk.table(slot).bus_address()
        );
    }

    // Slot 1 completes first: the Set Device Bits FIS clears its PxSACT
    // bit, and the look marks the FIS area again for the next.
    disk.bounce_mut(1).bytes_mut()[..512].fill(0x11);
    link.registers.borrow_mut()[PORT_SATA_ACTIVE / 4] &= !2;
    disk.commands.write(RECEIVED_SDB, FIS_SET_DEVICE_BITS);
    assert!(disk.posted());
    disk.run(&link);
    assert_eq!(
        disk.running[1].result.take(),
        Some(Ok(Some(vec![0x11; 512])))
    );
    assert!(disk.running[0].result.is_none() && disk.running[2].result.is_none());
    assert_eq!(
        disk.commands.read::<u8>(RECEIVED_SDB),
        FIS_REGISTER_HOST_TO_DEVICE
    );
    disk.running.remove(1);
    assert!(disk.room());

    // Slot 2's read is uncorrectable. The NCQ log names its tag: only it
    // fails, after revalidation without a reset, and slot 0's read runs
    // again uncharged (READ LOG EXT, IDENTIFY, SET FEATURES UDMA 6,
    // IDENTIFY, then the read).
    let log = &mut disk.table.bytes_mut()[LOG_DATA..LOG_DATA + 512];
    log[..4].copy_from_slice(&[2, 0, 0x41, 0x40]);
    disk.bounce_mut(0).bytes_mut()[..512].fill(0x33);
    {
        let mut registers = link.registers.borrow_mut();
        registers[PORT_INTERRUPTS / 4] |= INTERRUPT_TASK_FILE_ERROR;
        registers[PORT_TASK_FILE / 4] = 0x4041;
    }
    // The disk's Set Device Bits FIS carries the error.
    disk.commands.write(RECEIVED_SDB, FIS_SET_DEVICE_BITS);
    let issued = link.issued.get();
    disk.run(&link);
    assert_eq!(link.issued.get() - issued, 5);
    assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
    assert_eq!(
        disk.running[0].result.take(),
        Some(Ok(Some(vec![0x33; 512])))
    );
    assert_eq!(
        disk.running[1].result.take(),
        Some(Err(BlockError::Sense(Sense {
            key: Sense::MEDIUM_ERROR,
            asc: 0x11,
            ascq: 0x04,
        })))
    );
    disk.running.clear();

    // A flush is not queued: it waits until the queued read ends.
    let link = Link::new(&[Fault::Timeout]);
    disk.begin(Command::Read { lba: 0, bytes: 512 }).unwrap();
    disk.begin(Command::Flush).unwrap();
    disk.run(&link);
    assert_eq!(link.writes_to(PORT_ISSUE), [1]);
    link.registers.borrow_mut()[PORT_SATA_ACTIVE / 4] = 0;
    disk.commands.write(RECEIVED_SDB, FIS_SET_DEVICE_BITS);
    disk.run(&link);
    assert_eq!(link.writes_to(PORT_ISSUE), [1, 2]);
    assert_eq!(disk.table(1).bytes()[2], ATA_FLUSH_CACHE_EXT);
    assert_eq!(disk.running[1].result, Some(Ok(None)));
}

#[test]
fn posted_commands_complete_without_synchronous_waits() {
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    // A write is staged in the bounce buffer and completes at once.
    let link = Link::new(&[]);
    let data: Vec<u8> = (0..1024).map(|byte| byte as u8).collect();
    let disk = &mut fixture.disk;
    let tag = disk
        .begin(Command::Write {
            lba: 8,
            data: data.clone(),
            fua: false,
        })
        .unwrap();
    disk.run(&link);
    assert_eq!(disk.running[0].tag, tag);
    assert_eq!(disk.running[0].result.take(), Some(Ok(None)));
    assert_eq!(&disk.bounce.bytes()[..1024], &data[..]);
    assert_eq!(disk.table.bytes()[2], ATA_WRITE_DMA_EXT);
    disk.running.clear();

    // A read the disk has not finished leaves the port running.
    let link = Link::new(&[Fault::Timeout]);
    let tag = disk.begin(Command::Read { lba: 0, bytes: 512 }).unwrap();
    assert!(!disk.room());
    assert_eq!(
        disk.begin(Command::Flush),
        Err(BlockError::Protocol(
            "every AHCI command slot is running a command"
        ))
    );
    disk.run(&link);
    assert!(disk.running[0].result.is_none());
    assert_eq!(link.issued.get(), 1);
    // Its D2H Register FIS arrives with PxCI clear: the next look ends it.
    disk.bounce.bytes_mut()[..512].fill(0x5a);
    link.registers.borrow_mut()[PORT_ISSUE / 4] = 0;
    link.registers.borrow_mut()[PORT_TASK_FILE / 4] = READY;
    disk.commands
        .write(RECEIVED_D2H, FIS_REGISTER_DEVICE_TO_HOST);
    disk.run(&link);
    let running = &mut disk.running[0];
    assert_eq!(running.tag, tag);
    assert_eq!(running.result.take(), Some(Ok(Some(vec![0x5a; 512]))));
    assert_eq!(link.issued.get(), 1);
}

#[test]
fn ncq_limits_and_error_logs_follow_identify_capabilities() {
    // Reference: libata ata_dev_config_ncq and ata_eh_analyze_ncq_error.
    // NCQ with auto-activation, NCQ autosense and READ LOG DMA EXT.
    let mut page = identify_page("S1", 1024);
    for (word, value) in [(76u16, 1u16 << 8), (78, 0x84), (86, 1 << 15), (119, 0x4008)] {
        let at = 2 * usize::from(word);
        page[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    let found = identify(&page).unwrap();
    let (mut fixture, _clock) = recovering(page);
    fixture.disk.ncq.host = true;

    // ata_dev_config_ncq enables auto-activation; a refusal is ignored,
    // any other failure marks it broken.
    let link = Link::new(&[]);
    fixture.disk.configure(&link, &found).unwrap();
    assert_eq!(fixture.disk.table.bytes()[2..4], [ATA_SET_FEATURES, 0x10]);
    assert_eq!(fixture.disk.table.bytes()[12], 0x02);
    let link = Link::new(&[Fault::TaskFile(0x0451)]);
    fixture.disk.configure(&link, &found).unwrap();
    let link = Link::new(&[Fault::Interface]);
    assert!(fixture.disk.configure(&link, &found).is_err());
    assert!(fixture.disk.ncq.aa_broken);
    let link = Link::new(&[]);
    fixture.disk.configure(&link, &found).unwrap();
    assert_eq!(link.issued.get(), 0);
    assert!(fixture.disk.ncq.enabled());

    // A read is queued: the count in the features registers, tag 0.
    let link = Link::new(&[]);
    let read = |fixture: &mut Fixture, link: &Link| {
        fixture
            .disk
            .issue_on(link, ATA_READ_DMA_EXT, 0x1234, 8, 4096, false)
    };
    read(&mut fixture, &link).unwrap();
    let fis = &fixture.disk.table.bytes()[..14];
    assert_eq!(
        [fis[2], fis[3], fis[4], fis[7], fis[11], fis[12]],
        [ATA_READ_FPDMA_QUEUED, 8, 0x34, DEVICE_LBA, 0, 0]
    );
    assert_eq!(link.writes_to(PORT_SATA_ACTIVE), [1]);

    // An uncorrectable queued read: READ LOG DMA EXT fails and READ LOG
    // EXT names tag 0 with its autosense data. A medium error is not
    // retried; ERR_MEDIA revalidates without a reset.
    let log = &mut fixture.disk.table.bytes_mut()[LOG_DATA..LOG_DATA + 512];
    log[..4].copy_from_slice(&[0, 0, 0x43, 0x40]);
    log[14..17].copy_from_slice(&[Sense::MEDIUM_ERROR, 0x11, 0x04]);
    let link = Link::new(&[Fault::TaskFile(0x4041), Fault::TaskFile(0x0451)]);
    assert_eq!(
        read(&mut fixture, &link),
        Err(BlockError::Sense(Sense {
            key: Sense::MEDIUM_ERROR,
            asc: 0x11,
            ascq: 0x04,
        }))
    );
    assert!(fixture.disk.no_dma_log);
    // The read, both log reads, then IDENTIFY, SET FEATURES UDMA 6 and
    // IDENTIFY; auto-activation stays broken.
    assert_eq!(link.issued.get(), 6);
    assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());

    // Four aborted reads in ten minutes turn NCQ off, without a reset.
    fixture.disk.table.bytes_mut()[LOG_DATA + 2..LOG_DATA + 4].copy_from_slice(&[0x51, 0x04]);
    for _ in 0..4 {
        assert!(fixture.disk.ncq.enabled());
        let link = Link::new(&[Fault::TaskFile(0x0451)]);
        read(&mut fixture, &link).unwrap();
        assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
    }
    assert!(fixture.disk.ncq.off);
    read(&mut fixture, &Link::new(&[])).unwrap();
    assert_eq!(fixture.disk.table.bytes()[2], ATA_READ_DMA_EXT);
}

#[test]
fn completion_acknowledgment_preserves_command_progress() {
    let mut fixture = Fixture::new();
    let model = Link::new(&[]);
    fixture
        .disk
        .issue_on(&model, ATA_WRITE_DMA_EXT, 7, 1, 512, true)
        .unwrap();
    assert!(fixture.disk.fault.is_none());
    assert_eq!(fixture.disk.table.bytes()[2], ATA_WRITE_DMA_EXT);
    assert_eq!(fixture.disk.commands.read::<u32>(0), 5 | 1 << 6 | 1 << 16);
    fixture
        .disk
        .issue_on(&model, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)
        .unwrap();
    assert!(fixture.disk.fault.is_none());
    assert_eq!(fixture.disk.commands.read::<u32>(0), 5);
    assert_eq!(
        model
            .writes
            .borrow()
            .iter()
            .filter(|(offset, _)| *offset == PORT_ISSUE)
            .count(),
        2
    );
}
