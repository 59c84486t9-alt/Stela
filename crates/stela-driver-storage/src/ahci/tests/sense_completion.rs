//! AHCI sense completion cases.
use super::*;
#[test]
fn revalidation_restores_sense_reporting() {
    // Reference: libata ata_dev_configure.
    // A disk whose reset left Sense Data Reporting supported but off.
    let mut page = identify_page("S1", 1024);
    for (word, value) in [(86u16, 1u16 << 15), (119, 0x4040), (120, 0x4000)] {
        let at = 2 * usize::from(word);
        page[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    let issued = |page| {
        let (mut fixture, _clock) = recovering(page);
        let link = Link::new(&[Fault::Timeout]);
        fixture
            .disk
            .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)
            .unwrap();
        link.issued.get()
    };
    // Each of the two revalidations turns it back on.
    assert_eq!(issued(page), issued(identify_page("S1", 1024)) + 2);
}

#[test]
fn sense_fetch_results_decide_command_completion() {
    // The disk's D2H FIS for REQUEST SENSE DATA EXT.
    let reply = |fixture: &mut Fixture, status: u8, sense: [u8; 3]| {
        let d2h = &mut fixture.disk.commands.bytes_mut()[RECEIVED_D2H..];
        d2h[2] = status;
        d2h[4] = sense[2];
        d2h[5] = sense[1];
        d2h[6] = sense[0];
    };
    // Each failing command, then REQUEST SENSE DATA EXT.
    let failing = |task_file, times| {
        let link = Link::new(&[]);
        for _ in 0..times {
            link.faults
                .borrow_mut()
                .extend([Fault::TaskFile(task_file), Fault::Complete]);
        }
        link
    };
    // ERR | SENSE with ABRT: a medium error the disk could not recover
    // fails without a retry, carrying the sense.
    // Revalidation rereads Sense Data Reporting as enabled.
    let mut page = identify_page("S1", 1024);
    for (word, value) in [(86u16, 1u16 << 15), (119, 0x4040), (120, 0x4040)] {
        let at = 2 * usize::from(word);
        page[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    let (mut fixture, _clock) = recovering(page);
    reply(&mut fixture, 0x52, [Sense::MEDIUM_ERROR, 0x11, 0x04]);
    let link = Link::new(&[Fault::TaskFile(0x0453)]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Err(BlockError::Sense(Sense {
            key: Sense::MEDIUM_ERROR,
            asc: 0x11,
            ascq: 0x04
        }))
    );
    // The read, then REQUEST SENSE DATA EXT.
    assert_eq!(link.issued.get(), 2);
    assert_eq!(fixture.disk.table.bytes()[2], ATA_REQUEST_SENSE_DATA_EXT);
    // Without ERR_DEV the error is not charged to the device.
    assert_eq!(fixture.disk.errors.newest().count(), 0);

    // A recovered error is success.
    reply(&mut fixture, 0x52, [Sense::RECOVERED_ERROR, 0x17, 0x01]);
    let link = Link::new(&[Fault::TaskFile(0x0453)]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Ok(())
    );
    assert_eq!(link.issued.get(), 2);

    // A unit attention is requeued at once, outside the retry count.
    reply(&mut fixture, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0x00]);
    let link = failing(0x0453, 7);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 0, 1, 512, true),
        Ok(())
    );
    assert_eq!(link.issued.get(), 15);

    // An uncorrectable error with sense needing a retry keeps
    // ERR_MEDIA, so EH revalidates the disk and retries it five times;
    // sd then fails it.
    reply(&mut fixture, 0x52, [Sense::MEDIUM_ERROR, 0x0c, 0x00]);
    let link = Link::new(&[]);
    for _ in 0..6 {
        link.faults
            .borrow_mut()
            .extend([Fault::TaskFile(0x4053), Fault::Complete]);
        link.faults.borrow_mut().extend([Fault::Complete; 3]);
    }
    assert!(matches!(
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 0, 1, 512, true),
        Err(BlockError::Sense(_))
    ));
    assert_eq!(link.issued.get(), 6 * 5);

    // A disk still becoming ready is requeued until sd's runtime ends.
    reply(&mut fixture, 0x52, [Sense::NOT_READY, 0x04, 0x01]);
    // At 1000 µs per command timeout the runtime is 6 ms: the 9 ms
    // requeue delay allows exactly one requeue.
    let link = failing(0x0453, 2);
    assert!(matches!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Err(BlockError::Sense(_))
    ));
    assert_eq!(link.issued.get(), 4);

    // No sense without the SENSE status, with a device fault, with
    // reporting off, or with invalid sense.
    for (task_file, reporting, status, sense) in [
        (0x0451, true, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0]),
        (0x0473, true, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0]),
        (0x0453, false, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0]),
        (0x0453, true, 0x50, [Sense::UNIT_ATTENTION, 0x29, 0]),
        (0x0453, true, 0x52, [0, 0, 0]),
        (0x0453, true, 0x52, [0x10, 0x29, 0]),
    ] {
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        fixture.disk.sense_reporting = reporting;
        reply(&mut fixture, status, sense);
        let link = Link::new(&[Fault::TaskFile(task_file)]);
        assert!(matches!(
            fixture
                .disk
                .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
            Err(BlockError::Device { .. })
        ));
    }
}
