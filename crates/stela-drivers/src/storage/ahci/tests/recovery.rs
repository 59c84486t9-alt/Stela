//! AHCI recovery cases.
use super::*;
#[test]
fn device_errors_restart_the_engine_and_follow_ata_eh_worth_retry() {
    // An aborted read revalidates the disk without a reset (IDENTIFY,
    // SET FEATURES with UDMA 6 and its IDENTIFY) and is retried after
    // the engine restarts.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&[Fault::TaskFile(0x0451)]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Ok(())
    );
    assert_eq!(link.issued.get(), 5);
    let starts: Vec<u32> = link
        .writes_to(PORT_COMMAND)
        .iter()
        .map(|command| command & COMMAND_START)
        .collect();
    assert_eq!(starts, [0, COMMAND_START]);
    assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
    assert!(fixture.disk.fault.is_none());

    // A media error is not retried, and the disk stays usable.
    let link = Link::new(&[Fault::TaskFile(0x4051)]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Err(BlockError::Device { status: 0x4051 })
    );
    assert_eq!(link.issued.get(), 4);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Ok(())
    );

    // Nor is a plain device error on a command that is not I/O.
    let link = Link::new(&[Fault::TaskFile(0x0451)]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
        Err(BlockError::Device { status: 0x0451 })
    );
    assert_eq!(link.issued.get(), 1);

    // I/O is retried five times, as sd allows.
    drop(fixture);
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&[]);
    for _ in 0..7 {
        link.faults.borrow_mut().extend([
            Fault::TaskFile(0x0451),
            Fault::Complete,
            Fault::Complete,
            Fault::Complete,
        ]);
    }
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 0, 1, 512, true),
        Err(BlockError::Device { status: 0x0451 })
    );
    assert_eq!(link.issued.get(), 6 * 4);
    assert!(fixture.disk.fault.is_none());
}

#[test]
fn timeouts_and_link_errors_hard_reset_revalidate_and_retry() {
    for fault in [Fault::Timeout, Fault::Interface, Fault::TaskFile(0x8051)] {
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        fixture.disk.bounce.bytes_mut()[..512].fill(0x44);
        let link = Link::new(&[fault]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
            Ok(())
        );
        // The write, the revalidating IDENTIFY, SET FEATURES with UDMA 6
        // and its IDENTIFY, and the write again.
        assert_eq!(link.issued.get(), 5);
        let controls: Vec<u32> = link
            .writes_to(PORT_SATA_CONTROL)
            .iter()
            .map(|control| control & 0xf0f)
            .collect();
        assert_eq!(controls, [0x301, 0x300]);
        // The retried write still carries its data.
        assert!(
            fixture.disk.bounce.bytes()[..512]
                .iter()
                .all(|byte| *byte == 0x44)
        );
        assert_eq!(fixture.disk.table.bytes()[2], ATA_WRITE_DMA_EXT);
        assert_eq!(fixture.disk.mode, 0x46);
        assert_eq!(
            fixture.disk.commands.bytes()[RECEIVED_D2H..RECEIVED_D2H + 8],
            [0x27, 0, 0x80, 0, 0, 0, 0, 0xa0]
        );
        assert!(fixture.disk.fault.is_none());
    }
}

#[test]
fn repeated_link_errors_lower_the_sata_speed_like_linux() {
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&[]);
    link.fastest.set(3);
    link.registers.borrow_mut()[PORT_SATA_STATUS / 4] = 0x133;
    fixture.disk.speed = 3;
    let controls = |link: &Link| -> Vec<u32> {
        link.writes_to(PORT_SATA_CONTROL)
            .iter()
            .map(|control| control & 0xfff)
            .collect()
    };
    // Three verified bus errors only reset the link.
    for _ in 0..3 {
        link.faults.borrow_mut().push_back(Fault::Interface);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
            Ok(())
        );
    }
    assert_eq!(controls(&link), [0x301u32, 0x300].repeat(3));
    // The fourth lowers the limit below 6 Gbps, turning the Phy off to
    // program it, and clears the history.
    link.writes.borrow_mut().clear();
    link.faults.borrow_mut().push_back(Fault::Interface);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
        Ok(())
    );
    assert_eq!(fixture.disk.speed_limit, 0b11);
    assert_eq!(controls(&link), [0x304, 0x324, 0x321, 0x320]);
    assert_eq!(fixture.disk.speed, 2);
    assert_eq!(
        fixture
            .disk
            .errors
            .newest()
            .filter(|e| e.eflags & EFLAG_OLD == 0)
            .count(),
        0
    );
    // Four more reach 1.5 Gbps, the bottom.
    for _ in 0..4 {
        link.faults.borrow_mut().push_back(Fault::Interface);
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
            .unwrap();
    }
    assert_eq!(fixture.disk.speed_limit, 0b1);
    assert_eq!(fixture.disk.speed, 1);
    for _ in 0..4 {
        link.faults.borrow_mut().push_back(Fault::Interface);
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
            .unwrap();
    }
    assert_eq!(fixture.disk.speed_limit, 0b1);
    assert!(fixture.disk.fault.is_none());
    // Past the slowest link the UDMA mode steps down, to UDMA 5 and
    // then to the 40-wire UDMA 2, each reprogrammed with SET FEATURES.
    assert_eq!((fixture.disk.udma_mask, fixture.disk.mode), (0x3f, 0x45));
    for _ in 0..4 {
        link.faults.borrow_mut().push_back(Fault::Interface);
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
            .unwrap();
    }
    assert_eq!((fixture.disk.udma_mask, fixture.disk.mode), (0x07, 0x42));
    for _ in 0..4 {
        link.faults.borrow_mut().push_back(Fault::Interface);
        fixture
            .disk
            .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
            .unwrap();
    }
    assert_eq!((fixture.disk.udma_mask, fixture.disk.step_downs), (0x07, 2));

    // Before a verified transfer, two bus errors suffice and the
    // history is kept. A flush transfers no data and verifies nothing.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    fixture.disk.dubious = true;
    let link = Link::new(&[]);
    for _ in 0..2 {
        link.faults.borrow_mut().push_back(Fault::Interface);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
            Ok(())
        );
    }
    assert_eq!(fixture.disk.speed_limit, 0b1);
    assert_eq!(fixture.disk.errors.newest().count(), 2);
    assert!(fixture.disk.dubious);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Ok(())
    );
    assert!(!fixture.disk.dubious);

    // Device errors that only revalidate get a reset when they slow the
    // link.
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&[]);
    for _ in 0..6 {
        link.faults.borrow_mut().extend([
            Fault::TaskFile(0x0451),
            Fault::Complete,
            Fault::Complete,
            Fault::Complete,
        ]);
    }
    assert!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false)
            .is_err()
    );
    assert!(controls(&link).is_empty());
    link.faults.borrow_mut().push_back(Fault::TaskFile(0x0451));
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Ok(())
    );
    assert_eq!(fixture.disk.speed_limit, 0b1);
    assert_eq!(controls(&link), [0x304, 0x314, 0x311, 0x310]);
}
