// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright 2004-2005 Red Hat, Inc.
//! AHCI recovery cases.
use super::*;
#[test]
fn taskfile_faults_retry_after_engine_restart() {
    // Reference: libata ata_eh_worth_retry.
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
fn timeout_and_interface_faults_reset_before_retry() {
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
fn repeated_interface_faults_reduce_link_speed() {
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

#[test]
fn an_expired_command_is_named_with_the_registers_it_ended_with() {
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&[Fault::Timeout]);
    let buffer = fixture.disk.bounce.bus_address();
    let Err(failure) = fixture
        .disk
        .internal(&link, ATA_IDENTIFY, 0, 0, 512, buffer)
    else {
        panic!("a dropped IDENTIFY fails");
    };
    assert_ne!(failure.mask & ERR_TIMEOUT, 0);
    let BlockError::Expired(expired) = &failure.error else {
        panic!("{:?}", failure.error);
    };
    assert_eq!(
        expired.step,
        "ATA IDENTIFY DEVICE (0xec), waiting for its PxCI bit to clear"
    );
    assert!(expired.waited_us >= fixture.disk.command_timeout_us);
    assert_eq!(
        expired
            .registers
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        [
            "PxCI", "PxSACT", "PxTFD", "PxSSTS", "PxIS", "PxSERR", "PxCMD"
        ]
    );
    assert_eq!(expired.registers[0].1, 1);
    assert_eq!(expired.registers[2].1, 0xd0);
    let line = alloc::format!("{}", failure.error);
    assert!(
        line.starts_with("ATA IDENTIFY DEVICE (0xec), waiting for its PxCI bit to clear: not done after 1 ms; PxCI=0x1 PxSACT=0x0 PxTFD=0xd0 PxSSTS="),
        "{line}"
    );
}

/// A disk whose first IDENTIFY is answered with `page`, with production
/// command timeouts.
fn starting() -> (Fixture, crate::test_clock::Guard) {
    let (mut fixture, clock) = recovering(identify_page("S1", 1024));
    fixture.disk.command_timeout_us = COMMAND_TIMEOUT_US;
    let page = identify_page("S1", 1024);
    fixture.disk.bounce.bytes_mut()[..512].copy_from_slice(&page);
    (fixture, clock)
}

#[test]
fn internal_commands_take_linux_timeouts_and_wait_longer_after_one_expired() {
    // Reference: ata_eh_cmd_timeout_table, ata_internal_cmd_timeout and
    // ata_internal_cmd_timed_out.
    let (mut fixture, _clock) = starting();
    let disk = &mut fixture.disk;
    for (command, timeouts) in [
        (
            ATA_IDENTIFY,
            [5_000_000, 10_000_000, 30_000_000, 30_000_000],
        ),
        (
            ATA_SET_FEATURES,
            [5_000_000, 10_000_000, 10_000_000, 10_000_000],
        ),
        (ATA_READ_LOG_DMA_EXT, [15_000_000; 4]),
        (ATA_STANDBY_IMMEDIATE, [15_000_000; 4]),
        (ATA_REQUEST_SENSE_DATA_EXT, [5_000_000; 4]),
    ] {
        for timeout in timeouts {
            assert_eq!(disk.internal_timeout_us(command), timeout, "{command:#x}");
            disk.internal_timed_out(command);
        }
    }
    // READ LOG EXT shares its class with READ LOG DMA EXT.
    assert_eq!(disk.internal_timeout_us(ATA_READ_LOG_EXT), 15_000_000);
    // Never longer than a block command's.
    disk.command_timeout_us = 1_000;
    assert_eq!(disk.internal_timeout_us(ATA_IDENTIFY), 1_000);
    // Each error handling run starts again at the first.
    disk.command_timeout_us = COMMAND_TIMEOUT_US;
    let link = Link::new(&[]);
    let mut failure = Failure::new(BlockError::Timeout);
    disk.recover(&link, &mut failure, false).unwrap();
    assert_eq!(disk.internal_timeout_us(ATA_IDENTIFY), 5_000_000);
    assert_eq!(disk.internal_timeout_us(ATA_SET_FEATURES), 5_000_000);
}

#[test]
fn a_first_identify_the_disk_drops_is_retried_after_a_hard_reset() {
    // Reference: ata_eh_recover with ata_dev_read_id and
    // ata_eh_handle_dev_fail; ata_eh_identify_timeouts.
    let (mut fixture, _clock) = starting();
    let clock = fixture.disk.clock;
    let start = clock.try_start().unwrap();
    let link = Link::new(&[Fault::Timeout]);
    let found = fixture.disk.first_identify(&link).unwrap();
    assert_eq!(found.serial, "S1");
    assert_eq!(link.issued.get(), 2);
    // The dropped IDENTIFY cost its first timeout, 5 s, then a hard reset.
    let took = clock.try_elapsed_us(start).unwrap();
    assert!((5_000_000..6_000_000).contains(&took), "{took}");
    let controls: Vec<u32> = link
        .writes_to(PORT_SATA_CONTROL)
        .iter()
        .map(|control| control & 0xf0f)
        .collect();
    assert_eq!(controls, [0x301, 0x300]);
    // The next IDENTIFY in this run would wait 10 s.
    assert_eq!(fixture.disk.internal_timeout_us(ATA_IDENTIFY), 10_000_000);
}

#[test]
fn a_first_identify_that_never_completes_fails_after_three_tries_naming_its_wait() {
    let (mut fixture, _clock) = starting();
    let clock = fixture.disk.clock;
    let start = clock.try_start().unwrap();
    let link = Link::new(&[Fault::Timeout; 3]);
    let Err(error) = fixture.disk.first_identify(&link) else {
        panic!("a disk that never answers is refused");
    };
    assert_eq!(link.issued.get(), 3);
    // 5, 10 and 30 s, the last try at a lower link speed.
    let took = clock.try_elapsed_us(start).unwrap();
    assert!((45_000_000..47_000_000).contains(&took), "{took}");
    assert_eq!(fixture.disk.speed_limit, 0b1);
    let BlockError::Expired(expired) = &error else {
        panic!("{error:?}");
    };
    assert!((30_000_000..30_100_000).contains(&expired.waited_us));
    assert_eq!(expired.registers[0], ("PxCI", 1));
    assert_eq!(expired.registers[2], ("PxTFD", 0xd0));
    let line = alloc::format!("{error}");
    assert!(
        line.starts_with(
            "ATA IDENTIFY DEVICE (0xec), waiting for its PxCI bit to clear: not done after 30"
        ),
        "{line}"
    );
    assert!(
        line.contains("; PxCI=0x1 PxSACT=0x0 PxTFD=0xd0 PxSSTS="),
        "{line}"
    );
}

#[test]
fn a_first_identify_the_disk_refuses_is_not_retried() {
    let (mut fixture, _clock) = starting();
    let link = Link::new(&[Fault::TaskFile(0x0451)]);
    assert!(matches!(
        fixture.disk.first_identify(&link),
        Err(BlockError::Device { .. })
    ));
    assert_eq!(link.issued.get(), 1);
    assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
}
