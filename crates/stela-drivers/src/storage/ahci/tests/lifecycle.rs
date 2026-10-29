//! AHCI lifecycle cases.
use super::*;
#[test]
fn amd_raid_class_functions_bind_like_ahci_pci_tbl() {
    struct Config([u32; 4]);
    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            self.0[usize::from(offset / 4)]
        }
        fn write32(&mut self, _: u16, _: u32) {}
    }
    let function = |vendor: u32, class: u32| {
        let address = crate::bus::pci::Address {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
        };
        Function::new(address, Config([0x43f6 << 16 | vendor, 0, class << 8, 0])).unwrap()
    };
    assert!(matches(&function(0x1022, 0x01_06_01)));
    assert!(matches(&function(0x8086, 0x01_06_01)));
    assert!(matches(&function(0x1022, 0x01_04_00)));
    assert!(!matches(&function(0x8086, 0x01_04_00)));
    assert!(!matches(&function(0x1022, 0x01_04_01)));
    assert!(!matches(&function(0x1022, 0x01_06_00)));
}

#[test]
fn a_disk_that_leaves_or_changes_is_disabled() {
    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    let link = Link::new(&[Fault::Gone]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Err(DETACHED)
    );
    assert_eq!(fixture.disk.fault, Some(DETACHED));
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
        Err(DETACHED)
    );
    assert_eq!(link.issued.get(), 1);

    for page in [identify_page("S2", 1024), identify_page("S1", 2048)] {
        let (mut fixture, _clock) = recovering(page);
        let link = Link::new(&[Fault::Timeout]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Err(DETACHED)
        );
        // One more chance, slower, as ata_eh_handle_dev_fail gives.
        assert_eq!(link.issued.get(), 3);
        assert_eq!(fixture.disk.speed_limit, 0b1);
        assert_eq!(fixture.disk.pio_mask, 0x0f);
        assert_eq!(fixture.disk.fault, Some(DETACHED));
    }
}
#[test]
fn ports_stop_the_command_list_before_fis_reception() {
    let port = Engines {
        command: Cell::new(
            COMMAND_START | COMMAND_LIST_RUNNING | COMMAND_FIS_RECEIVE | COMMAND_FIS_RUNNING,
        ),
        writes: RefCell::new(Vec::new()),
    };
    // This peer acknowledges both engine stops immediately; its finite
    // clock remains admitted even when no waiting is needed.
    let clock = Clock {
        ticks_per_microsecond: 1000,
    };
    stop_port(&port, clock).unwrap();
    let enables: Vec<u32> = port
        .writes
        .borrow()
        .iter()
        .map(|value| value & (COMMAND_START | COMMAND_FIS_RECEIVE))
        .collect();
    assert_eq!(enables, [COMMAND_FIS_RECEIVE, 0]);
    assert_eq!(port.command.get(), 0);
}

#[test]
fn invalid_clock_never_attempts_an_engine_transition() {
    for ticks_per_microsecond in [0, u64::MAX, u64::MAX / (2 * COMMAND_TIMEOUT_US) + 1] {
        let command =
            COMMAND_START | COMMAND_LIST_RUNNING | COMMAND_FIS_RECEIVE | COMMAND_FIS_RUNNING;
        let port = Engines {
            command: Cell::new(command),
            writes: RefCell::new(Vec::new()),
        };
        assert!(
            stop_port(
                &port,
                Clock {
                    ticks_per_microsecond
                }
            )
            .is_err()
        );
        assert!(port.writes.borrow().is_empty());
        assert_eq!(port.command.get(), command);
    }
}

#[test]
fn an_unprogrammed_port_map_comes_from_the_port_count() {
    assert_eq!(port_map(0x4000_0005, 0), 0x3f);
    assert_eq!(port_map(CAP_PORTS, 0), u32::MAX);
    assert_eq!(port_map(0x5, 0x21), 0x21);
}
