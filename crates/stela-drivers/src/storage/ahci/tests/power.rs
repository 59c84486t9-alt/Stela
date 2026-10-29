//! AHCI power cases.
use super::*;
#[test]
fn link_power_policy_follows_port_and_device_features() {
    // Reference: libata ata_eh_link_set_lpm.
    let host = CAP_AGGRESSIVE_LPM | CAP_SLUMBER | CAP_PARTIAL;
    // Hotplug-capable and eSATA ports, and hosts without LPM states,
    // stay at maximum power.
    assert!(!Lpm::new(host, 0, COMMAND_HOTPLUG).allowed);
    assert!(!Lpm::new(host | CAP_EXTERNAL, 0, COMMAND_EXTERNAL).allowed);
    assert!(Lpm::new(host, 0, COMMAND_EXTERNAL).allowed);
    assert!(!Lpm::new(CAP_AGGRESSIVE_LPM, 0, 0).allowed);
    assert!(Lpm::new(CAP_AGGRESSIVE_LPM, CAP2_DEVICE_SLEEP, 0).allowed);

    let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
    fixture.disk.lpm = Lpm {
        hipm: true,
        dipm: true,
        ..Lpm::new(host, 0, 0)
    };
    let link = Link::new(&[]);
    fixture.disk.configure_lpm(&link, DEVICE_TRIES).unwrap();
    // DIPM off and on around Partial and Slumber allowed with ALPE.
    assert_eq!(link.issued.get(), 2);
    assert_eq!(link.writes_to(PORT_SATA_CONTROL), [0x400]);
    assert_ne!(link.read32(PORT_COMMAND) & COMMAND_AGGRESSIVE_LPM, 0);
    assert_eq!(fixture.disk.lpm.policy, LPM_MED_POWER_WITH_DIPM);

    // A hard reset wakes the link to maximum power before revalidating,
    // then restores the policy; without HIPM, ALPE stays off.
    fixture.disk.lpm.hipm = false;
    let link = Link::new(&[Fault::Timeout]);
    assert_eq!(
        fixture
            .disk
            .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
        Ok(())
    );
    let controls = link.writes_to(PORT_SATA_CONTROL);
    assert!(controls.ends_with(&[0x700, 0x400]), "{controls:x?}");
    assert_eq!(link.read32(PORT_COMMAND) & COMMAND_AGGRESSIVE_LPM, 0);
    assert_eq!(fixture.disk.lpm.policy, LPM_MED_POWER_WITH_DIPM);

    // A failure with two tries left disables LPM; the old policy stays.
    // (The revalidation's IDENTIFY data reported no DIPM.)
    fixture.disk.lpm.dipm = true;
    let link = Link::new(&[Fault::Timeout]);
    assert_eq!(
        fixture.disk.set_lpm(&link, LPM_MAX_POWER, 2),
        Err(BlockError::Timeout)
    );
    assert!(!fixture.disk.lpm.allowed);
    assert_eq!(fixture.disk.lpm.policy, LPM_MED_POWER_WITH_DIPM);
}

#[test]
fn devslp_uses_reported_timing_and_port_capabilities() {
    // Reference: ata_dev_config_devslp and ahci_set_aggressive_devslp.
    let mut page = identify_page("S1", 1024);
    page[2 * 78..2 * 78 + 2].copy_from_slice(&(1u16 << 8).to_le_bytes());
    let found = identify(&page).unwrap();
    let (mut fixture, _clock) = recovering(page);
    // One buffer answers all three log reads: the directory lists the
    // IDENTIFY DEVICE data log, whose page 0 lists SATA Settings.
    let log = &mut fixture.disk.table.bytes_mut()[LOG_DATA..LOG_DATA + 512];
    (log[8], log[9], log[2 * 0x30]) = (1, LOG_SATA_SETTINGS, 1);
    let link = Link::new(&[]);
    fixture.disk.configure(&link, &found).unwrap();
    assert!(fixture.disk.devslp);
    assert_eq!(link.issued.get(), 3);

    // Firmware's aggressive DevSleep is turned off on the way to
    // max_power, before SControl lifts the restrictions.
    fixture.disk.lpm.capabilities_2 = CAP2_DEVICE_SLEEP | CAP2_AGGRESSIVE_DEVICE_SLEEP;
    link.registers.borrow_mut()[PORT_DEVICE_SLEEP / 4] = 0x3;
    fixture.disk.apply_lpm(&link, LPM_MAX_POWER).unwrap();
    assert_eq!(link.writes_to(PORT_DEVICE_SLEEP), [DEVICE_SLEEP_PRESENT]);
    let table = fixture.disk.table.bytes();
    assert_eq!(
        [table[2], table[3], table[12]],
        [ATA_SET_FEATURES, 0x90, 0x09]
    );
    let order: Vec<usize> = link
        .writes
        .borrow()
        .iter()
        .filter(|(at, _)| matches!(*at, PORT_DEVICE_SLEEP | PORT_SATA_CONTROL))
        .map(|(at, _)| *at)
        .collect();
    assert_eq!(order, [PORT_DEVICE_SLEEP, PORT_SATA_CONTROL]);

    // Without the IDENTIFY DEVICE data log the disk gets NO_ID_DEV_LOG.
    fixture.disk.table.bytes_mut()[LOG_DATA + 2 * 0x30] = 0;
    fixture.disk.configure(&link, &found).unwrap();
    assert!(!fixture.disk.devslp);
    assert_ne!(fixture.disk.quirks & quirks::NO_ID_DEV_LOG, 0);
}

#[test]
fn flush_opcode_follows_write_cache_capabilities() {
    let identify = |defaults: u16, enabled: u16, commands: u16| {
        move |index: usize| match index {
            IDENTIFY_DEFAULTS => defaults,
            IDENTIFY_ENABLED_1 => enabled,
            IDENTIFY_COMMANDS_2 => commands,
            _ => 0,
        }
    };
    let cache = ENABLED_1_WRITE_CACHE;
    let ext = WORD_VALID | COMMANDS_2_LBA48 | COMMANDS_2_FLUSH_EXT;
    assert_eq!(
        flush_command(identify(WORD_VALID, cache, ext)),
        Some(ATA_FLUSH_CACHE_EXT)
    );
    // Without the extended command, or with word 83 unsigned.
    assert_eq!(
        flush_command(identify(WORD_VALID, cache, ext & !COMMANDS_2_FLUSH_EXT)),
        Some(ATA_FLUSH_CACHE)
    );
    assert_eq!(
        flush_command(identify(WORD_VALID, cache, ext & !WORD_VALID)),
        Some(ATA_FLUSH_CACHE)
    );
    // A disabled or unreported write cache needs no flush.
    assert_eq!(flush_command(identify(WORD_VALID, 0, ext)), None);
    assert_eq!(flush_command(identify(0, cache, ext)), None);

    let mut fixture = Fixture::new();
    fixture.disk.flush = None;
    let issued = fixture.disk.port.read32(PORT_ISSUE);
    assert_eq!(fixture.disk.flush_cache(), Ok(()));
    assert_eq!(fixture.disk.port.read32(PORT_ISSUE), issued);
    fixture.disk.fault = Some(BlockError::Timeout);
    assert_eq!(fixture.disk.flush_cache(), Err(BlockError::Timeout));
}
