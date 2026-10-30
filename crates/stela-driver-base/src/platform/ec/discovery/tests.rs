use super::*;
use alloc::vec::Vec;

fn checksum(bytes: &mut [u8], offset: usize) {
    bytes[offset] = 0;
    bytes[offset] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
}
fn ecdt() -> Vec<u8> {
    let mut bytes = alloc::vec![0; 65];
    bytes[..4].copy_from_slice(b"ECDT");
    bytes[8] = 1;
    for (offset, address) in [(36, 0x66u64), (48, 0x62)] {
        bytes[offset..offset + 4].copy_from_slice(&[1, 8, 0, 1]);
        bytes[offset + 4..offset + 12].copy_from_slice(&address.to_le_bytes());
    }
    bytes[60..64].copy_from_slice(&0x12ab_cdefu32.to_le_bytes());
    bytes[64] = 0x17;
    bytes.extend(b"\\_SB.PCI0.LPCB.EC0\0");
    let length = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&length.to_le_bytes());
    checksum(&mut bytes, 9);
    bytes
}
fn crs() -> Vec<u8> {
    // Small IO descriptors, first data and then command/status.
    alloc::vec![
        0x47, 1, 0x62, 0, 0x62, 0, 1, 1, 0x47, 1, 0x66, 0, 0x66, 0, 1, 1, 0x79, 0
    ]
}

#[test]
fn ecdt_preserves_addresses_uid_gpe_and_path() {
    let mut table = ecdt();
    let parsed = Ecdt::parse(&table).unwrap();
    assert_eq!(
        parsed.ports(),
        Ok(Ports {
            data: 0x62,
            command: 0x66
        })
    );
    assert_eq!(parsed.uid, 0x12ab_cdef);
    assert_eq!(parsed.gpe, 0x17);
    assert_eq!(parsed.path, "\\_SB.PCI0.LPCB.EC0");
    // GAS unspecified access width is legitimate for an 8-bit EC register.
    table[39] = 0;
    table[51] = 0;
    checksum(&mut table, 9);
    assert!(Ecdt::parse(&table).is_ok());
    // A memory descriptor remains a memory descriptor, never a guessed IO port.
    table[36] = 0;
    checksum(&mut table, 9);
    assert_eq!(Ecdt::parse(&table).unwrap().control, Register::Memory(0x66));
    assert_eq!(Ecdt::parse(&table).unwrap().ports(), Err(Error::Ports));
}

#[test]
fn malformed_ecdt_never_publishes_usable_resources() {
    let table = ecdt();
    for len in 0..table.len() {
        assert!(Ecdt::parse(&table[..len]).is_err());
    }
    for (offset, value) in [
        (0, b'F'),
        (9, 1),
        (37, 16),
        (38, 1),
        (39, 2),
        (36, 2),
        (40, 0),
        (43, 1),
        (65, 0),
        (65, 0xff),
        (65, 10),
    ] {
        let mut invalid = table.clone();
        invalid[offset] = value;
        if offset != 9 {
            checksum(&mut invalid, 9);
        }
        assert!(Ecdt::parse(&invalid).is_err(), "offset {offset}");
    }
    let mut aliased = table.clone();
    aliased[40] = 0x62;
    checksum(&mut aliased, 9);
    assert_eq!(Ecdt::parse(&aliased), Err(Error::Register));
    let mut unterminated = table;
    *unterminated.last_mut().unwrap() = b'0';
    checksum(&mut unterminated, 9);
    assert_eq!(Ecdt::parse(&unterminated), Err(Error::Path));
}

#[test]
fn namespace_resources_require_complete_fixed_byte_ports_and_termination() {
    let bytes = crs();
    assert_eq!(
        Ports::from_crs(&bytes),
        Ok(Ports {
            data: 0x62,
            command: 0x66
        })
    );
    for len in 0..bytes.len() {
        assert!(Ports::from_crs(&bytes[..len]).is_err());
    }
    let mut checked = bytes.clone();
    checksum(&mut checked, 17);
    assert!(Ports::from_crs(&checked).is_ok());
    checked[17] ^= 1;
    assert_eq!(Ports::from_crs(&checked), Err(Error::Checksum));
    for (offset, value) in [
        (1, 2),
        (2, 0),
        (4, 0x63),
        (7, 2),
        (10, 0x62),
        (12, 0x62),
        (16, 0x78),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset] = value;
        assert!(Ports::from_crs(&invalid).is_err(), "offset {offset}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(Ports::from_crs(&extra), Err(Error::Length));
    // An IRQ/GPIO requirement may not be discarded by a byte-only IO parser.
    let mut irq = alloc::vec![0x22, 1, 0];
    irq.extend(bytes);
    assert_eq!(Ports::from_crs(&irq), Err(Error::UnsupportedResource(0x22)));
}

#[test]
fn vendor_metadata_is_not_mistaken_for_ec_registers() {
    let mut bytes = alloc::vec![0x73, 1, 2, 3, 0x84, 2, 0, 8, 9];
    bytes.extend(crs());
    assert_eq!(
        Ports::from_crs(&bytes),
        Ok(Ports {
            data: 0x62,
            command: 0x66
        })
    );
    let mut duplicate = crs();
    duplicate.splice(16..16, [0x47, 1, 0x80, 0, 0x80, 0, 1, 1]);
    assert_eq!(Ports::from_crs(&duplicate), Err(Error::Resource));
}
