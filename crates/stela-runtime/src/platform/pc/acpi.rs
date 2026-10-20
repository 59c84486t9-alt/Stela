//! The ACPI tables the host drivers need: the RSDP's root table, the
//! MCFG table that locates PCI configuration space, and any table by
//! address ([`power`](super::power) reads the FADT and DSDT).
use alloc::vec::Vec;
use stela_drivers::bus::pci::EcamWindow;

const HEADER: usize = 36;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    BadRsdp,
    BadTable([u8; 4]),
    Missing([u8; 4]),
}

fn checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// # Safety
///
/// `address` must be readable, identity-mapped memory holding at least an
/// SDT header, and the length that header names.
pub unsafe fn table(address: u64) -> Result<&'static [u8], AcpiError> {
    // SAFETY: the caller's contract covers the header.
    let header = unsafe { core::slice::from_raw_parts(address as *const u8, HEADER) };
    let signature: [u8; 4] = header[..4].try_into().unwrap();
    let length = u32_at(header, 4) as usize;
    if length < HEADER {
        return Err(AcpiError::BadTable(signature));
    }
    // SAFETY: the caller's contract covers the named length.
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
    if !checksum(bytes) {
        return Err(AcpiError::BadTable(signature));
    }
    Ok(bytes)
}

/// Find a table by signature through the XSDT, or the RSDT on ACPI 1.0.
///
/// # Safety
///
/// `rsdp` must be the firmware's RSDP, with every table it reaches mapped.
pub unsafe fn find(rsdp: u64, signature: &[u8; 4]) -> Result<&'static [u8], AcpiError> {
    // SAFETY: an ACPI 1.0 RSDP has 20 bytes; the caller's contract.
    let short = unsafe { core::slice::from_raw_parts(rsdp as *const u8, 20) };
    if &short[..8] != b"RSD PTR " || !checksum(short) {
        return Err(AcpiError::BadRsdp);
    }
    let (root, width) = if short[15] >= 2 {
        // SAFETY: a revision 2 RSDP has 36 bytes.
        let long = unsafe { core::slice::from_raw_parts(rsdp as *const u8, 36) };
        if !checksum(long) {
            return Err(AcpiError::BadRsdp);
        }
        match u64_at(long, 24) {
            0 => (u64::from(u32_at(short, 16)), 4),
            xsdt => (xsdt, 8),
        }
    } else {
        (u64::from(u32_at(short, 16)), 4)
    };
    // SAFETY: the caller's contract.
    let root = unsafe { table(root)? };
    for entry in root[HEADER..].chunks_exact(width) {
        let address = match width {
            8 => u64_at(entry, 0),
            _ => u64::from(u32_at(entry, 0)),
        };
        // SAFETY: the caller's contract.
        let candidate = unsafe { table(address)? };
        if &candidate[..4] == signature {
            return Ok(candidate);
        }
    }
    Err(AcpiError::Missing(*signature))
}

/// The ECAM windows of an MCFG table.
pub fn mcfg(table: &[u8]) -> Result<Vec<EcamWindow>, AcpiError> {
    const ENTRIES: usize = HEADER + 8;
    if table.len() < ENTRIES
        || &table[..4] != b"MCFG"
        || !(table.len() - ENTRIES).is_multiple_of(16)
    {
        return Err(AcpiError::BadTable(*b"MCFG"));
    }
    table[ENTRIES..]
        .as_chunks::<16>()
        .0
        .iter()
        .map(|entry| {
            let window = EcamWindow {
                base: u64_at(entry, 0),
                segment: u16::from_le_bytes([entry[8], entry[9]]),
                start_bus: entry[10],
                end_bus: entry[11],
            };
            match window.start_bus <= window.end_bus && window.base.is_multiple_of(1 << 20) {
                true => Ok(window),
                false => Err(AcpiError::BadTable(*b"MCFG")),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(mut bytes: Vec<u8>) -> Vec<u8> {
        let length = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        let sum = bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        bytes[9] = bytes[9].wrapping_sub(sum);
        bytes
    }

    fn header(signature: &[u8; 4]) -> Vec<u8> {
        let mut bytes = vec![0; HEADER];
        bytes[..4].copy_from_slice(signature);
        bytes
    }

    fn mcfg_table(windows: &[(u64, u16, u8, u8)]) -> Vec<u8> {
        let mut bytes = header(b"MCFG");
        bytes.extend([0; 8]);
        for (base, segment, start, end) in windows {
            bytes.extend(base.to_le_bytes());
            bytes.extend(segment.to_le_bytes());
            bytes.extend([*start, *end, 0, 0, 0, 0]);
        }
        sealed(bytes)
    }

    #[test]
    fn mcfg_windows_parse_and_reject_bad_entries() {
        let table = mcfg_table(&[(0xb000_0000, 0, 0, 0xff), (0xe000_0000, 1, 0x10, 0x1f)]);
        assert_eq!(
            mcfg(&table).unwrap(),
            [
                EcamWindow {
                    base: 0xb000_0000,
                    segment: 0,
                    start_bus: 0,
                    end_bus: 0xff
                },
                EcamWindow {
                    base: 0xe000_0000,
                    segment: 1,
                    start_bus: 0x10,
                    end_bus: 0x1f
                }
            ]
        );
        assert!(mcfg(&mcfg_table(&[(0xb000_0000, 0, 9, 8)])).is_err());
        assert!(mcfg(&mcfg_table(&[(0xb000_1000, 0, 0, 1)])).is_err());
        assert!(mcfg(&table[..table.len() - 1]).is_err());
    }

    #[test]
    fn find_walks_the_xsdt_and_checks_every_checksum() {
        let mcfg = mcfg_table(&[(0xb000_0000, 0, 0, 0xff)]);
        let apic = sealed(header(b"APIC"));
        let mut xsdt = header(b"XSDT");
        xsdt.extend((apic.as_ptr() as u64).to_le_bytes());
        xsdt.extend((mcfg.as_ptr() as u64).to_le_bytes());
        let xsdt = sealed(xsdt);
        let mut rsdp = [0u8; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&(xsdt.as_ptr() as u64).to_le_bytes());
        let short = rsdp[..20]
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        rsdp[8] = rsdp[8].wrapping_sub(short);
        let long = rsdp.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        rsdp[32] = rsdp[32].wrapping_sub(long);
        let rsdp_address = rsdp.as_ptr() as u64;
        // SAFETY: every table above lives until the end of the test.
        unsafe {
            assert_eq!(find(rsdp_address, b"MCFG").unwrap(), &mcfg[..]);
            assert_eq!(
                find(rsdp_address, b"HPET"),
                Err(AcpiError::Missing(*b"HPET"))
            );
        }
        rsdp[0] = b'X';
        // SAFETY: as above.
        assert_eq!(
            unsafe { find(rsdp.as_ptr() as u64, b"MCFG") },
            Err(AcpiError::BadRsdp)
        );
    }
}
