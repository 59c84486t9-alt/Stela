//! Apple CHRP v1 banks, per XNU `IONVRAMCHRPHandler.cpp`
//! (`chrp_checksum`, `adler32_with_version`, `unserializeImage`) and Asahi
//! `asahi-nvram/apple-nvram/src/v1v2.rs` (`Partition::parse`).
//! The outer CHRP partition is only the 32-byte Apple header; common and
//! system partitions follow it. Adler-32 covers generation through bank end.
use alloc::{vec, vec::Vec};

pub mod variables;
pub use variables::{Partition, Variables};

pub const BANK_SIZE: usize = 0x10000;
pub const BANK_COUNT: u32 = 2;
pub const CURRENT_BANK: u32 = 0;
const APPLE_SIGNATURE: u8 = 0x5a;
const VARIABLES_SIGNATURE: u8 = 0x70;
const HEADER_SIZE: usize = 16;
const APPLE_HEADER_SIZE: usize = 32;
const SYSTEM_SIZE: usize = 0x4000;

fn checksum(header: &[u8]) -> u8 {
    let mut sum = u16::from(header[0]);
    for &byte in &header[2..HEADER_SIZE] {
        sum += u16::from(byte);
    }
    while sum > 0xff {
        sum = (sum & 0xff) + (sum >> 8);
    }
    sum as u8
}

fn adler(bytes: &[u8]) -> u32 {
    let (mut low, mut high) = (1, 0);
    for &byte in bytes {
        low = (low + u32::from(byte)) % 65521;
        high = (high + low) % 65521;
    }
    high << 16 | low
}

fn header(bank: &mut [u8], offset: usize, bytes: usize, signature: u8, name: &[u8]) {
    let header = &mut bank[offset..offset + HEADER_SIZE];
    header[0] = signature;
    header[2..4].copy_from_slice(&((bytes / HEADER_SIZE) as u16).to_le_bytes());
    header[4..4 + name.len()].copy_from_slice(name);
    header[1] = checksum(header);
}

/// Stela's empty bank: generation 1, 16 KiB system partition and the rest
/// common, zero-filled variable payloads (empty NUL-terminated lists).
/// These sizes and generation are boot-chain choices, not captured Apple data.
pub fn empty_bank() -> Vec<u8> {
    let mut bank = vec![0; BANK_SIZE];
    header(&mut bank, 0, APPLE_HEADER_SIZE, APPLE_SIGNATURE, b"nvram");
    header(
        &mut bank,
        APPLE_HEADER_SIZE,
        SYSTEM_SIZE,
        VARIABLES_SIGNATURE,
        b"system",
    );
    header(
        &mut bank,
        APPLE_HEADER_SIZE + SYSTEM_SIZE,
        BANK_SIZE - APPLE_HEADER_SIZE - SYSTEM_SIZE,
        VARIABLES_SIGNATURE,
        b"common",
    );
    bank[20..24].copy_from_slice(&1u32.to_le_bytes());
    let sum = adler(&bank[20..]);
    bank[16..20].copy_from_slice(&sum.to_le_bytes());
    bank
}

/// A bank's generation, which XNU's `IONVRAMCHRPHandler` and iBoot
/// increment on every save; the newest valid bank is current.
pub fn generation(bank: &[u8]) -> u32 {
    u32::from_le_bytes(bank[20..24].try_into().expect("a bank holds its header"))
}

/// An empty bank of generation `generation`, for tests.
#[cfg(any(test, feature = "test-support"))]
pub fn empty_bank_of(generation: u32) -> Vec<u8> {
    let mut bank = empty_bank();
    bank[20..24].copy_from_slice(&generation.to_le_bytes());
    let sum = adler(&bank[20..]);
    bank[16..20].copy_from_slice(&sum.to_le_bytes());
    bank
}

/// A CHRP partition header's NUL-terminated name.
fn partition_name(header: &[u8]) -> &[u8] {
    header[4..HEADER_SIZE]
        .split(|&b| b == 0)
        .next()
        .expect("one slice")
}

/// Recognize the Apple container independently of its payload's Adler-32.
/// A torn program can leave a complete header above incomplete variables.
/// This identifies a damaged bank; it does not authorize reading its variables.
pub(super) fn has_apple_header(bank: &[u8]) -> bool {
    bank.len() == BANK_SIZE
        && bank[0] == APPLE_SIGNATURE
        && matches!(partition_name(bank), b"nvram" | b"2nvram")
        && u16::from_le_bytes([bank[2], bank[3]]) as usize * HEADER_SIZE == APPLE_HEADER_SIZE
        && bank[1] == checksum(bank)
}

/// Validate the bounded CHRP image before accepting boot firmware's proxy.
/// XNU accepts both v1 and v2 names; Stela creates v1 and preserves either.
pub fn validate(bank: &[u8]) -> Result<(), &'static str> {
    if bank.len() != BANK_SIZE {
        return Err("NVRAM bank is not 64 KiB");
    }
    if !has_apple_header(bank)
        || u32::from_le_bytes(bank[16..20].try_into().expect("4 bytes")) != adler(&bank[20..])
    {
        return Err("invalid Apple CHRP bank header or Adler-32");
    }
    let mut offset = 0;
    let (mut common, mut system) = (false, false);
    while offset < BANK_SIZE {
        let h = bank
            .get(offset..offset + HEADER_SIZE)
            .ok_or("truncated CHRP header")?;
        let length = usize::from(u16::from_le_bytes([h[2], h[3]])) * HEADER_SIZE;
        if length < HEADER_SIZE || offset + length > BANK_SIZE || h[1] != checksum(h) {
            return Err("invalid CHRP partition length or checksum");
        }
        let name = partition_name(h);
        common |= matches!(name, b"common" | b"2common");
        system |= matches!(name, b"system" | b"2system");
        offset += length;
    }
    if !common || !system {
        return Err("CHRP bank lacks common or system partition");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chrp_bank_has_valid_checksums_and_empty_partitions() {
        let bank = empty_bank();
        assert_eq!(validate(&bank), Ok(()));
        assert_eq!(&bank[4..10], b"nvram\0");
        assert_eq!(&bank[36..43], b"system\0");
        assert!(bank[48..32 + SYSTEM_SIZE].iter().all(|&b| b == 0));
        assert_eq!(&bank[36 + SYSTEM_SIZE..43 + SYSTEM_SIZE], b"common\0");
        // Independent zlib.adler32 of this generated, non-Apple fixture.
        assert_eq!(
            u32::from_le_bytes(bank[16..20].try_into().unwrap()),
            0x51d7_073f
        );
    }

    #[test]
    fn corrupt_and_truncated_banks_are_rejected() {
        let mut bank = empty_bank();
        bank[100] ^= 1;
        assert!(validate(&bank).is_err());
        assert!(validate(&bank[..100]).is_err());
        let mut bank = empty_bank();
        bank[1] ^= 1;
        assert!(validate(&bank).is_err());
    }

    #[test]
    fn bank_recognition_needs_the_apple_header_but_never_trusts_the_payload() {
        let mut bank = empty_bank();
        bank[100] ^= 1;
        assert!(has_apple_header(&bank));
        assert!(validate(&bank).is_err());
        bank[2] = 3; // The Apple container is its 32-byte header only.
        bank[1] = checksum(&bank);
        assert!(!has_apple_header(&bank));
        assert!(validate(&bank).is_err());
        assert!(!has_apple_header(&bank[..100]));
        let mut bank = empty_bank();
        bank[4..16].fill(b'x');
        bank[1] = checksum(&bank);
        assert!(!has_apple_header(&bank));
    }
}
