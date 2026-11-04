// SPDX-License-Identifier: MIT
//! The SCSI commands USB disks receive (SPC-5, SBC-4) and the mode data
//! they return.

pub(super) const TEST_UNIT_READY: u8 = 0x00;
pub(super) const REQUEST_SENSE: u8 = 0x03;
pub(super) const INQUIRY: u8 = 0x12;
pub(super) const MODE_SENSE_6: u8 = 0x1a;
pub(super) const START_STOP_UNIT: u8 = 0x1b;
pub(super) const READ_CAPACITY_10: u8 = 0x25;
pub(super) const READ_10: u8 = 0x28;
pub(super) const WRITE_10: u8 = 0x2a;
pub(super) const SYNCHRONIZE_CACHE_10: u8 = 0x35;
pub(super) const READ_16: u8 = 0x88;
pub(super) const WRITE_16: u8 = 0x8a;
pub(super) const SERVICE_ACTION_IN_16: u8 = 0x9e;
pub(super) const READ_CAPACITY_16: u8 = 0x10;
pub(super) const REPORT_LUNS: u8 = 0xa0;
/// START STOP UNIT byte 4: START and LOEJ.
const START: u8 = 0x01;
pub(super) const LOAD_EJECT: u8 = 0x02;

pub(super) const SENSE_BYTES: usize = 18;
pub(super) const INQUIRY_BYTES: usize = 36;
/// Linux usb-storage asks for 192 bytes of mode data, which some devices
/// need (`use_192_bytes_for_3f`).
pub(super) const MODE_SENSE_BYTES: usize = 192;
pub(super) const ALL_PAGES: u8 = 0x3f;
pub(super) const CACHING_PAGE: u8 = 0x08;
const PAGE_CODE: u8 = 0x3f;
/// Mode parameter header (6): length, medium type, device-specific
/// parameter with WP, block descriptor length (SPC-5 7.5.6).
const MODE_HEADER: usize = 4;
const WRITE_PROTECT: u8 = 0x80;
/// Caching mode page byte 2: write cache enable (SBC-4 6.5.5).
const WRITE_CACHE_ENABLE: u8 = 0x04;
/// The device-specific parameter's DPOFUA bit: the unit takes FUA writes.
const DPOFUA: u8 = 0x10;
/// READ/WRITE (10) and (16) byte 1: Force Unit Access.
pub(super) const FUA: u8 = 0x08;

pub(super) enum Cdb {
    Ten([u8; 10]),
    Sixteen([u8; 16]),
}

impl AsRef<[u8]> for Cdb {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ten(bytes) => bytes,
            Self::Sixteen(bytes) => bytes,
        }
    }
}

/// READ or WRITE of `blocks` at `lba`, (10) when it fits, else (16),
/// with Force Unit Access when `fua`.
pub(super) fn read_write(write: bool, fua: bool, lba: u64, blocks: u32) -> Cdb {
    let flags = if fua { FUA } else { 0 };
    if lba
        .checked_add(u64::from(blocks))
        .is_some_and(|end| end <= u64::from(u32::MAX) + 1)
        && blocks <= u32::from(u16::MAX)
    {
        let mut cdb = [0; 10];
        cdb[0] = if write { WRITE_10 } else { READ_10 };
        cdb[1] = flags;
        cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
        cdb[7..9].copy_from_slice(&(blocks as u16).to_be_bytes());
        Cdb::Ten(cdb)
    } else {
        let mut cdb = [0; 16];
        cdb[0] = if write { WRITE_16 } else { READ_16 };
        cdb[1] = flags;
        cdb[2..10].copy_from_slice(&lba.to_be_bytes());
        cdb[10..14].copy_from_slice(&blocks.to_be_bytes());
        Cdb::Sixteen(cdb)
    }
}

pub(super) fn request_sense() -> [u8; 6] {
    [REQUEST_SENSE, 0, 0, 0, SENSE_BYTES as u8, 0]
}

pub(super) fn inquiry() -> [u8; 6] {
    [INQUIRY, 0, 0, 0, INQUIRY_BYTES as u8, 0]
}

pub(super) fn mode_sense(page: u8) -> [u8; 6] {
    [MODE_SENSE_6, 0, page, 0, MODE_SENSE_BYTES as u8, 0]
}

pub(super) fn start_unit() -> [u8; 6] {
    [START_STOP_UNIT, 0, 0, 0, START, 0]
}

pub(super) fn synchronize_cache() -> [u8; 10] {
    [SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// The write-protect bit of mode data, once its header is complete.
pub(super) fn write_protected(mode: &[u8]) -> Option<bool> {
    (mode.len() >= MODE_HEADER && usize::from(mode[0]) + 1 >= MODE_HEADER)
        .then(|| mode[2] & WRITE_PROTECT != 0)
}

/// A WRITE (10) of no blocks with FUA, to ask a transport's quirks whether
/// the unit may take FUA writes.
pub(super) fn write_10_fua() -> [u8; 10] {
    [WRITE_10, FUA, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// The mode header's DPOFUA bit, as Linux `sd_read_cache_type` reads it.
pub(super) fn fua_supported(mode: &[u8]) -> bool {
    mode.len() >= MODE_HEADER && mode[2] & DPOFUA != 0
}

/// The Caching page's WCE bit, when mode data holds the page.
pub(super) fn write_cache_enabled(mode: &[u8]) -> Option<bool> {
    let page = mode.get(MODE_HEADER + usize::from(*mode.get(3)?)..)?;
    (page.len() >= 3 && page[0] & PAGE_CODE == CACHING_PAGE)
        .then(|| page[2] & WRITE_CACHE_ENABLE != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_commands_keep_wire_width_lba_count_and_fua() {
        let last = u64::from(u32::MAX);
        assert_eq!(
            read_write(false, false, last, 1).as_ref(),
            &[READ_10, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 1, 0]
        );
        assert_eq!(
            read_write(true, true, last, 2).as_ref(),
            &[
                WRITE_16, FUA, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 2, 0, 0
            ]
        );
        assert_eq!(
            read_write(true, false, 17, 0x1_0000).as_ref(),
            &[WRITE_16, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn mode_data_yields_write_protection_and_the_write_cache() {
        assert_eq!(write_protected(&[3, 0, 0x80, 0]), Some(true));
        assert_eq!(write_protected(&[3, 0, 0, 0]), Some(false));
        assert_eq!(write_protected(&[1, 0, 0x80]), None);
        // Header, one 8-byte block descriptor, then the Caching page.
        let mut mode = vec![0, 0, 0, 8];
        mode.extend_from_slice(&[0; 8]);
        mode.extend_from_slice(&[0x08, 0x12, 0x04]);
        assert_eq!(write_cache_enabled(&mode), Some(true));
        mode[12] = 0x0a;
        assert_eq!(write_cache_enabled(&mode), None);
        assert_eq!(write_cache_enabled(&[0, 0, 0, 0]), None);
    }
}
