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
