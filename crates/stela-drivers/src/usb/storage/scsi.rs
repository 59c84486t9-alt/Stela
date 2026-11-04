// SPDX-License-Identifier: MIT
//! The SCSI commands USB disks receive (SPC-5, SBC-4) and the mode data
//! they return.

use super::{BlockError, Sense};
use alloc::vec::Vec;
use core::num::NonZeroUsize;

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

const SUPPORTED_VPD: u8 = 0x00;
const BLOCK_LIMITS_VPD: u8 = 0xb0;
const SUPPORTED_VPD_BYTES: u16 = 255;
const BLOCK_LIMITS_VPD_BYTES: u16 = 64;

/// A separately owned read path supplies its checked controller, DMA and
/// enclosure ceiling. Probe only when it offers more than the legacy path.
pub(super) fn probe_read_limit(
    block: usize,
    legacy: usize,
    ceiling: usize,
    mut inquiry: impl FnMut(&[u8; 6], usize) -> Result<Vec<u8>, BlockError>,
) -> Result<Option<NonZeroUsize>, BlockError> {
    let ceiling_blocks = ceiling / block;
    if ceiling_blocks <= legacy / block {
        return Ok(None);
    }
    let mut read_page = |page, allocation: u16| {
        let [high, low] = allocation.to_be_bytes();
        let cdb = [INQUIRY, 1, page, high, low, 0];
        match inquiry(&cdb, usize::from(allocation)) {
            Ok(reply) => Ok(Some(reply)),
            Err(BlockError::Sense(Sense {
                key: Sense::ILLEGAL_REQUEST,
                asc: 0x20 | 0x24,
                ascq: 0,
            })) => Ok(None),
            Err(error) => Err(error),
        }
    };
    let Some(pages) = read_page(SUPPORTED_VPD, SUPPORTED_VPD_BYTES)? else {
        return Ok(None);
    };
    if !vpd_payload(&pages, SUPPORTED_VPD).is_some_and(|pages| pages.contains(&BLOCK_LIMITS_VPD)) {
        return Ok(None);
    }
    let Some(limits) = read_page(BLOCK_LIMITS_VPD, BLOCK_LIMITS_VPD_BYTES)? else {
        return Ok(None);
    };
    // Match the minimum complete Block Limits response used by the pinned
    // SCSI disk driver. The maximum transfer length is in logical blocks.
    let Some(limits) = vpd_payload(&limits, BLOCK_LIMITS_VPD).and_then(|body| body.get(..12))
    else {
        return Ok(None);
    };
    let reported = u32::from_be_bytes(limits[4..8].try_into().unwrap());
    let limit = usize::try_from(reported)
        .unwrap_or(usize::MAX)
        .min(ceiling_blocks)
        * block;
    Ok(NonZeroUsize::new(limit).filter(|limit| limit.get() != legacy))
}

fn vpd_payload(bytes: &[u8], page: u8) -> Option<&[u8]> {
    let &[kind, code, high, low] = bytes.first_chunk()?;
    if kind != 0 || code != page {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([high, low]));
    bytes.get(4..4 + length)
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
    fn read_limit_queries_only_wide_transports_and_keeps_the_device_ceiling() {
        const LEGACY: usize = 64 * 1024;
        const WIDE: usize = 128 * 1024;
        assert_eq!(
            probe_read_limit(512, LEGACY, LEGACY, |_, _| unreachable!()),
            Ok(None)
        );
        for (reported, expected) in [
            (0, None),
            (128, None),
            (96, NonZeroUsize::new(96 * 512)),
            (240, NonZeroUsize::new(240 * 512)),
            (u32::MAX, NonZeroUsize::new(WIDE)),
        ] {
            let mut calls = 0;
            let result = probe_read_limit(512, LEGACY, WIDE, |cdb, allocation| {
                calls += 1;
                let reply = match cdb[2] {
                    0 => {
                        assert_eq!((*cdb, allocation), ([INQUIRY, 1, 0, 0, 255, 0], 255));
                        vec![0, 0, 0, 2, 0, 0xb0]
                    }
                    0xb0 => {
                        assert_eq!((*cdb, allocation), ([INQUIRY, 1, 0xb0, 0, 64, 0], 64));
                        let mut reply = vec![0; 16];
                        reply[1] = 0xb0;
                        reply[3] = 12;
                        reply[8..12].copy_from_slice(&reported.to_be_bytes());
                        reply
                    }
                    _ => unreachable!(),
                };
                Ok(reply)
            });
            assert_eq!(result, Ok(expected));
            assert_eq!(calls, 2);
        }
    }

    #[test]
    fn optional_vpd_never_accepts_unlisted_truncated_or_failed_geometry() {
        let probe = |reply: Result<Vec<u8>, BlockError>| {
            let mut reply = Some(reply);
            probe_read_limit(4096, 64 * 1024, 128 * 1024, |_, _| reply.take().unwrap())
        };
        for reply in [
            vec![],
            vec![0, 0, 0, 2, 0xb0],
            vec![0, 0, 0, 1, 0x83],
            vec![0x60, 0, 0, 1, 0xb0],
        ] {
            assert_eq!(probe(Ok(reply)), Ok(None));
        }
        for asc in [0x20, 0x24, Sense::UNSUPPORTED_UNIT] {
            let failed = BlockError::Sense(Sense {
                key: Sense::ILLEGAL_REQUEST,
                asc,
                ascq: 0,
            });
            let expected = if asc == Sense::UNSUPPORTED_UNIT {
                Err(failed.clone())
            } else {
                Ok(None)
            };
            assert_eq!(probe(Err(failed)), expected);
        }
        assert_eq!(probe(Err(BlockError::Timeout)), Err(BlockError::Timeout));
        let mut replies = [vec![0, 0, 0, 1, 0xb0], vec![0, 0xb0, 0, 12, 0, 0, 0]].into_iter();
        assert_eq!(
            probe_read_limit(4096, 64 * 1024, 128 * 1024, |_, _| Ok(replies
                .next()
                .unwrap())),
            Ok(None)
        );
    }

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
