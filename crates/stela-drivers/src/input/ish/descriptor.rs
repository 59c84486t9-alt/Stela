// SPDX-License-Identifier: GPL-2.0-only
//! Bounded HID wire-length inventory. Raw descriptors remain attached to data;
//! this does not translate sensor usages, units or firmware timestamps.
use super::{Error, Result};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportKind {
    Input,
    Output,
    Feature,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportLayout {
    pub kind: ReportKind,
    pub report_id: u8,
    /// Exact on-wire bytes, including the report ID when numbered.
    pub bytes: usize,
}
#[derive(Clone, Copy, Default)]
struct Global {
    size: u32,
    count: u32,
    id: u8,
}

pub(super) fn parse(bytes: &[u8]) -> Result<Vec<ReportLayout>> {
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err(Error::Protocol("bounded HID report descriptor"));
    }
    let mut at = 0;
    let mut depth = 0u8;
    let mut global = Global::default();
    let mut stack = Vec::new();
    let mut reports: Vec<(ReportKind, u8, usize)> = Vec::new();
    while at < bytes.len() {
        let prefix = bytes[at];
        at += 1;
        if prefix == 0xfe {
            return Err(Error::Requirement("HID long-item profile unsupported"));
        }
        let width = match prefix & 3 {
            3 => 4,
            n => usize::from(n),
        };
        let data = bytes
            .get(at..at + width)
            .ok_or(Error::Protocol("truncated HID item"))?;
        let value = data
            .iter()
            .enumerate()
            .fold(0u32, |v, (i, b)| v | (u32::from(*b) << (8 * i)));
        at += width;
        match ((prefix >> 2) & 3, prefix >> 4) {
            (0, 10) => {
                if width != 1 || value > 6 {
                    return Err(Error::Requirement("ordinary HID collection type"));
                }
                depth = depth
                    .checked_add(1)
                    .filter(|n| *n <= 16)
                    .ok_or(Error::Protocol("HID collection depth"))?;
            }
            (0, 12) => {
                if width != 0 {
                    return Err(Error::Protocol("HID end collection payload"));
                }
                depth = depth
                    .checked_sub(1)
                    .ok_or(Error::Protocol("HID collection underflow"))?;
            }
            (1, 7) => global.size = value,
            (1, 9) => global.count = value,
            (1, 8) => {
                global.id = u8::try_from(value)
                    .ok()
                    .filter(|v| *v != 0)
                    .ok_or(Error::Protocol("HID report ID"))?;
            }
            (1, 10) => {
                if width != 0 || stack.len() >= 8 {
                    return Err(Error::Protocol("HID global stack"));
                }
                stack.push(global);
            }
            (1, 11) => {
                if width != 0 {
                    return Err(Error::Protocol("HID pop payload"));
                }
                global = stack
                    .pop()
                    .ok_or(Error::Protocol("HID global stack underflow"))?;
            }
            (0, tag @ (8 | 9 | 11)) => {
                if depth == 0 || width == 0 {
                    return Err(Error::Protocol("HID report outside collection"));
                }
                let bits = global
                    .size
                    .checked_mul(global.count)
                    .filter(|n| *n > 0 && *n <= 131_072)
                    .ok_or(Error::Protocol("HID report bit bounds"))?
                    as usize;
                let kind = match tag {
                    8 => ReportKind::Input,
                    9 => ReportKind::Output,
                    _ => ReportKind::Feature,
                };
                if let Some(r) = reports.iter_mut().find(|r| r.0 == kind && r.1 == global.id) {
                    r.2 =
                        r.2.checked_add(bits)
                            .filter(|n| *n <= 131_072)
                            .ok_or(Error::Protocol("HID accumulated report bounds"))?;
                } else {
                    if reports.len() >= 256 {
                        return Err(Error::Protocol("HID report inventory bound"));
                    }
                    reports.push((kind, global.id, bits));
                }
            }
            (3, _) => return Err(Error::Requirement("reserved HID item type")),
            _ => {} // Other item bytes are held verbatim in the descriptor.
        }
    }
    if depth != 0 || !stack.is_empty() || reports.is_empty() {
        return Err(Error::Protocol("unbalanced or empty HID descriptor"));
    }
    if reports.iter().any(|r| r.1 != 0) && reports.iter().any(|r| r.1 == 0) {
        return Err(Error::Requirement("mixed numbered/unnumbered HID reports"));
    }
    Ok(reports
        .into_iter()
        .map(|(kind, report_id, bits)| ReportLayout {
            kind,
            report_id,
            bytes: bits.div_ceil(8) + usize::from(report_id != 0),
        })
        .collect())
}

pub(super) fn validate(layout: &[ReportLayout], kind: ReportKind, bytes: &[u8]) -> Result<u8> {
    let numbered = layout.iter().any(|r| r.report_id != 0);
    let id = if numbered {
        *bytes
            .first()
            .ok_or(Error::Protocol("missing HID report ID"))?
    } else {
        0
    };
    let r = layout
        .iter()
        .find(|r| r.kind == kind && r.report_id == id)
        .ok_or(Error::Protocol("unknown HID report"))?;
    if r.bytes != bytes.len() {
        return Err(Error::Protocol(
            "HID report length does not match actual descriptor",
        ));
    }
    Ok(id)
}
