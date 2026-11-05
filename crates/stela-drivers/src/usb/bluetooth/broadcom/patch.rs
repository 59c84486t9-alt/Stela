// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2015 Intel Corporation
//! Validate the complete HCD stream before putting the device in download mode.
use super::{Error, Result};

#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    pub opcode: u16,
    pub parameters: &'a [u8],
}
pub struct Hcd<'a> {
    bytes: &'a [u8],
    records: usize,
}
impl<'a> Hcd<'a> {
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut offset = 0;
        let mut records = 0;
        while offset < bytes.len() {
            let header = bytes
                .get(offset..offset + 3)
                .ok_or(Error::MalformedPatch { offset })?;
            let end = offset + 3 + usize::from(header[2]);
            if end > bytes.len() {
                return Err(Error::MalformedPatch { offset });
            }
            records += 1;
            offset = end;
        }
        if records == 0 {
            return Err(Error::MalformedPatch { offset: 0 });
        }
        Ok(Self { bytes, records })
    }
    pub fn len(&self) -> usize {
        self.records
    }
    pub fn is_empty(&self) -> bool {
        self.records == 0
    }
    pub fn records(&self) -> impl Iterator<Item = Record<'a>> + '_ {
        let mut bytes = self.bytes;
        core::iter::from_fn(move || {
            if bytes.is_empty() {
                return None;
            }
            let n = usize::from(bytes[2]);
            let record = Record {
                opcode: u16::from_le_bytes([bytes[0], bytes[1]]),
                parameters: &bytes[3..3 + n],
            };
            bytes = &bytes[3 + n..];
            Some(record)
        })
    }
}
