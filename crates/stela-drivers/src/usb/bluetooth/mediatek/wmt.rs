// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! WMT headers/status interpretation adapted from btmtk_usb_hci_wmt_sync.
use super::{Error, Result};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
pub(super) const OPCODE: u16 = 0xfc6f;
pub(super) const PATCH: u8 = 1;
pub(super) const FUNCTION: u8 = 6;
/// Pending command metadata retains exact wire identity without retaining any
/// executable firmware fragment in the historical error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmtCommandReceipt {
    pub operation: u8,
    pub flag: u8,
    pub data_length: usize,
    pub packet_sha256: [u8; 32],
}
impl WmtCommandReceipt {
    pub(super) fn new(operation: u8, flag: u8, packet: &[u8]) -> Self {
        Self {
            operation,
            flag,
            data_length: packet.len() - 8,
            packet_sha256: Sha256::digest(packet).into(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WmtEvent {
    pub(super) raw: Vec<u8>,
}
impl WmtEvent {
    pub(super) fn parse(raw: Vec<u8>, operation: u8) -> Result<Self> {
        if raw.len() < 7
            || raw.len() > 64
            || raw[0] != 0xe4
            || usize::from(raw[1]) + 2 != raw.len()
            || usize::from(u16::from_le_bytes([raw[4], raw[5]])) + 6 != raw.len()
        {
            return Err(Error::protocol(
                "complete nonfragmented EP0 WMT event",
                &raw,
            ));
        }
        if raw[3] != operation {
            return Err(Error::protocol("matching WMT operation", &raw));
        }
        Ok(Self { raw })
    }
    pub fn direction(&self) -> u8 {
        self.raw[2]
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn operation(&self) -> u8 {
        self.raw[3]
    }
    pub fn flag(&self) -> u8 {
        self.raw[6]
    }
    pub fn data(&self) -> &[u8] {
        &self.raw[7..]
    }
    pub(super) fn patch_status(&self) -> Result<PatchStatus> {
        // The pinned USB helper selects patch status from flag alone. Any
        // additional response bytes remain raw evidence, without guessed use.
        match self.flag() {
            0 => Ok(PatchStatus::Undone),
            1 => Ok(PatchStatus::Progress),
            2 => Ok(PatchStatus::Done),
            _ => Err(Error::protocol(
                "supported WMT patch status flag",
                &self.raw,
            )),
        }
    }
    pub(super) fn enabled(&self) -> bool {
        match self.data() {
            [] => self.flag() == 0,
            [a, b] => u16::from_be_bytes([*a, *b]) == 0x0404,
            _ => false,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PatchStatus {
    Undone,
    Progress,
    Done,
}
pub(super) fn command(operation: u8, flag: u8, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > 250 {
        return Err(Error::protocol("WMT parameters exceed HCI limit", data));
    }
    let mut b = OPCODE.to_le_bytes().to_vec();
    b.push((data.len() + 5) as u8);
    b.push(1);
    b.push(operation);
    b.extend_from_slice(&((data.len() + 1) as u16).to_le_bytes());
    b.push(flag);
    b.extend_from_slice(data);
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn function_status_is_big_endian_and_raw_patch_extensions_are_preserved() {
        let mut raw = vec![0xe4, 7, 2, FUNCTION, 3, 0, 1, 4, 4];
        assert!(WmtEvent::parse(raw.clone(), FUNCTION).unwrap().enabled());
        raw[8] = 0x20;
        assert!(!WmtEvent::parse(raw, FUNCTION).unwrap().enabled());
        let raw = vec![0xe4, 7, 2, PATCH, 3, 0, 2, 0xaa, 0xbb];
        let e = WmtEvent::parse(raw.clone(), PATCH).unwrap();
        assert_eq!(e.patch_status().unwrap(), PatchStatus::Done);
        assert_eq!(e.bytes(), raw);
        let packet = command(PATCH, 3, &[0xab; 250]).unwrap();
        assert_eq!(&packet[..8], &[0x6f, 0xfc, 255, 1, 1, 251, 0, 3]);
        assert_eq!(packet.len(), 258);
        assert!(command(PATCH, 3, &[0; 251]).is_err());
    }
}
