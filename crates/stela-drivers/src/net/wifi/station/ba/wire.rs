// SPDX-License-Identifier: GPL-2.0-only
//! Source ordinary ADDBA/DELBA and single-TID BAR fields. No session permission.
use super::Error;
use crate::bytes::get_le16;
use crate::net::{
    Mac,
    wifi::frame::{ACTION, BLOCK_ACK_REQUEST, FROM_DS, Mpdu, PROTECTED, TO_DS, TYPE_SUBTYPE},
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug)]
pub(super) struct Request {
    pub dialog: u8,
    pub tid: u8,
    pub start: u16,
    pub window: u16,
    pub timeout: u16,
    pub immediate: bool,
    pub extension: u8,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Management {
    Request(Request),
    Response {
        dialog: u8,
        tid: u8,
        window: u16,
        timeout: u16,
        status: u16,
        amsdu: bool,
    },
    Delete {
        tid: u8,
        initiator: bool,
    },
}
fn word(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    get_le16(bytes, offset).ok_or(Error::Truncated)
}

use super::super::wire::action::addba_extension;

pub(super) fn action(frame: &Mpdu, he: bool, eht: bool) -> Result<Management, Error> {
    if frame.header().control & TYPE_SUBTYPE != ACTION {
        return Err(Error::InvalidFrame);
    }
    action_body(frame.bytes().get(24..).ok_or(Error::Truncated)?, he, eht)
}

// Only the native authenticated consumer supplies a separate plaintext body.
// Ordinary RX continues to parse its original unprotected MPDU above.
pub(super) fn action_body(body: &[u8], he: bool, eht: bool) -> Result<Management, Error> {
    if body.first() != Some(&3) {
        return Err(Error::Unsupported);
    }
    match *body.get(1).ok_or(Error::Truncated)? {
        0 => {
            let parameters = word(body, 3)?;
            let timeout = word(body, 5)?;
            let start = word(body, 7)? >> 4;
            let ext = addba_extension(&body[9..], he);
            Ok(Management::Request(Request {
                dialog: body[2],
                tid: ((parameters >> 2) & 15) as u8,
                start,
                window: (parameters >> 6) | if eht { u16::from(ext >> 5) << 10 } else { 0 },
                timeout,
                immediate: parameters & 2 != 0,
                extension: ext,
            }))
        }
        1 => {
            let status = word(body, 3)?;
            let parameters = word(body, 5)?;
            let timeout = word(body, 7)?;
            let ext = addba_extension(&body[9..], he);
            Ok(Management::Response {
                dialog: body[2],
                tid: ((parameters >> 2) & 15) as u8,
                window: (parameters >> 6) | if eht { u16::from(ext >> 5) << 10 } else { 0 },
                timeout,
                status,
                amsdu: parameters & 1 != 0,
            })
        }
        2 => {
            let parameters = word(body, 2)?;
            // Validate the mandatory reason field; the complete original MPDU
            // remains with its caller. No duplicated unused reason metadata.
            word(body, 4)?;
            Ok(Management::Delete {
                tid: (parameters >> 12) as u8,
                initiator: parameters & 0x0800 != 0,
            })
        }
        _ => Err(Error::Unsupported),
    }
}

fn header(local: Mac, peer: Mac, sequence: u16) -> Vec<u8> {
    let mut bytes = vec![0; 24];
    bytes[..2].copy_from_slice(&0x00d0u16.to_le_bytes());
    bytes[4..10].copy_from_slice(&peer.0);
    bytes[10..16].copy_from_slice(&local.0);
    bytes[16..22].copy_from_slice(&peer.0);
    bytes[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    bytes
}

pub(super) fn request(local: Mac, peer: Mac, sequence: u16, request: Request, he: bool) -> Vec<u8> {
    let mut bytes = header(local, peer, sequence);
    // Ordinary immediate BA, with the source's A-MSDU request bit set.
    let parameters = 3 | u16::from(request.tid) << 2 | (request.window & 1023) << 6;
    bytes.extend_from_slice(&[3, 0, request.dialog]);
    bytes.extend_from_slice(&parameters.to_le_bytes());
    bytes.extend_from_slice(&request.timeout.to_le_bytes());
    bytes.extend_from_slice(&(request.start << 4).to_le_bytes());
    if he {
        bytes.extend_from_slice(&[159, 1, 1 | ((request.window >> 10) as u8 & 7) << 5]);
    }
    bytes
}

pub(super) struct Reply {
    pub window: u16,
    pub status: u16,
    pub amsdu: bool,
    pub he: bool,
}

pub(super) fn response(
    local: Mac,
    peer: Mac,
    sequence: u16,
    request: Request,
    reply: Reply,
) -> Vec<u8> {
    let Reply {
        window,
        status,
        amsdu,
        he,
    } = reply;
    let mut bytes = header(local, peer, sequence);
    let parameters = u16::from(amsdu) | 2 | u16::from(request.tid) << 2 | (window & 1023) << 6;
    bytes.extend_from_slice(&[3, 1, request.dialog]);
    bytes.extend_from_slice(&status.to_le_bytes());
    bytes.extend_from_slice(&parameters.to_le_bytes());
    bytes.extend_from_slice(&request.timeout.to_le_bytes());
    if he {
        let no_frag = if request.extension != 0 {
            1 & request.extension
        } else {
            1
        };
        bytes.extend_from_slice(&[159, 1, no_frag | ((window >> 10) as u8 & 7) << 5]);
    }
    bytes
}

pub(super) fn delete(
    local: Mac,
    peer: Mac,
    sequence: u16,
    tid: u8,
    initiator: bool,
    reason: u16,
) -> Vec<u8> {
    let mut bytes = header(local, peer, sequence);
    bytes.extend_from_slice(&[3, 2]);
    bytes.extend_from_slice(&(u16::from(tid) << 12 | u16::from(initiator) << 11).to_le_bytes());
    bytes.extend_from_slice(&reason.to_le_bytes());
    bytes
}

pub(super) fn bar(frame: &Mpdu, local: Mac, peer: Mac) -> Result<(u8, u16), Error> {
    let h = frame.header();
    if h.control & TYPE_SUBTYPE != BLOCK_ACK_REQUEST
        || h.receiver != local
        || h.transmitter != Some(peer)
        || h.control & (TO_DS | FROM_DS | PROTECTED) != 0
    {
        return Err(Error::InvalidFrame);
    }
    let control = word(frame.bytes(), 16)?;
    // This entry point implements the ordinary single-TID form; no invented
    // multi-TID entries or guessed per-link session are accepted.
    if control & 2 != 0 {
        return Err(Error::Unsupported);
    }
    Ok(((control >> 12) as u8, word(frame.bytes(), 18)? >> 4))
}
