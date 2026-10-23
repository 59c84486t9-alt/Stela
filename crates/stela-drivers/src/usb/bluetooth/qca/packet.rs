// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2005-2008 Marcel Holtmann <marcel@holtmann.org>
//! Source WCN USB diagnostics are not ordinary ACL. Controller-dump prefixes
//! indicate a failed controller even when the rest of the dump is truncated.
use super::{Kind, UsbIdentity};
use crate::usb::{bluetooth::Packet, xhci::Device};

pub(in crate::usb::bluetooth) fn classify(
    device: &Device,
    packet: Packet,
) -> core::result::Result<Packet, Packet> {
    if UsbIdentity::read(device).kind() != Some(Kind::Wcn) {
        return Ok(packet);
    }
    let dump = match &packet {
        Packet::Event(p) => p.len() >= 4 && p[0] == 0xff && p[2..4] == [1, 8],
        Packet::Acl(p) => {
            p.len() >= 8 && p[..2] == [0xdd, 0x2e] && p[4] == 0xff && p[6..8] == [1, 8]
        }
        Packet::Diagnostic(_) => false,
    };
    if dump {
        return Err(packet);
    }
    Ok(match packet {
        Packet::Acl(p) if p.len() >= 2 && p[..2] == [0xdc, 0x2e] => Packet::Diagnostic(p),
        other => other,
    })
}
