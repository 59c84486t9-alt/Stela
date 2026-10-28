// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Linux btmtk_usb_recv_acl and btmtk_recv_event: MediaTek firmware dumps and
//! debug logs arrive on reserved ACL handles and are diagnostics, never
//! Bluetooth data; the driver consumes Command Complete for vendor opcode
//! 0xfc5d instead of delivering it.
use super::UsbIdentity;
use crate::usb::{bluetooth::Packet, xhci::Device};

/// The firmware dump handle; its packets also feed coredump assembly.
pub(in crate::usb::bluetooth) const DUMP_HANDLE: u16 = 0xfc6f;
const LOG_HANDLES: [u16; 2] = [0x05ff, 0x05fe];
const FILTERED_OPCODE: [u8; 2] = 0xfc5du16.to_le_bytes();

/// The packet to deliver, if any. Devices btusb does not bind as MediaTek
/// pass through unchanged.
pub(in crate::usb::bluetooth) fn classify(device: &Device, packet: Packet) -> Option<Packet> {
    if !UsbIdentity::read(device).candidate() {
        return Some(packet);
    }
    match packet {
        Packet::Acl(p) if p.len() >= 2 && diagnostic_handle(u16::from_le_bytes([p[0], p[1]])) => {
            Some(Packet::Diagnostic(p))
        }
        // HCI event header, then ncmd and the completed opcode.
        Packet::Event(p) if p.len() >= 5 && p[0] == 0x0e && p[3..5] == FILTERED_OPCODE => None,
        other => Some(other),
    }
}

/// btmtk_usb_recv_acl compares the whole little-endian handle field,
/// packet-boundary and broadcast flags included.
fn diagnostic_handle(handle: u16) -> bool {
    handle == DUMP_HANDLE || LOG_HANDLES.contains(&handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn device(vendor: u16, product: u16) -> Device {
        let [v0, v1] = vendor.to_le_bytes();
        let [p0, p1] = product.to_le_bytes();
        Device {
            id: crate::usb::xhci::SlotId::fixture(1),
            slot: 1,
            speed: 3,
            location: "synthetic".into(),
            descriptor: [
                18, 1, 0, 2, 0xe0, 1, 1, 64, v0, v1, p0, p1, 0, 1, 0, 0, 0, 1,
            ],
            configurations: vec![],
            configuration: vec![],
            manufacturer: None,
            product: None,
            serial: None,
            language: None,
            vendor_ethernet_tcr: None,
            vendor_ethernet_revision: None,
        }
    }

    #[test]
    fn reserved_acl_handles_are_diagnostics_and_vendor_completions_are_consumed() {
        let mt7925 = device(0x13d3, 0x3602);
        for handle in [0xfc6f_u16, 0x05ff, 0x05fe] {
            let [a, b] = handle.to_le_bytes();
            let raw = vec![a, b, 2, 0, 0xaa, 0xbb];
            assert_eq!(
                classify(&mt7925, Packet::Acl(raw.clone())),
                Some(Packet::Diagnostic(raw))
            );
        }
        // Ordinary connection handles, including 0x05fd and flag variants of
        // a real handle, stay Bluetooth data.
        for raw in [vec![0x01, 0x20, 0, 0], vec![0xfd, 0x05, 0, 0], vec![0x6f]] {
            assert_eq!(
                classify(&mt7925, Packet::Acl(raw.clone())),
                Some(Packet::Acl(raw))
            );
        }
        let filtered = vec![0x0e, 4, 1, 0x5d, 0xfc, 0];
        assert_eq!(classify(&mt7925, Packet::Event(filtered.clone())), None);
        // Short completions and Command Status for the same opcode pass.
        for raw in [vec![0x0e, 2, 1, 0x5d], vec![0x0f, 4, 0, 1, 0x5d, 0xfc]] {
            assert_eq!(
                classify(&mt7925, Packet::Event(raw.clone())),
                Some(Packet::Event(raw))
            );
        }
        // Other vendors' identical frames are untouched.
        let other = device(0x8087, 0x0032);
        assert_eq!(
            classify(&other, Packet::Event(filtered.clone())),
            Some(Packet::Event(filtered))
        );
        let dump = vec![0x6f, 0xfc, 0, 0];
        assert_eq!(
            classify(&other, Packet::Acl(dump.clone())),
            Some(Packet::Acl(dump))
        );
    }
}
