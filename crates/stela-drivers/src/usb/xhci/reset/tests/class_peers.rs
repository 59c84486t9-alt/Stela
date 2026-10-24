// SPDX-License-Identifier: GPL-2.0-only
//! Actual HID and forwarded wire peers for retained-consumer reuse controls.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Hid,
    Forwarding { iso: bool },
}
// A complete eight-byte keyboard input report, including modifiers/reserved.
pub(super) const HID_REPORT: &[u8] = &[
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x06, 0x75, 0x08,
    0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xc0,
];
pub(super) fn configuration(kind: Kind, speed: u8) -> Vec<u8> {
    let (class, subclass, protocol, attributes, packet, interval) = match kind {
        Kind::Hid => (3, 1, 1, 3, 8u16, 4),
        Kind::Forwarding { iso: true } => (0xff, 0, 0, 1, 1024u16, 1),
        Kind::Forwarding { iso: false } => (
            0xff,
            0,
            0,
            2,
            if speed >= SUPER_SPEED { 1024u16 } else { 512 },
            0,
        ),
    };
    let mut raw = vec![
        9, 2, 0, 0, 1, 1, 0, 0x80, 0, 9, 4, 0, 0, 1, class, subclass, protocol, 0,
    ];
    if kind == Kind::Hid {
        raw.extend_from_slice(&[9, 0x21, 0x11, 0x01, 0, 1, 0x22, HID_REPORT.len() as u8, 0]);
    }
    raw.extend_from_slice(&[
        7,
        5,
        0x81,
        attributes,
        packet as u8,
        (packet >> 8) as u8,
        interval,
    ]);
    if speed >= SUPER_SPEED {
        let payload = if attributes == 2 { 0 } else { packet };
        raw.extend_from_slice(&[6, 48, 0, 0, payload as u8, (payload >> 8) as u8]);
    }
    let length = raw.len() as u16;
    raw[2..4].copy_from_slice(&length.to_le_bytes());
    raw
}
impl Hardware {
    pub(super) fn queue_class_transfer(&mut self, slot: u8, dci: u8, stream: u16) {
        assert_eq!((dci, stream), (3, 0));
        let expected = if self.class_peer == Some(Kind::Forwarding { iso: true }) {
            5
        } else {
            NORMAL
        };
        let (trb, buffer, status, control) =
            Self::take(self.cursors.get_mut(&(slot, dci, stream)).unwrap());
        assert_eq!(control >> 10 & 63, expected);
        assert_ne!(control & IOC, 0);
        let output = self.output(slot, dci);
        let actual = read::<u32>(output);
        assert!(matches!(actual & 7, ENDPOINT_RUNNING | ENDPOINT_STOPPED));
        put(output, actual & !7 | ENDPOINT_RUNNING);
        assert!(
            self.pending
                .insert(
                    (slot, dci, stream),
                    Td {
                        trb,
                        buffer,
                        length: (status & 0x1ffff) as usize
                    }
                )
                .is_none()
        );
    }
    /// Complete only an actual queued TD from this original hardware peer.
    pub(crate) fn complete_forwarded(&mut self, slot: u8, dci: u8, payload: &[u8]) {
        assert!(matches!(self.class_peer, Some(Kind::Forwarding { .. })));
        self.complete_class(slot, dci, payload);
    }
    pub(crate) fn feed_hid_report(&mut self, slot: u8, report: &[u8]) {
        assert_eq!(self.class_peer, Some(Kind::Hid));
        self.complete_class(slot, 3, report);
    }
    fn complete_class(&mut self, slot: u8, dci: u8, payload: &[u8]) {
        let td = self
            .pending
            .remove(&(slot, dci, 0))
            .expect("no actual class TD queued");
        assert!(payload.len() <= td.length);
        copy(td.buffer, payload);
        self.event(
            td.trb,
            (if payload.len() < td.length {
                SHORT_PACKET
            } else {
                SUCCESS
            }) << 24
                | (td.length - payload.len()) as u32,
            TRANSFER_EVENT,
            slot,
            dci,
        );
    }
}
pub(crate) fn fixture_hid(
    memory: &mut [u64],
    speed: u8,
    context: usize,
    max_slots: usize,
) -> (Shared, Device, Rc<RefCell<Hardware>>, RegionAllocator) {
    fixture_profile_class(
        memory,
        speed,
        context,
        max_slots,
        (false, false, dma::Profile::SPEC),
        Some(Kind::Hid),
        true,
    )
}
pub(crate) fn fixture_forwarding(
    memory: &mut [u64],
    speed: u8,
    context: usize,
    iso: bool,
) -> (Host, Shared, Device, Rc<RefCell<Hardware>>, RegionAllocator) {
    let (shared, physical, hardware, mut dma) = fixture_profile_class(
        memory,
        speed,
        context,
        1,
        (false, false, dma::Profile::SPEC),
        Some(Kind::Forwarding { iso }),
        false,
    );
    let mut failures = Vec::new();
    let host = Host::new(
        shared.clone(),
        core::slice::from_ref(&physical),
        &mut dma,
        &mut failures,
    );
    assert!(failures.is_empty());
    (host, shared, physical, hardware, dma)
}
