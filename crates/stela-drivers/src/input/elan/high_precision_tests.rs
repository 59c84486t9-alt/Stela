//! Independent extended peripheral packets, sparse hardware slots and lifecycle.
use super::*;

fn extended(bitmap: u8, buttons: u8, pressure: u8, hover: bool) -> [u8; 39] {
    let mut packet = [0xa5; 39];
    packet[..4].copy_from_slice(&[39, 0, 0x60, (bitmap << 3) | buttons]);
    let mut offset = 4;
    for slot in 0..5 {
        let x = 256 + slot * 8192u16;
        let y = 4096 + slot * 4096u16;
        if bitmap & (1 << slot) != 0 {
            packet[offset..offset + 2].copy_from_slice(&x.to_be_bytes());
            packet[offset + 2..offset + 4].copy_from_slice(&y.to_be_bytes());
            packet[offset + 4] = pressure;
            offset += 5;
        }
        // The width table follows hardware slot numbers, not record offsets.
        packet[33 + usize::from(slot)] = ((15 - slot) << 4 | (slot + 1)) as u8;
    }
    packet[30] = u8::from(hover) << 6;
    packet
}
fn wide_hardware(pattern: u8) -> Rc<RefCell<Hardware>> {
    let h = hardware(pattern, 0x42, 8);
    for register in [0x106, 0x107] {
        h.borrow_mut()
            .registers
            .insert(register, u16::MAX.to_le_bytes().to_vec());
    }
    h
}
#[test]
fn elan_extended_sparse_contacts_use_full_coordinates_and_slot_width_table() {
    let h = wide_hardware(2);
    let mut d = device(&h);
    d.initialize().unwrap();
    assert_eq!(d.capabilities().unwrap().report_length(), 39);
    assert_eq!(d.capabilities().unwrap().resolution_per_mm, (11, 51));
    for bitmap in 0..32 {
        for buttons in 0..8 {
            for hover in [false, true] {
                for pressure in [0, 230, 231, 255] {
                    let packet = extended(bitmap, buttons, pressure, hover);
                    h.borrow_mut().reports.push_back(packet.to_vec());
                    let Some(Frame::Absolute(frame)) = d.poll().unwrap() else {
                        panic!()
                    };
                    assert_eq!(frame.raw, Packet::Extended(packet));
                    assert_eq!((frame.buttons, frame.hover), (buttons, hover));
                    for slot in 0..5 {
                        if bitmap & (1 << slot) == 0 {
                            assert!(frame.contacts[slot].is_none());
                            continue;
                        }
                        let contact = frame.contacts[slot].unwrap();
                        let x = 256 + slot as u16 * 8192;
                        let y = 4096 + slot as u16 * 4096;
                        assert_eq!(
                            (contact.x, contact.y, contact.y_top_down),
                            (x, y, 65535 - y)
                        );
                        assert_eq!(
                            (contact.raw_pressure, contact.pressure),
                            (pressure, pressure.saturating_add(25))
                        );
                        assert_eq!(contact.width_marks, (slot as u8 + 1, 15 - slot as u8));
                        assert_eq!(
                            contact.areas,
                            (
                                (slot as u32 + 1) * (65535 / 12 - 90),
                                (15 - slot as u32) * (65535 / 10 - 90)
                            )
                        );
                    }
                }
            }
        }
    }
    assert_eq!(h.borrow().reads.last(), Some(&(None, 39)));
}
#[test]
fn elan_extended_identity_selects_transfer_length_but_packet_id_selects_encoding() {
    for pattern in [2, 3, 127, 254, 255] {
        let h = wide_hardware(pattern);
        let mut d = device(&h);
        d.initialize().unwrap();
        let mut ordinary = [0xe7; 39];
        ordinary[..34].copy_from_slice(&absolute(0b10010, 7, 11, true));
        h.borrow_mut().reports.push_back(ordinary.to_vec());
        let Some(Frame::Absolute(frame)) = d.poll().unwrap() else {
            panic!()
        };
        assert_eq!(frame.raw, Packet::Extended(ordinary));
        assert_eq!(frame.contacts[1].unwrap().x, 520);
        assert_eq!(frame.contacts[4].unwrap().width_marks, (5, 11));
        for id in [0x5e, 0x5f] {
            let mut packet = [0x89; 39];
            packet[..9].copy_from_slice(&[39, 0, id, 7, 0x80, 0x7f, 6, 255, 0]);
            h.borrow_mut().reports.push_back(packet.to_vec());
            let Some(Frame::Trackpoint(frame)) = d.poll().unwrap() else {
                panic!()
            };
            assert_eq!(frame.raw, Packet::Extended(packet));
            assert_eq!((frame.buttons, frame.motion), (7, Some((255, 510))));
        }
        assert_eq!(h.borrow().reads.last(), Some(&(None, 39)));
    }
}
#[test]
fn elan_high_precision_coordinate_boundaries_and_real_out_of_range_refusal() {
    let h = wide_hardware(2);
    let mut d = device(&h);
    d.initialize().unwrap();
    for value in [0u16, 255, 256, 4095, 4096, 32768, 65535] {
        let mut packet = extended(16, 0, 0, false);
        packet[4..6].copy_from_slice(&value.to_be_bytes());
        packet[6..8].copy_from_slice(&(65535 - value).to_be_bytes());
        h.borrow_mut().reports.push_back(packet.to_vec());
        let Some(Frame::Absolute(frame)) = d.poll().unwrap() else {
            panic!()
        };
        let contact = frame.contacts[4].unwrap();
        assert_eq!(
            (contact.x, contact.y, contact.y_top_down),
            (value, 65535 - value, value)
        );
    }
    let h = hardware(2, 0x42, 8);
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut()
        .reports
        .push_back(extended(1, 0, 0, false).to_vec());
    assert_eq!(
        d.poll().unwrap_err().kind,
        ErrorKind::Coordinate {
            slot: 0,
            x: 256,
            y: 4096
        }
    );
    assert_eq!(d.state(), State::Uncertain);
    assert!(h.borrow().reports.is_empty());
    assert!(h.borrow().masked);
}
#[test]
fn elan_extended_resolution_sign_and_physical_limits_are_checked() {
    for raw in 0u8..=255 {
        let h = hardware(2, 0x42, 8);
        h.borrow_mut().registers.insert(0x108, vec![raw, raw]);
        let mut d = device(&h);
        let signed = i32::from(raw as i8);
        if signed >= -2 {
            d.initialize().unwrap();
            let resolution = ((signed + 3) * 1000 / 254) as u32;
            assert_eq!(
                d.capabilities().unwrap().resolution_per_mm,
                (resolution, resolution)
            );
        } else {
            assert_eq!(d.initialize().unwrap_err().kind, ErrorKind::InvalidGeometry);
            assert!(d.capabilities().is_none());
        }
    }
}
#[test]
fn elan_extended_late_read_and_resume_identity_preserve_error_ownership() {
    let h = wide_hardware(2);
    let mut d = device(&h);
    d.initialize().unwrap();
    h.borrow_mut()
        .reports
        .push_back(extended(31, 7, 255, true).to_vec());
    let next_read = h.borrow().reads.len() + 1;
    h.borrow_mut().fail_read = Some(next_read);
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::Bus(bus_error()));
    assert!(h.borrow().reports.is_empty());
    let read_count = h.borrow().reads.len();
    assert_eq!(d.poll().unwrap_err().kind, ErrorKind::NeedsReset);
    assert_eq!(h.borrow().reads.len(), read_count);
    h.borrow_mut().fail_read = None;
    d.initialize().unwrap();
    d.sleep().unwrap();
    h.borrow_mut().registers.insert(0x100, vec![0, 1]);
    assert_eq!(d.wake().unwrap_err().kind, ErrorKind::IdentityChanged);
    assert_eq!(d.capabilities().unwrap().report_length(), 39);
    assert_eq!(d.state(), State::Uncertain);
    assert!(h.borrow().masked);
}
