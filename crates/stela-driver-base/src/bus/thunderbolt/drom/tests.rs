// SPDX-License-Identifier: GPL-2.0-only
use super::*;
use alloc::vec;

fn rom(revision: u8) -> Vec<u8> {
    let mut bytes = vec![0; if revision == 1 { 22 } else { 16 }];
    bytes[1..9].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
    bytes[13] = revision;
    if revision == 1 {
        bytes[16..20].copy_from_slice(&[0xbc, 0x9a, 0xf0, 0xde]);
    }
    let mut name = vec![68, 1];
    name.extend_from_slice(b"STELA\0");
    name.resize(68, b'V');
    bytes.extend(name);
    bytes.extend_from_slice(&[5, 2, b'D', b'P', 0, 8, 9, 0, 4, 0x34, 0x12, 0x78, 0x56]);
    bytes.extend_from_slice(&[8, 0x81, 0x90, 2, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[2, 0xc2, 2, 0x87, 2, 0x86]);
    seal(&mut bytes);
    bytes
}

fn parsed(bytes: Vec<u8>, uid: u64) -> Result<Image, Error> {
    Image::parse(bytes, uid, 5, |port| port < 5)
}

#[test]
fn images_yield_names_products_and_lanes() {
    for revision in [1, 3] {
        let image = parsed(rom(revision), 7).unwrap();
        assert_eq!(image.uid, 7);
        assert_eq!(image.uid_source, UidSource::Router);
        assert_eq!(image.vendor_name(), Some(&b"STELA"[..]));
        assert_eq!(image.device_name(), Some(&b"DP"[..]));
        assert!(image.crc32.matches());
        assert_eq!(
            image.product,
            if revision == 1 {
                (0x9abc, 0xdef0)
            } else {
                (0x1234, 0x5678)
            }
        );
        assert_eq!(
            image.port(1),
            Some(Port {
                disabled: false,
                lane: Some(Lane {
                    link_number: 1,
                    dual_port: Some(2),
                }),
            })
        );
        assert_eq!(image.port(2).map(|port| port.disabled), Some(true));
        assert_eq!(image.port(3), None);
        assert!(image.entries.iter().any(|entry| {
            entry.index == 7 && matches!(entry.kind, Kind::Port { extra: true, .. })
        }));
    }
}

#[test]
fn a_version_1_image_supplies_a_missing_uid() {
    let image = parsed(rom(1), 0).unwrap();
    assert_eq!(image.uid, 0x1122334455667788);
    assert_eq!(image.uid_source, UidSource::V1DromFallback);
}

#[test]
fn integrity_failures_are_explicit() {
    let mut bytes = rom(3);
    bytes[9] ^= 1;
    assert!(!parsed(bytes, 7).unwrap().crc32.matches());
    let mut bytes = rom(1);
    bytes[0] ^= 1;
    assert!(matches!(parsed(bytes, 7), Err(Error::UidCrc { .. })));
    assert_eq!(parsed(rom(2), 7).err(), Some(Error::UnsupportedRevision(2)));
}

#[test]
fn malformed_lengths_publish_nothing() {
    assert_eq!(parsed(vec![0; 8], 7).err(), Some(Error::HeaderSize));
    let mut short = rom(3);
    short.pop();
    assert_eq!(parsed(short, 7).err(), Some(Error::Size));
    let mut entry = rom(3);
    entry[16] = 1;
    seal(&mut entry);
    assert!(matches!(parsed(entry, 7), Err(Error::Entry { .. })));
    let mut lane = vec![0; 16];
    lane[13] = 3;
    lane.extend_from_slice(&[3, 0x81, 0]);
    seal(&mut lane);
    assert_eq!(parsed(lane, 7).err(), Some(Error::LaneLength { port: 1 }));
    let mut dual = vec![0; 16];
    dual[13] = 3;
    dual.extend_from_slice(&[8, 0x81, 0x80, 9, 0, 0, 0, 0]);
    seal(&mut dual);
    assert_eq!(
        parsed(dual, 7).err(),
        Some(Error::DualPort { port: 1, dual: 9 })
    );
}
