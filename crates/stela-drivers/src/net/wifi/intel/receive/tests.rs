use super::*;
use alloc::vec::Vec;
fn firmware(version: Option<u8>) -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
    bytes[72..76].copy_from_slice(&77u32.to_le_bytes());
    if let Some(version) = version {
        bytes.extend(48u32.to_le_bytes());
        bytes.extend(4u32.to_le_bytes());
        bytes.extend([1, 0, 99, version]);
    }
    bytes
}
fn wire_packet(payload: &[u8], queue: u8, command: u8) -> Vec<u8> {
    let mut bytes = vec![0; (payload.len() + 8).next_multiple_of(64)];
    bytes[..4].copy_from_slice(
        &((payload.len() as u32 + 4) | (u32::from(queue) << 16) | (1 << 25)).to_le_bytes(),
    );
    bytes[4] = command;
    bytes[6..8].copy_from_slice(&0x9a55u16.to_le_bytes());
    bytes[8..8 + payload.len()].copy_from_slice(payload);
    bytes
}
#[test]
fn source_multi_packet_alignment_single_packet_ax210_and_raw_sequence() {
    let mut bytes = wire_packet(&[1, 2, 3], 3, 1);
    bytes.extend(wire_packet(&[4; 65], 3, 2));
    bytes.extend([0; 64]);
    let end = bytes.len() - 64;
    bytes[end..end + 4].copy_from_slice(&0x55550000u32.to_le_bytes());
    let received = Packets::new(Family::Ax200, 3, &bytes)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0].range, 0..11);
    assert_eq!(received[1].range, 64..137);
    assert_eq!(received[0].payload(), [1, 2, 3]);
    assert_eq!(received[1].payload(), [4; 65]);
    assert!(received[0].unsolicited());
    assert_eq!(received[0].command_queue(), 0x1a);
    assert_eq!(received[0].command_index(), 0x55);
    assert_ne!(received[0].raw_flags & (1 << 25), 0);
    assert_eq!(received[1].raw().as_ptr(), bytes[64..].as_ptr());
    assert_eq!(Packets::new(Family::Ax210, 3, &bytes).unwrap().count(), 1);
    let mut end = Packets::new(Family::Ax200, 3, &bytes[end..]).unwrap();
    assert!(end.next().is_none());
    assert!(end.next().is_none());
}
#[test]
fn hostile_lengths_queues_and_truncations_fuse_without_exposing_payload() {
    for n in 0usize..256 {
        if !n.is_multiple_of(64) || n == 0 {
            assert!(matches!(
                Packets::new(Family::Ax200, 0, &vec![0; n]),
                Err(Error::BufferSize)
            ));
        }
    }
    for flags in [0u32, 1, 2, 3, 61, 62, 63, 64, 4095, 0x3fff, u32::MAX] {
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(&flags.to_le_bytes());
        let mut packets = Packets::new(Family::Ax200, 0, &bytes).unwrap();
        assert!(matches!(packets.next(), Some(Err(_))), "flags {flags:x}");
        assert!(packets.next().is_none());
    }
    let bytes = wire_packet(&[0], 2, 1);
    assert!(matches!(
        Packets::new(Family::Ax200, 1, &bytes).unwrap().next(),
        Some(Err(Error::Queue {
            expected: 1,
            actual: 2
        }))
    ));
}
#[test]
fn actual_family_descriptor_layouts_and_reserved_bytes_are_preserved() {
    assert_eq!(
        free_descriptor(Family::Ax200, 0x123456789000, 0xabc).unwrap(),
        FreeDescriptor::Ax200(0x123456789abcu64.to_le_bytes())
    );
    let FreeDescriptor::Ax210(bytes) =
        free_descriptor(Family::Ax210, 0x123456789000, 0xabc).unwrap()
    else {
        panic!()
    };
    assert_eq!(&bytes[..8], &[0xbc, 0x0a, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[8..], &0x123456789000u64.to_le_bytes());
    for id in [0x1000, u16::MAX] {
        let FreeDescriptor::Ax210(encoded) =
            free_descriptor(Family::Ax210, 0x123456789800, id).unwrap()
        else {
            panic!()
        };
        assert_eq!(le16(&encoded, 0), id);
        assert_eq!(le64(&encoded, 8), 0x123456789800);
        let mut raw = [0; 32];
        raw[4..6].copy_from_slice(&id.to_le_bytes());
        assert_eq!(used_descriptor(Family::Ax210, &raw).unwrap().id, id);
    }
    for id in [0, 4096, u16::MAX] {
        assert_eq!(
            free_descriptor(Family::Ax200, 4096, id),
            Err(Error::DescriptorId)
        );
    }
    for address in [0, 1, 4095, 4097, u64::MAX] {
        assert_eq!(
            free_descriptor(Family::Ax210, address, 1),
            Err(Error::DescriptorAddress)
        );
    }
    assert_eq!(
        used_descriptor(Family::Ax200, &0xfedc0abcu32.to_le_bytes())
            .unwrap()
            .id,
        0xabc
    );
    let mut completion = [0xaa; 32];
    completion[4..6].copy_from_slice(&0xabcu16.to_le_bytes());
    completion[6] = 0xfd;
    let used = used_descriptor(Family::Ax210, &completion).unwrap();
    assert_eq!(used.id, 0xabc);
    assert!(used.fragmented);
    assert_eq!(used.raw, &completion);
    for n in 0..64 {
        if n != 32 {
            assert_eq!(
                used_descriptor(Family::Ax210, &vec![0; n]),
                Err(Error::DescriptorSize)
            );
        }
    }
    completion[4..6].fill(0);
    assert_eq!(
        used_descriptor(Family::Ax210, &completion),
        Err(Error::DescriptorId)
    );
}
#[test]
fn negotiated_alive_layout_full_metadata_failures_and_extra_bytes() {
    for version in [6, 7, 8] {
        let fw_bytes = firmware(Some(version));
        let firmware = Firmware::parse(&fw_bytes).unwrap();
        let n = if version == 8 { 152 } else { 144 };
        let mut raw: Vec<_> = (0..n + 4).map(|n| (n + 17) as u8).collect();
        raw[..2].copy_from_slice(&0xcafeu16.to_le_bytes());
        let bytes = wire_packet(&raw, 0, 1);
        let packet = Packets::new(Family::Ax200, 0, &bytes)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let alive = Alive::decode(&packet, &firmware).unwrap();
        assert_eq!(alive.notification_version, version);
        assert_eq!(alive.raw(), &raw);
        assert_eq!(alive.flags, 0x1413);
        assert_eq!(alive.lmac[0].major, 0x18171615);
        assert_eq!(alive.lmac[1].major, 0x48474645);
        assert_eq!(alive.lmac[1].debug_addresses[7], 0x74737271);
        assert_eq!(alive.umac.major, 0x78777675);
        assert_eq!(alive.umac.minor, 0x7c7b7a79);
        assert_eq!(alive.umac.debug_addresses, [0x807f7e7d, 0x84838281]);
        assert_eq!(alive.sku, [0x88878685, 0x8c8b8a89, 0x908f8e8d]);
        assert_eq!(alive.imr.base, 0x9897969594939291);
        assert_eq!(alive.imr.bytes, 0x9c9b9a99);
        assert_eq!(alive.imr.enabled, 0xa09f9e9d);
        assert_eq!(
            alive.platform_id,
            if version == 8 {
                Some(0xa8a7a6a5a4a3a2a1)
            } else {
                None
            }
        );
        for n in 0..n {
            let bytes = wire_packet(&raw[..n], 0, 1);
            let packet = Packets::new(Family::Ax200, 0, &bytes)
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            assert!(matches!(
                Alive::decode(&packet, &firmware),
                Err(Error::AliveLength { .. })
            ));
        }
        raw[..2].copy_from_slice(&0xdeadu16.to_le_bytes());
        let bytes = wire_packet(&raw, 0, 1);
        let packet = Packets::new(Family::Ax200, 0, &bytes)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert!(matches!(
            Alive::decode(&packet, &firmware),
            Err(Error::AliveRejected { status: 0xdead, .. })
        ));
    }
    let bytes = wire_packet(&[0; 152], 0, 1);
    let packet = Packets::new(Family::Ax210, 0, &bytes)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    for version in [None, Some(0), Some(3), Some(5), Some(9), Some(255)] {
        let fw_bytes = firmware(version);
        let fw = Firmware::parse(&fw_bytes).unwrap();
        assert!(matches!(Alive::decode(&packet,&fw),Err(Error::AliveVersion(v)) if v==version));
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn both_actual_firmware_images_negotiate_alive_six() {
    extern crate std;
    use sha2::{Digest, Sha256};
    let directory = std::env::var("STELA_IWLWIFI_IMAGES").expect("image directory");
    for (family, hash) in [
        (
            Family::Ax200,
            "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab",
        ),
        (
            Family::Ax210,
            "792478ef7752595525379a5068e2d47e310a2c344636b7df866c54746ced1dc0",
        ),
    ] {
        let bytes =
            std::fs::read(std::path::Path::new(&directory).join(family.firmware_name())).unwrap();
        let actual: alloc::string::String = Sha256::digest(&bytes)
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(actual, hash);
        let firmware = Firmware::parse(&bytes).unwrap();
        let mut payload = [0; 144];
        payload[..2].copy_from_slice(&0xcafeu16.to_le_bytes());
        let bytes = wire_packet(&payload, 0, 1);
        let packet = Packets::new(family, 0, &bytes)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            Alive::decode(&packet, &firmware)
                .unwrap()
                .notification_version,
            6
        );
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_RECEIVE_ORACLE"]
fn unchanged_donor_structs_match_every_alive_field_and_ax210_descriptor_lane() {
    extern crate std;
    use core::fmt::Write;
    use sha2::{Digest, Sha256};
    let trace =
        std::fs::read(std::env::var("STELA_IWLWIFI_RECEIVE_ORACLE").expect("receive trace"))
            .unwrap();
    let hex = |bytes: &[u8]| -> alloc::string::String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    };
    assert_eq!(
        hex(&Sha256::digest(&trace)),
        "37700ac24f54d4cbe55b2d33d1f587c8d2bbfd6265720bdbe39ba5b5eac837d7"
    );
    let mut raw: Vec<_> = (0..152).map(|n| (n + 17) as u8).collect();
    raw[..2].copy_from_slice(&0xcafeu16.to_le_bytes());
    let fw_bytes = firmware(Some(8));
    let firmware = Firmware::parse(&fw_bytes).unwrap();
    let bytes = wire_packet(&raw, 0, 1);
    let packet = Packets::new(Family::Ax210, 0, &bytes)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let alive = Alive::decode(&packet, &firmware).unwrap();
    let mut actual = alloc::string::String::from("layout 144 152 48 100 116 128 16 8 4\n");
    writeln!(actual, "flags {:x}", alive.flags).unwrap();
    for l in alive.lmac {
        write!(
            actual,
            "lmac {:x} {:x} {:x} {:x} {:x} {:x} {:x}",
            l.major, l.minor, l.subtype, l.kind, l.mac, l.options, l.timestamp
        )
        .unwrap();
        for d in l.debug_addresses {
            write!(actual, " {d:x}").unwrap();
        }
        writeln!(actual).unwrap();
    }
    writeln!(
        actual,
        "umac {:x} {:x} {:x} {:x}",
        alive.umac.major,
        alive.umac.minor,
        alive.umac.debug_addresses[0],
        alive.umac.debug_addresses[1]
    )
    .unwrap();
    writeln!(
        actual,
        "sku {:x} {:x} {:x}",
        alive.sku[0], alive.sku[1], alive.sku[2]
    )
    .unwrap();
    writeln!(
        actual,
        "imr {:x} {:x} {:x}",
        alive.imr.base, alive.imr.bytes, alive.imr.enabled
    )
    .unwrap();
    writeln!(actual, "platform {:x}", alive.platform_id.unwrap()).unwrap();
    let FreeDescriptor::Ax210(td) = free_descriptor(Family::Ax210, 0x123456789000, 0xabc).unwrap()
    else {
        panic!()
    };
    writeln!(actual, "free {}", hex(&td)).unwrap();
    let mut cd = [0xaa; 32];
    cd[4..6].copy_from_slice(&0xabcu16.to_le_bytes());
    cd[6] = 0xfd;
    let used = used_descriptor(Family::Ax210, &cd).unwrap();
    assert_eq!(used.id, 0xabc);
    assert!(used.fragmented);
    writeln!(actual, "used {}", hex(used.raw)).unwrap();
    for id in [0x1000, u16::MAX] {
        let FreeDescriptor::Ax210(td) = free_descriptor(Family::Ax210, 0x123456789800, id).unwrap()
        else {
            panic!()
        };
        writeln!(actual, "widefree {}", hex(&td)).unwrap();
    }
    assert_eq!(actual.as_bytes(), trace);
}
