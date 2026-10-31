extern crate std;
use super::*;
use crate::wifi::intel::receive::Packets;
use alloc::vec::Vec;
fn firmware(version: Option<u8>, apis: bool) -> Vec<u8> {
    let mut b = alloc::vec![0;88];
    b[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
    if let Some(v) = version {
        b.extend(48u32.to_le_bytes());
        b.extend(4u32.to_le_bytes());
        b.extend([0xc1, 0, 99, v]);
    }
    if apis {
        b.extend(29u32.to_le_bytes());
        b.extend(8u32.to_le_bytes());
        b.extend(1u32.to_le_bytes());
        b.extend(((1u32 << 9) | (1 << 27)).to_le_bytes());
    }
    b
}
fn buffer(payload: &[u8]) -> Vec<u8> {
    let mut b = alloc::vec![0;(payload.len()+8).next_multiple_of(64)];
    b[..4].copy_from_slice(&((payload.len() + 4) as u32).to_le_bytes());
    b[4] = 0xc1;
    b[6..8].copy_from_slice(&0x8000u16.to_le_bytes());
    b[8..8 + payload.len()].copy_from_slice(payload);
    b
}
#[test]
fn wifi_7_descriptors_keep_their_layout_through_three_versions() {
    let mut descriptor = alloc::vec![0; 65];
    descriptor[..2].copy_from_slice(&1u16.to_le_bytes());
    descriptor[64] = 0xab;
    let raw = buffer(&descriptor);
    for family in [Family::Bz, Family::Sc] {
        for version in 0..=255 {
            let b = firmware(Some(version), false);
            let fw = Firmware::parse(&b).unwrap();
            let observed = Observation::parse_raw(&fw, family, &raw[..73]);
            if (6..=8).contains(&version) {
                assert_eq!(observed.unwrap().raw_mpdu(), [0xab]);
            } else {
                assert_eq!(observed, Err(Error::Version(Some(version))));
            }
        }
    }
}
#[test]
fn every_descriptor_truncation_declared_overflow_and_raw_identity_are_checked() {
    for family in [Family::Ax200, Family::Ax210] {
        let version = if family == Family::Ax200 { 4 } else { 5 };
        let size = if family == Family::Ax200 { 48 } else { 64 };
        let b = firmware(Some(version), false);
        let fw = Firmware::parse(&b).unwrap();
        for len in 0..=8 {
            assert_eq!(
                Observation::parse_raw(&fw, family, &alloc::vec![0;len]),
                Err(Error::PacketLength)
            );
        }
        for len in 0..size {
            let raw = buffer(&alloc::vec![0;len]);
            let packet = Packets::new(family, 0, &raw)
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            assert_eq!(
                Observation::parse(&fw, family, &packet),
                Err(Error::DescriptorLength {
                    minimum: size,
                    actual: len
                })
            );
        }
        let mut descriptor = alloc::vec![0;size+3];
        descriptor[..2].copy_from_slice(&4u16.to_le_bytes());
        let raw = buffer(&descriptor);
        let packet = Packets::new(family, 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(
            Observation::parse(&fw, family, &packet),
            Err(Error::MpduLength {
                declared: 4,
                available: 3
            })
        );
        descriptor[..2].copy_from_slice(&1u16.to_le_bytes());
        descriptor[size..].copy_from_slice(&[0xab, 0xcd, 0xef]);
        let mut raw = buffer(&descriptor);
        let mut packet = Packets::new(family, 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        packet.command = 2;
        packet.group = 99;
        let observed = Observation::parse(&fw, family, &packet).unwrap();
        assert_eq!(observed.raw_mpdu(), [0xab]);
        assert_eq!(observed.trailing(), [0xcd, 0xef]);
        for schema in 0..=255 {
            let b = firmware(Some(schema), false);
            let fw = Firmware::parse(&b).unwrap();
            if schema == version {
                assert!(Observation::parse(&fw, family, &packet).is_ok());
            } else {
                assert_eq!(
                    Observation::parse(&fw, family, &packet),
                    Err(Error::Version(Some(schema)))
                );
            }
        }
        let b = firmware(None, false);
        assert_eq!(
            Observation::parse(&Firmware::parse(&b).unwrap(), family, &packet),
            Err(Error::Version(None))
        );
        raw[4] = 2;
        let mut packet = Packets::new(family, 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        packet.command = 0xc1;
        assert_eq!(
            Observation::parse(&fw, family, &packet),
            Err(Error::NotMpdu)
        );
    }
}
#[test]
fn status_and_overloaded_fields_remain_observations_without_security_permission() {
    for apis in [false, true] {
        let b = firmware(Some(4), apis);
        let fw = Firmware::parse(&b).unwrap();
        let mut d = alloc::vec![0;48];
        d[2] = 0xf0;
        d[3] = 0x7d;
        d[4] = 0xff;
        d[5..7].copy_from_slice(&0x160u16.to_le_bytes());
        d[7] = 0xff;
        d[12..16].copy_from_slice(&0x1f4000ecu32.to_le_bytes());
        d[16..20].copy_from_slice(&0xffabcdefu32.to_le_bytes());
        d[34] = 0;
        d[40..48].copy_from_slice(&0x123456789abcdef0u64.to_le_bytes());
        let raw = buffer(&d);
        let packet = Packets::new(Family::Ax200, 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let o = Observation::parse(&fw, Family::Ax200, &packet).unwrap();
        assert!(o.status.failed_fcs_or_overrun());
        assert!(o.status.key_valid_bit());
        assert!(o.status.icv_ok_bit());
        assert!(o.status.mic_ok_bit());
        assert!(!o.status.decrypted_bit());
        assert!(o.status.duplicate_bit());
        assert_eq!(o.status.station_id(), Some(31));
        assert_eq!(
            o.status.replay_or_ttak(),
            if apis {
                ReplayOrTtak::ReplayError(true)
            } else {
                ReplayOrTtak::TtakOk(true)
            }
        );
        assert_eq!(o.mac.padding_bytes(), 2);
        assert_eq!(o.mac.mic_crc_tail_bytes(), 30);
        assert_eq!(o.mac.reported_header_bytes(), 58);
        assert!(o.mac.amsdu());
        assert!(o.mac.amsdu_last());
        assert_eq!(o.mac.amsdu_index(), 127);
        assert!(o.mac.ampdu());
        assert!(o.mac.ampdu_toggle());
        assert_eq!(o.reorder.ba_id, None);
        assert_eq!(
            o.radio.timestamp,
            Timestamp::Overloaded {
                low: 0x9abcdef0,
                high: 0x12345678
            }
        );
        assert_eq!(o.radio.phy_data5, None);
        assert_eq!(
            o.radio.band,
            if apis {
                Band::Explicit(3)
            } else {
                Band::ChannelInferred { five_ghz: false }
            }
        );
        assert!(o.raw_mpdu().is_empty()); // descriptor observations do not certify a MAC frame.
    }
    for raw in [0, 1, 2, 3] {
        assert_eq!(
            Status {
                raw,
                deprecate_ttak: true
            }
            .failed_fcs_or_overrun(),
            raw != 3
        );
    }
    assert_eq!(
        Status {
            raw: 0x1f000000,
            deprecate_ttak: true
        }
        .station_id(),
        None
    );
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn images_admit_only_source_family_descriptor_versions() {
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    for family in [Family::Ax200, Family::Ax210] {
        let b = std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
        let fw = Firmware::parse(&b).unwrap();
        let size = if family == Family::Ax200 { 48 } else { 64 };
        let raw = buffer(&alloc::vec![0;size]);
        let packet = Packets::new(family, 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let o = Observation::parse(&fw, family, &packet).unwrap();
        assert_eq!(o.descriptor().len(), size);
        assert_eq!(
            o.status.replay_or_ttak(),
            if fw.supports_api(41) {
                ReplayOrTtak::ReplayError(false)
            } else {
                ReplayOrTtak::TtakOk(false)
            }
        );
        assert_eq!(o.radio.phy_data5.is_some(), family >= Family::Ax210);
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_MPDU_ORACLE"]
fn unchanged_packed_source_fields_and_masks_match_all_metadata_vectors() {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_MPDU_ORACLE").unwrap()).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "a63ee11d03584ab98a6256357ced03397cd597945965fbfe7f5172ba19e9ca96"
    );
    let mut lines = core::str::from_utf8(&bytes).unwrap().lines();
    assert_eq!(lines.next().unwrap(), "layout 48 64 28 36 40 48 12 16");
    let mut count = 0;
    for line in lines {
        let f: Vec<_> = line.split_whitespace().collect();
        let u = |i: usize| f[i].parse::<u64>().unwrap();
        assert_eq!(f[0], "case");
        let family = if u(1) == 0 {
            Family::Ax200
        } else {
            Family::Ax210
        };
        let apis = u(2) & 1 != 0;
        let b = firmware(Some(if family == Family::Ax200 { 4 } else { 5 }), apis);
        let fw = Firmware::parse(&b).unwrap();
        let mut d: Vec<_> = f[3]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        let descriptor = d.clone();
        let payload: Vec<_> = (0..u(4)).map(|i| (i * 17 + u(2)) as u8).collect();
        d.extend(&payload);
        d.extend([0xca, 0xfe]);
        let raw = buffer(&d);
        let packet = Packets::new(family, 0, &raw)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let o = Observation::parse(&fw, family, &packet).unwrap();
        assert_eq!(o.descriptor(), descriptor);
        assert_eq!(o.raw_mpdu(), payload);
        assert_eq!(o.trailing(), [0xca, 0xfe]);
        assert_eq!(
            [
                u64::from(o.mac.flags1),
                u64::from(o.mac.flags2),
                u64::from(o.mac.amsdu_info),
                u64::from(o.mac.phy_info),
                u64::from(o.radio.mac_phy_band),
                u64::from(o.status.raw()),
                u64::from(o.reorder.raw)
            ],
            core::array::from_fn::<_, 7, _>(|i| u(5 + i))
        );
        assert_eq!(
            [
                u64::from(o.radio.raw_rate),
                u64::from(o.radio.energy[0]),
                u64::from(o.radio.energy[1]),
                u64::from(o.radio.channel),
                u64::from(o.radio.mac_context),
                u64::from(o.radio.gp2_on_air_rise),
                o.radio.raw_timestamp,
                u64::from(o.radio.phy_data0),
                u64::from(o.radio.phy_data1),
                u64::from(o.radio.phy_data2),
                u64::from(o.radio.phy_data3)
            ],
            core::array::from_fn::<_, 11, _>(|i| u(12 + i))
        );
        assert_eq!(
            o.radio.phy_data5,
            if f[23] == "-" {
                None
            } else {
                Some(u(23) as u32)
            }
        );
        assert_eq!(u64::from(o.radio.phy_word4), u(24));
        assert_eq!(u64::from(o.status.cipher_code()), u(25));
        assert_eq!(
            o.status.station_id(),
            if o.status.raw() & 4 != 0 {
                Some(u(26) as u8)
            } else {
                None
            }
        );
        assert_eq!(u64::from(o.reorder.next_sequence), u(27));
        assert_eq!(u64::from(o.reorder.sequence), u(28));
        assert_eq!(
            o.reorder.ba_id,
            if u(29) == 127 {
                None
            } else {
                Some(u(29) as u8)
            }
        );
        assert_eq!(u64::from(o.reorder.old_sequence), u(30));
        assert_eq!(o.mac.mic_crc_tail_bytes() as u64, u(31));
        assert_eq!(o.mac.reported_header_bytes() as u64, u(32));
        assert_eq!(o.mac.padding_bytes() as u64, u(33));
        assert_eq!(
            o.radio.band,
            if apis {
                Band::Explicit(u(34) as u8)
            } else {
                Band::ChannelInferred {
                    five_ghz: o.radio.channel > 14,
                }
            }
        );
        assert_eq!(
            o.radio.timestamp,
            if o.mac.phy_info & 0x100 != 0 {
                Timestamp::Overloaded {
                    low: o.radio.phy_data0,
                    high: o.radio.phy_data1,
                }
            } else {
                Timestamp::Counter(o.radio.raw_timestamp)
            }
        );
        count += 1;
    }
    assert_eq!(count, 4096);
}
