extern crate std;
use super::*;
const RATES: [LegacyRate; 12] = [
    LegacyRate::Cck1,
    LegacyRate::Cck2,
    LegacyRate::Cck5_5,
    LegacyRate::Cck11,
    LegacyRate::Ofdm6,
    LegacyRate::Ofdm9,
    LegacyRate::Ofdm12,
    LegacyRate::Ofdm18,
    LegacyRate::Ofdm24,
    LegacyRate::Ofdm36,
    LegacyRate::Ofdm48,
    LegacyRate::Ofdm54,
];
pub(super) fn firmware(rows: &[[u8; 4]]) -> Vec<u8> {
    let mut b = alloc::vec![0;88];
    b[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
    if !rows.is_empty() {
        b.extend(48u32.to_le_bytes());
        b.extend((rows.len() as u32 * 4).to_le_bytes());
        b.extend(rows.iter().flatten());
    }
    b
}
pub(super) fn rows(family: Family) -> [[u8; 4]; 4] {
    [
        [0x1c, 1, if family == Family::Ax200 { 9 } else { 10 }, 7],
        [0xf7, 5, 99, 3],
        [0xc1, 0, 99, if family == Family::Ax200 { 4 } else { 5 }],
        [0xf5, 5, 99, 3],
    ]
}
fn parameters() -> Parameters {
    Parameters {
        station_authorized: Some(true),
        force_host_rate: false,
        host_rate: LegacyRate::Ofdm6,
        host_antenna: 1,
        firmware_encryption: false,
    }
}
fn frame(data: bool, key: bool, len: usize, scene: u32) -> Vec<u8> {
    let mut f: Vec<_> = (0..len).map(|i| (i as u32 * 29 + scene) as u8).collect();
    f[..2].copy_from_slice(
        &(if data { 0x108u16 } else { 0xb0 } | if key { 0x4000 } else { 0 }).to_le_bytes(),
    );
    f[22] &= 0xf0;
    f
}
#[test]
fn schema_consistency_is_required_before_any_frame_preparation() {
    for family in [Family::Ax200, Family::Ax210] {
        let mut r = rows(family);
        let f = frame(true, false, 24, 0);
        for schema in [0, 7, 8, 11, 99, 255] {
            r[0][2] = schema;
            let b = firmware(&r);
            assert_eq!(
                Prepared::prepare(&Firmware::parse(&b).unwrap(), family, &f, parameters())
                    .unwrap_err(),
                Error::CommandVersion(schema)
            );
        }
        for missing in 0..3 {
            let r: Vec<_> = rows(family)
                .into_iter()
                .enumerate()
                .filter_map(|(i, v)| (i != missing).then_some(v))
                .collect();
            let b = firmware(&r);
            assert!(matches!(
                Prepared::prepare(&Firmware::parse(&b).unwrap(), family, &f, parameters()),
                Err(Error::MissingApi { .. })
            ));
        }
        for (row, field, value) in [
            (0, 3, 5),
            (0, 3, 9),
            (1, 3, 2),
            (1, 3, 4),
            (2, 3, 3),
            (2, 3, 6),
            (3, 3, 4),
        ] {
            let mut r = rows(family);
            r[row][field] = value;
            let b = firmware(&r);
            assert_eq!(
                Prepared::prepare(&Firmware::parse(&b).unwrap(), family, &f, parameters())
                    .unwrap_err(),
                Error::RateVersions
            );
        }
    }
}
#[test]
fn bounded_profile_preserves_header_sequence_and_refuses_unrepresented_effects() {
    let b = firmware(&rows(Family::Ax200));
    let fw = Firmware::parse(&b).unwrap();
    for len in [0, 1, 23, 4097] {
        assert_eq!(
            Prepared::prepare(&fw, Family::Ax200, &alloc::vec![0;len], parameters()).unwrap_err(),
            Error::FrameLength
        );
    }
    for (fc, error) in [
        (0x109, Error::FrameControl),
        (0x188, Error::FrameControl),
        (0x308, Error::FrameControl),
        (0x208, Error::FrameControl),
        (0x8108, Error::FrameControl),
        (0x508, Error::Fragment),
        (0x4108, Error::Encryption),
        (0x104, Error::FrameControl),
    ] {
        let mut f = frame(true, false, 24, 0);
        f[..2].copy_from_slice(&(fc as u16).to_le_bytes());
        assert_eq!(
            Prepared::prepare(&fw, Family::Ax200, &f, parameters()).unwrap_err(),
            error
        );
    }
    let mut f = frame(true, false, 25, 0);
    f[22] |= 1;
    assert_eq!(
        Prepared::prepare(&fw, Family::Ax200, &f, parameters()).unwrap_err(),
        Error::Fragment
    );
    let f = frame(true, false, 25, 0);
    let p = Parameters {
        host_antenna: 0,
        ..parameters()
    };
    assert!(
        Prepared::prepare(&fw, Family::Ax200, &f, p)
            .unwrap()
            .host_rate()
            .is_none()
    ); // unused host input.
    assert_eq!(
        Prepared::prepare(
            &fw,
            Family::Ax200,
            &f,
            Parameters {
                force_host_rate: true,
                ..p
            }
        )
        .unwrap_err(),
        Error::Antenna
    );
    for sequence in (0..=u16::MAX).step_by(16) {
        let mut f = f.clone();
        f[22..24].copy_from_slice(&sequence.to_le_bytes());
        let cmd = Prepared::prepare(&fw, Family::Ax200, &f, parameters()).unwrap();
        assert_eq!(&cmd.command_and_mac()[20..], &f[..24]);
    }
    let mut p = parameters();
    p.firmware_encryption = true;
    assert_eq!(
        Prepared::prepare(&fw, Family::Ax200, &f, p).unwrap_err(),
        Error::Encryption
    );
    assert_eq!(
        Prepared::prepare(&fw, Family::Ax200, &frame(false, true, 24, 0), p).unwrap_err(),
        Error::Encryption
    );
}
#[test]
fn source_short_header_full_queue_echo_and_exact_three_dma_ranges() {
    for family in [Family::Ax200, Family::Ax210] {
        let b = firmware(&rows(family));
        let fw = Firmware::parse(&b).unwrap();
        for len in [24, 25, 4096] {
            let f = frame(true, true, len, 123);
            let plan = Prepared::prepare(
                &fw,
                family,
                &f,
                Parameters {
                    firmware_encryption: true,
                    ..parameters()
                },
            )
            .unwrap();
            for queue in [0, 31, 32, 255, 511] {
                let encoded = plan.encode(queue, 0x12ab).unwrap();
                assert_eq!(encoded.queue(), queue);
                assert_eq!(
                    &encoded.command()[..4],
                    &[0x1c, 0, 0xab, (queue & 31) as u8]
                );
                assert_eq!(encoded.sequence(), ((queue & 31) << 8) | 0xab);
                assert_eq!(encoded.first_tb().len(), 20);
                assert_eq!(&encoded.command()[12..20], &[0; 8]);
                assert_eq!(encoded.payload(), &f[24..]);
                let first = Region {
                    address: 0x100000,
                    bytes: 20,
                };
                let second = Region {
                    address: 0x200001,
                    bytes: encoded.second_tb().len(),
                };
                let payload = (!encoded.payload().is_empty()).then_some(Region {
                    address: 0x300003,
                    bytes: encoded.payload().len(),
                });
                let (tfd, bc) = encoded.tfd(first, second, payload).unwrap();
                assert_eq!(
                    u16::from_le_bytes(tfd.bytes()[..2].try_into().unwrap()),
                    if len == 24 { 2 } else { 3 }
                );
                assert_eq!(
                    bc,
                    if family == Family::Ax200 {
                        len.div_ceil(4) as u16
                    } else {
                        len as u16
                    }
                );
                assert_eq!(
                    encoded
                        .tfd(Region { bytes: 19, ..first }, second, payload)
                        .unwrap_err(),
                    Error::Split
                );
                assert_eq!(
                    encoded
                        .tfd(
                            first,
                            Region {
                                bytes: second.bytes + 1,
                                ..second
                            },
                            payload
                        )
                        .unwrap_err(),
                    Error::Split
                );
            }
            assert_eq!(plan.encode(512, 0).unwrap_err(), Error::Queue);
        }
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
fn actual_images_negotiate_source_rate2_and_family9_10_layouts() {
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    for family in [Family::Ax200, Family::Ax210] {
        let b = std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
        let fw = Firmware::parse(&b).unwrap();
        let plan =
            Prepared::prepare(&fw, family, &frame(true, false, 60, 0), parameters()).unwrap();
        assert_eq!(
            plan.command_and_mac().len(),
            if family == Family::Ax200 { 44 } else { 52 }
        );
        assert_eq!(plan.host_rate(), None);
    }
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_TRANSMIT_ORACLE"]
fn unchanged_linux_new_tx_helpers_match_complete_commands_and_byte_counts() {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_TRANSMIT_ORACLE").unwrap()).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "5bdcc7ad438bed3d044f5ebc9148589c43a5e7b448fb0496abb6708f6f7797cf"
    );
    let mut count = 0;
    for line in core::str::from_utf8(&bytes).unwrap().lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        let u = |i: usize| f[i].parse::<u32>().unwrap();
        assert_eq!(f[0], "tx");
        let family = if u(1) == 0 {
            Family::Ax200
        } else {
            Family::Ax210
        };
        let b = firmware(&rows(family));
        let fw = Firmware::parse(&b).unwrap();
        let len = [24, 25, 60, 1514, 4096][u(8) as usize];
        let mpdu = frame(u(2) != 0, u(3) != 0, len, u(9));
        let p = Parameters {
            station_authorized: if u(4) == 0 { None } else { Some(u(4) == 2) },
            force_host_rate: u(5) != 0,
            host_rate: RATES[u(6) as usize],
            host_antenna: u(7) as u8,
            firmware_encryption: u(3) != 0,
        };
        let plan = Prepared::prepare(&fw, family, &mpdu, p).unwrap();
        let encoded = plan.encode(u(10) as u16, u(11) as u16).unwrap();
        let hex: std::string::String = encoded
            .command()
            .iter()
            .map(|b| std::format!("{b:02x}"))
            .collect();
        assert_eq!(hex, f[12], "{line}");
        let (_, bc) = encoded
            .tfd(
                Region {
                    address: 0x100000,
                    bytes: 20,
                },
                Region {
                    address: 0x200000,
                    bytes: encoded.second_tb().len(),
                },
                (len > 24).then_some(Region {
                    address: 0x300000,
                    bytes: len - 24,
                }),
            )
            .unwrap();
        assert_eq!(u32::from(bc), u(13));
        count += 1;
    }
    assert_eq!(count, 4320);
}
