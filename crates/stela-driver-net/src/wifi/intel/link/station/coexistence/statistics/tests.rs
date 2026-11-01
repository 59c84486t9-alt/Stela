// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Packet fields measured from the unchanged pinned C declarations, including
//! decoy adjacent counters, format rejection and current-MAC/zero filtering.
use super::*;
use alloc::{vec, vec::Vec};

const LAYOUTS: [(Format, usize, Option<usize>, usize); 5] = [
    (
        Format::Legacy {
            version: 11,
            new_statistics: false,
        },
        760,
        Some(252),
        584,
    ),
    (
        Format::Legacy {
            version: 13,
            new_statistics: true,
        },
        564,
        Some(120),
        404,
    ),
    (
        Format::Legacy {
            version: 14,
            new_statistics: true,
        },
        196,
        Some(8),
        12,
    ),
    (
        Format::Legacy {
            version: 15,
            new_statistics: true,
        },
        480,
        None,
        8,
    ),
    (Format::System { version: 3 }, 492, None, 4),
];

fn packet(layout: (Format, usize, Option<usize>, usize), mac: u8, energy: u32) -> Vec<u8> {
    let (format, size, id, energy_at) = layout;
    let mut raw = vec![0x5a; size];
    if let Format::Legacy {
        version: 14..=15, ..
    } = format
    {
        let Format::Legacy { version, .. } = format else {
            unreachable!()
        };
        raw[..4].copy_from_slice(&[0, version, size as u8, (size >> 8) as u8]);
    }
    if let Some(id) = id {
        raw[id..id + 4].copy_from_slice(&u32::from(mac).to_le_bytes());
    }
    match format {
        Format::Legacy {
            version: 0..=13, ..
        } => raw[energy_at] = energy as u8,
        _ => {
            let at = energy_at
                + if id.is_some() {
                    0
                } else {
                    usize::from(mac) * 28
                };
            raw[at..at + 4].copy_from_slice(&energy.to_le_bytes());
        }
    }
    raw
}

#[test]
fn every_source_layout_reads_beacon_filter_energy_not_adjacent_counters() {
    for layout in LAYOUTS {
        for mac in 0..4 {
            let raw = packet(layout, mac, 65);
            assert_eq!(layout.0.signal(&raw, mac), Ok(Some(-65)));
        }
    }
}

#[test]
fn incomplete_or_wrong_headers_cannot_become_signal_measurements() {
    for layout in LAYOUTS {
        let raw = packet(layout, 1, 50);
        for end in 0..raw.len() {
            assert!(matches!(
                layout.0.signal(&raw[..end], 1),
                Err(Error::Length { .. })
            ));
        }
        let mut tail = raw.clone();
        tail.push(0);
        let tlv = matches!(
            layout.0,
            Format::Legacy {
                version: 14..=15,
                ..
            }
        );
        assert_eq!(layout.0.signal(&tail, 1).is_ok(), tlv);
        if tlv {
            for byte in 0..4 {
                let mut bad = raw.clone();
                bad[byte] ^= 1;
                assert_eq!(layout.0.signal(&bad, 1), Err(Error::Header));
            }
            let mut high = raw.clone();
            high[0] |= 0x80;
            assert_eq!(layout.0.signal(&high, 1), Ok(Some(-50)));
        }
    }
}

#[test]
fn zero_and_other_mac_reports_leave_the_previous_measurement_alone() {
    for layout in LAYOUTS {
        assert_eq!(layout.0.signal(&packet(layout, 1, 0), 1), Ok(None));
        if let Some(at) = layout.2 {
            assert_eq!(layout.0.signal(&packet(layout, 1, 50), 0), Ok(None));
            let mut raw = packet(layout, 1, 50);
            raw[at + 2..at + 4].copy_from_slice(&[0xab, 0xcd]);
            assert_eq!(
                layout.0.signal(&raw, 1),
                Ok(Some(-50)),
                "source MAC comparison uses the low 16 bits"
            );
        }
        assert_eq!(
            layout.0.signal(&packet(layout, 1, 50), 4),
            Err(Error::Mac(4))
        );
    }
}

#[test]
fn source_signal_conversion_preserves_each_structures_field_width() {
    for layout in LAYOUTS {
        for energy in [0, 1, 50, 127, 255, 256, 0x8000_0000, u32::MAX] {
            let byte = matches!(
                layout.0,
                Format::Legacy {
                    version: 0..=14,
                    ..
                }
            );
            let measured = if byte {
                u32::from(energy as u8)
            } else {
                energy
            };
            let expected = (measured != 0).then_some((measured as i32).wrapping_neg());
            assert_eq!(layout.0.signal(&packet(layout, 1, energy), 1), Ok(expected));
        }
    }
}

#[test]
fn unknown_statistics_versions_are_explicit() {
    for format in [
        Format::Legacy {
            version: 16,
            new_statistics: true,
        },
        Format::System { version: 0 },
        Format::System { version: 4 },
    ] {
        assert!(matches!(
            format.signal(&[0; 760], 0),
            Err(Error::Version(_))
        ));
    }
}

#[test]
#[ignore = "oracle: STELA_IWLWIFI_STATS_ORACLE"]
fn pinned_c_statistics_declarations_match_complete_packets() {
    extern crate std;
    let path =
        std::env::var("STELA_IWLWIFI_STATS_ORACLE").expect("pinned C declaration packet trace");
    let trace = std::fs::read_to_string(path).unwrap();
    let mut lines = trace.lines();
    assert_eq!(
        lines.next().unwrap(),
        concat!(
            "linux=cc9de5d4b5ab6459f5774946aa3195ad51236fa8",
            " stats.h=23563771253355aedad33a1de51655a2ef7499e3aff4b71fd00db4ae44527e2a",
            " mac.h=6076083cec1720a0c5d94eebe9e156a8e866c24afad12ca7fd2efc54404f9bc0",
            " mac-cfg.h=3e4aa8bb08a992255e92b5136409b287cab5bfe0e693d7a2df57c87e68c3b0ae",
        )
    );
    let mut cases = 0;
    for row in lines {
        let mut fields = row.split_whitespace();
        let format = match fields.next().unwrap() {
            "legacy11" => Format::Legacy {
                version: 11,
                new_statistics: false,
            },
            "legacy13" => Format::Legacy {
                version: 13,
                new_statistics: true,
            },
            "tlv14" => Format::Legacy {
                version: 14,
                new_statistics: true,
            },
            "tlv15" => Format::Legacy {
                version: 15,
                new_statistics: true,
            },
            "system3" => Format::System { version: 3 },
            _ => panic!("unknown C packet structure"),
        };
        let mac = fields.next().unwrap().parse::<u8>().unwrap();
        let expected = fields.next().unwrap().parse::<i32>().unwrap();
        let hex = fields.next().unwrap();
        assert!(hex.len().is_multiple_of(2));
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert!(fields.next().is_none());
        assert_eq!(
            format.signal(&bytes, mac),
            Ok((expected != 0).then_some(expected))
        );
        cases += 1;
    }
    assert_eq!(cases, 220);
}
