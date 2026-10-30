extern crate std;
use super::*;
fn scan_elements(length: usize) -> Vec<u8> {
    let mut bytes = vec![0x5a; length];
    let mut at = 0;
    while at < length {
        let size = (length - at).min(257);
        bytes[at] = 221;
        bytes[at + 1] = (size - 2) as u8;
        at += size;
    }
    bytes
}
fn scan_channels(mask: u8) -> Vec<Channel> {
    [
        Channel {
            band: Band::Ghz2,
            number: 1,
            frequency_mhz: 2412,
        },
        Channel {
            band: Band::Ghz5,
            number: 36,
            frequency_mhz: 5180,
        },
        Channel {
            band: Band::Ghz6,
            number: 1,
            frequency_mhz: 5955,
        },
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(i, c)| (mask & (1 << i) != 0).then_some(c))
    .collect()
}
fn scan_context() -> Context {
    Context {
        bss_index: 0,
        omac_index: 0,
        band_index: 255,
        wmm_index: 0,
        link_index: 0,
        broadcast_wcid: 19,
        address: Mac([2; 6]),
    }
}
#[test]
fn full_source_rnr_scan_requests_match_targets_duplicates_bands_and_ie_budget() {
    use crate::wifi::scan::{Request, SixGhz};
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut index = 0;
    for n in [1, 2, 4, 10] {
        for duplicate in 0..3 {
            for names in [0, 1, 2, 4] {
                for length in [0, 4, 200] {
                    for mix in 0..3 {
                        let all = [
                            Channel {
                                band: Band::Ghz2,
                                number: 1,
                                frequency_mhz: 2412,
                            },
                            Channel {
                                band: Band::Ghz5,
                                number: 36,
                                frequency_mhz: 5180,
                            },
                            Channel {
                                band: Band::Ghz6,
                                number: 1,
                                frequency_mhz: 5955,
                            },
                            Channel {
                                band: Band::Ghz6,
                                number: 5,
                                frequency_mhz: 5975,
                            },
                        ];
                        let mut channels = Vec::new();
                        if mix == 2 {
                            channels.push(all[0]);
                        }
                        if mix != 0 {
                            channels.push(all[1]);
                        }
                        let six = channels.len();
                        channels.extend_from_slice(&all[2..]);
                        let mut params = Vec::new();
                        for j in 0..n {
                            let target = SixGhz {
                                channel_index: six + j % 2,
                                bssid: Mac([
                                    2,
                                    0x42,
                                    (index & 255) as u8,
                                    (index >> 8) as u8,
                                    j as u8,
                                    0x7f,
                                ]),
                                short_ssid: (j % 2 != 0).then_some(0xabc000 + j as u32),
                                unsolicited_probe: j % 2 == 0,
                                psc_no_listen: j % 2 != 0,
                                psd_20: -75 + j as i8,
                            };
                            params.push(target);
                            if duplicate == 2 {
                                params.push(SixGhz {
                                    channel_index: six + (j + 1) % 2,
                                    ..target
                                });
                            }
                        }
                        if duplicate == 1 {
                            for j in 0..n {
                                params.push(SixGhz {
                                    channel_index: six + j % 2,
                                    ..params[n - 1 - j]
                                });
                            }
                        }
                        let ssids = (0..names).map(|j| vec![65 + j as u8; j]).collect();
                        let request =
                            Request::with_six_ghz(channels, ssids, scan_elements(length), params)
                                .unwrap();
                        let encoded =
                            scan(scan_context(), (index % 127 + 1) as u8, &request).unwrap();
                        hash.update([0x16]);
                        hash.update((encoded.body().len() as u16).to_le_bytes());
                        hash.update(encoded.body());
                        index += 1;
                    }
                }
            }
        }
    }
    assert_eq!(index, 432);
    assert_eq!(
        alloc::format!("{:x}", hash.finalize()),
        "68a1c494a1886a2da6e86f7f013f35f70d3990ae076f4bf0f4c71216d722c831"
    );
}
#[test]
fn rnr_targets_past_ten_are_dropped_like_mt7925_mcu_hw_scan() {
    use crate::wifi::scan::{Request, SixGhz};
    let six = Channel {
        band: Band::Ghz6,
        number: 5,
        frequency_mhz: 5975,
    };
    let targets = (0..12)
        .map(|i| SixGhz {
            channel_index: 0,
            bssid: Mac([2, 0x42, 0, 0, i, 1]),
            short_ssid: None,
            unsolicited_probe: false,
            psc_no_listen: false,
            psd_20: 0,
        })
        .collect();
    let request = Request::with_six_ghz(vec![six], vec![vec![]], vec![], targets).unwrap();
    let encoded = scan(scan_context(), 1, &request).unwrap();
    let mut rest = &encoded.body()[4..];
    let mut bssids = Vec::new();
    while let [tag, _, length, high, ..] = rest {
        let length = usize::from(u16::from_le_bytes([*length, *high]));
        if *tag == 11 {
            bssids.push(rest[8]);
        }
        rest = &rest[length..];
    }
    assert_eq!(bssids, (0..10).collect::<Vec<_>>());
}
#[test]
fn native_per_band_probe_budget_refuses_before_losing_a_band() {
    let request = crate::wifi::scan::Request::new(scan_channels(7), vec![], vec![]).unwrap();
    let over = core::array::from_fn(|_| scan_elements(200));
    assert!(matches!(
        scan_with_elements(scan_context(), 1, &request, Some(&over)),
        Err(Error::InvalidScanElements)
    ));
    let mut fit = over;
    fit[2] = scan_elements(184);
    let bytes = scan_with_elements(scan_context(), 1, &request, Some(&fit)).unwrap();
    assert_eq!(
        u16::from_le_bytes(bytes.body()[2..4].try_into().unwrap()),
        8
    );
    assert_eq!(bytes.body().len(), 4 + 20 + 368 + 16 + 136 + 12 + 608);
}
#[test]
fn odd_scan_elements_keep_byte_layout_and_shared_band_budget() {
    for length in [3, 199, 295, 297, 383] {
        let request =
            crate::wifi::scan::Request::new(scan_channels(7), vec![], scan_elements(length))
                .unwrap();
        let encoded = scan(scan_context(), 1, &request).unwrap();
        let mut rest = &encoded.body()[4..];
        let mut ie_bytes = Vec::new();
        while !rest.is_empty() {
            let size = u16::from_le_bytes(rest[2..4].try_into().unwrap()) as usize;
            if rest[..2] == 13u16.to_le_bytes() {
                ie_bytes.push(rest[..size].to_vec());
            }
            rest = &rest[size..];
        }
        // Independent byte-level expectation: consecutive 8-byte IE
        // headers plus payload fit in the source's 608-byte total budget.
        let expected = (608 / (length + 8)).min(3);
        assert_eq!(ie_bytes.len(), expected);
        assert!(ie_bytes.iter().map(Vec::len).sum::<usize>() <= 608);
        assert_eq!(
            u16::from_le_bytes(encoded.body()[2..4].try_into().unwrap()) as usize,
            5 + expected
        );
        for (index, bytes) in ie_bytes.iter().enumerate() {
            assert_eq!(&bytes[..2], &13u16.to_le_bytes());
            assert_eq!(&bytes[2..4], &((length + 8) as u16).to_le_bytes());
            assert_eq!(&bytes[4..6], &(length as u16).to_le_bytes());
            assert_eq!(bytes[6], index as u8 + 1);
            assert_eq!(bytes[7], 0);
            assert_eq!(&bytes[8..], request.extra_elements());
        }
    }
}
#[test]
fn unchanged_full_scan_helper_matches_three_bands_and_total_ie_budget() {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut case = 0;
    for mask in 1..8 {
        for length in [0, 4, 200, 296, 297, 300, 384] {
            let request =
                crate::wifi::scan::Request::new(scan_channels(mask), vec![], scan_elements(length))
                    .unwrap();
            let encoded = scan(scan_context(), (case % 127 + 1) as u8, &request).unwrap();
            hash.update([0x16]);
            hash.update((encoded.body().len() as u16).to_le_bytes());
            hash.update(encoded.body());
            case += 1;
        }
    }
    assert_eq!(case, 49);
    // Full unchanged mt7925_mcu_hw_scan/build_scan_ie_tlv bodies, source
    // layouts and TLV appender under ASan/UBSan. Odd subsequent IE alignment
    // is an explicit donor oracle limit; the independent test keeps it.
    assert_eq!(
        <[u8; 32]>::from(hash.finalize()),
        [
            0x0f, 0xea, 0x6a, 0xda, 0xf0, 0xfa, 0xe0, 0x04, 0xa7, 0xde, 0xaa, 0xad, 0x2f, 0x26,
            0xd0, 0x3e, 0x7f, 0x28, 0x3e, 0x6c, 0xaa, 0x52, 0x65, 0x1b, 0x1a, 0xf6, 0x19, 0xcf,
            0xfe, 0x25, 0xce, 0x3a
        ]
    );
}

#[test]
#[ignore = "oracle: STELA_MT7925_CLIENT_ORACLE"]
fn unchanged_full_client_helpers_match_selected_legacy_requests_and_wcid() {
    let root = std::path::PathBuf::from(
        std::env::var_os("STELA_MT7925_CLIENT_ORACLE").expect("client source oracle"),
    );
    let trace = std::fs::read(root.join("client.trace")).unwrap();
    let mut at = 0;
    for i in 0..128u16 {
        let two = i % 2 == 0;
        let mut local = core::array::from_fn(|j| 2u8.wrapping_add(i as u8).wrapping_add(j as u8));
        local[0] &= 254;
        let mut peer = core::array::from_fn(|j| 4u8.wrapping_add(i as u8).wrapping_add(j as u8));
        peer[0] &= 254;
        let p = Profile {
            interface: Context {
                bss_index: (i % 4) as u8,
                omac_index: ((i * 7) % 64) as u8,
                band_index: 255,
                wmm_index: ((i / 4) % 4) as u8,
                link_index: 0,
                broadcast_wcid: 19 - i % 4,
                address: Mac(local),
            },
            peer: Mac(peer),
            wcid: i % 14,
            channel: Channel {
                band: if two { Band::Ghz2 } else { Band::Ghz5 },
                number: if two { 6 } else { 36 },
                frequency_mhz: if two { 2437 } else { 5180 },
            },
            aid: i + 1,
            basic_rates: if two { 15 } else { 0x15 },
            supported_rates: if two { 0xfff } else { 0xff },
            beacon_interval: 100 + i,
            dtim_period: 1 + (i % 4) as u8,
            slot_time: if (i / 8) % 2 == 1 { 9 } else { 20 },
            antenna_mask: 1 + (i % 15) as u8,
            cipher: if (i / 16) % 2 == 1 { 4 } else { 0 },
        };
        let names = (0..i % 5).map(|k| vec![65 + k as u8; k as usize]).collect();
        let scan_request = crate::wifi::scan::Request::new(
            vec![p.channel],
            names,
            if (i / 4) % 2 == 1 {
                vec![1, 1, 0x8c]
            } else {
                vec![]
            },
        )
        .unwrap();
        let sequence = ((i % 127) + 1) as u8 & 127;
        for (command, body) in [
            (3, p.peer_request(true, false).unwrap()),
            (3, p.peer_request(true, true).unwrap()),
            (3, p.peer_request(false, false).unwrap()),
            (2, p.bss_request(false).unwrap()),
            (2, p.bss_request(true).unwrap()),
            (0x27, p.roc((i + 1) as u8, 1000).unwrap().body().to_vec()),
            (0x27, p.abort_roc((i + 1) as u8).unwrap().body().to_vec()),
            (2, p.beacon_filter().unwrap()),
            (2, p.awake().unwrap()),
            (2, p.disable_beacon_pm().unwrap()),
            (8, p.filter_request(true).unwrap().body().to_vec()),
            (8, p.filter_request(false).unwrap().body().to_vec()),
            (
                0x16,
                scan(p.interface, sequence, &scan_request)
                    .unwrap()
                    .body()
                    .to_vec(),
            ),
            (0x16, cancel_scan(p.interface, sequence).body().to_vec()),
        ] {
            assert_eq!(trace[at], command, "case {i}");
            let n = u16::from_le_bytes(trace[at + 1..at + 3].try_into().unwrap()) as usize;
            at += 3;
            assert_eq!(body, &trace[at..at + n], "case {i} cmd {command}");
            at += n;
        }
    }
    let p = Profile {
        wcid: 1,
        interface: Context {
            bss_index: 0,
            omac_index: 0,
            band_index: 255,
            wmm_index: 0,
            link_index: 0,
            broadcast_wcid: 19,
            address: Mac([2; 6]),
        },
        peer: Mac([4; 6]),
        channel: Channel {
            band: Band::Ghz5,
            number: 36,
            frequency_mhz: 5180,
        },
        aid: 1,
        basic_rates: 1,
        supported_rates: 1,
        beacon_interval: 100,
        dtim_period: 1,
        slot_time: 9,
        antenna_mask: 1,
        cipher: 0,
    };
    for raw in 0..22 {
        for unicast in [false, true] {
            let expected = u16::from_le_bytes(trace[at..at + 2].try_into().unwrap());
            at += 2;
            assert_eq!(p.receive_slot(raw, unicast).unwrap_or(u16::MAX), expected);
        }
    }
    assert_eq!(at, trace.len());
}

#[test]
fn bss_updates_encode_like_mt7925_mcu() {
    use crate::wifi::station::{operations::ChannelDefinition, phy::Width};
    let channel = Channel {
        band: Band::Ghz5,
        number: 40,
        frequency_mhz: 5200,
    };
    let p = Profile {
        wcid: 1,
        interface: Context {
            bss_index: 3,
            omac_index: 0,
            band_index: 0,
            wmm_index: 0,
            link_index: 0,
            broadcast_wcid: 19,
            address: Mac([2; 6]),
        },
        peer: Mac([4; 6]),
        channel,
        aid: 1,
        basic_rates: 1,
        supported_rates: 1,
        beacon_interval: 100,
        dtim_period: 1,
        slot_time: 20,
        antenna_mask: 3,
        cipher: 0,
    };
    // mt7925_mcu_set_rssimonitor
    assert_eq!(
        p.rssi_monitor_request(true, -68, -72).unwrap(),
        [3, 0, 0, 0, 0, 0, 8, 0, 1, (-68i8) as u8, (-72i8) as u8, 0]
    );
    // mt7925_mcu_set_timing
    let timing = p.timing().unwrap();
    assert_eq!(timing[4..14], [23, 0, 20, 0, 1, 0, 0, 0, 20, 0]);
    // mt7925_mcu_set_chctx: 40 MHz on 36/40, control above center (SCB).
    let definition = ChannelDefinition {
        control: channel,
        width: Width::Mhz40,
        center1_mhz: 5190,
        center2_mhz: None,
        punctured: 0,
    };
    assert_eq!(
        p.channel_request(&definition).unwrap()[4..17],
        [2, 0, 16, 0, 40, 38, 0, 1, 2, 2, 4, 3, 2]
    );
}
