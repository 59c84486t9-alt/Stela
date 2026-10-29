use super::*;
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn packet(chip: Chip, groups: u32, mode: u8, format: u8, offset: u8) -> Vec<u8> {
    let c3 = chip == Chip::Mt7925;
    let base = if c3 { 32 } else { 24 };
    let sizes = [
        (8, 16),
        (1, 16),
        (2, if c3 { 16 } else { 8 }),
        (4, if c3 { 16 } else { 8 }),
        (16, if c3 { 96 } else { 72 }),
    ];
    let gap = base
        + sizes
            .iter()
            .filter(|(bit, _)| groups & bit != 0)
            .map(|(_, bytes)| bytes)
            .sum::<usize>()
        + usize::from(offset) * 2;
    let mut bytes = vec![0; gap + 24 + 40 + if format != 0 { 2 } else { 0 }];
    let len = bytes.len() as u32;
    put(&mut bytes, 0, (2 << 27) | len);
    put(
        &mut bytes,
        4,
        7 | (groups << if c3 { 16 } else { 11 })
            | (2 << 21)
            | if c3 { 0 } else { u32::from(mode) << 16 },
    );
    put(
        &mut bytes,
        8,
        if c3 {
            u32::from(mode) << 16 | u32::from(offset) << 13
        } else {
            u32::from(offset) << 14
        },
    );
    put(&mut bytes, 12, (36 << 8) | (1 << 16));
    put(&mut bytes, 16, u32::from(format));
    let mut at = base;
    for (bit, size) in sizes {
        if groups & bit == 0 {
            continue;
        }
        for i in 0..size {
            bytes[at + i] = (bit * 9 + i as u32) as u8;
        }
        if bit == 4 && c3 {
            // A 1 Mb/s CCK P-RXV rate.
            put(&mut bytes, at, 0);
            put(&mut bytes, at + 8, 0);
        }
        at += size;
    }
    for i in 0..24 {
        bytes[gap + i] = (i * 7) as u8;
    }
    bytes[gap] = 8;
    bytes[gap + 1] = 0;
    let payload = gap
        + 24
        + if format != 0 {
            bytes[gap + 24] = 0xff;
            bytes[gap + 25] = 0xfe;
            2
        } else {
            0
        };
    for i in 0..40 {
        bytes[payload + i] = i as u8;
    }
    bytes
}
#[test]
fn every_valid_optional_group_combination_retains_boundaries_and_payload_padding() {
    for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
        for groups in 0..32 {
            if groups & 16 != 0 && groups & 4 == 0 {
                continue;
            }
            for format in 0..4 {
                for offset in 0..if chip == Chip::Mt7925 { 8 } else { 4 } {
                    let bytes = packet(chip, groups, 4, format, offset);
                    let decoded = decode(chip, &bytes).unwrap();
                    assert_eq!(decoded.raw, bytes);
                    assert_eq!(decoded.wcid, 7);
                    assert!(decoded.unicast_to_me);
                    assert_eq!(decoded.security.key_index, 2);
                    assert!(decoded.security.decrypted);
                    let normalized = decoded.normalize(24).unwrap();
                    assert_eq!(normalized.len(), 64);
                    assert_eq!(&normalized[24..], &(0..40).collect::<Vec<u8>>());
                    assert_eq!(&normalized[..24], &decoded.payload[..24]);
                    assert_eq!(decoded.amsdu.is_some(), format != 0);
                    if let Some(one) = &decoded.groups.one {
                        assert_eq!(
                            decoded.security.packet_number_be.unwrap(),
                            core::array::from_fn::<_, 6, _>(|i| bytes[one.start + 5 - i])
                        );
                    } else {
                        assert!(decoded.security.packet_number_be.is_none());
                    }
                    assert_eq!(decoded.timestamp_low.is_some(), groups & 2 != 0);
                    assert_eq!(decoded.rxv.is_some(), groups & 4 != 0);
                    if let Some(signal) = decoded.signal {
                        for i in 0..4 {
                            assert_eq!(signal.dbm[i], (i16::from(signal.rcpi[i] / 2) - 110) as i8);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn p_rxv_rates_decode_like_mt7925_mac_fill_rx_rate() {
    // (mode, raw rate, NSTS, frame mode, GI, band) and the result.
    let rate = |mode: u32, index: u32, nsts: u32, bw: u32, gi: u32, band| {
        let v2 = mode << 11 | 1 << 9 | gi << 3 | bw;
        super::rate(&[index | nsts << 7, 0, v2, 0], band)
    };
    let legacy = |index| RxRate {
        index,
        stbc: 1,
        ..RxRate::default()
    };
    // Long- and short-preamble 2 Mb/s CCK; CCK outside 2.4 GHz.
    assert_eq!(rate(0, 1, 0, 0, 0, Band::Ghz2), Ok(legacy(1)));
    assert_eq!(rate(0, 5, 0, 0, 0, Band::Ghz2), Ok(legacy(1)));
    assert_eq!(rate(0, 1, 0, 0, 0, Band::Ghz5), Ok(legacy(0)));
    // 6 and 54 Mb/s OFDM by band.
    assert_eq!(rate(1, 11, 0, 0, 0, Band::Ghz2), Ok(legacy(4)));
    assert_eq!(rate(1, 12, 0, 0, 0, Band::Ghz6), Ok(legacy(7)));
    let ht = rate(2, 15, 1, 1, 1, Band::Ghz5).unwrap();
    assert_eq!(
        (ht.encoding, ht.index, ht.nss, ht.bandwidth, ht.short_gi),
        (Encoding::Ht, 15, 0, Bandwidth::Mhz40, true)
    );
    assert_eq!(rate(3, 32, 0, 0, 0, Band::Ghz5), Err(Error::InvalidRate));
    let vht = rate(4, 9, 1, 2, 0, Band::Ghz5).unwrap();
    assert_eq!(
        (vht.encoding, vht.nss, vht.bandwidth),
        (Encoding::Vht, 2, Bandwidth::Mhz80)
    );
    assert_eq!(rate(4, 12, 0, 0, 0, Band::Ghz5), Err(Error::InvalidRate));
    // Extended-range SU on a 106-tone RU with a 3.2 us GI.
    let he = rate(9, 1 << 5 | 3, 0, 1, 2, Band::Ghz5).unwrap();
    assert_eq!(
        (he.encoding, he.index, he.bandwidth, he.gi, he.short_gi),
        (Encoding::He, 3, Bandwidth::HeRu106, 2, false)
    );
    assert_eq!(rate(8, 7, 0, 3, 3, Band::Ghz6).unwrap().gi, 0);
    let eht = rate(15, 13, 3, 5, 1, Band::Ghz6).unwrap();
    assert_eq!(
        (eht.encoding, eht.index, eht.nss, eht.bandwidth, eht.gi),
        (Encoding::Eht, 13, 4, Bandwidth::Mhz320, 1)
    );
    assert_eq!(rate(5, 0, 0, 0, 0, Band::Ghz5), Err(Error::InvalidRate));
    assert_eq!(rate(1, 11, 0, 6, 0, Band::Ghz5), Err(Error::InvalidRate));
    // A frame whose vector Linux refuses is dropped.
    let mut bytes = packet(Chip::Mt7925, 4, 4, 0, 0);
    put(&mut bytes, 32, 7);
    put(&mut bytes, 32 + 8, 5 << 11);
    assert_eq!(decode(Chip::Mt7925, &bytes).err(), Some(Error::InvalidRate));
    put(&mut bytes, 32 + 8, 4 << 11 | 2);
    let decoded = decode(Chip::Mt7925, &bytes).unwrap();
    assert_eq!(decoded.rate.unwrap().bandwidth, Bandwidth::Mhz80);
    assert_eq!(
        decode(Chip::Mt7921, &packet(Chip::Mt7921, 4, 4, 0, 0))
            .unwrap()
            .rate,
        None
    );
}
#[test]
fn every_short_group_and_padding_boundary_refuses_before_reading() {
    for chip in [Chip::Mt7921, Chip::Mt7925] {
        let bytes = packet(chip, 31, 4, 0, if chip == Chip::Mt7925 { 7 } else { 3 });
        let gap = decode(chip, &bytes).unwrap().header_gap;
        for n in 0..=gap {
            assert!(decode(chip, &bytes[..n]).is_err(), "{chip:?} at {n}");
        }
        assert!(matches!(
            decode(chip, &vec![0; 16385]),
            Err(Error::TooLarge)
        ));
        assert!(matches!(
            decode(chip, &packet(chip, 16, 4, 0, 0)),
            Err(Error::InvalidGroupLayout)
        ));
    }
}
#[test]
fn security_flags_never_synthesize_integrity_key_or_replay_success() {
    for chip in [Chip::Mt7921, Chip::Mt7925] {
        for mode in 0..32 {
            for flags in 0u32..32 {
                let mut bytes = packet(chip, 1, mode, 0, 0);
                let r1 = word(&bytes, 4).unwrap() | ((flags & 15) << 23) | ((flags >> 4) << 31);
                put(&mut bytes, 4, r1);
                let decoded = decode(chip, &bytes).unwrap();
                let decrypted = mode != 0 && flags & 3 == 0;
                assert_eq!(decoded.security.decrypted, decrypted);
                assert_eq!(decoded.security.iv_stripped, decrypted);
                assert_eq!(decoded.security.icv_error, flags & 4 != 0);
                assert_eq!(decoded.only_monitor, flags & 4 != 0);
                assert_eq!(decoded.security.tkip_mic_error, flags & 8 != 0);
                assert_eq!(decoded.security.security_done, flags & 16 != 0);
                assert_eq!(
                    decoded.security.packet_number_be.is_some(),
                    decrypted && matches!(mode, 2 | 3 | 4 | 9 | 10 | 11 | 12)
                );
            }
        }
    }
}
#[test]
fn translated_fragment_and_error_profiles_remain_explicit_and_fcs_is_retained() {
    for chip in [Chip::Mt7921, Chip::Mt7925] {
        for (flag, error) in [
            (23, Error::AmsduError),
            (24, Error::MaximumLengthError),
            (
                if chip == Chip::Mt7925 { 7 } else { 13 },
                Error::UnsupportedTranslation,
            ),
        ] {
            let mut bytes = packet(chip, 0, 0, 0, 0);
            let r2 = word(&bytes, 8).unwrap() | (1 << flag);
            put(&mut bytes, 8, r2);
            assert!(matches!(decode(chip, &bytes), Err(e) if e == error));
        }
        let mut bytes = packet(chip, 0, 0, 0, 0);
        let r2 = word(&bytes, 8).unwrap() | (1 << 27);
        put(&mut bytes, 8, r2);
        assert_eq!(
            decode(chip, &bytes).unwrap().normalize(24),
            Err(Error::UnsupportedFragment)
        );
        let mut bytes = packet(chip, 0, 0, 0, 0);
        let at = if chip == Chip::Mt7925 { 12 } else { 4 };
        let word = word(&bytes, at).unwrap() | (1 << if chip == Chip::Mt7925 { 24 } else { 27 });
        put(&mut bytes, at, word);
        assert!(decode(chip, &bytes).unwrap().fcs_error);
    }
}
#[test]
fn packet_classification_and_channel_encoding_follow_actual_chip_layout_without_wrapping() {
    for chip in [Chip::Mt7921, Chip::Mt7925] {
        for kind in 0..32u32 {
            for flag in [0, 1, 2] {
                let mut bytes = packet(chip, 0, 0, 0, 0);
                put(&mut bytes, 0, kind << 27 | flag << 16);
                let sw = chip == Chip::Mt7925 && (((kind << 11) | flag) & 0x380f) == 0x3801;
                assert_eq!(
                    decode(chip, &bytes).is_ok(),
                    kind == 2 || (kind == 7 && flag == 1) || sw
                );
            }
        }
        for (encoded, band, number) in [
            (0, Band::Ghz2, 0),
            (14, Band::Ghz2, 14),
            (36, Band::Ghz5, 36),
            (180, Band::Ghz5, 180),
            (181, Band::Ghz6, 1),
            (239, Band::Ghz6, 233),
            (255, Band::Ghz6, 297),
        ] {
            let mut bytes = packet(chip, 0, 0, 0, 0);
            put(&mut bytes, 12, u32::from(encoded) << 8);
            assert_eq!(
                decode(chip, &bytes).unwrap().channel,
                Channel {
                    encoded,
                    band,
                    number
                }
            );
        }
    }
}

#[test]
#[ignore = "oracle: STELA_MT792X_RX_ORACLE"]
fn unchanged_full_receive_helpers_match_flags_pn_groups_rcpi_and_normalized_bytes() {
    extern crate std;
    let oracle = std::path::PathBuf::from(
        std::env::var_os("STELA_MT792X_RX_ORACLE").expect("STELA_MT792X_RX_ORACLE"),
    );
    let run = oracle.join(alloc::format!("run-{}", std::process::id()));
    std::fs::create_dir(&run).unwrap();
    for (chip, name, executable) in [
        (Chip::Mt7921, "7921", "rx7921"),
        (Chip::Mt7922, "7922", "rx7921"),
        (Chip::Mt7925, "7925", "rx7925"),
    ] {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        let mut cases = 0;
        for groups in 0..32 {
            if groups & 16 != 0 && groups & 4 == 0 {
                continue;
            }
            for n in 0..128u32 {
                let mode = (n % 13) as u8;
                let format = (n % 4) as u8;
                let offset = (n % if chip == Chip::Mt7925 { 8 } else { 4 }) as u8;
                let mut bytes = packet(chip, groups, mode, format, offset);
                let wcid = n % 20;
                let r1 =
                    word(&bytes, 4).unwrap() & !(if chip == Chip::Mt7925 { 0xfff } else { 0x3ff });
                put(&mut bytes, 4, r1 | wcid | (((n / 4) & 15) << 23));
                let at = if chip == Chip::Mt7925 { 12 } else { 4 };
                let fcs = word(&bytes, at).unwrap()
                    | ((n & 1) << if chip == Chip::Mt7925 { 24 } else { 27 });
                put(&mut bytes, at, fcs);
                let encoded = [1, 14, 36, 180, 181, 239][n as usize % 6];
                let r3 = word(&bytes, 12).unwrap() & !0xff00;
                put(&mut bytes, 12, r3 | (encoded << 8));
                let decoded = decode(chip, &bytes).unwrap();
                let mut flags = u32::from(decoded.only_monitor)
                    | (u32::from(decoded.fcs_error) << 1)
                    | (u32::from(decoded.security.tkip_mic_error) << 2);
                if decoded.security.decrypted {
                    flags |= 8 | 16 | 32 | 64;
                }
                if decoded.timestamp_low.is_some() {
                    flags |= 128;
                    if decoded.ampdu {
                        flags |= 256;
                    }
                }
                let payload = decoded.normalize(24).unwrap();
                let amsdu = decoded.amsdu;
                for value in [
                    flags,
                    (decoded.header_gap + usize::from(amsdu.is_some()) * 2) as u32,
                    decoded.timestamp_low.unwrap_or(0),
                    match decoded.channel.band {
                        Band::Ghz2 => 0,
                        Band::Ghz5 => 1,
                        Band::Ghz6 => 2,
                    },
                    u32::from(decoded.channel.number),
                    wcid,
                    1,
                    u32::from(amsdu.is_some()),
                    u32::from(amsdu.is_some_and(|a| a.first)),
                    u32::from(amsdu.is_some_and(|a| a.last)),
                    payload.len() as u32,
                ] {
                    expected.extend_from_slice(&value.to_le_bytes());
                }
                expected.extend_from_slice(&decoded.security.packet_number_be.unwrap_or([0; 6]));
                expected.extend_from_slice(
                    &decoded
                        .signal
                        .map(|s| s.dbm.map(|v| v as u8))
                        .unwrap_or([0; 4]),
                );
                expected.extend_from_slice(&payload);
                for value in [bytes.len() as u32, 24] {
                    input.extend_from_slice(&value.to_le_bytes());
                }
                input.extend_from_slice(&bytes);
                cases += 1;
            }
        }
        assert_eq!(cases, 3072);
        let input_path = run.join(alloc::format!("mt{name}-inputs.bin"));
        std::fs::write(&input_path, &input).unwrap();
        let result = std::process::Command::new(oracle.join(executable))
            .arg(input_path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{name}: {}",
            std::string::String::from_utf8_lossy(&result.stderr)
        );
        std::fs::write(
            run.join(alloc::format!("mt{name}-output.bin")),
            &result.stdout,
        )
        .unwrap();
        assert_eq!(result.stdout.len(), expected.len());
        for (case, (actual, expected)) in result
            .stdout
            .as_chunks::<118>()
            .0
            .iter()
            .zip(expected.as_chunks::<118>().0.iter())
            .enumerate()
        {
            assert_eq!(actual, expected, "chip {name} case {case}");
        }
    }
}
