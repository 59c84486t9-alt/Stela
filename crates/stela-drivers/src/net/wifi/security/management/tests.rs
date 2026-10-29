use super::*;
use crate::net::{
    Mac,
    wifi::{
        Band, RadioStatus, RawRate,
        security::{Cipher, InstallOutcome, KeySlot, ReplaySeed, SecurityStatus, TransmitSeed},
    },
};
use alloc::{vec, vec::Vec};
use sha2::{Digest, Sha256};

fn gtk() -> KeyIdentity {
    // SAFETY: independent pure protocol oracle, no hardware namespace/users.
    let mut slot = unsafe { KeySlot::new(7) }.unwrap();
    let ticket = slot
        .begin_install(
            2,
            Cipher::Ccmp128,
            &[0x44; 16],
            ReplaySeed::ZERO,
            KeyScope::Group(Mac([2, 6, 7, 8, 9, 10])),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    slot.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    slot.installed().unwrap()
}
fn packet(bytes: Vec<u8>) -> frame::Mpdu {
    frame::Mpdu::new(
        bytes,
        RadioStatus {
            band: Band::Ghz5,
            channel: 36,
            frequency_mhz: 5180,
            signal_dbm: Some(-40),
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 0,
                words: [0; 4],
            },
            rx_rate: None,
            tsf: None,
        },
        SecurityStatus::default(),
    )
    .unwrap()
}
fn mic(key: &Cmac, bytes: &[u8]) -> [u8; 16] {
    let mut aad = [0; 20];
    let fc = u16::from_le_bytes(bytes[..2].try_into().unwrap());
    aad[..2].copy_from_slice(&(fc & !AAD_MASK).to_le_bytes());
    aad[2..].copy_from_slice(&bytes[4..22]);
    let mut s = key.start();
    s.update(&aad);
    s.update(&bytes[24..bytes.len() - 8]);
    s.update(&[0; 8]);
    s.finish()
}
fn source_frame(i: usize, pn: u64) -> Vec<u8> {
    let body = if i % 3 == 2 { 6 + i % 61 } else { 2 + i % 65 };
    let mut bytes = vec![0; 24 + body + 18];
    let fc = (match i % 3 {
        0 => 0x00c0,
        1 => 0x00a0,
        _ => 0x00d0,
    }) | (((i / 3) % 8) as u16) << 11;
    bytes[..2].copy_from_slice(&fc.to_le_bytes());
    bytes[4..10].fill(0xff);
    bytes[10..16].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
    bytes[16..22].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
    bytes[22..24].copy_from_slice(&((i as u16) << 4).to_le_bytes());
    for j in 0..body {
        bytes[24 + j] = (i * 31 + j) as u8;
    }
    bytes[24] = if i % 3 == 2 { 3 } else { 7 };
    bytes[25] = if i % 3 == 2 { 2 } else { 0 };
    let mmie = &mut bytes[24 + body..];
    mmie[0] = 76;
    mmie[1] = 16;
    mmie[2] = 4 + (i % 2) as u8;
    mmie[4..10].copy_from_slice(&pn.to_le_bytes()[..6]);
    let end = bytes.len();
    let digest = mic(&Cmac::new(&[0x55; 16]).unwrap(), &bytes);
    bytes[end - 8..].copy_from_slice(&digest[..8]);
    bytes
}

#[test]
fn cmac_and_full_bip_mac_trace_match_complete_unchanged_source_helpers() {
    let key = Cmac::new(&[
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ])
    .unwrap();
    assert_eq!(
        key.start().finish(),
        [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46
        ]
    );
    let mut hash = Sha256::new();
    // 384 exact unchanged source CMAC/AAD/IPN helper cases.
    for i in 0usize..384 {
        let body = i % 131;
        let len = 24 + body + 18;
        let mut bytes = vec![0; len];
        let raw: [u8; 16] = core::array::from_fn(|j| (i * 17 + j) as u8);
        let fc = (match i % 3 {
            0 => 0xc0,
            1 => 0xa0,
            _ => 0xd0,
        }) | ((((i / 3) % 8) as u16) * 0x800);
        bytes[..2].copy_from_slice(&fc.to_le_bytes());
        for (j, b) in bytes.iter_mut().enumerate().take(24).skip(4) {
            *b = (i * 7 + j) as u8;
        }
        for j in 0..body {
            bytes[24 + j] = (i * 31 + j) as u8;
        }
        let pn = (i as u64) * 1_000_003 + 1;
        let mmie = &mut bytes[24 + body..];
        mmie[0] = 76;
        mmie[1] = 16;
        mmie[2] = 4 + (i % 2) as u8;
        mmie[4..10].copy_from_slice(&pn.to_le_bytes()[..6]);
        let digest = mic(&Cmac::new(&raw).unwrap(), &bytes);
        bytes[len - 8..].copy_from_slice(&digest[..8]);
        let mut aad = [0; 20];
        aad[..2].copy_from_slice(&(fc & !AAD_MASK).to_le_bytes());
        aad[2..].copy_from_slice(&bytes[4..22]);
        hash.update([i as u8, (i >> 8) as u8, len as u8, (len >> 8) as u8]);
        hash.update(&bytes);
        hash.update(aad);
        hash.update(&pn.to_be_bytes()[2..]);
    }
    assert_eq!(
        alloc::format!("{:x}", hash.finalize()),
        "cdae6f4d1a3567411307def1dd1fe55222d8d7d43f6adfa98165614e8487aa64"
    );
}

#[test]
fn bip_cmac256_and_gmac_match_independent_aes_vectors() {
    let gtk = gtk();
    for (cipher, mic) in [
        (
            ManagementCipher::Cmac256,
            [
                0x6b, 0x23, 0xeb, 0x1d, 0x5c, 0xba, 0x9a, 0x1f, 0xd9, 0xa7, 0x95, 0xd8, 0xb6, 0x29,
                0x55, 0x14,
            ],
        ),
        (
            ManagementCipher::Gmac128,
            [
                0xed, 0x8b, 0x43, 0xa6, 0xc3, 0xa3, 0x04, 0x13, 0x6e, 0xa5, 0x3e, 0x3f, 0x60, 0x23,
                0xf2, 0x3b,
            ],
        ),
        (
            ManagementCipher::Gmac256,
            [
                0x56, 0xf8, 0x6b, 0x82, 0x6a, 0x7b, 0xc6, 0xc9, 0x69, 0x5d, 0xf6, 0xf6, 0xa0, 0xe0,
                0x30, 0x9b,
            ],
        ),
    ] {
        // A deauthentication with a 26-byte MMIE, tags from Python
        // cryptography's CMAC and AESGCM.
        let mut bytes = vec![0; 24];
        bytes[0] = 0xc0;
        bytes[4..10].fill(0xff);
        bytes[10..16].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
        bytes[16..22].copy_from_slice(&[2, 6, 7, 8, 9, 10]);
        bytes.extend_from_slice(&[7, 0, 76, 24, 4, 0, 101, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&mic);
        let material = vec![0x55; cipher.key_length()];
        let mut key =
            BipKey::new(gtk, cipher, 4, &material, PacketNumber::new(100).unwrap()).unwrap();
        let mut forged = bytes.clone();
        forged[25] ^= 1;
        assert_eq!(
            key.authenticate(&packet(forged)).err(),
            Some(Error::Integrity)
        );
        let short = bytes[..bytes.len() - 8].to_vec();
        assert_eq!(key.authenticate(&packet(short)).err(), Some(Error::BadMmie));
        let frame = packet(bytes);
        let accepted = key.authenticate(&frame).unwrap();
        assert_eq!(accepted.body(), &[7, 0]);
        assert_eq!(accepted.packet_number().value(), 101);
    }
}

#[test]
fn all_source_robust_categories_and_protected_action_rules_match() {
    let mut hash = Sha256::new();
    for kind in [0x00c0u16, 0x00a0, 0x00d0, 0x0080, 0x00b0, 0x0008] {
        for protected in [false, true] {
            for category in 0..=255u8 {
                let mut bytes = vec![0; 25];
                let fc = kind | if protected { 0x4000 } else { 0 };
                bytes[..2].copy_from_slice(&fc.to_le_bytes());
                bytes[24] = category;
                hash.update([u8::from(robust(&packet(bytes)))]);
            }
        }
    }
    assert_eq!(
        alloc::format!("{:x}", hash.finalize()),
        "838da38c54f8be0a3fed285b0890f1d04b9196a966c1f47f4407e92f9cab94de"
    );
}

#[test]
fn complete_source_key_selection_decrypt_replay_mic_and_counter_effects_match() {
    let parent = gtk();
    let mut hash = Sha256::new();
    let mut count = 0;
    for i in 0usize..128 {
        for (f, seed) in [0u64, 1, 100, 0xffff_ffff_fffe, 0xffff_ffff_ffff]
            .into_iter()
            .enumerate()
        {
            for (p, pn) in [0u64, 1, 2, 101, 0xffff_ffff_fffe, 0xffff_ffff_ffff]
                .into_iter()
                .enumerate()
            {
                for mode in 0..7 {
                    let mut bytes = source_frame(i, pn);
                    let end = bytes.len();
                    match mode {
                        1 => bytes[end - 1] ^= 1,
                        2 => bytes[end - 18] ^= 1,
                        3 => bytes[end - 17] ^= 1,
                        4 => bytes[end - 16] ^= 1,
                        5 => bytes[24] ^= 1,
                        _ => {}
                    }
                    let mut frame = packet(bytes);
                    if mode == 6 {
                        frame.security.decrypted = true;
                        frame.security.integrity = super::super::Integrity::Verified;
                    }
                    let mut key = BipKey::new(
                        parent,
                        ManagementCipher::Cmac128,
                        4 + (i % 2) as u8,
                        &[0x55; 16],
                        PacketNumber::new(seed).unwrap(),
                    )
                    .unwrap();
                    key.statistics = Statistics {
                        replays: if i % 7 == 0 { u32::MAX } else { 0 },
                        mic_failures: if i % 11 == 0 { u32::MAX } else { 0 },
                    };
                    let result = key.authenticate(&frame);
                    let accepted = result.is_ok();
                    let after_len = result.as_ref().map_or(end, |a| a.end);
                    hash.update([i as u8, f as u8, p as u8, mode, u8::from(accepted)]);
                    hash.update(&key.receive_floor().value().to_be_bytes()[2..]);
                    hash.update(key.statistics().replays.to_le_bytes());
                    hash.update(key.statistics().mic_failures.to_le_bytes());
                    hash.update((after_len as u16).to_le_bytes());
                    hash.update(&frame.bytes()[..after_len]);
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 26_880);
    assert_eq!(
        alloc::format!("{:x}", hash.finalize()),
        "30699480f6d259480befb7b1d73ade37cbc2df73d11df92eac0a485bb19c4c31"
    );
}

#[test]
fn bad_peer_mmie_fragment_aggregate_or_receive_evidence_never_consumes_ipn() {
    let gtk = gtk();
    for fault in 0..16 {
        let mut bytes = source_frame(0, 101);
        let expected = match fault {
            0 => {
                bytes[4] &= !1;
                Error::WrongPeer
            }
            1 => {
                bytes[10] ^= 2;
                Error::WrongPeer
            }
            2 => {
                bytes[16] ^= 2;
                Error::WrongPeer
            }
            3 => {
                bytes[28] ^= 1;
                Error::WrongKey
            }
            4 => {
                bytes[26] ^= 1;
                Error::BadMmie
            }
            5 => {
                bytes[27] ^= 1;
                Error::BadMmie
            }
            6 => {
                bytes[1] |= 0x40;
                Error::InvalidFrame
            }
            7 => {
                bytes[22] |= 1;
                Error::InvalidFrame
            }
            8 => {
                bytes[1] |= 1;
                Error::InvalidFrame
            }
            9 => {
                bytes[1] |= 0x80;
                Error::InvalidFrame
            }
            10 => {
                bytes.truncate(41);
                Error::BadMmie
            }
            15 => Error::InvalidFrame,
            _ => Error::Integrity,
        };
        let mut frame = packet(bytes);
        match fault {
            11 => frame.fcs_error = true,
            12 => frame.monitor_only = true,
            13 => frame.security.icv_error = true,
            14 => {
                frame.security.hardware_replay =
                    super::super::HardwareReplay::Failed { layout: 0x7925 }
            }
            15 => frame.aggregation.ampdu = Some(7),
            _ => {}
        }
        let mut key = BipKey::new(
            gtk,
            ManagementCipher::Cmac128,
            4,
            &[0x55; 16],
            PacketNumber::new(100).unwrap(),
        )
        .unwrap();
        assert!(
            matches!(key.authenticate(&frame),Err(e) if e==expected),
            "fault {fault}"
        );
        assert_eq!(key.receive_floor().value(), 100);
        assert_eq!(key.statistics(), Statistics::default());
        let original = packet(source_frame(0, 101));
        let accepted = key.authenticate(&original).unwrap();
        assert_eq!(accepted.packet_number().value(), 101);
        assert_eq!(accepted.body(), &[7, 0]);
    }
}
