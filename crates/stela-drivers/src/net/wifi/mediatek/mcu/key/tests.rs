extern crate std;
use super::*;
use crate::net::{
    Mac,
    wifi::security::{InstallOutcome, KeySlot, PacketNumber, ReplaySeed, TransmitSeed},
};
fn ticket(
    slot: u16,
    scope: KeyScope,
    cipher: Cipher,
    material: &[u8],
    transmit: TransmitSeed,
) -> (KeySlot, InstallTicket) {
    // SAFETY: fresh independent software model of one empty native slot.
    let mut key = unsafe { KeySlot::new(slot) }.unwrap();
    let ticket = key
        .begin_install(
            if matches!(scope, KeyScope::Pairwise(_)) {
                0
            } else {
                2
            },
            cipher,
            material,
            ReplaySeed::uniform(PacketNumber::new(123).unwrap()),
            scope,
            transmit,
        )
        .unwrap();
    (key, ticket)
}
#[test]
fn tkip_swaps_its_michael_keys_like_mt76_connac_mcu_sta_key_tlv() {
    let context = Context {
        bss_index: 2,
        omac_index: 3,
        station_disabled: false,
    };
    let material: Vec<u8> = (0..32).collect();
    let swapped = [&material[..16], &material[24..], &material[16..24]].concat();
    for (chip, cipher_at, cipher, key_at) in [(Chip::Mt7921, 16, 4, 20), (Chip::Mt7925, 23, 2, 28)]
    {
        let scope = KeyScope::Pairwise(Mac([2, 1, 2, 3, 4, 5]));
        let (_slot, ticket) = ticket(
            7,
            scope,
            Cipher::Tkip,
            &material,
            TransmitSeed::FIRMWARE_FRESH,
        );
        let request = Request::install(chip, context, ticket, &material).unwrap();
        assert_eq!(request.bytes()[cipher_at], cipher);
        assert_eq!(&request.bytes()[key_at..key_at + 32], &swapped[..]);
    }
}
#[test]
fn wep_keys_take_the_stationless_form_like_mt7925_set_link_key() {
    let context = Context {
        bss_index: 2,
        omac_index: 3,
        station_disabled: false,
    };
    let scope = KeyScope::Pairwise(Mac([2, 1, 2, 3, 4, 5]));
    for (material, connac3, connac2) in [(&[7u8; 5][..], 1, 1), (&[7; 13], 5, 2)] {
        let cipher = if material.len() == 5 {
            Cipher::Wep40
        } else {
            Cipher::Wep104
        };
        // SAFETY: fresh independent software model of one empty native slot.
        let mut slot = unsafe { KeySlot::new(7) }.unwrap();
        let ticket = slot
            .begin_install(
                3,
                cipher,
                material,
                ReplaySeed::ZERO,
                scope,
                TransmitSeed::FIRMWARE_FRESH,
            )
            .unwrap();
        let v3 = Request::install(Chip::Mt7925, context, ticket, material).unwrap();
        let b = v3.bytes();
        assert_eq!((b[5], b[13], b[14]), (3, 0, 0));
        assert_eq!(
            (b[23], b[24], usize::from(b[25])),
            (connac3, 3, material.len())
        );
        assert_eq!(&b[28..28 + material.len()], material);
        let v2 = Request::install(Chip::Mt7921, context, ticket, material).unwrap();
        assert_eq!((v2.bytes()[16], v2.bytes()[18]), (connac2, 3));
    }
}
#[test]
fn exact_per_chip_key_fields_keep_canonical_identity_scope_and_receive_floors() {
    let context = Context {
        bss_index: 2,
        omac_index: 3,
        station_disabled: false,
    };
    for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
        for scope in [
            KeyScope::Pairwise(Mac([2, 1, 2, 3, 4, 5])),
            KeyScope::Group(Mac([2, 6, 7, 8, 9, 10])),
        ] {
            for cipher in [
                Cipher::Ccmp128,
                Cipher::Ccmp256,
                Cipher::Gcmp128,
                Cipher::Gcmp256,
            ] {
                let length = if matches!(cipher, Cipher::Ccmp128 | Cipher::Gcmp128) {
                    16
                } else {
                    32
                };
                let material: Vec<_> = (0..length as u8).collect();
                let tx = if matches!(scope, KeyScope::Pairwise(_)) {
                    TransmitSeed::FIRMWARE_FRESH
                } else {
                    TransmitSeed::RECEIVE_ONLY
                };
                let (mut slot, ticket) = ticket(7, scope, cipher, &material, tx);
                let request = Request::install(chip, context, ticket, &material).unwrap();
                assert_eq!(request.key(), ticket.identity());
                assert_eq!(
                    &request.bytes()[..8],
                    &[
                        2,
                        7,
                        1,
                        0,
                        1,
                        if matches!(scope, KeyScope::Pairwise(_)) {
                            3
                        } else {
                            14
                        },
                        0,
                        0
                    ]
                );
                if chip == Chip::Mt7925 {
                    assert_eq!(request.bytes().len(), 76);
                    assert_eq!(&request.bytes()[8..13], &[0x27, 0, 68, 0, 1]);
                    assert_eq!(&request.bytes()[16..22], &scope.peer().0);
                    assert_eq!(&request.bytes()[28..28 + length], material);
                    assert_eq!(&request.bytes()[60..76], &[0; 16]);
                } else {
                    assert_eq!(request.bytes().len(), 88);
                    assert_eq!(&request.bytes()[8..14], &[17, 0, 44, 0, 0, 1]);
                    assert_eq!(&request.bytes()[20..20 + length], material);
                    assert_eq!(&request.bytes()[52..88], &[0; 36]);
                }
                assert!(slot.installed().is_none()); // wire construction is not ACK
                assert_eq!(ticket.receive_seed().counters(), [123; 17]);
                slot.complete_install(ticket, InstallOutcome::Accepted)
                    .unwrap();
                let remove = Request::remove(chip, context, slot.installed().unwrap()).unwrap();
                assert_eq!(remove.key(), request.key());
                if chip == Chip::Mt7925 {
                    assert_eq!(remove.bytes()[12], 0);
                    assert_eq!(&remove.bytes()[28..], &[0; 48]);
                } else {
                    assert_eq!(&remove.bytes()[10..14], &[8, 0, 1, 0]);
                    assert_eq!(&remove.bytes()[16..], &[0; 72]);
                }
            }
        }
    }
}
#[test]
fn incompatible_transmit_policy_and_wire_bounds_refuse_without_key_programming() {
    let peer = KeyScope::Pairwise(Mac([2, 1, 2, 3, 4, 5]));
    let context = Context {
        bss_index: 0,
        omac_index: 0,
        station_disabled: false,
    };
    for tx in [
        TransmitSeed::host(PacketNumber::new(0).unwrap()),
        TransmitSeed::RECEIVE_ONLY,
    ] {
        let (_, ticket) = ticket(7, peer, Cipher::Ccmp128, &[1; 16], tx);
        assert!(matches!(
            Request::install(Chip::Mt7925, context, ticket, &[1; 16]),
            Err(Error::UnsupportedTransmitState)
        ));
    }
    let (_, ticket) = ticket(
        7,
        peer,
        Cipher::Ccmp128,
        &[1; 16],
        TransmitSeed::FIRMWARE_FRESH,
    );
    for n in [0, 15, 17, 32, 33] {
        assert!(matches!(
            Request::install(Chip::Mt7925, context, ticket, &vec![0; n]),
            Err(Error::InvalidKeyLength)
        ));
    }
    assert!(matches!(
        Request::install(
            Chip::Mt7925,
            Context {
                omac_index: 64,
                ..context
            },
            ticket,
            &[1; 16]
        ),
        Err(Error::InvalidOmac)
    ));
    let (_, ticket) = self::ticket(
        20,
        peer,
        Cipher::Ccmp128,
        &[1; 16],
        TransmitSeed::FIRMWARE_FRESH,
    );
    assert!(matches!(
        Request::install(Chip::Mt7925, context, ticket, &[1; 16]),
        Err(Error::InvalidWcid)
    ));
}
#[test]
#[ignore = "oracle: STELA_MT792X_KEY_ORACLE"]
fn unchanged_pinned_key_helpers_match_complete_station_requests() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("STELA_MT792X_KEY_ORACLE").expect("key oracle directory"),
    );
    for (chip, name) in [
        (Chip::Mt7921, "7921"),
        (Chip::Mt7922, "7922"),
        (Chip::Mt7925, "7925"),
    ] {
        let trace = std::fs::read(directory.join(alloc::format!("{name}.trace"))).unwrap();
        let mut cursor = 0;
        for i in 0..320usize {
            let cipher = [
                Cipher::Ccmp128,
                Cipher::Ccmp256,
                Cipher::Gcmp128,
                Cipher::Gcmp256,
            ][i % 4];
            let pairwise = (i / 4) % 2 != 0;
            let remove = (i / 16) % 2 != 0;
            let mut peer = core::array::from_fn(|j| (2 + i * 7 + j) as u8);
            peer[0] &= 0xfe;
            let scope = if pairwise {
                KeyScope::Pairwise(Mac(peer))
            } else {
                KeyScope::Group(Mac(peer))
            };
            let context = Context {
                bss_index: (i * 13) as u8,
                omac_index: ((i * 7) % 64) as u8,
                station_disabled: (i / 8) % 2 != 0,
            };
            let n = if i % 4 == 0 || i % 4 == 2 { 16 } else { 32 };
            let material: Vec<_> = (0..n).map(|j| (i * 17 + j) as u8).collect();
            // SAFETY: independent empty/drained modeled WCID, no hardware users.
            let mut slot = unsafe { KeySlot::new(((i * 3) % 20) as u16) }.unwrap();
            let ticket = slot
                .begin_install(
                    if pairwise {
                        0
                    } else {
                        (1 + (i / 32) % 3) as u8
                    },
                    cipher,
                    &material,
                    ReplaySeed::ZERO,
                    scope,
                    if pairwise {
                        TransmitSeed::FIRMWARE_FRESH
                    } else {
                        TransmitSeed::RECEIVE_ONLY
                    },
                )
                .unwrap();
            let request = if remove {
                Request::remove(chip, context, ticket.identity())
            } else {
                Request::install(chip, context, ticket, &material)
            }
            .unwrap();
            let header = &trace[cursor..cursor + 4];
            assert_eq!(
                header[..3],
                [(i % 4) as u8, u8::from(pairwise), u8::from(remove)]
            );
            let length = usize::from(header[3]);
            cursor += 4;
            assert_eq!(
                request.bytes(),
                &trace[cursor..cursor + length],
                "chip {name} case {i}"
            );
            cursor += length;
            assert!(slot.installed().is_none());
        }
        assert_eq!(cursor, trace.len());
    }
}
