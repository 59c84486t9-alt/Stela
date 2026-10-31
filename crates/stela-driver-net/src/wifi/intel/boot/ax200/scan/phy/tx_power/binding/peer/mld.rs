// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2015, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Selected MLD single-link peer with only legacy rates and no TX queue.
use super::*;

pub(super) fn prepare<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy>(
    owner: &mut Ax200LegacyPeer<'_, Q, B, O>,
) -> Result<(), Ax200LegacyPeerError> {
    let power = &owner.binding.power;
    let firmware = &power
        .phy
        .scan
        .mac
        .country
        .board
        .scan
        .mcc
        .setup
        .lari
        .radio
        .initialized
        .boot
        .firmware;
    if !owner.binding.mld
        || !power.phy.scan.mac.is_mld()
        || !firmware.supports_capability(110)
        || firmware.supports_capability(40)
        || !firmware.supports_capability(43)
    {
        return Err(Ax200LegacyPeerError::MissingApi);
    }
    // Original MLD send_sta_cmd explicitly defaults an unlisted STA_CONFIG to
    // version 0 and then uses v1 for <=1. Only the v1, v2 and v3 bodies are
    // implemented; a future advertised body cannot silently use this prefix.
    let version = firmware
        .command_version(3, 0x0a)
        .map_or(0, |v| v.command_version);
    if version > 3 {
        return Err(Ax200LegacyPeerError::Version {
            group: 3,
            command: 0x0a,
            version,
        });
    }
    if let Some(version) = firmware.command_version(3, 0x0c)
        && version.command_version != 1
    {
        return Err(Ax200LegacyPeerError::Version {
            group: 3,
            command: 0x0c,
            version: version.command_version,
        });
    }
    for (group, command, valid) in [(1, 0x1e, 2..=2), (5, 0x0f, 1..=6)] {
        let version = firmware
            .command_version(group, command)
            .ok_or(Ax200LegacyPeerError::MissingApi)?;
        if !valid.contains(&version.command_version)
            || !(if command == 0x1e {
                version.notification_version <= 1
            } else {
                version.notification_version == 0
            })
        {
            return Err(Ax200LegacyPeerError::Version {
                group,
                command,
                version: version.command_version,
            });
        }
    }
    let allowed = match power.channel().band {
        Band::Ghz2 => 0xfff,
        Band::Ghz5 | Band::Ghz6 => 0xff0,
    };
    if owner.peer.address.0 == [0; 6]
        || owner.peer.address.is_multicast()
        || owner.peer.beacon_interval_tu < 16
        || owner.peer.rates == 0
        || owner.peer.rates & !allowed != 0
    {
        return Err(Ax200LegacyPeerError::Peer);
    }
    let nvm = &power.phy.scan.mac.initialized_nvm().information;
    let mut antennas =
        ((firmware.phy_sku().ok_or(Ax200LegacyPeerError::MissingApi)? >> 16) & 15) as u8;
    if nvm.tx_chains as u8 != 0 {
        antennas &= nvm.tx_chains as u8;
    }
    if antennas == 0 || antennas & !3 != 0 {
        return Err(Ax200LegacyPeerError::Peer);
    }
    owner.flush_notification = firmware
        .command_version(1, 0x1e)
        .unwrap()
        .notification_version;
    let station = station(
        owner.peer.address,
        version,
        firmware.supports_capability(114),
    );
    // Full original mld_add_sta invokes mld_update_sta (CFG), then its active
    // link loop invokes CFG again. The common NOTEXIST -> NONE callback then
    // requires TLC legacy-rate initialization. All three get real ACK/reclaim.
    owner.commands = alloc::vec![
        PeerCommand {
            kind: PeerCommandKind::Add,
            id: Id {
                group: 3,
                opcode: 0x0a,
                version: 0
            },
            bytes: station.clone(),
        },
        PeerCommand {
            kind: PeerCommandKind::Configure,
            id: Id {
                group: 3,
                opcode: 0x0a,
                version: 0
            },
            bytes: station,
        },
        PeerCommand {
            kind: PeerCommandKind::Rates,
            id: Id {
                group: 5,
                opcode: 0x0f,
                version: 0
            },
            bytes: rates(firmware, owner.peer.rates, antennas)?,
        },
    ];
    Ok(())
}

pub(super) fn removal() -> [PeerCommand; 2] {
    [
        PeerCommand {
            kind: PeerCommandKind::Flush,
            id: Id {
                group: 0,
                opcode: 0x1e,
                version: 0,
            },
            bytes: alloc::vec![0, 0, 0, 0, 255, 255, 0, 0],
        },
        PeerCommand {
            kind: PeerCommandKind::Remove,
            id: Id {
                group: 3,
                opcode: 0x0c,
                version: 0,
            },
            bytes: alloc::vec![0;4],
        },
    ]
}

fn station(address: Mac, version: u8, mfp: bool) -> Vec<u8> {
    let mut bytes = alloc::vec![0; crate::wifi::intel::association::station_bytes(version)];
    // Source station0 on link0, STATION_TYPE_PEER=0, unassociated AID0.
    if version >= 3 {
        bytes[4] = 1;
    }
    bytes[8..14].copy_from_slice(&address.0);
    bytes[16..22].copy_from_slice(&address.0);
    bytes[36..40].copy_from_slice(&u32::from(mfp).to_le_bytes());
    // The exact legacy-only peer has NSS1/SMPS_OFF, no QoS/HT/VHT/HE/EHT or BA.
    // get_sta_ampdu_dens therefore returns density0/size0; all autonomous modern
    // fields stay source-zero. No session/key or transmit queue is installed.
    bytes
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_MLD_PEER_TRACE"]
    fn pinned_linux_mld_station_tlc_and_no_queue_removal_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_MLD_PEER_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "adbd5c1d17c86507c9669d44fd58311b1a7321715c3287dbfefead3ddf24a6f7"
        );
        let mut keys = alloc::collections::BTreeSet::new();
        for line in std::str::from_utf8(&trace).unwrap().lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            assert!(keys.insert(words[..words.len() - 1].join(" ")));
            let expected: Vec<_> = words
                .last()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect();
            let number = |i: usize| words[i].parse::<i32>().unwrap();
            let bytes = match words[0] {
                "S" => {
                    assert_eq!(words.len(), 7);
                    assert_eq!(number(4), if number(3) == 0 { 0 } else { -5 });
                    station(Mac([2, 3, 4, 5, 6, 7]), number(1) as u8, number(2) != 0)
                }
                "T" => {
                    assert_eq!(words.len(), 7);
                    let mut image = alloc::vec![0;88];
                    image[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
                    image[72..76].copy_from_slice(&0x4d00u32.to_le_bytes());
                    image.extend(48u32.to_le_bytes());
                    image.extend(4u32.to_le_bytes());
                    image.extend([15, 5, number(1) as u8, 0]);
                    rates(
                        &Firmware::parse(&image).unwrap(),
                        number(4) as u16,
                        number(2) as u8,
                    )
                    .unwrap()
                }
                "F" => {
                    assert_eq!(words.len(), 5);
                    assert_eq!(number(2), 0);
                    removal()[0].bytes.clone()
                }
                "R" => {
                    assert_eq!(words.len(), 5);
                    assert_eq!(number(2), if number(1) == 0 { 0 } else { -5 });
                    removal()[1].bytes.clone()
                }
                _ => panic!("source row"),
            };
            assert_eq!(bytes.len(), number(words.len() - 2) as usize);
            assert_eq!(bytes, expected, "{line}");
        }
        assert_eq!(keys.len(), 88);
    }
}
