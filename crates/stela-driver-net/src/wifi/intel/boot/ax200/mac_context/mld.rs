// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Source MLD initial MAC+inactive link. Neither object can transmit here.
use super::*;
const MAC: Id = Id {
    group: 3,
    opcode: 8,
    version: 0,
};
const LINK: Id = Id {
    group: 3,
    opcode: 9,
    version: 0,
};
const LINK_BYTES: usize = 208;
pub(super) fn prepare<Q: BootIo, B: BiosIo, O: CountryIo>(
    mac: &mut Ax200Mac<'_, Q, B, O>,
) -> Result<(), Ax200MacError> {
    let radio = &mac.country.board.scan.mcc.setup.lari.radio;
    let firmware = &radio.initialized.boot.firmware;
    if !firmware.supports_capability(110) {
        return Err(Ax200MacError::MissingApi(MacCommandKind::Add));
    }
    for (kind, id, default, maximum) in [
        (MacCommandKind::Add, MAC, Some(1), 4),
        (MacCommandKind::AddInactiveLink, LINK, Some(1), 8),
        (MacCommandKind::Power, MAC_POWER, None, 3),
        (MacCommandKind::DisableBeaconFilter, BEACON_FILTER, None, 4),
    ] {
        let version = firmware
            .command_version(id.wire().group, id.opcode)
            .map(|v| v.command_version)
            .or(default)
            .ok_or(Ax200MacError::MissingApi(kind))?;
        if version == 0
            || version > maximum
            || (kind == MacCommandKind::DisableBeaconFilter && version < 3)
        {
            return Err(Ax200MacError::Version { kind, version });
        }
    }
    let filter_v4 = firmware.supports_api(BEACON_FILTER_V4_API);
    let filter_version = firmware
        .command_version(1, BEACON_FILTER.opcode)
        .unwrap()
        .command_version;
    if filter_v4 != (filter_version == 4) {
        return Err(Ax200MacError::Version {
            kind: MacCommandKind::DisableBeaconFilter,
            version: filter_version,
        });
    }
    // Link add/remove calls sf_update. Original exclusive unassociated cold
    // state remains SF_INIT_OFF or API68 offloaded; there is no peer/other vif.
    if radio.phase() != ColdRadioPhase::PlatformConfigurationRequired
        || (!firmware.supports_api(68)
            && !radio
                .prefix_responses()
                .iter()
                .any(|response| response.command == 0xd1 && response.group == 1))
    {
        return Err(Ax200MacError::State);
    }
    let address = mac.initialized_nvm().address.bytes;
    let (mac_version, power_version) = (mac_version(firmware), power_version(firmware));
    let power_mode = mac.country.board.scan.mcc.setup.options.power_mode;
    mac.commands = alloc::vec![
        MacCommand {
            kind: MacCommandKind::Add,
            id: MAC,
            bytes: mac_bytes(mac_version, address, false)
        },
        MacCommand {
            kind: MacCommandKind::DisableBeaconFilter,
            id: BEACON_FILTER,
            bytes: alloc::vec![0;if filter_v4 {60}else{44}]
        },
        MacCommand {
            kind: MacCommandKind::AddInactiveLink,
            id: LINK,
            bytes: link_bytes(address, false)
        },
        MacCommand {
            kind: MacCommandKind::Power,
            id: MAC_POWER,
            bytes: cold_power_bytes(power_version, power_mode)
        }
    ];
    Ok(())
}
fn mac_version(firmware: &Firmware<'_>) -> u8 {
    firmware
        .command_version(MAC.wire().group, MAC.opcode)
        .map_or(1, |version| version.command_version)
}
fn power_version(firmware: &Firmware<'_>) -> u8 {
    firmware
        .command_version(1, MAC_POWER.opcode)
        .map_or(1, |version| version.command_version)
}
pub(super) fn removal<Q: BootIo, B: BiosIo, O: CountryIo>(
    mac: &Ax200Mac<'_, Q, B, O>,
) -> Vec<MacCommand> {
    // Source removes this cold vif's power contribution first. An unactivated
    // link has no phy_ctxt, so disable_link's active-change is a source no-op;
    // the REMOVE remains mandatory, before MAC removal.
    let options = mac.country.board.scan.mcc.setup.options;
    let firmware = &mac
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
    alloc::vec![
        MacCommand {
            kind: MacCommandKind::Power,
            id: MAC_POWER,
            bytes: cold_power_bytes(power_version(firmware), options.power_mode)
        },
        MacCommand {
            kind: MacCommandKind::RemoveInactiveLink,
            id: LINK,
            bytes: link_bytes([0; 6], true)
        },
        MacCommand {
            kind: MacCommandKind::Remove,
            id: MAC,
            bytes: mac_bytes(mac_version(firmware), [0; 6], true)
        }
    ]
}
fn mac_bytes(version: u8, address: [u8; 6], remove: bool) -> Vec<u8> {
    let mut bytes = alloc::vec![0; crate::wifi::intel::association::mac_bytes(version)];
    bytes[4..8].copy_from_slice(&(if remove { ACTION_REMOVE } else { ACTION_ADD }).to_le_bytes());
    if !remove {
        bytes[8..12].copy_from_slice(&MAC_TYPE_BSS_STATION.to_le_bytes());
        bytes[12..18].copy_from_slice(&address);
        bytes[20..24].copy_from_slice(&((1u32 << 2) | (1 << 3)).to_le_bytes());
        // Original HR2 station HE capability table sets MACcap2=0x20, whereas
        // ACK_EN is0x80. iwl_mvm_is_nic_ack_enabled therefore returns false;
        // this receiver capability field is unrelated to authorizing TX ACKs.
        bytes[32..36].copy_from_slice(&1u32.to_le_bytes());
    }
    bytes
}
fn link_bytes(address: [u8; 6], remove: bool) -> Vec<u8> {
    let mut bytes = alloc::vec![0;LINK_BYTES];
    bytes[..4].copy_from_slice(&(if remove { ACTION_REMOVE } else { ACTION_ADD }).to_le_bytes());
    bytes[12..16].fill(255); // Source FW_CTXT_INVALID, never an active PHY.
    if !remove {
        bytes[16..22].copy_from_slice(&address);
    }
    bytes
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_MLD_MAC_TRACE"]
    fn pinned_linux_cold_mld_mac_and_inactive_link_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_MLD_MAC_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "c2366dd18f083df00679d77f0b93b4e21f370854b80dfccfcedbde4f800f5577"
        );
        let mut keys = alloc::collections::BTreeSet::new();
        for line in std::str::from_utf8(&trace).unwrap().lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            assert_eq!(words.len(), 9);
            assert!(keys.insert(words[..6].join(" ")));
            assert_eq!(words[6], "0");
            let mut address = [2, 3, 4, 5, 6, 0];
            address[5] = words[4].parse().unwrap();
            let remove = words[5] == "1";
            let expected: Vec<u8> = words[8]
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let encoded = match words[0] {
                "M" => mac_bytes(3, address, remove),
                "L" => link_bytes(address, remove),
                _ => panic!("source record"),
            };
            assert_eq!(encoded.len(), words[7].parse::<usize>().unwrap());
            assert_eq!(encoded, expected, "{line}");
        }
        assert_eq!(keys.len(), 144);
        assert_eq!(
            MAC,
            Id {
                group: 3,
                opcode: 8,
                version: 0
            }
        );
        assert_eq!(
            LINK,
            Id {
                group: 3,
                opcode: 9,
                version: 0
            }
        );
    }
}
