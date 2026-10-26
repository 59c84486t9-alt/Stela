// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Original single non-MLO link0 assignment/activation and unassignment.
use super::*;
const LINK: Id = Id {
    group: 3,
    opcode: 9,
    version: 0,
};
pub(super) fn prepare<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy>(
    binding: &mut Ax200Binding<'_, Q, B, O>,
) -> Result<(), Ax200BindingError> {
    let mac = &binding.power.phy.scan.mac;
    if !mac.is_mld()
        || mac.inactive_link_id() != Some(0)
        || mac.phase() != Ax200MacPhase::ScanRequired
    {
        return Err(Ax200BindingError::State);
    }
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
    if !firmware.supports_capability(110) {
        return Err(Ax200BindingError::MissingApi);
    }
    // Original LINK_CONFIG lookup explicitly defaults to1 for unlisted API.
    let version = firmware
        .command_version(3, 9)
        .map_or(1, |v| v.command_version);
    if !(1..=8).contains(&version) {
        return Err(Ax200BindingError::Version {
            command: 9,
            version,
        });
    }
    if binding.power.channel().band == Band::Ghz6 {
        return Err(Ax200BindingError::State);
    }
    let address = mac.initialized_nvm().address.bytes;
    let power = mac
        .commands()
        .iter()
        .find(|command| command.kind() == MacCommandKind::Power)
        .ok_or(Ax200BindingError::State)?;
    binding.commands = alloc::vec![
        BindingCommand {
            kind: BindingCommandKind::AttachPhy,
            id: LINK,
            bytes: encode(address, 0, false)
        },
        BindingCommand {
            kind: BindingCommandKind::ActivateLink,
            id: LINK,
            bytes: encode(address, 3, true)
        },
        BindingCommand {
            kind: BindingCommandKind::Power,
            id: power.id(),
            bytes: power.bytes().to_vec()
        }
    ];
    // Original AP_TX_POWER_CONSTRAINTS helper returns without a command for
    // every 2.4/5 GHz link; this profile never admits 6 GHz. Cold power remains
    // source cfg.ps=false, no DTIM/peer/BF or other vif/device-PS transition.
    Ok(())
}
pub(super) fn removal<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy>(
    binding: &Ax200Binding<'_, Q, B, O>,
) -> Result<Vec<BindingCommand>, Ax200BindingError> {
    let address = binding.power.phy.scan.mac.initialized_nvm().address.bytes;
    let power = binding
        .commands
        .iter()
        .find(|command| command.kind == BindingCommandKind::Power)
        .ok_or(Ax200BindingError::State)?;
    let original = binding
        .power
        .phy
        .scan
        .mac
        .commands()
        .iter()
        .find(|command| command.kind() == MacCommandKind::AddInactiveLink)
        .ok_or(Ax200BindingError::State)?;
    let remove = remove_link_bytes(original.bytes().len());
    // Original stop_session_protection sees the untouched cold TE_MAX set by
    // mac_ctxt_init. Both SESSION_PROT_CMD branches return before any command:
    // TE_MAX differs from SESSION_PROTECT_CONF_ASSOC and
    // TE_BSS_STA_AGGRESSIVE_ASSOC. This owner never starts a session or peer.
    // The actual public unassign callback also removes/re-adds the link when
    // there is no peer/association. That resets FW state to PHY_INVALID before
    // the shared remove_chanctx callback may unref/REMOVE the unique PHY0.
    // No parent ownership escapes until all four real ACK/reclaims complete.
    Ok(alloc::vec![
        BindingCommand {
            kind: BindingCommandKind::DeactivateLink,
            id: LINK,
            bytes: encode(address, 1, false)
        },
        power.clone(),
        BindingCommand {
            kind: BindingCommandKind::RemoveLink,
            id: LINK,
            bytes: remove
        },
        BindingCommand {
            kind: BindingCommandKind::RestoreInactiveLink,
            id: LINK,
            bytes: original.bytes().to_vec()
        }
    ])
}
fn remove_link_bytes(length: usize) -> Vec<u8> {
    let mut bytes = alloc::vec![0;length];
    bytes[..4].copy_from_slice(&3u32.to_le_bytes());
    bytes[12..16].fill(255);
    bytes
}
fn encode(address: [u8; 6], changes: u32, active: bool) -> Vec<u8> {
    let mut bytes = alloc::vec![0;208];
    bytes[..4].copy_from_slice(&2u32.to_le_bytes()); // original MODIFY
    // Actual link0/mac0/PHY0, source listen_lmac0. This source non-MLO legacy
    // 20 MHz station has no BSS/HT/HE/EHT/DTIM/QoS negotiation or session yet.
    bytes[16..22].copy_from_slice(&address);
    bytes[24..28].copy_from_slice(&changes.to_le_bytes());
    bytes[28..32].copy_from_slice(&u32::from(active).to_le_bytes());
    bytes[36..40].copy_from_slice(&0xfu32.to_le_bytes());
    bytes[40..44].copy_from_slice(&0x15u32.to_le_bytes());
    for ac in 0..4 {
        bytes[60 + ac * 8 + 5] = 1 << (ac + 1);
    }
    bytes
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    #[ignore = "requires unchanged pinned Linux MLD active-link and full unassign trace"]
    fn pinned_linux_mld_link_activation_unassign_reset_and_phy_reference_bytes() {
        use sha2::{Digest, Sha256};
        let trace = std::fs::read(std::env::var("STELA_IWLWIFI_MLD_LINK_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&trace)),
            "a04246c40a6d805d7a8c165b0f5952845ce6cc99a57807614810dfb8571c8769"
        );
        let mut keys = alloc::collections::BTreeSet::new();
        let mut body = 0;
        let mut callbacks = 0;
        for line in std::str::from_utf8(&trace).unwrap().lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            let number = |i: usize| words[i].parse::<i32>().unwrap();
            let decode = |word: &str| -> Vec<u8> {
                word.as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                    .collect()
            };
            let address = [2, 3, 4, 5, 6, 7];
            match words[0] {
                "B" => {
                    assert_eq!(words.len(), 11);
                    assert!(keys.insert(words[..6].join(" ")));
                    let (stage, failed) = (number(4), number(5));
                    assert_eq!(number(6), if failed != 0 { -5 } else { 0 });
                    assert_eq!(
                        number(7),
                        i32::from(stage == 1 && failed == 0 || stage == 2 && failed != 0)
                    );
                    assert_eq!(number(8), 0);
                    assert_eq!(number(9), 208);
                    let changes = match stage {
                        0 => 0,
                        1 => 3,
                        2 => 1,
                        _ => panic!("stage"),
                    };
                    assert_eq!(
                        encode(address, changes, stage == 1),
                        decode(words[10]),
                        "{line}"
                    );
                    body += 1;
                }
                "W" => {
                    assert_eq!(words.len(), 9);
                    assert!(keys.insert(words[..5].join(" ")));
                    let step = number(4);
                    assert_eq!(number(7), if step == 7 { 0 } else { 1 });
                    match step {
                        2 | 4 => {
                            assert_eq!(number(5), 0xa9);
                            assert_eq!(number(6), 0);
                            assert_eq!(words[8], "-");
                        }
                        7 => {
                            assert_eq!(number(5), 8);
                            assert_eq!(number(6), 0);
                            assert_eq!(words[8], "-");
                        }
                        _ => {
                            assert_eq!(number(5), 0x309);
                            assert_eq!(number(6), 208);
                            let bytes = match step {
                                0 => encode(address, 0, false),
                                1 => encode(address, 3, true),
                                3 => encode(address, 1, false),
                                5 => remove_link_bytes(208),
                                6 => {
                                    let mut bytes = alloc::vec![0;208];
                                    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
                                    bytes[12..16].fill(255);
                                    bytes[16..22].copy_from_slice(&address);
                                    bytes
                                }
                                _ => panic!("callback"),
                            };
                            assert_eq!(bytes, decode(words[8]), "{line}");
                        }
                    }
                    callbacks += 1;
                }
                _ => panic!("source row"),
            }
        }
        assert_eq!((body, callbacks, keys.len()), (192, 256, 448));
    }
}
