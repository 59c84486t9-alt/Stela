// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2013-2014, 2018-2026 Intel Corporation
//! Private firmware-epoch coexistence state. Public RX diagnostics cannot
//! replace or erase the original captured profile used by native transmit.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoexistenceError {
    Uninitialized,
    Version,
    Channel,
    ProfileLength(usize),
    Activity(u32),
    Antennas,
}

pub(super) struct Coexistence {
    initialized: bool,
    profile: [u8; 40],
    profile_error: Option<CoexistenceError>,
    pub(super) applied_ci: [u8; 24],
}
impl Coexistence {
    pub(super) fn new() -> Self {
        Self {
            initialized: false,
            profile: [0; 40],
            profile_error: None,
            applied_ci: [0; 24],
        }
    }
    // Original send_bt_init_conf clears both records before command send.
    pub(super) fn begin_initialization(&mut self) {
        *self = Self::new();
    }
    // Only the private ColdRadio ACK + canonical HCMD reclaim calls this.
    pub(super) fn initialized(&mut self) {
        self.initialized = true;
    }
    // Called only after completed-RB CPU ownership and actual packet dispatch.
    // Preserve the first malformed actual profile; a later good packet cannot
    // erase the refusal. Raw diagnostics remain independently available.
    pub(super) fn observe(&mut self, command: u8, group: u8, raw: &[u8]) {
        if command != 0xce || group != 0 {
            return;
        }
        if raw.len() != self.profile.len() {
            self.profile_error
                .get_or_insert(CoexistenceError::ProfileLength(raw.len()));
            return;
        }
        let activity = u32::from_le_bytes(raw[32..36].try_into().unwrap());
        if activity > 4 {
            self.profile_error
                .get_or_insert(CoexistenceError::Activity(activity));
            return;
        }
        self.profile.copy_from_slice(raw);
    }
    pub(super) fn check(&self) -> Result<(), CoexistenceError> {
        if !self.initialized {
            return Err(CoexistenceError::Uninitialized);
        }
        if let Some(error) = &self.profile_error {
            return Err(error.clone());
        }
        Ok(())
    }
    pub(super) fn activity(&self) -> Result<u32, CoexistenceError> {
        self.check()?;
        Ok(u32::from_le_bytes(self.profile[32..36].try_into().unwrap()))
    }
    pub(super) fn management_antenna(
        &self,
        band: crate::net::wifi::Band,
        valid: u8,
        last: u8,
    ) -> Result<u8, CoexistenceError> {
        self.check()?;
        if valid == 0 || valid & !3 != 0 || last > 1 || valid & (1 << last) == 0 {
            return Err(CoexistenceError::Antennas);
        }
        // Original HR2 rf_hr::non_shared_ant=ANT_B. No caller antenna or
        // USB-HCI state stands in for this actual Wi-Fi firmware profile.
        let antenna = if band == crate::net::wifi::Band::Ghz2 && self.activity()? >= 3 {
            2
        } else {
            1 << last
        };
        if antenna & valid == 0 {
            return Err(CoexistenceError::Antennas);
        }
        Ok(antenna)
    }
}
pub(super) fn next_antenna(valid: u8, last: u8) -> Result<u8, CoexistenceError> {
    if valid == 0 || valid & !3 != 0 || last > 1 {
        return Err(CoexistenceError::Antennas);
    }
    let next = (last + 1) % 2;
    Ok(if valid & (1 << next) != 0 { next } else { last })
}

/// Original single 20 MHz link0/PHY0 CI, with no second interface or HT.
pub(super) fn channel_inhibition(
    channel: crate::net::wifi::Channel,
) -> Result<[u8; 24], CoexistenceError> {
    use crate::net::wifi::Band;
    // Exact column0 of coex.c::iwl_ci_mask, channels0..14.
    const MASKS: [u64; 15] = [
        0,
        0x1fff,
        0xffff,
        0x3fffc,
        0x1fffe0,
        0x7fff80,
        0x3fffc00,
        0xffff000,
        0x7fff8000,
        0x1fffe0000,
        0xffff00000,
        0x3fffc00000,
        0xfffe000000,
        0xfff8000000,
        0xfe00000000,
    ];
    let mask = match channel.band {
        Band::Ghz2 if (1..=14).contains(&channel.number) => MASKS[usize::from(channel.number)],
        Band::Ghz5 => 0,
        _ => return Err(CoexistenceError::Channel),
    };
    let mut bytes = [0; 24];
    bytes[..8].copy_from_slice(&mask.to_le_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::net::wifi::intel::{
        command::Id,
        firmware::{Family, Firmware},
    };
    use crate::net::wifi::{Band, Channel};
    use alloc::vec::Vec;
    #[test]
    fn actual_profile_errors_latch_and_uninitialized_state_grants_no_antenna() {
        let mut state = Coexistence::new();
        assert_eq!(state.activity(), Err(CoexistenceError::Uninitialized));
        state.initialized();
        state.observe(0xce, 1, &[0; 3]); // unrelated group cannot alter policy.
        assert_eq!(state.activity(), Ok(0));
        state.observe(0xce, 0, &[0; 39]);
        state.observe(0xce, 0, &[0; 40]);
        assert_eq!(state.activity(), Err(CoexistenceError::ProfileLength(39)));
        state.begin_initialization();
        assert_eq!(state.activity(), Err(CoexistenceError::Uninitialized));
        state.initialized();
        let mut profile = [0; 40];
        profile[32..36].copy_from_slice(&5u32.to_le_bytes());
        state.observe(0xce, 0, &profile);
        assert_eq!(state.activity(), Err(CoexistenceError::Activity(5)));
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_COEX_TRACE"]
    fn pinned_linux_cold_coexistence_ci_and_management_antenna() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_COEX_TRACE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "e35c694b8b88dd350cd9a9bf0cb62884c76dc4ab51b0ae62c858b0fc6c327dde"
        );
        let mut unique = alloc::collections::BTreeSet::new();
        for line in std::str::from_utf8(&bytes).unwrap().lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            let n = |i: usize| words[i].parse::<u32>().unwrap();
            let channel = |band, number| Channel {
                band,
                number,
                frequency_mhz: if band == Band::Ghz2 { 2412 } else { 5180 },
            };
            match words[0] {
                "I" => {
                    assert_eq!(words.len(), 6);
                    assert!(unique.insert(words[..3].join(" ")));
                    assert_eq!(words[3], if n(2) == 0 { "0" } else { "-5" });
                    assert_eq!(n(4), 8);
                    let mut image = alloc::vec![0;88];
                    image[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
                    for (kind, data) in [
                        (23u32, 0x330018u32.to_le_bytes().to_vec()),
                        (48, alloc::vec![0xd1, 1, 3, 0, 0x98, 1, 1, 0, 0x9b, 1, 6, 0]),
                        (
                            30,
                            alloc::vec![2, 0, 0, 0, if n(1) == 0 { 0 } else { 8 }, 0, 0, 0],
                        ),
                    ] {
                        image.extend(kind.to_le_bytes());
                        image.extend((data.len() as u32).to_le_bytes());
                        image.extend(data);
                        image.resize(image.len().next_multiple_of(4), 0);
                    }
                    let firmware = Firmware::parse(&image).unwrap();
                    let information = crate::net::wifi::intel::nvm::Information {
                        response_version: 4,
                        general_flags: 0,
                        nvm_version: 0,
                        board_type: 0,
                        hardware_addresses: 1,
                        mac_sku_flags: 0,
                        tx_chains: 3,
                        rx_chains: 3,
                        lar_enabled: 1,
                        channel_count: 0,
                        channel_profiles: Vec::new(),
                        raw: Vec::new(),
                    };
                    let plan = crate::net::wifi::intel::radio::InitialPlan::prepare(
                        &firmware,
                        Family::Ax200,
                        &information,
                    )
                    .unwrap();
                    let init = plan
                        .commands()
                        .iter()
                        .find(|c| {
                            c.stage() == crate::net::wifi::intel::radio::Stage::BluetoothCoexistence
                        })
                        .unwrap();
                    assert_eq!(
                        init.id(),
                        Id {
                            group: 0,
                            opcode: 0x9b,
                            version: 0
                        }
                    );
                    let expected: alloc::string::String = init
                        .bytes()
                        .iter()
                        .map(|b| std::format!("{b:02x}"))
                        .collect();
                    assert_eq!(words[5], expected);
                }
                "C" => {
                    assert_eq!(words.len(), 9);
                    assert!(unique.insert(words[..6].join(" ")));
                    let ci = channel_inhibition(channel(
                        if n(2) == 0 { Band::Ghz2 } else { Band::Ghz5 },
                        n(3) as u16,
                    ))
                    .unwrap();
                    let sent = n(2) == 0 && n(5) == 0;
                    assert_eq!(n(6), u32::from(sent));
                    assert_eq!(n(7), if sent { 24 } else { 0 });
                    let expected: alloc::string::String =
                        ci.iter().map(|b| std::format!("{b:02x}")).collect();
                    assert_eq!(words[8], if sent { expected.as_str() } else { "-" });
                }
                "N" => {
                    assert_eq!(words.len(), 4);
                    assert!(unique.insert(words[..3].join(" ")));
                    assert_eq!(next_antenna(n(1) as u8, n(2) as u8).unwrap(), n(3) as u8);
                }
                "A" => {
                    assert_eq!(words.len(), 5);
                    assert!(unique.insert(words[..4].join(" ")));
                    let mut state = Coexistence::new();
                    state.initialized();
                    let mut raw = [0; 40];
                    raw[32..36].copy_from_slice(&n(2).to_le_bytes());
                    state.observe(0xce, 0, &raw);
                    assert_eq!(
                        u32::from(
                            state
                                .management_antenna(
                                    if n(1) == 0 { Band::Ghz2 } else { Band::Ghz5 },
                                    3,
                                    n(3) as u8
                                )
                                .unwrap()
                        ) << 14,
                        n(4)
                    );
                }
                _ => panic!("unknown original row"),
            }
        }
        assert_eq!(unique.len(), 590);
    }
}
