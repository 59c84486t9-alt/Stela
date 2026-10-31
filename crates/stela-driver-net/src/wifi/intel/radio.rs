// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Source cold post-NVM setup prefix: unassociated Smart FIFO, TX antennas,
//! normal BT coexistence and standalone SOC latency. These pure commands stop
//! before BIOS LARI configuration; they supply no radio/scan/TX readiness.
use super::{command::Id, firmware::Firmware, identity::Platform, nvm::Information};
use alloc::vec::Vec;
pub mod bios;
pub mod control;
pub mod lari;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    SmartFifo,
    TxAntennas,
    BluetoothCoexistence,
    SocLatency,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MissingPhySku,
    NoTxAntennas,
    MissingApi(Stage),
    Version { stage: Stage, declared: u8 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialCommand {
    stage: Stage,
    id: Id,
    bytes: Vec<u8>,
}
impl InitialCommand {
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn id(&self) -> Id {
        self.id
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// Inputs and output are pure data, never NVM/current-epoch proof.
/// The later owned consumer must prepare this from its own firmware
/// and private real NVM completion, not accept a caller-substituted plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialPlan {
    commands: Vec<InitialCommand>,
    tx_antennas: u8,
    smart_fifo_offloaded: bool,
}
impl InitialPlan {
    pub fn prepare(
        firmware: &Firmware<'_>,
        platform: Platform,
        nvm: &Information,
    ) -> Result<Self, Error> {
        let mut tx_antennas = ((firmware.phy_sku().ok_or(Error::MissingPhySku)? >> 16) & 0xf) as u8;
        // Source cast/conditional intersection; upper NVM bits are not
        // silently interpreted as extra physical antennas.
        let nvm_antennas = nvm.tx_chains as u8;
        if nvm_antennas != 0 {
            tx_antennas &= nvm_antennas;
        }
        if tx_antennas == 0 {
            return Err(Error::NoTxAntennas);
        }
        let smart_fifo_offloaded = firmware.supports_api(68);
        let mut out = Self {
            commands: Vec::new(),
            tx_antennas,
            smart_fifo_offloaded,
        };
        if !smart_fifo_offloaded {
            let mut words = alloc::vec![3, 4096, 8192]; // SF_INIT_OFF; scan/MIMO2 watermarks.
            words.extend([1_000_000; 10]);
            for _ in 0..5 {
                words.extend([400, 160]);
            }
            out.push(
                firmware,
                Stage::SmartFifo,
                Id {
                    group: 0,
                    opcode: 0xd1,
                    version: 0,
                },
                &[3],
                words.into_iter().flat_map(u32::to_le_bytes).collect(),
            )?;
        }
        out.push(
            firmware,
            Stage::TxAntennas,
            Id {
                group: 0,
                opcode: 0x98,
                version: 0,
            },
            &[1],
            u32::from(tx_antennas).to_le_bytes().to_vec(),
        )?;
        let mut bt = 1u32.to_le_bytes().to_vec(); // BT_COEX_NW, never force BT/WiFi antenna.
        let modules = (1u32 << 2) | (1 << 4) | u32::from(firmware.supports_capability(67));
        bt.extend(modules.to_le_bytes());
        out.push(
            firmware,
            Stage::BluetoothCoexistence,
            Id {
                group: 0,
                opcode: 0x9b,
                version: 0,
            },
            &[6],
            bt,
        )?;
        if firmware.supports_capability(37) {
            let mut soc = platform.soc_flags().to_le_bytes().to_vec();
            soc.extend(platform.xtal_latency.to_le_bytes());
            out.push(
                firmware,
                Stage::SocLatency,
                Id {
                    group: 2,
                    opcode: 1,
                    version: 0,
                },
                &[1, 2],
                soc,
            )?;
        }
        Ok(out)
    }
    fn push(
        &mut self,
        firmware: &Firmware<'_>,
        stage: Stage,
        id: Id,
        supported: &[u8],
        bytes: Vec<u8>,
    ) -> Result<(), Error> {
        let group = if id.group == 0 { 1 } else { id.group };
        let declared = firmware
            .command_version(group, id.opcode)
            .ok_or(Error::MissingApi(stage))?
            .command_version;
        if !supported.contains(&declared) {
            return Err(Error::Version { stage, declared });
        }
        // Linux call sites use legacy ID or WIDE_ID, without explicit version
        // bits. Advertised payload ABI is not an encoded header override.
        self.commands.push(InitialCommand { stage, id, bytes });
        Ok(())
    }
    pub fn commands(&self) -> &[InitialCommand] {
        &self.commands
    }
    pub fn tx_antennas(&self) -> u8 {
        self.tx_antennas
    }
    pub fn smart_fifo_offloaded(&self) -> bool {
        self.smart_fifo_offloaded
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::wifi::intel::command::Command;
    fn image(phy: Option<u32>, offload: bool, mplut: bool, soc: bool) -> Vec<u8> {
        let mut b = alloc::vec![0;88];
        b[4..8].copy_from_slice(&0x0a4c5749u32.to_le_bytes());
        let mut tlv = |kind: u32, d: &[u8]| {
            b.extend(kind.to_le_bytes());
            b.extend((d.len() as u32).to_le_bytes());
            b.extend(d);
            b.resize(b.len().next_multiple_of(4), 0);
        };
        if let Some(phy) = phy {
            tlv(23, &phy.to_le_bytes());
        }
        tlv(
            48,
            &[0xd1, 1, 3, 0, 0x98, 1, 1, 0, 0x9b, 1, 6, 0, 1, 2, 2, 0],
        );
        if offload {
            tlv(29, &[2, 0, 0, 0, 16, 0, 0, 0]);
        }
        if mplut {
            tlv(30, &[2, 0, 0, 0, 8, 0, 0, 0]);
        }
        if soc {
            tlv(30, &[1, 0, 0, 0, 32, 0, 0, 0]);
        }
        b
    }
    fn nvm(tx_chains: u32) -> Information {
        Information {
            response_version: 4,
            general_flags: 0,
            nvm_version: 0,
            board_type: 0,
            hardware_addresses: 1,
            mac_sku_flags: 0,
            tx_chains,
            rx_chains: 3,
            lar_enabled: 1,
            channel_count: 0,
            channel_profiles: Vec::new(),
            raw: Vec::new(),
        }
    }
    #[test]
    fn cold_prefix_order_offload_exact_header_versions_and_standalone_latencies() {
        for offload in [false, true] {
            for soc in [false, true] {
                for platform in [Platform::AX200, Platform::AX210] {
                    let b = image(Some(0x330018), offload, true, soc);
                    let fw = Firmware::parse(&b).unwrap();
                    let plan = InitialPlan::prepare(&fw, platform, &nvm(1)).unwrap();
                    assert_eq!(plan.tx_antennas(), 1);
                    assert_eq!(plan.smart_fifo_offloaded(), offload);
                    let mut expected = Vec::new();
                    if !offload {
                        expected.push(Stage::SmartFifo);
                    }
                    expected.extend([Stage::TxAntennas, Stage::BluetoothCoexistence]);
                    if soc {
                        expected.push(Stage::SocLatency);
                    }
                    assert_eq!(
                        plan.commands()
                            .iter()
                            .map(InitialCommand::stage)
                            .collect::<Vec<_>>(),
                        expected
                    );
                    for c in plan.commands() {
                        let encoded = Command::encode(c.id(), 0, 0, c.bytes()).unwrap();
                        assert_eq!(encoded.bytes()[7], 0); // source call-site header version, not advertised ABI.
                        if c.stage() == Stage::SocLatency {
                            assert_eq!(
                                c.bytes(),
                                [
                                    1,
                                    0,
                                    0,
                                    0,
                                    if platform == Platform::AX210 { 0xf4 } else { 0 },
                                    if platform == Platform::AX210 { 1 } else { 0 },
                                    0,
                                    0
                                ]
                            );
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn missing_phy_disjoint_antennas_and_unqualified_schema_remain_explicit() {
        let b = image(None, false, true, true);
        let fw = Firmware::parse(&b).unwrap();
        assert_eq!(
            InitialPlan::prepare(&fw, Platform::AX200, &nvm(3)),
            Err(Error::MissingPhySku)
        );
        let b = image(Some(0x330018), false, true, true);
        let fw = Firmware::parse(&b).unwrap();
        assert_eq!(
            InitialPlan::prepare(&fw, Platform::AX200, &nvm(4)),
            Err(Error::NoTxAntennas)
        );
        assert_eq!(
            InitialPlan::prepare(&fw, Platform::AX200, &nvm(0))
                .unwrap()
                .tx_antennas(),
            3
        );
        assert_eq!(
            InitialPlan::prepare(&fw, Platform::AX200, &nvm(0x100))
                .unwrap()
                .tx_antennas(),
            3
        );
        // Mutate the exact command-table rows, leaving all other bytes stable.
        for (row, stage, supported) in [
            (0, Stage::SmartFifo, &[3][..]),
            (1, Stage::TxAntennas, &[1][..]),
            (2, Stage::BluetoothCoexistence, &[6][..]),
            (3, Stage::SocLatency, &[1, 2][..]),
        ] {
            let table = 108usize;
            for version in 0..=255 {
                let mut bytes = b.clone();
                bytes[table + row * 4 + 2] = version;
                let fw = Firmware::parse(&bytes).unwrap();
                let result = InitialPlan::prepare(&fw, Platform::AX200, &nvm(3));
                if supported.contains(&version) {
                    assert!(result.is_ok());
                } else {
                    assert_eq!(
                        result,
                        Err(Error::Version {
                            stage,
                            declared: version
                        })
                    );
                }
            }
            let mut bytes = b.clone();
            bytes[table + row * 4] = 0xff;
            let fw = Firmware::parse(&bytes).unwrap();
            assert_eq!(
                InitialPlan::prepare(&fw, Platform::AX200, &nvm(3)),
                Err(Error::MissingApi(stage))
            );
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_IMAGES"]
    fn images_use_source_cold_prefix_schemas_and_distinct_smart_fifo_policy() {
        let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
        use crate::wifi::intel::firmware::Family;
        for (family, platform) in [
            (Family::Ax200, Platform::AX200),
            (Family::Ax210, Platform::AX210),
        ] {
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(family.firmware_name())).unwrap();
            let fw = Firmware::parse(&bytes).unwrap();
            let plan = InitialPlan::prepare(&fw, platform, &nvm(3)).unwrap();
            assert_eq!(plan.tx_antennas(), 3);
            assert_eq!(plan.smart_fifo_offloaded(), platform == Platform::AX210);
            assert_eq!(
                plan.commands().len(),
                if platform == Platform::AX200 { 4 } else { 3 }
            );
            assert_eq!(plan.commands().last().unwrap().stage(), Stage::SocLatency);
        }
    }
    #[test]
    #[ignore = "oracle: STELA_IWLWIFI_RADIO_ORACLE"]
    fn unchanged_linux_cold_prefix_command_helpers_oracle() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_IWLWIFI_RADIO_ORACLE").unwrap()).unwrap();
        assert_eq!(
            std::format!("{:x}", Sha256::digest(&bytes)),
            "dd7bd4feed99c2b16119fba07f82655a4cd734ab804f3c925eeccfe8ec3e6e1f"
        );
        let hex = |v: &[u8]| -> std::string::String {
            v.iter().map(|b| std::format!("{b:02x}")).collect()
        };
        let (mut tx, mut bt, mut soc, mut sf) = (0, 0, 0, 0);
        for line in core::str::from_utf8(&bytes).unwrap().lines() {
            let f: Vec<_> = line.split_whitespace().collect();
            let (phy, nvm_chain, mplut, platform, stage, payload) = match f[0] {
                "tx" => (
                    f[1].parse::<u32>().unwrap() << 16,
                    f[2].parse().unwrap(),
                    false,
                    Platform::AX200,
                    Stage::TxAntennas,
                    f[4],
                ),
                "bt" => (
                    3 << 16,
                    3,
                    f[1] == "1",
                    Platform::AX200,
                    Stage::BluetoothCoexistence,
                    f[2],
                ),
                "soc" => (
                    3 << 16,
                    3,
                    false,
                    if f[1] == "0" {
                        Platform::AX200
                    } else {
                        Platform::AX210
                    },
                    Stage::SocLatency,
                    f[2],
                ),
                "sf" => (3 << 16, 3, false, Platform::AX200, Stage::SmartFifo, f[1]),
                _ => panic!("unknown row"),
            };
            let b = image(Some(phy), false, mplut, true);
            let fw = Firmware::parse(&b).unwrap();
            let plan = InitialPlan::prepare(&fw, platform, &nvm(nvm_chain));
            if f[0] == "tx" {
                tx += 1;
                if f[3] == "0" {
                    assert_eq!(plan, Err(Error::NoTxAntennas));
                    continue;
                }
                assert_eq!(
                    plan.as_ref().unwrap().tx_antennas(),
                    f[3].parse::<u8>().unwrap()
                );
            }
            let plan = plan.unwrap();
            let command = plan.commands().iter().find(|c| c.stage() == stage).unwrap();
            assert_eq!(hex(command.bytes()), payload, "{line}");
            match f[0] {
                "bt" => bt += 1,
                "soc" => soc += 1,
                "sf" => sf += 1,
                _ => (),
            }
        }
        assert_eq!((tx, bt, soc, sf), (4096, 2, 2, 1));
    }
}
