// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014-2019 aQuantia Corporation
// Copyright (C) 2019-2020 Marvell International Ltd.
use super::{
    Error, Generation, Hardware, Profile, Registers, Result, Timer,
    firmware::Firmware,
    memory::{BUFFER, COUNT, Memory},
    registers as f,
};
impl<R: Registers, T: Timer> Hardware<R, T> {
    pub(super) fn mask_interrupts(&self) -> Result<()> {
        self.set(f::ITR_IRQ_MSK_CLEARLSW_SET, 0, u32::MAX)?;
        self.set(f::REG_IRQ_GLB_CTL_SET, 0, 0x2000_0000)?;
        self.set(f::ITR_IRQ_STATUS_CLEARLSW_SET, 0, u32::MAX)
    }
    pub(super) fn configure(&self, profile: Profile, fw: &Firmware) -> Result<()> {
        let antigua = profile.generation == Generation::Antigua;
        // Four-TC register layout, with all eight user priorities and the single
        // active queue in TC0. No RSS, LRO, DCA, VLAN stripping or offloads.
        for (field, value) in [
            (f::TPB_TPS_TX_TC_MODE_SET, 1),
            (f::THM_LSO_TCP_FLAG_OF_FIRST_PKT_SET, 0xff6),
            (f::THM_LSO_TCP_FLAG_OF_MIDDLE_PKT_SET, 0xff6),
            (f::THM_LSO_TCP_FLAG_OF_LAST_PKT_SET, 0xf7f),
            (f::TDM_TX_DESC_WR_WB_IRQ_EN_SET, 1),
            (f::TDM_TX_DCA_EN_SET, 0),
            (f::TDM_TX_DCA_MODE_SET, 0),
            (f::TPB_TX_PATH_SCP_INS_EN_SET, 1),
            (f::RPB_RPF_RX_TRAF_CLASS_MODE_SET, 1),
            (f::RPB_RX_FLOW_CTL_MODE_SET, 1),
            (f::REG_RX_FLR_RSS_CONTROL1SET, 0),
            (f::REG_RX_FLR_MCST_FLR_MSK_SET, 0),
            (f::REG_RX_FLR_MCST_FLR_SET, 0x10fff),
            (f::RPF_VLAN_OUTER_ETHT_SET, 0x88a8),
            (f::RPF_VLAN_INNER_ETHT_SET, 0x8100),
            (f::RPF_VLAN_PROM_MODE_EN_SET, 1),
            (f::RPF_VLAN_ACCEPT_UNTAGGED_PACKETS_SET, 1),
            (f::RPF_VLAN_UNTAGGED_ACT_SET, 1),
            (f::RDM_RX_DESC_WR_WB_IRQ_EN_SET, 1),
            (f::RPFL2BROADCAST_EN_SET, 1),
            (f::RPFL2MULTICAST_FLR_EN_SET, 1),
            (f::RPFL2_ACCEPT_ALL_MC_PACKETS_SET, 1),
            (f::RPFL2BROADCAST_FLR_ACT_SET, 1),
            (f::RPFL2BROADCAST_COUNT_THRESHOLD_SET, 0xffff),
            (f::RDM_RX_DCA_EN_SET, 0),
            (f::RDM_RX_DCA_MODE_SET, 0),
            (f::TPO_IPV4HEADER_CRC_OFFLOAD_EN_SET, 0),
            (f::TPO_TCP_UDP_CRC_OFFLOAD_EN_SET, 0),
            (f::RPO_IPV4HEADER_CRC_OFFLOAD_EN_SET, 0),
            (f::RPO_TCP_UDP_CRC_OFFLOAD_EN_SET, 0),
            (f::TDM_LARGE_SEND_OFFLOAD_EN_SET, 0),
            (f::RPO_OUTER_VLAN_TAG_MODE_SET, 1),
            (f::RPO_LRO_EN_SET, 0),
            (f::ITR_RSC_EN_SET, 0),
            (f::TPS_TX_PKT_SHED_DESC_RATE_CURR_TIME_RES_SET, 0),
            (f::TPS_TX_PKT_SHED_DESC_RATE_LIM_SET, 10),
            (f::TPS_TX_PKT_SHED_DESC_VM_ARB_MODE_SET, 0),
            (f::TPS_TX_PKT_SHED_DATA_ARB_MODE_SET, 0),
            (f::TPS_TX_PKT_SHED_DESC_TC_ARB_MODE_SET, 0),
            (f::TPS_TX_DESC_RATE_MODE_SET, 0),
        ] {
            self.set(field, 0, value)?;
        }
        for index in 0..if antigua { 38 } else { 33 } {
            self.set(f::RPFL2_UC_FLR_EN_SET, index, 0)?;
            self.set(f::RPFL2UNICAST_FLR_ACT_SET, index, 1)?;
        }
        let index = usize::from(fw.l2_base);
        let m = fw.mac.0;
        self.set(
            f::RPFL2UNICAST_DEST_ADDRESSLSW_SET,
            index,
            u32::from_be_bytes([m[2], m[3], m[4], m[5]]),
        )?;
        self.set(
            f::RPFL2UNICAST_DEST_ADDRESSMSW_SET,
            index,
            u32::from(u16::from_be_bytes([m[0], m[1]])),
        )?;
        self.set(f::RPFL2_UC_FLR_EN_SET, index, 1)?;
        self.set(f::RPFL2PROMISCUOUS_MODE_EN_SET, 0, 0)?;
        self.write(0x54c4, 0)?; // all eight priority-to-TC fields map to TC0
        let (tx, rx) = if antigua { (128, 172) } else { (160, 320) };
        for tc in 0..4 {
            for (field, value) in [
                (
                    f::TPB_TX_PKT_BUFF_SIZE_PER_TC_SET,
                    if tc == 0 { tx } else { 0 },
                ),
                (
                    f::TPB_TX_BUFF_HI_THRESHOLD_PER_TC_SET,
                    if tc == 0 { tx * 32 * 66 / 100 } else { 0 },
                ),
                (
                    f::TPB_TX_BUFF_LO_THRESHOLD_PER_TC_SET,
                    if tc == 0 { tx * 16 } else { 0 },
                ),
                (
                    f::RPB_RX_PKT_BUFF_SIZE_PER_TC_SET,
                    if tc == 0 { rx } else { 0 },
                ),
                (
                    f::RPB_RX_BUFF_HI_THRESHOLD_PER_TC_SET,
                    if tc == 0 { rx * 32 * 66 / 100 } else { 0 },
                ),
                (
                    f::RPB_RX_BUFF_LO_THRESHOLD_PER_TC_SET,
                    if tc == 0 { rx * 16 } else { 0 },
                ),
                (f::RPB_RX_XOFF_EN_PER_TC_SET, 0),
                (f::TPS_TX_PKT_SHED_DESC_TC_MAX_CREDIT_SET, 255),
                (f::TPS_TX_PKT_SHED_DESC_TC_WEIGHT_SET, 30),
                (f::TPS_TX_PKT_SHED_TC_DATA_WEIGHT_SET, 100),
                (f::TPS_TX_PKT_SHED_TC_DATA_MAX_CREDIT_SET, 0xfff),
            ] {
                self.set(field, tc, value)?;
            }
        }
        for queue in 0..32 {
            self.set(f::TPS_TX_DESC_RATE_EN_SET, queue, 0)?;
            self.set(f::TPS_TX_DESC_RATE_X_SET, queue, 1)?;
            self.set(f::TPS_TX_DESC_RATE_Y_SET, queue, 0)?;
        }
        if antigua {
            self.antigua_path(fw)?;
        } else {
            self.write(0x7040, 0x10000)?;
            self.write(0x5040, 0xf0000)?;
            let v = self.read(0x1014)?;
            self.write(0x1014, (v & !0x707) | 0x404)?;
            self.write(0x7b20, 24)?;
        }
        // An all-zero key with RSS disabled follows the donor's disabled path.
        for address in 0..10 {
            self.set(f::RPF_RSS_KEY_WR_DATA_SET, 0, 0)?;
            self.set(f::RPF_RSS_KEY_ADDR_SET, 0, address)?;
            self.set(f::RPF_RSS_KEY_WR_EN_SET, 0, 1)?;
            self.wait(f::RPF_RSS_KEY_WR_EN_SET.address, 1000, 10000, |v| {
                v & f::RPF_RSS_KEY_WR_EN_SET.mask == 0
            })?;
        }
        self.firmware_link(profile, *fw, true)?;
        self.mask_interrupts()
    }
    pub(super) fn queues(&self, memory: &Memory) -> Result<()> {
        let rx = memory.rx_address()?;
        let tx = memory.tx_address()?;
        for (field, value) in [
            (f::RDM_RX_DESC_EN_SET, 0),
            (f::TDM_TX_DESC_EN_SET, 0),
            (f::REG_RX_DMA_DESC_BASE_ADDRESSLSWSET, rx as u32),
            (f::REG_RX_DMA_DESC_BASE_ADDRESSMSWSET, (rx >> 32) as u32),
            (f::RDM_RX_DESC_LEN_SET, (COUNT / 8) as u32),
            (f::RDM_RX_DESC_DATA_BUFF_SIZE_SET, (BUFFER / 1024) as u32),
            (f::RDM_RX_DESC_HEAD_BUFF_SIZE_SET, 0),
            (f::RDM_RX_DESC_HEAD_SPLITTING_SET, 0),
            (f::RPO_RX_DESC_VLAN_STRIPPING_SET, 0),
            (f::RDM_RX_DESC_DCA_EN_SET, 0),
            (f::RDM_RX_HEAD_DCA_EN_SET, 0),
            (f::RDM_RX_PLD_DCA_EN_SET, 0),
            (f::REG_TX_DMA_DESC_BASE_ADDRESSLSWSET, tx as u32),
            (f::REG_TX_DMA_DESC_BASE_ADDRESSMSWSET, (tx >> 32) as u32),
            (f::TDM_TX_DESC_LEN_SET, (COUNT / 8) as u32),
            (f::TX_TAIL, 0),
            (f::TDM_TX_DESC_WR_WB_THRESHOLD_SET, 0),
            (f::TDM_TX_DESC_DCA_EN_SET, 0),
        ] {
            self.set(field, 0, value)?;
        }
        self.set(f::RX_TAIL, 0, (COUNT - 1) as u32)
    }
    pub(super) fn enable_queues(&self) -> Result<()> {
        for f in [
            f::TDM_TX_DESC_EN_SET,
            f::RDM_RX_DESC_EN_SET,
            f::TPB_TX_BUFF_EN_SET,
            f::RPB_RX_BUFF_EN_SET,
        ] {
            self.set(f, 0, 1)?;
            self.wait(f.address, 10, 10000, |v| v & f.mask == f.mask)?;
        }
        Ok(())
    }
    pub(super) fn stop_queues(&self) -> Result<()> {
        self.mask_interrupts()?;
        // Stop every queue: retained firmware could have left unused queues on.
        for q in 0..32 {
            for f in [f::TDM_TX_DESC_EN_SET, f::RDM_RX_DESC_EN_SET] {
                self.set(f, q, 0)?;
                self.wait(f.address + q * f.stride, 10, 10000, |v| v & f.mask == 0)?;
            }
        }
        for f in [f::TPB_TX_BUFF_EN_SET, f::RPB_RX_BUFF_EN_SET] {
            self.set(f, 0, 0)?;
            self.wait(f.address, 10, 10000, |v| v & f.mask == 0)?;
        }
        let cache = self.read(0x5a00)?;
        self.write(0x5a00, cache ^ 1)?;
        self.wait(
            f::RDM_RX_DMA_DESC_CACHE_INIT_DONE_GET.address,
            1000,
            10000,
            |v| v & f::RDM_RX_DMA_DESC_CACHE_INIT_DONE_GET.mask != 0,
        )?;
        Ok(())
    }
    fn antigua_path(&self, fw: &Firmware) -> Result<()> {
        let version = self.read(0xf4)?;
        let ratio = if version < 0x01000000 {
            1
        } else if version >= 0x01005502 {
            2
        } else {
            4
        };
        self.write(0x7a1c, (self.read(0x7a1c)? & !0xff00) | (ratio << 8))?;
        self.set(f::ATL2_TPB_TX_BUF_CLK_GATE_EN_SET, 0, 0)?;
        if self.get(f::ATL2_PHI_EXT_TAG_GET, 0)? != 0 {
            self.set(f::ATL2_TDM_TX_DATA_READ_REQ_LIMIT_SET, 0, 0x7f)?;
            self.set(f::ATL2_TDM_TX_DESC_READ_REQ_LIMIT_SET, 0, 0xf)?;
        }
        self.set(f::ATL2_RPF_RSS_HASH_TYPE_SET, 0, 0)?;
        self.set(f::ATL2_RPF_REDIRECTION_TABLE2_SELECT_SET, 0, 0)?;
        self.set(f::ATL2_TPB_TX_TC_Q_RAND_MAP_EN_SET, 0, 1)?;
        // Four TCs of eight queues; only TC0 queue0 is published.
        for tc in 0..4 {
            self.write(0x5900 + tc * 4, 0)?;
        }
        for group in 0..8 {
            self.write(0x799c + group * 4, 0)?;
        }
        self.set(f::ATL2_RPFL2_UC_FLR_TAG_SET, usize::from(fw.l2_base), 1)?;
        self.set(f::ATL2_RPFL2_BC_FLR_TAG_SET, 0, 1)?;
        self.set(f::ATL2_RPF_L3_V6_V4_SELECT_SET, 0, 1)?;
        let start = usize::from(fw.art_base);
        let count = usize::from(fw.art_count);
        if start + count > 128 || count < 10 {
            return Err(Error::Unsupported("AQtion firmware ART allocation"));
        }
        let section_mask =
            ((1u32 << ((start + count).div_ceil(8))) - 1) & !((1u32 << (start / 8)) - 1);
        let sections = self.get(f::ATL2_RPF_ACT_RSLVR_SECTION_EN_GET, 0)?;
        self.set(
            f::ATL2_RPF_ACT_RSLVR_SECTION_EN_SET,
            0,
            sections | section_mask,
        )?;
        // First reject packets without a station/broadcast/multicast match,
        // then accept all VLANs and assign every priority to queue0.
        for record in start..start + count {
            self.art(record, 0, 0, 0)?;
        }
        self.art(start, 0, 0x7f, 1)?;
        self.art(start + 1, 0, 0, 0)?;
        for priority in 0..8 {
            self.art(
                start + 2 + priority,
                (priority as u32) << 29,
                7 << 29,
                0x101,
            )?;
        }
        self.set(f::ATL2_RPF_NEW_ENABLE_SET, 0, 1)
    }
    fn art(&self, index: usize, tag: u32, mask: u32, action: u32) -> Result<()> {
        self.wait(0x3ac, 1, 10000, |v| v == 1)?;
        let result = (|| {
            self.write(0x14000 + index * 0x10, tag)?;
            self.write(0x14004 + index * 0x10, mask)?;
            self.write(0x14008 + index * 0x10, action)
        })();
        let release = self.write(0x3ac, 1);
        result.and(release)
    }
}
