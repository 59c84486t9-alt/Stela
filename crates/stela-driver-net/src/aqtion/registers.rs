// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014-2019 aQuantia Corporation
// Copyright (C) 2019-2020 Marvell International Ltd.
//! Selected exact LLH fields from pinned Linux atlantic. Strides are bytes.
#[derive(Clone, Copy)]
pub(super) struct Field {
    pub address: usize,
    pub stride: usize,
    pub mask: u32,
    pub shift: u32,
}
pub(super) const ATL2_PHI_EXT_TAG_GET: Field = Field {
    address: 0x1000,
    stride: 0x0,
    mask: 0x00000020,
    shift: 5,
};
pub(super) const ATL2_RPFL2_BC_FLR_TAG_SET: Field = Field {
    address: 0x50f0,
    stride: 0x0,
    mask: 0x0000003f,
    shift: 0,
};
pub(super) const ATL2_RPFL2_UC_FLR_TAG_SET: Field = Field {
    address: 0x5114,
    stride: 0x8,
    mask: 0x0fc00000,
    shift: 22,
};
pub(super) const ATL2_RPF_ACT_RSLVR_SECTION_EN_GET: Field = Field {
    address: 0x6ff0,
    stride: 0x0,
    mask: 0x0000ffff,
    shift: 0,
};
pub(super) const ATL2_RPF_ACT_RSLVR_SECTION_EN_SET: Field = Field {
    address: 0x6ff0,
    stride: 0x0,
    mask: 0x0000ffff,
    shift: 0,
};
pub(super) const ATL2_RPF_L3_V6_V4_SELECT_SET: Field = Field {
    address: 0x6500,
    stride: 0x0,
    mask: 0x00800000,
    shift: 23,
};
pub(super) const ATL2_RPF_NEW_ENABLE_SET: Field = Field {
    address: 0x5104,
    stride: 0x0,
    mask: 0x00000800,
    shift: 11,
};
pub(super) const ATL2_RPF_REDIRECTION_TABLE2_SELECT_SET: Field = Field {
    address: 0x54c8,
    stride: 0x0,
    mask: 0x00001000,
    shift: 12,
};
pub(super) const ATL2_RPF_RSS_HASH_TYPE_SET: Field = Field {
    address: 0x54c8,
    stride: 0x0,
    mask: 0x000001ff,
    shift: 0,
};
pub(super) const ATL2_TDM_TX_DATA_READ_REQ_LIMIT_SET: Field = Field {
    address: 0x7b04,
    stride: 0x0,
    mask: 0x0000ff00,
    shift: 8,
};
pub(super) const ATL2_TDM_TX_DESC_READ_REQ_LIMIT_SET: Field = Field {
    address: 0x7b04,
    stride: 0x0,
    mask: 0x0000001f,
    shift: 0,
};
pub(super) const ATL2_TPB_TX_BUF_CLK_GATE_EN_SET: Field = Field {
    address: 0x7900,
    stride: 0x0,
    mask: 0x00000020,
    shift: 5,
};
pub(super) const ATL2_TPB_TX_TC_Q_RAND_MAP_EN_SET: Field = Field {
    address: 0x7900,
    stride: 0x0,
    mask: 0x00000200,
    shift: 9,
};
pub(super) const ITR_IRQ_MSK_CLEARLSW_SET: Field = Field {
    address: 0x2070,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const ITR_IRQ_STATUS_CLEARLSW_SET: Field = Field {
    address: 0x2050,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const ITR_RSC_EN_SET: Field = Field {
    address: 0x2200,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const RDM_RX_DCA_EN_SET: Field = Field {
    address: 0x6180,
    stride: 0x0,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const RDM_RX_DCA_MODE_SET: Field = Field {
    address: 0x6180,
    stride: 0x0,
    mask: 0x0000000f,
    shift: 0,
};
pub(super) const RDM_RX_DESC_DATA_BUFF_SIZE_SET: Field = Field {
    address: 0x5b18,
    stride: 0x20,
    mask: 0x0000001f,
    shift: 0,
};
pub(super) const RDM_RX_DESC_DCA_EN_SET: Field = Field {
    address: 0x6100,
    stride: 0x4,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const RDM_RX_DESC_EN_SET: Field = Field {
    address: 0x5b08,
    stride: 0x20,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const RDM_RX_DESC_HEAD_BUFF_SIZE_SET: Field = Field {
    address: 0x5b18,
    stride: 0x20,
    mask: 0x00001f00,
    shift: 8,
};
pub(super) const RDM_RX_DESC_HEAD_SPLITTING_SET: Field = Field {
    address: 0x5b08,
    stride: 0x20,
    mask: 0x10000000,
    shift: 28,
};
pub(super) const RDM_RX_DESC_LEN_SET: Field = Field {
    address: 0x5b08,
    stride: 0x20,
    mask: 0x00001ff8,
    shift: 3,
};
pub(super) const RDM_RX_DESC_WR_WB_IRQ_EN_SET: Field = Field {
    address: 0x5a30,
    stride: 0x0,
    mask: 0x00000004,
    shift: 2,
};
pub(super) const RDM_RX_DMA_DESC_CACHE_INIT_DONE_GET: Field = Field {
    address: 0x5a10,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const RDM_RX_HEAD_DCA_EN_SET: Field = Field {
    address: 0x6100,
    stride: 0x4,
    mask: 0x40000000,
    shift: 30,
};
pub(super) const RDM_RX_PLD_DCA_EN_SET: Field = Field {
    address: 0x6100,
    stride: 0x4,
    mask: 0x20000000,
    shift: 29,
};
pub(super) const REG_IRQ_GLB_CTL_SET: Field = Field {
    address: 0x2300,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const REG_RX_DMA_DESC_BASE_ADDRESSLSWSET: Field = Field {
    address: 0x5b00,
    stride: 0x20,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const REG_RX_DMA_DESC_BASE_ADDRESSMSWSET: Field = Field {
    address: 0x5b04,
    stride: 0x20,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const REG_RX_FLR_MCST_FLR_MSK_SET: Field = Field {
    address: 0x5270,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const REG_RX_FLR_MCST_FLR_SET: Field = Field {
    address: 0x5250,
    stride: 0x4,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const REG_RX_FLR_RSS_CONTROL1SET: Field = Field {
    address: 0x54c0,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const REG_TX_DMA_DESC_BASE_ADDRESSLSWSET: Field = Field {
    address: 0x7c00,
    stride: 0x40,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const REG_TX_DMA_DESC_BASE_ADDRESSMSWSET: Field = Field {
    address: 0x7c04,
    stride: 0x40,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const RPB_RPF_RX_TRAF_CLASS_MODE_SET: Field = Field {
    address: 0x5700,
    stride: 0x0,
    mask: 0x00000100,
    shift: 8,
};
pub(super) const RPB_RX_BUFF_EN_SET: Field = Field {
    address: 0x5700,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const RPB_RX_BUFF_HI_THRESHOLD_PER_TC_SET: Field = Field {
    address: 0x5714,
    stride: 0x10,
    mask: 0x3fff0000,
    shift: 16,
};
pub(super) const RPB_RX_BUFF_LO_THRESHOLD_PER_TC_SET: Field = Field {
    address: 0x5714,
    stride: 0x10,
    mask: 0x00003fff,
    shift: 0,
};
pub(super) const RPB_RX_FLOW_CTL_MODE_SET: Field = Field {
    address: 0x5700,
    stride: 0x0,
    mask: 0x00000030,
    shift: 4,
};
pub(super) const RPB_RX_PKT_BUFF_SIZE_PER_TC_SET: Field = Field {
    address: 0x5710,
    stride: 0x10,
    mask: 0x000001ff,
    shift: 0,
};
pub(super) const RPB_RX_XOFF_EN_PER_TC_SET: Field = Field {
    address: 0x5714,
    stride: 0x10,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const RPFL2BROADCAST_COUNT_THRESHOLD_SET: Field = Field {
    address: 0x5100,
    stride: 0x0,
    mask: 0xffff0000,
    shift: 16,
};
pub(super) const RPFL2BROADCAST_EN_SET: Field = Field {
    address: 0x5100,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const RPFL2BROADCAST_FLR_ACT_SET: Field = Field {
    address: 0x5100,
    stride: 0x0,
    mask: 0x00007000,
    shift: 12,
};
pub(super) const RPFL2MULTICAST_FLR_EN_SET: Field = Field {
    address: 0x5250,
    stride: 0x4,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const RPFL2PROMISCUOUS_MODE_EN_SET: Field = Field {
    address: 0x5100,
    stride: 0x0,
    mask: 0x00000008,
    shift: 3,
};
pub(super) const RPFL2UNICAST_DEST_ADDRESSLSW_SET: Field = Field {
    address: 0x5110,
    stride: 0x8,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const RPFL2UNICAST_DEST_ADDRESSMSW_SET: Field = Field {
    address: 0x5114,
    stride: 0x8,
    mask: 0x0000ffff,
    shift: 0,
};
pub(super) const RPFL2UNICAST_FLR_ACT_SET: Field = Field {
    address: 0x5114,
    stride: 0x8,
    mask: 0x00070000,
    shift: 16,
};
pub(super) const RPFL2_ACCEPT_ALL_MC_PACKETS_SET: Field = Field {
    address: 0x5270,
    stride: 0x0,
    mask: 0x00004000,
    shift: 14,
};
pub(super) const RPFL2_UC_FLR_EN_SET: Field = Field {
    address: 0x5114,
    stride: 0x8,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const RPF_RSS_KEY_ADDR_SET: Field = Field {
    address: 0x54d0,
    stride: 0x0,
    mask: 0x0000001f,
    shift: 0,
};
pub(super) const RPF_RSS_KEY_WR_DATA_SET: Field = Field {
    address: 0x54d4,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const RPF_RSS_KEY_WR_EN_SET: Field = Field {
    address: 0x54d0,
    stride: 0x0,
    mask: 0x00000020,
    shift: 5,
};
pub(super) const RPF_VLAN_ACCEPT_UNTAGGED_PACKETS_SET: Field = Field {
    address: 0x5280,
    stride: 0x0,
    mask: 0x00000004,
    shift: 2,
};
pub(super) const RPF_VLAN_INNER_ETHT_SET: Field = Field {
    address: 0x5284,
    stride: 0x0,
    mask: 0x0000ffff,
    shift: 0,
};
pub(super) const RPF_VLAN_OUTER_ETHT_SET: Field = Field {
    address: 0x5284,
    stride: 0x0,
    mask: 0xffff0000,
    shift: 16,
};
pub(super) const RPF_VLAN_PROM_MODE_EN_SET: Field = Field {
    address: 0x5280,
    stride: 0x0,
    mask: 0x00000002,
    shift: 1,
};
pub(super) const RPF_VLAN_UNTAGGED_ACT_SET: Field = Field {
    address: 0x5280,
    stride: 0x0,
    mask: 0x00000038,
    shift: 3,
};
pub(super) const RPO_IPV4HEADER_CRC_OFFLOAD_EN_SET: Field = Field {
    address: 0x5580,
    stride: 0x0,
    mask: 0x00000002,
    shift: 1,
};
pub(super) const RPO_LRO_EN_SET: Field = Field {
    address: 0x5590,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const RPO_OUTER_VLAN_TAG_MODE_SET: Field = Field {
    address: 0x5580,
    stride: 0x0,
    mask: 0x00000004,
    shift: 2,
};
pub(super) const RPO_RX_DESC_VLAN_STRIPPING_SET: Field = Field {
    address: 0x5b08,
    stride: 0x20,
    mask: 0x20000000,
    shift: 29,
};
pub(super) const RPO_TCP_UDP_CRC_OFFLOAD_EN_SET: Field = Field {
    address: 0x5580,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const RX_RX_REG_RES_DIS_SET: Field = Field {
    address: 0x5000,
    stride: 0x0,
    mask: 0x20000000,
    shift: 29,
};
pub(super) const RX_TAIL: Field = Field {
    address: 0x5b10,
    stride: 0x20,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const TDM_LARGE_SEND_OFFLOAD_EN_SET: Field = Field {
    address: 0x7810,
    stride: 0x0,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const TDM_TX_DCA_EN_SET: Field = Field {
    address: 0x8480,
    stride: 0x0,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const TDM_TX_DCA_MODE_SET: Field = Field {
    address: 0x8480,
    stride: 0x0,
    mask: 0x0000000f,
    shift: 0,
};
pub(super) const TDM_TX_DESC_DCA_EN_SET: Field = Field {
    address: 0x8400,
    stride: 0x4,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const TDM_TX_DESC_EN_SET: Field = Field {
    address: 0x7c08,
    stride: 0x40,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const TDM_TX_DESC_LEN_SET: Field = Field {
    address: 0x7c08,
    stride: 0x40,
    mask: 0x00001ff8,
    shift: 3,
};
pub(super) const TDM_TX_DESC_WR_WB_IRQ_EN_SET: Field = Field {
    address: 0x7b40,
    stride: 0x0,
    mask: 0x00000002,
    shift: 1,
};
pub(super) const TDM_TX_DESC_WR_WB_THRESHOLD_SET: Field = Field {
    address: 0x7c18,
    stride: 0x40,
    mask: 0x00007f00,
    shift: 8,
};
pub(super) const THM_LSO_TCP_FLAG_OF_FIRST_PKT_SET: Field = Field {
    address: 0x7820,
    stride: 0x0,
    mask: 0x00000fff,
    shift: 0,
};
pub(super) const THM_LSO_TCP_FLAG_OF_LAST_PKT_SET: Field = Field {
    address: 0x7824,
    stride: 0x0,
    mask: 0x00000fff,
    shift: 0,
};
pub(super) const THM_LSO_TCP_FLAG_OF_MIDDLE_PKT_SET: Field = Field {
    address: 0x7820,
    stride: 0x0,
    mask: 0x0fff0000,
    shift: 16,
};
pub(super) const TPB_TPS_TX_TC_MODE_SET: Field = Field {
    address: 0x7900,
    stride: 0x0,
    mask: 0x00000100,
    shift: 8,
};
pub(super) const TPB_TX_BUFF_EN_SET: Field = Field {
    address: 0x7900,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const TPB_TX_BUFF_HI_THRESHOLD_PER_TC_SET: Field = Field {
    address: 0x7914,
    stride: 0x10,
    mask: 0x1fff0000,
    shift: 16,
};
pub(super) const TPB_TX_BUFF_LO_THRESHOLD_PER_TC_SET: Field = Field {
    address: 0x7914,
    stride: 0x10,
    mask: 0x00001fff,
    shift: 0,
};
pub(super) const TPB_TX_PATH_SCP_INS_EN_SET: Field = Field {
    address: 0x7900,
    stride: 0x0,
    mask: 0x00000004,
    shift: 2,
};
pub(super) const TPB_TX_PKT_BUFF_SIZE_PER_TC_SET: Field = Field {
    address: 0x7910,
    stride: 0x10,
    mask: 0x000000ff,
    shift: 0,
};
pub(super) const TPO_IPV4HEADER_CRC_OFFLOAD_EN_SET: Field = Field {
    address: 0x7800,
    stride: 0x0,
    mask: 0x00000002,
    shift: 1,
};
pub(super) const TPO_TCP_UDP_CRC_OFFLOAD_EN_SET: Field = Field {
    address: 0x7800,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const TPS_TX_DESC_RATE_EN_SET: Field = Field {
    address: 0x7408,
    stride: 0x10,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const TPS_TX_DESC_RATE_MODE_SET: Field = Field {
    address: 0x7900,
    stride: 0x0,
    mask: 0x00000080,
    shift: 7,
};
pub(super) const TPS_TX_DESC_RATE_X_SET: Field = Field {
    address: 0x7408,
    stride: 0x10,
    mask: 0x03ff0000,
    shift: 16,
};
pub(super) const TPS_TX_DESC_RATE_Y_SET: Field = Field {
    address: 0x7408,
    stride: 0x10,
    mask: 0x00003fff,
    shift: 0,
};
pub(super) const TPS_TX_PKT_SHED_DATA_ARB_MODE_SET: Field = Field {
    address: 0x7100,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const TPS_TX_PKT_SHED_DESC_RATE_CURR_TIME_RES_SET: Field = Field {
    address: 0x7310,
    stride: 0x0,
    mask: 0x80000000,
    shift: 31,
};
pub(super) const TPS_TX_PKT_SHED_DESC_RATE_LIM_SET: Field = Field {
    address: 0x7310,
    stride: 0x0,
    mask: 0x000007ff,
    shift: 0,
};
pub(super) const TPS_TX_PKT_SHED_DESC_TC_ARB_MODE_SET: Field = Field {
    address: 0x7200,
    stride: 0x0,
    mask: 0x00000003,
    shift: 0,
};
pub(super) const TPS_TX_PKT_SHED_DESC_TC_MAX_CREDIT_SET: Field = Field {
    address: 0x7210,
    stride: 0x4,
    mask: 0x0fff0000,
    shift: 16,
};
pub(super) const TPS_TX_PKT_SHED_DESC_TC_WEIGHT_SET: Field = Field {
    address: 0x7210,
    stride: 0x4,
    mask: 0x000001ff,
    shift: 0,
};
pub(super) const TPS_TX_PKT_SHED_DESC_VM_ARB_MODE_SET: Field = Field {
    address: 0x7300,
    stride: 0x0,
    mask: 0x00000001,
    shift: 0,
};
pub(super) const TPS_TX_PKT_SHED_TC_DATA_MAX_CREDIT_SET: Field = Field {
    address: 0x7110,
    stride: 0x4,
    mask: 0x0fff0000,
    shift: 16,
};
pub(super) const TPS_TX_PKT_SHED_TC_DATA_WEIGHT_SET: Field = Field {
    address: 0x7110,
    stride: 0x4,
    mask: 0x000001ff,
    shift: 0,
};
pub(super) const TX_HEAD: Field = Field {
    address: 0x7c0c,
    stride: 0x40,
    mask: 0x00001fff,
    shift: 0,
};
pub(super) const TX_TAIL: Field = Field {
    address: 0x7c10,
    stride: 0x40,
    mask: 0xffffffff,
    shift: 0,
};
pub(super) const TX_TX_REG_RES_DIS_SET: Field = Field {
    address: 0x7000,
    stride: 0x0,
    mask: 0x20000000,
    shift: 29,
};
