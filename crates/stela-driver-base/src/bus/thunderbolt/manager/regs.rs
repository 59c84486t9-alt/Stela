// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Router and adapter registers from Linux tb_regs.h.

pub const ROUTER_CS_1: u16 = 0x01;
pub const ROUTER_CS_3_V: u32 = 1 << 31;
pub const ROUTER_CS_5: u16 = 0x05;
pub const ROUTER_CS_5_CNS: u32 = 1 << 23;
pub const ROUTER_CS_5_PTO: u32 = 1 << 24;
pub const ROUTER_CS_5_UTO: u32 = 1 << 25;
pub const ROUTER_CS_5_HCO: u32 = 1 << 26;
pub const ROUTER_CS_5_CV: u32 = 1 << 31;
pub const ROUTER_CS_6: u16 = 0x06;
pub const ROUTER_CS_6_HCI: u32 = 1 << 18;
pub const ROUTER_CS_6_RR: u32 = 1 << 24;
pub const ROUTER_CS_6_CR: u32 = 1 << 25;
pub const ROUTER_CS_7: u16 = 0x07;
pub const ROUTER_CS_9: u16 = 0x09;
pub const ROUTER_CS_25: u16 = 0x19;
pub const ROUTER_CS_26: u16 = 0x1a;
pub const ROUTER_CS_26_STATUS_SHIFT: u32 = 24;
pub const ROUTER_CS_26_STATUS_MASK: u32 = 0x3f << ROUTER_CS_26_STATUS_SHIFT;
pub const ROUTER_CS_26_ONS: u32 = 1 << 30;
pub const ROUTER_CS_26_OV: u32 = 1 << 31;
pub const CMUV_V1: u32 = 0x10;
/// `TMU_ACCESS_EN`, in a router register of the oldest controllers.
pub const TMU_ACCESS_ENABLE: u32 = 1 << 20;
pub const CMUV_V2: u32 = 0x20;

pub const OP_QUERY_DP_RESOURCE: u16 = 0x10;
pub const OP_ALLOC_DP_RESOURCE: u16 = 0x11;
pub const OP_DEALLOC_DP_RESOURCE: u16 = 0x12;
pub const OP_DROM_READ: u16 = 0x24;
pub const OP_BUFFER_ALLOC: u16 = 0x33;
/// `USB4_DROM_ADDRESS_SHIFT` and `USB4_DROM_SIZE_SHIFT` of the metadata.
pub const DROM_ADDRESS_SHIFT: u32 = 2;
pub const DROM_SIZE_SHIFT: u32 = 15;
pub const DROM_RETRIES: usize = 3;

/// Vendor-specific capabilities of routers from before USB4.
pub const VSE_PLUG_EVENTS: u8 = 0x01;
pub const VSE_TIME: u8 = 0x03;
pub const VSE_LINK_CONTROLLER: u8 = 0x06;
pub const PLUG_EVENTS_USB_DISABLE: u32 = 1 << 2;
/// The event enables of `TB_VSE_CAP_PLUG_EVENTS`, each active low.
pub const PLUG_EVENTS_DISABLE: u32 = 0x7c;
pub const EEPROM_CTL: u16 = 0x04;
pub const EEPROM_SK: u32 = 1 << 0;
pub const EEPROM_CS: u32 = 1 << 1;
pub const EEPROM_DI: u32 = 1 << 2;
pub const EEPROM_DO: u32 = 1 << 3;
pub const EEPROM_ENABLE: u32 = 1 << 4;
pub const EEPROM_NOT_PRESENT: u32 = 1 << 5;
pub const EEPROM_PRESENT: u32 = 1 << 7;
pub const DROM_OFFSET: u16 = 0x0c;
pub const TIME_VSEC_CS_26: u16 = 0x1a;
pub const TIME_VSEC_CS_26_TD: u32 = 1 << 22;
pub const LC_DESC: u16 = 0x02;
pub const LC_DESC_SIZE_SHIFT: u32 = 8;
pub const LC_DESC_PORT_SIZE_SHIFT: u32 = 16;
pub const LC_FUSE: u16 = 0x03;
pub const LC_SNK_ALLOCATION: u16 = 0x10;
pub const LC_SNK_ALLOCATION_MASK: u32 = 0xf;
pub const LC_SNK_ALLOCATION_CM: u32 = 0x1;
pub const LC_SNK_ALLOCATION_SNK1_SHIFT: u32 = 4;
pub const LC_CS_42: u16 = 0x2a;
pub const LC_CS_42_USB_PLUGGED: u32 = 1 << 31;
pub const LC_LINK_REQ: u16 = 0xad;
pub const LC_LINK_REQ_XHCI_CONNECT: u32 = 1 << 31;
pub const LC_PORT_ATTR: u16 = 0x8d;
pub const LC_PORT_ATTR_BE: u32 = 1 << 12;
pub const LC_SX_CTRL: u16 = 0x96;
pub const LC_SX_CTRL_L1C: u32 = 1 << 16;
pub const LC_SX_CTRL_L2C: u32 = 1 << 20;
pub const LC_SX_CTRL_UPSTREAM: u32 = 1 << 30;
pub const OP_DATA_WORDS: usize = 16;
pub const BA_MAX_USB3: u16 = 1;
pub const BA_MIN_DP_AUX: u16 = 2;
pub const BA_MIN_DP_MAIN: u16 = 3;
pub const BA_MAX_PCIE: u16 = 4;
pub const BA_MAX_HI: u16 = 5;

pub const CAP_PHY: u8 = 0x01;
pub const CAP_TIME: u8 = 0x03;
pub const CAP_ADAPTER: u8 = 0x04;
pub const CAP_VENDOR: u8 = 0x05;
pub const CAP_USB4: u8 = 0x06;

pub const PORT_STATE_DISABLED: u32 = 0;
pub const PORT_STATE_UP: u32 = 2;
pub const PORT_STATE_CL2: u32 = 6;
pub const PORT_STATE_UNPLUGGED: u32 = 7;

pub const ADP_CS_4: u16 = 0x04;
pub const ADP_CS_4_NFC_BUFFERS: u32 = 0x3ff;
pub const ADP_CS_4_TOTAL_SHIFT: u32 = 20;
pub const ADP_CS_4_TOTAL_BUFFERS: u32 = 0x3ff << ADP_CS_4_TOTAL_SHIFT;
pub const ADP_CS_4_LCK: u32 = 1 << 31;
pub const ADP_CS_5: u16 = 0x05;
pub const ADP_CS_5_DHP: u32 = 1 << 31;

pub const LANE_ADP_CS_0: u16 = 0x00;
pub const LANE_ADP_CS_0_WIDTH_SHIFT: u32 = 20;
pub const LANE_ADP_CS_1: u16 = 0x01;
pub const LANE_ADP_CS_1_TARGET_WIDTH: u32 = 3 << 4;
pub const LANE_ADP_CS_1_TARGET_DUAL: u32 = 3 << 4;
pub const LANE_ADP_CS_1_LB: u32 = 1 << 15;
pub const LANE_ADP_CS_1_SPEED_SHIFT: u32 = 16;
pub const LANE_ADP_CS_1_WIDTH_SHIFT: u32 = 20;
pub const LANE_ADP_CS_1_GEN3: u32 = 0x4;
pub const LANE_ADP_CS_1_GEN4: u32 = 0x2;

pub const WIDTH_SINGLE: u32 = 1;
pub const WIDTH_DUAL: u32 = 2;
pub const WIDTH_ASYM_TX: u32 = 4;
pub const WIDTH_ASYM_RX: u32 = 8;

pub const PORT_CS_18: u16 = 0x12;
pub const PORT_CS_18_BE: u32 = 1 << 8;
pub const PORT_CS_18_TCM: u32 = 1 << 9;
pub const PORT_CS_19: u16 = 0x13;
pub const PORT_CS_19_DPR: u32 = 1 << 0;
pub const PORT_CS_19_PC: u32 = 1 << 3;

pub const ADP_DP_CS_0: u16 = 0x00;
pub const ADP_DP_CS_0_VIDEO_SHIFT: u32 = 16;
pub const ADP_DP_CS_0_VIDEO: u32 = 0x7ff << ADP_DP_CS_0_VIDEO_SHIFT;
pub const ADP_DP_CS_0_AE: u32 = 1 << 30;
pub const ADP_DP_CS_0_VE: u32 = 1 << 31;
pub const ADP_DP_CS_1_AUX_TX: u32 = 0x7ff;
pub const ADP_DP_CS_1_AUX_RX_SHIFT: u32 = 11;
pub const ADP_DP_CS_1_AUX_RX: u32 = 0x7ff << ADP_DP_CS_1_AUX_RX_SHIFT;
pub const ADP_DP_CS_2: u16 = 0x02;
pub const ADP_DP_CS_2_HPD: u32 = 1 << 6;
pub const ADP_DP_CS_3: u16 = 0x03;
pub const ADP_DP_CS_3_HPDC: u32 = 1 << 9;
pub const DP_LOCAL_CAP: u16 = 0x04;
pub const DP_REMOTE_CAP: u16 = 0x05;
pub const DP_STATUS_CTRL: u16 = 0x06;
pub const DP_STATUS_CTRL_CMHS: u32 = 1 << 25;
pub const DP_STATUS_CTRL_UF: u32 = 1 << 26;
pub const DP_COMMON_CAP: u16 = 0x07;
pub const DP_CAP_RATE_SHIFT: u32 = 8;
pub const DP_CAP_RATE: u32 = 0xf << DP_CAP_RATE_SHIFT;
pub const DP_CAP_LANES_SHIFT: u32 = 12;
pub const DP_CAP_LANES: u32 = 7 << DP_CAP_LANES_SHIFT;
pub const DP_COMMON_CAP_DPRX_DONE: u32 = 1 << 31;
pub const DP_COMMON_CAP_LTTPR_NS: u32 = 1 << 27;

pub const ADP_PCIE_CS_0: u16 = 0x00;
pub const ADP_PCIE_CS_0_LTSSM_SHIFT: u32 = 25;
pub const ADP_PCIE_CS_0_LTSSM: u32 = 0xf << ADP_PCIE_CS_0_LTSSM_SHIFT;
pub const ADP_PCIE_CS_0_PE: u32 = 1 << 31;
pub const ADP_PCIE_CS_1: u16 = 0x01;
pub const ADP_PCIE_CS_1_EE: u32 = 1 << 0;

pub const ADP_USB3_CS_0: u16 = 0x00;
pub const ADP_USB3_CS_0_V: u32 = 1 << 30;
pub const ADP_USB3_CS_0_PE: u32 = 1 << 31;
pub const ADP_USB3_CS_1: u16 = 0x01;
pub const ADP_USB3_CS_1_CUBW: u32 = 0xfff;
pub const ADP_USB3_CS_1_CDBW_SHIFT: u32 = 12;
pub const ADP_USB3_CS_1_HCA: u32 = 1 << 31;
pub const ADP_USB3_CS_2: u16 = 0x02;
pub const ADP_USB3_CS_2_AUBW: u32 = 0xfff;
pub const ADP_USB3_CS_2_ADBW_SHIFT: u32 = 12;
pub const ADP_USB3_CS_2_ADBW: u32 = 0xfff << ADP_USB3_CS_2_ADBW_SHIFT;
pub const ADP_USB3_CS_2_CMR: u32 = 1 << 31;
pub const ADP_USB3_CS_3: u16 = 0x03;
pub const ADP_USB3_CS_3_SCALE: u32 = 0x3f;
pub const ADP_USB3_CS_4: u16 = 0x04;
pub const ADP_USB3_CS_4_MSLR_SHIFT: u32 = 12;
pub const ADP_USB3_CS_4_MSLR: u32 = 0x7f << ADP_USB3_CS_4_MSLR_SHIFT;
pub const ADP_USB3_CS_4_MSLR_20G: u32 = 1;

pub const TMU_RTR_CS_0: u16 = 0x00;
pub const TMU_RTR_CS_0_FREQ_WIND_SHIFT: u32 = 16;
pub const TMU_RTR_CS_0_FREQ_WIND: u32 = 0x7ff << TMU_RTR_CS_0_FREQ_WIND_SHIFT;
pub const TMU_RTR_CS_0_TD: u32 = 1 << 27;
pub const TMU_RTR_CS_0_UCAP: u32 = 1 << 30;
pub const TMU_RTR_CS_1: u16 = 0x01;
pub const TMU_RTR_CS_1_LOCAL_TIME_SHIFT: u32 = 16;
pub const TMU_RTR_CS_3: u16 = 0x03;
pub const TMU_RTR_CS_3_LOCAL_TIME: u32 = 0xffff;
pub const TMU_RTR_CS_3_INTERVAL_SHIFT: u32 = 16;
pub const TMU_RTR_CS_3_INTERVAL: u32 = 0xffff << TMU_RTR_CS_3_INTERVAL_SHIFT;
pub const TMU_RTR_CS_15: u16 = 0x0f;
pub const TMU_RTR_CS_15_AVERAGES: u32 = 0x00ff_ffff;
pub const TMU_RTR_CS_18: u16 = 0x12;
pub const TMU_RTR_CS_18_DELTA_AVG_SHIFT: u32 = 16;
pub const TMU_RTR_CS_18_DELTA_AVG: u32 = 0xff << TMU_RTR_CS_18_DELTA_AVG_SHIFT;
pub const TMU_RTR_CS_22: u16 = 0x16;
pub const TMU_RTR_CS_24: u16 = 0x18;
pub const TMU_RTR_CS_25: u16 = 0x19;
pub const TMU_ADP_CS_3: u16 = 0x03;
pub const TMU_ADP_CS_3_UDM: u32 = 1 << 29;
pub const TMU_ADP_CS_6: u16 = 0x06;
pub const TMU_ADP_CS_6_DTS: u32 = 1 << 1;
pub const TMU_ADP_CS_8: u16 = 0x08;
pub const TMU_ADP_CS_8_REPL_TIMEOUT: u32 = 0x7fff;
pub const TMU_ADP_CS_8_EUDM: u32 = 1 << 15;
pub const TMU_ADP_CS_8_REPL_THRESHOLD_SHIFT: u32 = 16;
pub const TMU_ADP_CS_8_REPL_THRESHOLD: u32 = 0x3ff << TMU_ADP_CS_8_REPL_THRESHOLD_SHIFT;
pub const TMU_ADP_CS_9: u16 = 0x09;
pub const TMU_ADP_CS_9_REPL_N: u32 = 0xff;
pub const TMU_ADP_CS_9_DIRSWITCH_SHIFT: u32 = 8;
pub const TMU_ADP_CS_9_DIRSWITCH: u32 = 0xff << TMU_ADP_CS_9_DIRSWITCH_SHIFT;
pub const TMU_ADP_CS_9_INTERVAL_SHIFT: u32 = 16;
pub const TMU_ADP_CS_9_INTERVAL: u32 = 0xffff << TMU_ADP_CS_9_INTERVAL_SHIFT;

pub const HOP_ENABLE: u32 = 1 << 31;
pub const HOP_PENDING: u32 = 1 << 28;
pub const HOP_INITIAL_CREDITS_SHIFT: u32 = 17;
pub const HOP_INGRESS_FC: u32 = 1 << 24;
pub const HOP_EGRESS_FC: u32 = 1 << 25;
pub const HOP_INGRESS_SHARED: u32 = 1 << 26;
pub const HOP_EGRESS_SHARED: u32 = 1 << 27;
