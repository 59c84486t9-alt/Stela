// SPDX-License-Identifier: GPL-2.0-or-later AND ISC
// Copyright (c) 2013 Johannes Berg <johannes@sipsolutions.net>
// Copyright (c) 2012 Qualcomm Atheros, Inc.
// Copyright (c) 2026 Stela contributors
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//! The registers, fields and PHY addresses of Linux `alx/reg.h` and `hw.h`
//! that the polled single-queue path uses.

pub(super) const REV_SHIFT: u8 = 3;
pub(super) const REV_A0: u8 = 0;
pub(super) const REV_A1: u8 = 1;
pub(super) const REV_B0: u8 = 2;
pub(super) const REV_C0: u8 = 3;

/// PCI Express Device Control's maximum read request size, as 128 << n.
pub(super) const DEV_CTRL_MAXRRS_MIN: u32 = 2;

pub(super) const UE_SVRT: usize = 0x010c;
pub(super) const UE_SVRT_FCPROTERR: u32 = 1 << 13;
pub(super) const UE_SVRT_DLPROTERR: u32 = 1 << 4;

pub(super) const EFLD: usize = 0x0204;
pub(super) const EFLD_F_EXIST: u32 = 1 << 10;
pub(super) const EFLD_E_EXIST: u32 = 1 << 9;
pub(super) const EFLD_STAT: u32 = 1 << 5;
pub(super) const EFLD_START: u32 = 1 << 0;

pub(super) const SLD: usize = 0x0218;
pub(super) const SLD_STAT: u32 = 1 << 12;
pub(super) const SLD_START: u32 = 1 << 11;
pub(super) const SLD_MAX_TO: usize = 100;

pub(super) const PDLL_TRNS1: usize = 0x1104;
pub(super) const PDLL_TRNS1_D3PLLOFF_EN: u32 = 1 << 11;

pub(super) const PMCTRL: usize = 0x12f8;
pub(super) const PMCTRL_HOTRST_WTEN: u32 = 1 << 31;
pub(super) const PMCTRL_ASPM_FCEN: u32 = 1 << 30;
pub(super) const PMCTRL_SADLY_EN: u32 = 1 << 29;
pub(super) const PMCTRL_LCKDET_TIMER: (u32, u32) = (0xf, 24);
pub(super) const PMCTRL_LCKDET_TIMER_DEF: u32 = 0xc;
pub(super) const PMCTRL_L1REQ_TO: (u32, u32) = (0xf, 20);
pub(super) const PMCTRL_L1REG_TO_DEF: u32 = 0xf;
pub(super) const PMCTRL_TXL1_AFTER_L0S: u32 = 1 << 19;
pub(super) const PMCTRL_L1_TIMER: (u32, u32) = (0x7, 16);
pub(super) const PMCTRL_L1_TIMER_16US: u32 = 4;
pub(super) const PMCTRL_RCVR_WT_1US: u32 = 1 << 15;
pub(super) const PMCTRL_L1_CLKSW_EN: u32 = 1 << 13;
pub(super) const PMCTRL_L0S_EN: u32 = 1 << 12;
pub(super) const PMCTRL_RXL1_AFTER_L0S: u32 = 1 << 11;
pub(super) const PMCTRL_L1_BUFSRX_EN: u32 = 1 << 7;
pub(super) const PMCTRL_L1_SRDSRX_PWD: u32 = 1 << 6;
pub(super) const PMCTRL_L1_SRDSPLL_EN: u32 = 1 << 5;
pub(super) const PMCTRL_L1_SRDS_EN: u32 = 1 << 4;
pub(super) const PMCTRL_L1_EN: u32 = 1 << 3;

pub(super) const MASTER: usize = 0x1400;
pub(super) const MASTER_PCLKSEL_SRDS: u32 = 1 << 12;
pub(super) const MASTER_IRQMOD2_EN: u32 = 1 << 11;
pub(super) const MASTER_IRQMOD1_EN: u32 = 1 << 10;
pub(super) const MASTER_SYSALVTIMER_EN: u32 = 1 << 7;
pub(super) const MASTER_OOB_DIS: u32 = 1 << 6;
pub(super) const MASTER_WAKEN_25M: u32 = 1 << 5;
pub(super) const MASTER_DMA_MAC_RST: u32 = 1 << 0;
pub(super) const DMA_MAC_RST_TO: usize = 50;

pub(super) const IRQ_MODU_TIMER: usize = 0x1408;

pub(super) const PHY_CTRL: usize = 0x140c;
pub(super) const PHY_CTRL_100AB_EN: u32 = 1 << 17;
pub(super) const PHY_CTRL_POWER_DOWN: u32 = 1 << 14;
pub(super) const PHY_CTRL_PLL_ON: u32 = 1 << 13;
pub(super) const PHY_CTRL_RST_ANALOG: u32 = 1 << 12;
pub(super) const PHY_CTRL_HIB_PULSE: u32 = 1 << 11;
pub(super) const PHY_CTRL_HIB_EN: u32 = 1 << 10;
pub(super) const PHY_CTRL_IDDQ: u32 = 1 << 7;
pub(super) const PHY_CTRL_GATE_25M: u32 = 1 << 5;
pub(super) const PHY_CTRL_LED_MODE: u32 = 1 << 2;
pub(super) const PHY_CTRL_DSPRST_OUT: u32 = 1 << 0;
pub(super) const PHY_CTRL_DSPRST_TO: u64 = 80;
pub(super) const PHY_CTRL_CLS: u32 = PHY_CTRL_LED_MODE | PHY_CTRL_100AB_EN | PHY_CTRL_PLL_ON;

pub(super) const MAC_STS: usize = 0x1410;
pub(super) const MAC_STS_IDLE: u32 = 0xf;

pub(super) const MDIO: usize = 0x1414;
pub(super) const MDIO_MODE_EXT: u32 = 1 << 30;
pub(super) const MDIO_BUSY: u32 = 1 << 27;
pub(super) const MDIO_CLK_SEL_SHIFT: u32 = 24;
pub(super) const MDIO_CLK_SEL_25MD4: u32 = 0;
pub(super) const MDIO_CLK_SEL_25MD128: u32 = 7;
pub(super) const MDIO_START: u32 = 1 << 23;
pub(super) const MDIO_SPRES_PRMBL: u32 = 1 << 22;
pub(super) const MDIO_OP_READ: u32 = 1 << 21;
pub(super) const MDIO_REG_SHIFT: u32 = 16;
pub(super) const MDIO_MAX_AC_TO: usize = 120;
pub(super) const MDIO_EXTN: usize = 0x1448;
pub(super) const MDIO_EXTN_DEVAD_SHIFT: u32 = 16;

pub(super) const SERDES: usize = 0x1424;
pub(super) const SERDES_PHYCLK_SLWDWN: u32 = 1 << 18;
pub(super) const SERDES_MACCLK_SLWDWN: u32 = 1 << 17;

pub(super) const LPI_CTRL: usize = 0x1440;
pub(super) const LPI_CTRL_EN: u32 = 1 << 0;

pub(super) const IDLE_DECISN_TIMER: usize = 0x1474;
pub(super) const IDLE_DECISN_TIMER_DEF: u32 = 0x400;

pub(super) const MAC_CTRL: usize = 0x1480;
pub(super) const MAC_CTRL_WOLSPED_SWEN: u32 = 1 << 30;
pub(super) const MAC_CTRL_MHASH_ALG_HI5B: u32 = 1 << 29;
pub(super) const MAC_CTRL_BRD_EN: u32 = 1 << 26;
pub(super) const MAC_CTRL_MULTIALL_EN: u32 = 1 << 25;
pub(super) const MAC_CTRL_SPEED: (u32, u32) = (0x3, 20);
pub(super) const MAC_CTRL_SPEED_10_100: u32 = 1;
pub(super) const MAC_CTRL_SPEED_1000: u32 = 2;
pub(super) const MAC_CTRL_PROMISC_EN: u32 = 1 << 15;
pub(super) const MAC_CTRL_PRMBLEN_SHIFT: u32 = 10;
pub(super) const MAC_CTRL_PCRCE: u32 = 1 << 7;
pub(super) const MAC_CTRL_CRCE: u32 = 1 << 6;
pub(super) const MAC_CTRL_FULLD: u32 = 1 << 5;
pub(super) const MAC_CTRL_RXFC_EN: u32 = 1 << 3;
pub(super) const MAC_CTRL_TXFC_EN: u32 = 1 << 2;
pub(super) const MAC_CTRL_RX_EN: u32 = 1 << 1;
pub(super) const MAC_CTRL_TX_EN: u32 = 1 << 0;

pub(super) const STAD0: usize = 0x1488;
pub(super) const STAD1: usize = 0x148c;
pub(super) const MTU: usize = 0x149c;
pub(super) const MTU_JUMBO_TH: u32 = 1514;
pub(super) const MTU_STD_ALGN: u32 = 1536;
pub(super) const WOL0: usize = 0x14a0;

pub(super) const SRAM5: usize = 0x1524;
pub(super) const SRAM_RXF_LEN: (u32, u32) = (0xfff, 0);
pub(super) const SRAM_RXF_LEN_8K: u32 = 8 * 1024;
pub(super) const SRAM9: usize = 0x1534;
pub(super) const SRAM_LOAD_PTR: u32 = 1 << 0;

pub(super) const RX_BASE_ADDR_HI: usize = 0x1540;
pub(super) const TX_BASE_ADDR_HI: usize = 0x1544;
pub(super) const RFD_ADDR_LO: usize = 0x1550;
pub(super) const RFD_RING_SZ: usize = 0x1560;
pub(super) const RFD_BUF_SZ: usize = 0x1564;
pub(super) const RRD_ADDR_LO: usize = 0x1568;
pub(super) const RRD_RING_SZ: usize = 0x1578;
pub(super) const TPD_PRI0_ADDR_LO: usize = 0x1580;
pub(super) const TPD_RING_SZ: usize = 0x1584;

pub(super) const TXQ0: usize = 0x1590;
pub(super) const TXQ0_TXF_BURST_PREF_SHIFT: u32 = 16;
pub(super) const TXQ_TXF_BURST_PREF_DEF: u32 = 0x200;
pub(super) const TXQ0_LSO_8023_EN: u32 = 1 << 7;
pub(super) const TXQ0_MODE_ENHANCE: u32 = 1 << 6;
pub(super) const TXQ0_EN: u32 = 1 << 5;
pub(super) const TXQ0_SUPT_IPOPT: u32 = 1 << 4;
pub(super) const TXQ_TPD_BURSTPREF_DEF: u32 = 5;
pub(super) const TXQ1: usize = 0x1594;
pub(super) const TXQ1_ERRLGPKT_DROP_EN: u32 = 1 << 11;
pub(super) const TXQ1_JUMBO_TSO_TH: u32 = 7 * 1024;

pub(super) const RXQ0: usize = 0x15a0;
pub(super) const RXQ0_EN: u32 = 1 << 31;
pub(super) const RXQ0_RSS_HASH_EN: u32 = 1 << 29;
pub(super) const RXQ0_RSS_MODE_SHIFT: u32 = 26;
pub(super) const RXQ0_RSS_MODE_DIS: u32 = 0;
pub(super) const RXQ0_NUM_RFD_PREF_SHIFT: u32 = 20;
pub(super) const RXQ0_NUM_RFD_PREF_DEF: u32 = 8;
pub(super) const RXQ0_IDT_TBL_SIZE_SHIFT: u32 = 8;
pub(super) const RXQ0_IDT_TBL_SIZE_DEF: u32 = 0x100;
pub(super) const RXQ0_IPV6_PARSE_EN: u32 = 1 << 7;
pub(super) const RXQ0_RSS_HSTYP_ALL: u32 = 0xf << 2;
pub(super) const RXQ0_ASPM_THRESH: (u32, u32) = (0x3, 0);
pub(super) const RXQ0_ASPM_THRESH_100M: u32 = 3;
pub(super) const RXQ2: usize = 0x15a8;
pub(super) const RXQ2_RXF_XOFF_THRESH_SHIFT: u32 = 16;
pub(super) const RXQ2_RXF_FLOW_CTRL_RSVD: u32 = 3212;

pub(super) const DMA: usize = 0x15c0;
pub(super) const DMA_RCHNL_SEL_SHIFT: u32 = 26;
pub(super) const DMA_WDLY_CNT_SHIFT: u32 = 16;
pub(super) const DMA_WDLY_CNT_DEF: u32 = 4;
pub(super) const DMA_RDLY_CNT_SHIFT: u32 = 11;
pub(super) const DMA_RDLY_CNT_DEF: u32 = 15;
pub(super) const DMA_RREQ_PRI_DATA: u32 = 1 << 10;
pub(super) const DMA_RREQ_BLEN_SHIFT: u32 = 4;
pub(super) const DMA_RORDER_MODE_OUT: u32 = 4;
pub(super) const SMB_TIMER: usize = 0x15c4;
pub(super) const TINT_TPD_THRSHLD: usize = 0x15c8;
pub(super) const TINT_TIMER: usize = 0x15cc;

pub(super) const RFD_PIDX: usize = 0x15e0;
pub(super) const TPD_PRI0_PIDX: usize = 0x15f2;
pub(super) const TPD_PRI0_CIDX: usize = 0x15f6;

pub(super) const ISR: usize = 0x1600;
pub(super) const ISR_DIS: u32 = 1 << 31;
pub(super) const IMR: usize = 0x1604;
pub(super) const INT_RETRIG: usize = 0x1608;
pub(super) const INT_RETRIG_TO: u32 = 20000;
pub(super) const MSIX_MASK: usize = 0x0090;

pub(super) const DRV: usize = 0x1804;
pub(super) const DRV_PHY_AUTO: u32 = 1 << 28;
pub(super) const DRV_PHY_100: u32 = 1 << 26;
pub(super) const DRV_PHY_10: u32 = 1 << 25;
pub(super) const DRV_PHY_DUPLEX: u32 = 1 << 24;
pub(super) const DRV_PHY: (u32, u32) = (0xff, 21);
pub(super) const DRV_PHY_UNKNOWN: u32 = 0;
pub(super) const PHY_INITED: u16 = 0x003f;
pub(super) const CLK_GATE: usize = 0x1814;
pub(super) const CLK_GATE_ALL: u32 = 0x3f;

pub(super) const WRR: usize = 0x1938;
pub(super) const WRR_PRI_SHIFT: u32 = 29;
pub(super) const WRR_PRI_RESTRICT_NONE: u32 = 3;
pub(super) const HQTPD: usize = 0x193c;
pub(super) const HQTPD_BURST_EN: u32 = 1 << 31;

pub(super) const MISC: usize = 0x19c0;
pub(super) const MISC_PSW_OCP: (u32, u32) = (0x7, 21);
pub(super) const MISC_PSW_OCP_DEF: u32 = 0x7;
pub(super) const MISC_ISO_EN: u32 = 1 << 12;
pub(super) const MISC_INTNLOSC_OPEN: u32 = 1 << 3;
pub(super) const MSIC2: usize = 0x19c8;
pub(super) const MSIC2_CALB_START: u32 = 1 << 0;
pub(super) const MISC3: usize = 0x19cc;
pub(super) const MISC3_25M_BY_SW: u32 = 1 << 1;
pub(super) const MISC3_25M_NOTO_INTNL: u32 = 1 << 0;

// Clause 22 registers (include/uapi/linux/mii.h) and the vendor ones.
pub(super) const MII_BMCR: u16 = 0x00;
pub(super) const MII_BMSR: u16 = 0x01;
pub(super) const MII_PHYSID1: u16 = 0x02;
pub(super) const MII_PHYSID2: u16 = 0x03;
pub(super) const MII_ADVERTISE: u16 = 0x04;
pub(super) const MII_CTRL1000: u16 = 0x09;
pub(super) const BMCR_RESET: u16 = 0x8000;
pub(super) const BMCR_ANENABLE: u16 = 0x1000;
pub(super) const BMCR_ANRESTART: u16 = 0x0200;
pub(super) const BMSR_LSTATUS: u16 = 0x0004;
pub(super) const ADVERTISE_CSMA: u16 = 0x0001;
pub(super) const ADVERTISE_10_100: u16 = 0x01e0;
pub(super) const ADVERTISE_1000FULL: u16 = 0x0200;
/// `ADVERTISED_Pause`, which `alx_setup_speed_duplex` ORs into the MII
/// advertisement as it stands.
pub(super) const ETHTOOL_ADVERTISED_PAUSE: u16 = 1 << 13;

pub(super) const MII_GIGA_PSSR: u16 = 0x11;
pub(super) const GIGA_PSSR_SPD_DPLX_RESOLVED: u16 = 0x0800;
pub(super) const GIGA_PSSR_DPLX: u16 = 0x2000;
pub(super) const GIGA_PSSR_SPEED: u16 = 0xc000;
pub(super) const GIGA_PSSR_10MBS: u16 = 0x0000;
pub(super) const GIGA_PSSR_100MBS: u16 = 0x4000;
pub(super) const GIGA_PSSR_1000MBS: u16 = 0x8000;
pub(super) const MII_IER: u16 = 0x12;
pub(super) const IER_LINK_UP: u16 = 0x0400;
pub(super) const IER_LINK_DOWN: u16 = 0x0800;
pub(super) const MII_ISR: u16 = 0x13;
pub(super) const MII_DBG_ADDR: u16 = 0x1d;
pub(super) const MII_DBG_DATA: u16 = 0x1e;

pub(super) const MIIDBG_ANACTRL: u16 = 0x00;
pub(super) const ANACTRL_DEF: u16 = 0x02ef;
pub(super) const MIIDBG_SYSMODCTRL: u16 = 0x04;
pub(super) const SYSMODCTRL_IECHOADJ_DEF: u16 = 0xbb8b;
pub(super) const MIIDBG_SRDSYSMOD: u16 = 0x05;
pub(super) const SRDSYSMOD_DEF: u16 = 0x2c46;
pub(super) const MIIDBG_TST10BTCFG: u16 = 0x12;
pub(super) const TST10BTCFG_DEF: u16 = 0x4c04;
pub(super) const MIIDBG_AZ_ANADECT: u16 = 0x15;
pub(super) const AZ_ANADECT_DEF: u16 = 0x3220;
pub(super) const AZ_ANADECT_LONG: u16 = 0x3210;
pub(super) const MIIDBG_MSE16DB: u16 = 0x18;
pub(super) const MSE16DB_UP: u16 = 0x05ea;
pub(super) const MSE16DB_DOWN: u16 = 0x02ea;
pub(super) const MIIDBG_MSE20DB: u16 = 0x1c;
pub(super) const MSE20DB_TH: (u16, u16) = (0x7f, 2);
pub(super) const MSE20DB_TH_DEF: u16 = 0x2e;
pub(super) const MSE20DB_TH_HI: u16 = 0x54;
pub(super) const MIIDBG_AGC: u16 = 0x23;
pub(super) const AGC_2_VGA: (u16, u16) = (0x3f, 8);
pub(super) const AGC_LONG1G_LIMT: u16 = 40;
pub(super) const AGC_LONG100M_LIMT: u16 = 44;
pub(super) const MIIDBG_LEGCYPS: u16 = 0x29;
pub(super) const LEGCYPS_DEF: u16 = 0x129d;
pub(super) const MIIDBG_TST100BTCFG: u16 = 0x36;
pub(super) const TST100BTCFG_DEF: u16 = 0xe12c;
pub(super) const MIIDBG_GREENCFG2: u16 = 0x3d;
pub(super) const GREENCFG2_BP_GREEN: u16 = 0x8000;
pub(super) const GREENCFG2_GATE_DFSE_EN: u16 = 0x0080;

pub(super) const MIIEXT_PCS: u8 = 3;
pub(super) const MIIEXT_CLDCTRL3: u16 = 0x8003;
pub(super) const CLDCTRL3_BP_CABLE1TH_DET_GT: u16 = 0x8000;
pub(super) const MIIEXT_CLDCTRL5: u16 = 0x8005;
pub(super) const CLDCTRL5_BP_VD_HLFBIAS: u16 = 0x4000;
pub(super) const MIIEXT_CLDCTRL6: u16 = 0x8006;
pub(super) const CLDCTRL6_CAB_LEN: (u16, u16) = (0xff, 0);
pub(super) const CLDCTRL6_CAB_LEN_SHORT1G: u16 = 116;
pub(super) const CLDCTRL6_CAB_LEN_SHORT100M: u16 = 152;
pub(super) const MIIEXT_VDRVBIAS: u16 = 0x8062;
pub(super) const VDRVBIAS_DEF: u16 = 0x3;
pub(super) const MIIEXT_ANEG: u8 = 7;
pub(super) const MIIEXT_LOCAL_EEEADV: u16 = 0x3c;
pub(super) const MIIEXT_AFE: u16 = 0x801a;
pub(super) const AFE_10BT_100M_TH: u16 = 0x0040;
pub(super) const MIIEXT_S3DIG10: u16 = 0x8023;
pub(super) const MIIEXT_S3DIG10_DEF: u16 = 0;
pub(super) const MIIEXT_NLP78: u16 = 0x8027;
pub(super) const MIIEXT_NLP78_120M_DEF: u16 = 0x8a05;

// Descriptor fields (hw.h).
pub(super) const TPD_EOP: u32 = 1 << 31;
pub(super) const RRD_NOR: (u32, u32) = (0xf, 16);
pub(super) const RRD_SI: (u32, u32) = (0xfff, 20);
pub(super) const RRD_PKTLEN: u32 = 0x3fff;
pub(super) const RRD_ERR_RES: u32 = 1 << 20;
pub(super) const RRD_ERR_LEN: u32 = 1 << 30;
pub(super) const RRD_UPDATED: u32 = 1 << 31;

/// `ALX_GET_FIELD`.
pub(super) fn field(value: u32, (mask, shift): (u32, u32)) -> u32 {
    (value >> shift) & mask
}

/// `ALX_SET_FIELD`.
pub(super) fn set_field(value: u32, (mask, shift): (u32, u32), field: u32) -> u32 {
    (value & !(mask << shift)) | ((field & mask) << shift)
}

pub(super) fn field16(value: u16, (mask, shift): (u16, u16)) -> u16 {
    (value >> shift) & mask
}

pub(super) fn set_field16(value: u16, (mask, shift): (u16, u16), field: u16) -> u16 {
    (value & !(mask << shift)) | ((field & mask) << shift)
}
