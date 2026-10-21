// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2007 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! Hardware encodings from the pinned Linux igb register/PHY headers.

pub const CTRL: usize = 0x0000;
pub const STATUS: usize = 0x0008;
pub const EECD: usize = 0x0010;
pub const EERD: usize = 0x0014;
pub const CTRL_EXT: usize = 0x0018;
pub const MDIC: usize = 0x0020;
pub const RCTL: usize = 0x0100;
pub const TCTL: usize = 0x0400;
pub const TIPG: usize = 0x0410;
pub const MDICNFG: usize = 0x0e04;
pub const PHPM: usize = 0x0e14;
pub const EEMNGCTL: usize = 0x1010;
pub const IMC: usize = 0x00d8;
pub const ICR: usize = 0x00c0;
pub const EIMC: usize = 0x1528;
pub const EICR: usize = 0x1580;
pub const GPIE: usize = 0x1514;
pub const RXPBS: usize = 0x2404;
pub const TXPBS: usize = 0x3404;
pub const RDBAL: usize = 0x2800;
pub const RDBAH: usize = 0x2804;
pub const RDLEN: usize = 0x2808;
pub const SRRCTL: usize = 0x280c;
pub const RDH: usize = 0x2810;
pub const RDT: usize = 0x2818;
pub const RXDCTL: usize = 0x2828;
pub const TDBAL: usize = 0x3800;
pub const TDBAH: usize = 0x3804;
pub const TDLEN: usize = 0x3808;
pub const TDH: usize = 0x3810;
pub const TDT: usize = 0x3818;
pub const TXDCTL: usize = 0x3828;
pub const RXCSUM: usize = 0x5000;
pub const RLPML: usize = 0x5004;
pub const RFCTL: usize = 0x5008;
pub const MTA: usize = 0x5200;
pub const RAL: usize = 0x5400;
pub const RAH: usize = 0x5404;
pub const VFTA: usize = 0x5600;
pub const WUC: usize = 0x5800;
pub const MRQC: usize = 0x5818;
pub const VT_CTL: usize = 0x581c;
pub const MANC: usize = 0x5820;
pub const GCR: usize = 0x5b00;
pub const SWSM: usize = 0x5b50;
pub const SW_FW_SYNC: usize = 0x5b5c;
pub const VMOLR: usize = 0x5ad0;
pub const UTA: usize = 0xa000;
pub const EEARBC: usize = 0x12024;
pub const EEMNGCTL_I210: usize = 0x12030;
pub const INVM: usize = 0x12120;
pub const INVM_WORDS: usize = 64;

pub const CTRL_MASTER_DISABLE: u32 = 1 << 2;
pub const CTRL_SLU: u32 = 1 << 6;
pub const CTRL_FRCSPD: u32 = 1 << 11;
pub const CTRL_FRCDPX: u32 = 1 << 12;
pub const CTRL_RST: u32 = 1 << 26;
pub const CTRL_RFCE: u32 = 1 << 27;
pub const CTRL_TFCE: u32 = 1 << 28;
pub const CTRL_VME: u32 = 1 << 30;
pub const CTRL_PHY_RST: u32 = 1 << 31;
pub const STATUS_MASTER: u32 = 1 << 19;
pub const STATUS_LU: u32 = 1 << 1;
pub const EECD_PRESENT: u32 = 1 << 8;
pub const EECD_AUTO_RD: u32 = 1 << 9;
pub const EECD_FLASH: u32 = 1 << 19;
pub const CTRL_EXT_I2C: u32 = 1 << 25;
pub const CTRL_EXT_MODE: u32 = 3 << 22;
pub const CTRL_EXT_DRIVER: u32 = 1 << 28;
pub const CTRL_EXT_PHY_POWER: u32 = (1 << 20) | (1 << 18);
pub const PHPM_LINK_DISCONNECT: u32 = 1 << 5;
pub const PHPM_LPLU: u32 = (1 << 1) | (1 << 2);
pub const RCTL_EN: u32 = 1 << 1;
pub const RCTL_MPE: u32 = 1 << 4;
pub const RCTL_LPE: u32 = 1 << 5;
pub const RCTL_BAM: u32 = 1 << 15;
pub const RCTL_SECRC: u32 = 1 << 26;
pub const TCTL_EN: u32 = 1 << 1;
pub const TCTL_PSP: u32 = 1 << 3;
pub const TCTL_COLLISIONS: u32 = (15 << 4) | (63 << 12);
pub const TCTL_RTLC: u32 = 1 << 24;
pub const QUEUE_ENABLE: u32 = 1 << 25;
pub const RFCTL_IPV6_EX_DIS: u32 = 1 << 16;
pub const RFCTL_LEF: u32 = 1 << 18;
pub const MANC_TCO: u32 = 1 << 17;
pub const MANC_BLOCK_PHY: u32 = 1 << 18;
pub const GCR_COMPLETION_MASK: u32 = 0xf << 12;
pub const GCR_COMPLETION_10MS: u32 = 1 << 12;
pub const GCR_RESEND: u32 = 1 << 16;
pub const GCR_V2: u32 = 1 << 18;
pub const MDIC_READ: u32 = 1 << 27;
pub const MDIC_WRITE: u32 = 1 << 26;
pub const MDIC_READY: u32 = 1 << 28;
pub const MDIC_ERROR: u32 = 1 << 30;
pub const MDIC_PHY: u32 = 1 << 21;
pub const MDIC_REGISTER_MASK: u32 = 31 << 16;
pub const NVM_EEPROM_SYNC: u32 = 1;
pub const NVM_CHECKSUM: u16 = 0x3f;
pub const NVM_SUM: u16 = 0xbaba;

pub const PHY_CONTROL: u16 = 0;
pub const PHY_ID1: u16 = 2;
pub const PHY_ID2: u16 = 3;
pub const PHY_ADVERTISE: u16 = 4;
pub const PHY_GIGABIT: u16 = 9;
pub const PHY_SPECIFIC: u16 = 16;
pub const PHY_PAGE_M88: u16 = 22;
pub const PHY_PAGE_IGP: u16 = 31;
pub const PHY_RESET: u16 = 1 << 15;
pub const PHY_LOOPBACK: u16 = 1 << 14;
pub const PHY_AUTONEG: u16 = 1 << 12;
pub const PHY_POWERDOWN: u16 = 1 << 11;
pub const PHY_ISOLATE: u16 = 1 << 10;
pub const PHY_RESTART: u16 = 1 << 9;
pub const PHY_IGP3: u32 = 0x02a8_0390;
pub const PHY_M88: u32 = 0x0141_0cc0;
pub const PHY_I347: u32 = 0x0141_0dc0;
pub const PHY_82580: u32 = 0x0154_03a0;
pub const PHY_I350: u32 = 0x0154_03b0;
pub const PHY_I210: u32 = 0x0141_0c00;

pub const fn queue_register(base: usize, index: usize) -> usize {
    if index < 4 {
        base + index * 0x100
    } else if base < 0x3000 {
        0xc000 + (base - RDBAL) + index * 0x40
    } else {
        0xe000 + (base - TDBAL) + index * 0x40
    }
}

pub const fn receive_address(index: usize) -> usize {
    if index < 16 {
        RAL + index * 8
    } else {
        0x54e0 + (index - 16) * 8
    }
}
