// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Register and descriptor encodings from the pinned Linux r8169 driver.
pub(super) const MAC0: usize = 0;
pub(super) const MAC4: usize = 4;
pub(super) const MAR0: usize = 8;
pub(super) const TX_LOW: usize = 0x20;
pub(super) const TX_HIGH: usize = 0x24;
pub(super) const COMMAND: usize = 0x37;
pub(super) const TX_POLL: usize = 0x38;
pub(super) const INTERRUPT_MASK: usize = 0x3c;
pub(super) const INTERRUPT_STATUS: usize = 0x3e;
pub(super) const TX_CONFIG: usize = 0x40;
pub(super) const RX_CONFIG: usize = 0x44;
pub(super) const CONFIG_LOCK: usize = 0x50;
pub(super) const CONFIG1: usize = 0x52;
pub(super) const CONFIG2: usize = 0x53;
pub(super) const CONFIG3: usize = 0x54;
pub(super) const CONFIG4: usize = 0x55;
pub(super) const CONFIG5: usize = 0x56;
pub(super) const PHY_ACCESS: usize = 0x60;
pub(super) const CSI_DATA: usize = 0x64;
pub(super) const CSI_ADDRESS: usize = 0x68;
pub(super) const PHY_STATUS: usize = 0x6c;
pub(super) const ERI_DATA: usize = 0x70;
pub(super) const ERI_ADDRESS: usize = 0x74;
pub(super) const EPHY_ACCESS: usize = 0x80;
pub(super) const MAC_OCP: usize = 0xb0;
pub(super) const PHY_OCP: usize = 0xb8;
pub(super) const DLL_POWER: usize = 0xd0;
pub(super) const EFUSE_ACCESS: usize = 0xdc;
pub(super) const DEBUG: usize = 0xd1;
pub(super) const MCU: usize = 0xd3;
pub(super) const RX_MAXIMUM: usize = 0xda;
pub(super) const CPLUS: usize = 0xe0;
pub(super) const INTERRUPT_MITIGATION: usize = 0xe2;
pub(super) const RX_LOW: usize = 0xe4;
pub(super) const RX_HIGH: usize = 0xe8;
pub(super) const EARLY_TX: usize = 0xec;
pub(super) const MISC: usize = 0xf0;
pub(super) const RESET: u8 = 0x10;
pub(super) const ENABLE: u8 = 0x0c;
pub(super) const POLL_NORMAL: u8 = 0x40;
pub(super) const ACCESS: u32 = 1 << 31;
pub(super) const OCP_PHY_BASE: u16 = 0xa400;
pub(super) const PHY_PAGE: u16 = 0x1f;
pub(super) const PHY_CONTROL: u16 = 0;
pub(super) const PHY_RESET: u16 = 1 << 15;
pub(super) const DESCRIPTORS: usize = 32;
pub(super) const DESCRIPTOR: usize = 16;
pub(super) const BUFFER: usize = 2048;
pub(super) const OWN: u32 = 1 << 31;
pub(super) const END: u32 = 1 << 30;
pub(super) const FIRST: u32 = 1 << 29;
pub(super) const LAST: u32 = 1 << 28;
pub(super) const RX_ERRORS: u32 = 0xf << 19;
pub(super) const LENGTH: u32 = 0x3fff;
