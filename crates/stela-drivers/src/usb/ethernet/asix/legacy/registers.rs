// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2003-2006 David Hollis <dhollis@davehollis.com>
// Copyright (C) 2005 Phil Chang <pchang23@sbcglobal.net>
// Copyright (C) 2006 James Painter <jamie.painter@iname.com>
// Copyright (C) 2002-2003 TiVo Inc.
// Numeric MII fields: Copyright (C) 1996, 1999, 2001 David S. Miller;
// GPL-2.0 WITH Linux-syscall-note, as recorded in THIRD_PARTY.md.
//! Pinned asix.h, asix_devices.c and standard MII encodings.
pub(super) const SET_SW_MII: u8 = 0x06;
pub(super) const READ_MII: u8 = 0x07;
pub(super) const WRITE_MII: u8 = 0x08;
pub(super) const STATUS: u8 = 0x09;
pub(super) const SET_HW_MII: u8 = 0x0a;
pub(super) const EEPROM: u8 = 0x0b;
pub(super) const READ_RX: u8 = 0x0f;
pub(super) const WRITE_RX: u8 = 0x10;
pub(super) const WRITE_IPG: u8 = 0x12;
pub(super) const READ_MAC: u8 = 0x13;
pub(super) const WRITE_MAC: u8 = 0x14;
pub(super) const READ_PHY: u8 = 0x19;
pub(super) const READ_MEDIUM: u8 = 0x1a;
pub(super) const WRITE_MEDIUM: u8 = 0x1b;
pub(super) const WRITE_GPIO: u8 = 0x1f;
pub(super) const SW_RESET: u8 = 0x20;
pub(super) const PHY_SELECT: u8 = 0x22;
pub(super) const QUEUE: u8 = 0x2a;
pub(super) const CHIP_MASK: u8 = 0x70;
pub(super) const ORIGINAL: u8 = 0;
pub(super) const A: u8 = 0x10;
pub(super) const B: u8 = 0x20;
pub(super) const HOST_EN: u8 = 1;
pub(super) const SSEN: u16 = 0x10;
pub(super) const INTERNAL_PHY: u16 = 0x10;
pub(super) const RESET_PRL: u16 = 0x08;
pub(super) const RESET_IPRL: u16 = 0x20;
pub(super) const RESET_IPPD: u16 = 0x40;
pub(super) const GPIO_RELOAD: u16 = 0x80;
pub(super) const GPIO_2: u16 = 0x20;
pub(super) const GPIO_2_ENABLE: u16 = 0x10;
pub(super) const MEDIUM_AC: u16 = 0x04;
pub(super) const MEDIUM_RE: u16 = 0x100;
pub(super) const MEDIUM_FD: u16 = 0x02;
pub(super) const MEDIUM_100: u16 = 0x200;
pub(super) const MEDIUM_TX_PAUSE: u16 = 0x20;
pub(super) const MEDIUM_RX_PAUSE: u16 = 0x10;
pub(super) const MEDIUM_DEFAULT: u16 = MEDIUM_AC | MEDIUM_RE | MEDIUM_FD | MEDIUM_100;
pub(super) const RX_DEFAULT: u16 = 0x88;
pub(super) const RX_ALL_MULTICAST: u16 = 0x02;
pub(super) const IPG0: u16 = 0x15;
pub(super) const IPG1: u16 = 0x0c;
pub(super) const IPG2: u16 = 0x12;
pub(super) const A_DEFAULTS: [(u16, u16); 3] = [(0x14, 0x442c), (0x15, 0x03c8), (0x16, 0x4044)];
pub(super) const PHY_A: u32 = 0x003b1861;
pub(super) const PHY_C: u32 = 0x003b1881;
pub(super) const PHY_96B: u32 = 0x003b1840;
// IEEE 802.3 clause 22 numeric fields, linux/uapi/linux/mii.h.
pub(super) const BMCR: u16 = 0;
pub(super) const BMSR: u16 = 1;
pub(super) const PHY_ID1: u16 = 2;
pub(super) const PHY_ID2: u16 = 3;
pub(super) const ADVERTISE: u16 = 4;
pub(super) const LPA: u16 = 5;
pub(super) const RESET: u16 = 0x8000;
pub(super) const SPEED_100: u16 = 0x2000;
pub(super) const AN_ENABLE: u16 = 0x1000;
pub(super) const POWER_DOWN: u16 = 0x0800;
pub(super) const ISOLATE: u16 = 0x0400;
pub(super) const AN_RESTART: u16 = 0x0200;
pub(super) const FULL: u16 = 0x0100;
pub(super) const AN_COMPLETE: u16 = 0x0020;
pub(super) const LINK: u16 = 0x0004;
pub(super) const CAP_100_FULL: u16 = 0x4000;
pub(super) const CAP_100_HALF: u16 = 0x2000;
pub(super) const CAP_10_FULL: u16 = 0x1000;
pub(super) const CAP_10_HALF: u16 = 0x0800;
pub(super) const AN_CAPABLE: u16 = 0x0008;
pub(super) const ADV_100_FULL: u16 = 0x0100;
pub(super) const ADV_100_HALF: u16 = 0x0080;
pub(super) const ADV_10_FULL: u16 = 0x0040;
pub(super) const ADV_10_HALF: u16 = 0x0020;
pub(super) const ADV_PAUSE: u16 = 0x0400;
pub(super) const ADV_ASYM: u16 = 0x0800;
pub(super) const ADV_MASK: u16 = 0x0fe0;
