// SPDX-License-Identifier: GPL-2.0-only
// PCI encodings follow Linux include/uapi/linux/pci_regs.h, copyright
// 1994 Drew Eckhardt and 1997-1999 Martin Mares; see bus/THIRD_PARTY.md.
//! The configuration header registers every function shares, and their bits.

pub const VENDOR_ID: u16 = 0x00;
pub const COMMAND: u16 = 0x04;
pub const COMMAND_IO: u16 = 1 << 0;
pub const COMMAND_MEMORY: u16 = 1 << 1;
pub const COMMAND_MASTER: u16 = 1 << 2;
pub const COMMAND_INVALIDATE: u16 = 1 << 4;
pub const COMMAND_INTX_DISABLE: u16 = 1 << 10;
pub const STATUS: u16 = 0x06;
pub const STATUS_CAP_LIST: u16 = 1 << 4;
/// Revision ID, then the class code's three bytes.
pub const CLASS_REVISION: u16 = 0x08;
pub const HEADER_TYPE: u16 = 0x0e;
pub const BASE_ADDRESS_0: u16 = 0x10;
pub const SUBSYSTEM_VENDOR_ID: u16 = 0x2c;
pub const CAPABILITY_LIST: u16 = 0x34;
