// SPDX-License-Identifier: GPL-2.0-only
//! ACP6x register facts adapted from AMD's Linux acp6x_chip_offset_byte.h and
//! acp6x.h at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright (C) 2021 Advanced Micro Devices, Inc. All rights reserved.
use super::{Error, Identity};

// BAR-relative offsets. The source's 0x1240000 is a register namespace base,
// not the PCI BAR or the host DMA address.
pub(super) const PAGE_SIZE: usize = 0x0c00;
pub(super) const PAGE_BASE: usize = 0x0c04;
pub(super) const ATU_CONTROL: usize = 0x0c40;
pub(super) const RESET: usize = 0x1000;
pub(super) const CONTROL: usize = 0x1004;
pub(super) const POWER_CONTROL: usize = 0x1024;
pub(super) const POWER_STATUS: usize = 0x1028;
pub(super) const CLOCK: usize = 0x102c;
pub(super) const PIN_CONFIG: usize = 0x1440;
pub(super) const IRQ_ENABLE: usize = 0x1a00;
pub(super) const IRQ_CONTROL: usize = 0x1a04;
pub(super) const IRQ_STATUS: usize = 0x1a0c;
pub(super) const PDM_ENABLE: usize = 0x2c04;
pub(super) const DMA_ENABLE: usize = 0x2c08;
pub(super) const RING_ADDRESS: usize = 0x2c0c;
pub(super) const RING_SIZE: usize = 0x2c10;
pub(super) const COUNT_HIGH: usize = 0x2c18;
pub(super) const COUNT_LOW: usize = 0x2c1c;
pub(super) const WATERMARK: usize = 0x2c20;
pub(super) const FIFO_FLUSH: usize = 0x2c24;
pub(super) const CHANNELS: usize = 0x2c28;
pub(super) const DECIMATION: usize = 0x2c2c;
pub(super) const MISC: usize = 0x2c5c;
pub(super) const PDM_CLOCK: usize = 0x2c60;
pub(super) const SCRATCH: usize = 0x10000;
pub(super) const REGION_BYTES: usize = 0x10204;
pub(super) const PERIOD_IRQ: u32 = 1 << 16;
pub(super) const ERROR_IRQ: u32 = 1 << 29;
pub(super) const PTE_VALID: u32 = 1 << 31;
pub(super) const SRAM_TABLE: u32 = 0x0380_0000;
pub(super) const PDM_WINDOW: u32 = 0x0400_0000;
pub(super) const RESET_ACK: u32 = 0x0001_0001;
pub(super) const DMA_REQUEST: u32 = 1;
pub(super) const DMA_ACTIVE: u32 = 2;
pub(super) const GAIN_MASK: u32 = 3 << 3;

/// One powered, exclusively owned ACP function. Accesses are native 32-bit,
/// BAR-relative. `identity` must re-read the actual PCI function and check its
/// retained BAR, power, decoding and interrupt containment on every call.
pub trait Registers {
    fn region_bytes(&self) -> usize;
    fn identity(&mut self) -> Result<Identity, Error>;
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error>;
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
}
