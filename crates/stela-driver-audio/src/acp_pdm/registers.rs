// SPDX-License-Identifier: GPL-2.0-only
//! Register facts common to the pinned Renoir/Yellow Carp/ACP63/ACP70 direct PDM blocks.
//! Copyright (C) 2020, 2021, 2022, 2023, 2025 Advanced Micro Devices, Inc.
use super::{Error, Identity};
// BAR-relative offsets. The source's 0x1240000 is a register namespace base,
// not the PCI BAR or the host DMA address.
pub(crate) const PAGE_SIZE: usize = 0x0c00;
pub(crate) const PAGE_BASE: usize = 0x0c04;
// Source SOF calls bit0 ACP_ATU_CACHE_INVALID: a command, not an enable latch.
pub(crate) const ATU_CONTROL: usize = 0x0c40;
pub(crate) const ATU_CACHE_INVALIDATE: u32 = 1;
pub(crate) const GROUP_ENABLE: u32 = 1 << 31;
pub(crate) const RESET: usize = 0x1000;
pub(crate) const CONTROL: usize = 0x1004;
pub(crate) const PDM_ENABLE: usize = 0x2c04;
pub(crate) const DMA_ENABLE: usize = 0x2c08;
pub(crate) const RING_ADDRESS: usize = 0x2c0c;
pub(crate) const RING_SIZE: usize = 0x2c10;
pub(crate) const COUNT_HIGH: usize = 0x2c18;
pub(crate) const COUNT_LOW: usize = 0x2c1c;
pub(crate) const WATERMARK: usize = 0x2c20;
pub(crate) const FIFO_FLUSH: usize = 0x2c24;
pub(crate) const CHANNELS: usize = 0x2c28;
pub(crate) const DECIMATION: usize = 0x2c2c;
pub(crate) const MISC: usize = 0x2c5c;
pub(crate) const PDM_CLOCK: usize = 0x2c60;
pub(crate) const SCRATCH: usize = 0x10000;
pub(crate) const REGION_BYTES: usize = 0x10204;
pub(crate) const PERIOD_IRQ: u32 = 1 << 16;
pub(crate) const ERROR_IRQ: u32 = 1 << 29;
pub(crate) const PTE_VALID: u32 = 1 << 31;
pub(crate) const PDM_WINDOW: u32 = 0x0400_0000;
pub(crate) const POWER_STATE_MASK: u32 = 3;
pub(crate) const POWER_ON_IN_PROGRESS: u32 = 1;
pub(crate) const POWERED_OFF: u32 = 2;
pub(crate) const POWER_ON_REQUEST: u32 = 1;
pub(crate) const POWER_OFF_REQUEST: u32 = 0;
pub(crate) const RESET_ACK: u32 = 0x0001_0001;
pub(crate) const DMA_REQUEST: u32 = 1;
pub(crate) const DMA_ACTIVE: u32 = 2;
pub(crate) const GAIN_MASK: u32 = 3 << 3;

/// One powered, exclusively owned ACP function. Accesses are native 32-bit,
/// BAR-relative. `identity` must re-read the PCI function and check its
/// BAR, power, decoding and interrupt containment on every call.
pub trait Registers {
    fn region_bytes(&self) -> usize;
    fn identity(&mut self) -> Result<Identity, Error>;
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error>;
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
}
