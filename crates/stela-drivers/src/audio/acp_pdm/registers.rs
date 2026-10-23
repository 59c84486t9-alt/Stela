// SPDX-License-Identifier: GPL-2.0-only
//! Register facts common to the pinned Renoir/Yellow Carp/ACP63/ACP70 direct PDM blocks.
//! Copyright (C) 2020, 2021, 2022, 2023, 2025 Advanced Micro Devices, Inc.
use super::{Error, Identity};
// BAR-relative offsets. The source's 0x1240000 is a register namespace base,
// not the PCI BAR or the host DMA address.
pub(in crate::audio) const PAGE_SIZE: usize = 0x0c00;
pub(in crate::audio) const PAGE_BASE: usize = 0x0c04;
// Source SOF calls bit0 ACP_ATU_CACHE_INVALID: a command, not an enable latch.
pub(in crate::audio) const ATU_CONTROL: usize = 0x0c40;
pub(in crate::audio) const ATU_CACHE_INVALIDATE: u32 = 1;
pub(in crate::audio) const GROUP_ENABLE: u32 = 1 << 31;
pub(in crate::audio) const RESET: usize = 0x1000;
pub(in crate::audio) const CONTROL: usize = 0x1004;
pub(in crate::audio) const PDM_ENABLE: usize = 0x2c04;
pub(in crate::audio) const DMA_ENABLE: usize = 0x2c08;
pub(in crate::audio) const RING_ADDRESS: usize = 0x2c0c;
pub(in crate::audio) const RING_SIZE: usize = 0x2c10;
pub(in crate::audio) const COUNT_HIGH: usize = 0x2c18;
pub(in crate::audio) const COUNT_LOW: usize = 0x2c1c;
pub(in crate::audio) const WATERMARK: usize = 0x2c20;
pub(in crate::audio) const FIFO_FLUSH: usize = 0x2c24;
pub(in crate::audio) const CHANNELS: usize = 0x2c28;
pub(in crate::audio) const DECIMATION: usize = 0x2c2c;
pub(in crate::audio) const MISC: usize = 0x2c5c;
pub(in crate::audio) const PDM_CLOCK: usize = 0x2c60;
pub(in crate::audio) const SCRATCH: usize = 0x10000;
pub(in crate::audio) const REGION_BYTES: usize = 0x10204;
pub(in crate::audio) const PERIOD_IRQ: u32 = 1 << 16;
pub(in crate::audio) const ERROR_IRQ: u32 = 1 << 29;
pub(in crate::audio) const PTE_VALID: u32 = 1 << 31;
pub(in crate::audio) const PDM_WINDOW: u32 = 0x0400_0000;
pub(in crate::audio) const POWER_STATE_MASK: u32 = 3;
pub(in crate::audio) const POWER_ON_IN_PROGRESS: u32 = 1;
pub(in crate::audio) const POWERED_OFF: u32 = 2;
pub(in crate::audio) const POWER_ON_REQUEST: u32 = 1;
pub(in crate::audio) const POWER_OFF_REQUEST: u32 = 0;
pub(in crate::audio) const RESET_ACK: u32 = 0x0001_0001;
pub(in crate::audio) const DMA_REQUEST: u32 = 1;
pub(in crate::audio) const DMA_ACTIVE: u32 = 2;
pub(in crate::audio) const GAIN_MASK: u32 = 3 << 3;

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
