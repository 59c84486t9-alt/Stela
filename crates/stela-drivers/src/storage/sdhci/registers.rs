// SPDX-License-Identifier: GPL-2.0-or-later
// Register encodings: Linux sdhci.h, Copyright 2005-2008 Pierre Ossman.
//! SDHCI register widths are architectural: never emulate byte/word writes
//! through read-modify-write of adjacent command or write-one-to-clear state.
use crate::bus::mmio::Mmio;
pub(super) trait Registers {
    /// An owning vendor provider can revoke its actual PCI/decode epoch before
    /// the engine touches its controller mapping. Ordinary providers retain
    /// their existing exclusive firmware-mapping contract.
    fn check_authority(&mut self) -> Result<(), crate::block::BlockError> {
        Ok(())
    }
    /// Runtime vendor controls use the same retained enumerated PCI function.
    /// Ordinary MMIO providers cannot invent configuration-space authority.
    fn configuration(
        &mut self,
    ) -> Result<&mut dyn crate::bus::pci::ConfigSpace, crate::block::BlockError> {
        Err(crate::block::BlockError::Unsupported(
            "SDHCI provider has no retained PCI configuration authority",
        ))
    }
    /// The ordinary attachment already admitted DMA. A retained vendor owner
    /// can defer its actual PCI grant until retained descriptors are ready.
    fn dma_ready(&mut self) -> Result<(), crate::block::BlockError> {
        Ok(())
    }
    fn read8(&mut self, at: usize) -> u8;
    fn read16(&mut self, at: usize) -> u16;
    fn read32(&mut self, at: usize) -> u32;
    fn write8(&mut self, at: usize, value: u8);
    fn write16(&mut self, at: usize, value: u16);
    fn write32(&mut self, at: usize, value: u32);
}
impl Registers for Mmio {
    fn read8(&mut self, at: usize) -> u8 {
        Mmio::read8(self, at)
    }
    fn read16(&mut self, at: usize) -> u16 {
        Mmio::read16(self, at)
    }
    fn read32(&mut self, at: usize) -> u32 {
        Mmio::read32(self, at)
    }
    fn write8(&mut self, at: usize, value: u8) {
        Mmio::write8(self, at, value);
    }
    fn write16(&mut self, at: usize, value: u16) {
        Mmio::write16(self, at, value);
    }
    fn write32(&mut self, at: usize, value: u32) {
        Mmio::write32(self, at, value);
    }
}
pub(super) const BLOCK_SIZE: usize = 0x04;
pub(super) const BLOCK_COUNT: usize = 0x06;
pub(super) const ARGUMENT: usize = 0x08;
pub(super) const TRANSFER_MODE: usize = 0x0c;
pub(super) const COMMAND: usize = 0x0e;
pub(super) const RESPONSE: usize = 0x10;
pub(super) const BUFFER: usize = 0x20;
pub(super) const PRESENT: usize = 0x24;
pub(super) const HOST_CONTROL: usize = 0x28;
pub(super) const POWER: usize = 0x29;
pub(super) const CLOCK: usize = 0x2c;
pub(super) const TIMEOUT: usize = 0x2e;
pub(super) const RESET: usize = 0x2f;
pub(super) const INTERRUPT: usize = 0x30;
pub(super) const INTERRUPT_ENABLE: usize = 0x34;
pub(super) const SIGNAL_ENABLE: usize = 0x38;
pub(super) const HOST_CONTROL2: usize = 0x3e;
pub(super) const CAPABILITIES: usize = 0x40;
pub(super) const CAPABILITIES2: usize = 0x44;
pub(super) const MAX_CURRENT: usize = 0x48;
pub(super) const ADMA_ADDRESS: usize = 0x58;
pub(super) const ADMA_ADDRESS_HIGH: usize = 0x5c;
pub(super) const VERSION: usize = 0xfe;
pub(super) const RESET_ALL: u8 = 1;
pub(super) const RESET_COMMAND: u8 = 2;
pub(super) const RESET_DATA: u8 = 4;
pub(super) const INHIBIT_COMMAND: u32 = 1;
pub(super) const INHIBIT_DATA: u32 = 2;
pub(super) const SPACE_AVAILABLE: u32 = 1 << 10;
pub(super) const DATA_AVAILABLE: u32 = 1 << 11;
pub(super) const CARD_PRESENT: u32 = 1 << 16;
pub(super) const CARD_STABLE: u32 = 1 << 17;
pub(super) const WRITE_ALLOWED: u32 = 1 << 19;
pub(super) const DATA0: u32 = 1 << 20;
pub(super) const DATA_LINES: u32 = 15 << 20;
pub(super) const RESPONSE_END: u32 = 1;
pub(super) const DATA_END: u32 = 2;
pub(super) const DMA_END: u32 = 8;
pub(super) const WRITE_READY: u32 = 1 << 4;
pub(super) const READ_READY: u32 = 1 << 5;
pub(super) const CARD_INSERT: u32 = 1 << 6;
pub(super) const CARD_REMOVE: u32 = 1 << 7;
pub(super) const BUS_POWER: u32 = 1 << 23;
pub(super) const COMMAND_TIMEOUT: u32 = 1 << 16;
pub(super) const ERROR: u32 = 0xffff_8000;
pub(super) const CLOCK_INTERNAL: u16 = 1;
pub(super) const CLOCK_STABLE: u16 = 2;
pub(super) const CLOCK_CARD: u16 = 4;
pub(super) const CLOCK_PLL: u16 = 8;
pub(super) const BUS4: u8 = 2;
pub(super) const HIGH_SPEED: u8 = 4;
pub(super) const DMA_MASK: u8 = 0x18;
pub(super) const ADMA32: u8 = 0x10;
pub(super) const ADMA64: u8 = 0x18;
pub(super) const BUS8: u8 = 0x20;
pub(super) const DMA: u16 = 1;
pub(super) const BLOCK_COUNT_ENABLE: u16 = 2;
pub(super) const READ: u16 = 0x10;
pub(super) const MULTIPLE: u16 = 0x20;
pub(super) const CAP_ADMA2: u32 = 1 << 19;
pub(super) const CAP_HIGH_SPEED: u32 = 1 << 21;
pub(super) const CAP_64: u32 = 1 << 28;
#[cfg(test)]
pub(super) const CAP_8BIT: u32 = 1 << 18;
pub(super) const CAP_330: u32 = 1 << 24;
pub(super) const CAP_300: u32 = 1 << 25;
pub(super) const CAP_180: u32 = 1 << 26;
pub(super) const CAP_SDR50: u32 = 1;
pub(super) const CAP_SDR104: u32 = 1 << 1;
pub(super) const CAP_DDR50: u32 = 1 << 2;
pub(super) const CAP_SDR50_TUNING: u32 = 1 << 13;
pub(super) const UHS_MODE: u16 = 7;
pub(super) const SIGNAL_180: u16 = 1 << 3;
pub(super) const EXECUTE_TUNING: u16 = 1 << 6;
pub(super) const TUNED_CLOCK: u16 = 1 << 7;
pub(super) const POWER_330: u8 = 0x0e;
pub(super) const POWER_300: u8 = 0x0c;
pub(super) const POWER_180: u8 = 0x0a;
pub(super) const POWER_ON: u8 = 1;
pub(super) const INIT_HZ: u32 = 400_000;
pub(super) const COMMAND_US: u64 = 1_000_000;
pub(super) const DATA_US: u64 = 5_000_000;
pub(super) const RESET_US: u64 = 100_000;
