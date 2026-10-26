// SPDX-License-Identifier: GPL-2.0-or-later
// Native SDHCI v4 DMA controls: Linux sdhci.c/h, Copyright 2005-2008 Pierre Ossman.
//! GL9750 uses ADMA32 selection plus HC2's independent 64-bit address control.
use super::*;
#[cfg(test)]
mod tests;

pub(in crate::storage::sdhci) fn wide_capability(version: u8, capabilities: u32) -> bool {
    capabilities & if version >= 4 { 1 << 27 } else { CAP_64 } != 0
}

pub(in crate::storage::sdhci) fn configure(
    registers: &mut dyn Registers,
    wide: bool,
) -> Result<u8, BlockError> {
    let control = registers.read16(HOST_CONTROL2);
    if control == u16::MAX || control & (1 << 12) == 0 {
        return Err(BlockError::Unsupported(
            "GL9750 ADMA requires actual v4 mode",
        ));
    }
    let address = if wide { 1 << 13 } else { 0 };
    registers.write16(HOST_CONTROL2, (control & !(1 << 13)) | address);
    let actual = registers.read16(HOST_CONTROL2);
    if actual == u16::MAX || actual & (3 << 12) != (1 << 12) | address {
        return Err(BlockError::Unsupported(
            "GL9750 DMA address width did not acknowledge",
        ));
    }
    let control = registers.read8(HOST_CONTROL);
    if control == u8::MAX {
        return Err(BlockError::Unsupported(
            "GL9750 DMA controls are unavailable",
        ));
    }
    Ok((control & !DMA_MASK) | ADMA32)
}

pub(in crate::storage::sdhci) fn descriptor(
    table: &mut DmaBuffer,
    address: u64,
    bytes: usize,
    wide: bool,
) {
    table.write(0, 0x23u16); // One source TRAN|VALID|END, never an END NOP.
    table.write(2, bytes as u16);
    table.write(4, address as u32);
    if wide {
        table.write(8, (address >> 32) as u32);
        table.write(12, 0u32); // Reserved high word in the v4 128-bit layout.
    }
}
