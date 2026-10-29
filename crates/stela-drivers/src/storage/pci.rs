// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict native PCI admission shared by polled storage controllers.
use crate::bus::pci::regs;
use crate::{
    block::BlockError,
    bus::pci::{ConfigSpace, Function, Layout, capability},
};
use alloc::vec::Vec;

const PCI_CAP_CONTROL: u16 = 2;
const PCI_PM: u8 = 0x01;
const PCI_VPD: u8 = 0x03;
const PCI_VENDOR: u8 = 0x09;
const PCI_SSVID: u8 = 0x0d;
const PCI_EXPRESS: u8 = 0x10;
const PCI_EXP_TYPE: u16 = 0x00f0;
const PCI_EXP_SLOT: u16 = 0x0100;
const PCI_EXP_ENDPOINT: u16 = 0;
const PCI_EXP_LEGACY_ENDPOINT: u16 = 1;
const PCI_EXP_RC_ENDPOINT: u16 = 9;
const PCI_MSI: u8 = 0x05;
const PCI_MSIX: u8 = 0x11;
const PCI_MSI_ENABLE: u16 = 1;
const PCI_MSIX_ENABLE: u16 = 1 << 15;

/// Return a capability only after validating the entire supported chain,
/// including the real version-specific body of every admitted capability.
pub(super) fn capability<C: ConfigSpace>(config: &C, id: u8) -> Result<Option<u16>, BlockError> {
    Ok(checked_capabilities(config, Some(id))?.1)
}

pub(super) fn quiesce_pio<C: ConfigSpace>(function: &mut Function<C>) -> Result<(), BlockError> {
    let identity = u32::from(function.vendor) | u32::from(function.device) << 16;
    if function.config().read32(0) != identity {
        return Err(BlockError::Unsupported(
            "storage PCI identity changed before PIO ownership",
        ));
    }
    let [msi, msix] = checked_capabilities(function.config(), None)?.0;
    set_pio_command(function, false)?;
    if let Some(at) = msi {
        let value = function.config().read16(at) & !PCI_MSI_ENABLE;
        function.config().write16(at, value);
        if function.config().read16(at) & PCI_MSI_ENABLE != 0 {
            return Err(BlockError::Unsupported(
                "storage PIO MSI disable did not acknowledge",
            ));
        }
    }
    if let Some(at) = msix {
        let value = function.config().read16(at) & !PCI_MSIX_ENABLE;
        function.config().write16(at, value);
        if function.config().read16(at) & PCI_MSIX_ENABLE != 0 {
            return Err(BlockError::Unsupported(
                "storage PIO MSI-X disable did not acknowledge",
            ));
        }
    }
    Ok(())
}

// The shared inventory is tolerant for discovery. Hardware ownership
// instead requires a complete, unambiguous chain before any power/BAR/MMIO work.
fn checked_capabilities<C: ConfigSpace>(
    config: &C,
    target: Option<u8>,
) -> Result<([Option<u16>; 2], Option<u16>), BlockError> {
    let malformed = BlockError::Unsupported("storage malformed PCI capability chain");
    if config.read8(regs::HEADER_TYPE) & 0x7f != 0 {
        return Err(malformed);
    }
    let mut controls = [None; 2];
    let mut found = None;
    let mut singletons = [false; 256];
    for entry in config.capabilities() {
        let entry = entry.map_err(|_| malformed.clone())?;
        let (at, id) = (entry.offset, entry.id);
        if id == 0 {
            return Err(malformed);
        }
        if id != PCI_VENDOR {
            if singletons[usize::from(id)] {
                return Err(malformed);
            }
            singletons[usize::from(id)] = true;
        }
        if target == Some(id) {
            found = Some(at);
        }
        // Every admitted body must be measured. Otherwise a next pointer can
        // name PM/MSI controls inside a different capability's real registers.
        match id {
            PCI_PM | PCI_VPD | PCI_SSVID | PCI_VENDOR => {}
            PCI_EXPRESS => {
                let flags = config.read16(at + PCI_CAP_CONTROL);
                let kind = (flags & PCI_EXP_TYPE) >> 4;
                if flags & PCI_EXP_SLOT != 0 {
                    return Err(BlockError::Unsupported(
                        "storage unqualified PCIe slot capability",
                    ));
                }
                if !matches!(
                    kind,
                    PCI_EXP_ENDPOINT | PCI_EXP_LEGACY_ENDPOINT | PCI_EXP_RC_ENDPOINT
                ) || entry.layout != Layout::Sized
                {
                    return Err(BlockError::Unsupported(
                        "storage unqualified PCIe capability extent",
                    ));
                }
            }
            PCI_MSI | PCI_MSIX => {
                controls[usize::from(id == PCI_MSIX)] = Some(at + PCI_CAP_CONTROL);
            }
            _ => {
                return Err(BlockError::Unsupported(
                    "storage unsupported PCI capability extent",
                ));
            }
        }
    }
    Ok((controls, found))
}

/// The offset of extended capability `target`, after every entry is
/// measured: endpoint AER without prefix or completion-timeout logging, serial
/// number, power budgeting, vendor-specific, LTR, L1 PM substates and PTM, each
/// once except vendor-specific. A header in another body grants nothing; any
/// other capability or layout is `invalid`.
pub(super) fn measured_extended<C: ConfigSpace + ?Sized>(
    config: &C,
    target: u16,
    invalid: BlockError,
) -> Result<Option<u16>, BlockError> {
    if config.read32(0x100) == u32::MAX {
        return Err(invalid);
    }
    let entries = capability::extended_capabilities(config)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid.clone())?;
    let mut singletons = 0u32;
    let mut found = None;
    for entry in &entries {
        let (at, id) = (entry.offset, entry.id);
        if entry.version != 1 && !(id == 1 && entry.version == 2) {
            return Err(invalid);
        }
        match id {
            // Conventional (non-Flit) endpoint AER through the four DWORD log.
            1 => {
                if at + 0x2c > 0x1000
                    || capability::overlap(entries.iter().map(|e| e.span()), at, 0x2c).is_some()
                    || config.read32(at + 0x18) & (1 << 11 | 1 << 12 | 1 << 18) != 0
                {
                    return Err(invalid);
                }
            }
            3 | 4 | 0x0b | 0x18 | 0x1e | 0x1f => {}
            _ => return Err(invalid),
        }
        if id != 0x0b {
            let bit = 1 << id;
            if singletons & bit != 0 {
                return Err(invalid);
            }
            singletons |= bit;
        }
        if id == target {
            found = Some(at);
        }
    }
    Ok(found)
}

pub(super) fn set_pio_command<C: ConfigSpace>(
    function: &mut Function<C>,
    grant_memory: bool,
) -> Result<(), BlockError> {
    let command = (function.config().read16(regs::COMMAND)
        & !(regs::COMMAND_MASTER | regs::COMMAND_MEMORY))
        | regs::COMMAND_INTX_DISABLE
        | if grant_memory {
            regs::COMMAND_MEMORY
        } else {
            0
        };
    // Clear DMA ownership before power-up/BAR probing; grant memory only after
    // every register mapping has been validated. Neither phase grants DMA.
    function.config().write16(regs::COMMAND, command);
    let mask = regs::COMMAND_MASTER | regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE;
    if function.config().read16(regs::COMMAND) & mask != command & mask {
        return Err(BlockError::Unsupported(
            "storage PIO PCI command did not acknowledge",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
