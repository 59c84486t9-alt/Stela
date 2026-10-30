// SPDX-License-Identifier: GPL-2.0-only
//! PCI D3hot transitions adapted from Linux controllers/intel.c's
//! azx_shutdown_chip / __azx_runtime_resume and drivers/pci/pci.c's PCI PM
//! sequencing at a804c5742bff224d4cb4d25dd383554d598be32b.
//! Copyright(c) 2004 Intel Corporation
//! Copyright (c) 2004 Takashi Iwai <tiwai@suse.de>
//!                     PeiSen Hou <pshou@realtek.com.tw>
//! Copyright 1993 -- 1997 Drew Eckhardt, Frederic Potter, David Mosberger-Tang
//! Copyright 1997 -- 2000 Martin Mares <mj@ucw.cz>
use super::{
    AttachError, PM_NO_SOFT_RESET, PM_PME_ENABLE, PM_PME_STATUS, PM_STATE, PciRegisters,
    capabilities, delay, registers::associated,
};
use crate::bus::pci::regs;
use crate::{
    Error, Phase,
    bus::{i2c::Timer, pci::ConfigSpace},
    hda::{
        Controller, Registers,
        registers::{GCTL, GCTL_RESET, GCTL_UNSOL},
    },
};

/// Failure keeps the original controller, DMA RAM and PCI/MMIO owners. After
/// a transition starts, only explicit resume may make the controller usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerError {
    Pci(AttachError),
    Controller(Error),
    AlreadySuspended,
    NotSuspended,
}
impl From<AttachError> for PowerError {
    fn from(error: AttachError) -> Self {
        Self::Pci(error)
    }
}
impl From<Error> for PowerError {
    fn from(error: Error) -> Self {
        Self::Controller(error)
    }
}

#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    bars: [u32; 6],
    pm: u16,
    command: u16,
}

impl<R: Registers, C: ConfigSpace, T: Timer> Controller<PciRegisters<'_, R, C>, T> {
    /// Stop the PCM/command engines, retire codec/GPU effects, assert
    /// link reset, disable PCI decode/mastering and enter D3hot. All DMA RAM,
    /// reservations and exact PCI/MMIO owners remain held across suspend.
    /// A failed stop prevents any PCI power write; a later power failure keeps
    /// MMIO inaccessible until explicit resume has restored and reset hardware.
    ///
    /// This is an explicit resource transition. The platform must keep
    /// main power, ECAM, BAR reservations, requester/IOMMU mappings and exclusive
    /// firmware/DSP ownership from the original unsafe claim. It must not use
    /// D3cold, hot removal, board-rail changes or wake routing during this epoch.
    /// Wake is disabled; system/runtime policy and wake dispatch are separate.
    pub fn suspend_pci_d3hot(&mut self) -> Result<(), PowerError> {
        if self.registers.suspended.is_some() {
            return Err(PowerError::AlreadySuspended);
        }
        let r = &mut self.registers;
        if !associated(r.function, r.address, r.identity, r.base) {
            return Err(AttachError::IdentityChanged.into());
        }
        let config = r.function.config();
        let caps = capabilities(config, r.identity.setup.controls(), r.identity.reset_policy)?;
        let pm = caps.pm.ok_or(AttachError::UnsupportedPowerManagement)?;
        let flags = config.read16(pm + 2);
        let state = config.read16(pm + 4);
        let command = config.read16(regs::COMMAND);
        if flags == u16::MAX
            || !(1..=3).contains(&(flags & 7))
            || state == u16::MAX
            || state & PM_STATE != 0
            || command == u16::MAX
            || command & (regs::COMMAND_MEMORY | regs::COMMAND_MASTER)
                != regs::COMMAND_MEMORY | regs::COMMAND_MASTER
        {
            return Err(AttachError::PowerNotReady.into());
        }
        let snapshot = Snapshot {
            bars: core::array::from_fn(|i| config.read32(regs::BASE_ADDRESS_0 + i as u16 * 4)),
            pm,
            command,
        };
        self.shutdown()?;
        // The GPU/HDA power grant must cover the final link-reset
        // accesses as well as stream/command stop. A failed reset keeps it.
        let reset = (|| {
            let gctl = self.registers.read32(GCTL);
            if gctl == u32::MAX {
                return Err(Error::RegisterUnavailable { offset: GCTL });
            }
            self.registers
                .write32(GCTL, gctl & !(GCTL_RESET | GCTL_UNSOL));
            self.wait(Phase::LinkResetEnter, |r| {
                let value = r.read32(GCTL);
                value != u32::MAX && value & GCTL_RESET == 0
            })?;
            self.delay(500);
            Ok(())
        })();
        if let Err(error) = reset {
            self.lifecycle_failed = true;
            return Err(error.into());
        }
        // No BAR access follows release of these powered-link owners. Retire
        // them after reset acknowledgement/delay and before PCI decode or PM.
        let retirement = self.retire_hdmi_for_pci_suspend();
        self.lifecycle_failed = true;
        retirement?;
        // From here even uncertain/failed PCI writes block all ordinary MMIO.
        // Retaining the snapshot before the first write permits safe recovery.
        self.registers.suspended = Some(snapshot);
        let config = self.registers.function.config();
        let disabled = snapshot.command & !(regs::COMMAND_MASTER | regs::COMMAND_MEMORY)
            | regs::COMMAND_INTX_DISABLE;
        config.write16(regs::COMMAND, disabled);
        let observed = config.read16(regs::COMMAND);
        if observed == u16::MAX || observed != disabled {
            return Err(AttachError::ConfigurationRejected.into());
        }
        let value = config.read16(pm + 4);
        if value == u16::MAX || value & PM_STATE != 0 {
            return Err(AttachError::PowerNotReady.into());
        }
        // PME_Status is W1C. Preserve pending wake evidence and disable PME.
        config.write16(
            pm + 4,
            value & !(PM_STATE | PM_PME_ENABLE | PM_PME_STATUS) | 3,
        );
        delay(&self.timer, 10_000);
        let observed = config.read16(pm + 4);
        if observed == u16::MAX || observed & (PM_STATE | PM_PME_ENABLE) != 3 {
            return Err(AttachError::PowerTransition.into());
        }
        Ok(())
    }

    /// Restore the same PCI function to D0 and perform a real full
    /// controller reset before any command DMA can resume. Old stream/route/
    /// graph handles are invalidated by `reinitialize`; PCM is not replayed.
    /// Discover codecs and bind new codec/GPU routes after success.
    /// Failure keeps the snapshot and every original DMA/resource owner.
    pub fn resume_pci_d0(&mut self) -> Result<(), PowerError> {
        let snapshot = self.registers.suspended.ok_or(PowerError::NotSuspended)?;
        let r = &mut self.registers;
        if r.function.address != r.address {
            return Err(AttachError::IdentityChanged.into());
        }
        let config = r.function.config();
        let id = config.read32(regs::VENDOR_ID);
        let class = config.read32(regs::CLASS_REVISION);
        if id != u32::from(r.identity.vendor) | (u32::from(r.identity.device) << 16)
            || [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8] != super::CLASS
            || config.read8(regs::HEADER_TYPE) & 0x7f != 0
        {
            return Err(AttachError::IdentityChanged.into());
        }
        let caps = capabilities(config, r.identity.setup.controls(), r.identity.reset_policy)?;
        if caps.pm != Some(snapshot.pm) {
            return Err(AttachError::InvalidCapabilities.into());
        }
        let flags = config.read16(snapshot.pm + 2);
        let value = config.read16(snapshot.pm + 4);
        if flags == u16::MAX
            || !(1..=3).contains(&(flags & 7))
            || value == u16::MAX
            || !matches!(value & PM_STATE, 0 | 3)
        {
            return Err(AttachError::PowerNotReady.into());
        }
        // Never restore a BAR with a possible live decoder or bus master.
        let disabled = snapshot.command & !(regs::COMMAND_MASTER | regs::COMMAND_MEMORY)
            | regs::COMMAND_INTX_DISABLE;
        config.write16(regs::COMMAND, disabled);
        let observed = config.read16(regs::COMMAND);
        if observed == u16::MAX || observed != disabled {
            return Err(AttachError::ConfigurationRejected.into());
        }
        config.write16(
            snapshot.pm + 4,
            value & !(PM_STATE | PM_PME_ENABLE | PM_PME_STATUS),
        );
        if value & PM_STATE == 3 {
            delay(&self.timer, 10_000);
        }
        let observed = config.read16(snapshot.pm + 4);
        if observed == u16::MAX || observed & (PM_STATE | PM_PME_ENABLE) != 0 {
            return Err(AttachError::PowerTransition.into());
        }
        // A D3hot exit may reset BARs. Restore the exact values only
        // after D0 acknowledgement, before decoding/mastering can be enabled.
        // Also recover a prior partial restore even if PMCSR now reports D0.
        if value & PM_NO_SOFT_RESET == 0
            || snapshot
                .bars
                .iter()
                .enumerate()
                .any(|(i, saved)| config.read32(regs::BASE_ADDRESS_0 + i as u16 * 4) != *saved)
        {
            for (index, value) in snapshot.bars.iter().enumerate() {
                config.write32(regs::BASE_ADDRESS_0 + index as u16 * 4, *value);
            }
        }
        if snapshot
            .bars
            .iter()
            .enumerate()
            .any(|(i, saved)| config.read32(regs::BASE_ADDRESS_0 + i as u16 * 4) != *saved)
        {
            return Err(AttachError::InvalidBar.into());
        }
        for control in r.identity.setup.controls() {
            control.apply(config)?;
        }
        // The original adapter has always used polled delivery. Keep every PCI
        // interrupt path masked before making MMIO available again.
        for (offset, enable) in [(caps.msi, 1), (caps.msix, 1 << 15)] {
            if let Some(offset) = offset {
                let previous = config.read16(offset + 2);
                if previous == u16::MAX {
                    return Err(AttachError::ConfigurationRejected.into());
                }
                config.write16(offset + 2, previous & !enable);
                let observed = config.read16(offset + 2);
                if observed == u16::MAX || observed & enable != 0 {
                    return Err(AttachError::ConfigurationRejected.into());
                }
            }
        }
        let enabled = disabled | regs::COMMAND_MEMORY | regs::COMMAND_MASTER;
        config.write16(regs::COMMAND, enabled);
        let observed = config.read16(regs::COMMAND);
        if observed == u16::MAX || observed != enabled {
            config.write16(regs::COMMAND, disabled);
            return Err(AttachError::ConfigurationRejected.into());
        }
        r.suspended = None;
        // `reinitialize` performs fresh RUN-off acknowledgements and reset
        // before retiring the software generation or starting command engines.
        if let Err(error) = self.reinitialize() {
            // D0 is confirmed but reset/stop may be uncertain. Suppress ordinary
            // MMIO and keep the snapshot for another explicit recovery attempt.
            self.registers.suspended = Some(snapshot);
            return Err(error.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
