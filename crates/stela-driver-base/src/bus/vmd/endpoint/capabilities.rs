// SPDX-License-Identifier: GPL-2.0-only
// PCI encodings follow Linux include/uapi/linux/pci_regs.h, copyright
// 1994 Drew Eckhardt and 1997-1999 Martin Mares; see NOTICE.
//! Extent-checked capabilities through the retained VMD child transport.
use super::*;
use crate::bus::pci::{self, capability::Transport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Capabilities {
    pub pm: Option<u16>,
    msi: Option<u16>,
    msix: Option<u16>,
    pcie: Option<(u16, u16)>,
}

fn word<R: Registers>(config: &mut ChildConfig<'_, R>, offset: u16) -> Result<u16, Error> {
    let value = config.read(offset, 2)? as u16;
    (value != u16::MAX)
        .then_some(value)
        .ok_or(Error::ReadFailed)
}
/// Which capabilities a function behind VMD is checked on, as for a stopped
/// function the PC's own PCI bus holds (`pci::requester`): only those with a
/// control that can make it send a request or an interrupt while Bus Master
/// and INTx Disable say it is quiet, and those this hierarchy's power and
/// routing steps use. Linux's VMD driver validates no capability list. Every
/// other capability is ignored, whatever its ID: bridge subsystem IDs, SATA,
/// vendor-specific and other identifying data; AER, ACS, ARI, virtual
/// channels, LTR, secondary PCI Express, L1 substates, PTM, data link
/// features, the physical layers, lane margining and other link, routing and
/// port-only layers, whose requests are messages or need Bus Master and whose
/// interrupts are the MSI, MSI-X or INTx this hierarchy keeps off. Firmware
/// commonly leaves several of them on the root port and SSD behind VMD.
impl Capabilities {
    pub(super) fn inspect<R: Registers>(
        config: &mut ChildConfig<'_, R>,
        bridge: bool,
    ) -> Result<Self, Error> {
        let mut result = Self {
            pm: None,
            msi: None,
            msix: None,
            pcie: None,
        };
        let standard =
            pci::Capabilities::new(Transport(|offset, bytes| config.read(offset, bytes)))
                .collect::<Result<Vec<_>, Error>>()?;
        let mut singleton = 0u32;
        for entry in standard {
            let (offset, id) = (entry.offset, entry.id);
            match id {
                1 => {
                    if !(1..=3).contains(&(word(config, offset + 2)? & 7)) {
                        return Err(Error::Capability);
                    }
                    result.pm = Some(offset);
                }
                5 => {
                    let control = word(config, offset + 2)?;
                    let supported = (control >> 1) & 7;
                    if control & (1 << 10) != 0
                        || control & 1 != 0
                        || supported > 5
                        || ((control >> 4) & 7) > supported
                    {
                        return Err(Error::ActiveChild);
                    }
                    result.msi = Some(offset);
                }
                0x10 => {
                    let flags = word(config, offset + 2)?;
                    let version = flags & 15;
                    let kind = (flags >> 4) & 15;
                    if !matches!(version, 1 | 2)
                        || !(if bridge {
                            matches!(kind, 4..=6)
                        } else {
                            matches!(kind, 0 | 1 | 9)
                        })
                        || (!bridge && flags & 0x100 != 0)
                    {
                        return Err(Error::Capability);
                    }
                    // Keep coherent payload policy: No Snoop stays off (the
                    // stop clears it). A bridge forwarding ARI would turn
                    // the frozen scan's device numbers into other functions.
                    if word(config, offset + 8)? & (1 << 11) != 0
                        || (bridge && version == 2 && word(config, offset + 0x28)? & 0x20 != 0)
                    {
                        return Err(Error::ActiveChild);
                    }
                    result.pcie = Some((offset, flags));
                }
                0x11 => {
                    if word(config, offset + 2)? & 0x8000 != 0 {
                        return Err(Error::ActiveChild);
                    }
                    result.msix = Some(offset);
                }
                _ => continue,
            }
            let bit = 1u32 << id;
            if singleton & bit != 0 {
                return Err(Error::Capability);
            }
            singleton |= bit;
        }
        result.extended(config)?;
        Ok(result)
    }
    pub(super) fn is_pcie(&self) -> bool {
        self.pcie.is_some()
    }

    fn extended<R: Registers>(&self, config: &mut ChildConfig<'_, R>) -> Result<(), Error> {
        // A conventional function has no extended configuration space, and
        // Linux reads none of it (`pci_cfg_space_size`); for a PCI Express
        // one an all-ones first header means none (`pci_cfg_space_size_ext`).
        if self.pcie.is_none() || config.read(0x100, 4)? == u32::MAX {
            return Ok(());
        }
        let entries =
            pci::ExtendedCapabilities::new(Transport(|offset, bytes| config.read(offset, bytes)))
                .collect::<Result<Vec<_>, Error>>()?;
        let mut seen = Vec::new();
        for entry in &entries {
            let (offset, id) = (entry.offset, entry.id);
            if !matches!(id, 0xf | 0x10 | 0x13 | 0x1b) {
                continue;
            }
            if seen.contains(&id) || entry.version != 1 {
                return Err(Error::Capability);
            }
            seen.push(id);
            let active = match id {
                // ATS and PASID enables let the function translate addresses.
                0xf => word(config, offset + 6)? & 0x8000 != 0,
                0x1b => word(config, offset + 6)? & 1 != 0,
                // SR-IOV: inert while its virtual functions are off.
                0x10 => word(config, offset + 8)? & 1 != 0,
                // PRI: enabled, or not stopped.
                _ => word(config, offset + 4)? & 3 != 0 || word(config, offset + 6)? & 0x100 == 0,
            };
            if active {
                return Err(Error::ActiveChild);
            }
        }
        Ok(())
    }
    pub(super) fn power_up<R: Registers>(
        &self,
        config: &mut ChildConfig<'_, R>,
        timer: &(impl crate::bus::pci::power::Timer + ?Sized),
    ) -> Result<(), Error> {
        timer.check()?;
        for (offset, enabled) in [(self.msi, 1), (self.msix, 0x8000)] {
            if let Some(offset) = offset
                && word(config, offset + 2)? & enabled != 0
            {
                return Err(Error::ActiveChild);
            }
        }
        let Some(pm) = self.pm else {
            return Ok(());
        };
        let control = word(config, pm + 4)?;
        // Do not replay PME_Status (W1C). Disable PME generation as well as
        // choosing D0; another owner's pending event is not acknowledged here.
        config.write(pm + 4, 2, u32::from(control & !0x8103))?;
        match control & 3 {
            3 => timer.wait_us(10_000)?,
            2 => timer.wait_us(200)?,
            _ => {}
        }
        if word(config, pm + 4)? & 0x103 != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }
    pub(super) fn check_d0<R: Registers>(
        &self,
        config: &mut ChildConfig<'_, R>,
    ) -> Result<(), Error> {
        if let Some(pm) = self.pm
            && word(config, pm + 4)? & 0x103 != 0
        {
            return Err(Error::Suspended);
        }
        Ok(())
    }
}
