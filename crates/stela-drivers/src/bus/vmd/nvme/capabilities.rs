// SPDX-License-Identifier: GPL-2.0-only
// PCI encodings follow Linux include/uapi/linux/pci_regs.h, copyright
// 1994 Drew Eckhardt and 1997-1999 Martin Mares; see bus/THIRD_PARTY.md.
//! Fallible, extent-checked capabilities; no infallible ConfigSpace adapter.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Capabilities {
    pub pm: Option<u16>,
    msi: Option<u16>,
    msix: Option<u16>,
    pcie: Option<(u16, u16)>,
}

struct Extents([bool; 4096]);
impl Extents {
    fn free_payload(&self, offset: u16, header: u16, bytes: u16, limit: u16) -> Result<(), Error> {
        extent(offset, bytes, limit)?;
        if self.0[usize::from(offset + header)..usize::from(offset + bytes)]
            .iter()
            .any(|used| *used)
        {
            return Err(Error::Capability);
        }
        Ok(())
    }
    fn reserve(&mut self, offset: u16, bytes: u16, limit: u16) -> Result<(), Error> {
        let end = offset
            .checked_add(bytes)
            .filter(|end| *end <= limit)
            .ok_or(Error::Capability)?;
        if bytes < 2 || !offset.is_multiple_of(4) {
            return Err(Error::Capability);
        }
        let span = &mut self.0[usize::from(offset)..usize::from(end)];
        if span.iter().any(|occupied| *occupied) {
            return Err(Error::Capability);
        }
        span.fill(true);
        Ok(())
    }
}
fn word<R: Registers>(config: &mut ChildConfig<'_, R>, offset: u16) -> Result<u16, Error> {
    let value = config.read(offset, 2)? as u16;
    (value != u16::MAX)
        .then_some(value)
        .ok_or(Error::ReadFailed)
}
fn extent(offset: u16, bytes: u16, limit: u16) -> Result<(), Error> {
    offset
        .checked_add(bytes)
        .filter(|end| *end <= limit)
        .map(|_| ())
        .ok_or(Error::Capability)
}
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
        let mut extents = Extents([false; 4096]);
        let mut singleton = 0u32;
        let mut offset = if word(config, 6)? & 0x10 != 0 {
            config.read(0x34, 1)? as u16
        } else {
            0
        };
        while offset != 0 {
            if !(0x40..=0xfc).contains(&offset) || !offset.is_multiple_of(4) {
                return Err(Error::Capability);
            }
            if extents.0[usize::from(offset)] {
                return Err(Error::Capability);
            }
            let header = word(config, offset)?;
            let id = header & 255;
            // Reserve the header before reading a capability-specific body.
            // Later full reservation excludes this already checked header.
            extents.reserve(offset, 4, 256)?;
            let bytes = match id {
                1 => {
                    extent(offset, 8, 256)?;
                    if !(1..=3).contains(&(word(config, offset + 2)? & 7)) {
                        return Err(Error::Capability);
                    }
                    result.pm = Some(offset);
                    8
                }
                5 => {
                    let control = word(config, offset + 2)?;
                    let supported = (control >> 1) & 7;
                    if control & !0x1ff != 0
                        || control & 1 != 0
                        || supported > 5
                        || ((control >> 4) & 7) > supported
                    {
                        return Err(Error::ActiveChild);
                    }
                    result.msi = Some(offset);
                    match (control & 0x80 != 0, control & 0x100 != 0) {
                        (false, false) => 10,
                        (true, false) => 14,
                        (false, true) => 20,
                        (true, true) => 24,
                    }
                }
                9 => {
                    let bytes = config.read(offset + 2, 1)? as u16;
                    if bytes < 3 {
                        return Err(Error::Capability);
                    }
                    bytes
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
                    let bytes = if bridge {
                        if version == 1 { 0x24 } else { 0x3c }
                    } else if kind == 9 {
                        if version == 1 { 12 } else { 44 }
                    } else if version == 1 {
                        20
                    } else {
                        52
                    };
                    extents.free_payload(offset, 4, bytes, 256)?;
                    // Retain coherent payload policy; do not silently admit
                    // NoSnoop, autonomous AtomicOp requests or ARI fanout.
                    if word(config, offset + 8)? & (1 << 11) != 0
                        || (version == 2 && word(config, offset + 0x28)? & 0x60 != 0)
                    {
                        return Err(Error::ActiveChild);
                    }
                    result.pcie = Some((offset, flags));
                    bytes
                }
                0x11 => {
                    if word(config, offset + 2)? & 0x8000 != 0 {
                        return Err(Error::ActiveChild);
                    }
                    result.msix = Some(offset);
                    12
                }
                _ => return Err(Error::Capability),
            };
            extent(offset, bytes, 256)?;
            if bytes > 4 {
                let tail = &mut extents.0[usize::from(offset + 4)..usize::from(offset + bytes)];
                if tail.iter().any(|used| *used) {
                    return Err(Error::Capability);
                }
                tail.fill(true);
            }
            if id != 9 {
                let bit = 1u32.checked_shl(u32::from(id)).ok_or(Error::Capability)?;
                if singleton & bit != 0 {
                    return Err(Error::Capability);
                }
                singleton |= bit;
            }
            offset = header >> 8;
        }
        // Conventional functions remain explicit: the selected NVMe and every
        // path bridge must independently provide the admitted PCIe profile.
        result.extended(config, &mut extents)?;
        Ok(result)
    }
    pub(super) fn is_pcie(&self) -> bool {
        self.pcie.is_some()
    }

    fn extended<R: Registers>(
        &self,
        config: &mut ChildConfig<'_, R>,
        extents: &mut Extents,
    ) -> Result<(), Error> {
        let mut offset: u16 = 0x100;
        let mut seen = Vec::new();
        loop {
            if !(0x100..=0xffc).contains(&offset) || !offset.is_multiple_of(4) {
                return Err(Error::Capability);
            }
            if extents.0[usize::from(offset)] {
                return Err(Error::Capability);
            }
            let header = config.read(offset, 4)?;
            if header == 0 && offset == 0x100 {
                return Ok(());
            }
            if header == u32::MAX {
                return Err(Error::ReadFailed);
            }
            let id = header as u16;
            let version = ((header >> 16) & 15) as u8;
            if seen.contains(&id) {
                return Err(Error::Capability);
            }
            seen.push(id);
            // Reserve first so a link into a previous payload is never read as
            // a capability-specific control field.
            extents.reserve(offset, 4, 4096)?;
            let bytes = match (id, version) {
                (1, 1 | 2) => {
                    extents.free_payload(offset, 4, 0x2c, 4096)?;
                    let control = config.read(offset + 0x18, 4)?;
                    if control == u32::MAX {
                        return Err(Error::ReadFailed);
                    }
                    let root = self.pcie.is_some_and(|(_, flags)| (flags >> 4) & 15 == 4);
                    if root {
                        extents.free_payload(offset, 4, 0x38, 4096)?;
                        if config.read(offset + 0x2c, 4)? & 7 != 0 {
                            return Err(Error::ActiveChild);
                        }
                    }
                    if control & (1 << 11) != 0 {
                        0x48
                    } else if root {
                        0x38
                    } else {
                        0x2c
                    }
                }
                (3, 1) => 12, // Device serial number; no DMA control.
                (0xf, 1) => {
                    extents.free_payload(offset, 4, 8, 4096)?;
                    if word(config, offset + 6)? & 0x8000 != 0 {
                        return Err(Error::ActiveChild);
                    }
                    8
                }
                (0x13, 1) => {
                    extents.free_payload(offset, 4, 16, 4096)?;
                    if word(config, offset + 4)? & 3 != 0 || word(config, offset + 6)? & 0x100 == 0
                    {
                        return Err(Error::ActiveChild);
                    }
                    16
                }
                (0x18, 1) => 8, // Read-only admission of retained LTR values.
                (0x1b, 1) => {
                    extents.free_payload(offset, 4, 8, 4096)?;
                    if word(config, offset + 6)? & 1 != 0 {
                        return Err(Error::ActiveChild);
                    }
                    8
                }
                // SR-IOV, unknown traffic-producing controls and other
                // unqualified capabilities are explicit profile refusals.
                _ => return Err(Error::Capability),
            };
            extent(offset, bytes, 4096)?;
            let tail = &mut extents.0[usize::from(offset + 4)..usize::from(offset + bytes)];
            if tail.iter().any(|used| *used) {
                return Err(Error::Capability);
            }
            tail.fill(true);
            offset = (header >> 20) as u16;
            if offset == 0 {
                return Ok(());
            }
        }
    }
    pub(super) fn power_up<R: Registers>(
        &self,
        config: &mut ChildConfig<'_, R>,
        clock: Clock,
    ) -> Result<(), Error> {
        for (offset, enabled) in [(self.msi, 1), (self.msix, 0x8000)] {
            if let Some(offset) = offset {
                if word(config, offset + 2)? & enabled != 0 {
                    return Err(Error::ActiveChild);
                }
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
            3 => clock.delay(10_000),
            2 => clock.delay(200),
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
        if let Some(pm) = self.pm {
            if word(config, pm + 4)? & 0x103 != 0 {
                return Err(Error::Suspended);
            }
        }
        Ok(())
    }
}
