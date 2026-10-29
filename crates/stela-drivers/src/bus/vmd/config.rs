// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2015, Intel Corporation.
//! Configuration access to devices on a VMD child bus.
use super::*;

/// Exclusive child configuration borrow. This supplies no
/// `pci::Address`: a 32-bit VMD domain cannot be truncated to an ACPI segment.
pub struct ChildConfig<'a, R: Registers> {
    pub(super) host: &'a mut Host<R>,
    pub(super) base: usize,
    pub(super) address: Address,
}
impl<R: Registers> ChildConfig<'_, R> {
    pub fn address(&self) -> Address {
        self.address
    }
    fn offset(&self, offset: u16, width: u8) -> Result<usize, Error> {
        if !matches!(width, 1 | 2 | 4)
            || !offset.is_multiple_of(u16::from(width))
            || usize::from(offset) + usize::from(width) > 4096
        {
            return Err(Error::Address);
        }
        self.base
            .checked_add(usize::from(offset))
            .ok_or(Error::Address)
    }
    pub fn read(&mut self, offset: u16, width: u8) -> Result<u32, Error> {
        self.host.check_live()?;
        let absolute = self.offset(offset, width)?;
        let result = self.host.io().child_read(absolute, width);
        if result.is_err() {
            self.host.poisoned = true;
        }
        result
    }
    pub fn write(&mut self, offset: u16, width: u8, value: u32) -> Result<(), Error> {
        self.host.check_live()?;
        let absolute = self.offset(offset, width)?;
        // Until the shared requester permission accepts synthetic domains, no
        // safe configuration API may enable child DMA. Also catch a byte write
        // of COMMAND and DWORD writes covering COMMAND/Status.
        if offset == COMMAND && value & u32::from(BUS_MASTER) != 0 {
            return Err(Error::ActiveChild);
        }
        let result = self.host.io().child_write(absolute, width, value);
        if result.is_err() {
            self.host.poisoned = true;
        }
        result
    }
    /// Exact ACPI companion address from pinned vmd_acpi_find_companion.
    pub fn acpi_address(&self) -> Option<u32> {
        let relative = self.address.bus.checked_sub(self.host.first_bus)?;
        (relative <= 31).then_some(
            u32::from(relative) << 24
                | u32::from(self.address.device * 8 + self.address.function) << 16
                | 0x8000_ffff,
        )
    }
}

impl<R: Registers> Host<R> {
    /// The bytes `child`'s memory BAR0 decodes, sized as Linux's
    /// `__pci_read_base` does: memory and I/O decode off while the BAR holds
    /// all ones, then the BAR and command register restored.
    pub fn memory_bar_bytes(&mut self, child: Address) -> Result<u64, Error> {
        let mut config = self.config(child.bus, child.device, child.function)?;
        let command = config.read(COMMAND, 2)?;
        config.write(COMMAND, 2, command & !u32::from(MEMORY | 1))?;
        let size = |config: &mut ChildConfig<'_, R>, offset: u16| -> Result<(u32, u32), Error> {
            let value = config.read(offset, 4)?;
            config.write(offset, 4, u32::MAX)?;
            let mask = config.read(offset, 4)?;
            config.write(offset, 4, value)?;
            Ok((value, mask))
        };
        let sized = (|| {
            let (low, low_mask) = size(&mut config, 0x10)?;
            if low & 1 != 0 {
                return Err(Error::InvalidResource);
            }
            let high_mask = if low & 6 == 4 {
                size(&mut config, 0x14)?.1
            } else {
                0
            };
            let writable = u64::from(high_mask) << 32 | u64::from(low_mask & !15);
            Ok(writable.isolate_lowest_one())
        })();
        config.write(COMMAND, 2, command)?;
        let bytes = sized?;
        if bytes == 0 {
            return Err(Error::InvalidResource);
        }
        Ok(bytes)
    }
}

// ConfigSpace cannot propagate hardware faults and is not
// implemented: a failed read must poison/keep the hierarchy rather than
// return an invented all-ones value that looks like an absent child.

pub(super) fn scan<R: Registers>(host: &mut Host<R>) -> Result<Vec<Child>, Error> {
    host.check_live()?;
    let mut found = Vec::new();
    for bus in host.buses() {
        for device in 0..32 {
            let mut functions = 1;
            let mut function = 0;
            while function < functions {
                let mut config = host.config(bus, device, function)?;
                let id = config.read(0, 4)?;
                if id as u16 != u16::MAX {
                    let header = config.read(0x0e, 1)? as u8;
                    if function == 0 && header & 0x80 != 0 {
                        functions = 8;
                    }
                    let class = config.read(8, 4)?;
                    found.push(Child {
                        address: config.address(),
                        vendor: id as u16,
                        device: (id >> 16) as u16,
                        class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
                        header: header & 0x7f,
                    });
                }
                function += 1;
            }
        }
    }
    Ok(found)
}
