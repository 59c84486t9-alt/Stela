// SPDX-License-Identifier: GPL-2.0-only
//! MSI-X capability discovery: where the table and pending-bit array sit.
use super::*;
use crate::bus::pci::ConfigSpace;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Layout {
    pub offset: u16,
    pub header: u16,
    pub vectors: u16,
    pub table_bar: u8,
    pub table_offset: u64,
    pub pending_bar: u8,
    pub pending_offset: u64,
    table_physical: PhysicalSpan,
    pending_physical: PhysicalSpan,
}
fn word<C: ConfigSpace>(config: &C, offset: u16) -> Result<u16, Error> {
    let value = config.read16(offset);
    if value == u16::MAX {
        Err(MsiError::FailedRead { offset }.into())
    } else {
        Ok(value)
    }
}
fn dword<C: ConfigSpace>(config: &C, offset: u16) -> Result<u32, Error> {
    let value = config.read32(offset);
    if value == u32::MAX {
        Err(MsiError::FailedRead { offset }.into())
    } else {
        Ok(value)
    }
}
fn bar<C: ConfigSpace, B: BarAccess>(
    config: &C,
    bars: &[Option<B>; 6],
    bir: u8,
    offset: u64,
    bytes: u64,
    header: u8,
) -> Result<PhysicalSpan, Error> {
    let count = if header == 0 { 6 } else { 2 };
    if usize::from(bir) >= count {
        return Err(Error::InvalidBar);
    }
    let backing = bars[usize::from(bir)].as_ref().ok_or(Error::InvalidBar)?;
    let mut index = 0;
    let base = loop {
        if index >= count {
            return Err(Error::InvalidBar);
        }
        let low = dword(config, 0x10 + index as u16 * 4)?;
        if low & 1 == 0 && !matches!(low & 6, 0 | 4) {
            // A reserved or legacy below-1MiB memory type does not authorize
            // guessing how subsequent BAR indices are laid out.
            return Err(Error::InvalidBar);
        }
        let wide = low & 7 == 4;
        if index == usize::from(bir) {
            if low & 1 != 0 || !matches!(low & 6, 0 | 4) {
                return Err(Error::InvalidBar);
            }
            let high = if wide {
                if index + 1 >= count {
                    return Err(Error::InvalidBar);
                }
                u64::from(dword(config, 0x14 + index as u16 * 4)?)
            } else {
                0
            };
            break high << 32 | u64::from(low & !15);
        }
        if wide && index + 1 == usize::from(bir) {
            return Err(Error::InvalidBar);
        }
        index += if wide { 2 } else { 1 };
    };
    let physical = backing.physical_span();
    if base == 0
        || physical.start() != base
        || offset
            .checked_add(bytes)
            .is_none_or(|end| end > physical.bytes())
        || !backing.accessible(offset, bytes)
    {
        return Err(Error::Mapping);
    }
    Ok(physical)
}

pub(super) fn discover<C: MsiConfigSpace, B: BarAccess>(
    function: &mut Function<C>,
    bars: &[Option<B>; 6],
) -> Result<(Layout, u16), Error> {
    let expected = u32::from(function.vendor) | u32::from(function.device) << 16;
    let config = function.config();
    if dword(config, 0)? != expected {
        return Err(MsiError::IdentityChanged.into());
    }
    let header_type = config.read8(0x0e) & 0x7f;
    if !matches!(header_type, 0 | 1) {
        return Err(MsiError::Unsupported.into());
    }
    if word(config, COMMAND)? & 2 == 0 {
        return Err(Error::MemoryDisabled);
    }
    // The walk reads Status; without a capability list nothing is found.
    let mut found = None;
    let mut msi = false;
    for entry in config.capabilities() {
        let entry = entry.map_err(MsiError::from)?;
        let (offset, header) = (entry.offset, entry.header);
        match entry.id {
            0x11 => {
                if found.is_some() {
                    return Err(MsiError::MalformedCapability.into());
                }
                let control = word(config, offset + 2)?;
                if control & 0x3800 != 0 {
                    return Err(MsiError::Unsupported.into());
                }
                let vectors = (control & 0x7ff) + 1;
                let table = dword(config, offset + 4)?;
                let pending = dword(config, offset + 8)?;
                let table_bar = (table & 7) as u8;
                let pending_bar = (pending & 7) as u8;
                let table_offset = u64::from(table & !7);
                let pending_offset = u64::from(pending & !7);
                let table_bytes = u64::from(vectors) * ENTRY_BYTES;
                let pending_bytes = u64::from(vectors).div_ceil(64) * 8;
                let table_physical = bar(
                    config,
                    bars,
                    table_bar,
                    table_offset,
                    table_bytes,
                    header_type,
                )?;
                let pending_physical = bar(
                    config,
                    bars,
                    pending_bar,
                    pending_offset,
                    pending_bytes,
                    header_type,
                )?;
                if table_bar == pending_bar {
                    if table_offset < pending_offset + pending_bytes
                        && pending_offset < table_offset + table_bytes
                    {
                        return Err(Error::InvalidTable);
                    }
                } else if table_physical.start() < pending_physical.end()
                    && pending_physical.start() < table_physical.end()
                {
                    return Err(Error::InvalidBar);
                }
                found = Some((
                    Layout {
                        offset,
                        header,
                        vectors,
                        table_bar,
                        table_offset,
                        pending_bar,
                        pending_offset,
                        table_physical,
                        pending_physical,
                    },
                    control,
                ));
            }
            5 => {
                if msi {
                    return Err(MsiError::MalformedCapability.into());
                }
                msi = true;
                let control = word(config, offset + 2)?;
                if control & 1 != 0 {
                    return Err(Error::ActiveMsi);
                }
                if control & !(0x01 | 0x0e | 0x70 | 0x80 | 0x100) != 0
                    || (control & 0x0e) >> 1 > 5
                    || (control & 0x70) >> 4 > (control & 0x0e) >> 1
                {
                    return Err(MsiError::Unsupported.into());
                }
            }
            0 => return Err(MsiError::MalformedCapability.into()),
            _ if entry.layout == crate::bus::pci::Layout::Unsupported => {
                return Err(MsiError::Unsupported.into());
            }
            _ => {}
        }
    }
    found.ok_or(Error::MissingCapability)
}
