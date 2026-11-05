//! Original AMD host graph inspection, not table/allocation/root authority.
//! The actual original unit/memory owner must retain the inspected objects.
use super::{DataMode, Dte};
use alloc::vec::Vec;
const PAGE: u64 = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const READ: u64 = 1 << 61;
const WRITE: u64 = 1 << 62;
const FC: u64 = 1 << 60;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Memory,
    Profile,
    Source,
    Capacity,
    Cycle,
    Encoding,
    UnsupportedLeaf,
    ControlWritable,
    ControlAlias,
}

/// Actual original RAM access/exclusion under the original CPU/root owner.
/// # Safety
/// The implementor retains real allocation or successful EBS transfer rights,
/// not just copied ranges. CPU/firmware table writers are excluded; hardware
/// A/D/table writers are disabled. Reads use those actual kept bytes and a
/// checked original CPU mapping. Mutable OS backing is never inferred from
/// generic reserved/runtime RAM. No read or returned bool grants DMA retirement.
pub unsafe trait Memory {
    fn contains(&self, physical: u64, bytes: u64) -> bool;
    fn owns_os_ram(&self, physical: u64, bytes: u64) -> bool;
    fn read(&self, physical: u64) -> Result<u64, Error>;
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ControlKind {
    DeviceTable,
    HostTable(u8),
    Command,
    Completion,
    Event,
    Ppr,
    GuestApic,
    RetirementCommand(usize),
    RetirementCompletion(usize),
}
#[derive(Clone, Copy, Debug)]
pub struct Description {
    pub base: u64,
    pub bytes: u64,
    pub physical_bits: u8,
    pub maximum_levels: u8,
}
pub struct Inventory {
    controls: Vec<(u64, ControlKind)>,
    writable: Vec<(u64, u64)>,
    dtes: Vec<(u16, Dte)>,
}
impl Inventory {
    /// Descriptive exact inspected values; no table mutation/access grant.
    pub fn dtes(&self) -> &[(u16, Dte)] {
        &self.dtes
    }
}
struct Walker<'a, M> {
    memory: &'a M,
    bits: u8,
    seen: Vec<(u64, ControlKind)>,
    active: Vec<u64>,
    writable_tables: Vec<u64>,
    writable: Vec<(u64, u64)>,
}
impl<M: Memory> Walker<'_, M> {
    fn word(&self, at: u64) -> Result<u64, Error> {
        if !at.is_multiple_of(8) || at >= 1u64 << self.bits || !self.memory.contains(at, 8) {
            return Err(Error::Memory);
        }
        self.memory.read(at)
    }
    fn control(&mut self, page: u64, kind: ControlKind) -> Result<bool, Error> {
        if !page.is_multiple_of(PAGE) || !self.memory.owns_os_ram(page, PAGE) {
            return Err(Error::Memory);
        }
        if let Some((_, old)) = self.seen.iter().find(|(p, _)| *p == page) {
            return if *old == kind {
                Ok(false)
            } else {
                Err(Error::ControlAlias)
            };
        }
        if self.seen.len() == 4096 {
            return Err(Error::Capacity);
        }
        self.seen.push((page, kind));
        Ok(true)
    }
    fn walk(&mut self, page: u64, level: u8, writable: bool) -> Result<(), Error> {
        if self.active.contains(&page) {
            return Err(Error::Cycle);
        }
        let fresh = self.control(page, ControlKind::HostTable(level))?;
        if !fresh && (!writable || self.writable_tables.contains(&page)) {
            return Ok(());
        }
        if writable {
            self.writable_tables.push(page);
        }
        self.active.push(page);
        for index in 0..512u64 {
            let entry = self.word(page + index * 8)?;
            if entry & 1 == 0 {
                if entry != 0 {
                    return Err(Error::Encoding);
                }
                continue;
            }
            if level == 6 && index >= 128 {
                return Err(Error::Encoding);
            }
            if entry & !(ADDRESS | 1 | (7 << 9) | READ | WRITE | FC) != 0 {
                return Err(Error::Encoding);
            }
            let next = ((entry >> 9) & 7) as u8;
            let target = entry & ADDRESS;
            let write = writable && entry & WRITE != 0;
            if next == 0 {
                // Initial source-backed profile supports ordinary4KiB leaves;
                // large/contiguous and skipped levels require their own codec.
                if level != 1 {
                    return Err(Error::UnsupportedLeaf);
                }
                if target
                    .checked_add(PAGE)
                    .is_none_or(|end| end > 1u64 << self.bits)
                    || !self.memory.contains(target, PAGE)
                {
                    return Err(Error::Memory);
                }
                if write {
                    self.writable.push((target, PAGE));
                }
            } else {
                if next != level - 1 || entry & FC != 0 {
                    return Err(Error::UnsupportedLeaf);
                }
                self.walk(target, next, write)?;
            }
        }
        self.active.pop();
        Ok(())
    }
}
pub fn inspect(
    memory: &impl Memory,
    description: Description,
    allowed: &[u16],
) -> Result<Inventory, Error> {
    let Description {
        base,
        bytes,
        physical_bits,
        maximum_levels,
    } = description;
    if !(32..=52).contains(&physical_bits)
        || !(1..=6).contains(&maximum_levels)
        || !base.is_multiple_of(PAGE)
        || bytes == 0
        || bytes > 2 * 1024 * 1024
        || !bytes.is_multiple_of(PAGE)
        || base
            .checked_add(bytes)
            .is_none_or(|end| end > 1u64 << physical_bits)
        || !memory.owns_os_ram(base, bytes)
    {
        return Err(Error::Memory);
    }
    if allowed
        .iter()
        .any(|rid| usize::from(*rid) >= bytes as usize / 32)
    {
        return Err(Error::Source);
    }
    let mut w = Walker {
        memory,
        bits: physical_bits,
        seen: Vec::new(),
        active: Vec::new(),
        writable_tables: Vec::new(),
        writable: Vec::new(),
    };
    for page in (base..base + bytes).step_by(PAGE as usize) {
        w.control(page, ControlKind::DeviceTable)?;
    }
    let mut dtes = Vec::new();
    for index in 0..bytes / 32 {
        let at = base + index * 32;
        let words = [
            w.word(at)?,
            w.word(at + 8)?,
            w.word(at + 16)?,
            w.word(at + 24)?,
        ];
        let dte = Dte::inspect_host(words, physical_bits).map_err(|_| Error::Profile)?;
        match dte.mode() {
            DataMode::WalkTerminated => {}
            DataMode::Paged {
                levels,
                root,
                write,
                ..
            } => {
                if !allowed.contains(&(index as u16)) {
                    return Err(Error::Source);
                }
                if levels > maximum_levels {
                    return Err(Error::Profile);
                }
                w.walk(root, levels, write)?;
            }
            // Identity mode is not remapped; all-zero DTEs are not blocks.
            DataMode::Identity { .. } | DataMode::Untranslated => return Err(Error::Profile),
        }
        dtes.push((index as u16, dte));
    }
    Ok(Inventory {
        controls: w.seen,
        writable: w.writable,
        dtes,
    })
}

/// All actual units plus old/new real queue/log/completion backings must be
/// represented. Extra ranges are DATA projected from retained allocation owners.
/// This check alone never creates physical ownership or a retirement receipt.
pub fn validate_all(
    inventories: &[Inventory],
    extra: &[(u64, u64, ControlKind)],
) -> Result<(), Error> {
    validate_refs(&inventories.iter().collect::<Vec<_>>(), extra)
}
pub fn validate_refs(
    inventories: &[&Inventory],
    extra: &[(u64, u64, ControlKind)],
) -> Result<(), Error> {
    let mut controls = inventories
        .iter()
        .flat_map(|i| i.controls.iter().copied())
        .collect::<Vec<_>>();
    for &(base, bytes, kind) in extra {
        if bytes == 0
            || !base.is_multiple_of(PAGE)
            || !bytes.is_multiple_of(PAGE)
            || base.checked_add(bytes).is_none()
        {
            return Err(Error::Memory);
        }
        for page in (base..base + bytes).step_by(PAGE as usize) {
            controls.push((page, kind));
        }
    }
    controls.sort_unstable();
    if controls
        .windows(2)
        .any(|w| w[0].0 == w[1].0 && w[0].1 != w[1].1)
    {
        return Err(Error::ControlAlias);
    }
    let mut writes = inventories
        .iter()
        .flat_map(|i| i.writable.iter().copied())
        .collect::<Vec<_>>();
    writes.sort_unstable();
    let mut cursor = 0;
    for (page, _) in controls {
        while cursor < writes.len() && writes[cursor].0 + writes[cursor].1 <= page {
            cursor += 1;
        }
        if cursor < writes.len() && writes[cursor].0 <= page {
            return Err(Error::ControlWritable);
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;
