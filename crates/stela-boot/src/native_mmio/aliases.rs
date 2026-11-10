//! The loader's page tables as the native MMIO source sees them: the table
//! pages it owns and every existing alias its roots and the guest's RAM hold.
use super::*;
use crate::{
    engine::host::MmioRoots,
    native_smp::{memory_types::Image, topology::Snapshot},
};
use alloc::vec::Vec;
use stela_drivers::bus::mmio::owned::{AddressSpace, CacheAttribute, ExistingAlias, PhysicalSpan};

/// A table page the loader owns, through the physmap.
pub(super) fn owned_table(wire: &Wire, physical: u64) -> Result<*mut u64, Error> {
    if !wire.table_owned(physical) {
        return Err(Error::Unavailable);
    }
    Ok(crate::layout::physical(physical) as *mut u64)
}

/// Every existing alias the roots and the guest's RAM hold, with
/// its cache policy where the roots fix one, after checking each root leads
/// to the aperture's leaf table. `written` are the table pages the caller
/// writes, whose aliases must be write-back.
pub(super) fn aliases(
    wire: &Wire,
    catalog: &MmioRoots,
    snapshot: &Snapshot,
    space: AddressSpace,
    written: &[u64],
) -> Result<Vec<ExistingAlias>, Error> {
    let roots = catalog.roots();
    if !roots.contains(&(snapshot.cr3 & ADDRESS)) {
        return Err(Error::Unavailable);
    }
    let mut visited = Vec::new();
    let mut aliases = Vec::new();
    let image = Image::from_snapshot(snapshot).map_err(failed)?;
    struct Walk<'a> {
        wire: &'a Wire,
        snapshot: &'a Snapshot,
        space: AddressSpace,
        image: Image,
        written: &'a [u64],
    }
    fn walk(
        p: &Walk<'_>,
        table: u64,
        level: u32,
        visited: &mut Vec<(u64, u32)>,
        aliases: &mut Vec<ExistingAlias>,
    ) -> Result<(), Error> {
        if visited.contains(&(table, level)) {
            return Ok(());
        }
        if visited.len() >= 65536 {
            return Err(Error::Exhausted);
        }
        visited.try_reserve(1).map_err(failed)?;
        visited.push((table, level));
        p.image.writeback_ram(table, PAGE).map_err(failed)?;
        let address = owned_table(p.wire, table)?;
        for index in 0..ENTRIES {
            // SAFETY: `owned_table` admitted this table page and `index` is below `ENTRIES`.
            let entry = unsafe { address.add(index).read_volatile() };
            if entry & PRESENT == 0 {
                continue;
            }
            if level == 0 || entry & HUGE != 0 {
                if level > 2
                    || (level != 0
                        && entry & ADDRESS & ((1u64 << (12 + 9 * level)) - 1) & !(1 << 12) != 0)
                {
                    return Err(Error::Unavailable);
                }
                let bytes = 1u64 << (12 + 9 * level);
                let physical = entry & ADDRESS & !(bytes - 1);
                if physical
                    .checked_add(bytes)
                    .is_none_or(|end| end > 1u64 << p.space.physical_bits)
                {
                    return Err(Error::InvalidRange);
                }
                let pat_index =
                    (entry >> 3 & 3) | ((entry >> if level == 0 { 7 } else { 12 }) & 1) << 2;
                // The adapter writes these table pages. Every data alias of
                // them must agree with their proven WB CPU access and WB
                // page-walker fetch policy; UC/WC/WT/unknown aliases refuse.
                if p.written
                    .iter()
                    .any(|&table| physical < table + PAGE && table < physical + bytes)
                    && (p.snapshot.pat >> (8 * pat_index)) & 0xff != 6
                {
                    return Err(Error::CacheConflict);
                }
                let attribute = if (p.snapshot.pat >> (8 * pat_index)) & 0xff == 0 {
                    Some(CacheAttribute::Uncached)
                } else {
                    None
                };
                aliases.try_reserve(1).map_err(failed)?;
                aliases.push(ExistingAlias {
                    physical: PhysicalSpan::new(physical, bytes)?,
                    attribute,
                });
            } else {
                if entry & ((1 << 3) | (1 << 4)) != 0 {
                    return Err(Error::UnsupportedCache);
                }
                walk(p, entry & ADDRESS, level - 1, visited, aliases)?;
            }
        }
        Ok(())
    }
    let walker = Walk {
        wire,
        snapshot,
        space,
        image,
        written,
    };
    // Every real root is scanned; shared table pages are visited once. Future
    // guest aliases are restricted by HostOwner to its RAM inventory,
    // conservatively imported below with unknown policy (blocks device reuse).
    for root in roots {
        walk(&walker, *root, wire.levels - 1, &mut visited, &mut aliases)?;
    }
    for physical in catalog.ram() {
        aliases.try_reserve(1).map_err(failed)?;
        aliases.push(ExistingAlias {
            physical: *physical,
            attribute: None,
        });
    }
    for root in roots {
        let mut table = *root;
        for level in (1..wire.levels).rev() {
            let slot = ((wire.virtual_base >> (12 + 9 * level)) & 511) as usize;
            // SAFETY: `owned_table` admitted this table page and `slot` is below 512.
            let entry = unsafe { owned_table(wire, table)?.add(slot).read_volatile() };
            if entry & (PRESENT | WRITABLE | HUGE) != (PRESENT | WRITABLE) {
                return Err(Error::Unavailable);
            }
            table = entry & ADDRESS;
        }
        if table != wire.leaf {
            return Err(Error::Unavailable);
        }
    }
    Ok(aliases)
}
