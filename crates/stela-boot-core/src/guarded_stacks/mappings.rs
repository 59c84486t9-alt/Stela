//! Read-only page-table qualification, separate from actual ownership admission.
use super::Slot;
const PAGE: u64 = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const LARGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Geometry,
    TableUnavailable,
    GuardMapped,
    Missing,
    Permissions,
    Physical,
    Cache,
}
struct Leaf {
    physical: u64,
    writable: bool,
    user: bool,
    nx: bool,
    pat: usize,
}
fn leaf(
    address: u64,
    root: u64,
    levels: u32,
    read: &mut impl FnMut(u64, usize) -> Option<u64>,
) -> Result<Option<Leaf>, Error> {
    let bits = 12 + 9 * levels;
    if (((address << (64 - bits)) as i64 >> (64 - bits)) as u64) != address {
        return Err(Error::Geometry);
    }
    let mut table = root;
    let (mut writable, mut user, mut nx) = (true, true, false);
    for level in (0..levels).rev() {
        let entry = read(table, ((address >> (12 + 9 * level)) & 511) as usize)
            .ok_or(Error::TableUnavailable)?;
        if entry & PRESENT == 0 {
            return Ok(None);
        }
        writable &= entry & WRITE != 0;
        user &= entry & USER != 0;
        nx |= entry & NX != 0;
        let large = entry & LARGE != 0;
        if level == 0 || (large && matches!(level, 1 | 2)) {
            let bytes = 1u64 << (12 + 9 * level);
            if level > 0 && entry & ADDRESS & (bytes - 1) & !(1 << 12) != 0 {
                return Err(Error::Geometry);
            }
            let pat_bit = if level == 0 { 7 } else { 12 };
            return Ok(Some(Leaf {
                physical: (entry & ADDRESS & !(bytes - 1)) + (address & (bytes - 1)),
                writable,
                user,
                nx,
                pat: (((entry >> 3) & 3) | (((entry >> pat_bit) & 1) << 2)) as usize,
            }));
        }
        if large {
            return Err(Error::Geometry);
        }
        table = entry & ADDRESS;
    }
    Err(Error::Geometry)
}
/// Check every retained root against the exact physical backing, RW/NX,
/// supervisor access and WB PAT selection; both guard pages must be absent.
/// The caller still owns/retains actual table pages, root/control epochs,
/// MTRR-effective WB, RAM exclusion and all writable aliases. A synthetic
/// reader or numeric root list confers none of that native authority.
pub fn qualify(
    slot: &Slot,
    physical: u64,
    roots: &[u64],
    levels: u32,
    pat: u64,
    mut read: impl FnMut(u64, usize) -> Option<u64>,
) -> Result<(), Error> {
    if !matches!(levels, 4 | 5)
        || roots.is_empty()
        || slot.lower_guard.end != slot.usable.start
        || slot.usable.end != slot.upper_guard.start
        || slot.lower_guard.end.checked_sub(slot.lower_guard.start) != Some(PAGE)
        || slot.upper_guard.end.checked_sub(slot.upper_guard.start) != Some(PAGE)
        || slot.usable.start >= slot.usable.end
        || !physical.is_multiple_of(PAGE)
        || [
            slot.lower_guard.start,
            slot.usable.start,
            slot.usable.end,
            slot.upper_guard.end,
        ]
        .iter()
        .any(|address| !address.is_multiple_of(PAGE))
        || physical
            .checked_add(slot.usable.end - slot.usable.start)
            .is_none()
    {
        return Err(Error::Geometry);
    }
    for root in roots {
        if *root == 0 || root & !ADDRESS != 0 {
            return Err(Error::Geometry);
        }
        for guard in [slot.lower_guard.start, slot.upper_guard.start] {
            if leaf(guard, *root, levels, &mut read)?.is_some() {
                return Err(Error::GuardMapped);
            }
        }
        for address in (slot.usable.start..slot.usable.end).step_by(PAGE as usize) {
            let leaf = leaf(address, *root, levels, &mut read)?.ok_or(Error::Missing)?;
            if !leaf.writable || leaf.user || !leaf.nx {
                return Err(Error::Permissions);
            }
            if leaf.physical != physical + (address - slot.usable.start) {
                return Err(Error::Physical);
            }
            if ((pat >> (leaf.pat * 8)) & 255) != 6 {
                return Err(Error::Cache);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::guarded_stacks::Layout;
    fn tables() -> [[u64; 512]; 5] {
        let mut t = [[0; 512]; 5];
        for (index, table) in t[..3].iter_mut().enumerate() {
            table[0] = ((index as u64 + 2) * PAGE) | PRESENT | WRITE;
        }
        t[3][1] = 0x10_0000 | PRESENT | WRITE | NX;
        t[4][0] = (2 * PAGE) | PRESENT | WRITE;
        t
    }
    fn check(t: &[[u64; 512]; 5], roots: &[u64]) -> Result<(), Error> {
        qualify(
            &Layout::new(PAGE, 1).unwrap().slot(0, 0).unwrap(),
            0x10_0000,
            roots,
            4,
            6,
            |table, index| {
                table
                    .checked_div(PAGE)
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|n| t.get(n as usize))
                    .map(|t| t[index])
            },
        )
    }
    #[test]
    fn every_root_must_map_owned_pages_with_real_absent_guards() {
        let mut t = tables();
        assert_eq!(check(&t, &[PAGE, 5 * PAGE]), Ok(()));
        t[4][0] = 0;
        assert_eq!(check(&t, &[PAGE, 5 * PAGE]), Err(Error::Missing));
        t = tables();
        t[3][0] = 0x20_0000 | PRESENT | WRITE | NX;
        assert_eq!(check(&t, &[PAGE]), Err(Error::GuardMapped));
        t = tables();
        t[3][2] = 0x20_0000 | PRESENT | WRITE | NX;
        assert_eq!(check(&t, &[PAGE]), Err(Error::GuardMapped));
    }
    #[test]
    fn permissions_backing_and_effective_leaf_pat_are_checked() {
        let mut t = tables();
        t[1][0] &= !WRITE;
        assert_eq!(check(&t, &[PAGE]), Err(Error::Permissions));
        t = tables();
        t[3][1] &= !NX;
        assert_eq!(check(&t, &[PAGE]), Err(Error::Permissions));
        t = tables();
        for table in &mut t[..4] {
            table[0] |= USER;
        }
        t[3][1] |= USER;
        assert_eq!(check(&t, &[PAGE]), Err(Error::Permissions));
        t = tables();
        t[3][1] += PAGE;
        assert_eq!(check(&t, &[PAGE]), Err(Error::Physical));
        t = tables();
        t[3][1] |= 1 << 3;
        assert_eq!(check(&t, &[PAGE]), Err(Error::Cache));
    }
    #[test]
    fn high_four_level_and_five_level_windows_do_not_overflow_backing_math() {
        let mut t = tables();
        let base = 0xffff_8000_0000_0000;
        t[0][256] = t[0][0];
        let slot = Layout::new(PAGE, 1).unwrap().slot(base, 0).unwrap();
        assert_eq!(
            qualify(&slot, 0x10_0000, &[PAGE], 4, 6, |table, index| table
                .checked_div(PAGE)
                .and_then(|n| n.checked_sub(1))
                .and_then(|n| t.get(n as usize))
                .map(|t| t[index])),
            Ok(())
        );
        let mut five = [[0; 512]; 6];
        five[..5].copy_from_slice(&tables());
        five[5][64] = PAGE | PRESENT | WRITE;
        let slot = Layout::new(PAGE, 1)
            .unwrap()
            .slot(0x0040_0000_0000_0000, 0)
            .unwrap();
        assert_eq!(
            qualify(&slot, 0x10_0000, &[6 * PAGE], 5, 6, |table, index| table
                .checked_div(PAGE)
                .and_then(|n| n.checked_sub(1))
                .and_then(|n| five.get(n as usize))
                .map(|t| t[index])),
            Ok(())
        );
    }
    #[test]
    fn absent_table_read_is_not_an_absent_guard() {
        let mut t = tables();
        t[0][0] = 0x90_0000 | PRESENT | WRITE;
        assert_eq!(check(&t, &[PAGE]), Err(Error::TableUnavailable));
        assert_eq!(check(&tables(), &[]), Err(Error::Geometry));
    }
}
