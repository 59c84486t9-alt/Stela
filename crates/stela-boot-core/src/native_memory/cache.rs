//! Read-only validation of the native heap's effective WB cache policy.
//! This does not change PAT/MTRRs or authorize aliases with another policy.
use alloc::vec::Vec;
use core::ops::Range;
use stela_drivers::bus::dma::memory::MemoryError;

pub const WRITE_BACK: u8 = 6;
const FIXED_TOP: u64 = 1024 * 1024;
pub const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const LARGE: u64 = 1 << 7;
#[cfg(test)]
const NX: u64 = 1 << 63;

/// Prove each current leaf maps the expected physical pages with a WB
/// PAT selection. Intermediate cache bits affect table fetches, not data PAT.
pub fn verify_mappings(
    cpu: u64,
    physical: u64,
    bytes: usize,
    root: u64,
    levels: u32,
    pat: u64,
    mut read: impl FnMut(u64, usize) -> Option<u64>,
) -> Result<(), MemoryError> {
    if !matches!(levels, 4 | 5) || bytes == 0 {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    let mut offset = 0u64;
    while offset < bytes as u64 {
        let address = cpu.checked_add(offset).ok_or(MemoryError::InvalidSize)?;
        let canonical_bits = 12 + 9 * levels;
        if ((address << (64 - canonical_bits)) as i64 >> (64 - canonical_bits)) as u64 != address {
            return Err(MemoryError::OutsideReservation);
        }
        let mut table = root;
        let mut writable = true;
        for level in (0..levels).rev() {
            let index = ((address >> (12 + 9 * level)) & 511) as usize;
            let entry = read(table, index).ok_or(MemoryError::OutsideReservation)?;
            if entry & PRESENT == 0 {
                return Err(MemoryError::OutsideReservation);
            }
            writable &= entry & WRITABLE != 0;
            let large = entry & LARGE != 0;
            if level == 0 || (large && matches!(level, 1 | 2)) {
                let size = 1u64 << (12 + 9 * level);
                let pat_bit = if level == 0 { 7 } else { 12 };
                let index = ((entry >> 3) & 3) | ((entry >> pat_bit) & 1) << 2;
                let cache_type = (pat >> (index * 8)) as u8;
                let leaf_offset = address & (size - 1);
                let base = entry & ADDRESS & !(size - 1);
                if !writable
                    || cache_type != WRITE_BACK
                    || base.checked_add(leaf_offset) != physical.checked_add(offset)
                    || (level != 0 && entry & ADDRESS & (size - 1) & !(1 << 12) != 0)
                {
                    return Err(MemoryError::CacheAttributeUnavailable);
                }
                offset += (size - leaf_offset).min(bytes as u64 - offset);
                break;
            }
            if large {
                return Err(MemoryError::OutsideReservation);
            }
            table = entry & ADDRESS;
        }
    }
    Ok(())
}

/// One enabled variable-range MTRR.
pub struct Variable {
    pub range: Range<u64>,
    pub kind: u8,
}

/// The MTRR state and CR0 cache controls that decide a range's type.
pub struct Policy {
    pub enabled: bool,
    pub caches_enabled: bool,
    pub default_kind: u8,
    pub physical_bits: u8,
    pub variables: Vec<Variable>,
}

impl Policy {
    /// The whole range is write-back: no non-WB overlap and full coverage.
    pub fn writeback(&self, start: u64, bytes: usize) -> Result<(), MemoryError> {
        let end = start
            .checked_add(bytes as u64)
            .ok_or(MemoryError::InvalidSize)?;
        if !self.enabled
            || !self.caches_enabled
            || bytes == 0
            || start < FIXED_TOP
            || !(32..=52).contains(&self.physical_bits)
            || end > 1u64 << self.physical_bits
        {
            return Err(MemoryError::CacheAttributeUnavailable);
        }
        // Reject all non-WB overlaps, including UC precedence and mixed-type
        // overlaps. We never guess a permissive type for an undefined mix.
        if self.variables.iter().any(|entry| {
            entry.range.start < end && start < entry.range.end && entry.kind != WRITE_BACK
        }) {
            return Err(MemoryError::CacheAttributeUnavailable);
        }
        if self.default_kind == WRITE_BACK {
            return Ok(());
        }
        // Extend through every interval touching the covered prefix. This
        // handles unsorted overlaps without an infallible scratch allocation;
        // each pass consumes at least one of the bounded MTRR endpoints.
        let mut cursor = start;
        while cursor < end {
            cursor = self
                .variables
                .iter()
                .filter(|entry| entry.kind == WRITE_BACK && entry.range.start <= cursor)
                .map(|entry| entry.range.end)
                .filter(|next| *next > cursor)
                .max()
                .ok_or(MemoryError::CacheAttributeUnavailable)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    fn tables(
        levels: u32,
        cpu: u64,
        physical: u64,
        leaf: u32,
        attributes: u64,
    ) -> BTreeMap<(u64, usize), u64> {
        let mut tables = BTreeMap::new();
        let mut table = 0x1000;
        for level in (leaf..levels).rev() {
            let index = ((cpu >> (12 + 9 * level)) & 511) as usize;
            let value = if level == leaf {
                physical | attributes | PRESENT | WRITABLE | NX | if leaf != 0 { LARGE } else { 0 }
            } else {
                (table + 0x1000) | PRESENT | WRITABLE
            };
            tables.insert((table, index), value);
            table += 0x1000;
        }
        tables
    }

    #[test]
    fn mapping_check_rejects_wrong_pat_or_address_on_any_page() {
        for levels in [4, 5] {
            let cpu = if levels == 5 {
                0x0040_0000_0040_0000
            } else {
                0xffff_8000_0040_0000
            };
            let mut pages = tables(levels, cpu, 0x800000, 0, 0);
            let leaf_table = u64::from(levels) * 0x1000;
            let index = ((cpu >> 12) & 511) as usize;
            pages.insert((leaf_table, index + 1), 0x801000 | PRESENT | WRITABLE | NX);
            let check = |pages: &BTreeMap<_, _>, pat| {
                verify_mappings(cpu, 0x800000, 8192, 0x1000, levels, pat, |table, index| {
                    pages.get(&(table, index)).copied()
                })
            };
            assert_eq!(check(&pages, 6), Ok(()));
            assert!(check(&pages, 0).is_err());
            pages.insert((leaf_table, index + 1), 0x802000 | PRESENT | WRITABLE | NX);
            assert!(check(&pages, 6).is_err());
            // PAT bit 7 in a 4 KiB PTE selects entry 4; PAT0 WB alone is
            // insufficient when the leaf selects an uncached entry.
            pages.insert(
                (leaf_table, index),
                0x800000 | PRESENT | WRITABLE | NX | LARGE,
            );
            pages.insert(
                (leaf_table, index + 1),
                0x801000 | PRESENT | WRITABLE | NX | LARGE,
            );
            assert!(check(&pages, 6).is_err());
            assert_eq!(check(&pages, 6u64 << 32), Ok(()));
        }
    }

    #[test]
    fn large_leaf_pat_bit_and_effective_permissions_are_not_guessed() {
        for leaf in [1, 2] {
            let cpu = 0xffff_8000_4000_0000;
            let pages = tables(4, cpu, 0x80000000, leaf, 1 << 12);
            let check = |pages: &BTreeMap<_, _>, pat| {
                verify_mappings(
                    cpu + 4096,
                    0x80001000,
                    8192,
                    0x1000,
                    4,
                    pat,
                    |table, index| pages.get(&(table, index)).copied(),
                )
            };
            assert!(check(&pages, 6).is_err());
            assert_eq!(check(&pages, 6u64 << 32), Ok(()));
            let mut read_only = pages.clone();
            *read_only
                .get_mut(&(0x1000, ((cpu >> 39) & 511) as usize))
                .unwrap() &= !WRITABLE;
            assert!(check(&read_only, 6u64 << 32).is_err());
        }
    }

    #[test]
    fn effective_wb_requires_pat_mtrr_and_complete_coverage() {
        let mut policy = Policy {
            enabled: true,
            caches_enabled: true,
            default_kind: WRITE_BACK,
            physical_bits: 48,
            variables: Vec::new(),
        };
        let range = 0x200000..0x204000;
        assert_eq!(policy.writeback(range.start, 0x4000), Ok(()));
        policy.enabled = false;
        assert!(policy.writeback(range.start, 0x4000).is_err());
        policy.enabled = true;
        policy.variables.push(Variable {
            range: 0x203000..0x204000,
            kind: 0,
        });
        assert!(policy.writeback(range.start, 0x4000).is_err());
        policy.variables.clear();
        policy.default_kind = 0;
        policy.variables.push(Variable {
            range: 0x200000..0x202000,
            kind: WRITE_BACK,
        });
        assert!(policy.writeback(range.start, 0x4000).is_err());
        policy.variables.push(Variable {
            range: 0x202000..0x204000,
            kind: WRITE_BACK,
        });
        assert_eq!(policy.writeback(range.start, 0x4000), Ok(()));
        assert!(policy.writeback(0, 4096).is_err());
        assert!(policy.writeback(u64::MAX - 4095, 8192).is_err());
        assert!(policy.writeback(1 << 48, 4096).is_err());
    }

    #[test]
    fn unsorted_wb_coverage_and_gaps_require_no_allocation() {
        use super::super::tests::allocation_failure;
        let mut policy = Policy {
            enabled: true,
            caches_enabled: true,
            default_kind: 0,
            physical_bits: 48,
            variables: [
                0x203000..0x205000,
                0x201000..0x204000,
                0x205000..0x206000,
                0x200000..0x202000,
            ]
            .into_iter()
            .map(|range| Variable {
                range,
                kind: WRITE_BACK,
            })
            .collect(),
        };
        allocation_failure::arm(0);
        let covered = policy.writeback(0x200000, 0x6000);
        let gap = policy.writeback(0x200000, 0x7000);
        policy.variables[1].kind = 0;
        let conflict = policy.writeback(0x200000, 0x6000);
        let observation = allocation_failure::disarm();
        assert_eq!(covered, Ok(()));
        assert_eq!(gap, Err(MemoryError::CacheAttributeUnavailable));
        assert_eq!(conflict, Err(MemoryError::CacheAttributeUnavailable));
        assert_eq!(observation.attempts, 0);
    }
}
