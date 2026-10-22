//! Read-only qualification of the native heap's effective WB cache policy.
//! This does not change PAT/MTRRs or authorize aliases with another policy.
use super::MemoryError;
use alloc::vec::Vec;
use core::ops::Range;

const WRITE_BACK: u8 = 6;
const FIXED_TOP: u64 = 1024 * 1024;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const LARGE: u64 = 1 << 7;
#[cfg(test)]
const NX: u64 = 1 << 63;

/// Prove each actual current leaf maps the expected physical pages with a WB
/// PAT selection. Intermediate cache bits affect table fetches, not data PAT.
fn verify_mappings(
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

struct Variable {
    range: Range<u64>,
    kind: u8,
}

struct Policy {
    enabled: bool,
    caches_enabled: bool,
    default_kind: u8,
    physical_bits: u8,
    variables: Vec<Variable>,
}

impl Policy {
    fn writeback(&self, start: u64, bytes: usize) -> Result<(), MemoryError> {
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
        let mut wb: Vec<_> = self
            .variables
            .iter()
            .filter(|entry| entry.kind == WRITE_BACK)
            .map(|entry| entry.range.clone())
            .collect();
        wb.sort_unstable_by_key(|range| range.start);
        let mut cursor = start;
        for range in wb {
            if range.start <= cursor && cursor < range.end {
                cursor = range.end;
            }
        }
        if cursor >= end {
            Ok(())
        } else {
            Err(MemoryError::CacheAttributeUnavailable)
        }
    }
}

#[cfg(not(test))]
pub(crate) fn verify_writeback(
    cpu: u64,
    start: u64,
    bytes: usize,
    table_offset: u64,
) -> Result<(), MemoryError> {
    use core::arch::{asm, x86_64::__cpuid};
    const PAT: u32 = 0x277;
    const CAP: u32 = 0xfe;
    const DEFAULT: u32 = 0x2ff;
    const VARIABLE_BASE: u32 = 0x200;
    const VALID: u64 = 1 << 11;
    const MTRR_ENABLE: u64 = 1 << 11;
    fn msr(register: u32) -> u64 {
        let (low, high): (u32, u32);
        // SAFETY: caller checks CPUID before these architectural MSRs, in CPL0.
        unsafe {
            asm!("rdmsr", in("ecx") register, out("eax") low, out("edx") high,
                options(nomem, nostack, preserves_flags));
        }
        u64::from(low) | u64::from(high) << 32
    }
    let vendor = __cpuid(0);
    if [vendor.ebx, vendor.edx, vendor.ecx] == [0x6874_7541, 0x6974_6e65, 0x444d_4163] {
        return verify_amd_writeback(cpu, start, bytes, table_offset);
    }
    // This decoder is qualified against Intel's architectural controls. Other
    // vendors need their own routing qualification, not an Intel fallback.
    if [vendor.ebx, vendor.edx, vendor.ecx] != [0x756e_6547, 0x4965_6e69, 0x6c65_746e] {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    // SAFETY: CPUID is available on the declared x86-64 host baseline.
    let features = __cpuid(1).edx;
    if features & (1 << 12 | 1 << 16) != (1 << 12 | 1 << 16) {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    // SAFETY: the extended CPUID maximum is always queryable.
    let maximum = __cpuid(0x8000_0000).eax;
    let physical_bits = if maximum >= 0x8000_0008 {
        // SAFETY: the maximum extended leaf includes this leaf.
        __cpuid(0x8000_0008).eax as u8
    } else {
        36
    };
    if !(32..=52).contains(&physical_bits) {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    let address_mask = ((1u64 << physical_bits) - 1) & !4095;
    let default = msr(DEFAULT);
    let cr0: u64;
    // SAFETY: read-only architectural control register access at CPL0.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    let (cr3, cr4): (u64, u64);
    // SAFETY: read-only current root/configuration at CPL0, with migration and
    // root changes excluded by the native allocator's platform contract.
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    verify_mappings(
        cpu,
        start,
        bytes,
        cr3 & ADDRESS,
        if cr4 & (1 << 12) != 0 { 5 } else { 4 },
        msr(PAT),
        |table, index| {
            let address = table_offset
                .checked_add(table)?
                .checked_add(index as u64 * 8)?;
            // SAFETY: initialize's table_offset contract covers all active
            // table pages; every index is within its retained 4 KiB page.
            Some(unsafe { (address as *const u64).read_volatile() })
        },
    )?;
    let mut variables = Vec::new();
    for index in 0..(msr(CAP) as u8) {
        let base = msr(VARIABLE_BASE + 2 * u32::from(index));
        let mask = msr(VARIABLE_BASE + 2 * u32::from(index) + 1);
        if mask & VALID == 0 {
            continue;
        }
        let size = ((!mask) & address_mask) + 4096;
        let start = base & address_mask;
        if !size.is_power_of_two() || !start.is_multiple_of(size) {
            return Err(MemoryError::CacheAttributeUnavailable);
        }
        variables.push(Variable {
            range: start..start + size,
            kind: base as u8,
        });
    }
    Policy {
        enabled: default & MTRR_ENABLE != 0,
        caches_enabled: cr0 & (1 << 30 | 1 << 29) == 0,
        default_kind: default as u8,
        physical_bits,
        variables,
    }
    .writeback(start, bytes)
}

/// AMD's effective DRAM routing is additional to the common PAT/MTRR fields.
/// Reuse the one native capture/query owner, including fixed-attribute visibility
/// restoration. A captured image alone is never a live cache-policy grant.
#[cfg(not(test))]
fn verify_amd_writeback(
    cpu: u64,
    physical: u64,
    bytes: usize,
    table_offset: u64,
) -> Result<(), MemoryError> {
    use crate::native_smp::{firmware, memory_types::Image};
    fn unavailable<E>(_: E) -> MemoryError {
        MemoryError::CacheAttributeUnavailable
    }
    // SAFETY: initialize's contract excludes migration, root/cache writers
    // and IRQ allocation. This is the actual current CPL0 processor; observe
    // restores AMD's read-visibility control without changing routing.
    let before = unsafe { firmware::observe() }.map_err(unavailable)?;
    let image = Image::from_snapshot(&before).map_err(unavailable)?;
    image
        .writeback_ram(physical, bytes as u64)
        .map_err(unavailable)?;
    if !before.pat_valid || before.apic_id().is_none() {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    verify_mappings(
        cpu,
        physical,
        bytes,
        before.cr3 & ADDRESS,
        if before.cr4 & (1 << 12) != 0 { 5 } else { 4 },
        before.pat,
        |table, index| {
            let address = table_offset
                .checked_add(table)?
                .checked_add(index as u64 * 8)?;
            // SAFETY: initialize pins each actual root-reachable table page;
            // the index stays inside its readable 4 KiB mapping.
            Some(unsafe { (address as *const u64).read_volatile() })
        },
    )?;
    // SAFETY: the same actor-local exclusion remains held through validation.
    let after = unsafe { firmware::observe() }.map_err(unavailable)?;
    if before.apic_id() != after.apic_id()
        || before.cr0 != after.cr0
        || before.cr3 != after.cr3
        || before.cr4 != after.cr4
        || before.efer != after.efer
    {
        return Err(MemoryError::CacheAttributeUnavailable);
    }
    before.same_memory_types(&after).map_err(unavailable)
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
    fn actual_leaf_pat_and_pa_are_checked_for_every_page_and_root_depth() {
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
            // insufficient when the actual leaf selects an uncached entry.
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
}
