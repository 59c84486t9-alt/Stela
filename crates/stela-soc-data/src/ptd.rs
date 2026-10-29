//! PTD publication-bank and update-alias geometry from the original AP/PMP
//! contract. This validates physical extents without granting transport or
//! controller-effect authority. See `docs/research/apple-mcc.md`.
use alloc::string::String;

/// The shared publication bank and its AP/PMP update alias.
pub const PTD_BYTES: u64 = 0x20000;
pub const UPDATE_OFFSET: u64 = 0x10000;

/// The source enable/disable windows each contain 256 bytes, one bit per
/// publication. A larger data/update aperture does not add interrupt routes.
pub const MAX_ENTRIES: usize = 256 * 8;

/// Complete physical bank/update-alias agreement, shared by the AP and PMP.
/// Both T6000 and T8112 originals publish 16-byte entries and update them
/// through 8-byte slots; J473's update reg[3] is only 0x4000 bytes. The
/// fourth word of a range record remains a separate interrupt resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    physical: u64,
    updates: (u64, u64),
    entries: usize,
}

impl Geometry {
    pub fn new(bank: (u64, u64), updates: (u64, u64)) -> Result<Self, &'static str> {
        const ENTRY_BYTES: u64 = 16;
        const UPDATE_BYTES: u64 = 8;
        let bank_end = bank.0.checked_add(bank.1).ok_or("PTD bank end overflows")?;
        let update_start = bank
            .0
            .checked_add(UPDATE_OFFSET)
            .ok_or("PTD update start overflows")?;
        let update_end = updates
            .0
            .checked_add(updates.1)
            .ok_or("PTD update end overflows")?;
        if bank.1 != PTD_BYTES
            || !bank.0.is_multiple_of(ENTRY_BYTES)
            || updates.0 != update_start
            || updates.1 == 0
            || !updates.1.is_multiple_of(UPDATE_BYTES)
            || update_end > bank_end
        {
            return Err("PTD update alias does not match its actual complete publication bank");
        }
        let entries = usize::try_from(updates.1 / UPDATE_BYTES)
            .map_err(|_| "PTD capacity exceeds host width")?;
        if entries > MAX_ENTRIES
            || (entries as u64)
                .checked_mul(ENTRY_BYTES)
                .is_none_or(|bytes| bytes > UPDATE_OFFSET)
        {
            return Err("PTD entries exceed publication or interrupt-routing capacity");
        }
        Ok(Self {
            physical: bank.0,
            updates,
            entries,
        })
    }

    pub fn physical(self) -> u64 {
        self.physical
    }
    pub fn updates(self) -> (u64, u64) {
        self.updates
    }
    pub fn entries(self) -> usize {
        self.entries
    }
}

/// A source-qualified `ptd-range` identity. The fourth DT word (the interrupt
/// resource) must also be retained by the mount; it is not an AIC input number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub id: u32,
    pub start: u32,
    pub count: u32,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_alias_uses_the_actual_update_and_interrupt_capacities() {
        const BASE: u64 = 0x23b3c0000;
        for entries in [1, 377, 1024, MAX_ENTRIES] {
            let geometry = Geometry::new(
                (BASE, PTD_BYTES),
                (BASE + UPDATE_OFFSET, entries as u64 * 8),
            )
            .unwrap();
            assert_eq!(geometry.physical(), BASE);
            assert_eq!(
                geometry.updates(),
                (BASE + UPDATE_OFFSET, entries as u64 * 8)
            );
            assert_eq!(geometry.entries(), entries);
        }
        for (bank, updates) in [
            ((BASE, PTD_BYTES - 1), (BASE + UPDATE_OFFSET, 0x4000)),
            ((BASE + 1, PTD_BYTES), (BASE + 1 + UPDATE_OFFSET, 0x4000)),
            ((BASE, PTD_BYTES), (BASE + UPDATE_OFFSET + 8, 0x4000)),
            ((BASE, PTD_BYTES), (BASE + UPDATE_OFFSET, 0)),
            ((BASE, PTD_BYTES), (BASE + UPDATE_OFFSET, 0x4001)),
            ((BASE, PTD_BYTES), (BASE + UPDATE_OFFSET, 0x4008)),
            ((BASE, PTD_BYTES), (BASE + UPDATE_OFFSET, 0x10000)),
            ((u64::MAX - UPDATE_OFFSET + 1, PTD_BYTES), (0, 8)),
            ((BASE, PTD_BYTES), (u64::MAX - 7, 16)),
        ] {
            assert!(
                Geometry::new(bank, updates).is_err(),
                "{bank:x?} {updates:x?}"
            );
        }
    }
}
