// SPDX-License-Identifier: GPL-2.0-only
//! Mixed page-backed layout data. No numeric extent grants physical ownership,
//! page-table authority, initialization or execution permission. Native owners
//! retain the complete raw allocation, qualify every actual root/cache alias,
//! and keep each immediate guard page genuinely absent.
use super::{Error, MAX_STACKS, PAGE, Slot};
use core::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    bytes: u64,
    alignment: u64,
}
impl Geometry {
    pub fn new(bytes: u64, alignment: u64) -> Result<Self, Error> {
        if bytes == 0
            || !bytes.is_multiple_of(PAGE)
            || alignment < PAGE
            || !alignment.is_power_of_two()
        {
            return Err(Error::Alignment);
        }
        Ok(Self { bytes, alignment })
    }
    pub fn bytes(self) -> u64 {
        self.bytes
    }
    pub fn alignment(self) -> u64 {
        self.alignment
    }
}
#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    usable: u64,
    bytes: u64,
    physical_offset: u64,
}
#[derive(Debug)]
pub struct MixedLayout {
    base: u64,
    count: usize,
    entries: [Entry; MAX_STACKS],
    virtual_bytes: u64,
    physical_bytes: u64,
    physical_alignment: u64,
    raw_allocation_bytes: u64,
}
fn aligned(value: u64, alignment: u64) -> Result<u64, Error> {
    value
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or(Error::Overflow)
}
impl MixedLayout {
    /// Lay out the exact virtual base and per-stack geometry. Padding between
    /// slots is never part of a usable range. Every usable interval has its own
    /// immediately adjacent lower/upper absent page, including aligned C stacks.
    pub fn new(base: u64, geometries: &[Geometry]) -> Result<Self, Error> {
        if geometries.is_empty() || geometries.len() > MAX_STACKS {
            return Err(Error::Capacity);
        }
        if !base.is_multiple_of(PAGE) {
            return Err(Error::Alignment);
        }
        let mut entries = [Entry::default(); MAX_STACKS];
        let (mut virtual_end, mut physical_bytes, mut physical_alignment) = (base, 0, PAGE);
        for (index, geometry) in geometries.iter().copied().enumerate() {
            let usable = aligned(
                virtual_end.checked_add(PAGE).ok_or(Error::Overflow)?,
                geometry.alignment,
            )?;
            virtual_end = usable
                .checked_add(geometry.bytes)
                .and_then(|n| n.checked_add(PAGE))
                .ok_or(Error::Overflow)?;
            let physical_offset = aligned(physical_bytes, geometry.alignment)?;
            physical_bytes = physical_offset
                .checked_add(geometry.bytes)
                .ok_or(Error::Overflow)?;
            physical_alignment = physical_alignment.max(geometry.alignment);
            entries[index] = Entry {
                usable,
                bytes: geometry.bytes,
                physical_offset,
            };
        }
        // UEFI AllocateAnyPages guarantees only PAGE alignment. Retain enough
        // *raw* pages to align the first backing without releasing its prefix.
        let raw_allocation_bytes = physical_bytes
            .checked_add(physical_alignment - PAGE)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            base,
            count: geometries.len(),
            entries,
            virtual_bytes: virtual_end - base,
            physical_bytes,
            physical_alignment,
            raw_allocation_bytes,
        })
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn virtual_bytes(&self) -> u64 {
        self.virtual_bytes
    }
    pub fn physical_bytes(&self) -> u64 {
        self.physical_bytes
    }
    pub fn physical_alignment(&self) -> u64 {
        self.physical_alignment
    }
    pub fn raw_allocation_bytes(&self) -> u64 {
        self.raw_allocation_bytes
    }
    fn entry(&self, index: usize) -> Result<Entry, Error> {
        if index >= self.count {
            return Err(Error::Slot);
        }
        Ok(self.entries[index])
    }
    pub fn slot(&self, index: usize) -> Result<Slot, Error> {
        let entry = self.entry(index)?;
        let end = entry.usable + entry.bytes;
        Ok(Slot {
            lower_guard: entry.usable - PAGE..entry.usable,
            usable: entry.usable..end,
            upper_guard: end..end + PAGE,
        })
    }
    /// Offset within the aligned physical payload, not within the raw allocation.
    pub fn physical_offset(&self, index: usize) -> Result<u64, Error> {
        Ok(self.entry(index)?.physical_offset)
    }
    /// Locate the payload in an actual page-aligned allocation. This arithmetic
    /// does not prove the allocation exists or authorize access to its pages.
    /// The native owner retains the complete supplied raw allocation on every
    /// success, failure, pause or quarantine; prefix/suffix are not free memory.
    pub fn backing(&self, raw: Range<u64>, index: usize) -> Result<Range<u64>, Error> {
        let entry = self.entry(index)?;
        let bytes = raw.end.checked_sub(raw.start).ok_or(Error::Overflow)?;
        if !raw.start.is_multiple_of(PAGE) || !raw.end.is_multiple_of(PAGE) {
            return Err(Error::Alignment);
        }
        if bytes < self.raw_allocation_bytes {
            return Err(Error::Capacity);
        }
        let first = aligned(raw.start, self.physical_alignment)?;
        let end = first
            .checked_add(self.physical_bytes)
            .ok_or(Error::Overflow)?;
        if end > raw.end {
            return Err(Error::Capacity);
        }
        let start = first
            .checked_add(entry.physical_offset)
            .ok_or(Error::Overflow)?;
        Ok(start..start + entry.bytes)
    }
    pub fn virtual_range(&self) -> Range<u64> {
        self.base..self.base + self.virtual_bytes
    }
}

#[cfg(test)]
mod tests;
