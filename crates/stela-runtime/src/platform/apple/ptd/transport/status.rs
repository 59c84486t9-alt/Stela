//! Nondestructive IRQ-status snapshots. Original AP `_irqStatus` reads32/64;
//! original PMP reader file0x28044..0x28204 also uses aligned LDP128. All words
//! belong to the pending bank and are read under one immutable borrow.
use super::{IRQ_STATUS, Ptd, State};

/// Checked complete status-register transaction widths in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Word,
    Double,
    Quad,
}

impl Width {
    const fn words(self) -> usize {
        match self {
            Self::Word => 1,
            Self::Double => 2,
            Self::Quad => 4,
        }
    }

    pub const fn bytes(self) -> u64 {
        match self {
            Self::Word => 4,
            Self::Double => 8,
            Self::Quad => 16,
        }
    }
}

/// Raw little-endian register words from one stable borrow. Narrow widths
/// zero-extend within this numeric container; no absent register is read or
/// supplied. This is data, never consumption or execution-retirement permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub low: u64,
    pub high: u64,
}

impl Ptd {
    /// Original T8112 PMP VA1012e40..1012fa8 reads naturally aligned status
    /// words/doubles/quads covering a range, then shifts and masks its bits.
    /// This is a nondestructive observation of at most128 entries.
    pub fn pending_range(&self, start: u32, count: u32) -> Result<Snapshot, &'static str> {
        self.0.borrow().pending_range(start, count)
    }
    /// Snapshot one naturally aligned, complete status span. `offset` is relative
    /// to the whole PTD device and must select status words, never entries,
    /// holes, routes or write aliases. Nothing is consumed or acknowledged.
    pub fn interrupt_snapshot(&self, offset: u64, width: Width) -> Result<Snapshot, &'static str> {
        self.0.borrow().interrupt_snapshot(offset, width)
    }
}

impl State {
    fn pending_range(&self, start: u32, count: u32) -> Result<Snapshot, &'static str> {
        let end = start.checked_add(count).ok_or("PTD pending range wraps")?;
        if count > 128 || end as usize > self.values.len() {
            return Err("PTD pending range exceeds its actual bank or128-bit result");
        }
        if count == 0 {
            return Ok(Snapshot { low: 0, high: 0 });
        }
        let mut word = start / 32;
        let last = (end - 1) / 32;
        let mut bits = 0u128;
        while word <= last {
            let remaining = last + 1 - word;
            let width = if remaining >= 4 && word.is_multiple_of(4) {
                Width::Quad
            } else if remaining >= 2 && word.is_multiple_of(2) {
                Width::Double
            } else {
                Width::Word
            };
            let raw = self.interrupt_snapshot(IRQ_STATUS + u64::from(word) * 4, width)?;
            let raw = u128::from(raw.low) | u128::from(raw.high) << 64;
            let first = word * 32;
            bits |= if first < start {
                raw >> (start - first)
            } else {
                raw.checked_shl(first - start).unwrap_or(0)
            };
            word += width.words() as u32;
        }
        if count < 128 {
            bits &= (1u128 << count) - 1;
        }
        Ok(Snapshot {
            low: bits as u64,
            high: (bits >> 64) as u64,
        })
    }
    pub(super) fn interrupt_snapshot(
        &self,
        offset: u64,
        width: Width,
    ) -> Result<Snapshot, &'static str> {
        self.accessible()?;
        if !offset.is_multiple_of(width.bytes()) {
            return Err("PTD IRQ access is not aligned");
        }
        let relative = offset
            .checked_sub(IRQ_STATUS)
            .ok_or("PTD IRQ read outside its bank")?;
        let index = usize::try_from(relative / 4).map_err(|_| "PTD IRQ read outside its bank")?;
        if index >= self.pending.len() {
            return Err("PTD IRQ read outside its bank");
        }
        let end = index
            .checked_add(width.words())
            .ok_or("PTD IRQ read crosses its bank")?;
        let words = self
            .pending
            .get(index..end)
            .ok_or("PTD IRQ read crosses its bank")?;
        let mut raw = [0u64; 2];
        for (position, word) in words.iter().enumerate() {
            raw[position / 2] |= word.read(u64::from(u32::MAX))? << (32 * (position % 2));
        }
        Ok(Snapshot {
            low: raw[0],
            high: raw[1],
        })
    }
}

#[cfg(test)]
mod tests;
