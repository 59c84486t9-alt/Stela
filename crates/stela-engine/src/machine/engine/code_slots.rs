//! Block slots grouped by the native arena part that owns their code.

use super::CodePartitions;
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Default)]
pub(super) enum CodeSlots {
    #[default]
    Uninitialized,
    Linear,
    Partitioned {
        layout: CodePartitions,
        slots: Vec<Vec<u32>>,
    },
}

impl CodePartitions {
    fn part_at(self, address: usize) -> Option<usize> {
        let offset = address.checked_sub(self.base)?;
        let part = offset.checked_div(self.bytes_per_part)?;
        (part < self.parts).then_some(part)
    }

    fn whole_part(self, range: &Range<usize>) -> Option<usize> {
        let part = self.part_at(range.start)?;
        let offset = range.start - self.base;
        (offset.is_multiple_of(self.bytes_per_part)
            && range.end.checked_sub(range.start) == Some(self.bytes_per_part))
        .then_some(part)
    }
}

impl CodeSlots {
    pub(super) fn record(
        &mut self,
        address: usize,
        slot: usize,
        partitions: impl FnOnce() -> Option<CodePartitions>,
    ) {
        if matches!(self, Self::Uninitialized) {
            *self = partitions().map_or(Self::Linear, |layout| {
                let mut slots = Vec::new();
                if slots.try_reserve_exact(layout.parts).is_err() {
                    return Self::Linear;
                }
                slots.resize_with(layout.parts, Vec::new);
                Self::Partitioned { layout, slots }
            });
        }
        let Self::Partitioned { layout, slots } = self else {
            return;
        };
        if let Some(part) = layout.part_at(address)
            && let Ok(slot) = u32::try_from(slot)
            && slots[part].try_reserve(1).is_ok()
        {
            slots[part].push(slot);
        } else {
            // The index is optional. A missing block would let reclaimed
            // code remain reachable, so discard the index and scan instead.
            *self = Self::Linear;
        }
    }

    /// Take the slots of a whole part. A non-partitioned or unexpected
    /// reclaim falls back to scanning the authoritative block table.
    pub(super) fn take(&mut self, range: &Range<usize>) -> Option<Vec<u32>> {
        let Self::Partitioned { layout, slots } = self else {
            return None;
        };
        if let Some(part) = layout.whole_part(range) {
            Some(core::mem::take(&mut slots[part]))
        } else {
            *self = Self::Linear;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAYOUT: CodePartitions = CodePartitions {
        base: 0x1000,
        bytes_per_part: 0x80,
        parts: 3,
    };

    #[test]
    fn reclamation_takes_only_the_requested_part_and_supports_wraparound() {
        let mut slots = CodeSlots::default();
        slots.record(0x1000, 5, || Some(LAYOUT));
        slots.record(0x107f, 2, || unreachable!());
        slots.record(0x1080, 4, || unreachable!());
        assert!(slots.take(&(0x1100..0x1180)).unwrap().is_empty());
        assert_eq!(slots.take(&(0x1000..0x1080)).unwrap(), [5, 2]);
        slots.record(0x1000, 3, || unreachable!());
        assert_eq!(slots.take(&(0x1080..0x1100)).unwrap(), [4]);
        assert_eq!(slots.take(&(0x1000..0x1080)).unwrap(), [3]);
    }

    #[test]
    fn nonconforming_reclamation_or_address_falls_back_to_linear_scan() {
        let mut slots = CodeSlots::default();
        slots.record(0x1000, 5, || Some(LAYOUT));
        assert!(slots.take(&(0x1010..0x1080)).is_none());
        assert!(slots.take(&(0x1000..0x1080)).is_none());

        let mut slots = CodeSlots::default();
        slots.record(0x1180, 5, || Some(LAYOUT));
        assert!(slots.take(&(0x1000..0x1080)).is_none());
    }
}
