//! Nondestructive IRQ-status snapshots. Original AP `_irqStatus` reads32/64;
//! original PMP reader file0x28044..0x28204 also uses aligned LDP128. All words
//! belong to the actual pending bank and are read under one immutable borrow.
use super::{IRQ_STATUS, Ptd, State};

/// Qualified complete status-register transaction widths in bytes.
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
/// supplied. This is data, never consumption or execution-retirement authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub low: u64,
    pub high: u64,
}

impl Ptd {
    /// Snapshot one naturally aligned, complete status span. `offset` is relative
    /// to the whole PTD device and must select actual status words, never entries,
    /// holes, routes or write aliases. Nothing is consumed or acknowledged.
    pub fn interrupt_snapshot(&self, offset: u64, width: Width) -> Result<Snapshot, &'static str> {
        self.0.borrow().interrupt_snapshot(offset, width)
    }
}

impl State {
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
mod tests {
    use super::*;
    use crate::platform::apple::{
        bus::{Access, Lifecycle, LifecycleState, MmioDevice, Width as BusWidth},
        interrupt::InterruptLatch,
        ptd::{Range, UPDATE_OFFSET, transport::Observation},
    };
    use alloc::vec::Vec;

    const PATTERN: [u32; 12] = [
        0x01234567, 0x89abcdef, 0x13579bdf, 0x2468ace0, 0x55667788, 0x99aabbcc, 0xddeeff00,
        0x10203040, 1, 0xdeadbeef, 0xfeedface, 0x80000000,
    ];

    fn lifecycle() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }

    fn ranges(entries: u32) -> [Range; 1] {
        [Range {
            id: 1,
            start: 0,
            count: entries,
            name: "declared status test".into(),
        }]
    }

    fn observations() -> Vec<Observation> {
        PATTERN
            .iter()
            .enumerate()
            .map(|(index, &value)| Observation {
                offset: IRQ_STATUS + u64::try_from(index).unwrap() * 4,
                value: u64::from(value),
                known: u64::from(u32::MAX),
            })
            .collect()
    }

    fn observed(entries: u32, observations: &[Observation]) -> Ptd {
        Ptd::from_observations(
            entries,
            &ranges(entries),
            lifecycle(),
            [None; 16],
            observations,
        )
        .unwrap()
    }

    #[test]
    fn stable_little_endian_snapshots_preserve_existing_scalar_reads() {
        let mut bank = observed(384, &observations());
        let mut latch = InterruptLatch::new();
        for (index, value) in PATTERN.into_iter().enumerate() {
            let offset = IRQ_STATUS + u64::try_from(index).unwrap() * 4;
            assert_eq!(
                bank.interrupt_snapshot(offset, Width::Word).unwrap(),
                Snapshot {
                    low: u64::from(value),
                    high: 0
                }
            );
            assert_eq!(
                bank.read(offset, BusWidth::Word, &mut Access::new(0, 0, &mut latch))
                    .unwrap(),
                u64::from(value)
            );
        }
        for (index, words) in PATTERN.as_chunks::<2>().0.iter().enumerate() {
            let offset = IRQ_STATUS + u64::try_from(index).unwrap() * 8;
            let expected = u64::from(words[0]) | u64::from(words[1]) << 32;
            assert_eq!(
                bank.interrupt_snapshot(offset, Width::Double).unwrap(),
                Snapshot {
                    low: expected,
                    high: 0
                }
            );
            assert_eq!(
                bank.read(offset, BusWidth::Double, &mut Access::new(0, 0, &mut latch))
                    .unwrap(),
                expected
            );
        }
        for (offset, low, high) in [
            (0, 0x89abcdef01234567, 0x2468ace013579bdf),
            (16, 0x99aabbcc55667788, 0x10203040ddeeff00),
            (32, 0xdeadbeef00000001, 0x80000000feedface),
        ] {
            assert_eq!(
                bank.interrupt_snapshot(IRQ_STATUS + offset, Width::Quad)
                    .unwrap(),
                Snapshot { low, high }
            );
        }
        assert!(bank.requests().is_empty());
        assert!(latch.take_aic_inputs().is_empty());
    }

    #[test]
    fn complete_width_alignment_and_knownness_are_required_without_padding_registers() {
        let mut bank = observed(384, &observations());
        let mut latch = InterruptLatch::new();
        for width in [Width::Word, Width::Double, Width::Quad] {
            assert_eq!(width.bytes(), 4 * u64::try_from(width.words()).unwrap());
            for offset in [
                0,
                UPDATE_OFFSET,
                IRQ_STATUS - 16,
                IRQ_STATUS + 48,
                0x18200,
                0x18300,
                0x18400,
                u64::MAX - 15,
            ] {
                assert!(bank.interrupt_snapshot(offset, width).is_err());
            }
            for delta in 1..width.bytes() {
                assert_eq!(
                    bank.interrupt_snapshot(IRQ_STATUS + delta, width),
                    Err("PTD IRQ access is not aligned")
                );
            }
        }
        for width in [BusWidth::Byte, BusWidth::Half] {
            assert!(
                bank.read(IRQ_STATUS, width, &mut Access::new(0, 0, &mut latch))
                    .is_err()
            );
        }
        assert!(
            bank.read(
                IRQ_STATUS + 4,
                BusWidth::Double,
                &mut Access::new(0, 0, &mut latch)
            )
            .is_err()
        );
        let tiny = observed(65, &observations()[..3]);
        assert_eq!(
            tiny.interrupt_snapshot(IRQ_STATUS + 8, Width::Double),
            Err("PTD IRQ read crosses its bank")
        );
        assert_eq!(
            tiny.interrupt_snapshot(IRQ_STATUS, Width::Quad),
            Err("PTD IRQ read crosses its bank")
        );
        assert_eq!(
            tiny.interrupt_snapshot(IRQ_STATUS + 8, Width::Word)
                .unwrap()
                .low,
            u64::from(PATTERN[2])
        );
        for index in 0..4 {
            let mut observations = observations();
            observations[index].known &= !(1 << 31);
            let bank = observed(384, &observations);
            assert_eq!(
                bank.interrupt_snapshot(IRQ_STATUS, Width::Quad),
                Err("PTD register contains unqualified bits")
            );
            assert!(
                bank.interrupt_snapshot(IRQ_STATUS + 16, Width::Quad)
                    .is_ok()
            );
            observations.remove(index);
            assert!(
                observed(384, &observations)
                    .interrupt_snapshot(IRQ_STATUS, Width::Quad)
                    .is_err()
            );
        }
    }

    #[test]
    fn snapshots_never_consume_metadata_notifications_or_retained_lifecycle() {
        let (mut bank, local) = Ptd::initialized_local(384, &ranges(384), lifecycle()).unwrap();
        let mut latch = InterruptLatch::new();
        for entry in [0u32, 33, 98, 383] {
            let bit = u64::from(1u32 << (entry % 32));
            bank.write(
                0x18200 + u64::from(entry / 32) * 4,
                BusWidth::Word,
                bit,
                &mut Access::new(0, 0, &mut latch),
            )
            .unwrap();
            for (now, value) in [(7, 0x1234), (9, 0x5678)] {
                bank.write(
                    UPDATE_OFFSET + u64::from(entry) * 8,
                    BusWidth::Double,
                    value + u64::from(entry),
                    &mut Access::new(0, now, &mut latch),
                )
                .unwrap();
            }
        }
        let history = bank.requests();
        let first = Snapshot {
            low: 0x0000000200000001,
            high: 0x0000000400000000,
        };
        for _ in 0..3 {
            assert_eq!(
                local
                    .bank()
                    .interrupt_snapshot(IRQ_STATUS, Width::Quad)
                    .unwrap(),
                first
            );
            assert_eq!(
                bank.interrupt_snapshot(IRQ_STATUS + 32, Width::Quad)
                    .unwrap(),
                Snapshot {
                    low: 0,
                    high: 0x8000000000000000
                }
            );
            assert_eq!(local.asserted(), 1);
            assert_eq!(bank.requests(), history);
        }
        let paused = LifecycleState {
            clocked: false,
            ..lifecycle()
        };
        bank.set_lifecycle(paused, &mut Access::new(0, 10, &mut latch));
        for width in [Width::Word, Width::Double, Width::Quad] {
            assert_eq!(
                bank.interrupt_snapshot(IRQ_STATUS, width),
                Err("PTD transport is paused by its actual owner")
            );
        }
        assert_eq!(local.asserted(), 1);
        bank.set_lifecycle(lifecycle(), &mut Access::new(0, 11, &mut latch));
        assert_eq!(
            bank.interrupt_snapshot(IRQ_STATUS, Width::Quad).unwrap(),
            first
        );
        assert!(
            bank.check_lifecycle(LifecycleState {
                reset: true,
                ..lifecycle()
            })
            .is_err()
        );
        for entry in [0u32, 33, 98, 383] {
            let raw = bank
                .consume_entry(entry, &mut Access::new(0, 12, &mut latch))
                .unwrap();
            assert_eq!(raw.value, 0x5678 + u64::from(entry));
            assert_eq!(raw.metadata, 9 << 10 | 3);
        }
        assert_eq!(local.asserted(), 0);
        assert_eq!(
            bank.interrupt_snapshot(IRQ_STATUS, Width::Quad).unwrap(),
            Snapshot { low: 0, high: 0 }
        );
        assert_eq!(
            bank.interrupt_snapshot(IRQ_STATUS + 32, Width::Quad)
                .unwrap(),
            Snapshot { low: 0, high: 0 }
        );
        assert_eq!(bank.requests(), history);
        assert!(latch.take_aic_inputs().is_empty());
    }
}
