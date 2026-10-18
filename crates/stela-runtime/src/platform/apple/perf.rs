//! PMGR version-1 AON/SOC/cluster event counters, selected by `perf-regs`
//! and the `devices`, `clocks`, `power-domains` and `events` DT records.
//!
//! Kernel file offsets: `_getPerfCounterOffset` 0x2b8e974 places selector n
//! at global+0x100+16*n; `_enableSOCPerfCounter` 0x2b913ec/0x2b916b4 changes
//! enable bit 0, polarity bit 1 and mode bits 11:8. `_enableSOCPerfCounters`
//! 0x2b92424 gates the bank with global bit 0. `_get/setSOCPerfCounter`
//! 0x2b925b4/0x2b928cc joins/restores the low/high words at +8/+12.
//!
//! Stela's boot stage hands off with global control, every selected counter's
//! control and counts zero: both gates disabled, polarity 0, mode 0, as a boot
//! chain that programs none of them would. iBoot's conditional programming is
//! not reproduced. Counts retain saved samples and share one 64-bit value
//! across the two 32-bit words. This emulated die has no physical
//! clock edges, voltage/thermal triggers or fabric events; those sources do
//! not invent activity from elapsed host time. A source with known event
//! units can call `record`, which honors both gates, polarity and mode.
//! No calibrated residency rate or source-to-PMGR-domain binding is known;
//! residency samples therefore also hold software's saved value. This is an
//! explicit absent-activity abstraction, not a measured silicon reset/rate.
//!
//! Only DT-selected counters exist; holes, other widths, layout versions,
//! class-1 busy status and control fields without described effects refuse.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::{collections::BTreeMap, vec::Vec};

const NAME: &str = "pmgr-perf";
pub const COUNTER_BASE: u64 = 0x100;
pub const STRIDE: u64 = 0x10;
const LOW: u64 = 8;
const HIGH: u64 = 12;
const ENABLE: u32 = 1;
/// Polarity bit 1 and the mode nibble supplied to the mode overload.
pub const MODE_MASK: u32 = 0xf02;
const CONTROL_MASK: u32 = ENABLE | MODE_MASK;

#[derive(Debug, Clone, Default)]
struct Counter {
    control: u32,
    count: u64,
}

#[derive(Debug, Clone)]
pub struct PerfCounters {
    global: u32,
    counters: BTreeMap<u16, Counter>,
}

impl PerfCounters {
    pub fn new(selectors: &[u16]) -> Result<Self, &'static str> {
        let mut counters = BTreeMap::new();
        for &selector in selectors {
            if selector > u16::from(u8::MAX) {
                return Err("PMGR performance selector exceeds the DT selector width");
            }
            if counters.insert(selector, Counter::default()).is_some() {
                return Err("duplicate PMGR performance counter selector");
            }
        }
        Ok(Self {
            global: 0,
            counters,
        })
    }

    /// Only these three words of each selected counter are mapped, plus the
    /// global word. Avoid claiming any other owner's overlapping registers.
    pub fn spans(&self) -> Vec<(u64, u64)> {
        let mut spans = alloc::vec![(0, 4)];
        for &selector in self.counters.keys() {
            let base = COUNTER_BASE + u64::from(selector) * STRIDE;
            spans.extend([(base, 4), (base + LOW, 8)]);
        }
        spans
    }

    /// Record documented units from a source whose mode includes polarity
    /// and the mode nibble exactly as programmed. No guessed event scaling.
    pub fn record(&mut self, selector: u16, mode: u32, amount: u64) -> Result<(), &'static str> {
        if mode & !MODE_MASK != 0 {
            return Err("PMGR event mode contains undescribed fields");
        }
        let counter = self
            .counters
            .get_mut(&selector)
            .ok_or("PMGR event selector is not described by the DeviceTree")?;
        if self.global & ENABLE == 0 {
            return Ok(());
        }
        let control = counter.control;
        if control & ENABLE != 0 && control & MODE_MASK == mode {
            counter.count = counter.count.wrapping_add(amount);
        }
        Ok(())
    }

    fn locate(&mut self, offset: u64, width: Width) -> Result<(&mut Counter, u64), &'static str> {
        if width != Width::Word {
            return Err("PMGR performance registers require 32-bit accesses");
        }
        let offset = offset
            .checked_sub(COUNTER_BASE)
            .ok_or("undescribed PMGR performance register")?;
        let selector = u16::try_from(offset / STRIDE)
            .map_err(|_| "PMGR performance selector is out of range")?;
        let word = offset % STRIDE;
        if !matches!(word, 0 | LOW | HIGH) {
            return Err("undescribed word within PMGR performance counter");
        }
        let counter = self
            .counters
            .get_mut(&selector)
            .ok_or("PMGR performance selector is not described by the DeviceTree")?;
        Ok((counter, word))
    }
}

impl MmioDevice for PerfCounters {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let result = if offset == 0 && width == Width::Word {
            Ok(u64::from(self.global))
        } else {
            self.locate(offset, width)
                .and_then(|(counter, word)| match word {
                    0 => Ok(u64::from(counter.control)),
                    LOW => Ok(counter.count & u64::from(u32::MAX)),
                    HIGH => Ok(counter.count >> u32::BITS),
                    _ => unreachable!(),
                })
        };
        result.map_err(|reason| refuse(NAME, offset, width, Direction::Read, reason))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let result = if offset == 0 && width == Width::Word {
            if value & !u64::from(ENABLE) != 0 {
                Err("PMGR global performance control contains undescribed fields")
            } else {
                self.global = value as u32;
                Ok(())
            }
        } else {
            self.locate(offset, width).and_then(|(counter, word)| {
                match word {
                    0 => {
                        if value & !u64::from(CONTROL_MASK) != 0 {
                            return Err("PMGR performance control contains undescribed fields");
                        }
                        counter.control = value as u32;
                    }
                    LOW => {
                        counter.count =
                            (counter.count & !(u32::MAX as u64)) | (value & u64::from(u32::MAX))
                    }
                    HIGH => {
                        counter.count = (counter.count & u64::from(u32::MAX))
                            | ((value & u64::from(u32::MAX)) << u32::BITS)
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })
        };
        result.map_err(|reason| refuse(NAME, offset, width, Direction::Write, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn the_boot_stage_hands_off_disabled_controls_and_empty_counts() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut perf = PerfCounters::new(&[0, 7, 255]).unwrap();
        assert_eq!(perf.read(0, Width::Word, &mut access), Ok(0));
        for selector in [0, 7, 255] {
            let base = COUNTER_BASE + u64::from(selector) * STRIDE;
            for word in [0, LOW, HIGH] {
                assert_eq!(perf.read(base + word, Width::Word, &mut access), Ok(0));
            }
            perf.record(selector, 0, 17).unwrap();
        }
        // Each gate alone inhibits events; the kernel can RMW the handoff
        // control and global words to enable a counter without seeding state.
        let base = COUNTER_BASE + 7 * STRIDE;
        let control = perf.read(base, Width::Word, &mut access).unwrap();
        perf.write(base, Width::Word, control | u64::from(ENABLE), &mut access)
            .unwrap();
        perf.record(7, 0, 17).unwrap();
        assert_eq!(perf.read(base + LOW, Width::Word, &mut access), Ok(0));
        let global = perf.read(0, Width::Word, &mut access).unwrap();
        perf.write(0, Width::Word, global | u64::from(ENABLE), &mut access)
            .unwrap();
        perf.record(0, 0, 17).unwrap();
        assert_eq!(
            perf.read(COUNTER_BASE + LOW, Width::Word, &mut access),
            Ok(0)
        );
        perf.record(7, 0, 17).unwrap();
        assert_eq!(perf.read(base + LOW, Width::Word, &mut access), Ok(17));
    }

    #[test]
    fn selected_counts_share_low_high_restore_and_gate_events_by_mode() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut perf = PerfCounters::new(&[7]).unwrap();
        let base = COUNTER_BASE + 7 * STRIDE;
        assert_eq!(perf.read(0, Width::Word, &mut access), Ok(0));
        assert_eq!(perf.read(base, Width::Word, &mut access), Ok(0));
        perf.write(base + LOW, Width::Word, u32::MAX.into(), &mut access)
            .unwrap();
        perf.write(base + HIGH, Width::Word, 3, &mut access)
            .unwrap();
        perf.write(base, Width::Word, 0x103, &mut access).unwrap();
        perf.record(7, 0x102, 1).unwrap(); // global gate starts disabled
        perf.write(0, Width::Word, 0, &mut access).unwrap();
        perf.record(7, 0x102, 1).unwrap();
        assert_eq!(
            perf.read(base + LOW, Width::Word, &mut access),
            Ok(u32::MAX.into())
        );
        perf.write(0, Width::Word, 1, &mut access).unwrap();
        perf.record(7, 0x100, 1).unwrap(); // opposite polarity
        perf.record(7, 0x302, 1).unwrap(); // another mode
        perf.record(7, 0x102, 2).unwrap();
        assert_eq!(perf.read(base + LOW, Width::Word, &mut access), Ok(1));
        assert_eq!(perf.read(base + HIGH, Width::Word, &mut access), Ok(4));
        perf.write(base, Width::Word, 0x102, &mut access).unwrap();
        perf.record(7, 0x102, 19).unwrap(); // individually disabled
        access.now += 24_000_000;
        perf.advance(&mut access).unwrap();
        assert_eq!(perf.read(base + LOW, Width::Word, &mut access), Ok(1));
        perf.write(base + HIGH, Width::Word, u32::MAX.into(), &mut access)
            .unwrap();
        perf.write(base + LOW, Width::Word, u32::MAX.into(), &mut access)
            .unwrap();
        perf.write(base, Width::Word, 0x103, &mut access).unwrap();
        perf.record(7, 0x102, 1).unwrap();
        assert_eq!(perf.read(base + HIGH, Width::Word, &mut access), Ok(0));
        assert_eq!(perf.read(base + LOW, Width::Word, &mut access), Ok(0));
    }

    #[test]
    fn holes_widths_and_undescribed_control_fields_refuse_without_effects() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut perf = PerfCounters::new(&[0, 3]).unwrap();
        for (offset, width) in [
            (4, Width::Word),
            (COUNTER_BASE + 4, Width::Word),
            (COUNTER_BASE + STRIDE, Width::Word),
            (COUNTER_BASE, Width::Double),
            (COUNTER_BASE + 9, Width::Byte),
            (0x10_0100, Width::Word),
        ] {
            assert!(perf.read(offset, width, &mut access).is_err());
            assert!(perf.write(offset, width, 0, &mut access).is_err());
        }
        perf.write(0, Width::Word, 1, &mut access).unwrap();
        perf.write(COUNTER_BASE, Width::Word, 3, &mut access)
            .unwrap();
        assert!(perf.write(0, Width::Word, 2, &mut access).is_err());
        assert!(
            perf.write(COUNTER_BASE, Width::Word, 7, &mut access)
                .is_err()
        );
        assert_eq!(perf.read(0, Width::Word, &mut access), Ok(1));
        assert_eq!(perf.read(COUNTER_BASE, Width::Word, &mut access), Ok(3));
        assert!(perf.record(1, 0, 1).is_err());
        assert!(perf.record(0, 4, 1).is_err());
        assert!(PerfCounters::new(&[1, 1]).is_err());
        assert!(PerfCounters::new(&[256]).is_err());
        assert_eq!(
            perf.spans(),
            alloc::vec![(0, 4), (0x100, 4), (0x108, 8), (0x130, 4), (0x138, 8)]
        );
    }
}
