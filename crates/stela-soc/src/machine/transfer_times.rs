//! The host time each part of a board transfer ([`Devices::transfer`])
//! takes, kept while the host gives a clock (`--profile`). A transfer runs
//! after every device write, under the devices' lock that every PE's device
//! access waits for, and for the home machine at the DMA deadline: this
//! names the master whose step holds it.
//!
//! Without a clock a part costs one branch.
//!
//! [`Devices::transfer`]: stela_engine::machine::Devices::transfer

/// The parts, in the order a transfer runs them: its entry (time and
/// lifecycle), each master's DMA step, and the wires it settles.
pub const TRANSFER_PARTS: [&str; 9] = [
    "entry", "pmp", "aes", "storage", "gfx", "sep", "dcp", "usb", "settle",
];

/// One part's calls, host ticks in all and the longest call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PartTime {
    pub calls: u64,
    pub ticks: u64,
    pub longest: u64,
}

/// The parts of a scalar device write, in the order it runs them: its
/// entry (time, lifecycle and the checks before the model), the model's
/// write, and the wires and CPU releases it settles.
pub const WRITE_PARTS: [&str; 3] = ["entry", "model", "service"];

/// The register pages [`TransferTimes`] times writes of apart.
pub const WRITE_PAGES: usize = 16;

/// The writes to one 4 KiB register page: their calls, each part's host
/// ticks by [`WRITE_PARTS`], and the longest write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageWrites {
    pub page: u64,
    pub calls: u64,
    pub parts: [u64; WRITE_PARTS.len()],
    pub longest: u64,
}

/// [`PageWrites`] by page, the first [`WRITE_PAGES`] pages written, and the
/// rest together in `other`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteTimes {
    pub pages: [PageWrites; WRITE_PAGES],
    pub other: PageWrites,
}

impl PageWrites {
    fn add(&mut self, parts: [u64; WRITE_PARTS.len()]) {
        self.calls += 1;
        let mut total = 0u64;
        for (sum, part) in self.parts.iter_mut().zip(parts) {
            *sum = sum.wrapping_add(part);
            total = total.wrapping_add(part);
        }
        self.longest = self.longest.max(total);
    }
}

#[derive(Default)]
pub(super) struct TransferTimes {
    clock: Option<fn() -> u64>,
    parts: [PartTime; TRANSFER_PARTS.len()],
    writes: WriteTimes,
}

/// The time since the last part ended.
pub(super) struct Lap {
    clock: Option<fn() -> u64>,
    last: u64,
}

impl TransferTimes {
    pub(super) fn set_clock(&mut self, clock: Option<fn() -> u64>) {
        self.clock = clock;
    }

    /// A lap from now.
    pub(super) fn lap(&self) -> Lap {
        Lap {
            clock: self.clock,
            last: self.clock.map_or(0, |clock| clock()),
        }
    }

    /// Each part's time since the last call, by [`TRANSFER_PARTS`].
    pub(super) fn take(&mut self) -> [PartTime; TRANSFER_PARTS.len()] {
        core::mem::take(&mut self.parts)
    }

    /// Count a write to `physical` whose parts took `parts`, while timed.
    pub(super) fn add_write(&mut self, physical: u64, parts: [u64; WRITE_PARTS.len()]) {
        if self.clock.is_none() {
            return;
        }
        let page = physical & !0xfff;
        match self
            .writes
            .pages
            .iter_mut()
            .find(|entry| entry.calls == 0 || entry.page == page)
        {
            Some(entry) => {
                entry.page = page;
                entry.add(parts);
            }
            None => self.writes.other.add(parts),
        }
    }

    /// The writes timed since the last call.
    pub(super) fn take_writes(&mut self) -> WriteTimes {
        core::mem::take(&mut self.writes)
    }
}

impl Lap {
    /// The ticks since the last part ended, which ends one now; 0 without
    /// a clock.
    pub(super) fn split(&mut self) -> u64 {
        let Some(clock) = self.clock else {
            return 0;
        };
        let now = clock();
        let took = now.wrapping_sub(self.last);
        self.last = now;
        took
    }

    /// Part `part` (an index of [`TRANSFER_PARTS`]) ended now.
    pub(super) fn end(&mut self, times: &mut TransferTimes, part: usize) {
        let Some(clock) = self.clock else {
            return;
        };
        let now = clock();
        let took = now.wrapping_sub(self.last);
        self.last = now;
        let time = &mut times.parts[part];
        time.calls += 1;
        time.ticks = time.ticks.wrapping_add(took);
        time.longest = time.longest.max(took);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::AppleDevices;
    use core::sync::atomic::{AtomicU64, Ordering};
    use stela_contracts::dma::test_support::Ram;
    use stela_engine::machine::Devices;

    static TICKS: AtomicU64 = AtomicU64::new(0);

    /// Advances by 10 a read.
    fn clock() -> u64 {
        TICKS.fetch_add(10, Ordering::Relaxed) + 10
    }

    #[test]
    fn a_clock_times_each_transfer_part_and_none_costs_nothing() {
        let mut devices = AppleDevices::new();
        let mut ram = Ram::new(0x8_0000_0000, 0x1000);
        devices.transfer(0, &mut ram, 0).unwrap();
        assert_eq!(devices.take_transfer_times(), [PartTime::default(); 9]);
        devices.time_transfers(Some(clock));
        devices.transfer(0, &mut ram, 1).unwrap();
        devices.transfer(0, &mut ram, 2).unwrap();
        let times = devices.take_transfer_times();
        // Each part read the clock once a transfer, one read after the
        // last: 10 ticks each.
        assert!(
            times.iter().all(|time| *time
                == PartTime {
                    calls: 2,
                    ticks: 20,
                    longest: 10
                }),
            "{times:?}"
        );
        assert_eq!(devices.take_transfer_times(), [PartTime::default(); 9]);
        devices.time_transfers(None);
        devices.transfer(0, &mut ram, 3).unwrap();
        assert_eq!(devices.take_transfer_times(), [PartTime::default(); 9]);
    }

    /// Writes count by page with their entry, model and service parts, the
    /// pages past the table together, and only while a clock is given.
    #[test]
    fn writes_are_timed_by_page_and_part() {
        let mut times = TransferTimes::default();
        times.add_write(0x1000, [1, 2, 3]);
        assert_eq!(times.take_writes(), WriteTimes::default());
        times.set_clock(Some(clock));
        times.add_write(0x1004, [1, 2, 3]);
        times.add_write(0x1ff8, [4, 0, 0]);
        for page in 0..WRITE_PAGES as u64 {
            times.add_write(0x10_0000 + page * 0x1000, [0, 1, 0]);
        }
        let writes = times.take_writes();
        assert_eq!(
            writes.pages[0],
            PageWrites {
                page: 0x1000,
                calls: 2,
                parts: [5, 2, 3],
                longest: 6,
            }
        );
        assert_eq!(writes.pages[WRITE_PAGES - 1].page, 0x10_0000 + 0xe000);
        assert_eq!((writes.other.calls, writes.other.parts), (1, [0, 1, 0]));
        assert_eq!(times.take_writes(), WriteTimes::default());
    }
}
