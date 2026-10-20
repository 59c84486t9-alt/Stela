//! The activity monitors (FEAT_AMUv1 and FEAT_AMUv1p1) of the chips whose
//! profile has them, the M4 and later.
//!
//! The architected group 0 has its four counters, each counting the event
//! AMEVTYPER0<n>_EL0 names (Arm mandates the numbers):
//!
//! - 0, processor frequency cycles (0x0011): the PE's core clock, the
//!   board's `cpus` clock where its DeviceTree gives one and otherwise the
//!   system counter's frequency, while the PE does not wait in WFI or WFE,
//!   whose wait gates the clock;
//! - 1, constant frequency cycles (0x4004): the system counter's ticks,
//!   while the PE does not wait, so that the ratio of counters 0 and 1 is
//!   the core clock over the counter's frequency;
//! - 2, instructions retired (0x0008): the instructions the engine retires,
//!   as `machine::pmu` counts them (SVC, HVC and SMC as they take their
//!   exception, no instruction that faults or traps);
//! - 3, memory stall cycles (0x4005): the cycles the PE stalls for memory.
//!   The modeled core has no memory hierarchy, so it never stalls and the
//!   counter keeps its value; that is its count, not a stand-in.
//!
//! Whether the cycle events count during a WFI or WFE wait is left to the
//! implementation by the event definitions; this one stops both, as a gated
//! clock does. The counters are 64 bits wide (AMCFGR_EL0.SIZE 63) and count
//! at every EL. Debug state is never entered here (no external debugger),
//! so AMCR_EL0.HDBG has nothing to halt. The auxiliary group 1 is absent:
//! AMCFGR_EL0.NCG is 0 and AMCGCR_EL0.CG1NC 0 (`machine::identification`
//! holds both), so every group 1 counter and
//! type register is UNDEFINED and AMCNTENSET1_EL0 and AMCNTENCLR1_EL0 hold
//! no enable. The counters and their enables reset to 0, as a power-down
//! resets them.
//!
//! A write to an enabled counter is UNPREDICTABLE; here it sets the count.
//! With FEAT_AMUv1p1 the engine subtracts the virtual offsets
//! (`Access::read`): AMEVCNTVOFF0<n>_EL2 for counters 0, 2 and 3, and
//! CNTVOFF_EL2 for counter 1, which has no offset register of its own.

/// The architected counters.
pub const COUNTERS: usize = 4;
/// AMEVTYPER0<n>_EL0.evtCount of each architected counter.
pub const EVENTS: [u64; COUNTERS] = [
    CPU_CYCLES_EVENT,
    CNT_CYCLES_EVENT,
    INST_RETIRED_EVENT,
    STALL_BACKEND_MEM_EVENT,
];
const CPU_CYCLES_EVENT: u64 = 0x0011;
const CNT_CYCLES_EVENT: u64 = 0x4004;
const INST_RETIRED_EVENT: u64 = 0x0008;
const STALL_BACKEND_MEM_EVENT: u64 = 0x4005;

const CPU_CYCLES: usize = 0;
const CNT_CYCLES: usize = 1;
const INST_RETIRED: usize = 2;

/// AMCNTENSET0_EL0 and AMCNTENCLR0_EL0's P<n> bits.
pub const ENABLES: u64 = (1 << COUNTERS) - 1;

/// One PE's activity monitors.
#[derive(Debug, Clone)]
pub struct Amu {
    /// The core clock, in Hz, and the system counter frequency.
    clock: u64,
    frequency: u64,
    enabled: u64,
    /// The counts as of `synced_count` and `synced_retired`.
    counters: [u64; COUNTERS],
    synced_count: u64,
    synced_retired: u64,
    /// Core cycles short of the next one, in 1/`frequency` cycle units.
    remainder: u64,
    waiting: bool,
}

impl Amu {
    pub fn new(clock: u64, frequency: u64) -> Self {
        Self {
            clock,
            frequency,
            enabled: 0,
            counters: [0; COUNTERS],
            synced_count: 0,
            synced_retired: 0,
            remainder: 0,
            waiting: false,
        }
    }

    /// Whether the counts depend on the time: a cycle counter is enabled.
    pub fn timed(&self) -> bool {
        self.enabled & (1 << CPU_CYCLES | 1 << CNT_CYCLES) != 0
    }

    /// AMCNTENSET0_EL0 and AMCNTENCLR0_EL0's P<n>.
    pub fn enabled(&self) -> u64 {
        self.enabled
    }

    /// The counts at system count `now` with `retired` instructions
    /// retired, and the cycle remainder they leave.
    fn counted(&self, now: u64, retired: u64) -> ([u64; COUNTERS], u64) {
        let mut counters = self.counters;
        let mut remainder = self.remainder;
        let on = |n: usize| self.enabled & 1 << n != 0;
        let ticks = now.saturating_sub(self.synced_count);
        if !self.waiting {
            if on(CPU_CYCLES) {
                let scaled = u128::from(ticks) * u128::from(self.clock) + u128::from(remainder);
                let frequency = u128::from(self.frequency);
                counters[CPU_CYCLES] =
                    counters[CPU_CYCLES].wrapping_add((scaled / frequency) as u64);
                remainder = (scaled % frequency) as u64;
            }
            if on(CNT_CYCLES) {
                counters[CNT_CYCLES] = counters[CNT_CYCLES].wrapping_add(ticks);
            }
        }
        if on(INST_RETIRED) {
            counters[INST_RETIRED] =
                counters[INST_RETIRED].wrapping_add(retired.wrapping_sub(self.synced_retired));
        }
        (counters, remainder)
    }

    /// Count up to `now` and `retired`.
    fn advance(&mut self, now: u64, retired: u64) {
        (self.counters, self.remainder) = self.counted(now, retired);
        self.synced_count = self.synced_count.max(now);
        self.synced_retired = retired;
    }

    /// Count up to now, then continue waiting or not.
    pub fn sync(&mut self, now: u64, retired: u64, waiting: bool) {
        self.advance(now, retired);
        self.waiting = waiting;
    }

    /// The physical count of counter `n`.
    pub fn count(&self, n: usize, now: u64, retired: u64) -> u64 {
        self.counted(now, retired).0[n]
    }

    /// AMEVCNTR0<n>_EL0 written.
    pub fn set_count(&mut self, n: usize, value: u64, now: u64, retired: u64) {
        self.advance(now, retired);
        self.counters[n] = value;
    }

    /// AMCNTENSET0_EL0 (`set`) or AMCNTENCLR0_EL0 written.
    pub fn set_enables(&mut self, value: u64, set: bool, now: u64, retired: u64) {
        self.advance(now, retired);
        if set {
            self.enabled |= value & ENABLES;
        } else {
            self.enabled &= !value;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The M4's P-core clock and the 24 MHz system counter.
    const CLOCK: u64 = 4_512_000_000;
    const FREQUENCY: u64 = 24_000_000;

    #[test]
    fn group_zero_counts_cycles_ticks_and_retired_instructions() {
        let mut amu = Amu::new(CLOCK, FREQUENCY);
        // Nothing counts before an enable.
        assert_eq!(amu.count(0, 24, 100), 0);
        amu.set_enables(ENABLES, true, 24, 100);
        // 24 ticks of the counter are 1 us: 4512 cycles.
        assert_eq!(amu.count(CPU_CYCLES, 48, 150), 4512);
        assert_eq!(amu.count(CNT_CYCLES, 48, 150), 24);
        assert_eq!(amu.count(INST_RETIRED, 48, 150), 50);
        assert_eq!(amu.count(3, 48, 150), 0);
        // A wait stops both cycle counts.
        amu.sync(48, 150, true);
        amu.sync(1000, 150, false);
        assert_eq!(amu.count(CPU_CYCLES, 1024, 160), 2 * 4512);
        assert_eq!(amu.count(CNT_CYCLES, 1024, 160), 48);
        assert_eq!(amu.count(INST_RETIRED, 1024, 160), 60);
        // Clearing an enable stops that counter alone; a write sets it.
        amu.set_enables(1 << INST_RETIRED, false, 1024, 160);
        assert_eq!(amu.enabled(), 0b1011);
        assert_eq!(amu.count(INST_RETIRED, 2000, 500), 60);
        amu.set_count(CNT_CYCLES, 7, 2000, 500);
        assert_eq!(amu.count(CNT_CYCLES, 2024, 500), 31);
        // Only the four architected enables exist.
        amu.set_enables(u64::MAX, true, 2024, 500);
        assert_eq!(amu.enabled(), ENABLES);
    }

    #[test]
    fn a_slow_clock_carries_its_fraction_of_a_cycle() {
        let mut amu = Amu::new(10_000_000, FREQUENCY);
        amu.set_enables(1, true, 0, 0);
        let reads: alloc::vec::Vec<u64> = (1..=3)
            .map(|tick| {
                amu.sync(tick, 0, false);
                amu.count(CPU_CYCLES, tick, 0)
            })
            .collect();
        assert_eq!(reads, [0, 0, 1]);
        assert_eq!(amu.count(CPU_CYCLES, 24, 0), 10);
    }
}
