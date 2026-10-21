//! Apple's per-PE CPMU fixed cycle and retired-instruction counters, with
//! separately qualified M1–M6 layouts (`layout`). XNU xnu-12377.121.6 H13
//! supplies M1's 48-bit width, H14–H17 supply M2–M5's 64-bit width, and
//! original 26A434 mac18g supplies M6's distinct 15-counter mapping.
//! See `docs/research/core-pmu.md` for source hashes and qualification limits.
//!
//! - PMC0 counts cycles and PMC1 retired instructions. All other counters
//!   preserve writes but refuse counting enables without qualified events.
//!   Counters wrap at their configured width, with bit47 (M1) or bit63
//!   (M2–M6) as overflow; PMSR uses the selected layout's slot mapping.
//! - PMCR0 enables counting (bits 0-7, 32-33 for PMC8 and PMC9), selects the
//!   PMI (bits 8-10, 4 for FIQ), reports it (bit 11, PMAI), enables each
//!   counter's PMI (bits 12-19, 44-45), PC capture for PMC5-7 (bits 24-26)
//!   and EL0 access (bit 30).
//! - PMCR1 filters counting by mode: bits 8-15 and 40-41 at EL0, bits 16-23
//!   and 48-49 in the kernel. XNU, which runs at EL2 on the M2, calls bits
//!   16 and 17 the EL2 enables, so they count at EL1 and EL2 alike
//!   (inference); a guarded level counts as its EL (inference).
//! - With `CONFIG_EXCLAVES || HYPERVISOR` XNU writes PMCR1's value to
//!   `S3_1_C15_C7_2` as well, before PMCR0. What that register filters is not
//!   described, so counting while it differs from PMCR1 stops.
//!
//! This machine counts cycles at the PE's core clock while it is not waiting
//! in WFI or WFE, and instructions as the engine retires them: each
//! instruction that completes, and SVC, HVC and SMC, which complete as they
//! take their exception; an instruction that faults or traps is not
//! counted. A PMI is asserted, as FIQ, while PMCR0 selects FIQ and a
//! counter with its PMI enabled has its overflow bit set; PMAI reads that
//! assertion (inference: XNU's FIQ handler reads PMAI to recognize a PMI,
//! then disables the monitor and clears every overflow by rewriting the
//! counters). The reset values are not documented; they are taken as 0,
//! under which nothing counts before software programs the monitor.
//!
//! Programmable event counting, PC capture, EL0 access, other PMI modes,
//! instruction matching (OPMAT, OPMSK) and the PMCR2-4 controls are not
//! modelled: a write that enables one stops. PMESR0 and PMESR1 store their
//! selectors within the layout's qualified field masks, which no counter
//! here uses. M6's new controls refuse every access until their effects
//! are independently qualified.
use super::Chip;

mod layout;
use layout::Layout;
use stela_compiler::aarch64::system::registers::Encoding;

const fn monitor(op1: u8, crm: u8, op2: u8) -> Encoding {
    Encoding::new(3, op1, 15, crm, op2)
}

pub const PMCR0: Encoding = monitor(1, 0, 0);
pub const PMCR1: Encoding = monitor(1, 1, 0);
pub const PMCR2: Encoding = monitor(1, 2, 0);
pub const PMCR3: Encoding = monitor(1, 3, 0);
pub const PMCR4: Encoding = monitor(1, 4, 0);
pub const PMESR0: Encoding = monitor(1, 5, 0);
pub const PMESR1: Encoding = monitor(1, 6, 0);
pub const OPMAT0: Encoding = monitor(1, 7, 0);
pub const OPMAT1: Encoding = monitor(1, 8, 0);
pub const OPMSK0: Encoding = monitor(1, 9, 0);
pub const OPMSK1: Encoding = monitor(1, 10, 0);
/// Two further controls without a public name that 26A434 XNU's kpc saves
/// after OPMSK1 (`kpc_get_config`, 0xfffffe000bd41050) and restores with the
/// others (0xfffffe000bd8db14); they configure nothing at 0.
pub const PMCR_C0_4: Encoding = monitor(1, 0, 4);
pub const PMCR_C1_4: Encoding = monitor(1, 1, 4);
/// Written with PMCR1's value (`S3_1_C15_C7_2`, no public name).
pub const PMCR1_ALTERNATE: Encoding = monitor(1, 7, 2);
pub const PMSR: Encoding = monitor(1, 13, 0);
/// The PC captured for a PMC5-7 PMI (`S3_1_C15_C14_1`).
pub const PC_CAPTURE: Encoding = monitor(1, 14, 1);
/// PMC0 to PMC9: CRm 0-7, then 9 and 10 (H14 lacks
/// `CPMU_S3_2_C15_C9_09_ADDRESS`).
pub const PMC: [Encoding; COUNTERS] = [
    monitor(2, 0, 0),
    monitor(2, 1, 0),
    monitor(2, 2, 0),
    monitor(2, 3, 0),
    monitor(2, 4, 0),
    monitor(2, 5, 0),
    monitor(2, 6, 0),
    monitor(2, 7, 0),
    monitor(2, 9, 0),
    monitor(2, 10, 0),
];
/// The registers that store a configuration and accept only 0, which
/// configures nothing, in [`Pmu::extension`] order.
const EXTENSION: [Encoding; EXTENSIONS] = [
    PMCR2, PMCR3, PMCR4, OPMAT0, OPMAT1, OPMSK0, OPMSK1, PMCR_C0_4, PMCR_C1_4,
];
const EXTENSIONS: usize = 9;

pub const COUNTERS: usize = 10;
const CYCLES: usize = 0;
const INSTRUCTIONS: usize = 1;
#[cfg(test)]
const OVERFLOW: u64 = 1 << 63;

/// Counter geometry, separately qualified from event selectors and clocks.
#[derive(Debug, Clone, Copy)]
enum Width {
    Bits48,
    Bits64,
}

impl Width {
    fn bits(self) -> u32 {
        match self {
            Self::Bits48 => 48,
            Self::Bits64 => 64,
        }
    }

    fn mask(self) -> u64 {
        u64::MAX >> (64 - self.bits())
    }

    fn overflow(self) -> u64 {
        1 << (self.bits() - 1)
    }
}

const PMCR0_COUNT: u64 = 0xff | 0b11 << 32;
const PMCR0_INTGEN: u64 = 0b111 << 8;
const PMCR0_INTGEN_FIQ: u64 = 4 << 8;
const PMCR0_PMAI: u64 = 1 << 11;
const PMCR0_PMI: u64 = 0xff << 12 | 0b11 << 44;
const PMCR0_PC_CAPTURE: u64 = 0b111 << 24;
const PMCR0_USER_ACCESS: u64 = 1 << 30;
const PMCR0_KNOWN: u64 =
    PMCR0_COUNT | PMCR0_INTGEN | PMCR0_PMAI | PMCR0_PMI | PMCR0_PC_CAPTURE | PMCR0_USER_ACCESS;
/// The counters this machine counts for: PMC0 and PMC1.
const PMCR0_FIXED: u64 = 0b11;
const PMCR1_KNOWN: u64 = 0xff << 8 | 0xff << 16 | 0b11 << 40 | 0b11 << 48;

/// Bit `n` of a PMCR0 or PMCR1 field whose PMC8 and PMC9 bits sit at
/// `high` instead of following PMC7's.
const fn counter_bit(low: u32, high: u32, n: usize) -> u64 {
    if n < 8 {
        1 << (low + n as u32)
    } else {
        1 << (high + n as u32 - 8)
    }
}

/// Where the PE runs, for counting: its EL and whether it waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub el: u8,
    pub waiting: bool,
}

/// One PE's CPMU.
#[derive(Debug, Clone)]
pub struct Pmu {
    layout: Layout,
    /// The core clock, in Hz, and the system counter frequency.
    clock: u64,
    frequency: u64,
    pmcr0: u64,
    pmcr1: u64,
    alternate: Option<u64>,
    pmesr: [Option<u64>; 2],
    extension: [Option<u64>; EXTENSIONS],
    /// The counts as of `synced_count` and `synced_retired`.
    counters: [u64; layout::MAX_COUNTERS],
    synced_count: u64,
    synced_retired: u64,
    /// Cycles short of the next one, in 1/`frequency` cycle units.
    remainder: u64,
    context: Context,
    /// The system count and retired instruction count at which the PMI
    /// asserts, while the context and controls hold.
    cycle_deadline: Option<u64>,
    instruction_deadline: Option<u64>,
    /// The PMI is asserted as of the last synchronization.
    asserted: bool,
}

impl Pmu {
    /// Preserve the original M2 monitor API.
    pub fn new(clock: u64, frequency: u64) -> Self {
        Self::with_layout(Layout::on(Chip::AppleM2), clock, frequency)
    }

    /// Construct only a source-qualified core monitor, with a core clock
    /// supplied by its PE profile. A generation name supplies no clock or
    /// event layout. A zero clock or system frequency cannot construct a
    /// monitor.
    pub fn for_chip(chip: Chip, clock: u64, frequency: u64) -> Option<Self> {
        if clock == 0 || frequency == 0 {
            return None;
        }
        Some(Self::with_layout(Layout::on(chip), clock, frequency))
    }

    fn with_layout(layout: Layout, clock: u64, frequency: u64) -> Self {
        Self {
            layout,
            clock,
            frequency,
            pmcr0: 0,
            pmcr1: 0,
            alternate: None,
            pmesr: [None; 2],
            extension: [None; EXTENSIONS],
            counters: [0; layout::MAX_COUNTERS],
            synced_count: 0,
            synced_retired: 0,
            remainder: 0,
            context: Context {
                el: 2,
                waiting: false,
            },
            cycle_deadline: None,
            instruction_deadline: None,
            asserted: false,
        }
    }

    /// All declared chips have a separately qualified fixed CPMU layout.
    /// This says nothing about events, extra controls or a board's clocks.
    pub fn on(chip: Chip) -> bool {
        let _ = Layout::on(chip);
        true
    }

    /// Preserve the original ten-counter allocation query (M1/M2).
    pub fn owns(encoding: Encoding) -> bool {
        Self::owns_on(Chip::AppleM2, encoding)
    }

    /// The selected chip's allocation, including explicitly unqualified
    /// controls whose effects must refuse, and its exact counter aliases.
    pub fn owns_on(chip: Chip, encoding: Encoding) -> bool {
        let layout = Layout::on(chip);
        Self::common(encoding)
            || layout.counters.contains(&encoding)
            || layout.unqualified_controls.contains(&encoding)
    }

    pub fn counter_count(&self) -> usize {
        self.layout.counters.len()
    }

    pub fn counter_encoding(&self, slot: usize) -> Option<Encoding> {
        self.layout.counters.get(slot).copied()
    }

    fn common(encoding: Encoding) -> bool {
        matches!(
            encoding,
            PMCR0 | PMCR1 | PMESR0 | PMESR1 | PMCR1_ALTERNATE | PMSR | PC_CAPTURE
        ) || EXTENSION.contains(&encoding)
    }

    fn check_access(&self, encoding: Encoding) -> Result<(), &'static str> {
        if self.layout.unqualified_controls.contains(&encoding) {
            Err("M6 CPMU control effects are not source-qualified")
        } else if Self::common(encoding) || self.layout.counters.contains(&encoding) {
            Ok(())
        } else {
            Err("register is not allocated in the selected CPMU layout")
        }
    }

    /// Whether counter `n` counts in `context`.
    fn counts(&self, n: usize, context: Context) -> bool {
        let filter = if context.el == 0 {
            counter_bit(8, 40, n)
        } else {
            counter_bit(16, 48, n)
        };
        self.pmcr0 & counter_bit(0, 32, n) != 0
            && self.pmcr1 & filter != 0
            && !(n == CYCLES && context.waiting)
    }

    /// Whether the counts depend on the time: PMC0 is enabled.
    pub fn timed(&self) -> bool {
        self.pmcr0 & counter_bit(0, 32, CYCLES) != 0
    }

    /// Count up to the system count `now` and `retired` instructions in the
    /// context since the last synchronization.
    fn advance(&mut self, now: u64, retired: u64) {
        let ticks = now.saturating_sub(self.synced_count);
        let instructions = retired.wrapping_sub(self.synced_retired);
        if self.counts(CYCLES, self.context) {
            let scaled = u128::from(ticks) * u128::from(self.clock) + u128::from(self.remainder);
            let frequency = u128::from(self.frequency);
            self.counters[CYCLES] = self.counters[CYCLES].wrapping_add((scaled / frequency) as u64)
                & self.layout.width.mask();
            self.remainder = (scaled % frequency) as u64;
        }
        if self.counts(INSTRUCTIONS, self.context) {
            self.counters[INSTRUCTIONS] =
                self.counters[INSTRUCTIONS].wrapping_add(instructions) & self.layout.width.mask();
        }
        self.synced_count = self.synced_count.max(now);
        self.synced_retired = retired;
    }

    /// Count up to now, then continue in `context`.
    pub fn sync(&mut self, now: u64, retired: u64, context: Context) {
        self.advance(now, retired);
        self.context = context;
        self.update();
    }

    /// The PMI of the current counts, and when the counting reaches one.
    fn update(&mut self) {
        let fiq = self.pmcr0 & PMCR0_INTGEN == PMCR0_INTGEN_FIQ;
        let armed = |n: usize| n < COUNTERS && fiq && self.pmcr0 & counter_bit(12, 44, n) != 0;
        self.asserted = (0..self.counter_count())
            .any(|n| armed(n) && self.counters[n] & self.layout.width.overflow() != 0);
        self.cycle_deadline = (armed(CYCLES) && self.counts(CYCLES, self.context))
            .then(|| {
                let needed = u128::from(
                    self.layout
                        .width
                        .overflow()
                        .wrapping_sub(self.counters[CYCLES])
                        & self.layout.width.mask(),
                );
                let scaled = (needed * u128::from(self.frequency))
                    .saturating_sub(u128::from(self.remainder));
                let ticks = scaled.div_ceil(u128::from(self.clock));
                u64::try_from(ticks)
                    .ok()
                    .and_then(|ticks| self.synced_count.checked_add(ticks))
            })
            .flatten();
        self.instruction_deadline = (armed(INSTRUCTIONS)
            && self.counts(INSTRUCTIONS, self.context))
        .then(|| {
            self.synced_retired.checked_add(
                self.layout
                    .width
                    .overflow()
                    .wrapping_sub(self.counters[INSTRUCTIONS])
                    & self.layout.width.mask(),
            )
        })
        .flatten();
    }

    /// Whether the PMI is asserted at system count `now` with `retired`
    /// instructions retired, the context unchanged since the last
    /// synchronization.
    pub fn asserted(&self, now: u64, retired: u64) -> bool {
        if !(self.asserted
            || self.cycle_deadline.is_some_and(|deadline| now >= deadline)
            || self
                .instruction_deadline
                .is_some_and(|deadline| retired >= deadline))
        {
            return false;
        }
        // A cached deadline identifies the first crossing, but the high
        // counter bit can clear again after a complete-width wrap. Do not
        // turn that deadline into an unqualified sticky pending latch.
        (0..self.counter_count()).any(|n| {
            let armed = n < COUNTERS
                && self.pmcr0 & PMCR0_INTGEN == PMCR0_INTGEN_FIQ
                && self.pmcr0 & counter_bit(12, 44, n) != 0;
            if !armed {
                return false;
            }
            let increment = if self.counts(n, self.context) {
                match n {
                    CYCLES => {
                        let ticks = now.saturating_sub(self.synced_count);
                        ((u128::from(ticks) * u128::from(self.clock) + u128::from(self.remainder))
                            / u128::from(self.frequency)) as u64
                    }
                    INSTRUCTIONS => retired.wrapping_sub(self.synced_retired),
                    _ => 0,
                }
            } else {
                0
            };
            self.counters[n].wrapping_add(increment) & self.layout.width.overflow() != 0
        })
    }

    /// The earliest system count at which the PMI can assert without
    /// another instruction retiring.
    pub fn deadline(&self) -> Option<u64> {
        if self.asserted {
            Some(self.synced_count)
        } else {
            self.cycle_deadline
        }
    }

    pub fn read(
        &mut self,
        encoding: Encoding,
        now: u64,
        retired: u64,
        context: Context,
    ) -> Result<u64, &'static str> {
        self.check_access(encoding)?;
        self.sync(now, retired, context);
        let stored = |value: Option<u64>| {
            value.ok_or("read of a performance monitor control before its first write")
        };
        Ok(match encoding {
            PMCR0 => self.pmcr0 | if self.asserted { PMCR0_PMAI } else { 0 },
            PMCR1 => self.pmcr1,
            PMCR1_ALTERNATE => stored(self.alternate)?,
            PMESR0 => stored(self.pmesr[0])?,
            PMESR1 => stored(self.pmesr[1])?,
            PMSR => (0..self.counter_count())
                .filter(|&n| self.counters[n] & self.layout.width.overflow() != 0)
                .fold(0, |status, n| status | self.layout.status_bit(n)),
            PC_CAPTURE => return Err("PMI PC capture is not modelled"),
            _ => match self.layout.counters.iter().position(|&pmc| pmc == encoding) {
                Some(n) => self.counters[n],
                None => {
                    let index = EXTENSION.iter().position(|&register| register == encoding);
                    stored(index.and_then(|index| self.extension[index]))?
                }
            },
        })
    }

    pub fn write(
        &mut self,
        encoding: Encoding,
        value: u64,
        now: u64,
        retired: u64,
        context: Context,
    ) -> Result<(), &'static str> {
        self.check_access(encoding)?;
        self.advance(now, retired);
        let written = self.store(encoding, value);
        self.context = context;
        self.update();
        written
    }

    fn store(&mut self, encoding: Encoding, value: u64) -> Result<(), &'static str> {
        match encoding {
            PMCR0 => {
                if value & !PMCR0_KNOWN != 0 {
                    return Err("PMCR0 bit without public description");
                }
                if value & PMCR0_COUNT & !PMCR0_FIXED != 0 {
                    return Err(
                        "PMCR0 enables a programmable counter; event counting is not modelled",
                    );
                }
                if !matches!(value & PMCR0_INTGEN, 0 | PMCR0_INTGEN_FIQ) {
                    return Err("PMCR0 PMI generation other than FIQ");
                }
                if value & PMCR0_PC_CAPTURE != 0 {
                    return Err("PMCR0 PMI PC capture is not modelled");
                }
                if value & PMCR0_USER_ACCESS != 0 {
                    return Err("PMCR0 EL0 access to the monitor is not modelled");
                }
                if value & PMCR0_COUNT != 0 && self.alternate != Some(self.pmcr1) {
                    return Err("counting while S3_1_C15_C7_2 differs from PMCR1");
                }
                // PMAI reports the PMI; writing it changes nothing.
                self.pmcr0 = value & !PMCR0_PMAI;
            }
            PMCR1 | PMCR1_ALTERNATE => {
                if value & !PMCR1_KNOWN != 0 {
                    return Err("PMCR1 bit without public description");
                }
                if encoding == PMCR1 {
                    if self.pmcr0 & PMCR0_COUNT != 0 && self.alternate != Some(value) {
                        return Err("counting while S3_1_C15_C7_2 differs from PMCR1");
                    }
                    self.pmcr1 = value;
                } else {
                    self.alternate = Some(value);
                }
            }
            PMESR0 | PMESR1 => {
                if value & !self.layout.selectors != 0 {
                    return Err(
                        "CPMU event selector field is not source-qualified for this layout",
                    );
                }
                self.pmesr[usize::from(encoding == PMESR1)] = Some(value);
            }
            PMSR | PC_CAPTURE => return Err("write of a performance monitor status register"),
            _ => match self.layout.counters.iter().position(|&pmc| pmc == encoding) {
                Some(n) => self.counters[n] = value & self.layout.width.mask(),
                None => {
                    let index = EXTENSION
                        .iter()
                        .position(|&register| register == encoding)
                        .expect("owned");
                    if value != 0 {
                        return Err(
                            "PMCR2-4, OPMAT, OPMSK and S3_1_C15_C0_4/C1_4 settings are not modelled",
                        );
                    }
                    self.extension[index] = Some(0);
                }
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const KERNEL: Context = Context {
        el: 2,
        waiting: false,
    };
    const USER: Context = Context {
        el: 0,
        waiting: false,
    };
    /// XNU's `PMCR0_INIT` and `PMCR1_INIT` without `CPMU_AIC_PMI`.
    const PMCR0_INIT: u64 = 0x3 | 0x3000 | 0x400;
    const PMCR1_INIT: u64 = 0x30300;
    /// The M2's P-core clock and the 24 MHz system counter.
    const CLOCK: u64 = 3_504_000_000;
    const FREQUENCY: u64 = 24_000_000;

    fn configured(clock: u64) -> Pmu {
        configured_on(Chip::AppleM2, clock)
    }

    fn configured_on(chip: Chip, clock: u64) -> Pmu {
        let mut pmu = Pmu::for_chip(chip, clock, FREQUENCY).unwrap();
        // `_cpc_cpmu_pmcr01_write`: PMCR1, its copy, then PMCR0.
        pmu.write(PMCR1, PMCR1_INIT, 0, 0, KERNEL).unwrap();
        pmu.write(PMCR1_ALTERNATE, PMCR1_INIT, 0, 0, KERNEL)
            .unwrap();
        pmu.write(PMCR0, PMCR0_INIT, 0, 0, KERNEL).unwrap();
        pmu
    }

    #[test]
    fn xnus_boot_configuration_counts_cycles_and_instructions() {
        let mut pmu = configured(CLOCK);
        // 24 ticks of the 24 MHz counter are 1 us: 3504 P-core cycles.
        assert_eq!(pmu.read(PMC[0], 24, 100, KERNEL), Ok(3504));
        assert_eq!(pmu.read(PMC[1], 24, 100, KERNEL), Ok(100));
        assert_eq!(pmu.read(PMC[0], 25, 100, KERNEL), Ok(3650));
        assert_eq!(pmu.read(PMC[0], 26, 100, KERNEL), Ok(3796));
        // At 10 MHz a tick is 5/12 of a cycle; the fraction carries over.
        let mut slow = configured(10_000_000);
        let reads: Vec<u64> = (1..=3)
            .map(|tick| slow.read(PMC[0], tick, 0, KERNEL).unwrap())
            .collect();
        assert_eq!(reads, [0, 0, 1]);
        assert_eq!(slow.read(PMC[0], 24, 0, KERNEL), Ok(10));
        // Cycles stop while the PE waits; both count at EL0.
        pmu.sync(
            26,
            100,
            Context {
                el: 2,
                waiting: true,
            },
        );
        pmu.sync(1000, 100, USER);
        assert_eq!(pmu.read(PMC[0], 1024, 110, USER), Ok(3796 + 3504));
        assert_eq!(pmu.read(PMC[1], 1024, 110, USER), Ok(110));
        // PMCR1's filter: kernel-only counting skips EL0.
        pmu.write(PMCR1, 0x30000, 1024, 110, USER).unwrap_err();
        pmu.write(PMCR1_ALTERNATE, 0x30000, 1024, 110, USER)
            .unwrap();
        pmu.write(PMCR1, 0x30000, 1024, 110, USER).unwrap();
        assert_eq!(pmu.read(PMC[1], 2000, 150, USER), Ok(110));
        assert_eq!(pmu.read(PMSR, 2000, 150, USER), Ok(0));
        assert_eq!(pmu.read(PMCR0, 2000, 150, USER), Ok(PMCR0_INIT));
    }

    #[test]
    fn overflow_asserts_the_pmi_until_software_rewrites_the_counter() {
        let mut pmu = configured(CLOCK);
        // A sampling period of 1000 instructions.
        pmu.write(PMC[1], OVERFLOW - 1000, 0, 0, KERNEL).unwrap();
        assert!(!pmu.asserted(0, 999));
        assert!(pmu.asserted(0, 1000));
        assert_eq!(pmu.read(PMSR, 0, 1000, KERNEL), Ok(1 << 1));
        assert_eq!(
            pmu.read(PMCR0, 0, 1000, KERNEL),
            Ok(PMCR0_INIT | PMCR0_PMAI)
        );
        // `_cpc_cpmu_control_disable`, the counter rewrite, re-enable.
        pmu.write(PMCR0, 0, 0, 1000, KERNEL).unwrap();
        assert!(!pmu.asserted(0, 1000));
        pmu.write(PMC[1], 0, 0, 1000, KERNEL).unwrap();
        pmu.write(PMCR0, PMCR0_INIT, 0, 1000, KERNEL).unwrap();
        assert_eq!(pmu.read(PMSR, 0, 1000, KERNEL), Ok(0));
        assert!(!pmu.asserted(0, 1000));
        // A cycle period reaches its PMI at a system count.
        pmu.write(PMC[0], OVERFLOW - 3504, 100, 1000, KERNEL)
            .unwrap();
        assert_eq!(pmu.deadline(), Some(124));
        assert!(!pmu.asserted(123, 1000));
        assert!(pmu.asserted(124, 1000));
        // Waiting stops the cycles, so no deadline is pending.
        pmu.sync(
            110,
            1000,
            Context {
                el: 2,
                waiting: true,
            },
        );
        assert_eq!(pmu.deadline(), None);
    }

    #[test]
    fn qualified_counter_geometry_masks_writes_without_inheriting_future_layouts() {
        for (chip, mask, overflow) in [
            (Chip::AppleM1, (1u64 << 48) - 1, 1u64 << 47),
            (Chip::AppleM2, u64::MAX, 1u64 << 63),
        ] {
            let mut pmu = Pmu::for_chip(chip, CLOCK, FREQUENCY).unwrap();
            assert!(Pmu::on(chip));
            for (index, encoding) in PMC.into_iter().enumerate() {
                pmu.write(encoding, u64::MAX, 0, 0, KERNEL).unwrap();
                assert_eq!(pmu.read(encoding, 0, 0, KERNEL), Ok(mask));
                assert_eq!(pmu.read(PMSR, 0, 0, KERNEL), Ok((1 << (index + 1)) - 1));
            }
            for encoding in PMC {
                pmu.write(encoding, overflow - 1, 0, 0, KERNEL).unwrap();
            }
            assert_eq!(pmu.read(PMSR, 0, 0, KERNEL), Ok(0));
            // Counter storage does not qualify event counting or EL0 access.
            for value in [1 << 2, 1 << 32, 1 << 30] {
                assert!(pmu.write(PMCR0, value, 0, 0, KERNEL).is_err());
            }
        }
        assert!(!Pmu::owns(monitor(2, 8, 0)), "PMC8 is CRm9, not CRm8");
        for chip in [Chip::AppleM3, Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            assert!(Pmu::on(chip));
            assert!(Pmu::for_chip(chip, CLOCK, FREQUENCY).is_some());
        }
    }

    #[test]
    fn later_layouts_keep_exact_counter_aliases_selectors_and_status_positions() {
        for chip in Chip::ALL {
            let mut pmu = Pmu::for_chip(chip, CLOCK, FREQUENCY).unwrap();
            assert_eq!(
                pmu.counter_count(),
                if chip == Chip::AppleM6 { 15 } else { 10 }
            );
            assert_eq!(pmu.counter_encoding(pmu.counter_count()), None);
            for slot in 0..pmu.counter_count() {
                let encoding = pmu.counter_encoding(slot).unwrap();
                assert!(Pmu::owns_on(chip, encoding));
                if chip == Chip::AppleM6 {
                    assert_eq!(
                        encoding,
                        if slot < 10 {
                            monitor(2, slot as u8, 0)
                        } else {
                            Encoding::new(3, 0, 11, 13, (slot - 10) as u8)
                        }
                    );
                } else {
                    assert_eq!(Some(encoding), PMC.get(slot).copied());
                }
                // Each raw counter remains independent even where M6
                // moves an old encoding or adds another CRn bank.
                pmu.write(encoding, slot as u64 + 100, 0, 0, KERNEL)
                    .unwrap();
            }
            for slot in 0..pmu.counter_count() {
                let encoding = pmu.counter_encoding(slot).unwrap();
                assert_eq!(pmu.read(encoding, 0, 0, KERNEL), Ok(slot as u64 + 100));
            }
            let overflow = pmu.layout.width.overflow();
            for slot in 0..pmu.counter_count() {
                let encoding = pmu.counter_encoding(slot).unwrap();
                pmu.write(encoding, overflow, 0, 0, KERNEL).unwrap();
                assert_eq!(
                    pmu.read(PMSR, 0, 0, KERNEL),
                    Ok(1 << if slot < 10 { slot } else { slot + 22 })
                );
                pmu.write(encoding, 0, 0, 0, KERNEL).unwrap();
            }
            let selectors = match chip {
                Chip::AppleM1 | Chip::AppleM2 => u32::MAX as u64,
                Chip::AppleM3 | Chip::AppleM4 | Chip::AppleM5 => u64::MAX,
                Chip::AppleM6 => 0,
            };
            for encoding in [PMESR0, PMESR1] {
                pmu.write(encoding, selectors, 0, 0, KERNEL).unwrap();
                assert_eq!(pmu.read(encoding, 0, 0, KERNEL), Ok(selectors));
                if selectors != u64::MAX {
                    assert!(pmu.write(encoding, !selectors, 0, 0, KERNEL).is_err());
                    assert_eq!(pmu.read(encoding, 0, 0, KERNEL), Ok(selectors));
                }
            }
            assert!(Pmu::for_chip(chip, 0, FREQUENCY).is_none());
            assert!(Pmu::for_chip(chip, CLOCK, 0).is_none());
        }
        assert!(!Pmu::owns_on(Chip::AppleM5, monitor(2, 8, 0)));
        assert!(!Pmu::owns_on(Chip::AppleM6, monitor(2, 10, 0)));
        let mut m6 = Pmu::for_chip(Chip::AppleM6, CLOCK, FREQUENCY).unwrap();
        assert!(m6.write(PMC[9], 123, 0, 0, KERNEL).is_err());
        assert!(m6.read(PMC[9], 0, 0, KERNEL).is_err());
        assert_eq!(m6.read(monitor(2, 9, 0), 0, 0, KERNEL), Ok(0));
        for &encoding in m6.layout.unqualified_controls {
            assert!(Pmu::owns_on(Chip::AppleM6, encoding));
            assert!(m6.read(encoding, 0, 0, KERNEL).is_err());
            for value in [0, 1, u64::MAX] {
                assert!(m6.write(encoding, value, 0, 0, KERNEL).is_err());
            }
        }
    }

    #[test]
    fn all_chip_fixed_events_keep_their_counter_width_and_interrupt_contract() {
        for chip in Chip::ALL {
            let mut pmu = configured_on(chip, 10_000_000);
            let overflow = if chip == Chip::AppleM1 {
                1u64 << 47
            } else {
                1u64 << 63
            };
            pmu.write(PMC[0], overflow - 1, 0, 0, KERNEL).unwrap();
            pmu.write(PMC[1], overflow - 2, 0, 0, KERNEL).unwrap();
            assert_eq!(pmu.deadline(), Some(3));
            assert!(!pmu.asserted(2, 1));
            assert!(pmu.asserted(2, 2));
            assert_eq!(pmu.read(PMSR, 2, 2, KERNEL), Ok(2));
            assert_eq!(pmu.read(PMSR, 3, 2, KERNEL), Ok(3));
            pmu.write(PMC[0], 0, 3, 2, KERNEL).unwrap();
            pmu.write(PMC[1], 0, 3, 2, KERNEL).unwrap();
            assert!(!pmu.asserted(3, 2));
            for value in [1 << 2, 1 << 32, 2 << 8, 1 << 24, 1 << 30] {
                assert!(pmu.write(PMCR0, value, 3, 2, KERNEL).is_err());
            }
            assert_eq!(pmu.read(PMCR0, 3, 2, KERNEL), Ok(PMCR0_INIT));
        }
    }

    #[test]
    fn m1_fixed_counts_wrap_at_48_bits_and_signal_at_bit47() {
        const M1_OVERFLOW: u64 = 1 << 47;
        const M1_MASK: u64 = (1 << 48) - 1;
        let mut pmu = configured_on(Chip::AppleM1, FREQUENCY);
        pmu.write(PMC[0], M1_OVERFLOW - 3, 0, 0, KERNEL).unwrap();
        pmu.write(PMC[1], M1_OVERFLOW - 2, 0, 0, KERNEL).unwrap();
        assert_eq!(pmu.deadline(), Some(3));
        assert!(!pmu.asserted(2, 1));
        assert!(pmu.asserted(2, 2));
        assert_eq!(pmu.read(PMSR, 2, 2, KERNEL), Ok(1 << 1));
        assert_eq!(pmu.read(PMC[1], 2, 2, KERNEL), Ok(M1_OVERFLOW));
        assert_eq!(pmu.read(PMSR, 3, 2, KERNEL), Ok(0b11));
        // Rewriting the counters clears their overflow indications.
        pmu.write(PMC[0], M1_MASK - 1, 3, 2, KERNEL).unwrap();
        pmu.write(PMC[1], M1_MASK - 1, 3, 2, KERNEL).unwrap();
        // Predictive FIQ must agree with an eventual synchronized read
        // even when a large elapsed interval crosses the full width.
        assert!(!pmu.asserted(6, 5));
        assert_eq!(pmu.read(PMC[0], 6, 5, KERNEL), Ok(1));
        assert_eq!(pmu.read(PMC[1], 6, 5, KERNEL), Ok(1));
        assert_eq!(pmu.read(PMSR, 6, 5, KERNEL), Ok(0));
        assert!(!pmu.asserted(6, 5));
        // On M2, crossing bit47 is ordinary counting, not overflow.
        let mut m2 = configured_on(Chip::AppleM2, FREQUENCY);
        m2.write(PMC[1], M1_OVERFLOW - 2, 0, 0, KERNEL).unwrap();
        assert!(!m2.asserted(0, 2));
        assert_eq!(m2.read(PMSR, 0, 2, KERNEL), Ok(0));
    }

    #[test]
    fn m1_cycle_deadlines_keep_fractions_filters_and_wait_state() {
        const M1_OVERFLOW: u64 = 1 << 47;
        let mut pmu = configured_on(Chip::AppleM1, 10_000_000);
        pmu.write(PMC[0], M1_OVERFLOW - 1, 0, 0, KERNEL).unwrap();
        // 5/12 cycle per tick: one cycle needs three ticks, preserving
        // fractional cycles across reads and wait/context transitions.
        assert_eq!(pmu.deadline(), Some(3));
        assert_eq!(pmu.read(PMC[0], 2, 0, KERNEL), Ok(M1_OVERFLOW - 1));
        assert_eq!(pmu.deadline(), Some(3));
        let waiting = Context {
            el: 2,
            waiting: true,
        };
        pmu.sync(2, 0, waiting);
        assert_eq!(pmu.deadline(), None);
        pmu.sync(100, 0, USER);
        assert_eq!(pmu.deadline(), Some(101));
        assert_eq!(pmu.read(PMC[0], 101, 0, USER), Ok(M1_OVERFLOW));
        assert_eq!(pmu.read(PMCR0, 101, 0, USER), Ok(PMCR0_INIT | PMCR0_PMAI));
        // Disable user counting without changing the fixed events.
        pmu.write(PMCR1_ALTERNATE, 0x30000, 101, 0, USER).unwrap();
        pmu.write(PMCR1, 0x30000, 101, 0, USER).unwrap();
        assert_eq!(pmu.read(PMC[0], 200, 100, USER), Ok(M1_OVERFLOW));
        assert_eq!(pmu.read(PMC[1], 200, 100, USER), Ok(0));
        pmu.sync(200, 100, KERNEL);
        assert_eq!(pmu.read(PMC[1], 200, 103, KERNEL), Ok(3));
    }

    #[test]
    fn undescribed_settings_and_unwritten_controls_refuse() {
        let mut pmu = Pmu::new(CLOCK, FREQUENCY);
        assert!(pmu.read(PMESR0, 0, 0, KERNEL).is_err());
        assert!(pmu.read(PMCR2, 0, 0, KERNEL).is_err());
        assert!(pmu.write(PMCR0, 1, 0, 0, KERNEL).is_err(), "copy unwritten");
        pmu.write(PMCR1_ALTERNATE, 0, 0, 0, KERNEL).unwrap();
        for value in [1 << 2, 1 << 32, 2 << 8, 1 << 24, 1 << 30, 1 << 20] {
            assert!(pmu.write(PMCR0, value, 0, 0, KERNEL).is_err(), "{value:#x}");
        }
        assert!(pmu.write(PMCR1, 1, 0, 0, KERNEL).is_err());
        assert!(pmu.write(OPMSK0, 1, 0, 0, KERNEL).is_err());
        pmu.write(OPMSK0, 0, 0, 0, KERNEL).unwrap();
        assert_eq!(pmu.read(OPMSK0, 0, 0, KERNEL), Ok(0));
        assert!(pmu.read(PMCR_C1_4, 0, 0, KERNEL).is_err());
        assert!(pmu.write(PMCR_C0_4, 1, 0, 0, KERNEL).is_err());
        pmu.write(PMCR_C1_4, 0, 0, 0, KERNEL).unwrap();
        assert_eq!(pmu.read(PMCR_C1_4, 0, 0, KERNEL), Ok(0));
        pmu.write(PMESR1, 0x8c, 0, 0, KERNEL).unwrap();
        assert_eq!(pmu.read(PMESR1, 0, 0, KERNEL), Ok(0x8c));
        assert!(pmu.write(PMSR, 0, 0, 0, KERNEL).is_err());
        assert!(pmu.read(PC_CAPTURE, 0, 0, KERNEL).is_err());
        // An event counter stores its value; its overflow still reports.
        pmu.write(PMC[9], OVERFLOW, 0, 0, KERNEL).unwrap();
        assert_eq!(pmu.read(PMSR, 0, 0, KERNEL), Ok(1 << 9));
        assert!(Pmu::owns(PMC[8]) && !Pmu::owns(monitor(1, 0, 3)));
    }
}
