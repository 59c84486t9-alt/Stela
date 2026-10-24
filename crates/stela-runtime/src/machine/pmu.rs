//! Apple's per-PE CPMU fixed cycle and retired-instruction counters, with
//! separately qualified M1–M6 layouts (`layout`). XNU xnu-12377.121.6 H13
//! supplies M1's 48-bit width, H14–H17 supply M2–M5's 64-bit width, and
//! original 26A434 mac18g supplies M6's distinct 15-counter mapping.
//! See `docs/research/core-pmu.md` for source hashes and qualification limits.
//!
//! - PMC0 counts cycles and PMC1 retired instructions. M1/M2 also count
//!   source-qualified programmable events (`events`): NONE and active
//!   cycles on PMC2–9, retired instructions on PMC7. Other enabled pairs
//!   refuse; raw counter writes are independent of event selection.
//!   Counters wrap at their configured width, with bit47 (M1) or bit63
//!   (M2–M6) as overflow; PMSR uses the selected layout's slot mapping.
//! - PMCR0 enables counting (bits 0-7, 32-33 for PMC8 and PMC9), selects the
//!   PMI (bits 8-10, 4 for FIQ), reports it (bit 11, PMAI), enables each
//!   counter's PMI (bits 12-19, 44-45), PC capture for PMC5-7 (bits 24-26)
//!   and EL0 access (bit 30).
//! - PMCR1 filters counting by mode: bits 8-15 and 40-41 at EL0, bits 16-23
//!   and 48-49 in the kernel. XNU, which runs at EL2 on the M2, calls bits
//!   16 and 17 the EL2 enables, so in the EL2&0 host they count at EL2
//!   (inference). Which PMCR1 applies follows where the PE runs
//!   ([`Filter`]): `S3_1_C15_C7_2` is PMCR1_EL12 (Linux
//!   `arch/arm64/include/asm/apple_m1_pmu.h`), the EL1&0 regime's copy, which
//!   XNU writes with PMCR1's value before PMCR0 under `CONFIG_EXCLAVES ||
//!   HYPERVISOR` (`osfmk/arm64/cpc_arm64.c`) and which, like the VHE `_EL12`
//!   registers, is UNDEFINED below EL2 and is what PMCR1 reaches in the EL1&0
//!   regime (inference from the name); a guarded
//!   level counts by PMCR1_GL1 (`S3_1_C15_C8_2`, m1n1 `apple_regs.json`),
//!   whose kernel field applies, which SPTM 26A434 writes once per PE at
//!   boot with 0x30300 or a full enable pattern and the kernel saves and
//!   restores around a VM (its storage is `machine::impdef`'s entry, which
//!   `Pmu::set_guarded_filter` mirrors).
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
//! Unqualified programmable events, PC capture, EL0 access, other PMI modes,
//! instruction matching (OPMAT, OPMSK) and the PMCR2-4 controls are not
//! modelled: a write that enables one stops. PMESR0 and PMESR1 store
//! selectors within the layout's field masks. An enabled event/slot must
//! have qualified semantics; unsupported reconfiguration refuses atomically. M6's new controls refuse every access until their effects
//! are independently qualified.
use super::Chip;

mod events;
mod layout;
use events::Event;
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
/// The two controls 26A434 XNU's kpc saves after OPMSK1 (`kpc_get_config`,
/// 0xfffffe000bd41050) and restores with the others (0xfffffe000bd8db14):
/// XNU's `kpc_get_rawpmu_config` saves PM_MEMFLT_CTL23_EL1 and
/// PM_MEMFLT_CTL45_EL1 there, in that order (`xnu-12377.121.6`
/// `osfmk/arm64/kpc.c`), by symbolic name, so the encodings' match is an
/// inference. They configure nothing at 0.
pub const PM_MEMFLT_CTL23: Encoding = monitor(1, 0, 4);
pub const PM_MEMFLT_CTL45: Encoding = monitor(1, 1, 4);
/// The M5 kpc's tenth raw configuration register: its `kpc_get_config`
/// saves it after PM_MEMFLT_CTL45 and its restore writes it back
/// (kernelcache.release.mac17g 0xfffffe000be64104, 0xfffffe000beb56b0), a
/// slot public XNU does not have. No public name; it configures nothing at
/// 0 (inference, as for the others). The M6 layout leaves it unqualified.
pub const KPC_C5_1: Encoding = monitor(1, 5, 1);
/// PMCR1's EL1&0 copy ([`Filter::Guest`]).
pub const PMCR1_EL12: Encoding = monitor(1, 7, 2);
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
    PMCR2,
    PMCR3,
    PMCR4,
    OPMAT0,
    OPMAT1,
    OPMSK0,
    OPMSK1,
    PM_MEMFLT_CTL23,
    PM_MEMFLT_CTL45,
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

/// Where the PE runs, for counting: its EL, the PMCR1 that filters there
/// and whether it waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub el: u8,
    pub filter: Filter,
    pub waiting: bool,
}

/// Which PMCR1 filters counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// PMCR1, in the EL2&0 regime.
    Host,
    /// PMCR1_EL12, in the EL1&0 regime.
    Guest,
    /// PMCR1_GL1's kernel field, at a guarded level.
    Guarded,
}

/// The register an access to `encoding` reaches: PMCR1 in the EL1&0
/// regime is that regime's copy, PMCR1_EL12, as the VHE `_EL1` encodings
/// reach the EL1 registers below EL2 (inference from the name).
fn regime_copy(encoding: Encoding, context: Context) -> Encoding {
    if encoding == PMCR1 && context.filter == Filter::Guest {
        PMCR1_EL12
    } else {
        encoding
    }
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
    pmcr1_el12: u64,
    /// PMCR1_GL1, mirrored from its `machine::impdef` entry.
    pmcr1_gl1: u64,
    pmesr: [Option<u64>; 2],
    extension: [Option<u64>; EXTENSIONS],
    /// [`KPC_C5_1`], on a layout that has it.
    kpc_c5_1: Option<u64>,
    /// The counts as of `synced_count` and `synced_retired`.
    counters: [u64; layout::MAX_COUNTERS],
    synced_count: u64,
    synced_retired: u64,
    /// Each cycle counter's fraction, in 1/`frequency` cycle units.
    remainder: [u64; layout::MAX_COUNTERS],
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
            pmcr1_el12: 0,
            pmcr1_gl1: 0,
            pmesr: [None; 2],
            extension: [None; EXTENSIONS],
            kpc_c5_1: None,
            counters: [0; layout::MAX_COUNTERS],
            synced_count: 0,
            synced_retired: 0,
            remainder: [0; layout::MAX_COUNTERS],
            context: Context {
                el: 2,
                filter: Filter::Host,
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
            || layout.kpc_c5_1 && encoding == KPC_C5_1
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
            PMCR0 | PMCR1 | PMESR0 | PMESR1 | PMCR1_EL12 | PMSR | PC_CAPTURE
        ) || EXTENSION.contains(&encoding)
    }

    fn check_access(&self, encoding: Encoding) -> Result<(), &'static str> {
        if self.layout.unqualified_controls.contains(&encoding) {
            Err("M6 CPMU control effects are not source-qualified")
        } else if Self::common(encoding)
            || self.layout.counters.contains(&encoding)
            || self.layout.kpc_c5_1 && encoding == KPC_C5_1
        {
            Ok(())
        } else {
            Err("register is not allocated in the selected CPMU layout")
        }
    }

    fn event_with(&self, n: usize, selectors: &[Option<u64>; 2]) -> Option<Event> {
        match n {
            CYCLES => Some(Event::Cycles),
            INSTRUCTIONS => Some(Event::Instructions),
            _ => self.layout.events.programmable(n, selectors),
        }
    }

    fn event(&self, n: usize) -> Option<Event> {
        self.event_with(n, &self.pmesr)
    }

    fn validate_events(
        &self,
        control: u64,
        selectors: &[Option<u64>; 2],
    ) -> Result<(), &'static str> {
        for n in 2..COUNTERS {
            if control & counter_bit(0, 32, n) != 0 && self.event_with(n, selectors).is_none() {
                return Err("programmable CPMU event/slot pair is not source-qualified");
            }
        }
        Ok(())
    }

    /// Whether counter `n` counts in `context`.
    fn counts(&self, n: usize, context: Context) -> bool {
        let (pmcr1, el) = match context.filter {
            Filter::Host => (self.pmcr1, context.el),
            Filter::Guest => (self.pmcr1_el12, context.el),
            Filter::Guarded => (self.pmcr1_gl1, 1),
        };
        let filter = if el == 0 {
            counter_bit(8, 40, n)
        } else {
            counter_bit(16, 48, n)
        };
        self.pmcr0 & counter_bit(0, 32, n) != 0
            && pmcr1 & filter != 0
            && !(self.event(n) == Some(Event::Cycles) && context.waiting)
    }

    /// Whether an enabled event depends on the core clock.
    pub fn timed(&self) -> bool {
        (0..COUNTERS).any(|n| {
            self.pmcr0 & counter_bit(0, 32, n) != 0 && self.event(n) == Some(Event::Cycles)
        })
    }

    /// Count up to the system count `now` and `retired` instructions in the
    /// context since the last synchronization.
    fn advance(&mut self, now: u64, retired: u64) {
        let ticks = now.saturating_sub(self.synced_count);
        let instructions = retired.wrapping_sub(self.synced_retired);
        for n in 0..COUNTERS {
            if !self.counts(n, self.context) {
                continue;
            }
            let increment = match self.event(n) {
                Some(Event::Cycles) => {
                    let scaled =
                        u128::from(ticks) * u128::from(self.clock) + u128::from(self.remainder[n]);
                    let frequency = u128::from(self.frequency);
                    self.remainder[n] = (scaled % frequency) as u64;
                    (scaled / frequency) as u64
                }
                Some(Event::Instructions) => instructions,
                Some(Event::None) | None => 0,
            };
            self.counters[n] = self.counters[n].wrapping_add(increment) & self.layout.width.mask();
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
        self.cycle_deadline = None;
        self.instruction_deadline = None;
        for n in 0..COUNTERS {
            if !armed(n) || !self.counts(n, self.context) {
                continue;
            }
            let needed = self.layout.width.overflow().wrapping_sub(self.counters[n])
                & self.layout.width.mask();
            match self.event(n) {
                Some(Event::Cycles) => {
                    let scaled = (u128::from(needed) * u128::from(self.frequency))
                        .saturating_sub(u128::from(self.remainder[n]));
                    let ticks = scaled.div_ceil(u128::from(self.clock));
                    let deadline = u64::try_from(ticks)
                        .ok()
                        .and_then(|ticks| self.synced_count.checked_add(ticks));
                    if let Some(deadline) = deadline {
                        self.cycle_deadline = Some(
                            self.cycle_deadline
                                .map_or(deadline, |old| old.min(deadline)),
                        );
                    }
                }
                Some(Event::Instructions) => {
                    if let Some(deadline) = self.synced_retired.checked_add(needed) {
                        self.instruction_deadline = Some(
                            self.instruction_deadline
                                .map_or(deadline, |old| old.min(deadline)),
                        );
                    }
                }
                Some(Event::None) | None => {}
            }
        }
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
                match self.event(n) {
                    Some(Event::Cycles) => {
                        let ticks = now.saturating_sub(self.synced_count);
                        ((u128::from(ticks) * u128::from(self.clock)
                            + u128::from(self.remainder[n]))
                            / u128::from(self.frequency)) as u64
                    }
                    Some(Event::Instructions) => retired.wrapping_sub(self.synced_retired),
                    Some(Event::None) | None => 0,
                }
            } else {
                0
            };
            self.counters[n].wrapping_add(increment) & self.layout.width.overflow() != 0
        })
    }

    /// Instruction PMI needs a scheduler observation after each native body.
    /// A disabled/reset monitor imposes no instruction deadline.
    pub(crate) fn has_instruction_deadline(&self) -> bool {
        self.asserted || self.instruction_deadline.is_some()
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

    /// PMCR1_GL1 took `value` at system count `now` with `retired`
    /// instructions retired.
    pub fn set_guarded_filter(&mut self, value: u64, now: u64, retired: u64, context: Context) {
        self.advance(now, retired);
        self.pmcr1_gl1 = value;
        self.context = context;
        self.update();
    }

    pub fn read(
        &mut self,
        encoding: Encoding,
        now: u64,
        retired: u64,
        context: Context,
    ) -> Result<u64, &'static str> {
        self.check_access(encoding)?;
        let encoding = regime_copy(encoding, context);
        self.sync(now, retired, context);
        let stored = |value: Option<u64>| {
            value.ok_or("read of a performance monitor control before its first write")
        };
        Ok(match encoding {
            PMCR0 => self.pmcr0 | if self.asserted { PMCR0_PMAI } else { 0 },
            PMCR1 => self.pmcr1,
            PMCR1_EL12 => self.pmcr1_el12,
            PMESR0 => stored(self.pmesr[0])?,
            PMESR1 => stored(self.pmesr[1])?,
            PMSR => (0..self.counter_count())
                .filter(|&n| self.counters[n] & self.layout.width.overflow() != 0)
                .fold(0, |status, n| status | self.layout.status_bit(n)),
            PC_CAPTURE => return Err("PMI PC capture is not modelled"),
            KPC_C5_1 => stored(self.kpc_c5_1)?,
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
        let written = self.store(regime_copy(encoding, context), value);
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
                self.validate_events(value, &self.pmesr)?;
                if !matches!(value & PMCR0_INTGEN, 0 | PMCR0_INTGEN_FIQ) {
                    return Err("PMCR0 PMI generation other than FIQ");
                }
                if value & PMCR0_PC_CAPTURE != 0 {
                    return Err("PMCR0 PMI PC capture is not modelled");
                }
                if value & PMCR0_USER_ACCESS != 0 {
                    return Err("PMCR0 EL0 access to the monitor is not modelled");
                }
                // PMAI reports the PMI; writing it changes nothing.
                self.pmcr0 = value & !PMCR0_PMAI;
            }
            PMCR1 | PMCR1_EL12 => {
                if value & !PMCR1_KNOWN != 0 {
                    return Err("PMCR1 bit without public description");
                }
                if encoding == PMCR1 {
                    self.pmcr1 = value;
                } else {
                    self.pmcr1_el12 = value;
                }
            }
            PMESR0 | PMESR1 => {
                if value & !self.layout.selectors != 0 {
                    return Err(
                        "CPMU event selector field is not source-qualified for this layout",
                    );
                }
                let mut selectors = self.pmesr;
                selectors[usize::from(encoding == PMESR1)] = Some(value);
                self.validate_events(self.pmcr0, &selectors)?;
                self.pmesr = selectors;
            }
            PMSR | PC_CAPTURE => return Err("write of a performance monitor status register"),
            KPC_C5_1 if value != 0 => {
                return Err("M5 kpc configuration S3_1_C15_C5_1 is not modelled");
            }
            KPC_C5_1 => self.kpc_c5_1 = Some(0),
            _ => match self.layout.counters.iter().position(|&pmc| pmc == encoding) {
                Some(n) => self.counters[n] = value & self.layout.width.mask(),
                None => {
                    let index = EXTENSION
                        .iter()
                        .position(|&register| register == encoding)
                        .expect("owned");
                    if value != 0 {
                        return Err(
                            "PMCR2-4, OPMAT, OPMSK and PM_MEMFLT_CTL settings are not modelled",
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
        filter: Filter::Host,
        waiting: false,
    };
    const USER: Context = Context { el: 0, ..KERNEL };
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
        pmu.write(PMCR1_EL12, PMCR1_INIT, 0, 0, KERNEL).unwrap();
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
                filter: Filter::Host,
                waiting: true,
            },
        );
        pmu.sync(1000, 100, USER);
        assert_eq!(pmu.read(PMC[0], 1024, 110, USER), Ok(3796 + 3504));
        assert_eq!(pmu.read(PMC[1], 1024, 110, USER), Ok(110));
        // PMCR1's filter: kernel-only counting skips EL0.
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
                filter: Filter::Host,
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
            filter: Filter::Host,
            waiting: true,
        };
        pmu.sync(2, 0, waiting);
        assert_eq!(pmu.deadline(), None);
        pmu.sync(100, 0, USER);
        assert_eq!(pmu.deadline(), Some(101));
        assert_eq!(pmu.read(PMC[0], 101, 0, USER), Ok(M1_OVERFLOW));
        assert_eq!(pmu.read(PMCR0, 101, 0, USER), Ok(PMCR0_INIT | PMCR0_PMAI));
        // Disable user counting without changing the fixed events.
        pmu.write(PMCR1_EL12, 0x30000, 101, 0, USER).unwrap();
        pmu.write(PMCR1, 0x30000, 101, 0, USER).unwrap();
        assert_eq!(pmu.read(PMC[0], 200, 100, USER), Ok(M1_OVERFLOW));
        assert_eq!(pmu.read(PMC[1], 200, 100, USER), Ok(0));
        pmu.sync(200, 100, KERNEL);
        assert_eq!(pmu.read(PMC[1], 200, 103, KERNEL), Ok(3));
    }

    fn programmed(chip: Chip, clock: u64, selectors: [u64; 2], control: u64, filter: u64) -> Pmu {
        let mut pmu = Pmu::for_chip(chip, clock, FREQUENCY).unwrap();
        pmu.write(PMCR1, filter, 0, 0, KERNEL).unwrap();
        pmu.write(PMCR1_EL12, filter, 0, 0, KERNEL).unwrap();
        pmu.write(PMESR0, selectors[0], 0, 0, KERNEL).unwrap();
        pmu.write(PMESR1, selectors[1], 0, 0, KERNEL).unwrap();
        pmu.write(PMCR0, control, 0, 0, KERNEL).unwrap();
        pmu
    }

    #[test]
    fn programmed_cycles_cover_every_qualified_slot_and_none_is_explicit() {
        // Original counter fields: all ten counts, EL0 and kernel filters.
        const COUNTS: u64 = 0xff | 3 << 32;
        const FILTERS: u64 = 0xffff00 | 3 << 40 | 3 << 48;
        for chip in [Chip::AppleM1, Chip::AppleM2] {
            let mut pmu = programmed(chip, 10_000_000, [0x02020202; 2], COUNTS, FILTERS);
            assert!(pmu.timed());
            for (slot, encoding) in PMC.iter().copied().enumerate() {
                assert_eq!(
                    pmu.read(encoding, 24, 7, KERNEL),
                    Ok(if slot == 1 { 7 } else { 10 })
                );
            }
            // Only PMC2 changes to the explicitly named NONE event.
            pmu.write(PMESR0, 0x02020200, 24, 7, KERNEL).unwrap();
            assert_eq!(pmu.read(PMC[2], 48, 10, KERNEL), Ok(10));
            assert_eq!(pmu.read(PMC[3], 48, 10, KERNEL), Ok(20));
            assert_eq!(pmu.read(PMC[8], 48, 10, KERNEL), Ok(20));
            assert_eq!(pmu.read(PMC[9], 48, 10, KERNEL), Ok(20));
            pmu.write(PMESR0, 0, 48, 10, KERNEL).unwrap();
            pmu.write(PMESR1, 0, 48, 10, KERNEL).unwrap();
            pmu.write(PMCR0, COUNTS & !3, 48, 10, KERNEL).unwrap();
            assert!(!pmu.timed(), "NONE is not a clock event");
            let before: Vec<_> = PMC
                .iter()
                .map(|&e| pmu.read(e, 48, 10, KERNEL).unwrap())
                .collect();
            for (slot, encoding) in PMC.iter().copied().enumerate() {
                assert_eq!(pmu.read(encoding, 240, 100, KERNEL), Ok(before[slot]));
            }
        }
    }

    #[test]
    fn programmed_instruction_event_counts_only_on_its_source_affinity() {
        for chip in [Chip::AppleM1, Chip::AppleM2] {
            let overflow = if chip == Chip::AppleM1 {
                1 << 47
            } else {
                1 << 63
            };
            // PMC7's selector is PMESR1[15:8], its EL0 filter bit15,
            // counting bit7 and PMI bit19; PMC0/1 remain disabled.
            let mut pmu = programmed(chip, CLOCK, [0, 0x8c00], 0x80 | 1 << 19 | 0x400, 1 << 15);
            assert!(!pmu.timed());
            pmu.sync(0, 0, USER);
            assert_eq!(pmu.read(PMC[7], 24, 12, USER), Ok(12));
            assert_eq!(pmu.read(PMC[1], 24, 12, USER), Ok(0));
            pmu.sync(24, 12, KERNEL);
            assert_eq!(pmu.read(PMC[7], 48, 20, KERNEL), Ok(12));
            pmu.write(PMC[7], overflow - 2, 48, 20, KERNEL).unwrap();
            pmu.sync(48, 20, USER);
            assert_eq!(pmu.deadline(), None);
            assert!(!pmu.asserted(48, 21));
            assert!(pmu.asserted(48, 22));
            assert_eq!(pmu.read(PMSR, 48, 22, USER), Ok(1 << 7));
            assert_eq!(pmu.read(PMC[7], 48, 22, USER), Ok(overflow));
        }
    }

    #[test]
    fn programmed_cycle_fractions_and_deadlines_follow_each_slots_mode() {
        for chip in [Chip::AppleM1, Chip::AppleM2] {
            let overflow = if chip == Chip::AppleM1 {
                1 << 47
            } else {
                1 << 63
            };
            let mut pmu = programmed(
                chip,
                10_000_000,
                [2, 2 << 16],
                4 | 1 << 32 | 1 << 14 | 1 << 44 | 0x400,
                1 << 10 | 1 << 48,
            );
            pmu.write(PMC[2], overflow - 1, 0, 0, KERNEL).unwrap();
            pmu.write(PMC[8], overflow - 2, 0, 0, KERNEL).unwrap();
            assert_eq!(pmu.deadline(), Some(5));
            pmu.sync(2, 0, USER);
            assert_eq!(pmu.deadline(), Some(5));
            assert_eq!(pmu.read(PMSR, 4, 0, USER), Ok(0));
            assert!(!pmu.asserted(4, 0));
            assert!(pmu.asserted(5, 0));
            pmu.sync(5, 0, KERNEL);
            assert_eq!(pmu.read(PMC[2], 5, 0, KERNEL), Ok(overflow));
            assert_eq!(pmu.read(PMC[8], 5, 0, KERNEL), Ok(overflow - 2));
            pmu.write(PMC[2], 0, 5, 0, KERNEL).unwrap();
            assert_eq!(pmu.deadline(), Some(8));
            assert!(!pmu.asserted(7, 0));
            assert!(pmu.asserted(8, 0));
            assert_eq!(pmu.read(PMC[8], 8, 0, KERNEL), Ok(overflow));
            assert_eq!(pmu.read(PMC[2], 8, 0, KERNEL), Ok(0));
            // Every cycle event stops in a clock-gated wait.
            pmu.write(PMC[8], 0, 8, 0, KERNEL).unwrap();
            pmu.sync(
                8,
                0,
                Context {
                    el: 2,
                    filter: Filter::Host,
                    waiting: true,
                },
            );
            assert_eq!(pmu.deadline(), None);
            assert_eq!(pmu.read(PMC[8], 100, 0, KERNEL), Ok(0));
        }
    }

    #[test]
    fn programmed_cycle_pmis_cover_all_enable_fields_and_clear_after_full_wrap() {
        // Slot, count-enable bit, kernel-filter bit, PMI-enable bit. High
        // fields for PMC8/9 are explicit source coordinates, not loop-derived.
        let slots = [
            (2, 4, 1 << 18, 1 << 14),
            (3, 8, 1 << 19, 1 << 15),
            (4, 16, 1 << 20, 1 << 16),
            (5, 32, 1 << 21, 1 << 17),
            (6, 64, 1 << 22, 1 << 18),
            (7, 128, 1 << 23, 1 << 19),
            (8, 1 << 32, 1 << 48, 1 << 44),
            (9, 1 << 33, 1 << 49, 1 << 45),
        ];
        for chip in [Chip::AppleM1, Chip::AppleM2] {
            let overflow = if chip == Chip::AppleM1 {
                1 << 47
            } else {
                1 << 63
            };
            let mask = if chip == Chip::AppleM1 {
                (1 << 48) - 1
            } else {
                u64::MAX
            };
            for (slot, count, filter, pmi) in slots {
                let mut pmu = programmed(
                    chip,
                    10_000_000,
                    [0x02020202; 2],
                    count | pmi | 0x400,
                    filter,
                );
                pmu.write(PMC[slot], overflow - 1, 0, 0, KERNEL).unwrap();
                assert_eq!(pmu.deadline(), Some(3));
                assert!(!pmu.asserted(2, 0));
                assert!(pmu.asserted(3, 0));
                assert_eq!(pmu.read(PMSR, 3, 0, KERNEL), Ok(1 << slot));
                assert_eq!(pmu.read(PMC[slot], 3, 0, KERNEL), Ok(overflow));
                pmu.write(PMC[slot], mask, 3, 0, KERNEL).unwrap();
                assert!(!pmu.asserted(6, 0));
                assert_eq!(pmu.read(PMC[slot], 6, 0, KERNEL), Ok(0));
                assert_eq!(pmu.read(PMSR, 6, 0, KERNEL), Ok(0));
            }
        }
    }

    #[test]
    fn enabled_selector_and_affinity_refusals_are_atomic_and_never_inherit_generations() {
        for chip in [Chip::AppleM1, Chip::AppleM2] {
            let mut pmu = programmed(chip, CLOCK, [2, 0], 4, 1 << 18);
            // Unsupported INST_ALL on PMC2 cannot replace active cycles.
            assert!(pmu.write(PMESR0, 0x8c, 0, 0, KERNEL).is_err());
            assert_eq!(pmu.read(PMESR0, 0, 0, KERNEL), Ok(2));
            // Disabled fields may be staged, but enabling an unknown event
            // refuses without changing the previous count enables.
            pmu.write(PMESR0, 0xff02, 0, 0, KERNEL).unwrap();
            assert!(pmu.write(PMCR0, 12, 0, 0, KERNEL).is_err());
            assert_eq!(pmu.read(PMCR0, 0, 0, KERNEL), Ok(4));
            assert_eq!(pmu.read(PMESR0, 0, 0, KERNEL), Ok(0xff02));
        }
        for chip in [Chip::AppleM3, Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            let selector = match chip {
                Chip::AppleM3 => 2,
                Chip::AppleM4 | Chip::AppleM5 => 0x11,
                _ => 0,
            };
            let mut pmu = Pmu::for_chip(chip, CLOCK, FREQUENCY).unwrap();
            pmu.write(PMESR0, selector, 0, 0, KERNEL).unwrap();
            pmu.write(PMCR1, 1 << 18, 0, 0, KERNEL).unwrap();
            pmu.write(PMCR1_EL12, 1 << 18, 0, 0, KERNEL).unwrap();
            assert!(pmu.write(PMCR0, 4, 0, 0, KERNEL).is_err());
            assert_eq!(pmu.read(PMCR0, 0, 0, KERNEL), Ok(0));
        }
    }

    /// PMCR1 filters the EL2&0 host, PMCR1_EL12 the EL1&0 regime, which
    /// reaches it as PMCR1, and PMCR1_GL1's kernel field a guarded level.
    #[test]
    fn each_regime_and_the_guarded_level_count_by_their_own_pmcr1() {
        let mut pmu = Pmu::for_chip(Chip::AppleM2, CLOCK, FREQUENCY).unwrap();
        let guest = Context {
            el: 1,
            filter: Filter::Guest,
            ..KERNEL
        };
        let guarded = Context {
            filter: Filter::Guarded,
            ..KERNEL
        };
        // Each step counts the instructions retired since the last under
        // the context it leaves. With PMCR1 alone set, only the host counts.
        pmu.write(PMCR1, 1 << 17, 0, 0, KERNEL).unwrap();
        pmu.write(PMCR0, 0b10, 0, 0, KERNEL).unwrap();
        pmu.sync(0, 10, guest);
        pmu.sync(0, 30, guarded);
        assert_eq!(pmu.read(PMC[1], 0, 40, KERNEL), Ok(10));
        // PMCR1_EL12 and PMCR1_GL1 enable the guest and the guarded level.
        pmu.write(PMCR1_EL12, 1 << 17, 0, 40, guest).unwrap();
        pmu.set_guarded_filter(1 << 17, 0, 40, guarded);
        assert_eq!(pmu.read(PMC[1], 0, 45, guest), Ok(15));
        assert_eq!(pmu.read(PMC[1], 0, 52, KERNEL), Ok(22));
        assert_eq!(pmu.read(PMCR1, 0, 52, guest), Ok(1 << 17));
        pmu.write(PMCR1, 1 << 16, 0, 52, guest).unwrap();
        assert_eq!(pmu.read(PMCR1_EL12, 0, 52, KERNEL), Ok(1 << 16));
        assert_eq!(pmu.read(PMCR1, 0, 52, KERNEL), Ok(1 << 17));
        pmu.write(PMCR1_EL12, 1 << 17, 0, 52, KERNEL).unwrap();
        // SPTM's 0x30300 enables PMC0 and PMC1 at the guarded level; 0
        // stops it there.
        pmu.set_guarded_filter(0x30300, 0, 52, guarded);
        pmu.sync(0, 60, guarded);
        pmu.set_guarded_filter(0, 0, 70, guarded);
        assert_eq!(pmu.read(PMC[1], 0, 80, KERNEL), Ok(40));
    }

    /// The M5 kpc saves and restores S3_1_C15_C5_1 with the other raw
    /// configurations; the M6 leaves it unqualified, and no earlier chip
    /// has it.
    #[test]
    fn the_m5_kpc_configuration_takes_only_0() {
        let mut m5 = Pmu::for_chip(Chip::AppleM5, CLOCK, FREQUENCY).unwrap();
        assert!(Pmu::owns_on(Chip::AppleM5, KPC_C5_1));
        assert!(m5.read(KPC_C5_1, 0, 0, KERNEL).is_err());
        assert!(m5.write(KPC_C5_1, 1, 0, 0, KERNEL).is_err());
        m5.write(KPC_C5_1, 0, 0, 0, KERNEL).unwrap();
        assert_eq!(m5.read(KPC_C5_1, 0, 0, KERNEL), Ok(0));
        let mut m6 = Pmu::for_chip(Chip::AppleM6, CLOCK, FREQUENCY).unwrap();
        assert!(m6.write(KPC_C5_1, 0, 0, 0, KERNEL).is_err());
        assert!(!Pmu::owns_on(Chip::AppleM4, KPC_C5_1));
    }

    #[test]
    fn undescribed_settings_and_unwritten_controls_refuse() {
        let mut pmu = Pmu::new(CLOCK, FREQUENCY);
        assert!(pmu.read(PMESR0, 0, 0, KERNEL).is_err());
        assert!(pmu.read(PMCR2, 0, 0, KERNEL).is_err());
        assert_eq!(pmu.read(PMCR1_EL12, 0, 0, KERNEL), Ok(0));
        for value in [1 << 2, 1 << 32, 2 << 8, 1 << 24, 1 << 30, 1 << 20] {
            assert!(pmu.write(PMCR0, value, 0, 0, KERNEL).is_err(), "{value:#x}");
        }
        assert!(pmu.write(PMCR1, 1, 0, 0, KERNEL).is_err());
        assert!(pmu.write(OPMSK0, 1, 0, 0, KERNEL).is_err());
        pmu.write(OPMSK0, 0, 0, 0, KERNEL).unwrap();
        assert_eq!(pmu.read(OPMSK0, 0, 0, KERNEL), Ok(0));
        assert!(pmu.read(PM_MEMFLT_CTL45, 0, 0, KERNEL).is_err());
        assert!(pmu.write(PM_MEMFLT_CTL23, 1, 0, 0, KERNEL).is_err());
        pmu.write(PM_MEMFLT_CTL45, 0, 0, 0, KERNEL).unwrap();
        assert_eq!(pmu.read(PM_MEMFLT_CTL45, 0, 0, KERNEL), Ok(0));
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
