//! Source-checked CPMU coordinates, independent of PE clocks and events.
//! H13–H17 definitions and original 26A434 consumers are pinned in
//! `docs/research/core-pmu.md`; M6 uses its own original accessor tables.
use super::{Chip, Encoding, Width, events, monitor};

pub(super) const MAX_COUNTERS: usize = 15;

#[derive(Debug, Clone, Copy)]
pub(super) struct Layout {
    pub width: Width,
    pub counters: &'static [Encoding],
    pub selectors: u64,
    pub events: events::Set,
    pub unqualified_controls: &'static [Encoding],
    /// The M5 kpc's [`super::KPC_C5_1`], which takes only 0.
    pub kpc_c5_1: bool,
}

const M6_COUNTERS: [Encoding; MAX_COUNTERS] = [
    monitor(2, 0, 0),
    monitor(2, 1, 0),
    monitor(2, 2, 0),
    monitor(2, 3, 0),
    monitor(2, 4, 0),
    monitor(2, 5, 0),
    monitor(2, 6, 0),
    monitor(2, 7, 0),
    monitor(2, 8, 0),
    monitor(2, 9, 0),
    Encoding::new(3, 0, 11, 13, 0),
    Encoding::new(3, 0, 11, 13, 1),
    Encoding::new(3, 0, 11, 13, 2),
    Encoding::new(3, 0, 11, 13, 3),
    Encoding::new(3, 0, 11, 13, 4),
];

// Original mac18g's register-application routine separately writes these
// controls. Their enabled effects are not supplied by the H13–H17 sources.
// xnu-12377.121.6 names S3_2_C15_C2_1..C9_1 PMEFR2–9 under
// CPMU_EVENT_FILTERING and writes them, with PMCR2–4, OPMAT, OPMSK and
// PM_MEMFLT_CTL23/45, only for an extended raw configuration (`cacr_ext`,
// cpc_arm64.c:667–688); the boot and reset configurations leave them alone
// (cpc_arm64.c:590–601).
const M6_UNQUALIFIED: [Encoding; 11] = [
    Encoding::new(3, 0, 11, 13, 5),
    Encoding::new(3, 0, 11, 13, 6),
    monitor(1, 5, 1),
    monitor(2, 2, 1),
    monitor(2, 3, 1),
    monitor(2, 4, 1),
    monitor(2, 5, 1),
    monitor(2, 6, 1),
    monitor(2, 7, 1),
    monitor(2, 8, 1),
    monitor(2, 9, 1),
];

impl Layout {
    pub fn on(chip: Chip) -> Self {
        match chip {
            Chip::AppleM1 => Self {
                width: Width::Bits48,
                counters: &super::PMC,
                selectors: u32::MAX as u64,
                events: events::Set::M1M2,
                unqualified_controls: &[],
                kpc_c5_1: false,
            },
            Chip::AppleM2 => Self {
                width: Width::Bits64,
                counters: &super::PMC,
                selectors: u32::MAX as u64,
                events: events::Set::M1M2,
                unqualified_controls: &[],
                kpc_c5_1: false,
            },
            Chip::AppleM3 | Chip::AppleM4 | Chip::AppleM5 => Self {
                width: Width::Bits64,
                counters: &super::PMC,
                selectors: u64::MAX,
                events: events::Set::Unqualified,
                unqualified_controls: &[],
                kpc_c5_1: chip == Chip::AppleM5,
            },
            Chip::AppleM6 => Self {
                width: Width::Bits64,
                counters: &M6_COUNTERS,
                // Original mac18g's PMESR writer writes zero to both
                // registers. No programmable event selector is checked.
                selectors: 0,
                events: events::Set::Unqualified,
                unqualified_controls: &M6_UNQUALIFIED,
                kpc_c5_1: false,
            },
        }
    }

    pub fn status_bit(self, counter: usize) -> u64 {
        // Original mac18g's PMI loop: slot <=9 uses its slot; slots
        // 10..14 use slot+22, hence PMSR bits32..36.
        1 << if counter < 10 { counter } else { counter + 22 }
    }
}
