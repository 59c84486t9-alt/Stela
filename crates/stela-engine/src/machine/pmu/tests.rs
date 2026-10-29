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
        // Counter storage does not check event counting or EL0 access.
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
/// configurations; the M6 leaves it unchecked, and no earlier chip
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
