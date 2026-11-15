use super::*;
use alloc::{vec, vec::Vec};

/// Registers with fixed values that log each access in order.
#[derive(Default)]
struct Logged {
    values: Vec<(u32, u64)>,
    accesses: Vec<(char, u32, u64)>,
}

impl Logged {
    fn with(values: &[(Msr, u64)]) -> Self {
        Self {
            values: values
                .iter()
                .map(|(msr, value)| (msr.index, *value))
                .collect(),
            accesses: Vec::new(),
        }
    }

    fn writes(&self) -> Vec<(u32, u64)> {
        self.accesses
            .iter()
            .filter(|(kind, ..)| *kind == 'w')
            .map(|&(_, index, value)| (index, value))
            .collect()
    }
}

impl Registers for Logged {
    unsafe fn read(&mut self, msr: Msr) -> u64 {
        let value = self
            .values
            .iter()
            .find(|(index, _)| *index == msr.index)
            .map_or(0, |(_, value)| *value);
        self.accesses.push(('r', msr.index, value));
        value
    }

    unsafe fn write(&mut self, msr: Msr, value: u64) {
        self.accesses.push(('w', msr.index, value));
        if let Some(entry) = self
            .values
            .iter_mut()
            .find(|(index, _)| *index == msr.index)
        {
            entry.1 = value;
        } else {
            self.values.push((msr.index, value));
        }
    }
}

fn intel(hwp: bool, notify: bool, epp: bool) -> Features {
    Features {
        intel: true,
        hwp,
        hwp_notify: notify,
        hwp_epp: epp,
        ..Features::default()
    }
}

fn amd(cppc: bool) -> Features {
    Features {
        amd: true,
        cppc,
        ..Features::default()
    }
}

fn request(features: Features, registers: &mut Logged) -> Outcome {
    // SAFETY: the registers are a log, not this processor's.
    unsafe { request_with(features, registers) }
}

#[test]
fn a_processor_without_either_interface_is_not_touched() {
    for features in [
        Features::default(),
        intel(false, false, false),
        amd(false),
        // A hypervisor that reports neither bit, on either vendor.
        Features {
            intel: true,
            amd: false,
            ..Features::default()
        },
    ] {
        let mut registers = Logged::default();
        assert_eq!(request(features, &mut registers), Outcome::Legacy);
        assert!(registers.accesses.is_empty(), "{features:?}");
    }
}

#[test]
fn intel_turns_notifications_off_then_hwp_on_before_the_request() {
    // highest 0x30, guaranteed 0x24, most efficient 0x10, lowest 0x08.
    let mut registers = Logged::with(&[
        (HWP_CAPABILITIES, 0x0810_2430),
        // Firmware: balanced EPP 0x80, desired 0x11, activity window.
        (HWP_REQUEST, 0x0000_0201_8011_3008),
    ]);
    let outcome = request(intel(true, true, true), &mut registers);
    assert_eq!(
        registers.writes(),
        vec![(0x773, 0), (0x770, 1), (0x774, 0x0000_0201_0000_3030),],
        "IA32_HWP_INTERRUPT, then IA32_PM_ENABLE, then IA32_HWP_REQUEST"
    );
    assert_eq!(
        outcome,
        Outcome::Hwp {
            levels: Levels {
                highest: 0x30,
                sustained: 0x24,
                lowest: 0x08
            },
            bounds: Bounds {
                minimum: 0x30,
                maximum: 0x30
            },
            epp: true,
            package: false,
        }
    );
}

#[test]
fn intel_with_hwp_already_on_writes_only_the_request() {
    let mut registers = Logged::with(&[
        (PM_ENABLE, 1),
        (HWP_CAPABILITIES, 0x0810_2430),
        // Package control (bit 42) set by firmware.
        (HWP_REQUEST, 0x0000_0400_8000_3008),
    ]);
    let outcome = request(intel(true, false, true), &mut registers);
    assert_eq!(registers.writes(), vec![(0x774, 0x0000_0400_0000_3030)]);
    assert!(matches!(outcome, Outcome::Hwp { package: true, .. }));
}

#[test]
fn intel_hwp_without_epp_stays_off_and_keeps_the_preference_field() {
    // Off: left off, as intel_pstate does without EPP (or DEC).
    let mut registers = Logged::with(&[(HWP_CAPABILITIES, 0x0810_2430)]);
    assert_eq!(
        request(intel(true, true, false), &mut registers),
        Outcome::HwpWithoutEpp
    );
    assert!(registers.writes().is_empty());
    assert_eq!(registers.accesses, vec![('r', 0x770, 0)]);
    // On already (firmware's choice): bits 31:24 are not an EPP field.
    let mut registers = Logged::with(&[
        (PM_ENABLE, 1),
        (HWP_CAPABILITIES, 0x0810_2430),
        (HWP_REQUEST, 0x5a00_3008),
    ]);
    let outcome = request(intel(true, false, false), &mut registers);
    assert_eq!(registers.writes(), vec![(0x774, 0x5a00_3030)]);
    assert!(matches!(outcome, Outcome::Hwp { epp: false, .. }));
}

#[test]
fn unpublished_levels_keep_the_firmware_request() {
    let mut registers = Logged::with(&[(PM_ENABLE, 1), (HWP_REQUEST, 0x8000_ff01)]);
    assert_eq!(
        request(intel(true, false, true), &mut registers),
        Outcome::Unpublished
    );
    assert!(registers.writes().is_empty());
    // Lowest above highest.
    assert_eq!(intel_request(0x4000_0020, 0, true), None);
    let mut registers = Logged::with(&[(AMD_CPPC_ENABLE, 1), (AMD_CPPC_REQ, 0x8000_ff01)]);
    assert_eq!(request(amd(true), &mut registers), Outcome::Unpublished);
    assert!(registers.writes().is_empty());
}

#[test]
fn amd_enables_cppc_then_asks_nominal_to_highest() {
    // CAP1: highest 0xa6, nominal 0x7c, lowest nonlinear 0x38, lowest 0x12.
    let mut registers = Logged::with(&[
        (AMD_CPPC_CAP1, 0xa67c_3812),
        // Firmware: EPP 0x80, desired 0, minimum 0x12, maximum 0xa6, and
        // upper bits that stay.
        (AMD_CPPC_REQ, 0xdead_0000_8000_12a6),
    ]);
    let outcome = request(amd(true), &mut registers);
    assert_eq!(
        registers.writes(),
        vec![(0xc001_02b1, 1), (0xc001_02b3, 0xdead_0000_0000_7ca6)],
        "CPPC_ENABLE, then CPPC_REQ: maximum 7:0, minimum 15:8"
    );
    assert_eq!(
        outcome,
        Outcome::Cppc {
            levels: Levels {
                highest: 0xa6,
                sustained: 0x7c,
                lowest: 0x12
            },
            bounds: Bounds {
                minimum: 0x7c,
                maximum: 0xa6
            },
        }
    );
    // Already on: only the request.
    let mut registers = Logged::with(&[
        (AMD_CPPC_ENABLE, 1),
        (AMD_CPPC_CAP1, 0xa67c_3812),
        (AMD_CPPC_REQ, 0x8000_12a6),
    ]);
    request(amd(true), &mut registers);
    assert_eq!(registers.writes(), vec![(0xc001_02b3, 0x7ca6)]);
}

#[test]
fn amd_keeps_a_firmware_minimum_from_an_otherwise_empty_request() {
    // amd-pstate's bios_min_perf: only the minimum field is set.
    let (value, bounds) = amd_request(0xa67c_3812, 0x5000).unwrap();
    assert_eq!(bounds.minimum, 0x50);
    assert_eq!(value, 0x50a6);
    // A request with other fields set holds no firmware minimum.
    let (_, bounds) = amd_request(0xa67c_3812, 0x8000_50a6).unwrap();
    assert_eq!(bounds.minimum, 0x7c);
    // An empty request: the nominal level.
    let (_, bounds) = amd_request(0xa67c_3812, 0).unwrap();
    assert_eq!(bounds.minimum, 0x7c);
}

#[test]
fn a_minimum_outside_the_published_range_is_clamped() {
    // Nominal 0xc0 above highest 0xa6.
    let (_, bounds) = amd_request(0xa6c0_3812, 0).unwrap();
    assert_eq!(bounds.minimum, 0xa6);
    // Nominal 0 below lowest 0x12.
    let (_, bounds) = amd_request(0xa600_3812, 0).unwrap();
    assert_eq!(bounds.minimum, 0x12);
}

#[test]
fn the_summary_counts_outcomes_and_the_range_of_levels() {
    let tally = Tally::new();
    assert!(
        tally
            .summary()
            .contains("highest=none requested_minimum=none")
    );
    for (highest, nominal) in [(0xa6u64, 0x7cu64), (0xb0, 0x7c)] {
        let capabilities = highest << 24 | nominal << 16 | 0x3812;
        let (_, bounds) = amd_request(capabilities, 0).unwrap();
        tally.record(Outcome::Cppc {
            levels: Levels::amd(capabilities),
            bounds,
        });
    }
    tally.record(Outcome::Legacy);
    let line = tally.summary();
    assert!(line.starts_with("HOST PERFORMANCE hwp=0 cppc=2 "), "{line}");
    assert!(line.contains(" legacy=1 "), "{line}");
    assert!(
        line.contains("highest=166-176 requested_minimum=124 "),
        "{line}"
    );
}
