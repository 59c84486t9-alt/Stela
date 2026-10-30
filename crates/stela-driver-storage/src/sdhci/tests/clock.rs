//! Independent clock register phases, monotonic deadlines and source traces.
use super::super::*;
use model::CLOCK_TICKS_PER_US;

struct Port {
    clock: Clock,
    v4: bool,
    control: u16,
    writes: Vec<u16>,
    started: u64,
    first_us: u64,
    second_us: u64,
    ignored_pll: bool,
}
impl Port {
    fn new(v4: bool, first_us: u64, second_us: u64) -> Self {
        Self {
            clock: Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US,
            },
            v4,
            control: 0,
            writes: Vec::new(),
            started: 0,
            first_us,
            second_us,
            ignored_pll: false,
        }
    }
}
impl Registers for Port {
    fn read8(&mut self, _: usize) -> u8 {
        panic!("no byte clock access");
    }
    fn read32(&mut self, _: usize) -> u32 {
        panic!("no dword clock access");
    }
    fn write8(&mut self, _: usize, _: u8) {
        panic!("no byte clock access");
    }
    fn write32(&mut self, _: usize, _: u32) {
        panic!("no dword clock access");
    }
    fn read16(&mut self, at: usize) -> u16 {
        if at == HOST_CONTROL2 {
            return if self.v4 { 1 << 12 } else { 0 };
        }
        assert_eq!(at, CLOCK);
        let wait = if self.control & CLOCK_PLL != 0 {
            self.second_us
        } else {
            self.first_us
        };
        self.control
            | if self.clock.now_us().wrapping_sub(self.started) >= wait {
                CLOCK_STABLE
            } else {
                0
            }
    }
    fn write16(&mut self, at: usize, value: u16) {
        assert_eq!(at, CLOCK);
        if value & CLOCK_CARD != 0 {
            let wait = if self.control & CLOCK_PLL != 0 {
                self.second_us
            } else {
                self.first_us
            };
            assert!(
                self.clock.now_us().wrapping_sub(self.started) >= wait,
                "card clock before actual phase stable"
            );
        }
        self.control = value & !CLOCK_STABLE;
        if self.ignored_pll {
            self.control &= !CLOCK_PLL;
        }
        self.writes.push(value & !CLOCK_STABLE);
        self.started = self.clock.now_us();
    }
}

#[test]
fn v4_410_clock_waits_for_both_phases_beyond_the_old_twenty_ms_window() {
    let mut port = Port::new(true, 30_000, 40_000);
    enable_clock(
        &mut port,
        Clock {
            ticks_per_microsecond: CLOCK_TICKS_PER_US,
        },
        4,
        0x100,
    )
    .unwrap();
    assert_eq!(port.writes, [0x101, 0x109, 0x10d]);
    for (version, v4) in [(2, true), (4, false)] {
        let mut port = Port::new(v4, 0, 180_000);
        enable_clock(
            &mut port,
            Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US,
            },
            version,
            0,
        )
        .unwrap();
        assert_eq!(port.writes, [1, 5]);
    }
}

#[test]
fn unacknowledged_or_unstable_v4_pll_never_enables_card_clock() {
    for ignore in [false, true] {
        let mut port = Port::new(true, 0, if ignore { 0 } else { 180_000 });
        port.ignored_pll = ignore;
        let result = enable_clock(
            &mut port,
            Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US,
            },
            4,
            0,
        );
        if ignore {
            assert!(matches!(result, Err(BlockError::Unsupported(_))));
        } else {
            assert_eq!(result, Err(BlockError::Timeout));
        }
        assert_eq!(port.writes, [1, 9]);
        assert_eq!(port.control & CLOCK_CARD, 0);
    }
}

#[test]
#[ignore = "oracle: STELA_SDHCI_CLOCK_ORACLE"]
fn unchanged_linux_clock_enable_v4_pll_phases_and_independent_deadlines_match_native() {
    extern crate std;
    let records = std::fs::read_to_string(
        std::env::var("STELA_SDHCI_CLOCK_ORACLE").expect("pinned clock records"),
    )
    .unwrap();
    let mut count = 0;
    for line in records.lines() {
        let fields: Vec<u32> = line
            .split_whitespace()
            .map(|n| n.parse().unwrap())
            .collect();
        let mut port = Port::new(fields[1] != 0, u64::from(fields[3]), u64::from(fields[4]));
        let result = enable_clock(
            &mut port,
            Clock {
                ticks_per_microsecond: CLOCK_TICKS_PER_US,
            },
            fields[0] as u8,
            fields[2] as u16,
        );
        assert_eq!(
            result.is_ok(),
            fields[5] & u32::from(CLOCK_CARD) != 0,
            "{line}"
        );
        assert_eq!(u32::from(port.control), fields[5], "{line}");
        assert_eq!(port.writes.len(), fields[6] as usize, "{line}");
        assert_eq!(
            port.writes
                .iter()
                .map(|n| u32::from(*n))
                .collect::<Vec<_>>(),
            fields[7..],
            "{line}"
        );
        count += 1;
    }
    assert_eq!(count, 192);
}
