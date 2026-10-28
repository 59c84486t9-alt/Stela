// SPDX-License-Identifier: GPL-2.0-or-later
//
// Linux DesignWare I2C timing selection adapted at the pinned stable tree:
// drivers/i2c/busses/i2c-designware-common.c (i2c_dw_acpi_configure,
// i2c_dw_adjust_bus_speed, i2c_dw_scl_hcnt, i2c_dw_scl_lcnt,
// i2c_dw_set_sda_hold), i2c-designware-master.c (i2c_dw_set_timings_master)
// and i2c-designware-platdrv.c (the SDA hold time from nanoseconds).
// Copyright (C) 2006 Texas Instruments.
// Copyright (C) 2007 MontaVista Software Inc.
// Copyright (C) 2009 Provigent Ltd.
//
//! DesignWare SCL counts and SDA hold for one bus: the counts the controller's
//! firmware methods (`SSCN`, `FMCN`, `FPCN`, `HSCN`) give for the bus speed
//! its devices' connections allow, else the counts Linux computes from the
//! controller's input clock and the board's fall times.
use super::{Speed, Timing};

/// The standard bus speeds, as Linux rounds a connection speed down to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusSpeed {
    Standard,
    Fast,
    FastPlus,
    High,
}

impl BusSpeed {
    /// Linux `i2c_dw_acpi_round_bus_speed` and `i2c_dw_adjust_bus_speed`:
    /// the slowest connection speed on the bus, rounded down to a standard
    /// speed, or fast mode when no connection gives one.
    pub fn from_connections(speeds: impl IntoIterator<Item = u32>) -> Self {
        match speeds.into_iter().min() {
            Some(hz) if hz >= 3_400_000 => Self::High,
            Some(hz) if hz >= 1_000_000 => Self::FastPlus,
            Some(hz) if hz >= 400_000 => Self::Fast,
            Some(hz) if hz >= 100_000 => Self::Standard,
            _ => Self::Fast,
        }
    }
}

/// One firmware timing method's package: SCL high and low counts and the
/// SDA_HOLD register value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub high: u16,
    pub low: u16,
    pub sda_hold: u32,
}

/// What the controller's firmware methods returned, by speed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Firmware {
    pub standard: Option<Counts>,
    pub fast: Option<Counts>,
    pub fast_plus: Option<Counts>,
    pub high: Option<Counts>,
}

/// The controller's input clock and the board properties its platform
/// driver supplies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Board {
    pub clock_hz: u32,
    /// `i2c-sda-hold-time-ns`; zero when the platform gives none.
    pub sda_hold_ns: u32,
    /// `i2c-sda-falling-time-ns` and `i2c-scl-falling-time-ns`; zero means
    /// Linux's 300 ns default.
    pub sda_fall_ns: u32,
    pub scl_fall_ns: u32,
}

/// Bits 16..24 of SDA_HOLD: the RX hold count.
const SDA_HOLD_RX: u32 = 0xff << 16;

/// The engine timing for a bus at `speed`. The engine has no high-speed
/// mode, so a high-speed bus runs in fast mode, as Linux runs it on a core
/// without high speed. `None` for SDA_HOLD keeps the controller's value.
pub fn select(speed: BusSpeed, firmware: Firmware, board: Board) -> Timing {
    let clock_khz = u64::from(board.clock_hz / 1000);
    let fall = |ns: u32| u64::from(if ns == 0 { 300 } else { ns });
    let (sda_fall, scl_fall) = (fall(board.sda_fall_ns), fall(board.scl_fall_ns));
    // i2c_dw_scl_hcnt and i2c_dw_scl_lcnt, without offsets.
    let high = |symbol_ns: u64| -> u16 {
        ((clock_khz * (symbol_ns + sda_fall)).div_ceil_closest() - 3).min(u64::from(u16::MAX))
            as u16
    };
    let low = |low_ns: u64| -> u16 {
        ((clock_khz * (low_ns + scl_fall)).div_ceil_closest() - 1).min(u64::from(u16::MAX)) as u16
    };
    let given = |counts: Option<Counts>| counts.filter(|c| c.high != 0 && c.low != 0);
    let held = match speed {
        BusSpeed::Standard => firmware.standard,
        BusSpeed::FastPlus => firmware.fast_plus,
        BusSpeed::High => firmware.high,
        BusSpeed::Fast => firmware.fast,
    }
    .map_or(0, |counts| counts.sda_hold);
    let (scl_high, scl_low) = match speed {
        BusSpeed::Standard => {
            given(firmware.standard).map_or_else(|| (high(4000), low(4700)), |c| (c.high, c.low))
        }
        BusSpeed::FastPlus => {
            given(firmware.fast_plus).map_or_else(|| (high(260), low(500)), |c| (c.high, c.low))
        }
        BusSpeed::Fast | BusSpeed::High => {
            given(firmware.fast).map_or_else(|| (high(600), low(1300)), |c| (c.high, c.low))
        }
    };
    // The platform driver's hold time when firmware gives none, then
    // i2c_dw_set_sda_hold's minimum RX hold.
    let hold = if held != 0 {
        held
    } else {
        (clock_khz * u64::from(board.sda_hold_ns)).div_ceil_closest() as u32
    };
    Timing {
        speed: if speed == BusSpeed::Standard {
            Speed::Standard
        } else {
            Speed::Fast
        },
        scl_high,
        scl_low,
        sda_hold: (hold != 0).then_some(if hold & SDA_HOLD_RX == 0 {
            hold | 1 << 16
        } else {
            hold
        }),
    }
}

/// Division by a million rounded to the closest integer, as Linux's
/// `DIV_ROUND_CLOSEST_ULL(x, MICRO)`.
trait Closest {
    fn div_ceil_closest(self) -> u64;
}
impl Closest for u64 {
    fn div_ceil_closest(self) -> u64 {
        (self + 500_000) / 1_000_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUNRISEPOINT: Board = Board {
        clock_hz: 120_000_000,
        sda_hold_ns: 230,
        sda_fall_ns: 0,
        scl_fall_ns: 0,
    };

    #[test]
    fn the_slowest_connection_sets_the_bus_speed() {
        assert_eq!(
            BusSpeed::from_connections([400_000, 1_000_000]),
            BusSpeed::Fast
        );
        assert_eq!(BusSpeed::from_connections([1_000_000]), BusSpeed::FastPlus);
        assert_eq!(BusSpeed::from_connections([3_400_000]), BusSpeed::High);
        assert_eq!(BusSpeed::from_connections([250_000]), BusSpeed::Standard);
        assert_eq!(BusSpeed::from_connections([]), BusSpeed::Fast);
        assert_eq!(BusSpeed::from_connections([50_000]), BusSpeed::Fast);
    }

    #[test]
    fn firmware_counts_win_over_computed_ones() {
        let firmware = Firmware {
            fast: Some(Counts {
                high: 0x48,
                low: 0xa0,
                sda_hold: 0x1e,
            }),
            ..Firmware::default()
        };
        let timing = select(BusSpeed::Fast, firmware, SUNRISEPOINT);
        assert_eq!((timing.scl_high, timing.scl_low), (0x48, 0xa0));
        assert_eq!(timing.sda_hold, Some(0x1_001e), "RX hold of at least one");
    }

    #[test]
    fn missing_firmware_counts_are_computed_from_the_clock() {
        let timing = select(BusSpeed::Fast, Firmware::default(), SUNRISEPOINT);
        // 120 MHz: (600 + 300) ns is 108 counts less 3, (1300 + 300) ns
        // is 192 counts less 1; 230 ns of hold is 28 counts (27.6).
        assert_eq!(timing.speed, Speed::Fast);
        assert_eq!((timing.scl_high, timing.scl_low), (105, 191));
        assert_eq!(timing.sda_hold, Some(1 << 16 | 28));
        let standard = select(BusSpeed::Standard, Firmware::default(), SUNRISEPOINT);
        assert_eq!(standard.speed, Speed::Standard);
        assert_eq!((standard.scl_high, standard.scl_low), (513, 599));
    }

    #[test]
    fn a_high_speed_bus_runs_with_fast_mode_counts() {
        let firmware = Firmware {
            fast: Some(Counts {
                high: 100,
                low: 200,
                sda_hold: 0,
            }),
            high: Some(Counts {
                high: 7,
                low: 9,
                sda_hold: 0x2_0005,
            }),
            ..Firmware::default()
        };
        let timing = select(BusSpeed::High, firmware, SUNRISEPOINT);
        assert_eq!(timing.speed, Speed::Fast);
        assert_eq!((timing.scl_high, timing.scl_low), (100, 200));
        assert_eq!(timing.sda_hold, Some(0x2_0005));
    }

    #[test]
    fn no_hold_from_firmware_or_board_keeps_the_controller_value() {
        let board = Board {
            sda_hold_ns: 0,
            ..SUNRISEPOINT
        };
        assert_eq!(
            select(BusSpeed::Fast, Firmware::default(), board).sda_hold,
            None
        );
    }
}
