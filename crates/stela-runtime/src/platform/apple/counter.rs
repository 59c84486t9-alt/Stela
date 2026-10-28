//! The Apple silicon system counter frequency.
//!
//! Apple silicon reports `CNTFRQ_EL0` = 24 MHz, the `clkref` crystal rate that
//! also clocks the watchdog (Linux `arch/arm64/boot/dts/apple/t8112.dtsi`,
//! `clkref: clock-ref`, `clock-frequency = <24000000>`). This is distinct from the 1 GHz hosted
//! commpage clock in `crate::clock`.

/// `CNTFRQ_EL0` on Apple silicon.
pub const FREQUENCY_HZ: u64 = 24_000_000;
