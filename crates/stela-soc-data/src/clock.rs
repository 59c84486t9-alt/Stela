//! The SoC reference clock.
//!
//! Apple silicon's `clkref` crystal runs at 24 MHz (Linux
//! `arch/arm64/boot/dts/apple/t8112.dtsi`, `clkref: clock-ref`,
//! `clock-frequency = <24000000>`). It is the system counter's rate
//! (`CNTFRQ_EL0`, the DeviceTree `timebase-frequency`), the watchdog's clock,
//! and the value iBoot's clock getter reports for every boot CPU clock
//! ([`crate::board::BOOT_CLOCK_HZ`]).

/// The 24 MHz `clkref` rate, in hertz.
pub const REFERENCE_HZ: u64 = 24_000_000;
