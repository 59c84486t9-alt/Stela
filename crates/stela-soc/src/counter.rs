//! The Apple silicon system counter frequency.
//!
//! Apple silicon reports `CNTFRQ_EL0` = 24 MHz, the `clkref` crystal rate that
//! also clocks the watchdog ([`stela_soc_data::clock`]).

/// `CNTFRQ_EL0` on Apple silicon.
pub const FREQUENCY_HZ: u64 = stela_soc_data::clock::REFERENCE_HZ;
