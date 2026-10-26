//! Physical PC Type-C policy-manager transports and connector control.
//!
//! These backends do not emulate an Apple USB-C controller or choose system
//! power policy. The platform supplies the actual ACPI/I²C resources and owns
//! connector-to-host-router and role-switch association. Selected mux/retimer
//! backends perform the actual register and power programming.
pub mod mux;
pub mod tps6598x;
pub mod ucsi;

#[cfg(test)]
mod clock_tests;
