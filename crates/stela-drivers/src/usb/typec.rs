//! Physical PC Type-C policy-manager transports and connector control.
//!
//! These backends do not emulate an Apple USB-C controller or choose system
//! power policy. The platform supplies the actual ACPI/I²C resources and owns
//! connector-to-host-router, role-switch, mux and retimer routing.
pub mod ucsi;
