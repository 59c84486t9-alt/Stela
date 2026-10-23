//! Native PC platform services. Actual CPU/root adapters install their capabilities.

#[cfg(feature = "native-acpi")]
pub mod acpi;
pub mod ec;
pub mod work;
