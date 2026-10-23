//! Native PC platform services. Actual CPU/root adapters install their capabilities.

#[cfg(feature = "native-acpi")]
pub mod acpi;
#[cfg(feature = "native-acpi")]
pub mod battery;
pub mod ec;
pub mod ec_smbus;
pub mod image;
pub mod sbs;
pub mod wait;
pub mod work;
