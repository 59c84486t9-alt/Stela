//! Native PC platform services. CPU/root adapters install their capabilities.

#[cfg(feature = "native-acpi")]
pub mod ac;
#[cfg(feature = "native-acpi")]
pub mod acpi;
#[cfg(feature = "native-acpi")]
pub mod battery;
pub mod ec;
pub mod ec_smbus;
pub mod image;
#[cfg(feature = "native-acpi")]
pub mod lid;
pub mod sbs;
pub mod wait;
pub mod work;
