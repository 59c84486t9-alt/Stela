//! Audio's timer requirement: nominal deadlines and qualified minimum waits,
//! met by the drivers' shared [`Timing`] owner.
use crate::bus::{i2c, pci::power};

/// Audio protocols use nominal deadlines and independently qualified minimum waits.
/// Implementing the nominal clock trait alone cannot satisfy this contract.
/// ```compile_fail
/// use stela_driver_audio::Timer;
/// fn needs_minimum(_: &impl Timer) {}
/// needs_minimum(&stela_driver_base::Clock { ticks_per_microsecond: 3_000 });
/// ```
pub trait Timer: i2c::Timer + power::Timer {}
impl<T: i2c::Timer + power::Timer> Timer for T {}

pub use stela_driver_base::timing::Timing;
