//! One retained audio timing owner: nominal deadlines and physical minima.
use crate::bus::{i2c, pci::power};
use alloc::rc::Rc;

/// Audio protocols use nominal deadlines and independently qualified minimum waits.
/// Implementing the nominal clock trait alone cannot satisfy this contract.
/// ```compile_fail
/// use stela_driver_audio::Timer;
/// fn needs_minimum(_: &impl Timer) {}
/// needs_minimum(&stela_driver_base::Clock { ticks_per_microsecond: 3_000 });
/// ```
pub trait Timer: i2c::Timer + power::Timer {}
impl<T: i2c::Timer + power::Timer> Timer for T {}

#[derive(Clone)]
pub struct Timing<N> {
    nominal: N,
    minimum: Rc<dyn power::Timer>,
}
impl<N> Timing<N> {
    /// Associate an existing genuine provider; this performs no device effect
    /// and grants no clock, CPU, root or hardware ownership.
    pub fn new(nominal: N, minimum: Rc<dyn power::Timer>) -> Self {
        Self { nominal, minimum }
    }
}
impl<N: i2c::Timer> i2c::Timer for Timing<N> {
    fn now_us(&self) -> u64 {
        self.nominal.now_us()
    }
    fn relax(&self) {
        self.nominal.relax();
    }
}
// SAFETY: all admission and minimum waits delegate to the same retained
// actual provider; the independently supplied nominal clock grants nothing.
unsafe impl<N> power::Timer for Timing<N> {
    fn check(&self) -> Result<(), power::Error> {
        self.minimum.check()
    }
    fn wait_us(&self, us: u64) -> Result<(), power::Error> {
        self.minimum.wait_us(us)
    }
}
