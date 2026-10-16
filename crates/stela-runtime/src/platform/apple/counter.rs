//! The Apple silicon system counter, derived from a host monotonic counter.
//!
//! Apple silicon reports `CNTFRQ_EL0` = 24 MHz, the `clkref` crystal rate that
//! also clocks the watchdog (Linux `arch/arm64/boot/dts/apple/t8112.dtsi`,
//! `clkref: clock-ref`, `clock-frequency = <24000000>`). On the bare-metal PC
//! the host counter is the invariant TSC or the HPET; the engine supplies it.
//! This is distinct from the 1 GHz hosted commpage clock in `crate::clock`.

/// `CNTFRQ_EL0` on Apple silicon.
pub const FREQUENCY_HZ: u64 = 24_000_000;

/// A host counter that never runs backwards, at a fixed frequency.
pub trait HostCounter {
    fn frequency_hz(&self) -> u64;
    fn read(&mut self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError {
    /// The host counter has no usable frequency.
    ZeroFrequency,
    /// The host counter moved backwards from `previous` to `current`.
    Backwards { previous: u64, current: u64 },
    /// The guest counter left the 64-bit range.
    Overflow,
}

/// The guest-visible physical count (`CNTPCT_EL0`), scaled from the host
/// counter so that it starts at `start` when the counter is created.
#[derive(Debug)]
pub struct SystemCounter<H> {
    host: H,
    host_frequency: u64,
    host_epoch: u64,
    host_last: u64,
    start: u64,
}
impl<H: HostCounter> SystemCounter<H> {
    pub fn new(mut host: H, start: u64) -> Result<Self, CounterError> {
        let host_frequency = host.frequency_hz();
        if host_frequency == 0 {
            return Err(CounterError::ZeroFrequency);
        }
        let host_epoch = host.read();
        Ok(Self {
            host,
            host_frequency,
            host_epoch,
            host_last: host_epoch,
            start,
        })
    }
    /// Samples the host counter and returns the current guest count.
    pub fn now(&mut self) -> Result<u64, CounterError> {
        let current = self.host.read();
        if current < self.host_last {
            return Err(CounterError::Backwards {
                previous: self.host_last,
                current,
            });
        }
        self.host_last = current;
        let elapsed = u128::from(current - self.host_epoch) * u128::from(FREQUENCY_HZ)
            / u128::from(self.host_frequency);
        u64::try_from(elapsed)
            .ok()
            .and_then(|elapsed| self.start.checked_add(elapsed))
            .ok_or(CounterError::Overflow)
    }
    /// The earliest host counter value at which the guest count reaches
    /// `guest`, for programming a host timer (LAPIC TSC-deadline or HPET).
    pub fn host_deadline(&self, guest: u64) -> Result<u64, CounterError> {
        let Some(elapsed) = guest.checked_sub(self.start) else {
            return Ok(self.host_epoch);
        };
        let host = (u128::from(elapsed) * u128::from(self.host_frequency))
            .div_ceil(u128::from(FREQUENCY_HZ));
        u64::try_from(host)
            .ok()
            .and_then(|host| self.host_epoch.checked_add(host))
            .ok_or(CounterError::Overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed {
        frequency: u64,
        values: alloc::collections::VecDeque<u64>,
    }
    impl HostCounter for Fixed {
        fn frequency_hz(&self) -> u64 {
            self.frequency
        }
        fn read(&mut self) -> u64 {
            self.values
                .pop_front()
                .expect("test host counter exhausted")
        }
    }
    fn host(frequency: u64, values: &[u64]) -> Fixed {
        Fixed {
            frequency,
            values: values.iter().copied().collect(),
        }
    }

    #[test]
    fn scales_a_tsc_to_24_mhz() {
        // A 3.6 GHz TSC: 150 host ticks per guest tick.
        let mut counter = SystemCounter::new(
            host(3_600_000_000, &[1000, 1000 + 150 * 7, 1000 + 3_600_000_000]),
            5,
        )
        .unwrap();
        assert_eq!(counter.now(), Ok(12));
        assert_eq!(counter.now(), Ok(5 + FREQUENCY_HZ));
        assert_eq!(counter.host_deadline(12), Ok(1000 + 150 * 7));
        assert_eq!(counter.host_deadline(3), Ok(1000));
    }

    #[test]
    fn rounds_host_deadlines_up() {
        // A 14.318180 MHz HPET is slower than the guest counter.
        let counter = SystemCounter::new(host(14_318_180, &[0]), 0).unwrap();
        let deadline = counter.host_deadline(1).unwrap();
        assert_eq!(deadline, 1);
        assert!(u128::from(deadline) * u128::from(FREQUENCY_HZ) >= 14_318_180);
    }

    #[test]
    fn refuses_a_backwards_host_counter() {
        let mut counter = SystemCounter::new(host(24_000_000, &[10, 20, 19]), 0).unwrap();
        assert_eq!(counter.now(), Ok(10));
        assert_eq!(
            counter.now(),
            Err(CounterError::Backwards {
                previous: 20,
                current: 19
            })
        );
        assert_eq!(
            SystemCounter::new(host(0, &[0]), 0).err(),
            Some(CounterError::ZeroFrequency)
        );
    }
}
