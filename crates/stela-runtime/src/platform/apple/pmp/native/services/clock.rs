//! Source101fb00 reads counter plus signed offset;102a598 converts it.
#[derive(Clone, Copy)]
pub struct Clock {
    read: fn() -> u64,
    frequency: u32,
    signed_offset: i64,
}
impl Clock {
    /// The configuration owner supplies a fresh native counter reader,
    /// e.g. its calibrated BSP physical counter. No Access.now or default clock.
    pub fn new(
        read: fn() -> u64,
        frequency: u32,
        signed_offset: i64,
    ) -> Result<Self, &'static str> {
        if frequency == 0 {
            return Err("native clock frequency is zero");
        }
        Ok(Self {
            read,
            frequency,
            signed_offset,
        })
    }
    pub fn raw(self) -> u64 {
        (self.read)().wrapping_add(self.signed_offset as u64)
    }
    pub fn converted(self) -> u64 {
        self.convert(self.raw())
    }
    fn convert(self, ticks: u64) -> u64 {
        if self.frequency.is_multiple_of(1_000_000) {
            ticks / u64::from(self.frequency / 1_000_000)
        } else {
            ticks.wrapping_mul(1_000_000) / u64::from(self.frequency)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ticks() -> u64 {
        48
    }
    #[test]
    fn reader_offset_precedes_exact_source_conversion() {
        let c = Clock::new(ticks, 24_000_000, -24).unwrap();
        assert_eq!(c.raw(), 24);
        assert_eq!(c.converted(), 1);
        let c = Clock::new(ticks, 3, 0).unwrap();
        assert_eq!(c.convert(u64::MAX), u64::MAX.wrapping_mul(1_000_000) / 3);
        assert!(Clock::new(ticks, 0, 0).is_err());
    }
}
