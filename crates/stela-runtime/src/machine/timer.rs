//! One generic-timer channel (CNTP or CNTV) of Arm ARM DDI0487 D12.
//! The counter value comes from the host; CNTVOFF is zero because there is
//! no EL2, so both channels compare against the same count.

const ENABLE: u64 = 1;
const IMASK: u64 = 2;
const ISTATUS: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timer {
    control: u64,
    compare: u64,
}

impl Timer {
    /// The timer condition, independent of IMASK.
    pub fn met(&self, now: u64) -> bool {
        self.control & ENABLE != 0 && now >= self.compare
    }

    /// The interrupt output: enabled, unmasked and met.
    pub fn asserted(&self, now: u64) -> bool {
        self.control & IMASK == 0 && self.met(now)
    }

    /// The compare value when the output can still assert.
    pub fn deadline(&self) -> Option<u64> {
        (self.control & (ENABLE | IMASK) == ENABLE).then_some(self.compare)
    }

    pub fn read_control(&self, now: u64) -> u64 {
        self.control | if self.met(now) { ISTATUS } else { 0 }
    }

    pub fn write_control(&mut self, value: u64) {
        self.control = value & (ENABLE | IMASK);
    }

    pub fn compare(&self) -> u64 {
        self.compare
    }

    pub fn write_compare(&mut self, value: u64) {
        self.compare = value;
    }

    /// TimerValue: the low 32 bits of CVAL minus the count.
    pub fn read_value(&self, now: u64) -> u64 {
        self.compare.wrapping_sub(now) & 0xffff_ffff
    }

    /// Writing TimerValue sets CVAL to the count plus the sign-extended value.
    pub fn write_value(&mut self, now: u64, value: u64) {
        self.compare = now.wrapping_add(value as u32 as i32 as i64 as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_value_and_masking() {
        let mut timer = Timer::default();
        timer.write_value(1000, 500);
        assert_eq!(timer.compare(), 1500);
        assert_eq!(timer.deadline(), None);
        timer.write_control(ENABLE | 0xf0);
        assert_eq!(timer.deadline(), Some(1500));
        assert!(!timer.asserted(1499) && timer.asserted(1500));
        assert_eq!(timer.read_control(1500), ENABLE | ISTATUS);
        assert_eq!(timer.read_value(1600), 0xffff_ff9c);
        timer.write_control(ENABLE | IMASK);
        assert!(timer.met(1600) && !timer.asserted(1600));
        assert_eq!(timer.deadline(), None);
        timer.write_value(1000, 0xffff_fff6);
        assert_eq!(timer.compare(), 990);
    }
}
