//! Logical vote nibbles (`Packed`) and the software `Interpolation` state,
//! which maps a requested value and duration onto a bounded state table and
//! steps between adjacent table entries as time advances.
use alloc::vec::Vec;

/// Logical source vote nibbles, not controller raw register codes or settlement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Packed(pub [u64; 2]);
impl Packed {
    pub fn nibble(self, index: u8) -> Option<u8> {
        (index < 32).then(|| ((self.0[usize::from(index / 16)] >> (index % 16 * 4)) & 15) as u8)
    }
    pub(super) fn set(&mut self, index: u8, value: u32) {
        let word = &mut self.0[usize::from(index / 16)];
        let shift = (index % 16) * 4;
        // Source inserts a full W32 logical value; it does not mask to a nibble.
        *word = (*word & !(15u64 << shift)) | (u64::from(value) << shift);
    }
}

/// Source40-byte software interpolation state (10198b0..98dc), owned locally.
/// Units are retained source table/tick units, not physical MHz or voltage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interpolation {
    table: Vec<u32>,
    period: u32,
    duty: u32,
    phase: u32,
    remaining: u32,
    target: u32,
}
impl Interpolation {
    pub(super) fn initialized(table: Vec<u32>) -> Result<Self, &'static str> {
        if table.is_empty() || table.len() > 16 {
            return Err("native interpolation needs a bounded nonempty source state table");
        }
        Ok(Self {
            table,
            period: 0,
            duty: 0,
            phase: 0,
            remaining: 0,
            target: 0,
        })
    }
    pub fn target(&self) -> u32 {
        self.target
    }
    pub fn phase(&self) -> u32 {
        self.phase
    }
    pub fn remaining(&self) -> u32 {
        self.remaining
    }
    /// Original1010f78..101113c. All MUL/SUB/DIV operands are W32; ARM UDIV0=0.
    pub(super) fn request(&mut self, payload: u64) -> u32 {
        let value = payload as u32 & 0xffff;
        let duration = (payload as u32) >> 16;
        self.period = 0;
        self.target = 0;
        self.phase = 0;
        if value <= self.table[0] {
            return 0;
        }
        let count = self.table.len() as u32;
        self.target = count - 1;
        for i in 1..count {
            let high = self.table[i as usize];
            if high == 0 {
                self.target = i - 1;
                break;
            }
            if value > high {
                continue;
            }
            if duration == 0 {
                self.target = i;
                break;
            }
            let low = self.table[(i - 1) as usize];
            let numerator = value.wrapping_sub(low).wrapping_mul(duration);
            let denominator = high.wrapping_sub(low);
            let fraction = numerator.checked_div(denominator).unwrap_or(0);
            if fraction <= 199 {
                self.target = i - 1;
            } else {
                self.target = i;
                if duration.wrapping_sub(fraction) >= 200 {
                    self.period = duration;
                    self.duty = fraction;
                    self.phase = 2;
                    self.remaining = fraction;
                }
            }
            break;
        }
        self.target
    }
    /// Original101140c..1011498: at most one phase boundary per evaluation.
    pub(super) fn advance(&mut self, interval: u64) -> Option<u32> {
        if self.phase == 0 {
            return None;
        }
        if interval < u64::from(self.remaining) {
            self.remaining = self.remaining.wrapping_sub(interval as u32);
            return None;
        }
        if self.phase == 2 {
            self.remaining = self.period.wrapping_sub(self.duty);
            self.target = self.target.wrapping_sub(1);
            self.phase = 1;
        } else {
            self.remaining = self.duty;
            self.target = self.target.wrapping_add(1);
            self.phase = 2;
        }
        Some(self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn source_isp_interpolation_keeps_fraction_thresholds_and_one_boundary() {
        let mut x = Interpolation::initialized(vec![300, 427, 533]).unwrap();
        assert_eq!(x.request((1000 << 16) | 363), 1);
        assert_eq!(
            (x.phase, x.remaining, x.period, x.duty),
            (2, 496, 1000, 496)
        );
        assert_eq!(x.advance(7), None);
        assert_eq!(x.remaining, 489);
        assert_eq!(x.advance(10000), Some(0));
        assert_eq!((x.phase, x.remaining), (1, 504));
        assert_eq!(x.advance(504), Some(1));
        assert_eq!(x.request((100 << 16) | 363), 0);
        assert_eq!(x.phase, 0);
        assert_eq!(x.request(400), 1);
        assert_eq!(x.request(u16::MAX as u64), 2);
    }
    #[test]
    fn source_tables_zero_sentinel_equal_boundary_and_wrapping_multiply() {
        let mut x = Interpolation::initialized(vec![300, 427, 0]).unwrap();
        assert_eq!(x.request(428), 1);
        assert_eq!(x.request(300), 0);
        assert_eq!(x.request(427), 1);
        let mut y = Interpolation::initialized(vec![0, 100000]).unwrap();
        let payload = (65535u64 << 16) | 65535;
        let expected = 65535u32.wrapping_mul(65535) / 100000;
        y.request(payload);
        assert_eq!(y.remaining, expected);
        let mut p = Packed::default();
        p.set(17, 3);
        p.set(1, 2);
        assert_eq!(p.nibble(17), Some(3));
        assert_eq!(p.nibble(1), Some(2));
        assert_eq!(p.nibble(32), None);
    }
}
