//! Raw layout classes, not effective values after guest FPCR flushing.
use serde::Serialize;

pub(super) const FP_CLASSES: [&str; 12] = [
    "positive_zero", "negative_zero", "positive_subnormal", "negative_subnormal",
    "positive_lowest_normal_binade", "negative_lowest_normal_binade",
    "positive_other_normal", "negative_other_normal", "positive_infinity",
    "negative_infinity", "quiet_nan", "signaling_nan",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Ieee { bits: u8 },
    Integer { bits: u8, signed: bool },
    Predicate { bits: u8 },
    Nzcv,
}

impl Kind {
    pub(super) fn bits(self) -> u32 {
        match self {
            Self::Ieee { bits } | Self::Integer { bits, .. } | Self::Predicate { bits } => u32::from(bits),
            Self::Nzcv => 4,
        }
    }
}

/// Selected lanes packed from lane zero. No inactive or merge-only bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) struct Lanes {
    pub kind: Kind,
    pub count: u8,
    pub raw: [u64; 2],
}

impl Lanes {
    pub(super) fn gather(kind: Kind, count: u32, mut read: impl FnMut(u32) -> u64) -> Self {
        let bits = kind.bits();
        let mut value = Self { kind, count: count as u8, raw: [0; 2] };
        for lane in 0..count {
            let offset = lane * bits;
            value.raw[(offset / 64) as usize] |= (read(lane) & mask(bits)) << (offset % 64);
        }
        value
    }

    pub(super) fn lane(self, lane: u32) -> u64 {
        let bits = self.kind.bits();
        let offset = lane * bits;
        (self.raw[(offset / 64) as usize] >> (offset % 64)) & mask(bits)
    }

    pub(super) fn signature(self) -> Signature {
        let mut codes = 0;
        let mut signs = 0;
        let mut low = None;
        let mut high = None;
        let mut magnitudes = 0;
        let mut trailing = 0;
        for lane in 0..u32::from(self.count) {
            let raw = self.lane(lane);
            match self.kind {
                Kind::Ieee { bits } => {
                    let class = ieee_class(u32::from(bits), raw);
                    codes |= u32::from(class) << (lane * 4);
                    signs |= ((raw >> (bits - 1)) as u8) << lane;
                    if let Some(exponent) = normal_exponent(u32::from(bits), raw) {
                        low = Some(low.map_or(exponent, |value: i16| value.min(exponent)));
                        high = Some(high.map_or(exponent, |value: i16| value.max(exponent)));
                    }
                }
                Kind::Integer { bits, signed } => {
                    let (negative, magnitude, zeros) = integer_class(u32::from(bits), signed, raw);
                    signs |= u8::from(negative) << lane;
                    magnitudes |= u64::from(magnitude) << (lane * 7);
                    trailing |= u64::from(zeros) << (lane * 7);
                }
                Kind::Predicate { bits } => {
                    let code = if raw == 0 { 0 } else if raw == mask(u32::from(bits)) { 1 } else { 2 };
                    codes |= code << (lane * 2);
                }
                Kind::Nzcv => codes = raw as u32,
            }
        }
        Signature { kind: self.kind, count: self.count, codes, signs,
            normal_exponent_min: low, normal_exponent_max: high,
            magnitude_bits: magnitudes, trailing_zeros: trailing }
    }
}

/// IEEE classes use four bits/lane; predicate classes use two; integer lengths
/// use seven. These are integer encodings, never host FP conversions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct Signature {
    pub kind: Kind,
    pub count: u8,
    pub codes: u32,
    pub signs: u8,
    pub normal_exponent_min: Option<i16>,
    pub normal_exponent_max: Option<i16>,
    pub magnitude_bits: u64,
    pub trailing_zeros: u64,
}

pub(super) fn mask(bits: u32) -> u64 { u64::MAX >> (64 - bits) }

fn geometry(bits: u32) -> (u32, u32) {
    match bits { 16 => (5, 10), 32 => (8, 23), 64 => (11, 52), _ => unreachable!("IEEE layout width") }
}

pub(super) fn ieee_class(bits: u32, raw: u64) -> u8 {
    let (exponent_bits, fraction_bits) = geometry(bits);
    let exponent = (raw >> fraction_bits) & mask(exponent_bits);
    let fraction = raw & mask(fraction_bits);
    let sign = ((raw >> (bits - 1)) & 1) as u8;
    match (exponent, fraction) {
        (0, 0) => sign,
        (0, _) => 2 + sign,
        (1, _) => 4 + sign,
        (e, 0) if e == mask(exponent_bits) => 8 + sign,
        (e, f) if e == mask(exponent_bits) => if f & (1 << (fraction_bits - 1)) != 0 { 10 } else { 11 },
        _ => 6 + sign,
    }
}

pub(super) fn normal_exponent(bits: u32, raw: u64) -> Option<i16> {
    let (exponent_bits, fraction_bits) = geometry(bits);
    let exponent = (raw >> fraction_bits) & mask(exponent_bits);
    (exponent != 0 && exponent != mask(exponent_bits))
        .then_some(exponent as i16 - ((1 << (exponent_bits - 1)) - 1) as i16)
}

pub(super) fn integer_class(bits: u32, signed: bool, raw: u64) -> (bool, u8, u8) {
    let raw = raw & mask(bits);
    let negative = signed && raw >> (bits - 1) != 0;
    let magnitude = if negative { raw.wrapping_neg() & mask(bits) } else { raw };
    (negative, (64 - magnitude.leading_zeros()) as u8,
        if raw == 0 { bits as u8 } else { raw.trailing_zeros() as u8 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_half_layouts_match_independent_ieee_fields() {
        for raw in 0..=u16::MAX {
            let exponent = (raw >> 10) & 31;
            let fraction = raw & 1023;
            let sign = (raw >> 15) as u8;
            let expected = if exponent == 0 { if fraction == 0 { sign } else { 2 + sign } }
                else if exponent == 31 { if fraction == 0 { 8 + sign } else if fraction & 512 != 0 { 10 } else { 11 } }
                else if exponent == 1 { 4 + sign } else { 6 + sign };
            assert_eq!(ieee_class(16, u64::from(raw)), expected);
        }
    }

    #[test]
    fn integer_extremes_width_masking_and_packed_lanes() {
        for bits in [16, 32, 64] {
            assert_eq!(integer_class(bits, true, 1 << (bits - 1)), (true, bits as u8, (bits - 1) as u8));
            assert_eq!(integer_class(bits, true, u64::MAX), (true, 1, 0));
            assert_eq!(integer_class(bits, false, u64::MAX), (false, bits as u8, 0));
            assert_eq!(integer_class(bits, true, 0), (false, 0, bits as u8));
        }
        let lanes = Lanes::gather(Kind::Ieee { bits: 16 }, 8, |n| u64::from(n) << 12);
        for n in 0..8 { assert_eq!(lanes.lane(n), u64::from(n) << 12); }
        assert_eq!(normal_exponent(64, 0x3ff0_0000_0000_0000), Some(0));
        assert_eq!(ieee_class(32, 0xff80_0001), 11);
        assert_eq!(ieee_class(64, 0x7ff8_0000_0000_0000), 10);
    }
}
