// SPDX-License-Identifier: GPL-2.0-only
// Original Synaptics source notices: ../synaptics.rs and input/THIRD_PARTY.md.
//! Source-checked extended button data, including its target and validity.
use super::Capabilities;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Button0..Button(count-1), in source event order, without padding bits.
    Touchpad(u8),
    /// Source trackstick left/right/middle mapping. Delivery to an associated
    /// child requires its separate owned passthrough binding.
    Trackstick(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extended {
    pub count: u8,
    /// Complete decoded source bitmap, including an odd count's padding bit.
    pub wire_bitmap: u8,
    pub target: Target,
}
pub(super) fn decode(c: &Capabilities, p: [u8; 6]) -> Option<Extended> {
    let count = ((c.extended >> 12) & 15) as u8;
    if count == 0 {
        return None;
    }
    let ext_bit = (p[0] ^ p[3]) & 2 != 0;
    let version = ((c.identity & 15) << 8) | (c.identity >> 16);
    // These firmware versions do not report a release when ExtBit is
    // clear. None preserves that absence of an update; it is not bitmap zero.
    if matches!(version, 0x801 | 0x802) && !ext_bit {
        return None;
    }
    let bits = count.div_ceil(2);
    let mask = (1u8 << bits) - 1;
    let wire_bitmap = if ext_bit {
        (p[4] & mask) | ((p[5] & mask) << bits)
    } else {
        0
    };
    let target = if c.extended_10 & (1 << 16) != 0 {
        Target::Trackstick((wire_bitmap & 1) | ((wire_bitmap & 4) >> 1) | ((wire_bitmap & 2) << 1))
    } else {
        let mut logical = 0;
        for index in 0..bits {
            logical |= ((wire_bitmap >> index) & 1) << (2 * index);
            logical |= ((wire_bitmap >> (index + bits)) & 1) << (2 * index + 1);
        }
        Target::Touchpad(logical & ((1u16 << count) - 1) as u8)
    };
    Some(Extended {
        count,
        wire_bitmap,
        target,
    })
}
