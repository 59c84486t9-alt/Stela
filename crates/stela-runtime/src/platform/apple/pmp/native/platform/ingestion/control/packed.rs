//! Exact source register-width arithmetic, with no synthetic observations.
pub(super) fn local_field(value: u64, start: u32, width: u32) -> u32 {
    let mask = u64::MAX.wrapping_shl(width & 63) ^ u64::from(u32::MAX);
    (value.wrapping_shr(start & 63) & mask) as u32
}
pub(super) fn local(
    old_scratch: u32,
    value: u32,
    width: u32,
    extended: bool,
    offset: u16,
) -> (u32, u32) {
    let (mask, nibble, valid) = if width == 32 {
        (0x7fff, 0, 1 << 31)
    } else {
        (0x7ff0, 15, 1 << 15)
    };
    let mut packed = (old_scratch & 0xfff0_8000) | ((value & nibble) << 16) | (value & mask);
    packed = (packed & !(1 << 20))
        | if extended || value & valid != 0 {
            1 << 20
        } else {
            0
        };
    // Source writes scratch BEFORE adding the configured low15 offset.
    (
        packed,
        (packed & !0x7fff) | (packed.wrapping_add(u32::from(offset)) & 0x7fff),
    )
}
pub(super) fn mapped(old: u32, value: u32, offset: u16) -> u32 {
    (old & 0xffe0_8000)
        | (value & 0xf0000)
        | ((value >> 31) << 20)
        | (value.wrapping_add(u32::from(offset)) & 0x7fff)
}
pub(super) fn member_word(value: u32, offset: u16) -> u16 {
    (value as u16 & 0x8000) | (value.wrapping_add(u32::from(offset)) as u16 & 0x7fff)
}
pub(super) fn extended_field(value: u64, start: u32, width: u32) -> u32 {
    (value.wrapping_shr(start & 63) as u32) & !u32::MAX.wrapping_shl(width & 31)
}
pub(super) fn signed15(value: u32) -> i32 {
    ((value << 17) as i32) >> 17
}
pub(super) fn threshold(value: i32, limit: u32) -> u8 {
    // SCVTF signed15/64 is exact. UCVTF u32 is also exact in the only
    // comparable range0..255; larger unsigned thresholds are always higher.
    u8::from(value >= 0 && limit <= 255 && value >= (limit * 64) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packed_widths_opaque_bits_and_offsets_follow_w32_operations() {
        let (scratch, result) = local(0xa5c0_8000, 0x8ab3, 16, false, 0x7fff);
        assert_eq!(scratch, 0xa5d3_8ab0);
        assert_eq!(result, 0xa5d3_8aaf);
        let (_, result) = local(0, 0x8000_7fff, 32, false, 2);
        assert_eq!(result, 0x10_0001);
        assert_eq!(mapped(0xabcd_9876, 0x800a_7ffe, 5), 0xabda_8003);
        assert_eq!(member_word(0x8000_ffff, 2), 0x8001);
        assert_eq!(local_field(u64::MAX, 0, 32), u32::MAX);
        assert_eq!(extended_field(u64::MAX, 64, 32), 0); // LSL W32 shift modulo32.
    }
    #[test]
    fn signed_fixed_fraction_compares_without_unqualified_host_fp_state() {
        assert_eq!(signed15(0x4000), -16384);
        assert_eq!(signed15(0x3fff), 16383);
        assert_eq!(threshold(-1, 0), 0);
        assert_eq!(threshold(64, 1), 1);
        assert_eq!(threshold(63, 1), 0);
        assert_eq!(threshold(16383, 255), 1);
        assert_eq!(threshold(16383, 256), 0);
        assert_eq!(threshold(16383, u32::MAX), 0);
    }
}
