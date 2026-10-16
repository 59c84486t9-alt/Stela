use super::*;

#[test]
fn compact_masks_keep_only_group_leading_bits() {
    assert_eq!(compact_mask(2, 1), 0x5555_5555_5555_5555);
    assert_eq!(compact_mask(2, 16), 0x0000_ffff_0000_ffff);
    assert_eq!(compact_mask(4, 2), 0x0303_0303_0303_0303);
    assert_eq!(compact_mask(4, 16), 0xffff);
}
