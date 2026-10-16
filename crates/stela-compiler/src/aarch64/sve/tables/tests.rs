use super::*;
#[test]
fn all_forms_and_parts() {
    for (base, count, id) in [
        (LUTI2_BYTE, 4, "luti2_z_zz_8"),
        (LUTI2_HALF, 8, "luti2_z_zz_16"),
        (LUTI4_BYTE, 2, "luti4_z_zz_8"),
        (LUTI4_HALF_PAIR, 4, "luti4_z_zz_2x16"),
        (LUTI4_HALF_SINGLE, 4, "luti4_z_zz_1x16"),
    ] {
        for part in 0..count {
            let encoded = if base == LUTI2_HALF {
                ((part >> 1) << PART_SHIFT) | ((part & 1) << PART_LOW_SHIFT)
            } else if base == LUTI4_BYTE {
                part << 23
            } else {
                part << PART_SHIFT
            };
            let op = decode(base | encoded | 31 | (31 << TABLE_SHIFT) | (31 << INDEX_SHIFT))
                .unwrap()
                .unwrap();
            assert_eq!(op.part, part as u8);
            assert_eq!(op.canonical_id(), id);
            assert_eq!(op.table, 31);
        }
    }
    assert!(decode(0).is_none());
}
