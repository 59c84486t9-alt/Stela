use super::*;

#[test]
fn exact_forms_accept_all_registers_and_keep_hash_parts_distinct() {
    for (base, mask, kind) in [
        (SHA256H, THREE_REGISTER_MASK, Kind::Hash),
        (SHA256H2, THREE_REGISTER_MASK, Kind::Hash2),
        (SHA256SU0, TWO_REGISTER_MASK, Kind::Schedule0),
        (SHA256SU1, THREE_REGISTER_MASK, Kind::Schedule1),
    ] {
        for destination in 0..32 {
            for left in 0..32 {
                for right in 0..if mask == THREE_REGISTER_MASK { 32 } else { 1 } {
                    let operand = decode(
                        base | destination
                            | (left << LEFT_REGISTER_SHIFT)
                            | (right << RIGHT_REGISTER_SHIFT),
                    )
                    .unwrap();
                    assert_eq!(operand.kind, kind);
                    assert_eq!(operand.destination, destination as u8);
                    assert_eq!(operand.left, left as u8);
                    if mask == THREE_REGISTER_MASK {
                        assert_eq!(operand.right, right as u8);
                    }
                }
            }
        }
        for bit in [22, 23, 24, 25, 26, 27, 28, 29, 30, 31] {
            assert!(decode(base ^ (1 << bit)).is_none());
        }
    }
}
