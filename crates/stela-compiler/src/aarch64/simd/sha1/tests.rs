use super::*;

#[test]
fn exact_forms_accept_all_registers_and_decline_fixed_bit_mutations() {
    for (base, mask, kind) in [
        (SHA1C, THREE_REGISTER_MASK, Kind::Choose),
        (SHA1P, THREE_REGISTER_MASK, Kind::Parity),
        (SHA1M, THREE_REGISTER_MASK, Kind::Majority),
        (SHA1SU0, THREE_REGISTER_MASK, Kind::Schedule0),
        (SHA1H, TWO_REGISTER_MASK, Kind::Rotate),
        (SHA1SU1, TWO_REGISTER_MASK, Kind::Schedule1),
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
        // The fixed size/Q/top-level bits must not broaden this family.
        for bit in [22, 23, 24, 25, 26, 27, 28, 29, 30, 31] {
            assert!(decode(base ^ (1 << bit)).is_none());
        }
    }
}
