use super::*;

const FORMS: [(u32, u32, Kind); 4] = [
    (
        SIGNED_MINIMUM_REGISTER,
        SIGNED_MINIMUM_IMMEDIATE,
        Kind::SignedMinimum,
    ),
    (
        SIGNED_MAXIMUM_REGISTER,
        SIGNED_MAXIMUM_IMMEDIATE,
        Kind::SignedMaximum,
    ),
    (
        UNSIGNED_MINIMUM_REGISTER,
        UNSIGNED_MINIMUM_IMMEDIATE,
        Kind::UnsignedMinimum,
    ),
    (
        UNSIGNED_MAXIMUM_REGISTER,
        UNSIGNED_MAXIMUM_IMMEDIATE,
        Kind::UnsignedMaximum,
    ),
];

#[test]
fn every_register_field_including_zero_is_allocated() {
    for (opcode, _, kind) in FORMS {
        for (width_bit, width) in [(0, Width::W32), (WIDTH_BIT, Width::X64)] {
            for destination in 0..=REGISTER_MASK {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        assert_eq!(
                            decode(
                                opcode
                                    | width_bit
                                    | destination
                                    | (left << LEFT_SHIFT)
                                    | (right << RIGHT_SHIFT)
                            ),
                            Some(Operand {
                                kind,
                                width,
                                destination: register(destination, false),
                                left: register(left, false),
                                right: Right::Register(register(right, false)),
                            })
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn every_immediate_and_each_register_role_retains_raw_bits() {
    for (_, opcode, kind) in FORMS {
        for (width_bit, width) in [(0, Width::W32), (WIDTH_BIT, Width::X64)] {
            for immediate in 0..=u8::MAX {
                for destination in 0..=REGISTER_MASK {
                    for left in [destination, REGISTER_MASK - destination, REGISTER_MASK] {
                        assert_eq!(
                            decode(
                                opcode
                                    | width_bit
                                    | destination
                                    | (left << LEFT_SHIFT)
                                    | (u32::from(immediate) << IMMEDIATE_SHIFT)
                            ),
                            Some(Operand {
                                kind,
                                width,
                                destination: register(destination, false),
                                left: register(left, false),
                                right: Right::Immediate(immediate),
                            })
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn neighboring_integer_classes_are_not_claimed() {
    for word in [0x1ac0_2000, 0x1ac0_7000, 0x11d0_0000, 0x1180_0000] {
        assert!(decode(word).is_none());
        assert!(decode(word | WIDTH_BIT).is_none());
    }
}
