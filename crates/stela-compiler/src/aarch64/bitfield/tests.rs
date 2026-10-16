use super::*;
use crate::{
    GuestAddress, Lifter,
    aarch64::{Decoder, Operation},
};

#[test]
fn complete_immediate_and_width_opcode_space_is_validated_before_lifting() {
    let pc = GuestAddress(0x100000);
    for sf in 0..2 {
        for n in 0..2 {
            for opc in 0..4 {
                for rotation in 0..64 {
                    for mask_end in 0..64 {
                        let word = 0x13000000
                            | (sf << 31)
                            | (opc << 29)
                            | (n << 22)
                            | (rotation << 16)
                            | (mask_end << 10)
                            | (9 << 5)
                            | 17;
                        let valid =
                            n == sf && opc != 3 && (sf == 1 || (rotation < 32 && mask_end < 32));
                        let decoded = decode(word);
                        assert_eq!(decoded.is_some(), valid, "{word:08x}");
                        if valid {
                            let expected = Operand {
                                width: if sf == 0 { Width::W32 } else { Width::X64 },
                                kind: match opc {
                                    0 => Kind::Signed,
                                    1 => Kind::Insert,
                                    _ => Kind::Unsigned,
                                },
                                destination: Register::X(17),
                                source: Register::X(9),
                                rotation: rotation as u8,
                                mask_end: mask_end as u8,
                            };
                            assert_eq!(decoded, Some(expected));
                            let lifted = Decoder.lift(pc, word).unwrap();
                            assert_eq!(lifted.pc, pc);
                            assert_eq!(lifted.operation, Operation::Bitfield(expected));
                        } else {
                            assert!(Decoder.lift(pc, word).is_err(), "{word:08x}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn every_register_pair_preserves_zr_and_overlapping_operand_roles() {
    for sf in 0..2 {
        for (opc, kind) in [Kind::Signed, Kind::Insert, Kind::Unsigned]
            .into_iter()
            .enumerate()
        {
            for destination in 0..32 {
                for source in 0..32 {
                    let word = 0x13000000
                        | (sf << 31)
                        | ((opc as u32) << 29)
                        | (sf << 22)
                        | (3 << 16)
                        | (7 << 10)
                        | (source << 5)
                        | destination;
                    let expected_register = |number| {
                        if number == 31 {
                            Register::Zero
                        } else {
                            Register::X(number as u8)
                        }
                    };
                    assert_eq!(
                        decode(word),
                        Some(Operand {
                            width: if sf == 0 { Width::W32 } else { Width::X64 },
                            kind,
                            destination: expected_register(destination),
                            source: expected_register(source),
                            rotation: 3,
                            mask_end: 7,
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn neighboring_instruction_classes_are_not_bitfield_moves() {
    for base in [
        0x13000000u32,
        0x33000000,
        0x53000000,
        0x93400000,
        0xb3400000,
        0xd3400000,
    ] {
        assert!(decode(base).is_some());
        for bit in 0..32 {
            if 0x1f800000 & (1 << bit) != 0 {
                assert!(decode(base ^ (1 << bit)).is_none());
            }
        }
    }
    for word in [0x92401c20, 0xd2800020, 0x93c20820, 0x9ac22020] {
        // Logical immediate, wide move, extract and variable shift.
        assert!(decode(word).is_none(), "{word:08x}");
    }
}
