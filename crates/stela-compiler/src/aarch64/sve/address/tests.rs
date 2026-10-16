use super::*;

#[test]
fn all_canonical_forms_and_destination_roles_decode() {
    let representatives = [
        0x04605000, 0x04205000, 0x0420e000, 0x04e0e000, 0x0460e000, 0x25208000, 0x25208200,
        0x04a0e000, 0x0430e400, 0x04f0e400, 0x04f0c400, 0x0470e400, 0x0470c400, 0x252d8800,
        0x256d8000, 0x04b0e400, 0x04b0c400, 0x0430e000, 0x04f0e000, 0x04f0c000, 0x0470e000,
        0x0470c000, 0x252c8800, 0x256c8000, 0x04b0e000, 0x04b0c000, 0x04bf5000, 0x0420f800,
        0x0430f800, 0x04e0f800, 0x04f0f800, 0x04e0c800, 0x0460f800, 0x0470f800, 0x0460c800,
        0x252a8800, 0x252a8c00, 0x256a8000, 0x04a0f800, 0x04b0f800, 0x04a0c800, 0x0420f000,
        0x0430f000, 0x04e0f000, 0x04f0f000, 0x04e0c000, 0x0460f000, 0x0470f000, 0x0460c000,
        0x25288800, 0x25288c00, 0x25688000, 0x04a0f000, 0x04b0f000, 0x04a0c000, 0x0420fc00,
        0x0430fc00, 0x04e0fc00, 0x04f0fc00, 0x04e0cc00, 0x0460fc00, 0x0470fc00, 0x0460cc00,
        0x252b8800, 0x252b8c00, 0x256b8000, 0x04a0fc00, 0x04b0fc00, 0x04a0cc00, 0x0420f400,
        0x0430f400, 0x04e0f400, 0x04f0f400, 0x04e0c400, 0x0460f400, 0x0470f400, 0x0460c400,
        0x25298800, 0x25298c00, 0x25698000, 0x04a0f400, 0x04b0f400, 0x04a0c400,
    ];
    assert_eq!(representatives.len(), 83);
    for word in representatives {
        for destination in 0..=REGISTER_MASK {
            let operand = decode(word | destination)
                .expect("allocated class")
                .expect("allocated width");
            match operand.destination {
                Destination::Scalar {
                    register: actual, ..
                } => {
                    assert_eq!(
                        actual,
                        register(
                            destination,
                            matches!(
                                operand.kind,
                                Kind::Length {
                                    source: Some(_),
                                    ..
                                }
                            )
                        )
                    );
                }
                Destination::Vector(actual) => assert_eq!(actual, destination as u8),
            }
        }
    }
}

#[test]
fn vector_byte_widths_are_explicitly_reserved() {
    for word in [
        INC_VECTOR,
        DEC_VECTOR,
        SQINC_VECTOR,
        UQINC_VECTOR,
        SQDEC_VECTOR,
        UQDEC_VECTOR,
        INCP_VECTOR,
        DECP_VECTOR,
        SQINCP_VECTOR,
        UQINCP_VECTOR,
        SQDECP_VECTOR,
        UQDECP_VECTOR,
    ] {
        assert_eq!(decode(word), Some(Err(())));
    }
}

#[test]
fn all_signed_length_immediates_preserve_sp_roles() {
    for opcode in [ADDVL, ADDPL, RDVL] {
        for immediate in 0..=IMMEDIATE_MASK {
            let word = opcode | immediate << IMMEDIATE_SHIFT | REGISTER_MASK;
            let operand = decode(word).unwrap().unwrap();
            let Kind::Length {
                immediate: actual, ..
            } = operand.kind
            else {
                panic!("length class");
            };
            let expected = if immediate < 32 {
                immediate as i8
            } else {
                immediate as i8 - 64
            };
            assert_eq!(actual, expected);
            assert_eq!(
                operand.destination,
                Destination::Scalar {
                    register: if opcode == RDVL {
                        Register::Zero
                    } else {
                        Register::Sp
                    },
                    bits: 64,
                }
            );
        }
    }
}

#[test]
fn counter_has_all_sixteen_predicate_registers_and_both_widths() {
    for source in 0..=PREDICATE_REGISTER_MASK {
        for width in 0..=1 {
            let operand =
                decode(CNTP_COUNTER | source << PREDICATE_SHIFT | width << COUNTER_WIDTH_SHIFT)
                    .unwrap()
                    .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Count(Count::Counter {
                    source: source as u8,
                    vectors: 2 << width
                })
            );
        }
    }
}
