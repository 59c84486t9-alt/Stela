//! ADDVL/ADDPL/RDVL and predicate counts (CNTP, INC/DEC by element count).
use super::super::{Register, register, scalable::ElementSize};

const LENGTH_MASK: u32 = 0xffe0_f800;
const READ_LENGTH_MASK: u32 = 0xffff_f800;
const PATTERN_MASK: u32 = 0xff30_fc00;
const SATURATING_PATTERN_MASK: u32 = 0xff20_fc00;
const PREDICATE_MASK: u32 = 0xff3f_fe00;
const COUNT_PREDICATE_MASK: u32 = 0xff3f_c200;
const COUNT_COUNTER_MASK: u32 = 0xff3f_fa00;
const ADDVL: u32 = 0x0420_5000;
const ADDPL: u32 = 0x0460_5000;
const RDVL: u32 = 0x04bf_5000;
const CNT_PATTERN: u32 = 0x0420_e000;
const INC_SCALAR: u32 = 0x0430_e000;
const DEC_SCALAR: u32 = 0x0430_e400;
const INC_VECTOR: u32 = 0x0430_c000;
const DEC_VECTOR: u32 = 0x0430_c400;
const SQINC_SCALAR: u32 = 0x0420_f000;
const UQINC_SCALAR: u32 = 0x0420_f400;
const SQDEC_SCALAR: u32 = 0x0420_f800;
const UQDEC_SCALAR: u32 = 0x0420_fc00;
const SQINC_VECTOR: u32 = 0x0420_c000;
const UQINC_VECTOR: u32 = 0x0420_c400;
const SQDEC_VECTOR: u32 = 0x0420_c800;
const UQDEC_VECTOR: u32 = 0x0420_cc00;
const CNTP: u32 = 0x2520_8000;
const CNTP_COUNTER: u32 = 0x2520_8200;
const INCP_SCALAR: u32 = 0x252c_8800;
const DECP_SCALAR: u32 = 0x252d_8800;
const INCP_VECTOR: u32 = 0x252c_8000;
const DECP_VECTOR: u32 = 0x252d_8000;
const SQINCP_SCALAR32: u32 = 0x2528_8800;
const SQINCP_SCALAR64: u32 = 0x2528_8c00;
const UQINCP_SCALAR32: u32 = 0x2529_8800;
const UQINCP_SCALAR64: u32 = 0x2529_8c00;
const SQDECP_SCALAR32: u32 = 0x252a_8800;
const SQDECP_SCALAR64: u32 = 0x252a_8c00;
const UQDECP_SCALAR32: u32 = 0x252b_8800;
const UQDECP_SCALAR64: u32 = 0x252b_8c00;
const SQINCP_VECTOR: u32 = 0x2528_8000;
const UQINCP_VECTOR: u32 = 0x2529_8000;
const SQDECP_VECTOR: u32 = 0x252a_8000;
const UQDECP_VECTOR: u32 = 0x252b_8000;
const REGISTER_MASK: u32 = 31;
const PREDICATE_REGISTER_MASK: u32 = 15;
const SOURCE_SHIFT: u32 = 16;
const IMMEDIATE_SHIFT: u32 = 5;
const IMMEDIATE_MASK: u32 = 63;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const MULTIPLIER_SHIFT: u32 = 16;
const PREDICATE_SHIFT: u32 = 5;
const GOVERNING_SHIFT: u32 = 10;
const COUNTER_WIDTH_SHIFT: u32 = 10;
const SCALAR64_BIT: u32 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Saturation {
    Wrapping,
    Signed,
    Unsigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Scalar { register: Register, bits: u8 },
    Vector(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    Pattern { pattern: u8, multiplier: u8 },
    Predicate(u8),
    Intersection { governing: u8, source: u8 },
    Counter { source: u8, vectors: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Length {
        source: Option<Register>,
        immediate: i8,
        predicate: bool,
    },
    Count(Count),
    Adjust {
        count: Count,
        subtract: bool,
        saturation: Saturation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: Destination,
    pub element: ElementSize,
    pub kind: Kind,
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let d = word & REGISTER_MASK;
    let scalar = |bits| Destination::Scalar {
        register: register(d, false),
        bits,
    };
    let vector = Destination::Vector(d as u8);
    let element = ElementSize::from_bytes(1 << ((word >> SIZE_SHIFT) & SIZE_MASK))
        .expect("two-bit element size");
    let pattern = Count::Pattern {
        pattern: ((word >> IMMEDIATE_SHIFT) & REGISTER_MASK) as u8,
        multiplier: (((word >> MULTIPLIER_SHIFT) & PREDICATE_REGISTER_MASK) + 1) as u8,
    };
    let predicate = Count::Predicate(((word >> PREDICATE_SHIFT) & PREDICATE_REGISTER_MASK) as u8);
    let adjust = |destination, count, subtract, saturation| Operand {
        destination,
        element,
        kind: Kind::Adjust {
            count,
            subtract,
            saturation,
        },
    };
    if matches!(word & LENGTH_MASK, ADDVL | ADDPL) || word & READ_LENGTH_MASK == RDVL {
        let read = word & READ_LENGTH_MASK == RDVL;
        let imm = ((word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK) as i8;
        return Some(Ok(Operand {
            destination: if read {
                scalar(64)
            } else {
                Destination::Scalar {
                    register: register(d, true),
                    bits: 64,
                }
            },
            element: ElementSize::Byte,
            kind: Kind::Length {
                source: if read {
                    None
                } else {
                    Some(register((word >> SOURCE_SHIFT) & REGISTER_MASK, true))
                },
                immediate: (imm << 2) >> 2,
                predicate: word & LENGTH_MASK == ADDPL,
            },
        }));
    }
    let operand = match word & PATTERN_MASK {
        CNT_PATTERN => Operand {
            destination: scalar(64),
            element,
            kind: Kind::Count(pattern),
        },
        INC_SCALAR | DEC_SCALAR => adjust(
            scalar(64),
            pattern,
            word & PATTERN_MASK == DEC_SCALAR,
            Saturation::Wrapping,
        ),
        INC_VECTOR | DEC_VECTOR | SQINC_VECTOR | UQINC_VECTOR | SQDEC_VECTOR | UQDEC_VECTOR => {
            if element == ElementSize::Byte {
                return Some(Err(()));
            }
            let opcode = word & PATTERN_MASK;
            let subtract = matches!(opcode, DEC_VECTOR | SQDEC_VECTOR | UQDEC_VECTOR);
            let saturation = match opcode {
                SQINC_VECTOR | SQDEC_VECTOR => Saturation::Signed,
                UQINC_VECTOR | UQDEC_VECTOR => Saturation::Unsigned,
                _ => Saturation::Wrapping,
            };
            adjust(vector, pattern, subtract, saturation)
        }
        _ => match word & SATURATING_PATTERN_MASK {
            SQINC_SCALAR | UQINC_SCALAR | SQDEC_SCALAR | UQDEC_SCALAR => {
                let opcode = word & SATURATING_PATTERN_MASK;
                let bits = if word & SCALAR64_BIT == 0 { 32 } else { 64 };
                adjust(
                    scalar(bits),
                    pattern,
                    matches!(opcode, SQDEC_SCALAR | UQDEC_SCALAR),
                    if matches!(opcode, SQINC_SCALAR | SQDEC_SCALAR) {
                        Saturation::Signed
                    } else {
                        Saturation::Unsigned
                    },
                )
            }
            _ => {
                if word & COUNT_PREDICATE_MASK == CNTP {
                    Operand {
                        destination: scalar(64),
                        element,
                        kind: Kind::Count(Count::Intersection {
                            governing: ((word >> GOVERNING_SHIFT) & PREDICATE_REGISTER_MASK) as u8,
                            source: ((word >> PREDICATE_SHIFT) & PREDICATE_REGISTER_MASK) as u8,
                        }),
                    }
                } else if word & COUNT_COUNTER_MASK == CNTP_COUNTER {
                    Operand {
                        destination: scalar(64),
                        element,
                        kind: Kind::Count(Count::Counter {
                            source: ((word >> PREDICATE_SHIFT) & PREDICATE_REGISTER_MASK) as u8,
                            vectors: (2 << ((word >> COUNTER_WIDTH_SHIFT) & 1)) as u8,
                        }),
                    }
                } else {
                    let opcode = word & PREDICATE_MASK;
                    let (destination, subtract, saturation) = match opcode {
                        INCP_SCALAR => (scalar(64), false, Saturation::Wrapping),
                        DECP_SCALAR => (scalar(64), true, Saturation::Wrapping),
                        INCP_VECTOR => (vector, false, Saturation::Wrapping),
                        DECP_VECTOR => (vector, true, Saturation::Wrapping),
                        SQINCP_SCALAR32 => (scalar(32), false, Saturation::Signed),
                        SQINCP_SCALAR64 => (scalar(64), false, Saturation::Signed),
                        UQINCP_SCALAR32 => (scalar(32), false, Saturation::Unsigned),
                        UQINCP_SCALAR64 => (scalar(64), false, Saturation::Unsigned),
                        SQDECP_SCALAR32 => (scalar(32), true, Saturation::Signed),
                        SQDECP_SCALAR64 => (scalar(64), true, Saturation::Signed),
                        UQDECP_SCALAR32 => (scalar(32), true, Saturation::Unsigned),
                        UQDECP_SCALAR64 => (scalar(64), true, Saturation::Unsigned),
                        SQINCP_VECTOR => (vector, false, Saturation::Signed),
                        UQINCP_VECTOR => (vector, false, Saturation::Unsigned),
                        SQDECP_VECTOR => (vector, true, Saturation::Signed),
                        UQDECP_VECTOR => (vector, true, Saturation::Unsigned),
                        _ => return None,
                    };
                    if matches!(destination, Destination::Vector(_)) && element == ElementSize::Byte
                    {
                        return Some(Err(()));
                    }
                    adjust(destination, predicate, subtract, saturation)
                }
            }
        },
    };
    Some(Ok(operand))
}

#[cfg(test)]
mod tests {
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
}
