use super::*;

#[test]
fn all_immediates_and_register_roles() {
    for encoded in 0..=IMMEDIATE_MASK {
        let immediate = if encoded & IMMEDIATE_SIGN == 0 {
            encoded as i8
        } else {
            (encoded as i32 - (1 << IMMEDIATE_BITS)) as i8
        };
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                for (opcode, scale) in [(ADDSPL, Scale::Predicate), (ADDSVL, Scale::Vector)] {
                    assert_eq!(
                        decode(
                            opcode
                                | (source << SOURCE_SHIFT)
                                | (encoded << IMMEDIATE_SHIFT)
                                | destination
                        ),
                        Some(Operand {
                            destination: register(destination, true),
                            immediate,
                            kind: Kind::Add {
                                source: register(source, true),
                                scale
                            },
                        })
                    );
                }
            }
            assert_eq!(
                decode(RDSVL | (encoded << IMMEDIATE_SHIFT) | destination),
                Some(Operand {
                    destination: register(destination, false),
                    immediate,
                    kind: Kind::Read,
                })
            );
        }
    }
}

#[test]
fn fixed_bits_exclude_unrelated_forms() {
    for (opcode, mask) in [
        (ADDSPL, ADD_LENGTH_MASK),
        (ADDSVL, ADD_LENGTH_MASK),
        (RDSVL, READ_LENGTH_MASK),
    ] {
        for bit in 0..u32::BITS {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let changed = opcode ^ (1 << bit);
            let belongs = [ADDSPL, ADDSVL].contains(&(changed & ADD_LENGTH_MASK))
                || changed & READ_LENGTH_MASK == RDSVL;
            assert_eq!(decode(changed).is_some(), belongs);
        }
    }
}
