use super::*;

fn word(form: u32, immediate: i32, destination: u32) -> u32 {
    form | ((immediate as u32 & IMMEDIATE_MASK) << IMMEDIATE_SHIFT) | destination
}

#[test]
fn all_forms_destinations_and_signed_displacements_decode() {
    for form in [LDR_W, LDR_X, LDRSW, LDR_S, LDR_D, LDR_Q] {
        for destination in 0..=REGISTER_MASK {
            for immediate in [-262144, -1, 0, 1, 262143] {
                for pc in [0, 0x1004, u64::MAX - 3] {
                    let operand = decode(GuestAddress(pc), word(form, immediate, destination))
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        operand.address,
                        (i128::from(pc) + i128::from(immediate) * 4) as u64
                    );
                    let expected = match form {
                        LDR_W | LDR_X | LDRSW => Transfer::Integer {
                            destination: register(destination, false),
                            width: if form == LDR_W {
                                Width::W32
                            } else {
                                Width::X64
                            },
                            signed: form == LDRSW,
                        },
                        _ => Transfer::Simd {
                            destination: destination as u8,
                            bytes: if form == LDR_S {
                                4
                            } else if form == LDR_D {
                                8
                            } else {
                                16
                            },
                        },
                    };
                    assert_eq!(operand.transfer, expected);
                }
            }
        }
    }
}

#[test]
fn prefetch_reserved_and_neighboring_classes_do_not_become_loads() {
    for unsupported in [0xd8000000, 0xdc000000] {
        assert_eq!(decode(GuestAddress(0), unsupported), Some(Err(())));
    }
    for bit in [24, 25, 27, 28, 29] {
        assert!(decode(GuestAddress(0), LDR_W ^ (1 << bit)).is_none());
    }
}
