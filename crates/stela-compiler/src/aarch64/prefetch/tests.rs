use super::*;

#[test]
fn immediate_forms_preserve_all_hints_bases_and_boundaries() {
    for hint in 0..32 {
        for base in 0..32 {
            for immediate in [0, 1, 15, 16, 4095] {
                let operand = decode(
                    GuestAddress(0),
                    UNSIGNED_FORM | (immediate << 10) | (base << 5) | hint,
                )
                .unwrap()
                .unwrap();
                assert_eq!(operand.hint.encoding(), hint as u8);
                assert_eq!(
                    operand.address,
                    Address::Immediate {
                        base: register(base, true),
                        displacement: (immediate * 8) as i32,
                    }
                );
            }
            for immediate in [-256_i32, -129, -128, -1, 0, 1, 127, 128, 255] {
                let operand = decode(
                    GuestAddress(0),
                    UNSCALED_FORM | ((immediate as u32 & 0x1ff) << 12) | (base << 5) | hint,
                )
                .unwrap()
                .unwrap();
                assert_eq!(operand.hint.encoding(), hint as u8);
                assert_eq!(
                    operand.address,
                    Address::Immediate {
                        base: register(base, true),
                        displacement: immediate,
                    }
                );
            }
        }
    }
}

#[test]
fn register_extensions_scales_and_range_neighbors_are_explicit() {
    for hint in 0..32 {
        for option in 0..8 {
            for scaled in [false, true] {
                for index in [0, 1, 30, 31] {
                    let word = REGISTER_FORM
                        | (index << 16)
                        | (option << 13)
                        | (u32::from(scaled) << 12)
                        | (31 << 5)
                        | hint;
                    let decoded = decode(GuestAddress(0), word);
                    if hint >= 24 {
                        assert_eq!(decoded, None);
                    } else if option & 2 == 0 {
                        assert_eq!(decoded, Some(Err(())));
                    } else {
                        let operand = decoded.unwrap().unwrap();
                        assert_eq!(operand.hint.encoding(), hint as u8);
                        assert_eq!(
                            operand.address,
                            Address::Register {
                                base: Register::Sp,
                                index: register(index, false),
                                extend: IndexExtend::decode(option).unwrap(),
                                shift: if scaled { 3 } else { 0 },
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn literals_use_signed_original_pc_offsets_with_modulo_64_wrap() {
    for hint in 0..32 {
        for immediate in [-262144_i32, -1, 0, 1, 262143] {
            for pc in [0, 0x1004, u64::MAX - 3] {
                let operand = decode(
                    GuestAddress(pc),
                    LITERAL_FORM | ((immediate as u32 & 0x7ffff) << 5) | hint,
                )
                .unwrap()
                .unwrap();
                assert_eq!(operand.hint.encoding(), hint as u8);
                assert_eq!(
                    operand.address,
                    Address::Literal((i128::from(pc) + i128::from(immediate) * 4) as u64)
                );
            }
        }
    }
}

#[test]
fn other_transfers_and_address_modes_do_not_become_prefetches() {
    for word in [
        0xf9400000, // LDR unsigned
        0xf8400000, // LDUR
        0xf8800400, // reserved post-index prefetch neighbor
        0xf8800800, // reserved unprivileged prefetch neighbor
        0xf8800c00, // reserved pre-index prefetch neighbor
        0xf8a00000, // atomic/address-class neighbor
        0x58000000, // LDR literal
        0xdc000000, // reserved SIMD literal
    ] {
        assert_eq!(decode(GuestAddress(0), word), None);
    }
}
