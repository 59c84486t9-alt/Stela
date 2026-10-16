use super::*;

const FORMS: [(u32, bool, u8, bool); 10] = [
    (STNP_W, false, DWORD_BYTES, false),
    (LDNP_W, true, DWORD_BYTES, false),
    (STNP_X, false, QWORD_BYTES, false),
    (LDNP_X, true, QWORD_BYTES, false),
    (STNP_S, false, DWORD_BYTES, true),
    (LDNP_S, true, DWORD_BYTES, true),
    (STNP_D, false, QWORD_BYTES, true),
    (LDNP_D, true, QWORD_BYTES, true),
    (STNP_Q, false, VECTOR_BYTES, true),
    (LDNP_Q, true, VECTOR_BYTES, true),
];

fn word(form: u32, immediate: i32, data: [u32; 2], base: u32) -> u32 {
    form | ((immediate as u32 & IMMEDIATE_MASK) << IMMEDIATE_SHIFT)
        | (data[1] << SECOND_DATA_SHIFT)
        | (base << BASE_SHIFT)
        | data[0]
}

#[test]
fn all_forms_register_roles_and_aliases_are_explicit() {
    for (form, load, bytes, vector) in FORMS {
        for first in 0..=REGISTER_MASK {
            for second in 0..=REGISTER_MASK {
                for base in 0..=REGISTER_MASK {
                    let result = decode(word(form, 0, [first, second], base)).unwrap();
                    if load && first == second {
                        assert_eq!(result, Err(()));
                        continue;
                    }
                    assert_eq!(
                        result,
                        Ok(Operand {
                            load,
                            bytes,
                            data: if vector {
                                Data::Vector([first as u8, second as u8])
                            } else {
                                Data::Integer([register(first, false), register(second, false)])
                            },
                            base: register(base, true),
                            displacement: 0,
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn every_signed_immediate_scales_by_element_width() {
    for (form, _, bytes, _) in FORMS {
        for immediate in -64..64 {
            let operand = decode(word(form, immediate, [31, 0], 31)).unwrap().unwrap();
            assert_eq!(operand.displacement, immediate * i32::from(bytes));
            assert_eq!(operand.base, Register::Sp);
        }
    }
}

#[test]
fn reserved_sizes_and_other_pair_address_modes_are_not_reinterpreted() {
    for form in [
        0x68000000, 0x68400000, 0xe8000000, 0xe8400000, 0xec000000, 0xec400000,
    ] {
        assert_eq!(decode(form | (1 << SECOND_DATA_SHIFT)), Some(Err(())));
    }
    for (form, _, _, _) in FORMS {
        for fixed_bit in [23, 24, 25, 27, 28, 29] {
            assert!(decode(form ^ (1 << fixed_bit)).is_none());
        }
    }
    for neighbor in [0xf9000000, 0xf8200800, 0xf9800000, 0xc85f7c00] {
        assert!(decode(neighbor).is_none());
    }
}
