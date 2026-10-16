use super::*;

#[test]
fn generic_code_preserves_all_register_roles() {
    for destination in 0..=REGISTER_MASK {
        for source in 0..=REGISTER_MASK {
            for modifier in 0..=REGISTER_MASK {
                let word =
                    PACGA | destination | (source << SOURCE_SHIFT) | (modifier << MODIFIER_SHIFT);
                assert_eq!(
                    decode(word),
                    Some(Instruction::GenericCode(GenericCode {
                        destination: destination as u8,
                        source: source as u8,
                        modifier: modifier as u8,
                    }))
                );
            }
        }
    }
}

#[test]
fn loads_cover_complete_offsets_keys_writeback_and_register_roles() {
    for key in [0, LOAD_KEY_B] {
        for writeback in [0, LOAD_WRITEBACK] {
            for immediate in 0..(LOAD_SIGN_VALUE as u32 * 2) {
                let offset = (immediate as i32
                    - if immediate < LOAD_SIGN_VALUE as u32 {
                        0
                    } else {
                        LOAD_SIGN_VALUE * 2
                    })
                    * (1 << LOAD_SCALE);
                let fields = ((immediate & LOAD_IMMEDIATE_MASK) << LOAD_IMMEDIATE_SHIFT)
                    | if immediate & LOAD_SIGN_VALUE as u32 == 0 {
                        0
                    } else {
                        LOAD_SIGN
                    };
                for (base, destination) in [(0, 1), (1, 1), (30, 31), (31, 0), (31, 31)] {
                    let word =
                        LOAD | key | writeback | fields | (base << SOURCE_SHIFT) | destination;
                    let Some(Instruction::Load(load)) = decode(word) else {
                        panic!("load declined")
                    };
                    assert_eq!(load.displacement, offset);
                    assert_eq!(load.base, base as u8);
                    assert_eq!(load.destination, destination as u8);
                    assert_eq!(load.key, if key == 0 { DataKey::A } else { DataKey::B });
                    assert_eq!(load.writeback, writeback != 0);
                    assert_eq!(
                        load.undefined_overlap(),
                        writeback != 0 && base == destination && base != REGISTER_MASK
                    );
                }
            }
        }
    }
}

#[test]
fn reserved_fixed_neighbors_decline() {
    for fixed in 0..u32::BITS {
        let bit = 1 << fixed;
        for (mask, opcode) in [(PACGA_MASK, PACGA), (LOAD_MASK, LOAD)] {
            if mask & bit != 0 {
                assert_eq!(decode(opcode ^ bit), None);
            }
        }
    }
}
