use super::*;

mod execution_access;

#[test]
fn vector_group_fields_preserve_nonconsecutive_registers_and_counter_role() {
    for four in [false, true] {
        for high in [false, true] {
            for low in 0..=if four {
                FOUR_REGISTER_LOW_MASK
            } else {
                TWO_REGISTER_LOW_MASK
            } {
                for size in 0..=SIZE_MASK {
                    for predicate in 0..=PREDICATE_MASK {
                        let word = VECTOR_GROUP_CLASS
                            | (size << SIZE_SHIFT)
                            | (predicate << PREDICATE_SHIFT)
                            | (REGISTER_MASK << BASE_SHIFT)
                            | low
                            | if four { FOUR_REGISTERS_BIT } else { 0 }
                            | if high { HIGH_REGISTER_BIT } else { 0 };
                        let Some(Operand::Vectors(transfer)) = decode(word) else {
                            panic!("allocated vector group {word:08x}");
                        };
                        assert_eq!(
                            transfer.registers,
                            VectorGroup {
                                first: low as u8 + if high { HIGH_REGISTER_BASE } else { 0 },
                                count: if four { 4 } else { 2 },
                                stride: if four { 4 } else { 8 },
                            }
                        );
                        assert_eq!(transfer.predicate, COUNTER_PREDICATE_BASE + predicate as u8);
                        assert_eq!(transfer.element.bytes(), 1 << size);
                        assert_eq!(transfer.address.base, Register::Sp);
                    }
                }
            }
        }
    }
}

#[test]
fn signed_group_offsets_and_register_zero_are_distinct() {
    for raw in 0..=IMMEDIATE_MASK {
        let Some(Operand::Vectors(transfer)) =
            decode(VECTOR_GROUP_CLASS | IMMEDIATE_BIT | (raw << OFFSET_SHIFT))
        else {
            panic!()
        };
        let expected = if raw < (1 << (IMMEDIATE_BITS - 1)) {
            raw as i8
        } else {
            raw as i8 - (1 << IMMEDIATE_BITS)
        };
        assert_eq!(transfer.address.offset, Offset::VectorGroups(expected));
    }
    let Some(Operand::Vectors(transfer)) =
        decode(VECTOR_GROUP_CLASS | (REGISTER_MASK << OFFSET_SHIFT))
    else {
        panic!()
    };
    assert_eq!(transfer.address.offset, Offset::Register(Register::Zero));
    assert!(decode(VECTOR_GROUP_CLASS | IMMEDIATE_BIT | IMMEDIATE_RESERVED_BIT).is_none());
    assert!(
        decode(VECTOR_GROUP_CLASS | FOUR_REGISTERS_BIT | FOUR_REGISTERS_RESERVED_BIT).is_none()
    );
}

#[test]
fn za_tiles_split_the_low_selector_by_element_width() {
    for (class, bytes) in [
        (TILE_BYTE_CLASS, 1_u8),
        (TILE_HALFWORD_CLASS, 2),
        (TILE_WORD_CLASS, 4),
        (TILE_DOUBLEWORD_CLASS, 8),
        (TILE_QUADWORD_CLASS, 16),
    ] {
        for store in [0, STORE_BIT] {
            for selector in 0..=IMMEDIATE_MASK {
                let word = class
                    | store
                    | selector
                    | VERTICAL_BIT
                    | (SLICE_SELECTOR_MASK << SLICE_SELECTOR_SHIFT)
                    | (PREDICATE_MASK << PREDICATE_SHIFT)
                    | (REGISTER_MASK << BASE_SHIFT)
                    | (REGISTER_MASK << OFFSET_SHIFT);
                let Some(Operand::Tile(tile)) = decode(word) else {
                    panic!()
                };
                assert_eq!(tile.element.bytes(), usize::from(bytes));
                assert_eq!(tile.tile, selector as u8 / (16 / bytes));
                assert_eq!(tile.slice_offset, selector as u8 % (16 / bytes));
                assert_eq!(tile.slice_register, 15);
                assert_eq!(tile.predicate, 7);
                assert!(tile.vertical);
                assert_eq!(tile.address.base, Register::Sp);
                assert_eq!(tile.address.offset, Offset::Register(Register::Zero));
            }
        }
    }
    for reserved in [0xe100_0000, 0xe140_0000, 0xe180_0000] {
        assert!(!matches!(decode(reserved), Some(Operand::Tile(_))));
    }
}

#[test]
fn whole_za_and_zt_transfers_keep_distinct_selector_contracts() {
    for store in [0, STORE_BIT] {
        let direction = direction(store);
        let base = Register::Sp;
        assert_eq!(
            decode(ZT_CLASS | store | (REGISTER_MASK << BASE_SHIFT)),
            Some(Operand::Zt(ZtTransfer { direction, base }))
        );
        assert_eq!(
            decode(
                ZA_VECTOR_CLASS
                    | store
                    | (REGISTER_MASK << BASE_SHIFT)
                    | (SLICE_SELECTOR_MASK << SLICE_SELECTOR_SHIFT)
                    | IMMEDIATE_MASK
            ),
            Some(Operand::ZaVector(ZaVectorTransfer {
                direction,
                base,
                vector_register: 15,
                offset: 15,
            }))
        );
    }
}
