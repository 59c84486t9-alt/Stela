use super::*;

const STORE_CLASSES: [(u32, StoreKind); 4] = [
    (STG, StoreKind::Tag),
    (ST2G, StoreKind::TagPair),
    (STZG, StoreKind::ZeroTag),
    (STZ2G, StoreKind::ZeroTagPair),
];
const STORE_MODES: [(u32, AddressMode); 3] = [
    (POST_INDEX, AddressMode::PostIndex),
    (OFFSET, AddressMode::Offset),
    (PRE_INDEX, AddressMode::PreIndex),
];
const PAIR_CLASSES: [(u32, AddressMode); 3] = [
    (STGP_OFFSET, AddressMode::Offset),
    (STGP_PRE, AddressMode::PreIndex),
    (STGP_POST, AddressMode::PostIndex),
];

#[test]
fn random_tag_all_registers_preserve_sp_and_zero_roles() {
    for destination in 0..=REGISTER_MASK {
        for address in 0..=REGISTER_MASK {
            for mask in 0..=REGISTER_MASK {
                let word =
                    IRG | (mask << RANDOM_MASK_SHIFT) | (address << BASE_SHIFT) | destination;
                assert_eq!(
                    decode(word),
                    Some(Operand::RandomTag {
                        destination: register(destination, true),
                        address: register(address, true),
                        mask: register(mask, false),
                    })
                );
            }
        }
    }
}

#[test]
fn load_and_tag_store_immediates_include_signed_extremes() {
    for immediate in 0..(1 << IMMEDIATE_BITS) {
        let offset = if immediate & (1 << (IMMEDIATE_BITS - 1)) == 0 {
            immediate as i32
        } else {
            immediate as i32 - (1 << IMMEDIATE_BITS)
        } << TAG_GRANULE_SHIFT;
        let fields = (immediate << IMMEDIATE_SHIFT) | (REGISTER_MASK << BASE_SHIFT) | REGISTER_MASK;
        assert_eq!(
            decode(LDG | fields),
            Some(Operand::LoadTag {
                destination: Register::Zero,
                base: Register::Sp,
                displacement: offset,
            })
        );
        for (opcode, kind) in STORE_CLASSES {
            for (mode_bits, mode) in STORE_MODES {
                assert_eq!(
                    decode(opcode | (mode_bits << STORE_MODE_SHIFT) | fields),
                    Some(Operand::StoreTags {
                        kind,
                        source: Register::Sp,
                        base: Register::Sp,
                        displacement: offset,
                        mode,
                    })
                );
            }
        }
    }
}

#[test]
fn tag_store_aliases_and_load_data_registers_are_allocated() {
    for data in 0..=REGISTER_MASK {
        for base in 0..=REGISTER_MASK {
            let fields = (base << BASE_SHIFT) | data;
            assert_eq!(
                decode(LDG | fields),
                Some(Operand::LoadTag {
                    destination: register(data, false),
                    base: register(base, true),
                    displacement: 0,
                })
            );
            for (opcode, kind) in STORE_CLASSES {
                for (mode_bits, mode) in STORE_MODES {
                    assert_eq!(
                        decode(opcode | (mode_bits << STORE_MODE_SHIFT) | fields),
                        Some(Operand::StoreTags {
                            kind,
                            source: register(data, true),
                            base: register(base, true),
                            displacement: 0,
                            mode,
                        })
                    );
                }
            }
        }
    }
}

#[test]
fn pair_all_registers_and_writeback_aliases_are_allocated() {
    for first in 0..=REGISTER_MASK {
        for second in 0..=REGISTER_MASK {
            for base in 0..=REGISTER_MASK {
                for (opcode, mode) in PAIR_CLASSES {
                    assert_eq!(
                        decode(opcode | (second << SECOND_SHIFT) | (base << BASE_SHIFT) | first),
                        Some(Operand::StorePair {
                            data: [register(first, false), register(second, false)],
                            base: register(base, true),
                            displacement: 0,
                            mode,
                        })
                    );
                }
            }
        }
    }
    for immediate in 0..(1 << PAIR_IMMEDIATE_BITS) {
        let offset = if immediate & (1 << (PAIR_IMMEDIATE_BITS - 1)) == 0 {
            immediate as i32
        } else {
            immediate as i32 - (1 << PAIR_IMMEDIATE_BITS)
        } << TAG_GRANULE_SHIFT;
        for (opcode, mode) in PAIR_CLASSES {
            assert_eq!(
                decode(opcode | (immediate << PAIR_IMMEDIATE_SHIFT)),
                Some(Operand::StorePair {
                    data: [Register::X(0), Register::X(0)],
                    base: Register::X(0),
                    displacement: offset,
                    mode,
                })
            );
        }
    }
}

#[test]
fn bulk_privilege_is_an_execution_requirement_and_data31_is_zero() {
    for (opcode, kind) in [
        (LDGM, BulkKind::Load),
        (STGM, BulkKind::Store),
        (STZGM, BulkKind::StoreZero),
    ] {
        for data in 0..=REGISTER_MASK {
            for base in 0..=REGISTER_MASK {
                let expected = Operand::BulkTags {
                    kind,
                    data: register(data, false),
                    base: register(base, true),
                };
                assert!(expected.requires_privilege());
                assert_eq!(decode(opcode | (base << BASE_SHIFT) | data), Some(expected));
            }
        }
    }
    assert!(!decode(IRG).unwrap().requires_privilege());
    assert!(!decode(LDG).unwrap().requires_privilege());
    assert!(
        !decode(STG | (OFFSET << STORE_MODE_SHIFT))
            .unwrap()
            .requires_privilege()
    );
    assert!(!decode(STGP_OFFSET).unwrap().requires_privilege());
}

#[test]
fn reserved_zero_mode_tag_stores_do_not_become_bulk_immediates() {
    for opcode in [STG, ST2G, STZ2G] {
        for immediate in 1..(1 << IMMEDIATE_BITS) {
            assert!(decode(opcode | (immediate << IMMEDIATE_SHIFT)).is_none());
        }
    }
    for word in [0, u32::MAX, 0xd503_201f, 0xd960_0400 ^ (1 << 21)] {
        assert!(decode(word).is_none());
    }
}

#[test]
fn allocated_decodes_validate_but_malformed_public_roles_and_offsets_do_not() {
    for immediate in 0..(1 << IMMEDIATE_BITS) {
        let fields = (immediate << IMMEDIATE_SHIFT) | (REGISTER_MASK << BASE_SHIFT) | REGISTER_MASK;
        assert!(decode(LDG | fields).unwrap().is_valid());
        for (opcode, _) in STORE_CLASSES {
            for (mode, _) in STORE_MODES {
                assert!(
                    decode(opcode | (mode << STORE_MODE_SHIFT) | fields)
                        .unwrap()
                        .is_valid()
                );
            }
        }
    }
    for immediate in 0..(1 << PAIR_IMMEDIATE_BITS) {
        for (opcode, _) in PAIR_CLASSES {
            assert!(
                decode(opcode | (immediate << PAIR_IMMEDIATE_SHIFT) | REGISTER_MASK)
                    .unwrap()
                    .is_valid()
            );
        }
    }
    for register in REGISTER_MASK as u8..=u8::MAX {
        assert!(
            !Operand::LoadTag {
                destination: Register::X(register),
                base: Register::Sp,
                displacement: 0
            }
            .is_valid()
        );
        assert!(
            !Operand::BulkTags {
                kind: BulkKind::Store,
                data: Register::Zero,
                base: Register::X(register)
            }
            .is_valid()
        );
    }
    for displacement in [
        MIN_TAG_DISPLACEMENT - TAG_GRANULE_BYTES,
        MAX_TAG_DISPLACEMENT + TAG_GRANULE_BYTES,
        -1,
        1,
        i32::MIN,
        i32::MAX,
    ] {
        assert!(
            !Operand::LoadTag {
                destination: Register::Zero,
                base: Register::Sp,
                displacement
            }
            .is_valid()
        );
    }
    for displacement in [
        MIN_PAIR_DISPLACEMENT - TAG_GRANULE_BYTES,
        MAX_PAIR_DISPLACEMENT + TAG_GRANULE_BYTES,
        -1,
        1,
        i32::MIN,
        i32::MAX,
    ] {
        assert!(
            !Operand::StorePair {
                data: [Register::Zero; 2],
                base: Register::Sp,
                displacement,
                mode: AddressMode::Offset
            }
            .is_valid()
        );
    }
    for operand in [
        Operand::RandomTag {
            destination: Register::Zero,
            address: Register::Sp,
            mask: Register::Zero,
        },
        Operand::LoadTag {
            destination: Register::Sp,
            base: Register::Sp,
            displacement: 0,
        },
        Operand::StoreTags {
            kind: StoreKind::Tag,
            source: Register::Zero,
            base: Register::Sp,
            displacement: 0,
            mode: AddressMode::Offset,
        },
        Operand::BulkTags {
            kind: BulkKind::Load,
            data: Register::Sp,
            base: Register::Sp,
        },
        Operand::StorePair {
            data: [Register::Sp, Register::Zero],
            base: Register::Sp,
            displacement: 0,
            mode: AddressMode::Offset,
        },
        Operand::StorePair {
            data: [Register::Zero; 2],
            base: Register::Zero,
            displacement: 0,
            mode: AddressMode::Offset,
        },
    ] {
        assert!(!operand.is_valid());
    }
}
