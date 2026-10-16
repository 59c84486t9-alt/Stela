use super::*;
use crate::aarch64::{Register, simd::structure_memory::PostIndex};
use alloc::vec::Vec;

#[test]
fn all_multiple_shapes_and_address_modes_decode() {
    let mut allocated = 0;
    for load in [0, LOAD_BIT] {
        for address in [0, POST_INDEX_BIT, POST_INDEX_BIT | INDEX_MASK] {
            for opcode in 0..=OPCODE_MASK {
                for q in [0, Q_BIT] {
                    for size in 0..=SIZE_MASK {
                        let word = CLASS
                            | load
                            | address
                            | opcode << OPCODE_SHIFT
                            | q
                            | size << SIZE_SHIFT
                            | 31 << 5
                            | 31;
                        let decoded = decode(word).unwrap();
                        let shape = match opcode {
                            FOUR_STRUCTURES => Some((1, 4)),
                            FOUR_REGISTERS => Some((4, 1)),
                            THREE_STRUCTURES => Some((1, 3)),
                            THREE_REGISTERS => Some((3, 1)),
                            ONE_REGISTER => Some((1, 1)),
                            TWO_STRUCTURES => Some((1, 2)),
                            TWO_REGISTERS => Some((2, 1)),
                            _ => None,
                        };
                        let Some((repetitions, structures)) = shape else {
                            assert!(decoded.is_err());
                            continue;
                        };
                        if structures != 1 && q == 0 && size == 3 {
                            assert!(decoded.is_err());
                            continue;
                        }
                        allocated += 1;
                        let operand = decoded.unwrap();
                        assert_eq!(
                            operand.direction,
                            if load == 0 {
                                Direction::Store
                            } else {
                                Direction::Load
                            }
                        );
                        assert_eq!(operand.first_vector, 31);
                        assert_eq!(operand.base, Register::Sp);
                        assert_eq!(operand.element_bytes, 1 << size);
                        assert_eq!(
                            operand.layout,
                            Layout::Multiple {
                                repetitions,
                                structures,
                                vector_bytes: if q == 0 { 8 } else { 16 },
                            }
                        );
                        assert_eq!(
                            operand.post_index,
                            match address {
                                0 => PostIndex::None,
                                POST_INDEX_BIT => PostIndex::Register(0),
                                _ => PostIndex::TransferredBytes,
                            }
                        );
                    }
                }
            }
        }
    }
    assert_eq!(allocated, 318);
}

#[test]
fn fixed_bits_and_offset_index_field_are_enforced() {
    let word = CLASS | ONE_REGISTER << OPCODE_SHIFT;
    for bit in [31, 29, 28, 27, 26, 25, 24, 21] {
        assert!(decode(word ^ (1 << bit)).is_none());
    }
    for index in 1..32 {
        assert!(decode(word | index << 16).unwrap().is_err());
    }
}

#[test]
fn all_vector_base_and_post_index_register_roles_are_independent() {
    for vector in 0..32 {
        for base in 0..32 {
            for index in 0..32 {
                let word = CLASS
                    | LOAD_BIT
                    | POST_INDEX_BIT
                    | Q_BIT
                    | FOUR_STRUCTURES << OPCODE_SHIFT
                    | index << 16
                    | base << 5
                    | vector;
                let operand = decode(word).unwrap().unwrap();
                assert_eq!(operand.first_vector, vector as u8);
                assert_eq!(
                    operand.base,
                    if base == 31 {
                        Register::Sp
                    } else {
                        Register::X(base as u8)
                    }
                );
                assert_eq!(
                    operand.post_index,
                    if index == 31 {
                        PostIndex::TransferredBytes
                    } else {
                        PostIndex::Register(index as u8)
                    }
                );
                let vectors: Vec<_> = operand
                    .accesses()
                    .take(4)
                    .map(|access| access.vector)
                    .collect();
                assert_eq!(
                    vectors,
                    (0..4)
                        .map(|delta| ((vector + delta) % 32) as u8)
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}
