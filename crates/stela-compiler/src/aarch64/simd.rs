//! Reviewed SIMD data movement and integer operations, with FP/AdvSIMD enabled.
//! Encoding facts: Arm ISA_A64_xml_A_profile-2026-06/{ldr_imm_fpsimd,
//! str_imm_fpsimd,ldur_fpsimd,stur_fpsimd,movi_advsimd,ldp_fpsimd,stp_fpsimd}.xml.
use super::{AddressMode, Register, register};
pub mod rearrange;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerOperation {
    And,
    Bic,
    Orr,
    Orn,
    Eor,
    Bsl,
    Bit,
    Bif,
    Add,
    Sub,
    Abs,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    Greater,
    GreaterEqual,
    Higher,
    HigherEqual,
    LessZero,
    LessEqualZero,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Rearrange(rearrange::Operand),
    Compare {
        operation: Comparison,
        destination: u8,
        left: u8,
        right: Option<u8>,
        bytes: u8,
        lane_bytes: u8,
    },
    Integer {
        operation: IntegerOperation,
        destination: u8,
        left: u8,
        /// Unused for unary ABS/NEG. V31 is ordinary data in every role.
        right: u8,
        bytes: u8,
        lane_bytes: u8,
    },
    MemoryPair {
        load: bool,
        bytes: u8,
        /// V31 is ordinary vector data; GPR/SP base roles are independent.
        vectors: [u8; 2],
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    Memory {
        load: bool,
        bytes: u8,
        /// SIMD register 31 is V31, not the integer zero register.
        vector: u8,
        base: Register,
        displacement: i32,
        mode: AddressMode,
    },
    MoveImmediate {
        vector: u8,
        /// Expanded 8-bit byte mask, one bit per 0x00/0xff byte.
        mask: u64,
        /// D writes clear the upper half; 2D replicates the mask.
        two_lanes: bool,
    },
}

/// None denotes another encoding class; Err is an unsupported/reserved member.
/// FP arithmetic, other MOVI forms, register offsets and structures decline.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if let Some(decoded) = rearrange::decode(word) {
        return Some(decoded.map(Operand::Rearrange));
    }
    let scalar = word & (1 << 28) != 0;
    let normalized = word & !(1 << 28);
    let comparison = match normalized & 0xbf20fc00 {
        0x2e208c00 => Some(Comparison::Equal),
        0x0e203400 => Some(Comparison::Greater),
        0x0e203c00 => Some(Comparison::GreaterEqual),
        0x2e203400 => Some(Comparison::Higher),
        0x2e203c00 => Some(Comparison::HigherEqual),
        0x0e208c00 => Some(Comparison::Test),
        _ => None,
    };
    let compare_zero = match normalized & 0xbf3ffc00 {
        0x0e209800 => Some(Comparison::Equal),
        0x0e208800 => Some(Comparison::Greater),
        0x2e208800 => Some(Comparison::GreaterEqual),
        0x0e20a800 => Some(Comparison::LessZero),
        0x2e209800 => Some(Comparison::LessEqualZero),
        _ => None,
    };
    if let Some(operation) = comparison.or(compare_zero) {
        let q = word & (1 << 30) != 0;
        let size = (word >> 22) & 3;
        // Other scalar sizes/Q values share space with scalar FP encodings;
        // they are outside this integer comparison class, not vector compares.
        if scalar && (!q || size != 3) {
            return None;
        }
        if !scalar && !q && size == 3 {
            return Some(Err(()));
        }
        return Some(Ok(Operand::Compare {
            operation,
            destination: (word & 31) as u8,
            left: ((word >> 5) & 31) as u8,
            right: comparison.map(|_| ((word >> 16) & 31) as u8),
            bytes: if scalar || !q { 8 } else { 16 },
            lane_bytes: 1 << size,
        }));
    }
    use IntegerOperation::*;
    let logical = match word & 0xbfe0fc00 {
        0x0e201c00 => Some(And),
        0x0e601c00 => Some(Bic),
        0x0ea01c00 => Some(Orr),
        0x0ee01c00 => Some(Orn),
        0x2e201c00 => Some(Eor),
        0x2e601c00 => Some(Bsl),
        0x2ea01c00 => Some(Bit),
        0x2ee01c00 => Some(Bif),
        _ => None,
    };
    let vector_math = match word & 0xbf20fc00 {
        0x0e208400 => Some(Add),
        0x2e208400 => Some(Sub),
        _ => None,
    }
    .or(match word & 0xbf3ffc00 {
        0x0e20b800 => Some(Abs),
        0x2e20b800 => Some(Neg),
        _ => None,
    });
    let scalar_math = match word & 0xffe0fc00 {
        0x5ee08400 => Some(Add),
        0x7ee08400 => Some(Sub),
        _ => None,
    }
    .or(match word & 0xfffffc00 {
        0x5ee0b800 => Some(Abs),
        0x7ee0b800 => Some(Neg),
        _ => None,
    });
    if let Some(operation) = logical.or(vector_math).or(scalar_math) {
        let q = word & (1 << 30) != 0;
        let lane_bytes = if logical.is_some() {
            1
        } else {
            1 << ((word >> 22) & 3)
        };
        if vector_math.is_some() && !q && lane_bytes == 8 {
            return Some(Err(()));
        }
        return Some(Ok(Operand::Integer {
            operation,
            destination: (word & 31) as u8,
            left: ((word >> 5) & 31) as u8,
            right: ((word >> 16) & 31) as u8,
            bytes: if scalar_math.is_some() || !q { 8 } else { 16 },
            lane_bytes,
        }));
    }
    if word & 0x3e000000 == 0x2c000000 {
        let opcode = word >> 30;
        let mode = match (word >> 23) & 3 {
            1 => AddressMode::PostIndex,
            2 => AddressMode::Offset,
            3 => AddressMode::PreIndex,
            _ => return Some(Err(())), // non-temporal pairs are a separate class
        };
        if opcode == 3 {
            return Some(Err(()));
        }
        let load = word & (1 << 22) != 0;
        let vectors = [(word & 31) as u8, ((word >> 10) & 31) as u8];
        // LDPOVERLAP permits UNKNOWN/UNDEF/NOP, not ordinary two-result writes.
        // Decline every duplicate destination, including the real V31 register.
        if load && vectors[0] == vectors[1] {
            return Some(Err(()));
        }
        let bytes = 4u8 << opcode;
        let immediate = ((word >> 15) & 127) as i32;
        return Some(Ok(Operand::MemoryPair {
            load,
            bytes,
            vectors,
            base: register((word >> 5) & 31, true),
            displacement: ((immediate << 25) >> 25) * i32::from(bytes),
            mode,
        }));
    }
    if word & 0xbff8fc00 == 0x2f00e400 {
        let immediate = ((word >> 16) & 7) << 5 | ((word >> 5) & 31);
        let mut mask = 0;
        for byte in 0..8 {
            if immediate & (1 << byte) != 0 {
                mask |= 0xffu64 << (byte * 8);
            }
        }
        return Some(Ok(Operand::MoveImmediate {
            vector: (word & 31) as u8,
            mask,
            two_lanes: word & (1 << 30) != 0,
        }));
    }
    let unsigned = word & 0x3f000000 == 0x3d000000;
    if !unsigned && word & 0x3f200000 != 0x3c000000 {
        return None;
    }
    let size = word >> 30;
    let opcode = (word >> 22) & 3;
    // opc[1] selects Q, whose size field must be 00.
    if opcode & 2 != 0 && size != 0 {
        return Some(Err(()));
    }
    let scale = if opcode & 2 != 0 { 4 } else { size };
    let (displacement, mode) = if unsigned {
        ((((word >> 10) & 4095) << scale) as i32, AddressMode::Offset)
    } else {
        let mode = match (word >> 10) & 3 {
            0 => AddressMode::Offset,
            1 => AddressMode::PostIndex,
            3 => AddressMode::PreIndex,
            _ => return Some(Err(())),
        };
        let immediate = ((word >> 12) & 511) as i32;
        ((immediate << 23) >> 23, mode)
    };
    Some(Ok(Operand::Memory {
        load: opcode & 1 != 0,
        bytes: 1 << scale,
        vector: (word & 31) as u8,
        base: register((word >> 5) & 31, true),
        displacement,
        mode,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, Lifter};

    #[test]
    fn integer_vectors_reject_single_d_lanes_and_keep_v31_as_data() {
        for (base, unary) in [
            (0x0e208400, false),
            (0x2e208400, false),
            (0x0e20b800, true),
            (0x2e20b800, true),
        ] {
            for q in 0..2 {
                for size in 0..4 {
                    let word = base
                        | (q << 30)
                        | (size << 22)
                        | (31 << 5)
                        | 31
                        | if unary { 0 } else { 31 << 16 };
                    let decoded = decode(word).unwrap();
                    if q == 0 && size == 3 {
                        assert_eq!(decoded, Err(()));
                    } else if let Ok(Operand::Integer {
                        destination,
                        left,
                        right,
                        bytes,
                        lane_bytes,
                        ..
                    }) = decoded
                    {
                        assert_eq!((destination, left), (31, 31));
                        if !unary {
                            assert_eq!(right, 31);
                        }
                        assert_eq!(bytes, 8 << q);
                        assert_eq!(lane_bytes, 1 << size);
                    } else {
                        panic!("integer vector decoded as another class");
                    }
                }
            }
        }
        for base in [0x5ee08400, 0x7ee08400, 0x5ee0b800, 0x7ee0b800] {
            assert!(matches!(
                decode(base),
                Some(Ok(Operand::Integer {
                    bytes: 8,
                    lane_bytes: 8,
                    ..
                }))
            ));
            for size in 0..3 {
                let word = (base & !(3 << 22)) | (size << 22);
                assert!(!matches!(decode(word), Some(Ok(Operand::Integer { .. }))));
            }
        }
    }

    #[test]
    fn comparisons_distinguish_zero_operands_and_reserved_scalar_vector_sizes() {
        for (base, zero) in [
            (0x2e208c00, false),
            (0x0e203400, false),
            (0x0e203c00, false),
            (0x2e203400, false),
            (0x2e203c00, false),
            (0x0e208c00, false),
            (0x0e209800, true),
            (0x0e208800, true),
            (0x2e208800, true),
            (0x0e20a800, true),
            (0x2e209800, true),
        ] {
            let registers = (31 << 5) | 31 | if zero { 0 } else { 31 << 16 };
            for scalar in 0..2 {
                for q in 0..2 {
                    for size in 0..4 {
                        let word = base | (scalar << 28) | (q << 30) | (size << 22) | registers;
                        if scalar != 0 && (q == 0 || size != 3) {
                            assert!(!matches!(decode(word), Some(Ok(Operand::Compare { .. }))));
                        } else if scalar == 0 && q == 0 && size == 3 {
                            assert_eq!(decode(word), Some(Err(())));
                        } else if let Some(Ok(Operand::Compare {
                            destination,
                            left,
                            right,
                            bytes,
                            lane_bytes,
                            ..
                        })) = decode(word)
                        {
                            assert_eq!((destination, left), (31, 31));
                            assert_eq!(right, if zero { None } else { Some(31) });
                            assert_eq!(lane_bytes, 1 << size);
                            assert_eq!(bytes, if scalar != 0 { 8 } else { 8 << q });
                        } else {
                            panic!("comparison decoded as another instruction class");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn actual_xcode_words_keep_vector_bank_and_address_units() {
        for (word, expected) in [
            (
                0xfd42f100,
                Operand::Memory {
                    load: true,
                    bytes: 8,
                    vector: 0,
                    base: Register::X(8),
                    displacement: 1504,
                    mode: AddressMode::Offset,
                },
            ),
            (
                0x3cda83a0,
                Operand::Memory {
                    load: true,
                    bytes: 16,
                    vector: 0,
                    base: Register::X(29),
                    displacement: -88,
                    mode: AddressMode::Offset,
                },
            ),
            (
                0x6f00e400,
                Operand::MoveImmediate {
                    vector: 0,
                    mask: 0,
                    two_lanes: true,
                },
            ),
        ] {
            assert_eq!(decode(word), Some(Ok(expected)));
            assert_eq!(
                super::super::Decoder
                    .lift(GuestAddress(0x1000), word)
                    .unwrap()
                    .operation,
                super::super::Operation::Simd(expected)
            );
        }
    }

    #[test]
    fn every_size_mode_and_immediate_extreme_has_distinct_vector_sp_roles() {
        for (size, q, bytes) in [
            (0, false, 1),
            (1, false, 2),
            (2, false, 4),
            (3, false, 8),
            (0, true, 16),
        ] {
            for load in [false, true] {
                let prefix = (size << 30) | (u32::from(q) << 23) | (u32::from(load) << 22);
                for vector in 0..32 {
                    let unsigned = prefix | 0x3d000000 | (4095 << 10) | (31 << 5) | vector;
                    assert_eq!(
                        decode(unsigned),
                        Some(Ok(Operand::Memory {
                            load,
                            bytes,
                            vector: vector as u8,
                            base: Register::Sp,
                            displacement: 4095 * i32::from(bytes),
                            mode: AddressMode::Offset,
                        }))
                    );
                    for (bits, displacement) in [(256, -256), (511, -1), (0, 0), (255, 255)] {
                        for (mode_bits, mode) in [
                            (0, AddressMode::Offset),
                            (1, AddressMode::PostIndex),
                            (3, AddressMode::PreIndex),
                        ] {
                            let word = prefix
                                | 0x3c000000
                                | (bits << 12)
                                | (mode_bits << 10)
                                | (vector << 5)
                                | vector;
                            assert_eq!(
                                decode(word),
                                Some(Ok(Operand::Memory {
                                    load,
                                    bytes,
                                    vector: vector as u8,
                                    base: if vector == 31 {
                                        Register::Sp
                                    } else {
                                        Register::X(vector as u8)
                                    },
                                    displacement,
                                    mode,
                                }))
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn all_byte_masks_and_widths_expand_without_accepting_other_movi_classes() {
        for immediate in 0u32..256 {
            let expected = (0..8).fold(0u64, |mask, i| {
                mask | if immediate & (1 << i) == 0 {
                    0
                } else {
                    255u64 << (i * 8)
                }
            });
            for two_lanes in [false, true] {
                let word = 0x2f00e400
                    | (u32::from(two_lanes) << 30)
                    | ((immediate >> 5) << 16)
                    | ((immediate & 31) << 5)
                    | 31;
                assert_eq!(
                    decode(word),
                    Some(Ok(Operand::MoveImmediate {
                        vector: 31,
                        mask: expected,
                        two_lanes,
                    }))
                );
            }
        }
        for bit in [
            31, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 15, 14, 13, 12, 11, 10,
        ] {
            // A fixed-bit neighbor may be another admitted class (e.g. STP),
            // but must never retain MOVI semantics.
            assert!(!matches!(
                decode(0x6f00e400 ^ (1 << bit)),
                Some(Ok(Operand::MoveImmediate { .. }))
            ));
        }
    }

    #[test]
    fn reserved_sizes_and_adjacent_memory_classes_decline() {
        for size in 1..4 {
            for prefix in [0x3d800000, 0x3dc00000, 0x3c800000, 0x3cc00000] {
                assert_eq!(decode(prefix | (size << 30)), Some(Err(())));
            }
        }
        assert_eq!(decode(0x3cc00800), Some(Err(()))); // unprivileged/reserved SIMD mode
        for word in [
            0xfd000000 ^ (1 << 26),
            0x3ce00800,
            0x9c000000,
            0x4c407000,
            0xc85f7c00,
        ] {
            assert!(decode(word).is_none());
        }
    }

    #[test]
    fn pair_sizes_modes_signed_extrema_and_independent_banks_are_explicit() {
        for (opcode, bytes) in [(0, 4), (1, 8), (2, 16)] {
            for load in [false, true] {
                for (mode_bits, mode) in [
                    (1, AddressMode::PostIndex),
                    (2, AddressMode::Offset),
                    (3, AddressMode::PreIndex),
                ] {
                    for immediate in [-64i32, -1, 0, 63] {
                        for first in 0..32u32 {
                            for second in 0..32u32 {
                                let word = (opcode << 30)
                                    | 0x2c000000
                                    | (mode_bits << 23)
                                    | (u32::from(load) << 22)
                                    | (((immediate as u32) & 127) << 15)
                                    | (second << 10)
                                    | (first << 5)
                                    | first;
                                let expected = if load && first == second {
                                    Err(())
                                } else {
                                    Ok(Operand::MemoryPair {
                                        load,
                                        bytes,
                                        vectors: [first as u8, second as u8],
                                        base: if first == 31 {
                                            Register::Sp
                                        } else {
                                            Register::X(first as u8)
                                        },
                                        displacement: immediate * i32::from(bytes),
                                        mode,
                                    })
                                };
                                assert_eq!(decode(word), Some(expected));
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn pair_non_temporal_reserved_sizes_and_other_classes_do_not_become_ordinary_pairs() {
        for load in [false, true] {
            for opcode in 0..4 {
                let prefix = (opcode << 30) | 0x2c000400 | (u32::from(load) << 22);
                assert_eq!(decode(prefix), Some(Err(()))); // mode00: STNP/LDNP
                for mode in 1..4 {
                    if opcode == 3 {
                        assert_eq!(decode(prefix | (mode << 23)), Some(Err(())));
                    }
                }
            }
        }
        let pair = 0xad000400; // STP Q0,Q1,[X0]
        for bit in [25, 26, 27, 28, 29] {
            assert!(!matches!(
                decode(pair ^ (1 << bit)),
                Some(Ok(Operand::MemoryPair { .. }))
            ));
        }
        assert_eq!(
            decode(0xad000000),
            Some(Ok(Operand::MemoryPair {
                load: false,
                bytes: 16,
                vectors: [0, 0],
                base: Register::X(0),
                displacement: 0,
                mode: AddressMode::Offset,
            }))
        );
    }
}
