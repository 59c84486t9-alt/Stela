//! SVE vector Boolean operations, copies and prefix moves.
use super::super::{Register, Width, logical_mask, register};
use crate::aarch64::Unsupported;
use crate::aarch64::scalable::{ElementSize, Predication};

const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const SIZE_SHIFT: u32 = 22;
const SIZE_MASK: u32 = 3;
const PREDICATE_SHIFT: u32 = 10;
const PREDICATE_MASK: u32 = 7;
const PREDICATED_MASK: u32 = 0xff3f_e000;
const REGISTER_OPCODE_MASK: u32 = 0xffe0_fc00;
const IMMEDIATE_OPCODE_MASK: u32 = 0xfffc_0000;
const COPY_IMMEDIATE_MASK: u32 = 0xff30_c000;
const CROSS_OPCODE_MASK: u32 = 0xff20_fc00;
const PREFIX_MASK: u32 = 0xff3e_e000;
const SELECT_MASK: u32 = 0xff20_c000;
const MOVE_MASK: u32 = 0xffff_fc00;
const IMM13_MASK: u32 = 0x1fff;
const BITMASK_N_SHIFT: u32 = 12;
const BITMASK_ROTATION_SHIFT: u32 = 6;
const BITMASK_FIELD_MASK: u32 = 63;
const COPY_PREDICATE_SHIFT: u32 = 16;
const WIDE_PREDICATE_MASK: u32 = 15;
const COPY_SHIFT_FLAG: u32 = 1 << 13;
const COPY_IMMEDIATE_MASK_BITS: u32 = 255;
const COPY_IMMEDIATE_SHIFT: u32 = 8;
const PREFIX_MERGING_FLAG: u32 = 1 << 16;

const AND_PREDICATED: u32 = 0x041a_0000;
const BIC_PREDICATED: u32 = 0x041b_0000;
const ORR_PREDICATED: u32 = 0x0418_0000;
const EOR_PREDICATED: u32 = 0x0419_0000;
const NOT_PREDICATED: u32 = 0x041e_a000;
const CNOT_PREDICATED: u32 = 0x041b_a000;
const AND_REGISTER: u32 = 0x0420_3000;
const BIC_REGISTER: u32 = 0x04e0_3000;
const ORR_REGISTER: u32 = 0x0460_3000;
const EOR_REGISTER: u32 = 0x04a0_3000;
const AND_IMMEDIATE: u32 = 0x0580_0000;
const ORR_IMMEDIATE: u32 = 0x0500_0000;
const EOR_IMMEDIATE: u32 = 0x0540_0000;
const BCAX: u32 = 0x0460_3800;
const EOR3: u32 = 0x0420_3800;
const BSL: u32 = 0x0420_3c00;
const BSL1N: u32 = 0x0460_3c00;
const BSL2N: u32 = 0x04a0_3c00;
const NBSL: u32 = 0x04e0_3c00;
const EORBT: u32 = 0x4500_9000;
const EORTB: u32 = 0x4500_9400;
const COPY_IMMEDIATE_ZERO: u32 = 0x0510_0000;
const COPY_IMMEDIATE_MERGE: u32 = 0x0510_4000;
const COPY_REGISTER: u32 = 0x0528_a000;
const COPY_SCALAR_VECTOR: u32 = 0x0520_8000;
const PREFIX_PREDICATED: u32 = 0x0410_2000;
const PREFIX_UNPREDICATED: u32 = 0x0420_bc00;
const SELECT: u32 = 0x0520_c000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boolean {
    And,
    BitClear,
    Or,
    Xor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ternary {
    BitClearXor,
    Xor,
    Select,
    SelectNotFirst,
    SelectNotSecond,
    SelectNotResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopySource {
    Immediate(i64),
    General(Register),
    ScalarVector(u8),
    Vector(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Binary {
        operation: Boolean,
        left: u8,
        right: u8,
    },
    Immediate {
        operation: Boolean,
        value: u64,
    },
    Unary {
        source: u8,
        conditional: bool,
    },
    Ternary {
        operation: Ternary,
        right: u8,
        mask: u8,
    },
    CrossXor {
        left: u8,
        right: u8,
        top: bool,
    },
    Copy(CopySource),
    Select {
        left: u8,
        right: u8,
    },
}

/// All vector indices include Z31. Predication uses one bit per byte and tests
/// the first byte of each element; zeroing copies are the only zeroing forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub destination: u8,
    pub element_size: ElementSize,
    pub predication: Predication,
    pub kind: Kind,
}

pub fn decode(word: u32) -> Option<Result<Operand, Unsupported>> {
    let destination = (word & REGISTER_MASK) as u8;
    let source = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    let right = ((word >> RIGHT_SHIFT) & REGISTER_MASK) as u8;
    let element_size = ElementSize::from_bytes(1 << ((word >> SIZE_SHIFT) & SIZE_MASK))
        .expect("two-bit size is an allocated integer element width");
    let predicate = ((word >> PREDICATE_SHIFT) & PREDICATE_MASK) as u8;
    let mut operand = Operand {
        destination,
        element_size,
        predication: Predication::Unpredicated,
        kind: Kind::Copy(CopySource::Vector(source)),
    };
    let predicated = match word & PREDICATED_MASK {
        AND_PREDICATED => Some(Boolean::And),
        BIC_PREDICATED => Some(Boolean::BitClear),
        ORR_PREDICATED => Some(Boolean::Or),
        EOR_PREDICATED => Some(Boolean::Xor),
        NOT_PREDICATED | CNOT_PREDICATED => {
            operand.predication = Predication::Merging(predicate);
            operand.kind = Kind::Unary {
                source,
                conditional: word & PREDICATED_MASK == CNOT_PREDICATED,
            };
            return Some(Ok(operand));
        }
        COPY_REGISTER | COPY_SCALAR_VECTOR => {
            operand.predication = Predication::Merging(predicate);
            operand.kind = Kind::Copy(if word & PREDICATED_MASK == COPY_REGISTER {
                CopySource::General(register(u32::from(source), true))
            } else {
                CopySource::ScalarVector(source)
            });
            return Some(Ok(operand));
        }
        _ => None,
    };
    if let Some(operation) = predicated {
        operand.predication = Predication::Merging(predicate);
        operand.kind = Kind::Binary {
            operation,
            left: destination,
            right: source,
        };
        return Some(Ok(operand));
    }
    let binary = match word & REGISTER_OPCODE_MASK {
        AND_REGISTER => Some(Boolean::And),
        BIC_REGISTER => Some(Boolean::BitClear),
        ORR_REGISTER => Some(Boolean::Or),
        EOR_REGISTER => Some(Boolean::Xor),
        _ => None,
    };
    if let Some(operation) = binary {
        operand.element_size = ElementSize::Byte;
        operand.kind = Kind::Binary {
            operation,
            left: source,
            right,
        };
        return Some(Ok(operand));
    }
    let immediate = match word & IMMEDIATE_OPCODE_MASK {
        AND_IMMEDIATE => Some(Boolean::And),
        ORR_IMMEDIATE => Some(Boolean::Or),
        EOR_IMMEDIATE => Some(Boolean::Xor),
        _ => None,
    };
    if let Some(operation) = immediate {
        let encoded = (word >> SOURCE_SHIFT) & IMM13_MASK;
        let Some(value) = logical_mask(
            Width::X64,
            encoded >> BITMASK_N_SHIFT,
            (encoded >> BITMASK_ROTATION_SHIFT) & BITMASK_FIELD_MASK,
            encoded & BITMASK_FIELD_MASK,
        ) else {
            return Some(Err(Unsupported));
        };
        operand.element_size = ElementSize::Doubleword;
        operand.kind = Kind::Immediate { operation, value };
        return Some(Ok(operand));
    }
    let ternary = match word & REGISTER_OPCODE_MASK {
        BCAX => Some(Ternary::BitClearXor),
        EOR3 => Some(Ternary::Xor),
        BSL => Some(Ternary::Select),
        BSL1N => Some(Ternary::SelectNotFirst),
        BSL2N => Some(Ternary::SelectNotSecond),
        NBSL => Some(Ternary::SelectNotResult),
        _ => None,
    };
    if let Some(operation) = ternary {
        operand.element_size = ElementSize::Byte;
        operand.kind = Kind::Ternary {
            operation,
            right,
            mask: source,
        };
        return Some(Ok(operand));
    }
    if matches!(word & CROSS_OPCODE_MASK, EORBT | EORTB) {
        operand.kind = Kind::CrossXor {
            left: source,
            right,
            top: word & CROSS_OPCODE_MASK == EORTB,
        };
        return Some(Ok(operand));
    }
    if matches!(
        word & COPY_IMMEDIATE_MASK,
        COPY_IMMEDIATE_ZERO | COPY_IMMEDIATE_MERGE
    ) {
        let shifted = word & COPY_SHIFT_FLAG != 0;
        if element_size == ElementSize::Byte && shifted {
            return Some(Err(Unsupported));
        }
        let value = ((word >> SOURCE_SHIFT) & COPY_IMMEDIATE_MASK_BITS) as u8 as i8;
        let predicate = ((word >> COPY_PREDICATE_SHIFT) & WIDE_PREDICATE_MASK) as u8;
        operand.predication = if word & COPY_IMMEDIATE_MASK == COPY_IMMEDIATE_MERGE {
            Predication::Merging(predicate)
        } else {
            Predication::Zeroing(predicate)
        };
        operand.kind = Kind::Copy(CopySource::Immediate(
            i64::from(value) << if shifted { COPY_IMMEDIATE_SHIFT } else { 0 },
        ));
        return Some(Ok(operand));
    }
    if word & PREFIX_MASK == PREFIX_PREDICATED {
        operand.predication = if word & PREFIX_MERGING_FLAG != 0 {
            Predication::Merging(predicate)
        } else {
            Predication::Zeroing(predicate)
        };
        return Some(Ok(operand));
    }
    if word & MOVE_MASK == PREFIX_UNPREDICATED {
        operand.element_size = ElementSize::Byte;
        return Some(Ok(operand));
    }
    if word & SELECT_MASK == SELECT {
        operand.predication =
            Predication::Merging(((word >> PREDICATE_SHIFT) & WIDE_PREDICATE_MASK) as u8);
        operand.kind = Kind::Select {
            left: source,
            right,
        };
        return Some(Ok(operand));
    }
    None
}

/// Decode MOVPRFX itself. Pair legality and adjacency are checked by the
/// caller.
pub fn decode_prefix(word: u32) -> Option<Operand> {
    if word & PREFIX_MASK != PREFIX_PREDICATED && word & MOVE_MASK != PREFIX_UNPREDICATED {
        return None;
    }
    decode(word)?.ok()
}

impl Operand {
    /// MOVPRFX requirements of the follower word. The typed operand is checked
    /// again so that normalized kinds cannot admit another encoding.
    pub fn prefix_requirement(
        self,
        word: u32,
    ) -> Result<Option<super::prefix::PrefixRequirement>, Unsupported> {
        use super::prefix::{PredicatedPrefixRequirement, PrefixRequirement};

        if decode(word) != Some(Ok(self)) {
            return Err(Unsupported);
        }
        let predicated = match self.predication {
            Predication::Merging(predicate) => Some(PredicatedPrefixRequirement {
                predicate,
                element: self.element_size,
            }),
            Predication::Unpredicated | Predication::Zeroing(_) => None,
        };
        let vector = |predicated, other_vector_sources| PrefixRequirement::Vector {
            destination: self.destination,
            predicated,
            other_vector_sources,
        };
        let source_bit = |register: u8| 1_u32 << register;
        let requirement = match self.kind {
            Kind::Binary { right, .. }
                if matches!(
                    word & PREDICATED_MASK,
                    AND_PREDICATED | BIC_PREDICATED | ORR_PREDICATED | EOR_PREDICATED
                ) =>
            {
                Some(vector(predicated, source_bit(right)))
            }
            Kind::Unary { source, .. }
                if matches!(word & PREDICATED_MASK, NOT_PREDICATED | CNOT_PREDICATED) =>
            {
                Some(vector(predicated, source_bit(source)))
            }
            Kind::Copy(CopySource::Immediate(_))
                if word & COPY_IMMEDIATE_MASK == COPY_IMMEDIATE_MERGE =>
            {
                Some(vector(predicated, 0))
            }
            Kind::Copy(CopySource::General(_)) if word & PREDICATED_MASK == COPY_REGISTER => {
                Some(vector(predicated, 0))
            }
            Kind::Copy(CopySource::ScalarVector(source))
                if word & PREDICATED_MASK == COPY_SCALAR_VECTOR =>
            {
                Some(vector(predicated, source_bit(source)))
            }
            Kind::Immediate { .. }
                if matches!(
                    word & IMMEDIATE_OPCODE_MASK,
                    AND_IMMEDIATE | ORR_IMMEDIATE | EOR_IMMEDIATE
                ) =>
            {
                Some(vector(None, 0))
            }
            Kind::Ternary { right, mask, .. }
                if matches!(
                    word & REGISTER_OPCODE_MASK,
                    BCAX | EOR3 | BSL | BSL1N | BSL2N | NBSL
                ) =>
            {
                Some(vector(None, source_bit(right) | source_bit(mask)))
            }
            Kind::CrossXor { left, right, .. }
                if matches!(word & CROSS_OPCODE_MASK, EORBT | EORTB) =>
            {
                Some(vector(None, source_bit(left) | source_bit(right)))
            }
            Kind::Binary { .. }
                if matches!(
                    word & REGISTER_OPCODE_MASK,
                    AND_REGISTER | BIC_REGISTER | ORR_REGISTER | EOR_REGISTER
                ) =>
            {
                Some(PrefixRequirement::Forbidden)
            }
            Kind::Copy(CopySource::Immediate(_))
                if word & COPY_IMMEDIATE_MASK == COPY_IMMEDIATE_ZERO =>
            {
                Some(PrefixRequirement::Forbidden)
            }
            Kind::Copy(CopySource::Vector(_))
                if word & PREFIX_MASK == PREFIX_PREDICATED
                    || word & MOVE_MASK == PREFIX_UNPREDICATED =>
            {
                Some(PrefixRequirement::Forbidden)
            }
            Kind::Select { .. } if word & SELECT_MASK == SELECT => {
                Some(PrefixRequirement::Forbidden)
            }
            _ => None,
        };
        Ok(requirement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod prefix_requirement {
        use super::*;
        use crate::aarch64::sve::prefix::PrefixRequirement;

        #[test]
        fn all_28_exact_june_logic_policies_match_canonical_word_adapters() {
            // Independent exact-June metadata, bound in logic28-facts.json.
            let facts = [
                (0x041a0000, true, true),   // and_z_p_zz_
                (0x05800000, true, false),  // and_z_zi_
                (0x04203000, false, false), // and_z_zz_
                (0x04603800, true, false),  // bcax_z_zzz_
                (0x041b0000, true, true),   // bic_z_p_zz_
                (0x04e03000, false, false), // bic_z_zz_
                (0x04603c00, true, false),  // bsl1n_z_zzz_
                (0x04a03c00, true, false),  // bsl2n_z_zzz_
                (0x04203c00, true, false),  // bsl_z_zzz_
                (0x041ba000, true, true),   // cnot_z_p_z_m
                (0x05100000, false, false), // cpy_z_o_i_
                (0x05104000, true, true),   // cpy_z_p_i_
                (0x0528a000, true, true),   // cpy_z_p_r_
                (0x05208000, true, true),   // cpy_z_p_v_
                (0x04203800, true, false),  // eor3_z_zzz_
                (0x04190000, true, true),   // eor_z_p_zz_
                (0x05400000, true, false),  // eor_z_zi_
                (0x04a03000, false, false), // eor_z_zz_
                (0x45009000, true, false),  // eorbt_z_zz_
                (0x45009400, true, false),  // eortb_z_zz_
                (0x04102000, false, false), // movprfx_z_p_z_
                (0x0420bc00, false, false), // movprfx_z_z_
                (0x04e03c00, true, false),  // nbsl_z_zzz_
                (0x041ea000, true, true),   // not_z_p_z_m
                (0x04180000, true, true),   // orr_z_p_zz_
                (0x05000000, true, false),  // orr_z_zi_
                (0x04603000, false, false), // orr_z_zz_
                (0x0520c000, false, false), // sel_z_p_zz_
            ];
            for (word, permitted, predicated) in facts {
                let operand = decode(word).unwrap().unwrap();
                let requirement = operand
                    .prefix_requirement(word)
                    .unwrap()
                    .expect("all28 canonical forms reviewed");
                match requirement {
                    PrefixRequirement::Forbidden => assert!(!permitted),
                    PrefixRequirement::Vector {
                        predicated: actual, ..
                    } => {
                        assert!(permitted);
                        assert_eq!(actual.is_some(), predicated);
                    }
                }
            }
        }

        #[test]
        fn other_source_masks_use_shared_vector_storage_and_exclude_only_implicit_destination() {
            let destination = 3;
            let vector_source = 3 << SOURCE_SHIFT;
            for (opcode, expected) in [
                (COPY_REGISTER, 0),
                (COPY_SCALAR_VECTOR, 1_u32 << destination),
                (AND_PREDICATED, 1_u32 << destination),
                (NOT_PREDICATED, 1_u32 << destination),
            ] {
                let word = opcode | vector_source | destination;
                let operand = decode(word).unwrap().unwrap();
                let PrefixRequirement::Vector {
                    other_vector_sources,
                    ..
                } = operand
                    .prefix_requirement(word)
                    .unwrap()
                    .expect("reviewed source form")
                else {
                    panic!("reviewed source form forbidden")
                };
                assert_eq!(other_vector_sources, expected);
            }
            for opcode in [BCAX, EORBT] {
                let word = opcode | (5 << SOURCE_SHIFT) | (7 << RIGHT_SHIFT) | destination;
                let operand = decode(word).unwrap().unwrap();
                let PrefixRequirement::Vector {
                    other_vector_sources,
                    ..
                } = operand
                    .prefix_requirement(word)
                    .unwrap()
                    .expect("reviewed source form")
                else {
                    panic!("reviewed source form forbidden")
                };
                assert_eq!(other_vector_sources, (1_u32 << 5) | (1_u32 << 7));
            }
        }

        #[test]
        fn source_or_normalized_operand_mismatch_cannot_authorize_a_follower() {
            let word = AND_PREDICATED | (2 << SOURCE_SHIFT);
            let operand = decode(word).unwrap().unwrap();
            let mut forged = operand;
            forged.destination = 1;
            assert!(forged.prefix_requirement(word).is_err());
            assert!(operand.prefix_requirement(AND_REGISTER).is_err());
        }
    }

    #[test]
    fn destructive_and_constructive_register_roles_include_z31() {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                let operand = decode(AND_PREDICATED | (source << SOURCE_SHIFT) | destination)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    operand.kind,
                    Kind::Binary {
                        operation: Boolean::And,
                        left: destination as u8,
                        right: source as u8,
                    }
                );
                let operand =
                    decode(BCAX | (source << RIGHT_SHIFT) | (31 << SOURCE_SHIFT) | destination)
                        .unwrap()
                        .unwrap();
                assert_eq!(
                    operand.kind,
                    Kind::Ternary {
                        operation: Ternary::BitClearXor,
                        right: source as u8,
                        mask: 31,
                    }
                );
            }
        }
    }

    #[test]
    fn copies_distinguish_full_predicate_range_sp_and_reserved_byte_shift() {
        for size in 0..=SIZE_MASK {
            for predicate in 0..=WIDE_PREDICATE_MASK {
                for shifted in [false, true] {
                    let word = COPY_IMMEDIATE_ZERO
                        | (size << SIZE_SHIFT)
                        | (predicate << COPY_PREDICATE_SHIFT)
                        | (255 << SOURCE_SHIFT)
                        | if shifted { COPY_SHIFT_FLAG } else { 0 };
                    let result = decode(word).unwrap();
                    if size == 0 && shifted {
                        assert_eq!(result, Err(Unsupported));
                    } else {
                        let operand = result.unwrap();
                        assert_eq!(operand.predication, Predication::Zeroing(predicate as u8));
                        assert_eq!(
                            operand.kind,
                            Kind::Copy(CopySource::Immediate(if shifted { -256 } else { -1 }))
                        );
                    }
                }
            }
        }
        assert_eq!(
            decode(COPY_REGISTER | (31 << SOURCE_SHIFT))
                .unwrap()
                .unwrap()
                .kind,
            Kind::Copy(CopySource::General(Register::Sp))
        );
    }

    #[test]
    fn reserved_logical_immediates_decline_and_zeroing_unary_is_outside_inventory() {
        for opcode in [AND_IMMEDIATE, ORR_IMMEDIATE, EOR_IMMEDIATE] {
            assert_eq!(
                decode(opcode | (63 << SOURCE_SHIFT)),
                Some(Err(Unsupported))
            );
            assert!(decode(opcode).unwrap().is_ok());
        }
        assert_eq!(decode(NOT_PREDICATED ^ (1 << 20)), None);
        assert_eq!(decode(CNOT_PREDICATED ^ (1 << 20)), None);
    }
}
