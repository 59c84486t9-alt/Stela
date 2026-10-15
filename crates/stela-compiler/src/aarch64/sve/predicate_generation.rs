//! Scalable predicate generation, break propagation and scalar WHILE conditions.
//!
//! Decoding is state independent. The caller applies the immutable scalable
//! profile and architectural streaming checks before execution. PN destinations
//! alias P8..P15; no instruction here accesses guest RAM or changes FFR/ZA/Z.

pub use basic::BasicOperand;
pub use breaks::{Boundary, BreakKind, BreakOperand};
pub use whiles::{Comparison, Destination, WhileOperand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Basic(BasicOperand),
    Break(BreakOperand),
    While(WhileOperand),
}

impl Operand {
    /// Counter and paired-predicate destinations require the SME2 extension.
    pub const fn requires_sme2(self) -> bool {
        matches!(
            self,
            Self::Basic(BasicOperand::TrueCounter { .. })
                | Self::While(WhileOperand {
                    destination: Destination::Pair(_) | Destination::Counter { .. },
                    ..
                })
        )
    }
}

/// Matching allocated operands are never silently discarded. None means this
/// decoder does not own the word; Err is reserved for an owned invalid operand.
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    if let Some(result) = basic::decode_basic(word) {
        return Some(result.map(Operand::Basic));
    }
    if let Some(result) = breaks::decode(word) {
        return Some(result.map(Operand::Break));
    }
    whiles::decode(word).map(|result| result.map(Operand::While))
}

mod basic {
    //! Basic predicate generation. Predicate indices are packed architectural P registers.
    use crate::aarch64::scalable::ElementSize;
    use crate::aarch64::{Register, Width, register};

    const PREDICATE_MASK: u32 = 15;
    const SCALAR_REGISTER_MASK: u32 = 31;
    const SIZE_SHIFT: u32 = 22;
    const SIZE_MASK: u32 = 3;
    const FIRST_SOURCE_SHIFT: u32 = 5;
    const GOVERNING_SHIFT: u32 = 10;
    const SECOND_SOURCE_SHIFT: u32 = 16;
    const PATTERN_MASK: u32 = 31;
    const PN_MASK: u32 = 7;
    const PN_BASE: u8 = 8;
    const PFALSE_MASK: u32 = 0xffff_fff0;
    const PFALSE_CLASS: u32 = 0x2518_e400;
    const PFIRST_MASK: u32 = 0xffff_fe10;
    const PFIRST_CLASS: u32 = 0x2558_c000;
    const PNEXT_MASK: u32 = 0xff3f_fe10;
    const PNEXT_CLASS: u32 = 0x2519_c400;
    const PTEST_MASK: u32 = 0xffff_c21f;
    const PTEST_CLASS: u32 = 0x2550_c000;
    const PTRUE_MASK: u32 = 0xff3f_fc10;
    const PTRUE_CLASS: u32 = 0x2518_e000;
    const PTRUES_CLASS: u32 = 0x2519_e000;
    const PTRUE_PN_MASK: u32 = 0xff3f_fff8;
    const PTRUE_PN_CLASS: u32 = 0x2520_7810;
    const CTERM_MASK: u32 = 0xffa0_fc1f;
    const CTERMEQ_CLASS: u32 = 0x25a0_2000;
    const CTERMNE_CLASS: u32 = 0x25a0_2010;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BasicOperand {
        False {
            destination: u8,
        },
        First {
            destination: u8,
            governing: u8,
        },
        Next {
            destination: u8,
            governing: u8,
            element: ElementSize,
        },
        Test {
            governing: u8,
            source: u8,
        },
        True {
            destination: u8,
            element: ElementSize,
            pattern: u8,
            set_flags: bool,
        },
        TrueCounter {
            destination: u8,
            element: ElementSize,
        },
        ConditionalTerminate {
            first: Register,
            second: Register,
            width: Width,
            equal: bool,
        },
    }

    /// No basic form has reserved operand encodings. Unnamed five-bit PTRUE patterns
    /// execute with zero active elements; they are not decoder errors. GPR31 is ZR.
    pub fn decode_basic(word: u32) -> Option<Result<BasicOperand, ()>> {
        let destination = (word & PREDICATE_MASK) as u8;
        let element = ElementSize::from_bytes(1 << ((word >> SIZE_SHIFT) & SIZE_MASK))?;
        let near_source = ((word >> FIRST_SOURCE_SHIFT) & PREDICATE_MASK) as u8;
        let operand = if word & PFALSE_MASK == PFALSE_CLASS {
            BasicOperand::False { destination }
        } else if word & PFIRST_MASK == PFIRST_CLASS {
            BasicOperand::First {
                destination,
                governing: near_source,
            }
        } else if word & PNEXT_MASK == PNEXT_CLASS {
            BasicOperand::Next {
                destination,
                governing: near_source,
                element,
            }
        } else if word & PTEST_MASK == PTEST_CLASS {
            BasicOperand::Test {
                governing: ((word >> GOVERNING_SHIFT) & PREDICATE_MASK) as u8,
                source: near_source,
            }
        } else if matches!(word & PTRUE_MASK, PTRUE_CLASS | PTRUES_CLASS) {
            BasicOperand::True {
                destination,
                element,
                pattern: ((word >> FIRST_SOURCE_SHIFT) & PATTERN_MASK) as u8,
                set_flags: word & PTRUE_MASK == PTRUES_CLASS,
            }
        } else if word & PTRUE_PN_MASK == PTRUE_PN_CLASS {
            BasicOperand::TrueCounter {
                destination: PN_BASE + (word & PN_MASK) as u8,
                element,
            }
        } else if matches!(word & CTERM_MASK, CTERMEQ_CLASS | CTERMNE_CLASS) {
            BasicOperand::ConditionalTerminate {
                first: register((word >> FIRST_SOURCE_SHIFT) & SCALAR_REGISTER_MASK, false),
                second: register((word >> SECOND_SOURCE_SHIFT) & SCALAR_REGISTER_MASK, false),
                width: if word & (1 << SIZE_SHIFT) == 0 {
                    Width::W32
                } else {
                    Width::X64
                },
                equal: word & CTERM_MASK == CTERMEQ_CLASS,
            }
        } else {
            return None;
        };
        Some(Ok(operand))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn basic_allocations_include_all_patterns_and_predicate_registers() {
            for destination in 0..=PREDICATE_MASK {
                assert_eq!(
                    decode_basic(PFALSE_CLASS | destination),
                    Some(Ok(BasicOperand::False {
                        destination: destination as u8
                    }))
                );
                for size in 0..=SIZE_MASK {
                    let element = ElementSize::from_bytes(1 << size).unwrap();
                    for pattern in 0..=PATTERN_MASK {
                        for (class, set_flags) in [(PTRUE_CLASS, false), (PTRUES_CLASS, true)] {
                            assert_eq!(
                                decode_basic(
                                    class
                                        | destination
                                        | size << SIZE_SHIFT
                                        | pattern << FIRST_SOURCE_SHIFT
                                ),
                                Some(Ok(BasicOperand::True {
                                    destination: destination as u8,
                                    element,
                                    pattern: pattern as u8,
                                    set_flags
                                }))
                            );
                        }
                    }
                    for governing in 0..=PREDICATE_MASK {
                        assert_eq!(
                            decode_basic(
                                PNEXT_CLASS
                                    | destination
                                    | governing << FIRST_SOURCE_SHIFT
                                    | size << SIZE_SHIFT
                            ),
                            Some(Ok(BasicOperand::Next {
                                destination: destination as u8,
                                governing: governing as u8,
                                element
                            }))
                        );
                    }
                }
            }
        }

        #[test]
        fn counter_aliases_and_scalar_zero_width_are_explicit() {
            for destination in 0..=PN_MASK {
                for size in 0..=SIZE_MASK {
                    assert_eq!(
                        decode_basic(PTRUE_PN_CLASS | destination | size << SIZE_SHIFT),
                        Some(Ok(BasicOperand::TrueCounter {
                            destination: PN_BASE + destination as u8,
                            element: ElementSize::from_bytes(1 << size).unwrap()
                        }))
                    );
                }
            }
            for (class, equal) in [(CTERMEQ_CLASS, true), (CTERMNE_CLASS, false)] {
                for first in 0..=SCALAR_REGISTER_MASK {
                    for second in 0..=SCALAR_REGISTER_MASK {
                        for (size, width) in [(0, Width::W32), (1, Width::X64)] {
                            assert_eq!(
                                decode_basic(
                                    class
                                        | first << FIRST_SOURCE_SHIFT
                                        | second << SECOND_SOURCE_SHIFT
                                        | size << SIZE_SHIFT
                                ),
                                Some(Ok(BasicOperand::ConditionalTerminate {
                                    first: register(first, false),
                                    second: register(second, false),
                                    width,
                                    equal
                                }))
                            );
                        }
                    }
                }
            }
            assert!(decode_basic(PFALSE_CLASS ^ (1 << 4)).is_none());
        }
    }
}

mod breaks {
    // Predicate breaks decode operand roles without state-layout assumptions.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Boundary {
        Before,
        After,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum BreakKind {
        Break { boundary: Boundary, merging: bool },
        Next,
        Previous { boundary: Boundary, source: u8 },
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct BreakOperand {
        pub kind: BreakKind,
        pub destination: u8,
        pub guard: u8,
        pub source: u8,
        pub set_flags: bool,
    }

    const PREDICATE_FIELD_MASK: u32 = 0xf;
    const SOURCE_SHIFT: u32 = 5;
    const GUARD_SHIFT: u32 = 10;
    const PREVIOUS_SOURCE_SHIFT: u32 = 16;
    const MERGING_BIT: u32 = 1 << 4;
    const BREAK_MASK: u32 = 0xffff_c200;
    const BREAK_FLAGS_MASK: u32 = 0xffff_c210;
    const PREVIOUS_MASK: u32 = 0xfff0_c210;
    const BRKA: u32 = 0x2510_4000;
    const BRKAS: u32 = 0x2550_4000;
    const BRKB: u32 = 0x2590_4000;
    const BRKBS: u32 = 0x25d0_4000;
    const BRKN: u32 = 0x2518_4000;
    const BRKNS: u32 = 0x2558_4000;
    const BRKPA: u32 = 0x2500_c000;
    const BRKPAS: u32 = 0x2540_c000;
    const BRKPB: u32 = 0x2500_c010;
    const BRKPBS: u32 = 0x2540_c010;

    fn predicate(word: u32, shift: u32) -> u8 {
        ((word >> shift) & PREDICATE_FIELD_MASK) as u8
    }

    pub fn decode(word: u32) -> Option<Result<BreakOperand, ()>> {
        let previous_source = predicate(word, PREVIOUS_SOURCE_SHIFT);
        let (kind, set_flags) = match word & BREAK_FLAGS_MASK {
            BRKAS => (
                BreakKind::Break {
                    boundary: Boundary::After,
                    merging: false,
                },
                true,
            ),
            BRKBS => (
                BreakKind::Break {
                    boundary: Boundary::Before,
                    merging: false,
                },
                true,
            ),
            BRKN => (BreakKind::Next, false),
            BRKNS => (BreakKind::Next, true),
            _ => match word & BREAK_MASK {
                BRKA => (
                    BreakKind::Break {
                        boundary: Boundary::After,
                        merging: word & MERGING_BIT != 0,
                    },
                    false,
                ),
                BRKB => (
                    BreakKind::Break {
                        boundary: Boundary::Before,
                        merging: word & MERGING_BIT != 0,
                    },
                    false,
                ),
                _ => match word & PREVIOUS_MASK {
                    BRKPA => (
                        BreakKind::Previous {
                            boundary: Boundary::After,
                            source: previous_source,
                        },
                        false,
                    ),
                    BRKPAS => (
                        BreakKind::Previous {
                            boundary: Boundary::After,
                            source: previous_source,
                        },
                        true,
                    ),
                    BRKPB => (
                        BreakKind::Previous {
                            boundary: Boundary::Before,
                            source: previous_source,
                        },
                        false,
                    ),
                    BRKPBS => (
                        BreakKind::Previous {
                            boundary: Boundary::Before,
                            source: previous_source,
                        },
                        true,
                    ),
                    _ => return None,
                },
            },
        };
        Some(Ok(BreakOperand {
            kind,
            destination: predicate(word, 0),
            guard: predicate(word, GUARD_SHIFT),
            source: predicate(word, SOURCE_SHIFT),
            set_flags,
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn all_predicate_fields_and_merge_forms() {
            for d in 0..16_u32 {
                for g in 0..16_u32 {
                    for n in 0..16_u32 {
                        let fields = d | (g << GUARD_SHIFT) | (n << SOURCE_SHIFT);
                        for base in [BRKA, BRKB] {
                            for merge in [0, MERGING_BIT] {
                                let op = decode(base | fields | merge).unwrap().unwrap();
                                assert_eq!(
                                    (op.destination, op.guard, op.source),
                                    (d as u8, g as u8, n as u8)
                                );
                            }
                        }
                        for base in [BRKAS, BRKBS, BRKN, BRKNS] {
                            assert!(decode(base | fields).is_some());
                            assert!(decode(base | fields | MERGING_BIT).is_none());
                        }
                        for m in 0..16_u32 {
                            for base in [BRKPA, BRKPAS, BRKPB, BRKPBS] {
                                let op = decode(base | fields | (m << PREVIOUS_SOURCE_SHIFT))
                                    .unwrap()
                                    .unwrap();
                                assert!(
                                    matches!(op.kind, BreakKind::Previous { source: value, .. } if value == m as u8)
                                );
                            }
                        }
                    }
                }
            }
        }
        #[test]
        fn nonfamily_fixed_bits_decline() {
            assert!(decode(BRKA ^ (1 << 9)).is_none());
            assert!(decode(BRKA ^ (1 << 15)).is_none());
            assert!(decode(BRKPA ^ (1 << 9)).is_none());
        }
    }
}

mod whiles {
    //! Scalar WHILE conditions and predicate/counter destination roles.
    const ELEMENT_SIZE_SHIFT: u32 = 22;
    const ELEMENT_SIZE_MASK: u32 = 3;
    const SOURCE_N_SHIFT: u32 = 5;
    const SOURCE_M_SHIFT: u32 = 16;
    const SCALAR_REGISTER_MASK: u32 = 31;
    const SCALAR_WIDTH_SHIFT: u32 = 12;
    const COUNTER_WIDTH_SHIFT: u32 = 13;
    const PREDICATE_MASK: u32 = 15;
    const COUNTER_DESTINATION_BASE: u8 = 8;
    const COUNTER_DESTINATION_MASK: u32 = 7;
    const PAIR_DESTINATION_MASK: u32 = 14;

    use crate::aarch64::scalable::ElementSize;
    use crate::aarch64::{Register, Width, register};
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Comparison {
        SignedLt,
        SignedLe,
        SignedGe,
        SignedGt,
        UnsignedLt,
        UnsignedLe,
        UnsignedGe,
        UnsignedGt,
        ReadWriteDistance,
        WriteReadDistance,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Destination {
        Predicate(u8),
        Pair(u8),
        Counter { register: u8, vectors: u8 },
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WhileOperand {
        pub comparison: Comparison,
        pub element: ElementSize,
        pub width: Width,
        pub destination: Destination,
        pub first: Register,
        pub limit: Register,
    }
    #[derive(Debug, Clone, Copy)]
    enum Representation {
        Predicate,
        Pair,
        Counter,
    }
    struct Form {
        mask: u32,
        class: u32,
        comparison: Comparison,
        representation: Representation,
    }
    const FORMS: [Form; 26] = [
        Form {
            mask: 0xff20ec10,
            class: 0x25200000,
            comparison: Comparison::SignedGe,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204010,
            comparison: Comparison::SignedGe,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205010,
            comparison: Comparison::SignedGe,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20ec10,
            class: 0x25200010,
            comparison: Comparison::SignedGt,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204018,
            comparison: Comparison::SignedGt,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205011,
            comparison: Comparison::SignedGt,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20ec10,
            class: 0x25200810,
            comparison: Comparison::UnsignedGt,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204818,
            comparison: Comparison::UnsignedGt,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205811,
            comparison: Comparison::UnsignedGt,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20ec10,
            class: 0x25200800,
            comparison: Comparison::UnsignedGe,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204810,
            comparison: Comparison::UnsignedGe,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205810,
            comparison: Comparison::UnsignedGe,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20ec10,
            class: 0x25200410,
            comparison: Comparison::SignedLe,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204418,
            comparison: Comparison::SignedLe,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205411,
            comparison: Comparison::SignedLe,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20ec10,
            class: 0x25200c00,
            comparison: Comparison::UnsignedLt,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204c10,
            comparison: Comparison::UnsignedLt,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205c10,
            comparison: Comparison::UnsignedLt,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20ec10,
            class: 0x25200c10,
            comparison: Comparison::UnsignedLe,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204c18,
            comparison: Comparison::UnsignedLe,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205c11,
            comparison: Comparison::UnsignedLe,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20ec10,
            class: 0x25200400,
            comparison: Comparison::SignedLt,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20dc18,
            class: 0x25204410,
            comparison: Comparison::SignedLt,
            representation: Representation::Counter,
        },
        Form {
            mask: 0xff20fc11,
            class: 0x25205410,
            comparison: Comparison::SignedLt,
            representation: Representation::Pair,
        },
        Form {
            mask: 0xff20fc10,
            class: 0x25203010,
            comparison: Comparison::ReadWriteDistance,
            representation: Representation::Predicate,
        },
        Form {
            mask: 0xff20fc10,
            class: 0x25203000,
            comparison: Comparison::WriteReadDistance,
            representation: Representation::Predicate,
        },
    ];
    fn scalar_register(encoded: u32) -> Register {
        register(encoded, false)
    }
    /// All matching operand fields are allocated; mode/feature checks belong to the caller.
    /// Scalar sources31 are ZR, never SP. Pair destinations are encoded even first registers.
    pub fn decode(word: u32) -> Option<Result<WhileOperand, ()>> {
        let form = FORMS.iter().find(|form| word & form.mask == form.class)?;
        let element =
            ElementSize::from_bytes(1 << ((word >> ELEMENT_SIZE_SHIFT) & ELEMENT_SIZE_MASK))?;
        let (destination, width) = match form.representation {
            Representation::Predicate => {
                let address_distance = matches!(
                    form.comparison,
                    Comparison::ReadWriteDistance | Comparison::WriteReadDistance
                );
                let width = if address_distance || (word >> SCALAR_WIDTH_SHIFT) & 1 != 0 {
                    Width::X64
                } else {
                    Width::W32
                };
                (Destination::Predicate((word & PREDICATE_MASK) as u8), width)
            }
            Representation::Pair => (
                Destination::Pair((word & PAIR_DESTINATION_MASK) as u8),
                Width::X64,
            ),
            Representation::Counter => (
                Destination::Counter {
                    register: COUNTER_DESTINATION_BASE + (word & COUNTER_DESTINATION_MASK) as u8,
                    vectors: 2 << ((word >> COUNTER_WIDTH_SHIFT) & 1),
                },
                Width::X64,
            ),
        };
        Some(Ok(WhileOperand {
            comparison: form.comparison,
            element,
            width,
            destination,
            first: scalar_register((word >> SOURCE_N_SHIFT) & SCALAR_REGISTER_MASK),
            limit: scalar_register((word >> SOURCE_M_SHIFT) & SCALAR_REGISTER_MASK),
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn all_forms_all_operand_fields_and_aliases() {
            for form in &FORMS {
                for size in 0..=ELEMENT_SIZE_MASK {
                    for first in 0..=SCALAR_REGISTER_MASK {
                        for limit in 0..=SCALAR_REGISTER_MASK {
                            let word = form.class
                                | (size << ELEMENT_SIZE_SHIFT)
                                | (first << SOURCE_N_SHIFT)
                                | (limit << SOURCE_M_SHIFT);
                            let op = decode(word).unwrap().unwrap();
                            assert_eq!(op.comparison, form.comparison);
                            assert_eq!(op.first, scalar_register(first));
                            assert_eq!(op.limit, scalar_register(limit));
                            for bit in 0..u32::BITS {
                                if form.mask & (1 << bit) != 0 {
                                    let changed = word ^ (1 << bit);
                                    if let Some(Ok(changed_op)) = decode(changed) {
                                        // Another owned WHILE form may occupy a changed class.
                                        assert!(
                                            FORMS.iter().any(|candidate| changed & candidate.mask
                                                == candidate.class)
                                        );
                                        assert_ne!(changed_op, op);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        #[test]
        fn representation_fields_and_scalar_width_are_distinct() {
            for form in &FORMS {
                let op = decode(
                    form.class
                        | match form.representation {
                            Representation::Predicate => PREDICATE_MASK,
                            Representation::Pair => PAIR_DESTINATION_MASK,
                            Representation::Counter => COUNTER_DESTINATION_MASK,
                        },
                )
                .unwrap()
                .unwrap();
                match form.representation {
                    Representation::Predicate => {
                        assert_eq!(op.destination, Destination::Predicate(15));
                        if !matches!(
                            op.comparison,
                            Comparison::ReadWriteDistance | Comparison::WriteReadDistance
                        ) {
                            assert_eq!(op.width, Width::W32);
                            assert_eq!(
                                decode(form.class | (1 << SCALAR_WIDTH_SHIFT))
                                    .unwrap()
                                    .unwrap()
                                    .width,
                                Width::X64
                            );
                        }
                    }
                    Representation::Pair => assert_eq!(op.destination, Destination::Pair(14)),
                    Representation::Counter => {
                        assert_eq!(
                            op.destination,
                            Destination::Counter {
                                register: 15,
                                vectors: 2
                            }
                        );
                        assert_eq!(
                            decode(form.class | (1 << COUNTER_WIDTH_SHIFT))
                                .unwrap()
                                .unwrap()
                                .destination,
                            Destination::Counter {
                                register: 8,
                                vectors: 4
                            }
                        );
                    }
                }
            }
        }
        #[test]
        fn unrelated_instruction_is_declined() {
            assert_eq!(decode(0xd503201f), None);
        }
    }
}
